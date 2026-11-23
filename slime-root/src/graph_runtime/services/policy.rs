use super::*;

pub(super) fn serve_supervision_status(
    tasks: &mut TaskTable<MAX_TASKS>,
    terminations: &supervision::Terminations,
    id: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let slot = words[0] as u32;
    let Ok(capability) = tasks
        .authority(id)
        .ok_or(IpcError::InvalidOperation)
        .and_then(|table| table.resolve_supervision(slot, RIGHT_SUPERVISE))
    else {
        return Response::error(IpcError::BadCapability);
    };
    let Some(termination) = terminations.get(capability.task) else {
        return Response::error(IpcError::WouldBlock);
    };
    if let Some(table) = tasks.authority_mut(id) {
        table.drop_slot(slot);
    }
    let (kind, detail) = termination.encode();
    crate::diagnostic_println!(
        "SLIME_GRAPH supervision collected task={} child={} kind={kind}",
        id.0,
        capability.task.0
    );
    Response::success(kind, detail)
}

pub(super) fn serve_supervision_derive(
    tasks: &mut TaskTable<MAX_TASKS>,
    id: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let slot = words[0] as u32;
    let Ok(source) = tasks
        .authority(id)
        .ok_or(IpcError::InvalidOperation)
        .and_then(|table| table.resolve_supervision(slot, RIGHT_SUPERVISE))
    else {
        return Response::error(IpcError::BadCapability);
    };
    let Some(derived) = tasks.authority_mut(id).and_then(|table| {
        let free = table.free_slot_from(1)?;
        // Derivation is the "I intend to hand this on" operation: a spawn
        // returns a handle carrying `RIGHT_SUPERVISE` alone, and a service that
        // must pass its child's outcome to a client has no other way to make a
        // transferable copy. The derived handle names the same task and adds
        // nothing but the right to move it, which is authority the deriver
        // already exercises by asking.
        let capability = graph::CapabilityEntry::supervision(
            source.task,
            source.rights.bits() | RIGHT_TRANSFER,
        )?;
        table.install(free, capability).ok()?;
        Some(free)
    }) else {
        return Response::error(IpcError::DestinationSlotsExhausted);
    };
    crate::diagnostic_println!(
        "SLIME_GRAPH supervision derived task={} child={} slot={derived}",
        id.0,
        source.task.0
    );
    Response::success(0, sel4::Word::from(derived))
}

/// Wake every waiter whose declared C9.2 supervision source names `dead`, then
/// retire the dead task's own row.
///
/// One helper rather than two calls at each site, because the order matters and
/// is easy to get wrong: the signal is gated on the *waiter's* slot still
/// holding a handle naming `dead`, so it must run while the authority tables are
/// intact, and `dead`'s own row must go afterwards or a task supervising itself
/// through a stale slot would be signalled on the way out.
pub(super) fn signal_declared_death(
    service: &mut wait_set::WaitSetService,
    tasks: &TaskTable<MAX_TASKS>,
    dead: TaskId,
) {
    let woken = service.signal_death(tasks, dead);
    service.clear_task(dead);
    if woken != 0 {
        crate::diagnostic_println!("SLIME_WAIT death task={} woken={woken}", dead.0);
    }
}

/// Serve C9.3's two scheduling operations.
///
/// `CLASS_READ` is self-scoped and never refused for want of authority: the
/// instance is the badge's, and every live task has a class because every thread
/// runs at some priority.
///
/// `CLASS_PROMOTE` resolves its subject through a supervision capability the
/// *caller* holds, so no task identity crosses the wire — the same rule
/// `supervision_derive` follows (B42). Three checks must all pass: the slot must
/// hold supervision over the subject with `schedulingPromote`, the generation
/// must declare a promotion edge from this holder to that subject, and the
/// requested class's band must sit at or below that edge's ceiling.
pub(super) fn serve_scheduling_request(
    service: &mut scheduling::SchedulingService,
    policy: Option<&boot_contracts::scheduling_class::SchedulingClass<'_>>,
    tasks: &TaskTable<MAX_TASKS>,
    task: TaskId,
    label: sel4::Word,
    words: &[sel4::Word],
) -> Response {
    match label {
        scheduling_labels::CLASS_READ => {
            let class = service.class(task);
            crate::diagnostic_println!(
                "SLIME_SCHED read task={} class={} priority={}",
                task.0,
                class.name(),
                class.priority(),
            );
            Response::success(class.class_id() as i64, class.priority())
        }
        scheduling_labels::CLASS_PROMOTE => {
            let Ok(slot) = u32::try_from(words[0]) else {
                return Response::error(IpcError::InvalidOperation);
            };
            let Ok(class_id) = u32::try_from(words[1]) else {
                return Response::error(IpcError::InvalidOperation);
            };
            // The capability, not the wire, names the subject. Narrowed to
            // `RIGHT_SCHEDULING_PROMOTE` rather than to `RIGHT_SUPERVISE`: a
            // component may legitimately hold a supervision handle in order to
            // observe a peer's death without thereby being able to reprioritize
            // it, so the right the operation is gated on is the one the matrix
            // names for this operation.
            let Ok(capability) = tasks
                .authority(task)
                .ok_or(IpcError::InvalidOperation)
                .and_then(|table| {
                    table.resolve_supervision(
                        slot,
                        boot_contracts::generation::RIGHT_SCHEDULING_PROMOTE,
                    )
                })
            else {
                crate::diagnostic_println!(
                    "SLIME_SCHED refused task={} class=undeclared detail=slot",
                    task.0,
                );
                return Response::error(IpcError::BadCapability);
            };
            let Some(subject) = tasks.get(capability.task) else {
                crate::diagnostic_println!(
                    "SLIME_SCHED refused task={} class=absent detail=subject",
                    task.0,
                );
                return Response::error(IpcError::BadCapability);
            };
            match service.promote(policy, task, capability.task, subject.tcb, class_id) {
                Ok(class) => {
                    crate::diagnostic_println!(
                        "SLIME_SCHED promoted task={} subject={} class={} priority={}",
                        task.0,
                        capability.task.0,
                        class.name(),
                        class.priority(),
                    );
                    Response::success(class.class_id() as i64, class.priority())
                }
                Err(error) => {
                    crate::diagnostic_println!(
                        "SLIME_SCHED refused task={} subject={} class={} detail={error:?}",
                        task.0,
                        capability.task.0,
                        scheduling_error_class(error),
                    );
                    Response::error(scheduling_error_status(error))
                }
            }
        }
        _ => Response::error(IpcError::UnsupportedOperation),
    }
}

pub(super) const fn scheduling_error_status(error: scheduling::SchedulingError) -> IpcError {
    match error {
        // A caller naming itself is `InvalidOperation` rather than
        // `BadCapability`: the capability it presented was real, and the request
        // is refused for what it asked rather than for what it holds.
        scheduling::SchedulingError::SelfPromotion
        | scheduling::SchedulingError::UnknownClass
        | scheduling::SchedulingError::AboveCeiling
        | scheduling::SchedulingError::Malformed
        | scheduling::SchedulingError::SchedParams => IpcError::InvalidOperation,
        scheduling::SchedulingError::Undeclared => IpcError::BadCapability,
    }
}

pub(super) const fn scheduling_error_class(error: scheduling::SchedulingError) -> &'static str {
    match error {
        scheduling::SchedulingError::Undeclared => "undeclared",
        scheduling::SchedulingError::Malformed => "malformed",
        scheduling::SchedulingError::SelfPromotion => "self-promotion",
        scheduling::SchedulingError::AboveCeiling => "above-ceiling",
        scheduling::SchedulingError::UnknownClass => "unknown-class",
        scheduling::SchedulingError::SchedParams => "sched-params",
    }
}

/// Serve C9.4's lifecycle state, restart admission, and parameter authority.
///
/// `STATE_READ` is self-scoped and never refused for want of authority: the
/// instance is the badge's, and an instance the policy does not name reads
/// `undeclared` rather than an error, on `CLASS_READ`'s rule.
///
/// `STATE_ADVANCE` is self-scoped too, and takes no subject: moving another
/// component's lifecycle state is authority no C9.4 field grants, so there is
/// nothing to authorize beyond being the task whose state moves. What it *is*
/// gated on is the graph — an edge the generation does not admit is refused.
///
/// The three supervision operations resolve their subject through a capability
/// the *caller* holds, so no task identity crosses the wire (B42). Each is
/// narrowed to its own right rather than to `RIGHT_SUPERVISE`, for the reason
/// `CLASS_PROMOTE` is: a component may hold a supervision handle to observe a
/// peer's death without thereby being able to restart it or read its
/// configuration.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_lifecycle_request(
    service: &mut lifecycle::LifecycleService,
    policy: Option<&boot_contracts::lifecycle_policy::LifecyclePolicy<'_>>,
    generation: &Generation<'_>,
    tasks: &TaskTable<MAX_TASKS>,
    timer_adapter: &mut PhysicalTimerAdapter,
    task: TaskId,
    label: sel4::Word,
    words: &[sel4::Word],
) -> Response {
    match label {
        lifecycle_labels::STATE_READ => {
            let state = service.state(task);
            let instance = service.instance_of(task);
            let remaining = instance.map_or(0, |instance| {
                service.attempts_remaining(policy, instance, generation)
            });
            let cause = instance.map_or(0, |instance| service.terminal_id(instance));
            crate::diagnostic_println!(
                "SLIME_LIFECYCLE read task={} state={} attempts={remaining} cause={}",
                task.0,
                boot_contracts::lifecycle_policy::state_name(state),
                boot_contracts::lifecycle_policy::cause_name(cause),
            );
            // The auxiliary word packs the remaining attempts low and the
            // predecessor's terminal cause high, so a replacement learns both in
            // one call without a second self-scoped operation.
            Response::success(
                state as i64,
                sel4::Word::from(remaining) | (sel4::Word::from(cause) << 32),
            )
        }
        lifecycle_labels::STATE_ADVANCE => {
            let Ok(state_id) = u32::try_from(words[0]) else {
                return Response::error(IpcError::InvalidOperation);
            };
            match service.advance(policy, task, state_id) {
                Ok(state) => {
                    crate::diagnostic_println!(
                        "SLIME_LIFECYCLE advanced task={} state={}",
                        task.0,
                        boot_contracts::lifecycle_policy::state_name(state),
                    );
                    Response::success(state as i64, 0)
                }
                Err(error) => {
                    crate::diagnostic_println!(
                        "SLIME_LIFECYCLE refused task={} class={} detail={error:?}",
                        task.0,
                        lifecycle_error_class(error),
                    );
                    Response::error(lifecycle_error_status(error))
                }
            }
        }
        supervision_labels::RESTART_ADMIT => {
            let Some((subject_task, subject_instance)) = resolve_lifecycle_subject(
                tasks,
                service,
                task,
                words[0],
                boot_contracts::generation::RIGHT_LIFECYCLE_RESTART,
                // The subject is dead by construction: the death is what this
                // operation answers, so its task row is already released.
                true,
            ) else {
                crate::diagnostic_println!(
                    "SLIME_LIFECYCLE refused task={} class=undeclared detail=slot",
                    task.0,
                );
                return Response::error(IpcError::BadCapability);
            };
            let Ok(now) = timer_adapter.monotonic_now() else {
                crate::diagnostic_println!(
                    "SLIME_LIFECYCLE FAIL restart clock read task={}",
                    task.0
                );
                return Response::error(IpcError::InvalidOperation);
            };
            match service.admit_restart(policy, generation, subject_instance, now.0) {
                Ok(admission) => {
                    crate::diagnostic_println!(
                        "SLIME_LIFECYCLE restart admitted task={} subject={} attempt={} remaining={} ready_at={}",
                        task.0,
                        subject_task.0,
                        admission.attempt,
                        admission.remaining,
                        admission.ready_at,
                    );
                    Response::success(admission.remaining as i64, admission.ready_at)
                }
                Err(error) => {
                    // An exhausted bound is the declared terminal state, and the
                    // marker says so rather than only that a restart was
                    // declined: the two read very differently to an operator.
                    if error == lifecycle::LifecycleError::AttemptsExhausted {
                        crate::diagnostic_println!(
                            "SLIME_LIFECYCLE terminal task={} subject={} state={} attempts=exhausted",
                            task.0,
                            subject_task.0,
                            boot_contracts::lifecycle_policy::state_name(
                                lifecycle::LifecycleService::terminal_state(policy)
                            ),
                        );
                    } else {
                        crate::diagnostic_println!(
                            "SLIME_LIFECYCLE restart refused task={} subject={} class={} detail={error:?}",
                            task.0,
                            subject_task.0,
                            lifecycle_error_class(error),
                        );
                    }
                    Response::error(lifecycle_error_status(error))
                }
            }
        }
        supervision_labels::PARAMETER_READ | supervision_labels::PARAMETER_WRITE => {
            let write = label == supervision_labels::PARAMETER_WRITE;
            let required = if write {
                boot_contracts::generation::RIGHT_PARAMETER_WRITE
            } else {
                boot_contracts::generation::RIGHT_PARAMETER_READ
            };
            // `PARAMETER_SELF_SLOT` names the caller's own instance rather than a
            // capability, and it is the only shape that reaches a *reflexive*
            // parameter edge. Without it that edge would decode, admit, and be
            // unreachable — a declared authority that silently never applies,
            // which is the shape B71 closed. A component holds no supervision
            // capability naming itself (the root mints one only for a spawner),
            // so the sentinel is not a widening: the declared reflexive edge is
            // still the whole authority, and its absence still denies.
            let subject_instance = if words[0] == PARAMETER_SELF_SLOT {
                match service.instance_of(task) {
                    Some(instance) => instance,
                    None => return Response::error(IpcError::InvalidOperation),
                }
            } else {
                match resolve_lifecycle_subject(
                    tasks, service, task, words[0], required,
                    // A parameter operation acts on a live subject: writing
                    // configuration for an instance whose task is gone would be
                    // a write nothing reads until a restart that may never be
                    // admitted.
                    false,
                ) {
                    Some((_, instance)) => instance,
                    None => {
                        crate::diagnostic_println!(
                            "SLIME_LIFECYCLE parameter refused task={} class=undeclared detail=slot",
                            task.0,
                        );
                        return Response::error(IpcError::BadCapability);
                    }
                }
            };
            let Some(holder_instance) = service.instance_of(task) else {
                return Response::error(IpcError::InvalidOperation);
            };
            let key = words[1];
            let outcome = if write {
                service.parameter_write(
                    policy,
                    generation,
                    holder_instance,
                    subject_instance,
                    key,
                    words[2],
                )
            } else {
                service.parameter_read(policy, generation, holder_instance, subject_instance, key)
            };
            match outcome {
                Ok(value) => {
                    crate::diagnostic_println!(
                        "SLIME_LIFECYCLE parameter task={} subject-instance={subject_instance} key={key} write={write} value={value}",
                        task.0,
                    );
                    Response::success(value as i64, 0)
                }
                Err(error) => {
                    crate::diagnostic_println!(
                        "SLIME_LIFECYCLE parameter refused task={} subject-instance={subject_instance} key={key} class={} detail={error:?}",
                        task.0,
                        lifecycle_error_class(error),
                    );
                    Response::error(lifecycle_error_status(error))
                }
            }
        }
        _ => Response::error(IpcError::UnsupportedOperation),
    }
}

/// Resolve a lifecycle subject from the caller's own supervision capability.
///
/// The subject's *instance* is what every C9.4 operation acts on — an attempt
/// bound and a parameter table belong to a declaration, not to a task lifetime —
/// but the capability names a `TaskId`.
///
/// `released` is what distinguishes the two callers, and it is load-bearing.
/// `RESTART_ADMIT` names a subject that has *already died*, so its task row is
/// gone by construction and the instance must come from the instance row that
/// survived it. The parameter operations name a live subject, and admitting a
/// released one there would let a holder write configuration for an instance
/// whose task no longer exists — a write nothing would read until a restart the
/// generation might never admit.
pub(super) fn resolve_lifecycle_subject(
    tasks: &TaskTable<MAX_TASKS>,
    service: &lifecycle::LifecycleService,
    caller: TaskId,
    slot: sel4::Word,
    required: u64,
    released: bool,
) -> Option<(TaskId, usize)> {
    let slot = u32::try_from(slot).ok()?;
    let capability = tasks
        .authority(caller)
        .and_then(|table| table.resolve_supervision(slot, required).ok())?;
    let instance = if released {
        service.instance_of_any(capability.task)
    } else {
        service
            .instance_of(capability.task)
            .or_else(|| launched_instance_of(tasks, capability.task))
    }?;
    Some((capability.task, instance))
}

/// The declared instance a live task represents, read from the task table.
pub(super) fn launched_instance_of(tasks: &TaskTable<MAX_TASKS>, task: TaskId) -> Option<usize> {
    tasks.get(task).and_then(|record| record.instance)
}

/// The `PARAMETER_READ`/`PARAMETER_WRITE` slot operand that names the caller's
/// own instance.
///
/// `u32::MAX` because no capability table has that many slots — `graph::MAX_TASK_CAPS`
/// bounds them far below — so the sentinel cannot collide with a real slot a
/// component might hold. Declared here beside the operation that reads it, and
/// documented in `docs/syscall-abi.md` as part of the operand contract.
pub const PARAMETER_SELF_SLOT: sel4::Word = u32::MAX as sel4::Word;

pub(super) const fn lifecycle_error_status(error: lifecycle::LifecycleError) -> IpcError {
    match error {
        // Absent authority is `BadCapability`, on `CLASS_PROMOTE`'s rule: the
        // caller's own table is what came up short.
        lifecycle::LifecycleError::Undeclared | lifecycle::LifecycleError::NoParameterAuthority => {
            IpcError::BadCapability
        }
        // A subject still live is `WouldBlock`, exactly as `SUPERVISION STATUS`
        // answers for an outcome that has not happened yet: the request is
        // well-formed and the answer is "not yet".
        lifecycle::LifecycleError::StillLive => IpcError::WouldBlock,
        // A full parameter table is a resource answer rather than an authority
        // one, so it maps to the status a caller can act on by writing fewer
        // keys — the same mapping a spawn's exhausted budget uses.
        lifecycle::LifecycleError::ParameterTableFull => IpcError::DestinationSlotsExhausted,
        // A pending backoff is `WouldBlock` on `StillLive`'s rule: the request is
        // well-formed and the answer is "not yet". A caller that waits the
        // instant `RESTART_ADMIT` answered and retries is admitted, so a
        // permanent status here would read as a refusal it cannot recover from.
        lifecycle::LifecycleError::BackoffPending => IpcError::WouldBlock,
        lifecycle::LifecycleError::UnadmittedTransition
        | lifecycle::LifecycleError::UnknownState
        | lifecycle::LifecycleError::UnadmittedCause
        | lifecycle::LifecycleError::AttemptsExhausted
        | lifecycle::LifecycleError::UnknownParameter
        | lifecycle::LifecycleError::Malformed => IpcError::InvalidOperation,
    }
}

pub(super) const fn lifecycle_error_class(error: lifecycle::LifecycleError) -> &'static str {
    match error {
        lifecycle::LifecycleError::Undeclared => "undeclared",
        lifecycle::LifecycleError::Malformed => "malformed",
        lifecycle::LifecycleError::UnadmittedTransition => "unadmitted-transition",
        lifecycle::LifecycleError::UnknownState => "unknown-state",
        lifecycle::LifecycleError::StillLive => "still-live",
        lifecycle::LifecycleError::UnadmittedCause => "unadmitted-cause",
        lifecycle::LifecycleError::AttemptsExhausted => "attempts-exhausted",
        lifecycle::LifecycleError::BackoffPending => "backoff-pending",
        lifecycle::LifecycleError::NoParameterAuthority => "no-parameter-authority",
        lifecycle::LifecycleError::UnknownParameter => "unknown-parameter",
        lifecycle::LifecycleError::ParameterTableFull => "parameter-table-full",
    }
}
