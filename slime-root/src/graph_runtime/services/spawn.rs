use super::*;

const MAX_SPAWN_GRANTS: usize = transfer_window::MAX_STAGED_ARRAY_BYTES / SPAWN_GRANT_RECORD_BYTES;

// The two sides of the ABI agree on the ceiling. `sel4_transport::spawn`
// encodes into a fixed `MAX_SPAWN_GRANTS * GRANT_RECORD_BYTES` array of its
// own; a root that accepted fewer would refuse a list the component staged
// successfully, and one that accepted more would be describing a payload no
// caller can produce.
const _: () = assert!(MAX_SPAWN_GRANTS == 64);

#[derive(Clone, Copy)]
pub(super) struct SpawnPlan {
    executable: usize,
    instance: usize,
    granted: [Option<(u32, u32, graph::CapabilityEntry, bool)>; MAX_SPAWN_GRANTS],
    count: usize,
    transferable_supervision: bool,
}

#[derive(Clone, Copy)]
pub(super) struct SpawnGrant {
    slot: u32,
    rights: u64,
}

pub(in crate::graph_runtime) fn resource_label<'a>(
    generation: &Generation<'a>,
    capability: &graph::CapabilityEntry,
) -> &'a str {
    match capability {
        graph::CapabilityEntry::Executable(capability) => generation
            .executable(capability.executable)
            .map_or("?", |record| record.name),
        _ => "-",
    }
}

pub(super) enum DeclaredCapability<'a> {
    Granted(usize, Grant<'a>),
    Minted(MintedBinding<'a>),
}
impl DeclaredCapability<'_> {
    const fn slot(&self) -> usize {
        match self {
            Self::Granted(slot, _) => *slot,
            Self::Minted(minted) => minted.slot,
        }
    }
}
/// Whether a grant-backed binding is one the child's *owner* must supply at
/// spawn.
///
/// Re-exported from [`crate::generation`], which owns the rule: it is pure over
/// decoded generation data, so it belongs where `just test_sel4_root` can reach
/// it. This is the same function the image links, not a copy.
pub(super) use crate::generation::grant_crosses_spawn;

pub(super) fn nth_declared_capability<'a>(
    generation: &Generation<'a>,
    child: Instance<'a>,
    child_instance: usize,
    index: usize,
) -> Result<DeclaredCapability<'a>, IpcError> {
    let mut selected = None;
    let mut each = |candidate: DeclaredCapability<'a>| -> Result<(), IpcError> {
        if declarations_below(generation, child, child_instance, candidate.slot())? == index
            && selected.replace(candidate).is_some()
        {
            return Err(IpcError::BadCapability);
        }
        Ok(())
    };
    for at in 0..child.binding_count() {
        let binding = generation
            .binding(child, at)
            .map_err(|_| IpcError::BadCapability)?;
        let declared = generation
            .grant(binding.grant)
            .map_err(|_| IpcError::BadCapability)?;
        if grant_crosses_spawn(declared, child_instance) {
            each(DeclaredCapability::Granted(binding.slot, declared))?;
        }
    }
    for at in 0..generation.minted_binding_count() {
        let minted = generation
            .minted_binding(at)
            .map_err(|_| IpcError::BadCapability)?;
        if minted.holder == child_instance && minted.capability_kind != CapabilityKind::Endpoint {
            each(DeclaredCapability::Minted(minted))?;
        }
    }
    selected.ok_or(IpcError::BadCapability)
}

pub(super) fn declarations_below(
    generation: &Generation<'_>,
    child: Instance<'_>,
    child_instance: usize,
    slot: usize,
) -> Result<usize, IpcError> {
    let mut below = 0;
    for at in 0..child.binding_count() {
        let binding = generation
            .binding(child, at)
            .map_err(|_| IpcError::BadCapability)?;
        let declared = generation
            .grant(binding.grant)
            .map_err(|_| IpcError::BadCapability)?;
        below += usize::from(grant_crosses_spawn(declared, child_instance) && binding.slot < slot);
    }
    for at in 0..generation.minted_binding_count() {
        let minted = generation
            .minted_binding(at)
            .map_err(|_| IpcError::BadCapability)?;
        below += usize::from(
            minted.holder == child_instance
                && minted.capability_kind != CapabilityKind::Endpoint
                && minted.slot < slot,
        );
    }
    Ok(below)
}

pub(super) fn preflight_spawn_grants(
    generation: &Generation<'_>,
    caller_instance: usize,
    table: &graph::AuthorityTable,
    executable_slot: u32,
    records: &[u8],
    launched: &LaunchedInstances,
) -> Result<SpawnPlan, IpcError> {
    let executable = match table.resolve_executable(executable_slot, RIGHT_EXEC | RIGHT_SPAWN) {
        Ok(executable) => executable,
        Err(error) => {
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn preflight executable task-instance={caller_instance} slot={executable_slot} held={:?} required={:#x} error={error:?}",
                table.get(executable_slot),
                RIGHT_EXEC | RIGHT_SPAWN,
            );
            return Err(IpcError::BadCapability);
        }
    };
    let executable_index = executable.executable;
    crate::diagnostic_println!(
        "SLIME_GRAPH spawn preflight executable-ok task-instance={caller_instance} slot={executable_slot} executable={executable_index} rights={:#x}",
        executable.rights.bits(),
    );
    let mut child_instance = None;
    for index in 0..generation.instance_count() {
        let instance = generation
            .instance(index)
            .map_err(|_| IpcError::BadCapability)?;
        if instance.owner == InstanceOwner::Instance(caller_instance)
            && instance.executable == executable_index
            && child_instance.replace(index).is_some()
        {
            return Err(IpcError::BadCapability);
        }
    }
    let child_instance = child_instance.ok_or(IpcError::BadCapability)?;
    let child = generation
        .instance(child_instance)
        .map_err(|_| IpcError::BadCapability)?;
    crate::diagnostic_println!(
        "SLIME_GRAPH spawn preflight child-ok task-instance={caller_instance} child={child_instance} name={}",
        child.name,
    );
    if !records.len().is_multiple_of(SPAWN_GRANT_RECORD_BYTES) {
        return Err(IpcError::InvalidLength);
    }
    let count = records.len() / SPAWN_GRANT_RECORD_BYTES;
    if count > MAX_SPAWN_GRANTS {
        return Err(IpcError::InvalidLength);
    }
    // The declared total, from the one function that computes it
    // (`declared_crossing_grants`). `parent_supplied` and `minted_count` are
    // still reported separately below because a mismatch is nearly always a
    // fixture defect, and knowing which half moved is what makes it findable.
    let minted_count = (0..generation.minted_binding_count())
        .filter(|index| {
            generation
                .minted_binding(*index)
                .is_ok_and(|m| m.holder == child_instance)
        })
        .count();
    let declared = crate::generation::declared_crossing_grants(generation, child, child_instance)
        .map_err(|_| IpcError::BadCapability)?;
    let parent_supplied = declared - minted_count;
    let respawn = launched.ever_launched(child_instance);
    if count != parent_supplied + minted_count && !(respawn && count == 0) {
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn preflight count task-instance={caller_instance} child={child_instance} requested={count} parent={parent_supplied} minted={minted_count} respawn={respawn}",
        );
        return Err(IpcError::BadCapability);
    }
    let mut requested = [None; MAX_SPAWN_GRANTS];
    for (destination, record) in requested
        .iter_mut()
        .zip(records.chunks_exact(SPAWN_GRANT_RECORD_BYTES))
    {
        let slot = u64::from_le_bytes(
            record[GRANT_SLOT_OFFSET..GRANT_SLOT_OFFSET + 8]
                .try_into()
                .map_err(|_| IpcError::InvalidLength)?,
        );
        let rights = u64::from_le_bytes(
            record[GRANT_RIGHTS_OFFSET..GRANT_RIGHTS_OFFSET + 8]
                .try_into()
                .map_err(|_| IpcError::InvalidLength)?,
        );
        *destination = Some(SpawnGrant {
            slot: u32::try_from(slot).map_err(|_| IpcError::BadCapability)?,
            rights,
        });
    }
    let mut granted = [None; MAX_SPAWN_GRANTS];
    for index in 0..count {
        let request = requested[index].ok_or(IpcError::InvalidLength)?;
        if request.slot == executable_slot
            || requested[..index]
                .iter()
                .flatten()
                .any(|seen| seen.slot == request.slot)
        {
            return Err(IpcError::BadCapability);
        }
        let declaration = nth_declared_capability(generation, child, child_instance, index)?;
        let minted = matches!(declaration, DeclaredCapability::Minted(_));
        let (destination, ceiling) = match declaration {
            DeclaredCapability::Granted(slot, declared) => {
                if !generation.grant_applies_to_instance(declared, child_instance) {
                    return Err(IpcError::BadCapability);
                }
                (slot, declared.rights)
            }
            DeclaredCapability::Minted(declared) => {
                if declared.owner != caller_instance {
                    return Err(IpcError::BadCapability);
                }
                (declared.slot, declared.rights)
            }
        };
        if request.rights == 0 || request.rights & !ceiling != 0 {
            return Err(IpcError::BadCapability);
        }
        let narrowed = table
            .get(request.slot)
            .and_then(|held| held.narrow(request.rights))
            .ok_or(IpcError::BadCapability)?;
        granted[index] = Some((
            request.slot,
            u32::try_from(destination).map_err(|_| IpcError::BadCapability)?,
            narrowed,
            minted,
        ));
    }
    if respawn && count == 0 {
        for (index, slot) in granted.iter_mut().enumerate().take(parent_supplied) {
            let declaration = nth_declared_capability(generation, child, child_instance, index)?;
            let DeclaredCapability::Granted(destination, declared) = declaration else {
                return Err(IpcError::BadCapability);
            };
            let resource = match declared.capability_kind {
                CapabilityKind::Device
                | CapabilityKind::MmioRegion
                | CapabilityKind::InterruptSource
                | CapabilityKind::DmaAccount => 0,
                _ => return Err(IpcError::BadCapability),
            };
            let held = table.slots().any(|(_, capability)| {
                matches!(
                    (declared.capability_kind, capability),
                    (
                        CapabilityKind::Device,
                        Some(graph::CapabilityEntry::Device(_))
                    ) | (
                        CapabilityKind::MmioRegion,
                        Some(graph::CapabilityEntry::MmioRegion(_))
                    ) | (
                        CapabilityKind::InterruptSource,
                        Some(graph::CapabilityEntry::InterruptSource(_))
                    ) | (
                        CapabilityKind::DmaAccount,
                        Some(graph::CapabilityEntry::DmaAccount(_))
                    )
                )
            });
            if !held {
                return Err(IpcError::BadCapability);
            }
            let capability =
                declared_capability(declared.capability_kind, resource, declared.rights)
                    .ok_or(IpcError::BadCapability)?;
            *slot = Some((
                0,
                u32::try_from(destination).map_err(|_| IpcError::BadCapability)?,
                capability,
                false,
            ));
        }
        return Ok(SpawnPlan {
            executable: executable_index,
            instance: child_instance,
            granted,
            count: parent_supplied,
            transferable_supervision: executable.rights.allows(RIGHT_TRANSFER),
        });
    }
    Ok(SpawnPlan {
        executable: executable_index,
        instance: child_instance,
        granted,
        count,
        transferable_supervision: executable.rights.allows(RIGHT_TRANSFER),
    })
}

/// Construct the child a validated plan names, and install both tables.
///
/// Ordering is the whole safety argument, and it is the one
/// `launch_component_graph` already uses for the boot graph: nothing is
/// allocated until every check has passed, and the two failure points that
/// remain after allocation each tear down what they made.
///
/// The child's slot numbering comes only from its declared instance bindings.
/// Request order is merely the canonical binding-slice traversal used to pair
/// caller capabilities with declarations; it never becomes a destination slot.
/// first spawn grant.
#[allow(clippy::too_many_arguments)]
pub(super) fn construct_child(
    retirements: &mut supervision::Retirements,
    generation: &Generation<'_>,
    tasks: &mut TaskTable<MAX_TASKS>,
    windows: &mut WindowTable<MAX_WINDOW_ENTRIES>,
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    scratch: &ScratchPage,
    service_endpoint: sel4::cap::Endpoint,
    console_endpoint: sel4::cap::Endpoint,
    parent: TaskId,
    plan: &SpawnPlan,
    adaptive: Option<&mut super::super::adaptive::AdaptivePolicy<'_>>,
) -> Result<TaskId, IpcError> {
    let mut adaptive = adaptive;
    let record = generation
        .executable(plan.executable)
        .map_err(|_| IpcError::BadCapability)?;
    let instance = generation
        .instance(plan.instance)
        .map_err(|_| IpcError::BadCapability)?;
    let object = generation
        .object(record.object)
        .map_err(|_| IpcError::BadCapability)?;
    let profile = boot_contracts::target_profile::TargetProfile::by_name(TARGET_PROFILE)
        .map_err(|_| IpcError::BadCapability)?;
    let elf = boot_contracts::component_image::admit_elf(object.bytes, profile)
        .map_err(|_| IpcError::BadCapability)?;

    let image = ChildImage::parse(elf).map_err(|_| IpcError::BadCapability)?;
    let authority = bound_authority(generation, instance).map_err(|_| IpcError::BadCapability)?;
    let declared = (0..generation.resource_quota_count())
        .filter_map(|index| generation.resource_quota(index).ok())
        .find(|quota| {
            generation
                .process(quota.owner_process)
                .is_ok_and(|process| process.instance == plan.instance)
        })
        .ok_or(IpcError::BadCapability)?
        .frame_count;
    let image_baseline = (
        allocator.live_slots(),
        allocator.live_objects(),
        allocator.live_bytes(),
        allocator.allocation_descriptors_free(),
    );

    let id = tasks
        .create(
            allocator,
            &image,
            service_endpoint,
            console_endpoint,
            authority,
            Supervision::SelfManaged,
            sel4::init_thread::slot::VSPACE.cap(),
            scratch,
            sel4::init_thread::slot::ASID_POOL.cap(),
            Some(parent),
            Some(plan.executable),
            Some(plan.instance),
            // A dynamically spawned child is never the bootstrap instance.
            0,
            // A spawned child is a declared instance too, so its CSpace comes
            // from the same plan the boot graph reads.
            generation
                .instance_cspace_size_bits(plan.instance)
                .map_err(|_| IpcError::BadCapability)?
                .ok_or(IpcError::BadCapability)? as usize,
            match generation.instance_child_slots(plan.instance) {
                Ok(Some(boot_contracts::generation::ChildSlotPlan {
                    service: Some(service),
                    console: Some(console),
                    tcb: Some(tcb),
                    fault: Some(fault),
                })) => (task::ChildSlots {
                    service: service as sel4::CPtrBits,
                    console: console as sel4::CPtrBits,
                    tcb: tcb as sel4::CPtrBits,
                    fault: fault as sel4::CPtrBits,
                })
                .validate()
                .map_err(|_| IpcError::BadCapability)?,
                _ => return Err(IpcError::BadCapability),
            },
            // As the boot path: a spawned child is a declared instance, so its
            // priority comes from the same plan, and is recorded for the same
            // reason -- a priority nothing reports is indistinguishable from
            // the constant it replaced (B48).
            {
                let priority = match generation.instance_priority(plan.instance) {
                    Ok(Some(priority)) => sel4::Word::from(priority),
                    Ok(None) => task::CHILD_PRIORITY,
                    Err(_) => return Err(IpcError::BadCapability),
                };
                crate::diagnostic_println!(
                    "SLIME_GRAPH schedule instance={} priority={priority} default={}",
                    generation
                        .instance(plan.instance)
                        .map_or("<unknown>", |record| record.name),
                    task::CHILD_PRIORITY,
                );
                priority
            },
            // As the boot path: the thread count comes from the same plan, so
            // a spawned instance declaring a worker gets one (B47).
            match generation.instance_threads(plan.instance) {
                Ok(Some(threads)) => threads,
                Ok(None) => 1,
                Err(_) => return Err(IpcError::BadCapability),
            },
            // As the boot path: each worker's own declared priority (B48).
            {
                let main_priority = match generation.instance_priority(plan.instance) {
                    Ok(Some(priority)) => sel4::Word::from(priority),
                    Ok(None) => task::CHILD_PRIORITY,
                    Err(_) => return Err(IpcError::BadCapability),
                };
                let mut priorities = [main_priority; child_vspace::MAX_CHILD_THREADS];
                for (thread_index, slot) in priorities.iter_mut().enumerate().skip(1) {
                    match generation.thread_priority(plan.instance, thread_index) {
                        Ok(Some(priority)) => *slot = sel4::Word::from(priority),
                        Ok(None) => {}
                        Err(_) => return Err(IpcError::BadCapability),
                    }
                }
                priorities
            },
            // As the boot path: the ceiling the generation declares for this
            // component, keyed by its declared instance name (C10.2). A
            // spawned child is a declared instance too, so it reads the same
            // budget rather than inheriting its parent's quota — a parent
            // cannot widen what the generation granted its child.
            //
            // A malformed budget cannot reach here: admission failed the whole
            // generation before anything launched. A budget that will not decode
            // *at this point* would therefore be a root defect, so it resolves
            // to zero (deny) rather than being papered over.
            match crate::generation::private_memory_budget_object(generation) {
                Some(Ok(budget)) => declared_private_memory_pages(Some(&budget), instance.name),
                Some(Err(_)) => return Err(IpcError::BadCapability),
                None => 0,
            },
            adaptive
                .as_ref()
                .and_then(|policy| policy.maximum_pages(instance.name)),
        )
        .map_err(|error| {
            crate::diagnostic_println!(
                "SLIME_GRAPH construction refused instance={} error={error:?}",
                instance.name
            );
            IpcError::DestinationSlotsExhausted
        })?;

    crate::diagnostic_println!(
        "SLIME_ROOT image launch task={} instance={} pages={} declared={} live_slots={} live_objects={} live_bytes={} allocation_descriptors_free={}",
        id.0,
        instance.name,
        tasks
            .get(id)
            .expect("constructed task")
            .vspace
            .frames_mapped,
        declared,
        image_baseline.0,
        image_baseline.1,
        image_baseline.2,
        image_baseline.3,
    );

    // Bound between construction and publication, exactly as the boot path
    // does: a duplicate live incarnation is refused here rather than
    // multiplying its entitlement, and the spawn is unwound.
    if let Some(policy) = adaptive.as_deref_mut()
        && policy.maximum_pages(instance.name).is_some()
    {
        match policy.bind(instance.name) {
            Some(binding) if tasks.bind_private_memory(id, binding).is_ok() => {}
            _ => {
                release_child(
                    retirements,
                    generation,
                    tasks,
                    windows,
                    buffers,
                    allocator,
                    None,
                    id,
                );
                return Err(IpcError::BadCapability);
            }
        }
    }
    if let Some(policy) = adaptive.as_deref_mut() {
        let (installed, base) = tasks.get(id).map_or((0, 0), |task| {
            (
                task.private_memory.reservation(),
                task.private_memory.base(),
            )
        });
        policy.report_task(
            id,
            instance.name,
            tasks.private_binding(id),
            installed,
            base,
        );
    }
    // One injected construction failure for the first dynamically spawned
    // subject, after its incarnation is bound and before it is published. The
    // unwind must hold the entitlement until the arena's revoke succeeds and
    // then release it, so a retried spawn binds the next incarnation rather
    // than a second live one.
    #[cfg(slime_private_conservation)]
    if tasks.private_binding(id).is_some() {
        use core::sync::atomic::{AtomicBool, Ordering};
        static ARMED: AtomicBool = AtomicBool::new(true);
        if ARMED.swap(false, Ordering::Relaxed) {
            crate::diagnostic_println!(
                "SLIME_MEM adaptive injected kind=construction task={} instance={}",
                id.0,
                instance.name,
            );
            // The unwind's own revoke fails too, so the unpublished task must
            // reach the retirement retry before its subject can spawn again.
            crate::object_allocator::elastic::arm_arena_revoke_failure();
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                id,
            );
            return Err(IpcError::DestinationSlotsExhausted);
        }
    }
    let Some(task) = tasks.get(id) else {
        release_child(
            retirements,
            generation,
            tasks,
            windows,
            buffers,
            allocator,
            adaptive.as_deref_mut(),
            id,
        );
        return Err(IpcError::DestinationSlotsExhausted);
    };
    for (thread, pages) in task
        .vspace
        .pages
        .iter()
        .take(task.vspace.threads)
        .enumerate()
    {
        if windows
            .declare(
                id,
                thread,
                pages.transfer_window_addr,
                pages.transfer_window,
                pages.transfer_window_alias,
            )
            .is_err()
        {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                id,
            );
            return Err(IpcError::DestinationSlotsExhausted);
        }
    }

    let quota = declared_quota(shared_buffer_budget(generation).as_ref(), instance.name);
    if buffers
        .declare_quota(HolderId(u64::from(id.0)), quota)
        .is_err()
    {
        release_child(
            retirements,
            generation,
            tasks,
            windows,
            buffers,
            allocator,
            adaptive.as_deref_mut(),
            id,
        );
        return Err(IpcError::DestinationSlotsExhausted);
    }
    crate::diagnostic_println!(
        "SLIME_GRAPH quota task={} instance={} executable={} pages={} buffers={} mappings={} loans={}",
        id.0,
        instance.name,
        record.name,
        quota.byte_pages,
        quota.buffer_count,
        quota.mapping_count,
        quota.loan_count,
    );
    // As on the boot path, read back from the task record rather than from the
    // budget: the declared number and the live ceiling are two facts, and only
    // comparing them proves the declaration is what bounds the child (C10.2).
    crate::diagnostic_println!(
        "SLIME_MEM quota task={} instance={} declared={} installed={} base={:#x}",
        id.0,
        instance.name,
        match crate::generation::private_memory_budget_object(generation) {
            Some(Ok(budget)) => declared_private_memory_pages(Some(&budget), instance.name),
            _ => 0,
        },
        tasks.get(id).map_or(0, |task| task.private_memory.quota()),
        tasks.get(id).map_or(0, |task| task.private_memory.base()),
    );
    for granted in plan.granted.iter().take(plan.count) {
        let Some((_, destination, capability, _minted)) = granted else {
            continue;
        };
        if tasks
            .install_authority(id, *destination, *capability)
            .is_err()
        {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                id,
            );
            return Err(IpcError::DestinationSlotsExhausted);
        }
    }

    // so no parent passes it and the loop above never sees it. The root is
    // the only party that can install it, and preflight has already excluded
    // these from the count the parent must satisfy.
    let Ok(child) = generation.instance(plan.instance) else {
        release_child(
            retirements,
            generation,
            tasks,
            windows,
            buffers,
            allocator,
            adaptive.as_deref_mut(),
            id,
        );
        return Err(IpcError::BadCapability);
    };
    for index in 0..child.binding_count() {
        let Ok(binding) = generation.binding(child, index) else {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                id,
            );
            return Err(IpcError::BadCapability);
        };
        let Ok(grant) = generation.grant(binding.grant) else {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                id,
            );
            return Err(IpcError::BadCapability);
        };
        if grant.source != GrantEndpoint::Instance(plan.instance)
            || grant.target != GrantEndpoint::Instance(plan.instance)
        {
            continue;
        }
        // Resource 0 for every kind: B90 deleted the `Block` launch-order
        // ordinal, and the IO kinds carry their device identity in the
        // IO-resource authority table rather than here.
        let Some(capability) = declared_capability(grant.capability_kind, 0, grant.rights) else {
            continue;
        };
        if tasks
            .install_authority(id, binding.slot as u32, capability)
            .is_err()
        {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                id,
            );
            return Err(IpcError::DestinationSlotsExhausted);
        }
        // The evidence that a child's own declared authority reached it. Only
        // the root can place these — the parent holds no copy — so this is the
        // only point at which it is observable.
        crate::diagnostic_println!(
            "SLIME_GRAPH declared placed task={} child={} slot={} kind={}",
            parent.0,
            id.0,
            binding.slot,
            capability.kind_name(),
        );
    }
    Ok(id)
}

/// Tear a partially constructed child back down.
///
/// This is the single unwind owner after `TaskTable::create` succeeds. Each
/// resource release is idempotent, so every later failure can call it without
/// tracking which construction stages completed. Quota is released before the
/// task identity becomes unreachable, and the task's object span is revoked
/// last.
pub(super) fn release_child(
    retirements: &mut supervision::Retirements,
    generation: &Generation<'_>,
    tasks: &mut TaskTable<MAX_TASKS>,
    windows: &mut WindowTable<MAX_WINDOW_ENTRIES>,
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    adaptive: Option<&mut super::super::adaptive::AdaptivePolicy<'_>>,
    id: TaskId,
) {
    windows.release(id);
    buffers.release_quota(HolderId(u64::from(id.0)));
    // Read before reclamation clears the record. An unwound construction that
    // bound an incarnation must return it, or its entitlement would be
    // permanently held by a task that never ran.
    let binding = tasks.private_binding(id);
    let held_pages = tasks.get(id).map_or(0, |task| task.private_memory.pages());
    let instance = tasks
        .get(id)
        .and_then(|task| task.instance)
        .and_then(|index| generation.instance(index).ok())
        .map_or("", |instance| instance.name);
    let reclaimed = tasks.reclaim(allocator, id);
    // A revoke that did not complete leaves the task owned and its
    // incarnation quarantined; the exit and fault paths' retry settles it.
    if reclaimed.is_err() && !retirements.insert(id) {
        fatal!("SLIME_GRAPH FAIL pending retirement capacity task={}", id.0);
    }
    if let (Some(policy), Some(binding)) = (adaptive, binding.as_ref()) {
        policy.retire(
            allocator,
            id,
            instance,
            binding,
            reclaimed.is_ok(),
            held_pages,
        );
    }
    match reclaimed {
        Ok(cleanup) => crate::diagnostic_println!(
            "SLIME_GRAPH spawn unwound task={} slots={} arena={}",
            id.0,
            cleanup.slot_count(),
            cleanup.arena.index(),
        ),
        Err(error) => crate::diagnostic_println!(
            "SLIME_GRAPH spawn unwind incomplete task={} error={error:?}",
            id.0
        ),
    }
}

/// The live-child budget the generation declares for the component `task` is.
///
/// Zero when the task is not a launched component, or when the generation
/// declares no budget for it — deny by default, exactly as an absent
/// shared-buffer holder resolves to `HolderQuota::DENY`. A component the
/// manifest gives no budget spawns nothing.
pub(super) fn spawner_budget(
    generation: &Generation<'_>,
    _launched: &LaunchedInstances,
    tasks: &TaskTable<MAX_TASKS>,
    task: TaskId,
) -> usize {
    tasks
        .get(task)
        .and_then(|task| task.executable)
        .and_then(|executable| generation.executable(executable).ok())
        .map_or(0, |record| usize::from(record.spawn_budget))
}

/// Serve one `spawn`: validate, construct, activate, and hand the parent a
/// supervision handle.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_spawn(
    retirements: &mut supervision::Retirements,
    generation: &Generation<'_>,
    launched: &mut LaunchedInstances,
    tasks: &mut TaskTable<MAX_TASKS>,
    windows: &mut WindowTable<MAX_WINDOW_ENTRIES>,
    buffers: &mut SharedBufferTable,
    clock_service: &mut clock::ClockService,
    wait_set_service: &mut wait_set::WaitSetService,
    scheduling_service: &mut scheduling::SchedulingService,
    scheduling_policy: Option<&boot_contracts::scheduling_class::SchedulingClass<'_>>,
    lifecycle_service: &mut lifecycle::LifecycleService,
    lifecycle_policy: Option<&boot_contracts::lifecycle_policy::LifecyclePolicy<'_>>,
    timer_adapter: &mut PhysicalTimerAdapter,
    io_service: &mut IoResourceService,
    io_authority: &platform::AuthorityInventory,
    allocator: &mut ObjectAllocator,
    scratch: &ScratchPage,
    service_endpoint: sel4::cap::Endpoint,
    console_endpoint: sel4::cap::Endpoint,
    id: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
    spawns: &mut usize,
    adaptive: Option<&mut super::super::adaptive::AdaptivePolicy<'_>>,
) -> Response {
    let mut adaptive = adaptive;
    let executable_slot = words[0] as u32;
    // The wide reader (B15), because a grant array is not a message: at
    // `SPAWN_GRANT_RECORD_BYTES` each, the message bound admitted four records
    // where the oracle admits sixty-four. It refuses a descriptor naming any
    // capability itself — grants are logical slot numbers in the payload, and a
    // spawn carrying real seL4 capabilities is refused by `recv_request` before
    // reaching here.
    //
    // An empty grant list stages nothing, so a spawn granting no capabilities
    // still does not require a bound window: a zero-length transfer reports the
    // empty array, and `preflight_spawn_grants` reads zero records out of it.
    let frame = match transfer_window::read_staged_array(
        windows.bound(id, descriptor_thread(words[1])),
        words[1],
        words,
        scratch,
    ) {
        Ok(frame) => frame,
        Err(error) => return Response::error(error),
    };

    let Some(table) = tasks.authority(id) else {
        return Response::error(IpcError::InvalidOperation);
    };
    let Some(caller_instance) = tasks.get(id).and_then(|task| task.instance) else {
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn refused task={} slot={executable_slot} undeclared-instance",
            id.0,
        );
        return Response::error(IpcError::BadCapability);
    };
    let plan = match preflight_spawn_grants(
        generation,
        caller_instance,
        table,
        executable_slot,
        frame.bytes(),
        launched,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn refused task={} slot={executable_slot} ungranted",
                id.0,
            );
            return Response::error(error);
        }
    };
    let name = generation
        .instance(plan.instance)
        .map_or("<unknown>", |record| record.name);
    // `DestinationSlotsExhausted`, whose status is -5 — `ERR_OUT_OF_MEMORY`,
    if launched.task_for_instance(plan.instance).is_some() {
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn refused task={} child={name} class=instance-live",
            id.0,
        );
        return Response::error(IpcError::BadCapability);
    }
    // matching `sys_spawn`, which maps `BudgetExhausted` and
    // `TooManyTasks` alike to `ERR_OUT_OF_MEMORY` and everything else to
    // `ERR_BAD_CAP`. That distinction is the caller's business here in a way the
    // preflight refusals are not: a component that has hit its ceiling learns
    // something true about itself and can wait for a child to exit, whereas a
    // component naming an ungranted slot learns nothing about its table.
    let budget = spawner_budget(generation, launched, tasks, id);
    let live = tasks.live_children(id);
    if live >= budget {
        crate::diagnostic_println!(
            // `child=` rather than `component=`: the budget is the *caller's*,
            // and naming the child's component beside it read as though the
            // ceiling belonged to the thing being refused.
            "SLIME_GRAPH spawn refused task={} child={name} class=budget live={live} budget={budget}",
            id.0,
        );
        return Response::error(IpcError::DestinationSlotsExhausted);
    }
    // C9.4: exhaustion is terminal, so a spawn of an instance whose declared
    // attempt bound is spent is refused here rather than only at admission. A
    // supervisor that ignored its `RESTART_ADMIT` refusal and spawned anyway
    // would otherwise restart forever, which is the exact behaviour the
    // milestone's check forbids.
    if lifecycle_service.is_exhausted(plan.instance) {
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn refused task={} child={name} class=lifecycle-exhausted state={}",
            id.0,
            boot_contracts::lifecycle_policy::state_name(
                lifecycle::LifecycleService::terminal_state(lifecycle_policy)
            ),
        );
        return Response::error(IpcError::InvalidOperation);
    }
    // The declared backoff, enforced rather than trusted. `RESTART_ADMIT`
    // answered an instant; a supervisor that skips its own wait and spawns early
    // is refused by the same number it was given, so "backoff is observed
    // against C9.1's clock" is a property of the mechanism rather than of the
    // supervisor's loop.
    //
    // The refusal goes through `LifecycleError` so its status and its marker
    // class have one source — the same pair every other lifecycle refusal uses —
    // rather than being restated here beside the mechanism that decides it.
    let backoff = match timer_adapter.monotonic_now() {
        Ok(now) => lifecycle_service.restart_ready(plan.instance, now.0),
        // The clock the reservation was measured against is unreadable, so the
        // wait cannot be shown to have elapsed. Refused rather than admitted:
        // proceeding would honour a backoff by assumption.
        Err(_) => Err(lifecycle::LifecycleError::Malformed),
    };
    if let Err(error) = backoff {
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn refused task={} child={name} class={}",
            id.0,
            lifecycle_error_class(error),
        );
        return Response::error(lifecycle_error_status(error));
    }
    // Declared health dependencies are evaluated on *every* start, unlike
    // `Instance.dependencies`' one-shot autostart barrier: a replacement whose
    // dependency has since left the state the edge names must wait for the same
    // condition its predecessor was launched under.
    if !lifecycle_service.dependencies_satisfied(lifecycle_policy, generation, plan.instance) {
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn refused task={} child={name} class=lifecycle-dependency",
            id.0,
        );
        return Response::error(IpcError::WouldBlock);
    }

    crate::diagnostic_println!(
        "SLIME_GRAPH spawn authorized task={} slot={executable_slot} component={name} grants={}",
        id.0,
        plan.count,
    );

    let child = match construct_child(
        retirements,
        generation,
        tasks,
        windows,
        buffers,
        allocator,
        scratch,
        service_endpoint,
        console_endpoint,
        id,
        &plan,
        adaptive.as_deref_mut(),
    ) {
        Ok(child) => child,
        Err(error) => {
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error={error:?}",
                id.0,
            );
            return Response::error(error);
        }
    };
    let (child_arena, child_cnode, child_cnode_bits) = match tasks.get(child) {
        Some(task) => (task.cleanup.arena, task.cnode, task.cnode_size_bits),
        None => {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            return Response::error(IpcError::DestinationSlotsExhausted);
        }
    };
    let copied = match unsafe { &*ptr::addr_of!(PEER_ENDPOINTS) }.install_instance(
        generation,
        plan.instance,
        child,
        allocator,
        child_arena,
        child_cnode,
        child_cnode_bits,
    ) {
        Ok(installed) => installed,
        Err(error) => {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error=EndpointInstall({error:?})",
                id.0
            );
            return Response::error(IpcError::BadCapability);
        }
    };
    let notification_copied = match unsafe { &*ptr::addr_of!(NOTIFICATIONS) }.install_instance(
        generation,
        plan.instance,
        child,
        allocator,
        child_arena,
        child_cnode,
        child_cnode_bits,
    ) {
        Ok(installed) => installed,
        Err(error) => {
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error=NotificationInstall({error:?})",
                id.0
            );
            return Response::error(IpcError::BadCapability);
        }
    };
    // C8.13.3: both installs filled slots the generation declared, in the
    // component's own logical numbering, so they belong to the child's
    // declared-space count -- the space `capabilitySlots` budgets. Credited
    // rather than observed because every install into that space is a root
    // operation, so the count is complete without asking the kernel.
    if let Some(child_task) = tasks.get_mut(child) {
        child_task
            .cspace
            .installed((copied + notification_copied) as u32);
    }
    let child_clock = match clock::authority_object(generation) {
        Some(Ok(authority)) => clock_service.declare(
            Some(&authority),
            generation,
            unsafe { &*ptr::addr_of!(NOTIFICATIONS) },
            allocator,
            child_arena,
            child,
            plan.instance,
        ),
        Some(Err(_)) => Err(clock::ClockError::Malformed),
        None => clock_service.declare(
            None,
            generation,
            unsafe { &*ptr::addr_of!(NOTIFICATIONS) },
            allocator,
            child_arena,
            child,
            plan.instance,
        ),
    };
    let child_clock = match child_clock {
        Ok(authority) => authority,
        Err(error) => {
            clock_service.clear_task(child);
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error=ClockInstall({error:?})",
                id.0
            );
            return Response::error(IpcError::BadCapability);
        }
    };
    crate::diagnostic_println!(
        "SLIME_CLOCK authority task={} instance={} flags={:#x} timers={} badge={:#x}",
        child.0,
        name,
        child_clock.flags(),
        child_clock.timer_quota(),
        child_clock.timer_badge(),
    );
    // C9.2's supervision sources for the child, on the same rule as its clock
    // authority: declared before it runs, from the same generation resource, so
    // a spawned waiter's sources are not a boot-only property.
    let child_sources = match wait_set_service.declare(
        wait_set::source_object(generation)
            .and_then(Result::ok)
            .as_ref(),
        generation,
        unsafe { &*ptr::addr_of!(NOTIFICATIONS) },
        allocator,
        child_arena,
        child,
        plan.instance,
    ) {
        Ok(declared) => declared,
        Err(error) => {
            wait_set_service.clear_task(child);
            clock_service.clear_task(child);
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error=WaitSetInstall({error:?})",
                id.0
            );
            return Response::error(IpcError::BadCapability);
        }
    };
    if child_sources != 0 {
        crate::diagnostic_println!(
            "SLIME_WAIT supervision task={} instance={name} sources={child_sources}",
            child.0,
        );
    }
    // C9.3's declared class for the child, on the same rule as its clock
    // authority and wake sources: recorded before it runs, from the same
    // generation resource, so a spawned instance's class is not a boot-only
    // property. Its band's priority is already on the TCB — `TaskTable::create`
    // applied the plan's `ScheduleRecord` above — so this records the class the
    // root will answer `CLASS_READ` with and promote against.
    let child_class = match scheduling_service.declare(
        scheduling_policy,
        generation,
        child,
        plan.instance,
    ) {
        Ok(class) => class,
        Err(error) => {
            scheduling_service.release(child);
            wait_set_service.clear_task(child);
            clock_service.clear_task(child);
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error=SchedulingInstall({error:?})",
                id.0
            );
            return Response::error(IpcError::BadCapability);
        }
    };
    if scheduling_policy.is_some() {
        crate::diagnostic_println!(
            "SLIME_SCHED class task={} instance={name} class={} priority={}",
            child.0,
            child_class.name(),
            child_class.priority(),
        );
    }
    // C9.4's declared lifecycle state, on the same rule and for the same reason:
    // recorded before the child runs, from the same generation resource, so a
    // spawned instance enters the graph's declared entry state rather than
    // inheriting whatever its predecessor left. A restart is exactly this path,
    // so this is also where a replacement's state is re-derived.
    let child_state = match lifecycle_service.declare(lifecycle_policy, child, plan.instance) {
        Ok(state) => state,
        Err(error) => {
            lifecycle_service.release(child);
            scheduling_service.release(child);
            wait_set_service.clear_task(child);
            clock_service.clear_task(child);
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_GRAPH spawn failed task={} component={name} error=LifecycleInstall({error:?})",
                id.0
            );
            return Response::error(IpcError::BadCapability);
        }
    };
    if lifecycle_policy.is_some() {
        crate::diagnostic_println!(
            "SLIME_LIFECYCLE state task={} instance={name} state={} attempts={}",
            child.0,
            boot_contracts::lifecycle_policy::state_name(child_state),
            lifecycle_service.attempts_remaining(lifecycle_policy, plan.instance, generation),
        );
    }
    // The parent's handle, installed before the child runs. A child that exited
    // before its parent held a handle would leave the parent waiting on a task
    // it can never learn the fate of, so the ordering is load-bearing rather
    // than tidy.
    //
    // C9.3 rides on this handle: the promote bit is set exactly when the
    // generation declares a promotion edge from *this spawner's instance* to
    // *this child's instance*. Deriving it here rather than granting it
    // separately is what keeps the two statements from disagreeing — the
    // operation resolves the right off the capability, and the capability
    // carries the right only where the declared policy already says so.
    let promote = scheduling_policy.is_some_and(|policy| {
        let holder = launched
            .instance_for_task(id)
            .and_then(|instance| generation.instance(instance).ok())
            .map(|instance| boot_contracts::scheduling_class::instance_identity(instance.name));
        let subject = boot_contracts::scheduling_class::instance_identity(name);
        holder.is_some_and(|holder| policy.promotion_ceiling(&holder, &subject).is_some())
    });
    // C9.4 rides on the same handle, for C9.3's reason: the right on the
    // capability and the edge in the resource are one fact with one source.
    //
    // `lifecycleRestart` is set where the policy declares a restart bound for
    // *this child's instance*, because that is exactly the subject a supervisor
    // may charge attempts against, and the root mints a handle only for a
    // spawner over its own child — which is why admission refuses a restart bound
    // on a root-autostart instance no handle could ever name.
    //
    // The parameter bits are set where the policy declares a parameter edge from
    // this spawner's instance to this child's, and read and write are separately
    // derived: a supervisor granted only read gets only read.
    let holder_identity = launched
        .instance_for_task(id)
        .and_then(|instance| generation.instance(instance).ok())
        .map(|instance| boot_contracts::lifecycle_policy::instance_identity(instance.name));
    let subject_identity = boot_contracts::lifecycle_policy::instance_identity(name);
    let restartable =
        lifecycle_policy.is_some_and(|policy| policy.restart_for(&subject_identity).is_some());
    let parameter_flags = lifecycle_policy
        .zip(holder_identity)
        .and_then(|(policy, holder)| policy.parameter_authority(&holder, &subject_identity))
        .unwrap_or(0);
    let handle = tasks.authority_mut(id).and_then(|table| {
        let slot = table.free_slot_from(1)?;
        let rights = RIGHT_SUPERVISE
            | if plan.transferable_supervision {
                RIGHT_TRANSFER
            } else {
                0
            }
            | if promote {
                boot_contracts::generation::RIGHT_SCHEDULING_PROMOTE
            } else {
                0
            }
            | if restartable {
                boot_contracts::generation::RIGHT_LIFECYCLE_RESTART
            } else {
                0
            }
            | if parameter_flags & boot_contracts::lifecycle_policy::PARAMETER_READ != 0 {
                boot_contracts::generation::RIGHT_PARAMETER_READ
            } else {
                0
            }
            | if parameter_flags & boot_contracts::lifecycle_policy::PARAMETER_WRITE != 0 {
                boot_contracts::generation::RIGHT_PARAMETER_WRITE
            } else {
                0
            };
        let capability = graph::CapabilityEntry::supervision(child, rights)?;
        table.install(slot, capability).ok()?;
        Some(slot)
    });
    let Some(handle) = handle else {
        // The parent's table is full. The copied child table can simply be
        // released; the parent's grants were never consumed.
        lifecycle_service.release(child);
        scheduling_service.release(child);
        wait_set_service.clear_task(child);
        clock_service.clear_task(child);
        release_child(
            retirements,
            generation,
            tasks,
            windows,
            buffers,
            allocator,
            adaptive.as_deref_mut(),
            child,
        );
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn failed task={} component={name} error=NoHandleSlot",
            id.0,
        );
        return Response::error(IpcError::DestinationSlotsExhausted);
    };

    if tasks.activate(child).is_err() {
        if let Some(table) = tasks.authority_mut(id) {
            table.drop_slot(handle);
        }
        // The lifecycle row goes with the class row, and omitting it leaks a
        // `TaskRow` for a task that never ran — which `dependencies_satisfied`
        // would later read as a live dependency, and which fills a fixed table
        // for the boot's lifetime (found by review).
        lifecycle_service.release(child);
        scheduling_service.release(child);
        wait_set_service.clear_task(child);
        clock_service.clear_task(child);
        release_child(
            retirements,
            generation,
            tasks,
            windows,
            buffers,
            allocator,
            adaptive.as_deref_mut(),
            child,
        );
        crate::diagnostic_println!(
            "SLIME_GRAPH spawn failed task={} component={name} error=Activate",
            id.0,
        );
        return Response::error(IpcError::DestinationSlotsExhausted);
    }
    if let Some(quota) = crate::generation::io_resource_budget_object(generation)
        .and_then(Result::ok)
        .and_then(|budget| budget.quota_for(&boot_contracts::io_resource::driver_identity(name)))
    {
        let shared = io_authority.device(0).is_some_and(|device| {
            io_authority
                .device(1)
                .is_some_and(|other| other.region == device.region)
        });
        if let Err(error) = install_driver(
            io_service,
            crate::io_resource::DriverId(u64::from(child.0)),
            plan.instance,
            quota,
            shared,
        ) {
            if let Some(table) = tasks.authority_mut(id) {
                table.drop_slot(handle);
            }
            lifecycle_service.release(child);
            scheduling_service.release(child);
            wait_set_service.clear_task(child);
            clock_service.clear_task(child);
            release_child(
                retirements,
                generation,
                tasks,
                windows,
                buffers,
                allocator,
                adaptive.as_deref_mut(),
                child,
            );
            crate::diagnostic_println!(
                "SLIME_IO FAIL spawned quota install task={} instance={} error={error:?}",
                child.0,
                name
            );
            return Response::error(IpcError::BadCapability);
        }
        crate::diagnostic_println!(
            "SLIME_IO quota task={} instance={} devices={} shared_granule={}",
            child.0,
            name,
            io_authority.len(),
            shared as u8
        );
    }
    if launched
        .record(plan.instance, plan.executable, child)
        .is_err()
    {
        if let Some(table) = tasks.authority_mut(id) {
            table.drop_slot(handle);
        }
        lifecycle_service.release(child);
        scheduling_service.release(child);
        wait_set_service.clear_task(child);
        clock_service.clear_task(child);
        release_child(
            retirements,
            generation,
            tasks,
            windows,
            buffers,
            allocator,
            adaptive,
            child,
        );
        return Response::error(IpcError::BadCapability);
    }
    // The satisfied restart reservation, cleared only now that the replacement
    // is genuinely live. Cleared here rather than before activation, because a
    // launch that unwinds must leave the reservation the attempt was charged
    // against in place: discarding it early would let the next spawn skip a
    // backoff the supervisor was already charged for (found by review). And
    // cleared at all, rather than at admission, because the refusal above must
    // hold until a replacement actually launches.
    lifecycle_service.clear_restart_reservation(plan.instance);
    let supervision_grants = plan
        .granted
        .iter()
        .take(plan.count)
        .flatten()
        .filter(|(_, _, capability, _)| {
            matches!(capability, graph::CapabilityEntry::Supervision(_))
        })
        .count();
    let buffer_factory_grants = plan
        .granted
        .iter()
        .take(plan.count)
        .flatten()
        .filter(|(_, _, capability, _)| {
            matches!(capability, graph::CapabilityEntry::BufferFactory(_))
        })
        .count();
    *spawns += 1;
    crate::diagnostic_println!(
        "SLIME_GRAPH spawned task={} child={} component={name} grants={} endpoints={copied} notifications={notification_copied} handle={handle} supervision_grants={supervision_grants} buffer_factory_grants={buffer_factory_grants}",
        id.0,
        child.0,
        plan.count,
    );
    Response::success(0, handle as sel4::Word)
}
