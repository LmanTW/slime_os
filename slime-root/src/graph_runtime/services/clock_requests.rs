use super::*;

pub(super) fn serve_clock_request(
    service: &mut clock::ClockService,
    timer_adapter: &mut PhysicalTimerAdapter,
    task: TaskId,
    label: sel4::Word,
    operand: sel4::Word,
) -> Response {
    let authority = service.authority(task);
    let mut now = || {
        timer_adapter
            .monotonic_now()
            .map_err(|_| clock::ClockError::TimeOverflow)
    };
    let outcome = match label {
        clock_labels::MONOTONIC_READ => {
            now().map(|instant| (clock::ClockService::read_monotonic(instant) as i64, 0))
        }
        clock_labels::TIMER_ARM => now()
            .and_then(|instant| service.arm(authority, task, instant, operand))
            .and_then(|(timer_id, programming)| {
                apply_deadline_programming(timer_adapter, programming)
                    .map_err(|_| clock::ClockError::TimeOverflow)?;
                Ok((timer_id.0 as i64, service.live_timers() as sel4::Word))
            }),
        clock_labels::TIMER_CANCEL => now()
            .and_then(|instant| service.cancel(authority, task, instant, TimerId(operand)))
            .and_then(|programming| {
                apply_deadline_programming(timer_adapter, programming)
                    .map_err(|_| clock::ClockError::TimeOverflow)?;
                Ok((0, service.live_timers() as sel4::Word))
            }),
        clock_labels::SIMULATED_READ => service
            .read_simulated(authority)
            .map(|value| (value as i64, 0)),
        clock_labels::SIMULATED_ADVANCE => service
            .advance_simulated(authority, operand)
            .map(|previous| (previous as i64, 0)),
        clock_labels::RATE_READ => Ok((
            clock::ClockService::read_rate(timer_adapter.frequency_hz()) as i64,
            0,
        )),
        _ => return Response::error(IpcError::UnsupportedOperation),
    };
    match outcome {
        Ok((result, aux)) => {
            if super::diagnostic_once::clock_served(task.0, label) {
                crate::diagnostic_println!(
                    "SLIME_CLOCK served task={} label={label} result={result} live={}",
                    task.0,
                    service.live_timers(),
                );
            }
            Response::success(result, aux)
        }
        Err(error) => {
            if super::diagnostic_once::clock_refused(task.0, label, clock_error_index(error)) {
                crate::diagnostic_println!(
                    "SLIME_CLOCK refused task={} label={label} class={} detail={error:?}",
                    task.0,
                    clock_error_class(error),
                );
            }
            Response::error(clock_error_status(error))
        }
    }
}

pub(super) fn service_clock_source(
    service: &mut clock::ClockService,
    timer_adapter: &mut PhysicalTimerAdapter,
) {
    let clock::TimerSourceOutcome { expired, failure } =
        service.service_timer_source(timer_adapter);
    if let Some(failure) = failure {
        match failure {
            clock::TimerSourceFailure::Clock(error) => {
                crate::diagnostic_println!("SLIME_CLOCK FAIL expiry clock error={error:?}");
                return;
            }
            clock::TimerSourceFailure::Scheduler(error) => {
                crate::diagnostic_println!("SLIME_CLOCK FAIL expiry scheduler error={error:?}");
                return;
            }
            clock::TimerSourceFailure::Program(error) => crate::diagnostic_println!(
                "SLIME_CLOCK FAIL deadline reprogramming error={error:?} due={}",
                expired.due(),
            ),
            clock::TimerSourceFailure::Acknowledge(error) => crate::diagnostic_println!(
                "SLIME_CLOCK FAIL irq acknowledgement error={error:?} due={}",
                expired.due(),
            ),
        }
    }
    let due = expired.due();
    let mut delivered = 0;
    for task in expired.tasks() {
        match service.authority(task).signal_timer() {
            Ok(()) => delivered += 1,
            Err(error) => crate::diagnostic_println!(
                "SLIME_CLOCK FAIL expiry signal task={} error={error:?}",
                task.0,
            ),
        }
    }
    crate::diagnostic_println!(
        "SLIME_CLOCK expired due={due} delivered={delivered} live={}",
        service.live_timers(),
    );
}

pub(super) fn drop_task_clock(
    service: &mut clock::ClockService,
    timer_adapter: &mut PhysicalTimerAdapter,
    task: TaskId,
) {
    let before = service.live_timers();
    let now = match timer_adapter.monotonic_now() {
        Ok(now) => now,
        Err(error) => {
            crate::diagnostic_println!(
                "SLIME_CLOCK FAIL teardown clock task={} error={error:?}",
                task.0,
            );
            service.clear_task(task);
            return;
        }
    };
    match service.cancel_task(task, now) {
        Ok(programming) => {
            if apply_deadline_programming(timer_adapter, programming).is_err() {
                crate::diagnostic_println!("SLIME_CLOCK FAIL teardown programming task={}", task.0,);
            }
        }
        Err(error) => {
            crate::diagnostic_println!("SLIME_CLOCK FAIL teardown task={} error={error:?}", task.0,)
        }
    }
    service.clear_task(task);
    crate::diagnostic_println!(
        "SLIME_CLOCK teardown task={} before={before} live={}",
        task.0,
        service.live_timers(),
    );
}

pub(super) const fn clock_error_status(error: clock::ClockError) -> IpcError {
    match error {
        clock::ClockError::Undeclared | clock::ClockError::InvalidNotification => {
            IpcError::BadCapability
        }
        clock::ClockError::TimerLimit => IpcError::DestinationSlotsExhausted,
        clock::ClockError::TimerNotFound => IpcError::BadCapability,
        clock::ClockError::Malformed
        | clock::ClockError::TimeOverflow
        | clock::ClockError::SimulatedTimeOverflow => IpcError::InvalidOperation,
    }
}

/// The refusal's position in [`clock_error_class`]'s vocabulary, the key the
/// once-per-key diagnostic gate remembers.
const fn clock_error_index(error: clock::ClockError) -> u8 {
    match error {
        clock::ClockError::Undeclared => 0,
        clock::ClockError::Malformed => 1,
        clock::ClockError::InvalidNotification => 2,
        clock::ClockError::TimerLimit => 3,
        clock::ClockError::TimerNotFound => 4,
        clock::ClockError::TimeOverflow => 5,
        clock::ClockError::SimulatedTimeOverflow => 6,
    }
}

pub(super) const fn clock_error_class(error: clock::ClockError) -> &'static str {
    match error {
        clock::ClockError::Undeclared => "undeclared",
        clock::ClockError::Malformed => "malformed",
        clock::ClockError::InvalidNotification => "notification",
        clock::ClockError::TimerLimit => "timer-limit",
        clock::ClockError::TimerNotFound => "timer-absent",
        clock::ClockError::TimeOverflow => "time-overflow",
        clock::ClockError::SimulatedTimeOverflow => "simulated-overflow",
    }
}
