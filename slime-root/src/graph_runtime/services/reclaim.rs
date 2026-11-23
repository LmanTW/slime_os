use super::*;

pub(super) fn record_termination(
    terminations: &mut supervision::Terminations,
    tasks: &TaskTable<MAX_TASKS>,
    child: TaskId,
    termination: supervision::Termination,
) {
    if terminations.record(child, termination) {
        return;
    }
    let freed = supervision::sweep(terminations, tasks);
    if !terminations.record(child, termination) {
        crate::diagnostic_println!(
            "SLIME_GRAPH FAIL termination lost task={} reason=records-full",
            child.0
        );
    } else {
        crate::diagnostic_println!(
            "SLIME_GRAPH supervision swept freed={freed} live={}",
            terminations.len()
        );
    }
}

pub(super) fn reclaim_dead_task(
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    id: TaskId,
    vspace: VSpaceCap,
) -> bool {
    let holder = HolderId(u64::from(id.0));
    let charged = buffers.holder_buffers(holder)
        + buffers.holder_mappings(holder)
        + buffers.holder_loans(holder);
    let mut adapter = BufferAdapter::new(allocator);
    if buffers.retry_vspace_orphans(&mut adapter, vspace) != 0 {
        return false;
    }
    // Receiver-only loans have no local charge. Settlement must examine the
    // relationships even when this holder's occupancy is zero.
    match buffers.reclaim_holder(&mut adapter, holder) {
        Ok(actions) => {
            if charged != 0 || !actions.is_empty() {
                crate::diagnostic_println!(
                    "SLIME_GRAPH holder reclaimed task={} charges={charged} actions={}",
                    id.0,
                    actions.len()
                );
            }
        }
        Err(error) => {
            crate::diagnostic_println!(
                "SLIME_GRAPH holder reclaim incomplete task={} class={}",
                id.0,
                buffer_error_class(error)
            );
            return false;
        }
    }
    if adapter.settle_pending_cleanup().is_err() {
        return false;
    }
    if buffers.release_quota(holder) {
        crate::diagnostic_println!(
            "SLIME_GRAPH quota released task={} live={}",
            id.0,
            buffers.quota_count()
        );
    }
    true
}

/// The half of teardown `reclaim_dead_task` does not do. That function settles
/// what the task *held* — channels, buffers, loans, in-flight capabilities —
/// and this returns what the task *is*. Both death paths need both: a task
/// whose peers were all notified and whose buffers were all reclaimed still
/// occupies a `TaskTable` entry and still holds every root CSlot its
/// construction allocated.
///
/// Two things depend on it, which is why it is not merely tidiness:
///
/// - **`TaskTable::live_children`** counts the table, so a dead child that
///   stays in it consumes its parent's declared `spawnBudget` forever. The
///   budget would be a lifetime cap rather than the live-child cap the
///   generation declares and `sys_spawn` enforces.
/// - **`CleanupRecord::revoke`** is reachable only from `TaskTable::reclaim`,
///   so without this every component that exits or faults leaks its root
///   CSlots for the rest of the boot.
///
/// Reported rather than fatal: the objects stay recorded as the table's own
/// state and the terminal marker's count is what surfaces them, and a graph
/// whose other components are still running should not be stopped over one
/// task's cleanup.
pub(super) fn reclaim_task_objects(
    generation: &Generation<'_>,
    launched: &mut LaunchedInstances,
    tasks: &mut TaskTable<MAX_TASKS>,
    allocator: &mut ObjectAllocator,
    mut adaptive: Option<&mut super::super::adaptive::AdaptivePolicy<'_>>,
    reclaimed: &mut usize,
    id: TaskId,
) -> bool {
    // Read while the record still exists: reclamation clears the entry, and
    // the entitlement this incarnation returns to is a property of the task
    // that is about to stop existing.
    let binding = tasks.private_binding(id);
    let instance = tasks
        .get(id)
        .and_then(|task| task.instance)
        .and_then(|index| generation.instance(index).ok())
        .map_or("", |instance| instance.name);
    let held_pages = tasks.get(id).map_or(0, |task| task.private_memory.pages());
    // One injected revoke failure for the first published adaptive holder that
    // dies, so the quarantine-and-retry path is observed on a real task rather
    // than modelled: a reclamation that did not recover the machine's memory
    // must refund nothing, and exactly one retry must return it.
    #[cfg(slime_private_conservation)]
    if binding.is_some() && launched.instance_for_task(id).is_some() {
        use core::sync::atomic::{AtomicBool, Ordering};
        static ARMED: AtomicBool = AtomicBool::new(true);
        if ARMED.swap(false, Ordering::Relaxed) {
            crate::object_allocator::elastic::arm_arena_revoke_failure();
            crate::diagnostic_println!(
                "SLIME_MEM adaptive injected kind=revoke task={} instance={instance}",
                id.0,
            );
        }
    }
    match tasks.reclaim(allocator, id) {
        Ok(record) => {
            *reclaimed += record.slot_count();
            // The revoke succeeded, so the pages are genuinely gone and the
            // entitlement may have them back.
            if let (Some(policy), Some(binding)) = (adaptive.as_deref_mut(), binding.as_ref()) {
                policy.retire(allocator, id, instance, binding, true, held_pages);
            }
        }
        Err(error) => {
            // Capacity the machine has not recovered is never returned: the
            // incarnation stays charged and quarantined until a retry lands.
            if let (Some(policy), Some(binding)) = (adaptive, binding.as_ref()) {
                policy.retire(allocator, id, instance, binding, false, 0);
            }
            crate::diagnostic_println!(
                "SLIME_GRAPH task reclaim incomplete task={} error={error:?}",
                id.0
            );
            return false;
        }
    }
    launched.release_by_task(id);
    crate::diagnostic_println!(
        "SLIME_ROOT image reclaimed task={} instance={} live_slots={} live_objects={} live_bytes={} allocation_descriptors_free={}",
        id.0,
        instance,
        allocator.live_slots(),
        allocator.live_objects(),
        allocator.live_bytes(),
        allocator.allocation_descriptors_free(),
    );
    for peer in tasks.tasks() {
        let Some(peer_instance) = peer
            .instance
            .and_then(|index| generation.instance(index).ok())
        else {
            continue;
        };
        if let Ok((slots, objects, bytes)) = allocator.arena_usage(peer.cleanup.arena) {
            crate::diagnostic_println!(
                "SLIME_ROOT image peer task={} instance={} slots={} objects={} bytes={}",
                peer.id.0,
                peer_instance.name,
                slots,
                objects,
                bytes,
            );
        }
    }
    report_memory_census(allocator, tasks, id.0);
    // C10.4: the allocator's own free capacity, printed at the one point in the
    // boot where a task has just returned everything it held.
    //
    // Every count above is of things the root *tracks* — CSlots reclaimed,
    // tasks live, buffers released — and each is reported by the same
    // bookkeeping that would be wrong if reclamation were broken. B9 is the
    // standing evidence that this is not a hypothetical: terminated tasks were
    // marked terminated and their buffers reclaimed while thirteen frames per
    // spawn were never returned, and every counter the root printed agreed with
    // every other one throughout.
    //
    // These three are read from the allocator's watermarks instead, so a leak
    // shows up as a number that fails to come back rather than as a
    // disagreement between two tallies that share an author. `slots` and
    // `bytes` are what a repeated spawn/exit workload must return to its
    // starting value; `live_objects` is what must return to *its* starting
    // value even though the arena is reused rather than freed.
    crate::diagnostic_println!(
        "SLIME_ROOT reclaim census task={} slots={} bytes={} live_objects={} extent_reuses={}",
        id.0,
        allocator.slots_remaining(),
        allocator.untyped_bytes_remaining(),
        allocator.live_objects(),
        allocator.extents_reused(),
    );
    true
}

pub(super) fn report_memory_census(
    allocator: &ObjectAllocator,
    tasks: &TaskTable<MAX_TASKS>,
    retired: u32,
) {
    crate::diagnostic_println!(
        "SLIME_MEM census retired={} free_slots={} live_objects={} live_bytes={} untyped={} reusable={} anchors={} mapped_pages={} allocations_free={} extents_free={} shared_reusable={} shared_retained={} shared_anchors={} active_extent_bytes={} preserved_bytes={} preserved_anchors={} infrastructure_owned={}",
        retired,
        allocator.free_slots(),
        allocator.live_objects(),
        allocator.live_bytes(),
        allocator.untyped_bytes_remaining(),
        allocator.reusable_extent_bytes(),
        allocator.reusable_extent_anchors(),
        tasks.private_memory().total_pages(),
        allocator.allocation_descriptors_free(),
        allocator.extent_descriptors_free(),
        allocator.reusable_shared_bytes(),
        allocator.retained_shared_bytes(),
        allocator.retained_shared_anchors(),
        allocator.active_extent_bytes(),
        allocator.preserved_bytes_remaining(),
        allocator.preserved_anchor_count(),
        allocator.infrastructure_owned_bytes(),
    );
}

/// Stable name for a private-memory refusal, for the root's own marker (C10.1).
///
/// A short token rather than the `Debug` rendering, because a gate asserts on
/// it: the fields inside each variant are diagnostic detail that varies with
/// the request, while the *cause* is the thing a check must be able to pin.
/// Both are emitted — this as `cause=`, the full variant as `detail=` — so the
/// marker names the class without hiding the numbers.
pub fn private_memory_cause(error: &private_memory::GrowError) -> &'static str {
    match error {
        private_memory::GrowError::DeltaOverflow { .. } => "delta-overflow",
        private_memory::GrowError::ReservationExceeded { .. } => "reservation",
        private_memory::GrowError::QuotaExceeded { .. } => "quota",
        private_memory::GrowError::TotalExceeded { .. } => "root-ceiling",
        private_memory::GrowError::Frames { .. } => "frames",
    }
}
