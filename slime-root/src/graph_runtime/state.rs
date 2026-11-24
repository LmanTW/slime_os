use super::*;

/// Rights recorded on a shared buffer's own slot.
///
/// The region's real authority lives in the `BufferHandle` the table issued and
/// the quota it charged; this slot's rights only say the task holds it at all,
/// so the buffer plane's own checks stay the single place rights are decided.
pub(super) const RIGHT_BUFFER_ALL: u64 = u64::MAX;

/// Generation-global native object catalogues. Objects live for the generation;
/// child-local derived capabilities are charged to and reclaimed with each task.
pub(super) static mut PEER_ENDPOINTS: peer_endpoint::PeerEndpointTable =
    peer_endpoint::PeerEndpointTable::new();
pub(super) static mut NOTIFICATIONS: notification::NotificationTable =
    notification::NotificationTable::new();
pub(super) static mut CLOCK_SERVICE: clock::ClockService = clock::ClockService::new();
pub(super) static mut WAIT_SET_SERVICE: wait_set::WaitSetService = wait_set::WaitSetService::new();
pub(super) static mut SCHEDULING_SERVICE: scheduling::SchedulingService =
    scheduling::SchedulingService::new();
pub(super) static mut LIFECYCLE_SERVICE: lifecycle::LifecycleService =
    lifecycle::LifecycleService::new();

/// The launch phase's task and transfer-window tables, and its record of which
/// declared instances were launched.
///
/// These generation-lived tables stay off the bounded root stack. They are
/// initialized once before launch and retained for the graph lifetime.
///
/// `MaybeUninit` rather than `TaskTable::new()` directly, for the same reason
/// and by the same pattern as `main`'s `OBJECT_ALLOCATOR`. `Option<Task>`'s
/// niche makes `None` the byte `0x2`, not zero, so a `const`-initialized
/// `[Option<Task>; 48]` is not all-zero and the linker must place it in
/// `.data` — 163 KiB of image, and therefore ~40 root CSlots, to store 48
/// non-zero tag bytes. Uninitialized storage is `.bss`, costs nothing in the
/// image, and is written exactly once by [`init_launch_tables`] before any
/// reference is handed out.
pub(super) static mut LAUNCH_TASKS: core::mem::MaybeUninit<TaskTable<MAX_TASKS>> =
    core::mem::MaybeUninit::uninit();
pub(super) static mut LAUNCH_WINDOWS: core::mem::MaybeUninit<WindowTable<MAX_WINDOW_ENTRIES>> =
    core::mem::MaybeUninit::uninit();
pub(super) static mut LAUNCH_INSTANCES: LaunchedInstances = LaunchedInstances::new();

/// Initialize the launch tables and borrow them for the rest of the phase.
///
/// Called once, from the one place that owns the launch phase. Returning the
/// references from the same call that writes them is what keeps "initialized
/// before use" a property of the code rather than a rule a caller must
/// remember.
pub(super) fn init_launch_tables() -> (
    &'static mut TaskTable<MAX_TASKS>,
    &'static mut WindowTable<MAX_WINDOW_ENTRIES>,
    &'static mut LaunchedInstances,
) {
    // SAFETY: root startup is single-threaded and `launch_instance_graph` runs
    // once, so this is the only writer and the only borrow of each static.
    unsafe {
        (&raw mut LAUNCH_TASKS).write(core::mem::MaybeUninit::new(TaskTable::new()));
        (&raw mut LAUNCH_WINDOWS).write(core::mem::MaybeUninit::new(WindowTable::new()));
        (
            (&raw mut LAUNCH_TASKS)
                .cast::<TaskTable<MAX_TASKS>>()
                .as_mut()
                .unwrap(),
            (&raw mut LAUNCH_WINDOWS)
                .cast::<WindowTable<MAX_WINDOW_ENTRIES>>()
                .as_mut()
                .unwrap(),
            (&raw mut LAUNCH_INSTANCES).as_mut().unwrap(),
        )
    }
}

/// Exports one sender may hold that no receiver has imported yet.
pub(super) const MAX_EXPORTS_PER_SENDER: usize = 4;
/// Room for every task's share, so no sender can take another sender's.
pub(super) const MAX_CAPABILITY_EXPORTS: usize = MAX_TASKS * MAX_EXPORTS_PER_SENDER;
#[derive(Clone, Copy)]
pub(super) struct CapabilityExport {
    pub(super) id: u32,
    pub(super) sender: TaskId,
    pub(super) receiver: TaskId,
    pub(super) capability: graph::CapabilityEntry,
    pub(super) ticket: Option<sel4::CPtrBits>,
    pub(super) sender_ticket_slot: Option<sel4::CPtrBits>,
    pub(super) retain: bool,
    pub(super) finalized: bool,
}
pub(super) struct CapabilityExports {
    pub(super) entries: [Option<CapabilityExport>; MAX_CAPABILITY_EXPORTS],
    pub(super) next_id: u32,
    pub(super) exported: usize,
    pub(super) imported: usize,
    pub(super) cancelled: usize,
    pub(super) finalized: usize,
}
impl CapabilityExports {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_CAPABILITY_EXPORTS],
            next_id: 1,
            exported: 0,
            imported: 0,
            cancelled: 0,
            finalized: 0,
        }
    }
    /// A free entry for `sender`, or none once it holds its share.
    pub(super) fn admit(&self, sender: TaskId) -> Option<usize> {
        let held = self
            .entries
            .iter()
            .flatten()
            .filter(|entry| entry.sender == sender);
        if held.count() >= MAX_EXPORTS_PER_SENDER {
            return None;
        }
        self.entries.iter().position(Option::is_none)
    }
    /// Take one export that names `task` as its sender or as its receiver.
    pub(super) fn take_of(&mut self, task: TaskId) -> Option<CapabilityExport> {
        self.entries
            .iter_mut()
            .find(|entry| {
                entry.is_some_and(|entry| entry.sender == task || entry.receiver == task)
            })?
            .take()
    }
    pub(super) fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }
    pub(super) fn get_mut(&mut self, id: u32) -> Option<&mut CapabilityExport> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.id == id)
    }
    pub(super) fn remove(&mut self, id: u32) -> Option<CapabilityExport> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|entry| entry.id == id))?;
        slot.take()
    }
}
pub(super) static mut CAPABILITY_EXPORTS: CapabilityExports = CapabilityExports::new();
/// Decode the generation's shared-buffer budget resource, if it carries one.
///
/// Located by magic among the `KIND_RESOURCE` objects, exactly as
/// `kernel/src/runtime/generation.rs::budget_object` does — the generation
/// authenticates every object against its digest table, so this decodes bytes
/// whose integrity is already established and enforces only structural
/// validity.
///
/// A generation carrying no budget is not an error: it declares that no
/// component holds any shared-buffer quota, and every holder then resolves to
/// [`HolderQuota::DENY`]. Neither is a malformed one — it also yields `DENY`
/// for every holder, which fails closed. Both are the same answer the retired
/// kernel gives, and it is the conservative one: a component denied a quota it
/// was promised fails at its own probe with a bounded error, whereas a
/// permissive fallback would hand out authority no generation declared.
pub(super) fn shared_buffer_budget<'a>(
    generation: &Generation<'a>,
) -> Option<SharedBufferBudget<'a>> {
    // The *first* magic match decides, and a malformed one is `None` rather
    // than a reason to keep looking. Scanning past it would let a generation
    // carrying one bad budget and one good one resolve the good one, which is
    // not what "the generation declares a budget" means. `budget_object` in the
    // retired kernel returns `Some(Err(..))` here for the same reason.
    let object = (0..generation.object_count())
        .filter_map(|index| generation.object(index).ok())
        .filter(|object| object.kind == KIND_RESOURCE)
        .find(|object| object.bytes.len() >= 8 && object.bytes[..8] == budget_magic::MAGIC)?;
    SharedBufferBudget::decode(object.bytes).ok()
}

/// The ceiling this generation declares for the component named `component`.
///
/// [`HolderQuota::DENY`] when the generation declares no budget or the
/// component is absent from it — authority is never ambient, so a component the
/// budget does not name holds nothing rather than something small.
pub(super) fn declared_quota(
    budget: Option<&SharedBufferBudget<'_>>,
    component: &str,
) -> HolderQuota {
    let Some(budget) = budget else {
        return HolderQuota::DENY;
    };
    match budget.quota_for(&budget_magic::holder_identity(component)) {
        Some(quota) => HolderQuota {
            byte_pages: quota.byte_pages,
            buffer_count: quota.buffer_count,
            mapping_count: quota.mapping_count,
            loan_count: quota.loan_count,
        },
        None => HolderQuota::DENY,
    }
}

/// The private-memory page ceiling this generation declares for `component`
/// (C10.2).
///
/// Zero when the generation declares no budget or the component is absent from
/// it: authority is never ambient, so a component the budget does not name
/// grows nothing rather than something small. That is the same rule
/// [`declared_quota`] applies to shared buffers, and it is what makes omission
/// meaningful instead of a default.
///
/// A malformed budget cannot reach here — `Admission::admit` fails the whole
/// generation closed on one (C10.2's exit condition), which is the asymmetry
/// with the C7.3 path: a shared-buffer budget that will not decode denies every
/// holder and boots, whereas an undecodable private-memory budget is
/// indistinguishable from a quota a component was promised and never got.
pub(super) fn declared_private_memory_pages(
    budget: Option<&PrivateMemoryBudget<'_>>,
    component: &str,
) -> usize {
    let Some(budget) = budget else {
        return 0;
    };
    budget
        .quota_for(&private_memory_budget::holder_identity(component))
        .map_or(0, |quota| quota.page_quota as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(id: u32, sender: u32, receiver: u32, finalized: bool) -> CapabilityExport {
        CapabilityExport {
            id,
            sender: TaskId(sender),
            receiver: TaskId(receiver),
            capability: graph::CapabilityEntry::buffer_factory(RIGHT_TRANSFER).unwrap(),
            ticket: None,
            sender_ticket_slot: None,
            retain: true,
            finalized,
        }
    }

    /// Store one export of `sender` the way `serve_capability_export` does:
    /// in the entry that `admit` chose.
    fn store(exports: &mut CapabilityExports, sender: u32, receiver: u32, finalized: bool) -> bool {
        let Some(index) = exports.admit(TaskId(sender)) else {
            return false;
        };
        let id = exports.next_id;
        exports.next_id += 1;
        exports.entries[index] = Some(export(id, sender, receiver, finalized));
        true
    }

    #[test]
    fn a_full_share_refuses_its_sender_and_takes_no_entry_of_another() {
        let mut exports = CapabilityExports::new();
        for sender in 0..MAX_TASKS as u32 {
            for _ in 0..MAX_EXPORTS_PER_SENDER {
                assert!(store(&mut exports, sender, sender + 1, false));
            }
            assert!(!store(&mut exports, sender, sender + 1, false));
        }
        assert_eq!(exports.len(), MAX_TASKS * MAX_EXPORTS_PER_SENDER);
    }

    #[test]
    fn retirement_takes_exactly_the_exports_that_name_the_task() {
        let mut exports = CapabilityExports::new();
        // Task 1 sent a finalized export and one it never finalized, and it is
        // the receiver of a third. The fourth export names it nowhere.
        assert!(store(&mut exports, 1, 2, true));
        assert!(store(&mut exports, 1, 3, false));
        assert!(store(&mut exports, 3, 1, true));
        assert!(store(&mut exports, 2, 3, true));
        let mut released = 0;
        while let Some(export) = exports.take_of(TaskId(1)) {
            assert!(export.sender == TaskId(1) || export.receiver == TaskId(1));
            released += 1;
        }
        assert_eq!(released, 3);
        assert_eq!(exports.len(), 1);
        let left = exports.entries.iter().flatten().next().unwrap();
        assert_eq!((left.sender, left.receiver), (TaskId(2), TaskId(3)));
    }
}
