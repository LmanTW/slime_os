//! The root fixture: two native children the root builds without a generation
//! executable, and the phases they exercise.
//!
//! Only a root image built with `SLIME_ROOT_FIXTURE=1` compiles this module.
//! `main` runs [`run`] in place of the graph launch. The children are two
//! tasks of the program in `components/root-child`, with endpoint authority
//! borrowed from the generation's declared instances.

use boot_contracts::generation::{RIGHT_RECV, RIGHT_SEND};
use slime_proto::syscall_abi::{fixture_labels, lifecycle_labels, shared_buffer_labels};
use slime_root::buffer_adapter::BufferAdapter;
use slime_root::child_vspace::{self, ChildImage, ScratchPage};
use slime_root::fatal;
use slime_root::fault::{self, LifecycleEventKind, SupervisionTable};
use slime_root::generation::{Authority, bound_authority};
use slime_root::graph_runtime::private_memory_cause;
use slime_root::ipc::{self, IpcError, Response};
use slime_root::object_allocator::ObjectAllocator;
use slime_root::shared_buffer::{
    BufferHandle, GenerationEpoch, HolderId, HolderQuota, MappingRights, PAGE_SIZE,
    SharedBufferTable, VSpaceCap,
};
use slime_root::task::{
    self, Arrival, CHILD_CNODE_SIZE_BITS, MAX_TASKS, Supervision, TaskId, TaskTable,
};
use slime_root::{private_memory, shared_buffer, vm_attributes};

use super::Aligned;

/// The native child fixture, built for this platform's seL4 userspace target.
/// Supplied by the build harness; see `components/root-child`. `Aligned` gives
/// the 8-byte alignment that `object`'s ELF64 parser requires.
static CHILD_ELF: Aligned<{ include_bytes!(env!("CHILD_ELF")).len() }> =
    Aligned(*include_bytes!(env!("CHILD_ELF")));

/// Fixture request tag, mirroring `components/root-child/src/main.rs`.
const REQUEST_TAG: sel4::Word = 0x534c_494d_4552_4551;

/// Directives the root returns to a fixture in reply MR1.
const DIRECTIVE_EXIT: sel4::Word = 0;
const DIRECTIVE_FAULT: sel4::Word = 1;

/// Child tasks this startup builds: one proving a clean request/exit cycle, one
/// proving fault delivery and supervision.
const FIXTURE_TASKS: usize = 2;

/// Service-loop iterations per fixture. A fixture contributes one request plus
/// one terminal message; the clean-exit fixture additionally contributes its
/// shared-buffer report, two supervised protection faults, and — since C10.1 —
/// its private-memory phase: five growth operations (two size queries, two
/// growths, one refused) plus that phase's own report. Eleven for the clean-exit
/// fixture, so sixteen leaves the same surplus the earlier eight did, bounding
/// unexpected traffic so the loop cannot spin forever.
const MAX_SERVICE_ITERATIONS: usize = 16;

/// What one fixture task is expected to demonstrate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    CleanExit,
    DeliberateFault,
}

impl Role {
    const fn directive(self) -> sel4::Word {
        match self {
            Self::CleanExit => DIRECTIVE_EXIT,
            Self::DeliberateFault => DIRECTIVE_FAULT,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::CleanExit => "clean-exit",
            Self::DeliberateFault => "deliberate-fault",
        }
    }
}

/// A fixture task and the declared component whose authority it carries.
#[derive(Clone, Copy)]
struct Fixture {
    id: TaskId,
    role: Role,
    source: &'static str,
    authority: Authority,
    terminated: bool,
}

// ---- shared-buffer phase contract ----
//
// Every constant below is duplicated in `components/root-child/src/main.rs` under
// the same name. They are a compile-time agreement between the two images, not
// runtime discovery: the child never searches for its shared region, so what
// grants it access is the root's mapping and nothing else.

/// Where the root maps the read-write shared region in the child's VSpace.
/// Well clear of the child image (which loads at `0x200000`) and of its IPC
/// buffer, so the mapping cannot collide with an existing translation.
const SHARED_RW_VADDR: usize = 0x4000_0000;
/// Where the root maps the read-only shared region in the child's VSpace.
const SHARED_RO_VADDR: usize = 0x4001_0000;

/// Byte offset within each region at which the deterministic pattern lives.
const SHARED_PATTERN_OFFSET: usize = 64;

/// `b"SBUF_RW!"` big-endian: the exact bytes the root writes into the
/// read-write region and the child must read back.
const SHARED_RW_PATTERN: u64 = 0x5342_5546_5f52_5721;
/// `b"CHILD_OK"`: what the child writes back through the shared mapping.
const SHARED_CHILD_REPLY: u64 = 0x4348_494c_445f_4f4b;
/// What the child attempts, and must fail, to store into the read-only region.
const SHARED_RO_INTRUSION: u64 = 0xdead_beef_dead_beef;

/// Report flags the child returns in the shared-buffer report's MR2.
const REPORT_RW_READBACK_OK: sel4::Word = 1 << 0;
const REPORT_RO_WRITE_REFUSED: sel4::Word = 1 << 1;
/// Set by the root, not the child: the child cannot distinguish a supervised
/// instruction abort from a page that genuinely executed, so the execute-never
/// verdict comes from the root's own fault record.
const REPORT_EXECUTE_REFUSED: sel4::Word = 1 << 2;

/// The holder identity the shared-buffer phase charges. Derived from the
/// clean-exit fixture's logical task id, never from a capability pointer.
const SHARED_HOLDER: HolderId = HolderId(0);

/// Ceiling for the P5.1 fixture phase's shared-buffer holder. Two single-page
/// regions and two mappings is exactly what this phase needs; the phase fails
/// closed rather than raising its own ceiling.
///
/// This phase alone, and only because it has no generation to read: the fixture
/// is an ELF the root task embeds at compile time, not a declared component, so
/// there is no budget resource naming it. The component graph resolves every
/// holder's ceiling from the generation's `shared-buffer-budget` resource —
/// see [`declared_quota`] — and never consults this constant.
const SHARED_QUOTA: HolderQuota = HolderQuota {
    byte_pages: 2,
    buffer_count: 2,
    mapping_count: 2,
    loan_count: 0,
};

/// Ceiling for the C10.1 fixture phase's private-memory region, in pages.
///
/// Four, which is the smallest number that exercises every property the
/// mechanism claims: two growths (so the base is proven stable across more than
/// one), a batch larger than one page (so a partial mapping would be visible),
/// and a refusal at the ceiling with the region still intact.
///
/// This phase alone, on exactly the grounds [`SHARED_QUOTA`] records: the
/// fixture is an embedded ELF rather than a declared component, so no
/// generation resource names it. Every declared instance sits at
/// deny-by-default zero until C10.2 adds the budget resource that would name
/// one.
const PRIVATE_QUOTA_PAGES: usize = 4;

/// Pages the incremental-rollback fixture retries after its injected failure.
///
/// One large-frame span, not the target's whole region ceiling. What this
/// fixture proves is that a failure partway through a growth preserves the
/// pages already committed and that the retry reaches the same quota over the
/// same base — a property of one span's worth of pages, which the embedded
/// child touches byte by byte. Scaling it with a raised region ceiling would
/// make the fixture walk 64 MiB of guest memory to assert nothing further, and
/// the child's own growth request is this same constant.
#[cfg(slime_private_fail_second_allocation)]
const PRIVATE_RETRY_QUOTA_PAGES: usize = child_vspace::LARGE_FRAME_PAGES;

/// Pages the phases must still hold when the clean-exit fixture reports.
#[cfg(not(slime_private_fail_second_allocation))]
const MEM_EXPECTED_PAGES: usize = PRIVATE_QUOTA_PAGES;
#[cfg(slime_private_fail_second_allocation)]
const MEM_EXPECTED_PAGES: usize = 1 + PRIVATE_RETRY_QUOTA_PAGES;

/// Growth operations that must actually charge pages.
#[cfg(not(slime_private_fail_second_allocation))]
const MEM_EXPECTED_GRANTS: usize = 2;
#[cfg(slime_private_fail_second_allocation)]
const MEM_EXPECTED_GRANTS: usize = 2;

/// The value the clean-exit fixture writes into its first private page and
/// re-reads after a further growth. `components/root-child/src/main.rs::MEM_PATTERN`.
const MEM_PATTERN: u64 = 0x4d454d5f42415345;

/// Marks a report as the private-memory phase's rather than the shared-buffer
/// phase's; both arrive on the same label.
/// `components/root-child/src/main.rs::MEM_REPORT_TAG`.
const MEM_REPORT_TAG: sel4::Word = 0x4d454d5f52505449;

/// Report flags the private-memory phase sets.
/// `components/root-child/src/main.rs::REPORT_MEM_*`.
const REPORT_MEM_QUERY_OK: sel4::Word = 1 << 0;
const REPORT_MEM_FIRST_GROWTH_OK: sel4::Word = 1 << 1;
const REPORT_MEM_ZEROED: sel4::Word = 1 << 2;
const REPORT_MEM_SECOND_GROWTH_OK: sel4::Word = 1 << 3;
const REPORT_MEM_BASE_STABLE: sel4::Word = 1 << 4;
const REPORT_MEM_QUOTA_REFUSED: sel4::Word = 1 << 5;
const REPORT_MEM_REFUSAL_HAD_NO_EFFECT: sel4::Word = 1 << 6;

/// Every flag the phase must set.
///
/// The root owns this rather than the fixture, for the same reason the
/// execute-never verdict is the root's: a phase that judged its own
/// completeness could pass by making fewer observations than it was supposed
/// to. Compared as an exact mask rather than a count, so a missing observation
/// names itself in the report marker.
const MEM_REPORT_ALL: sel4::Word = REPORT_MEM_QUERY_OK
    | REPORT_MEM_FIRST_GROWTH_OK
    | REPORT_MEM_ZEROED
    | REPORT_MEM_SECOND_GROWTH_OK
    | REPORT_MEM_BASE_STABLE
    | REPORT_MEM_QUOTA_REFUSED
    | REPORT_MEM_REFUSAL_HAD_NO_EFFECT;

/// What the root observed of the clean-exit fixture's private-memory phase.
#[derive(Clone, Copy, Default)]
struct MemoryPhase {
    /// Flags the fixture reported.
    flags: sel4::Word,
    /// Whether the report arrived at all.
    reported: bool,
}

/// Supervised protection probes the shared-buffer phase expects. One store to
/// a read-only mapping, one branch into an execute-never page. A third fault
/// from the clean-exit fixture is not part of the contract and is treated as a
/// real failure.
///
/// x86-64 expects only the first: seL4 exposes no execute-never frame
/// attribute there, so a data page is executable and the branch probe cannot
/// fault. See `slime_root::vm_attributes`.
#[cfg(not(target_arch = "x86_64"))]
const SHARED_EXPECTED_PROBES: usize = 2;
#[cfg(target_arch = "x86_64")]
const SHARED_EXPECTED_PROBES: usize = 1;

/// What the root observed while supervising the clean-exit fixture's
/// shared-buffer phase.
#[derive(Clone, Copy, Default)]
struct BufferPhase {
    /// Flags the child reported plus the execute-never verdict the root adds.
    flags: sel4::Word,
    /// The pattern word the child claims it read from the shared frame.
    observed: sel4::Word,
    /// Whether the child's report arrived at all.
    reported: bool,
    /// Supervised protection faults handled so far, bounding the resume path.
    probes: usize,
    /// A fault that did not match an expected probe. Any occurrence fails the
    /// phase; it is never silently resumed.
    unexpected: usize,
}

/// Build the two fixture tasks, run their phases and report.
///
/// The fixtures borrow endpoint authority from the first two declared
/// instances whose bound authority holds send and receive rights.
pub(super) fn run(booted: slime_root::boot::Booted, allocator: &mut ObjectAllocator) -> ! {
    let slime_root::boot::Booted {
        generation,
        admission,
        scratch,
        service_endpoint,
        console_endpoint,
        ..
    } = booted;
    let image = match ChildImage::parse(&CHILD_ELF.0) {
        Ok(image) => image,
        Err(error) => fatal!("child image rejected: {error:?}"),
    };

    let mut authorities: [Option<Authority>; FIXTURE_TASKS] = [None; FIXTURE_TASKS];
    let mut found = 0;
    for instance in admission.instances(&generation) {
        if found == FIXTURE_TASKS {
            break;
        }
        let authority = match bound_authority(&generation, instance) {
            Ok(authority) => authority,
            Err(error) => fatal!("grant closure rejected: {error:?}"),
        };
        if authority.rights & RIGHT_SEND == 0 || authority.rights & RIGHT_RECV == 0 {
            continue;
        }
        authorities[found] = Some(authority);
        found += 1;
    }
    if found != FIXTURE_TASKS {
        fatal!("generation declares {found} instances with service authority, need {FIXTURE_TASKS}")
    }

    let mut tasks = TaskTable::<MAX_TASKS>::new();
    let mut supervision = SupervisionTable::<MAX_TASKS>::new();
    let mut fixtures: [Option<Fixture>; FIXTURE_TASKS] = [None; FIXTURE_TASKS];

    for (index, role) in [Role::CleanExit, Role::DeliberateFault]
        .into_iter()
        .enumerate()
    {
        let Some(authority) = authorities[index] else {
            fatal!("fixture {index} lost its declared authority")
        };
        let id = match tasks.create(
            allocator,
            &image,
            service_endpoint,
            console_endpoint,
            authority,
            Supervision::SelfManaged,
            sel4::init_thread::slot::VSPACE.cap(),
            &scratch,
            sel4::init_thread::slot::ASID_POOL.cap(),
            // The P5.1 fixture path: neither spawned by a component nor built
            // from a generation component, so it carries neither. Every
            // per-component bound reads as absent for it, which is correct —
            // no manifest describes this task.
            None,
            None,
            None,
            0,
            // The fixture path constructs tasks outside any admitted plan,
            // so it keeps the minimum four-slot shell.
            CHILD_CNODE_SIZE_BITS,
            task::ChildSlots::SHELL,
            task::CHILD_PRIORITY,
            // The fixture path predates the thread plan and runs one thread.
            1,
            // No workers, so no worker priorities.
            [task::CHILD_PRIORITY; child_vspace::MAX_CHILD_THREADS],
            // The C10.1 private-memory quota. The clean-exit fixture always
            // exercises the four-page phase. The injected rollback image also
            // gives the deliberate-fault fixture one full window so it can
            // prove a failed initial small-page transaction retries against the
            // retained leaf mapping.
            if role == Role::CleanExit {
                PRIVATE_QUOTA_PAGES
            } else {
                #[cfg(slime_private_fail_second_allocation)]
                {
                    PRIVATE_RETRY_QUOTA_PAGES
                }
                #[cfg(not(slime_private_fail_second_allocation))]
                {
                    0
                }
            },
            // The fixture path carries no policy, so no adaptive window.
            None,
        ) {
            Ok(id) => id,
            Err(error) => fatal!("child task construction failed: {error:?}"),
        };
        if let Err(error) = supervision.register(id.0, id.0) {
            fatal!("supervision registration failed: {error:?}")
        }
        let Some(task) = tasks.get(id) else {
            fatal!("constructed task {} is missing", id.0)
        };
        slime_root::diagnostic_println!(
            "SLIME_ROOT native fixture staged task={} role={} source={} badge={:#x} fault_badge={:#x} grants={} child_slots={} root_slots={} frames={} tables={} entry={:#x}",
            id.0,
            role.name(),
            "generation",
            id.service_badge(),
            id.fault_badge(),
            authority.grants,
            task.granted_slots(),
            task.cleanup.slot_count(),
            task.vspace.frames_mapped,
            task.vspace.tables_mapped,
            task.entry,
        );
        fixtures[index] = Some(Fixture {
            id,
            role,
            source: "generation",
            authority,
            terminated: false,
        });
    }

    slime_root::diagnostic_println!(
        "SLIME_ROOT allocations complete tasks={} objects={} slots={} bytes={}",
        tasks.len(),
        allocator.objects_allocated(),
        allocator.slots_allocated(),
        allocator.bytes_allocated(),
    );

    // ---- shared-buffer phase ----
    //
    // Runs after the timer phase and before activation, because the child must
    // find its shared region already mapped the moment it runs. The frames come
    // from the same untyped pool and CSlot range as every other object, and the
    // mappings are installed into the clean-exit fixture's own VSpace.
    let Some(buffer_fixture) = fixtures[0] else {
        fatal!("shared-buffer phase has no clean-exit fixture")
    };
    let Some(buffer_task) = tasks.get(buffer_fixture.id) else {
        fatal!("shared-buffer phase lost its fixture task")
    };
    let child_vspace_cap = VSpaceCap(buffer_task.vspace.vspace.bits() as usize);
    let mut buffers = SharedBufferTable::new(GenerationEpoch(generation.number));
    // The ceiling is declared before any allocation, so every later admission
    // reads generation-declared state instead of a caller argument.
    if let Err(error) = buffers.declare_quota(SHARED_HOLDER, SHARED_QUOTA) {
        fatal!("shared-buffer quota rejected: {error:?}")
    }

    let mut buffer_phase = BufferPhase::default();
    let mut memory_phase = MemoryPhase::default();
    let (rw_handle, rw_frame, ro_handle) = {
        let mut adapter = BufferAdapter::new(allocator);
        let (rw, rw_frame) = match setup_shared_region(
            &mut buffers,
            &mut adapter,
            child_vspace_cap,
            SHARED_RW_VADDR,
            MappingRights::ReadWrite,
            SHARED_RW_PATTERN,
            &scratch,
        ) {
            Ok(created) => created,
            Err(error) => fatal!("SLIME_BUF FAIL rw region: {error}"),
        };
        let (ro, _) = match setup_shared_region(
            &mut buffers,
            &mut adapter,
            child_vspace_cap,
            SHARED_RO_VADDR,
            MappingRights::ReadOnly,
            SHARED_RW_PATTERN,
            &scratch,
        ) {
            Ok(created) => created,
            Err(error) => fatal!("SLIME_BUF FAIL ro region: {error}"),
        };

        // The exact range and rights the table committed, read back from the
        // record rather than from the request, so the marker reports what was
        // installed rather than what was asked for.
        for index in 0..2 {
            let Some(record) = buffers.mapping(index) else {
                fatal!("SLIME_BUF FAIL mapping {index} missing after map")
            };
            slime_root::diagnostic_println!(
                "SLIME_BUF mapped buffer={} vaddr={:#x}..{:#x} pages={} rights={} holder={} frames={} tables={}",
                record.buffer.0,
                record.base,
                record.base + record.page_count as usize * PAGE_SIZE,
                record.page_count,
                match record.rights {
                    MappingRights::ReadOnly => "read-only",
                    MappingRights::ReadWrite => "read-write",
                },
                record.holder.0,
                adapter.frames_allocated(),
                adapter.tables_mapped(),
            );
        }
        slime_root::diagnostic_println!(
            "SLIME_BUF accounting live={} pages={} mappings={} holder_pages={} orphans={}",
            buffers.live_count(),
            buffers.total_pages(),
            buffers.mapping_count(),
            buffers.holder_pages(SHARED_HOLDER),
            buffers.orphan_count(),
        );
        (rw, rw_frame, ro)
    };

    // Every allocation for every task has succeeded, so activation is safe. One
    // fixture runs at a time: both children share a priority, so serving them
    // sequentially is what makes the serial record ordered.
    let mut activated = 0;
    for index in 0..FIXTURE_TASKS {
        let Some(fixture) = fixtures[index] else {
            continue;
        };
        if let Err(error) = tasks.activate(fixture.id) {
            fatal!("activation failed: {error:?}")
        }
        activated += 1;
        slime_root::diagnostic_println!(
            "SLIME_ROOT task activated task={} role={}",
            fixture.id.0,
            fixture.role.name()
        );
        serve(
            service_endpoint,
            index,
            &mut tasks,
            allocator,
            &mut supervision,
            &mut fixtures,
            &mut buffer_phase,
            &mut memory_phase,
        );
    }

    // Adjudicate the phase from what the root itself observed. The child's own
    // claims are only half the evidence; the execute-never verdict and the
    // probe count come from the root's fault records.
    //
    // Reading the child's write-back requires binding the frame to the root's
    // scratch window, and a frame capability records exactly one mapping, so
    // the child's mapping is removed first. The fixture has already exited, so
    // nothing observes the removal. This is also the first real exercise of the
    // unmap path: the mapping count must drop while the region stays live.
    {
        let mut adapter = BufferAdapter::new(allocator);
        if let Err(error) = buffers.unmap(
            &mut adapter,
            SHARED_HOLDER,
            rw_handle,
            child_vspace_cap,
            SHARED_RW_VADDR,
        ) {
            fatal!("SLIME_BUF FAIL rw unmap: {error:?}")
        }
    }
    if buffers.mapping_count() != 1 || buffers.live_count() != 2 {
        fatal!(
            "SLIME_BUF FAIL unmap accounting mappings={} live={}",
            buffers.mapping_count(),
            buffers.live_count()
        )
    }
    report_buffer_phase(&buffer_phase, rw_frame, &scratch);
    report_memory_phase(&memory_phase, &tasks);

    // Teardown: reclaim every frame and mapping the phase created, then confirm
    // the accounting is genuinely back at zero rather than merely unreferenced.
    {
        let mut adapter = BufferAdapter::new(allocator);
        if let Err(error) = buffers.release(&mut adapter, SHARED_HOLDER, rw_handle) {
            fatal!("SLIME_BUF FAIL rw release: {error:?}")
        }
        if let Err(error) = buffers.release(&mut adapter, SHARED_HOLDER, ro_handle) {
            fatal!("SLIME_BUF FAIL ro release: {error:?}")
        }
        let orphans = buffers.orphan_count();
        if orphans != 0 {
            fatal!("SLIME_BUF FAIL teardown left {orphans} orphaned pages")
        }
        if buffers.live_count() != 0
            || buffers.total_pages() != 0
            || buffers.mapping_count() != 0
            || buffers.holder_pages(SHARED_HOLDER) != 0
            || buffers.holder_mappings(SHARED_HOLDER) != 0
        {
            fatal!(
                "SLIME_BUF FAIL teardown incomplete live={} pages={} mappings={} holder_pages={} holder_mappings={}",
                buffers.live_count(),
                buffers.total_pages(),
                buffers.mapping_count(),
                buffers.holder_pages(SHARED_HOLDER),
                buffers.holder_mappings(SHARED_HOLDER),
            )
        }
        slime_root::diagnostic_println!(
            "SLIME_BUF teardown unmapped={} revoked={} released={} live=0 pages=0 mappings=0 holder_pages=0 orphans=0",
            adapter.unmapped(),
            adapter.revoked(),
            adapter.released(),
        );
    }
    // ---- end shared-buffer phase ----

    let mut reclaimed_tasks = 0;
    let mut reclaimed_slots = 0;
    for fixture in fixtures.iter().flatten().copied() {
        match supervision.take_termination(fixture.id.0) {
            Ok(Some(termination)) => slime_root::diagnostic_println!(
                "SLIME_ROOT task settled task={} role={} termination={termination:?}",
                fixture.id.0,
                fixture.role.name(),
            ),
            Ok(None) => slime_root::diagnostic_println!(
                "SLIME_ROOT task unsettled task={} role={}",
                fixture.id.0,
                fixture.role.name()
            ),
            Err(error) => slime_root::diagnostic_println!(
                "SLIME_ROOT supervision rejected task={} error={error:?}",
                fixture.id.0
            ),
        }
        match tasks.reclaim(allocator, fixture.id) {
            Ok(record) => {
                reclaimed_tasks += 1;
                reclaimed_slots += record.slot_count();
                slime_root::diagnostic_println!(
                    "SLIME_ROOT task reclaimed task={} source={} slots={} arena={}",
                    fixture.id.0,
                    fixture.source,
                    record.slot_count(),
                    record.arena.index(),
                );
            }
            Err(error) => fatal!("task reclamation failed: {error:?}"),
        }
    }
    // Every private page returned when its task died (C10.1). The frames go
    // with the arena revoke above; this is the charge, which is the half a
    // revoke cannot see — so a page count that stayed nonzero here is a leak
    // the frame allocator would not report.
    {
        let table = tasks.private_memory();
        if table.total_pages() != 0 || table.reclaimed_pages() != table.grown_pages() {
            fatal!(
                "SLIME_MEM FAIL teardown left pages={} grown={} reclaimed={}",
                table.total_pages(),
                table.grown_pages(),
                table.reclaimed_pages(),
            )
        }
        slime_root::diagnostic_println!(
            "SLIME_MEM teardown grown={} reclaimed={} pages=0",
            table.grown_pages(),
            table.reclaimed_pages(),
        );
    }
    slime_root::diagnostic_println!(
        "SLIME_ROOT cleanup tasks={reclaimed_tasks} slots={reclaimed_slots} live={}",
        tasks.len()
    );
    slime_root::diagnostic_println!(
        "SLIME_ROOT allocator live_slots={} live_objects={} live_bytes={} slot_reuses={} extent_reuses={}",
        allocator.live_slots(),
        allocator.live_objects(),
        allocator.live_bytes(),
        allocator.slots_reused(),
        allocator.extents_reused(),
    );

    let granted: usize = fixtures
        .iter()
        .flatten()
        .map(|fixture| fixture.authority.grants)
        .sum();
    slime_root::diagnostic_println!(
        "SLIME_ROOT READY tasks={activated} grants={granted} declared_grants={} reclaimed_slots={}",
        admission.grants,
        tasks.reclaimed_slots(),
    );

    sel4::init_thread::suspend_self()
}

/// Serve the badged root endpoint until fixture `index` reaches a terminal state
/// or its bounded iteration budget is spent.
///
/// Requests and faults arrive on the same endpoint object under different
/// badges, because the non-MCS kernel resolves a thread's fault handler in that
/// thread's own CSpace; see `task.rs`.
#[allow(clippy::too_many_arguments)]
fn serve(
    endpoint: sel4::cap::Endpoint,
    index: usize,
    tasks: &mut TaskTable<MAX_TASKS>,
    allocator: &mut ObjectAllocator,
    supervision: &mut SupervisionTable<MAX_TASKS>,
    fixtures: &mut [Option<Fixture>; FIXTURE_TASKS],
    buffer_phase: &mut BufferPhase,
    memory_phase: &mut MemoryPhase,
) {
    for _ in 0..MAX_SERVICE_ITERATIONS {
        if fixtures[index].is_none_or(|fixture| fixture.terminated) {
            return;
        }
        let (info, badge) = endpoint.recv(());
        let Some((id, arrival)) = TaskId::from_badge(badge) else {
            slime_root::diagnostic_println!(
                "SLIME_ROOT unbadged arrival badge={badge:#x} rejected"
            );
            ipc::reply(Response::error(IpcError::InvalidOperation));
            continue;
        };
        let Some(position) = fixtures
            .iter()
            .position(|fixture| fixture.is_some_and(|fixture| fixture.id == id))
        else {
            slime_root::diagnostic_println!("SLIME_ROOT unknown task badge={badge:#x} rejected");
            ipc::reply(Response::error(IpcError::InvalidOperation));
            continue;
        };

        match arrival {
            Arrival::Request => {
                // `seL4_Recv` writes the fast message registers back into the
                // IPC buffer, so the request words are readable here.
                let words = sel4::with_ipc_buffer(|buffer| {
                    let mut words = [0 as sel4::Word; ipc::FAST_MESSAGE_REGISTERS];
                    let len = info.length().min(ipc::FAST_MESSAGE_REGISTERS);
                    words[..len].copy_from_slice(&buffer.msg_regs()[..len]);
                    words
                });
                serve_request(
                    &info,
                    &words,
                    id,
                    position,
                    tasks,
                    allocator,
                    supervision,
                    fixtures,
                    buffer_phase,
                    memory_phase,
                );
            }
            Arrival::Fault => serve_fault(
                &info,
                id,
                position,
                tasks,
                supervision,
                fixtures,
                buffer_phase,
            ),
        }
    }
    slime_root::diagnostic_println!(
        "SLIME_ROOT service budget exhausted iterations={MAX_SERVICE_ITERATIONS} task={}",
        fixtures[index].map_or(u32::MAX, |fixture| fixture.id.0)
    );
}

#[allow(clippy::too_many_arguments)]
fn serve_request(
    info: &sel4::MessageInfo,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
    id: TaskId,
    position: usize,
    tasks: &mut TaskTable<MAX_TASKS>,
    allocator: &mut ObjectAllocator,
    supervision: &mut SupervisionTable<MAX_TASKS>,
    fixtures: &mut [Option<Fixture>; FIXTURE_TASKS],
    buffer_phase: &mut BufferPhase,
    memory_phase: &mut MemoryPhase,
) {
    let Some(role) = fixtures[position].map(|fixture| fixture.role) else {
        ipc::reply(Response::error(IpcError::InvalidOperation));
        return;
    };

    match info.label() {
        // The fixture's request. Answering it with the task's directive is what
        // proves a grant-derived endpoint carries real service authority.
        // The clean-exit fixture's shared-buffer report. The root records what
        // the child claims and answers immediately; adjudication happens once,
        // after the fixture has finished, in `report_buffer_phase`.
        fixture_labels::DIRECTIVE => {
            if info.length() < 2 || words[0] != REQUEST_TAG {
                slime_root::diagnostic_println!(
                    "SLIME_ROOT request malformed task={} len={} tag={:#x}",
                    id.0,
                    info.length(),
                    words[0]
                );
                ipc::reply(Response::error(IpcError::InvalidLength));
                return;
            }
            slime_root::diagnostic_println!(
                "SLIME_ROOT request badge={:#x} task={} service_label={} directive={}",
                id.service_badge(),
                id.0,
                fixture_labels::DIRECTIVE,
                role.directive(),
            );
            match supervision.ipc_completed(id.0, fixture_labels::DIRECTIVE, 0) {
                Ok(event) => report(&event.kind, id, position, fixtures),
                Err(error) => slime_root::diagnostic_println!(
                    "SLIME_ROOT ipc accounting rejected task={} error={error:?}",
                    id.0
                ),
            }
            ipc::reply(Response::success(0, role.directive()));
        }
        // The clean-exit fixture's phase reports. Both arrive on this label and
        // are told apart by the tag in MR1: the shared-buffer phase sends its
        // observed pattern word, the private-memory phase sends
        // `MEM_REPORT_TAG`. The root records what the child claims and answers
        // immediately; adjudication happens once, after the fixture has
        // finished, in `report_buffer_phase` and `report_memory_phase`.
        shared_buffer_labels::MAP => {
            if info.length() < 3 || words[0] != REQUEST_TAG {
                slime_root::diagnostic_println!(
                    "SLIME_ROOT shared report malformed task={} len={} tag={:#x}",
                    id.0,
                    info.length(),
                    words[0]
                );
                ipc::reply(Response::error(IpcError::InvalidLength));
                return;
            }
            if words[1] == MEM_REPORT_TAG {
                memory_phase.flags |= words[2] & MEM_REPORT_ALL;
                memory_phase.reported = true;
                slime_root::diagnostic_println!(
                    "SLIME_MEM child reported task={} flags={:#x}",
                    id.0,
                    words[2],
                );
                ipc::reply(Response::success(0, 0));
                return;
            }
            buffer_phase.observed = words[1];
            // The child contributes only what it can actually attest to; the
            // execute-never verdict is the root's and is preserved here.
            buffer_phase.flags |= words[2] & (REPORT_RW_READBACK_OK | REPORT_RO_WRITE_REFUSED);
            buffer_phase.reported = true;
            slime_root::diagnostic_println!(
                "SLIME_BUF child reported task={} observed={:#x} flags={:#x}",
                id.0,
                buffer_phase.observed,
                words[2],
            );
            ipc::reply(Response::success(0, 0));
        }
        // C10.1's growth, served on the fixture path too. The mechanism is the
        // same `TaskTable` operation the component graph's dispatcher calls;
        // what differs is only which loop received the request.
        lifecycle_labels::PRIVATE_MEMORY_GROW => {
            let delta = words[0] as usize;
            #[cfg(slime_private_fail_second_allocation)]
            if delta == 2 {
                slime_root::object_allocator::arm_private_second_allocation_failure();
            }
            let response = match tasks.grow_private_memory(allocator, id, delta) {
                Ok(previous) => {
                    let region = tasks
                        .get(id)
                        .map(|task| task.private_memory)
                        .unwrap_or(private_memory::Region::DENIED);
                    slime_root::diagnostic_println!(
                        "SLIME_MEM grown task={} delta={delta} previous={previous} pages={} base={:#x} quota={} total={} large_frames={} base_frames={} leaf_tables={}",
                        id.0,
                        region.pages(),
                        region.base(),
                        region.quota(),
                        tasks.private_memory().total_pages(),
                        region.large_frames(),
                        region.base_frames(),
                        region.leaf_tables(),
                    );
                    Response::success(previous as i64, region.base() as sel4::Word)
                }
                Err(task::TaskError::PrivateMemory(error)) => {
                    slime_root::diagnostic_println!(
                        "SLIME_MEM refused task={} delta={delta} cause={} detail={error:?}",
                        id.0,
                        private_memory_cause(&error),
                    );
                    Response::error(IpcError::TransferFailed)
                }
                Err(error) => {
                    slime_root::diagnostic_println!(
                        "SLIME_MEM rejected task={} delta={delta} error={error:?}",
                        id.0
                    );
                    Response::error(IpcError::InvalidOperation)
                }
            };
            ipc::reply(response);
        }
        // A clean exit is a send, not a call: the task is suspended rather than
        // replied to.
        lifecycle_labels::EXIT => {
            let status = words[0] as i64;
            match supervision.exit(id.0, status) {
                Ok(transition) => {
                    report(&transition.event.kind, id, position, fixtures);
                    if let Some(fixture) = fixtures[position].as_mut() {
                        fixture.terminated = true;
                    }
                }
                Err(error) => slime_root::diagnostic_println!(
                    "SLIME_ROOT exit supervision rejected task={} error={error:?}",
                    id.0
                ),
            }
            stop(tasks, id, "exit");
        }
        label => {
            let response = Response::error(IpcError::UnsupportedOperation);
            slime_root::diagnostic_println!(
                "SLIME_ROOT request unsupported task={} service_label={} result={}",
                id.0,
                label,
                response.result,
            );
            ipc::reply(response);
        }
    }
}

fn serve_fault(
    info: &sel4::MessageInfo,
    id: TaskId,
    position: usize,
    tasks: &mut TaskTable<MAX_TASKS>,
    supervision: &mut SupervisionTable<MAX_TASKS>,
    fixtures: &mut [Option<Fixture>; FIXTURE_TASKS],
    buffer_phase: &mut BufferPhase,
) {
    let record = match fault::decode_fault(info) {
        Ok(record) => record,
        Err(error) => {
            slime_root::diagnostic_println!(
                "SLIME_ROOT fault undecodable task={} error={error:?}",
                id.0
            );
            return;
        }
    };

    // A shared-buffer protection probe is a fault the root *expects*: the
    // clean-exit fixture deliberately violates a mapping's rights so the
    // enforcement can be observed. Such a fault is supervised and resumed
    // rather than treated as a termination, which is what lets the fixture go
    // on to its ordinary clean exit and keeps every pre-existing marker firing.
    //
    // The recovery is bounded three ways: only the clean-exit fixture is
    // eligible, only at the two exact addresses the phase mapped, and only
    // `SHARED_EXPECTED_PROBES` times in total. Anything else falls through to
    // the ordinary termination path below.
    if fixtures[position].is_some_and(|fixture| fixture.role == Role::CleanExit)
        && let Some(probe) = classify_probe(&record)
        && buffer_phase.probes < SHARED_EXPECTED_PROBES
    {
        buffer_phase.probes += 1;
        #[cfg(not(target_arch = "x86_64"))]
        if probe == Probe::Execute {
            buffer_phase.flags |= REPORT_EXECUTE_REFUSED;
        }
        slime_root::diagnostic_println!(
            "SLIME_BUF probe refused task={} kind={} access={:?} address={:#x} instruction={:#x}",
            id.0,
            probe.name(),
            match record.kind {
                fault::FaultKind::VirtualMemory { access, .. } => access,
                _ => fault::AccessKind::Unknown,
            },
            record.address.unwrap_or_default(),
            record.instruction.unwrap_or_default(),
        );
        if let Err(error) = resume_past_probe(tasks, id, probe) {
            fatal!("SLIME_BUF FAIL probe resume task={} error={error:?}", id.0)
        }
        return;
    }
    if fixtures[position].is_some_and(|fixture| fixture.role == Role::CleanExit) {
        // The clean-exit fixture faulted somewhere the phase did not plan for.
        // Recording it is what makes the phase report fail loudly instead of
        // silently resuming an unattributable fault.
        buffer_phase.unexpected += 1;
    }
    match supervision.fault(id.0, record) {
        Ok(transition) => {
            report(&transition.event.kind, id, position, fixtures);
            if let Some(fixture) = fixtures[position].as_mut() {
                fixture.terminated = true;
            }
        }
        Err(error) => slime_root::diagnostic_println!(
            "SLIME_ROOT fault supervision rejected task={} error={error:?}",
            id.0
        ),
    }
    // A faulted thread is already blocked on its fault endpoint; suspending it
    // makes the stop explicit and keeps reclamation uniform with a clean exit.
    stop(tasks, id, "fault");
}

fn stop(tasks: &TaskTable<MAX_TASKS>, id: TaskId, after: &str) {
    if let Some(task) = tasks.get(id)
        && let Err(error) = task.suspend()
    {
        slime_root::diagnostic_println!(
            "SLIME_ROOT suspend after {after} failed task={} error={error:?}",
            id.0
        );
    }
}

/// Emit one lifecycle observation. Markers name the logical task and role only;
/// no badge, CSlot, or physical identifier appears in an event.
fn report(
    kind: &LifecycleEventKind,
    id: TaskId,
    position: usize,
    fixtures: &[Option<Fixture>; FIXTURE_TASKS],
) {
    let role = fixtures[position].map_or("unknown", |fixture| fixture.role.name());
    match kind {
        LifecycleEventKind::IpcCompleted {
            service_label,
            result,
        } => slime_root::diagnostic_println!(
            "SLIME_ROOT child request served task={} role={role} service_label={service_label} result={result}",
            id.0,
        ),
        LifecycleEventKind::Exited { status } => slime_root::diagnostic_println!(
            "SLIME_ROOT child exit observed task={} role={role} status={status}",
            id.0
        ),
        LifecycleEventKind::Faulted(record) => slime_root::diagnostic_println!(
            "SLIME_ROOT child fault observed task={} role={role} kind={:?} instruction={:?} address={:?}",
            id.0,
            record.kind,
            record.instruction,
            record.address,
        ),
        other => slime_root::diagnostic_println!(
            "SLIME_ROOT child event task={} role={role} kind={other:?}",
            id.0
        ),
    }
}

/// Which protection a supervised fault demonstrated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Probe {
    /// A store refused by a read-only mapping.
    ReadOnlyWrite,
    /// A branch refused by an execute-never mapping.
    ///
    /// Absent on x86-64: `seL4_X86_VMAttributes` is a cache-policy selector
    /// with no execute bit, so a data mapping there is executable and no such
    /// fault can occur. See `slime_root::vm_attributes`.
    #[cfg(not(target_arch = "x86_64"))]
    Execute,
}

impl Probe {
    const fn name(self) -> &'static str {
        match self {
            Self::ReadOnlyWrite => "ro-write",
            #[cfg(not(target_arch = "x86_64"))]
            Self::Execute => "wx-execute",
        }
    }
}

/// Decide whether a fault is one of the phase's two planned probes.
///
/// Both the access kind *and* the faulting address must match: a write
/// anywhere else, or an execute fetch from any page other than the shared data
/// region, is not a probe and must not be resumed.
fn classify_probe(record: &fault::FaultRecord) -> Option<Probe> {
    let fault::FaultKind::VirtualMemory { access, .. } = record.kind else {
        return None;
    };
    let address = usize::try_from(record.address?).ok()?;
    match access {
        fault::AccessKind::Write
            if (SHARED_RO_VADDR..SHARED_RO_VADDR + PAGE_SIZE).contains(&address) =>
        {
            Some(Probe::ReadOnlyWrite)
        }
        #[cfg(not(target_arch = "x86_64"))]
        fault::AccessKind::Execute
            if (SHARED_RW_VADDR..SHARED_RW_VADDR + PAGE_SIZE).contains(&address) =>
        {
            Some(Probe::Execute)
        }
        _ => None,
    }
}

/// Step a probing thread past the instruction that faulted, then let it run.
///
/// Data faults report the store itself, so resuming means advancing the PC by
/// exactly that store's width. AArch64 instructions are fixed-width; the RV64
/// fixture emits its probing store inside an explicit `.option norvc` block so
/// this one instruction is fixed-width even though the image otherwise uses the
/// compressed extension; the x86-64 fixture emits a pinned three-byte encoding
/// (`48 89 01`, `mov %rax, (%rcx)`) for the same reason. Each width is stated
/// beside the architecture that emits it, because a mismatch resumes the thread
/// mid-instruction rather than failing.
///
/// Execute faults report the non-executable branch target, so resume at the
/// link register the indirect call set.
fn resume_past_probe(
    tasks: &TaskTable<MAX_TASKS>,
    id: TaskId,
    probe: Probe,
) -> Result<(), sel4::Error> {
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    const DATA_INSTRUCTION_BYTES: sel4::Word = 4;
    #[cfg(target_arch = "x86_64")]
    const DATA_INSTRUCTION_BYTES: sel4::Word = 3;

    let Some(task) = tasks.get(id) else {
        return Err(sel4::Error::InvalidCapability);
    };
    let mut context = task.tcb.tcb_read_all_registers(false)?;
    let resume_at = match probe {
        Probe::ReadOnlyWrite => context.pc().wrapping_add(DATA_INSTRUCTION_BYTES),
        #[cfg(not(target_arch = "x86_64"))]
        Probe::Execute => {
            #[cfg(target_arch = "aarch64")]
            {
                *context.gpr(30)
            }
            #[cfg(target_arch = "riscv64")]
            {
                context.inner().ra
            }
        }
    };

    *context.pc_mut() = resume_at;
    // `resume = true`: the thread is blocked on its fault endpoint, and this is
    // the reply that releases it.
    task.tcb.tcb_write_all_registers(true, &mut context)
}

/// Create one shared region, seed it with `pattern`, and map it into the
/// child's VSpace at `vaddr` with exactly `rights`.
///
/// The pattern is written through the root's own scratch window rather than
/// through the child's mapping, so a read-only region really is read-only
/// everywhere the child can see it: the root never holds a writable alias.
#[allow(clippy::too_many_arguments)]
fn setup_shared_region(
    buffers: &mut SharedBufferTable,
    adapter: &mut BufferAdapter<'_>,
    vspace: VSpaceCap,
    vaddr: usize,
    rights: MappingRights,
    pattern: u64,
    scratch: &ScratchPage,
) -> Result<(BufferHandle, shared_buffer::FrameCap), &'static str> {
    let frame = adapter.allocate_frame().map_err(|_| "frame allocation")?;
    let anchors = shared_buffer::FrameAnchors::from_slice(&[frame]).map_err(|_| "frame anchors")?;
    // Created writable so the root may seed it; the *mapping* rights are what
    // the child is bound by, and those are narrowed below.
    let handle = buffers
        .create(SHARED_HOLDER, anchors, true)
        .map_err(|_| "region admission")?;

    write_pattern_through_scratch(frame, scratch, pattern).map_err(|_| "pattern seed")?;

    buffers
        .map(
            adapter,
            SHARED_HOLDER,
            handle,
            vspace,
            vaddr,
            0,
            PAGE_SIZE,
            rights,
        )
        .map_err(|_| "child mapping")?;
    Ok((handle, frame))
}

/// Write `pattern` into a frame through the root's scratch window.
///
/// The frame is mapped read-write at the scratch address just long enough for
/// the store, then unmapped, so the root retains no standing alias of a region
/// it hands to a child.
fn write_pattern_through_scratch(
    frame: shared_buffer::FrameCap,
    scratch: &ScratchPage,
    pattern: u64,
) -> Result<(), sel4::Error> {
    let cap =
        slime_root::root_cspace::RootSlot::<sel4::cap_type::Granule>::from_address(frame.0).cap();
    cap.frame_map(
        sel4::init_thread::slot::VSPACE.cap(),
        scratch.addr(),
        sel4::CapRights::read_write(),
        vm_attributes::data(),
    )?;
    // SAFETY: `scratch.addr()` is a granule-aligned page mapped read-write into
    // this VSpace for the duration of this store and aliased by no live Rust
    // reference. `SHARED_PATTERN_OFFSET + 8` is inside the 4 KiB page and the
    // address is 8-byte aligned, so the write is in bounds and aligned.
    unsafe {
        ((scratch.addr() + SHARED_PATTERN_OFFSET) as *mut u64).write_volatile(pattern);
    }
    cap.frame_unmap()
}

/// Read one word back out of a frame through the root's scratch window.
fn read_word_through_scratch(
    frame: shared_buffer::FrameCap,
    scratch: &ScratchPage,
) -> Result<u64, sel4::Error> {
    let cap =
        slime_root::root_cspace::RootSlot::<sel4::cap_type::Granule>::from_address(frame.0).cap();
    cap.frame_map(
        sel4::init_thread::slot::VSPACE.cap(),
        scratch.addr(),
        sel4::CapRights::read_write(),
        vm_attributes::data(),
    )?;
    // SAFETY: as for `write_pattern_through_scratch`; the same page, offset,
    // and alignment, and the mapping is live for the duration of this load.
    let value = unsafe { ((scratch.addr() + SHARED_PATTERN_OFFSET) as *const u64).read_volatile() };
    cap.frame_unmap()?;
    Ok(value)
}

/// Adjudicate the shared-buffer phase from what the root observed, and print
/// the ordered markers that record it.
///
/// Every verdict here is the root's: the child's self-reported flags are
/// checked, not trusted, and the execute-never result comes from the root's own
/// fault record. Any shortfall is fatal rather than a missing marker, so a
/// protection that silently stopped working fails the gate loudly.
fn report_buffer_phase(
    phase: &BufferPhase,
    rw_frame: shared_buffer::FrameCap,
    scratch: &ScratchPage,
) {
    if !phase.reported {
        fatal!("SLIME_BUF FAIL child never reported the shared-buffer phase")
    }
    if phase.unexpected != 0 {
        fatal!(
            "SLIME_BUF FAIL {} unattributable fault(s) from the clean-exit fixture",
            phase.unexpected
        )
    }

    // (b) The child observed exactly the bytes the root wrote.
    if phase.flags & REPORT_RW_READBACK_OK == 0 || phase.observed != SHARED_RW_PATTERN as sel4::Word
    {
        fatal!(
            "SLIME_BUF FAIL child read {:#x} expected {:#x}",
            phase.observed,
            SHARED_RW_PATTERN
        )
    }

    // The reverse direction: the child's write-back must be visible to the root
    // through the same frame, which is what distinguishes a shared mapping from
    // a copy handed to the child at startup.
    let echoed = match read_word_through_scratch(rw_frame, scratch) {
        Ok(value) => value,
        Err(error) => fatal!("SLIME_BUF FAIL reading child write-back: {error:?}"),
    };
    if echoed != SHARED_CHILD_REPLY {
        fatal!(
            "SLIME_BUF FAIL child write-back {echoed:#x} expected {:#x}",
            SHARED_CHILD_REPLY
        )
    }
    slime_root::diagnostic_println!(
        "SLIME_BUF readback vaddr={:#x} root_wrote={:#x} child_read={:#x} child_wrote={:#x} match=1",
        SHARED_RW_VADDR + SHARED_PATTERN_OFFSET,
        SHARED_RW_PATTERN,
        phase.observed,
        echoed,
    );

    // (c) Both protections held, each observed as a real fault rather than as
    // a rejected bookkeeping flag.
    if phase.flags & REPORT_RO_WRITE_REFUSED == 0 {
        fatal!("SLIME_BUF FAIL read-only mapping accepted a child write")
    }
    #[cfg(not(target_arch = "x86_64"))]
    if phase.flags & REPORT_EXECUTE_REFUSED == 0 {
        fatal!("SLIME_BUF FAIL execute-never mapping did not refuse execution")
    }
    // The inverse assertion on x86-64: the flag is only ever set from an
    // observed Execute fault, and no such fault can occur where the frame
    // attribute does not exist. Seeing it would mean the fault vocabulary or
    // the probe classification changed, which must fail rather than pass
    // quietly.
    #[cfg(target_arch = "x86_64")]
    if phase.flags & REPORT_EXECUTE_REFUSED != 0 {
        fatal!("SLIME_BUF FAIL execute fault reported where no execute attribute exists")
    }
    if phase.probes != SHARED_EXPECTED_PROBES {
        fatal!(
            "SLIME_BUF FAIL supervised {} probe(s), expected {SHARED_EXPECTED_PROBES}",
            phase.probes
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    slime_root::diagnostic_println!(
        "SLIME_BUF rights enforced ro_write=refused wx_execute=refused probes={} supervised=1",
        phase.probes,
    );
    // Distinct text on purpose: this profile did not observe an execute
    // refusal, and printing the other marker would make an unenforced mapping
    // read as an enforced one in a transcript.
    #[cfg(target_arch = "x86_64")]
    slime_root::diagnostic_println!(
        "SLIME_BUF rights enforced ro_write=refused wx_execute=unenforced probes={} supervised=1",
        phase.probes,
    );
}

/// Adjudicate the private-memory phase from what the root observed, and print
/// the ordered markers that record it (C10.1).
///
/// Every verdict is the root's. The child reports what it saw from inside its
/// own address space — zeros, a surviving pattern, a refusal — and the root
/// checks those against its own page accounting, which the child cannot see and
/// cannot forge. A shortfall is fatal rather than a missing marker, so a
/// mechanism that silently stopped bounding growth fails the gate loudly.
fn report_memory_phase(phase: &MemoryPhase, tasks: &TaskTable<MAX_TASKS>) {
    if !phase.reported {
        fatal!("SLIME_MEM FAIL child never reported the private-memory phase")
    }
    let missing = MEM_REPORT_ALL & !phase.flags;
    if missing != 0 {
        fatal!(
            "SLIME_MEM FAIL child reported {:#x}, missing {missing:#x} of {MEM_REPORT_ALL:#x}",
            phase.flags
        )
    }
    // The root's own half: the phase's own arm grew to exactly the pages it is
    // supposed to still hold, and nothing else grew at all. The child can
    // attest that its pattern survived; only the root can say how many pages it
    // handed out.
    let table = tasks.private_memory();
    if table.total_pages() != MEM_EXPECTED_PAGES {
        fatal!(
            "SLIME_MEM FAIL {} live page(s), expected exactly {MEM_EXPECTED_PAGES}",
            table.total_pages()
        )
    }
    // The grants the arm's growths must charge, which is the property a total
    // alone cannot state: a size query and a refusal must each take no page, so
    // a mechanism that charged a query, or charged twice per growth, would
    // reach the same total by a different and wrong route.
    if table.grants() != MEM_EXPECTED_GRANTS {
        fatal!(
            "SLIME_MEM FAIL {} growth grant(s), expected exactly {MEM_EXPECTED_GRANTS}",
            table.grants()
        )
    }
    #[cfg(not(slime_private_fail_second_allocation))]
    slime_root::diagnostic_println!(
        "SLIME_MEM enforced quota={PRIVATE_QUOTA_PAGES} pages={} grants={} grown={} reclaimed={} flags={:#x}",
        table.total_pages(),
        table.grants(),
        table.grown_pages(),
        table.reclaimed_pages(),
        phase.flags,
    );
    #[cfg(slime_private_fail_second_allocation)]
    slime_root::diagnostic_println!(
        "SLIME_MEM enforced clean_quota={PRIVATE_QUOTA_PAGES} retry_quota={PRIVATE_RETRY_QUOTA_PAGES} pages={} grants={} grown={} reclaimed={} flags={:#x}",
        table.total_pages(),
        table.grants(),
        table.grown_pages(),
        table.reclaimed_pages(),
        phase.flags,
    );
}
