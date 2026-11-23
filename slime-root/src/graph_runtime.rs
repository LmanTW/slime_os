/// The root must stop. The record that says why is already on the console.
///
/// A phase that cannot go on prints its record with [`stop!`](crate::stop)
/// and returns this, so the function returns and its caller decides. The value
/// carries no text: a record that travelled in it would need a buffer of a
/// fixed size, and a record cut to fit is not the record the gates read.
pub struct Stop;

/// Print the record of an unrecoverable condition and yield a [`Stop`].
///
/// This is the one definition of the record's format. `fatal!` expands to it.
#[macro_export]
macro_rules! stop {
    ($($arg:tt)*) => {{
        $crate::diagnostic_println!("SLIME_ROOT FATAL {}", format_args!($($arg)*));
        $crate::graph_runtime::Stop
    }};
}

/// Park the root task after a [`Stop`]. Nothing panics.
///
/// The serial record is already printed; this adds the panel's. Serial is
/// what every emulated plane reads; the panel is the *only* channel a physical
/// Framework has, and a stop that reaches serial alone is silent there. The
/// panel carries a fixed label rather than the formatted message: it tells an
/// operator with no serial port that the root died rather than hung.
pub fn halt(_stop: Stop) -> ! {
    // SAFETY: this path is terminal and single-threaded: the root suspends on
    // the next line, so the render cannot overlap another.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        crate::framebuffer::report_fatal("ROOT FATAL - BOOT ABANDONED");
    }
    sel4::init_thread::suspend_self()
}

/// Report an unrecoverable condition and park the root task, where no caller
/// can stop the root in this function's place. Elsewhere a function returns
/// [`stop!`](crate::stop) and its caller halts.
#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {
        $crate::graph_runtime::halt($crate::stop!($($arg)*))
    };
}

#[cfg(slime_boot_selector)]
use crate::boot_selector;
use crate::{
    buffer_adapter, child_vspace, clock, console, cspace, device, directory, event, fault,
    generation, graph, ipc, launched, lifecycle, notification, object_allocator, peer_endpoint,
    platform_timer, private_memory, scheduling, shared_buffer, supervision, task, thread_abi,
    timer, transfer_window, wait_set,
};

use boot_contracts::generation::{
    CapabilityKind, Generation, Grant, GrantEndpoint, Instance, InstanceHealth, InstanceOwner,
    KIND_RESOURCE, MintedBinding,
};
use boot_contracts::private_memory_budget::{self, PrivateMemoryBudget};
use boot_contracts::shared_buffer_budget::{self as budget_magic, SharedBufferBudget};

use boot_contracts::generation::{RIGHT_EXEC, RIGHT_RECV, RIGHT_SEND, RIGHT_TRANSFER};
use buffer_adapter::BufferAdapter;
use child_vspace::{ChildImage, GRANULE_SIZE, ScratchPage};
#[cfg(slime_boot_selector)]
use device::MAX_BLOCK_DEVICES;
use event::{TaskEpoch, TimerId};
use generation::{Admission, bound_authority};
use ipc::{IpcError, Response, poll_notification};
use launched::LaunchedInstances;
use object_allocator::ObjectAllocator;
use platform_timer::PhysicalTimerAdapter;
use shared_buffer::{
    BufferHandle, GenerationEpoch, HolderId, HolderQuota, MappingRights, SharedBufferTable,
    VSpaceCap,
};
use task::{Arrival, MAX_TASKS, Supervision, TaskId, TaskTable};
use timer::{PlatformTimer, ServiceTimerError, TimerScheduler, apply_deadline_programming};
use transfer_window::{WindowTable, descriptor_thread};

use slime_proto::syscall_abi::{
    capability_table_labels, capability_transfer_labels, clock_labels, directory_labels,
    lifecycle_labels, scheduling_labels, shared_buffer_labels, spawn_labels, supervision_labels,
};

use core::ptr;

/// One staged transfer window per admitted component thread.
pub const MAX_WINDOW_ENTRIES: usize = MAX_TASKS * child_vspace::MAX_CHILD_THREADS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BufferLifecycleRequest {
    Map,
    Unmap,
    Seal,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoanLifecycleRequest {
    Map,
    Return,
    Revoke,
}

/// The target profile this root task admits executables for. The build harness
/// states it explicitly for the root, child, generation, and loader together;
/// admission then compares every serialized target axis before mapping bytes.
pub const TARGET_PROFILE: &str = env!("SLIME_TARGET_PROFILE");

/// The timer phase schedules a deadline this fraction of a second out — short
/// enough that a working IRQ path fires almost immediately, generous enough
/// that QEMU's timer emulation reliably delivers it.
const TIMER_PROOF_DEADLINE_DIVISOR: u64 = 100;

/// Wall-clock ceiling, in whole seconds of the timer's own counter, the
/// bounded wait loop tolerates before declaring the interrupt undelivered.
/// Generous relative to the scheduled deadline so real delivery never comes
/// close, while still keeping a wedged boot failing in a few seconds instead
/// of burning the full boot-check timeout.
const TIMER_PROOF_BOUND_SECONDS: u64 = 3;

/// Run one IRQ-backed deadline and name the phase in every marker.
pub fn prove_timer(timer_adapter: &mut PhysicalTimerAdapter, phase: &str) -> Result<(), Stop> {
    let mut timer_scheduler = TimerScheduler::<1>::new();
    const TIMER_PROOF_OWNER: TaskEpoch = TaskEpoch::new(0, 0);
    let timer_start = timer_adapter
        .monotonic_now()
        .map_err(|error| stop!("timer clock unreadable during {phase}: {error:?}"))?;
    let deadline_ticks = (timer_adapter.frequency_hz() / TIMER_PROOF_DEADLINE_DIVISOR).max(1);
    let (_, scheduled) = timer_scheduler
        .schedule_after(TIMER_PROOF_OWNER, timer_start, deadline_ticks)
        .map_err(|error| stop!("timer proof deadline rejected during {phase}: {error:?}"))?;
    apply_deadline_programming(timer_adapter, scheduled.programming).map_err(|error| {
        stop!("timer deadline could not be programmed during {phase}: {error:?}")
    })?;

    let bound_ticks = timer_adapter
        .frequency_hz()
        .saturating_mul(TIMER_PROOF_BOUND_SECONDS);
    let mut polls: u64 = 0;
    loop {
        if poll_notification(timer_adapter.notification()) == Some(timer_adapter.signal_badge()) {
            break;
        }
        let now = timer_adapter.monotonic_now().map_err(|error| {
            stop!("timer clock unreadable while waiting during {phase}: {error:?}")
        })?;
        let elapsed = now.0.wrapping_sub(timer_start.0);
        if elapsed > bound_ticks {
            return Err(stop!(
                "SLIME_TIMER FAIL phase={phase} timeout waited_ticks={elapsed} bound_ticks={bound_ticks} polls={polls}"
            ));
        }
        polls += 1;
    }
    if phase == "startup" {
        crate::diagnostic_println!(
            "SLIME_TIMER delivered badge={:#x} polls={polls}",
            timer_adapter.signal_badge(),
        );
    } else {
        crate::diagnostic_println!(
            "SLIME_TIMER phase={phase} delivered badge={:#x} polls={polls}",
            timer_adapter.signal_badge(),
        );
    }

    let drained = timer_scheduler
        .service_timer_source(timer_adapter, |_| true)
        .map_err(|error| match error {
            ServiceTimerError::Program { error, transition } => stop!(
                "timer deadline reprogramming failed during {phase}: {error:?} wakes={}",
                transition.events.len()
            ),
            ServiceTimerError::Acknowledge { error, transition } => stop!(
                "timer acknowledgement failed during {phase}: {error:?} wakes={}",
                transition.events.len()
            ),
            error => stop!("timer service rejected the observed {phase} expiry: {error:?}"),
        })?;
    let timer_end = timer_adapter
        .monotonic_now()
        .map_err(|error| stop!("timer clock unreadable after {phase} service: {error:?}"))?;
    if phase == "startup" {
        crate::diagnostic_println!(
            "SLIME_TIMER serviced events={} programming={:?}",
            drained.events.len(),
            drained.programming,
        );
        crate::diagnostic_println!(
            "SLIME_TIMER advanced start={} end={} delta={}",
            timer_start.0,
            timer_end.0,
            timer_end.0.wrapping_sub(timer_start.0),
        );
        crate::diagnostic_println!("SLIME_TIMER OK");
    } else {
        crate::diagnostic_println!(
            "SLIME_TIMER phase={phase} serviced events={} programming={:?}",
            drained.events.len(),
            drained.programming,
        );
        crate::diagnostic_println!(
            "SLIME_TIMER phase={phase} advanced start={} end={} delta={}",
            timer_start.0,
            timer_end.0,
            timer_end.0.wrapping_sub(timer_start.0),
        );
        crate::diagnostic_println!("SLIME_TIMER phase={phase} OK");
    }
    Ok(())
}

#[repr(C, align(4096))]
pub struct FreePage(pub [u8; GRANULE_SIZE]);

/// A root-image page whose virtual address becomes the console dispatcher's
/// scratch window (B41).
///
/// Separate from the loader's: the console thread maps a caller's window into
/// its own address while the main dispatcher may be mapping another into
/// [`FREE_PAGE`], and one shared virtual address cannot hold both.
pub(crate) static mut CONSOLE_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// A second root-image page, whose virtual address becomes the standing window
/// for one device's MMIO register bank (P5.4.2a).
///
/// Separate from `FREE_PAGE` rather than sharing it: the loader and every
/// windowed syscall map and unmap a child frame at the scratch address on each
/// use, so an MMIO frame left mapped there would be replaced by the next
/// transfer. A device register bank must stay mapped for as long as the driver
/// holds the device.
pub(crate) static mut DEVICE_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// Standing MMIO windows for the userspace-authority inventory, one per
/// granule in QEMU's virtio-mmio transport range.
///
/// The scan page is transient; a granule containing an attached transport must
/// remain mapped until its generation-declared userspace driver binds it.
#[cfg(not(slime_boot_selector))]
pub(crate) static mut AUTHORITY_MMIO_PAGES: [FreePage; VIRTIO_MMIO_GRANULES] =
    [const { FreePage([0; GRANULE_SIZE]) }; VIRTIO_MMIO_GRANULES];

#[cfg(slime_boot_selector)]
pub(crate) static mut BOOT_MMIO_PAGES: [FreePage; MAX_BLOCK_DEVICES] =
    [const { FreePage([0; GRANULE_SIZE]) }; MAX_BLOCK_DEVICES];
#[cfg(slime_boot_selector)]
pub(crate) static mut BOOT_QUEUE_PAGES: [FreePage; MAX_BLOCK_DEVICES] =
    [const { FreePage([0; GRANULE_SIZE]) }; MAX_BLOCK_DEVICES];
#[cfg(slime_boot_selector)]
pub(crate) static mut BOOT_BUFFER_PAGES: [FreePage; MAX_BLOCK_DEVICES] =
    [const { FreePage([0; GRANULE_SIZE]) }; MAX_BLOCK_DEVICES];

/// QEMU virt's architecture-specific virtio-mmio transport window.
///
/// These are pinned machine facts, not discovery. The generation's userspace
/// driver owns device semantics; root uses the constants only for the bounded
/// bootstrap inventory and IRQ-capability handoff.
///
/// QEMU q35 has no virtio-mmio window at all: virtio devices there are PCI
/// functions behind an ACPI-described host bridge. P6 explicitly does not
/// enumerate PCI or enable bus mastering — that is H2's — so this profile
/// declares an empty transport range and its bootstrap inventory finds no
/// devices. The range is stated as zero granules rather than omitted so the
/// scan is a real bounded loop over nothing instead of a separate code path.
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;
#[cfg(target_arch = "riscv64")]
pub(crate) const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
#[cfg(target_arch = "x86_64")]
pub(crate) const VIRTIO_MMIO_BASE: usize = 0;
/// Bytes between consecutive transports.
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_MMIO_STRIDE: usize = 0x200;
#[cfg(any(target_arch = "riscv64", target_arch = "x86_64"))]
pub(crate) const VIRTIO_MMIO_STRIDE: usize = 0x1000;
pub(crate) const VIRTIO_MMIO_SLOTS_PER_GRANULE: usize = GRANULE_SIZE / VIRTIO_MMIO_STRIDE;
/// Number of transport granules to scan.
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_MMIO_GRANULES: usize = 4;
#[cfg(target_arch = "riscv64")]
pub(crate) const VIRTIO_MMIO_GRANULES: usize = 8;
#[cfg(target_arch = "x86_64")]
pub(crate) const VIRTIO_MMIO_GRANULES: usize = 0;
/// Interrupt number of the first transport in seL4's IRQ namespace.
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_MMIO_FIRST_IRQ: sel4::Word = 48;
#[cfg(target_arch = "riscv64")]
pub(crate) const VIRTIO_MMIO_FIRST_IRQ: sel4::Word = 1;
/// Unreachable on this profile: no transport exists to derive an IRQ for.
#[cfg(target_arch = "x86_64")]
pub(crate) const VIRTIO_MMIO_FIRST_IRQ: sel4::Word = 0;
/// Badge the device notification carries, distinct from the timer's.
pub(crate) const VIRTIO_IRQ_BADGE: sel4::Word = 0x2;

pub(crate) const fn virtio_irq(paddr: usize) -> sel4::Word {
    let index = ((paddr - VIRTIO_MMIO_BASE) / VIRTIO_MMIO_STRIDE) as sel4::Word;
    VIRTIO_MMIO_FIRST_IRQ + index
}

mod state;
use state::*;

pub(super) mod adaptive;
mod console_runtime;
pub mod platform;

use console_runtime::{ConsoleTables, declared_capability, input_script, start_console_dispatcher};
// Matches the sole caller's cfg in `main.rs`: the fixture image asserts the
// root's two-fixture proof path rather than launching a generation graph, so it
// never admits an IO-resource budget and never probes for userspace authority.
#[cfg(all(not(slime_boot_selector), not(slime_root_fixture)))]
pub use platform::probe_authority_devices;

#[derive(Clone, Copy)]
pub struct RootEndpoints {
    pub service: sel4::cap::Endpoint,
    pub console: sel4::cap::Endpoint,
}

pub struct RuntimeDevices<'a> {
    pub timer: &'a mut PhysicalTimerAdapter,
    #[cfg(slime_boot_selector)]
    pub boot_blocks: &'a mut device::BlockDevices,
    pub input: Option<device::TerminalInput>,
    pub io_authority: &'a mut platform::AuthorityInventory,
}

/// What the phases of the launch share: the generation, the tables that
/// outlive the launch, and the resources the generation admitted.
struct Launch<'a, 'g> {
    generation: &'a Generation<'g>,
    admission: &'a Admission,
    allocator: &'a mut ObjectAllocator,
    tasks: &'static mut TaskTable<MAX_TASKS>,
    windows: &'static mut WindowTable<MAX_WINDOW_ENTRIES>,
    instances: &'static mut LaunchedInstances,
    private_budget: Option<PrivateMemoryBudget<'g>>,
    adaptive: Option<adaptive::AdaptivePolicy<'g>>,
    clock_authority: Option<boot_contracts::clock_authority::ClockAuthority<'g>>,
    wait_sources: Option<boot_contracts::wait_set::WaitSet<'g>>,
    scheduling_policy: Option<boot_contracts::scheduling_class::SchedulingClass<'g>>,
    lifecycle_policy: Option<boot_contracts::lifecycle_policy::LifecyclePolicy<'g>>,
    io_budget: Option<boot_contracts::io_resource::IoResourceBudget<'g>>,
    io_service: services::IoResourceService,
    io_authority: &'a mut platform::AuthorityInventory,
}

/// What a phase with nothing to hand on returns.
type Phase = Result<(), Stop>;

/// Launch the generation's root-started instances and serve them. Each phase
/// makes the kernel calls of one stretch of the launch, in one order for every
/// root image, and returns [`Stop`] when the launch cannot go on.
pub fn launch_instance_graph(
    generation: &Generation<'_>,
    admission: &Admission,
    bootinfo: &sel4::BootInfo,
    allocator: &mut ObjectAllocator,
    scratch: &ScratchPage,
    endpoints: RootEndpoints,
    devices: RuntimeDevices<'_>,
    #[cfg(slime_boot_selector)] boot_runtime: &mut boot_selector::BootRuntime,
) -> Phase {
    let RuntimeDevices {
        timer,
        #[cfg(slime_boot_selector)]
        boot_blocks,
        input,
        io_authority,
    } = devices;
    let mut launch = Launch::admit(generation, admission, allocator, io_authority)?;
    launch.provision_images()?;
    let mut launched = 0;
    for index in 0..generation.instance_count() {
        launched += usize::from(launch.stage(index, scratch, endpoints)?);
    }
    launch.wire(launched)?;
    launch.declare_clocks_and_waits()?;
    launch.declare_classes_and_states()?;
    launch.report_layout();
    #[cfg(slime_private_fail_large_map)]
    launch.qualify_capacity(bootinfo)?;
    launch.activate(launched)?;
    // No component request has been received yet: activation can queue a
    // synchronous IPC call, but only the service loop below can mutate the
    // ClockService scheduler or program its hardware deadline. This second
    // proof therefore establishes post-activation IRQ liveness before timer
    // ownership passes to the service loop.
    prove_timer(timer, "post-graph-start")?;

    let mut buffers = SharedBufferTable::new(GenerationEpoch(generation.number));
    launch.declare_quotas(&mut buffers)?;
    // The shared filesystem namespaces and their append-only interned scopes.
    let mut namespaces = directory::Namespaces::new();
    let mut scopes = directory::ScopeTable::new();

    // B41: the console dispatcher starts before the service loop, so console
    // traffic has a receiver for as long as any child can send. `windows`
    // outlives it — the tables live in statics.
    start_console_dispatcher(
        bootinfo,
        launch.allocator,
        endpoints.console,
        ConsoleTables {
            windows: launch.windows,
            tasks: launch.tasks,
            script: input_script(generation.number),
            input,
            namespaces: &mut namespaces,
            scopes: &scopes,
        },
    )?;

    // The last marker before the service loop, which is where the readiness
    // record is written. A panel stopping here means the components and the
    // console dispatcher exist but the graph never reached healthy. The
    // console dispatcher is a second thread from here on, but it never touches
    // the panel; this is still the only renderer.
    #[cfg(target_arch = "x86_64")]
    crate::boot::show_stage(launch.allocator, "COMPONENTS RUNNING");

    // SAFETY: the launch reset each service above, and the service loop is the
    // only borrower of the four statics from here on.
    serve_instance_graph(
        generation,
        launch.instances,
        endpoints.service,
        endpoints.console,
        launch.tasks,
        launch.windows,
        &mut buffers,
        unsafe { &mut *ptr::addr_of_mut!(CLOCK_SERVICE) },
        unsafe { &mut *ptr::addr_of_mut!(WAIT_SET_SERVICE) },
        unsafe { &mut *ptr::addr_of_mut!(SCHEDULING_SERVICE) },
        launch.scheduling_policy.as_ref(),
        unsafe { &mut *ptr::addr_of_mut!(LIFECYCLE_SERVICE) },
        launch.lifecycle_policy.as_ref(),
        timer,
        launch.allocator,
        scratch,
        &mut launch.io_service,
        launch.io_authority,
        admission.fabric_capability_slots,
        &mut scopes,
        launch.adaptive.as_mut(),
        #[cfg(slime_boot_selector)]
        boot_blocks,
        #[cfg(slime_boot_selector)]
        boot_runtime,
    )
}

impl<'a, 'g> Launch<'a, 'g> {
    /// Decode the resources the generation admitted, and make every declared
    /// guarantee physical before the first task is constructed.
    fn admit(
        generation: &'a Generation<'g>,
        admission: &'a Admission,
        allocator: &'a mut ObjectAllocator,
        io_authority: &'a mut platform::AuthorityInventory,
    ) -> Result<Self, Stop> {
        // The three tables are ~488 KiB together and live in `.bss` rather
        // than in a frame; see the comment above `LAUNCH_TASKS`. As locals
        // they subtracted `0x7a000` from `sp` in one prologue step,
        // overrunning the 1 MiB stack.
        let (tasks, windows, instances) = init_launch_tables();
        // C10.2's declared private-memory budget, resolved once.
        // `Admission::admit` has already refused a malformed or over-committed
        // one, so anything reaching here is a budget this root can honour in
        // full.
        let private_budget = admitted(
            crate::generation::private_memory_budget_object(generation),
            "SLIME_MEM FAIL admitted budget",
            stopped,
        )?;
        // Every declared guarantee is made physical here, before the first
        // task is constructed: backing a later static construction could spend
        // is not a guarantee. A policy this machine cannot fund stops the boot
        // while nothing has been published.
        let mut policy_instances = [boot_contracts::private_memory_policy::Instance {
            identity: [0; 32],
            owner: None,
        }; crate::generation::MAX_ADMITTED_INSTANCES];
        let policy = crate::generation::private_memory_policy_object(generation);
        let adaptive = match admitted(policy, "SLIME_MEM FAIL admitted policy", stopped)? {
            Some(decoded) => {
                let count =
                    crate::generation::private_memory_instances(generation, &mut policy_instances)
                        .map_err(|error| {
                            stop!("SLIME_MEM FAIL policy topology rejected: {error:?}")
                        })?;
                let instances = &policy_instances[..count];
                match adaptive::AdaptivePolicy::admit(decoded, instances, allocator) {
                    Ok(policy) => {
                        policy.report();
                        Some(policy)
                    }
                    Err(failure) => {
                        failure.report();
                        return Err(stop!("SLIME_MEM FAIL adaptive admission refused"));
                    }
                }
            }
            None => None,
        };
        let holders = private_budget
            .as_ref()
            .map_or(0, PrivateMemoryBudget::holder_count);
        let declared = private_budget.is_some() as u8;
        crate::diagnostic_println!("SLIME_MEM budget holders={holders} declared={declared}");
        let clock_authority = admitted(
            generation::clock_authority_object(generation),
            "SLIME_CLOCK FAIL admitted authority",
            stopped,
        )?;
        let clock = clock_authority.as_ref();
        let (holders, quota) = (
            clock.map_or(0, |authority| authority.holder_count()),
            clock.map_or(0, |authority| authority.timer_quota()),
        );
        crate::diagnostic_println!("SLIME_CLOCK authority holders={holders} timer_quota={quota}");
        let wait_sources = admitted(
            wait_set::source_object(generation),
            "SLIME_WAIT FAIL admitted sources",
            stopped,
        )?;
        let declared = wait_sources
            .as_ref()
            .map_or(0, |sources| sources.entry_count());
        let resource = wait_sources.is_some() as u8;
        crate::diagnostic_println!("SLIME_WAIT sources declared={declared} resource={resource}");
        let scheduling_policy = admitted(
            generation::scheduling_class_object(generation),
            "SLIME_SCHED FAIL admitted policy",
            stopped,
        )?;
        let lifecycle_policy = admitted(
            lifecycle::policy_object(generation),
            "SLIME_LIFECYCLE FAIL admitted policy",
            stopped,
        )?;
        let io_budget = admitted(
            generation::io_resource_budget_object(generation),
            "SLIME_IO FAIL admitted budget",
            stopped,
        )?;
        Ok(Self {
            generation,
            admission,
            allocator,
            tasks,
            windows,
            instances,
            private_budget,
            adaptive,
            clock_authority,
            wait_sources,
            scheduling_policy,
            lifecycle_policy,
            io_budget,
            io_service: services::IoResourceService::new(),
            io_authority,
        })
    }

    /// Provision the declared large-image population before launch. Static
    /// extent anchors survive task reclamation, so first use cannot change the
    /// generation's retained backing while a child is being reclaimed.
    fn provision_images(&mut self) -> Phase {
        if self.adaptive.is_some() {
            return Ok(());
        }
        let mut backing = [None; MAX_TASKS];
        for (index, slot) in backing
            .iter_mut()
            .enumerate()
            .take(self.generation.instance_count())
        {
            let budget = self.private_budget.as_ref();
            if let Some(bits) = image_arena_bits(self.generation, index, budget, stopped)? {
                *slot = Some(
                    self.allocator
                        .begin_task_arena(bits)
                        .map_err(|error| stop!("image backing rejected: {error:?}"))?,
                );
            }
        }
        for arena in backing.into_iter().flatten() {
            self.allocator
                .release_task_arena(arena)
                .map_err(|error| stop!("image backing release rejected: {error:?}"))?;
        }
        Ok(())
    }

    /// Build the task of the instance at `index` as its plan declares, without
    /// running it. Returns whether the root starts the instance.
    fn stage(
        &mut self,
        index: usize,
        scratch: &ScratchPage,
        endpoints: RootEndpoints,
    ) -> Result<bool, Stop> {
        let generation = self.generation;
        let note = |line: core::fmt::Arguments<'_>| crate::diagnostic_println!("{line}");
        let planned = plan_instance(generation, self.admission, index, note, stopped)?;
        let Some(plan) = planned else {
            return Ok(false);
        };
        let instance = plan.instance;
        let id = self
            .tasks
            .create(
                self.allocator,
                &plan.image,
                endpoints.service,
                endpoints.console,
                plan.authority,
                Supervision::SelfManaged,
                sel4::init_thread::slot::VSPACE.cap(),
                scratch,
                sel4::init_thread::slot::ASID_POOL.cap(),
                None,
                Some(instance.executable),
                Some(index),
                // Only the bootstrap instance composes a boot graph, so only it
                // is told which one. Every other instance starts with zero.
                if index == generation.bootstrap() {
                    generation.boot_action.id()
                } else {
                    0
                },
                plan.cspace_size_bits,
                plan.child_slots,
                plan.priority,
                plan.threads,
                plan.worker_priorities,
                // The quota this generation declares for this component
                // (C10.2). Zero for a component the budget does not name, which
                // is the same deny-by-default answer an absent
                // `sharedBufferBudget` holder gets: authority is never ambient,
                // so omission means "grows nothing" rather than "gets a small
                // default".
                //
                // Resolved before `create` rather than installed after it,
                // unlike the shared-buffer quota: `create` feeds this into the
                // arena plan, because an arena is fixed at construction and
                // never grows, so a ceiling whose frames the arena has no room
                // for would be one the task could never reach.
                declared_private_memory_pages(self.private_budget.as_ref(), instance.name),
                // The admitted address maximum for a policy subject. Its
                // backing arrives on demand against the entitlement bound
                // below, so construction reserves none of it.
                self.adaptive
                    .as_ref()
                    .and_then(|policy| policy.maximum_pages(instance.name)),
            )
            .map_err(|error| {
                stop!(
                    "SLIME_GRAPH FAIL instance {} construction failed: {error:?}",
                    instance.name
                )
            })?;
        self.equip(index, instance, plan.executable, plan.authority.grants, id)?;
        Ok(true)
    }

    /// Give the constructed task `id` what the generation declares for its
    /// instance: its entitlement, its transfer windows, its bindings and its IO
    /// quota. The task is still suspended, and no dispatcher can see it.
    fn equip(
        &mut self,
        index: usize,
        instance: Instance<'g>,
        executable: &str,
        grants: usize,
        id: TaskId,
    ) -> Phase {
        let (name, task_id, bindings) = (instance.name, id.0, instance.binding_count());
        // Bound here, between construction and publication: a subject that
        // cannot bind fails the boot rather than running with an entitlement
        // nobody holds.
        if let Some(policy) = self.adaptive.as_mut()
            && policy.maximum_pages(name).is_some()
        {
            let Some(binding) = policy.bind(name) else {
                return Err(stop!("SLIME_MEM FAIL incarnation refused instance={name}"));
            };
            self.tasks
                .bind_private_memory(id, binding)
                .map_err(|error| {
                    stop!("SLIME_MEM FAIL binding install instance={name} error={error:?}")
                })?;
        }
        let Some(task) = self.tasks.get(id) else {
            return Err(stop!(
                "SLIME_GRAPH FAIL constructed task {task_id} is missing"
            ));
        };
        // One window per thread (B47): each stages its own payloads, and a
        // thread whose window was never declared is refused at bind and cannot
        // receive anything.
        let vspace = &task.vspace;
        for (thread, pages) in vspace.pages.iter().take(vspace.threads).enumerate() {
            let (addr, window, alias) = (
                pages.transfer_window_addr,
                pages.transfer_window,
                pages.transfer_window_alias,
            );
            self.windows
                .declare(id, thread, addr, window, alias)
                .map_err(|error| {
                    stop!("SLIME_GRAPH FAIL window declaration rejected: {error:?}")
                })?;
        }
        let (window, entry) = (vspace.main().transfer_window_addr, task.entry);
        let (frames, tables) = (vspace.frames_mapped, vspace.tables_mapped);
        self.install_bindings(index, instance, id)?;
        let driver = boot_contracts::io_resource::driver_identity(name);
        if let Some(quota) = self
            .io_budget
            .as_ref()
            .and_then(|budget| budget.quota_for(&driver))
        {
            let ordinal = quota.device as usize;
            let shared = self.io_authority.device(ordinal).is_some_and(|device| {
                (0..self.io_authority.len()).any(|other_ordinal| {
                    other_ordinal != ordinal
                        && self
                            .io_authority
                            .device(other_ordinal)
                            .is_some_and(|other| other.region == device.region)
                })
            });
            let driver = crate::io_resource::DriverId(u64::from(task_id));
            services::install_driver(&mut self.io_service, driver, index, quota, shared).map_err(
                |error| {
                    stop!(
                        "SLIME_IO FAIL quota install task={task_id} instance={name} error={error:?}"
                    )
                },
            )?;
            let (devices, shared) = (self.io_authority.len(), shared as u8);
            crate::diagnostic_println!(
                "SLIME_IO quota task={task_id} instance={name} devices={devices} shared_granule={shared}"
            );
        }
        self.instances
            .record(index, instance.executable, id)
            .map_err(|error| stop!("SLIME_GRAPH FAIL instance mapping rejected: {error:?}"))?;
        crate::diagnostic_println!(
            "SLIME_GRAPH staged task={task_id} instance={name} executable={executable} grants={grants} bindings={bindings} window={window:#x} frames={frames} tables={tables} entry={entry:#x}"
        );
        Ok(())
    }

    /// Install the typed authority that each binding of `instance` declares
    /// into the capability table of task `id`. Endpoints are wired later.
    fn install_bindings(&mut self, index: usize, instance: Instance<'g>, id: TaskId) -> Phase {
        let (generation, name) = (self.generation, instance.name);
        let Some(table) = self.tasks.authority_mut(id) else {
            return Err(stop!(
                "SLIME_GRAPH FAIL capability table unavailable for task {}",
                id.0
            ));
        };
        for binding_index in 0..instance.binding_count() {
            let binding = generation
                .binding(instance, binding_index)
                .map_err(|error| {
                    stop!("SLIME_GRAPH FAIL instance {name} binding rejected: {error:?}")
                })?;
            let grant = generation
                .grant(binding.grant)
                .map_err(|error| stop!("SLIME_GRAPH FAIL bound grant rejected: {error:?}"))?;
            if grant.capability_kind == CapabilityKind::Endpoint {
                continue;
            }
            let bound = grant.name;
            if !generation.grant_applies_to_instance(grant, index) {
                return Err(stop!(
                    "SLIME_GRAPH FAIL binding {bound} is unrelated to instance {name}"
                ));
            }
            let capability = if grant.capability_kind == CapabilityKind::Executable {
                let GrantEndpoint::Executable(executable) = grant.target else {
                    return Err(stop!(
                        "SLIME_GRAPH FAIL binding {bound} executable target rejected"
                    ));
                };
                graph::CapabilityEntry::executable(executable, grant.rights)
            } else {
                // Every kind this path still constructs is either singular or
                // carries its per-device identity in the IO-resource authority
                // table rather than in a launch-order ordinal, so the resource
                // argument is 0. B90 deleted the one ordinal that was not: the
                // `Block` counter, whose value no operation ever read.
                declared_capability(grant.capability_kind, 0, grant.rights)
            };
            let Some(capability) = capability else {
                return Err(stop!(
                    "SLIME_GRAPH FAIL binding {bound} carries invalid typed authority"
                ));
            };
            let slot = u32::try_from(binding.slot)
                .map_err(|_| stop!("SLIME_GRAPH FAIL binding {bound} slot is out of range"))?;
            table.install(slot, capability).map_err(|error| {
                stop!("SLIME_GRAPH FAIL binding {bound} slot={slot} rejected: {error:?}")
            })?;
            // A factory is authority to mint objects, so where it lands is the
            // difference between a component reaching its own declared factory
            // and reaching none. The boot layout names the slot and this
            // records that the root honoured it.
            if matches!(capability, graph::CapabilityEntry::BufferFactory(_)) {
                crate::diagnostic_println!(
                    "SLIME_GRAPH factory placed task={} component={name} slot={slot} kind={}",
                    id.0,
                    capability.kind_name(),
                );
            }
        }
        Ok(())
    }

    /// Materialize the endpoints and notifications between the staged tasks.
    /// Graph launch is the one phase with no marker between its start and the
    /// readiness record, so the panel names its three steps: images staged
    /// into child VSpaces, endpoints materialized between them, then the
    /// components started. No component runs until `activate`.
    fn wire(&mut self, launched: usize) -> Phase {
        let (generation, admission) = (self.generation, self.admission);
        crate::diagnostic_println!(
            "SLIME_GRAPH staged instances={launched} root_autostart={} loadable_executables={} slimecm={} wrong_target={} unrecognized={}",
            admission.root_autostart_instances(generation).count(),
            admission.loadable,
            admission.slime_component_images,
            admission.wrong_target_images,
            admission.unrecognized_images,
        );
        #[cfg(target_arch = "x86_64")]
        crate::boot::show_stage(self.allocator, "IMAGES STAGED");
        let peers = unsafe { &mut *ptr::addr_of_mut!(PEER_ENDPOINTS) };
        let materialized = peers
            .materialize(generation, self.instances, self.allocator, self.tasks)
            .map_err(|error| {
                stop!("SLIME_GRAPH FAIL endpoint materialization rejected: {error:?}")
            })?;
        crate::diagnostic_println!(
            "SLIME_GRAPH peer endpoints created={} grants={} installed={}",
            peers.len(),
            materialized.grants,
            materialized.installed,
        );
        #[cfg(target_arch = "x86_64")]
        crate::boot::show_stage(self.allocator, "ENDPOINTS WIRED");
        let notifications = unsafe { &mut *ptr::addr_of_mut!(NOTIFICATIONS) };
        let mut report = notifications
            .materialize(generation, self.allocator)
            .map_err(|error| {
                stop!("SLIME_GRAPH FAIL notification materialization rejected: {error:?}")
            })?;
        for launched in self.instances.iter() {
            let (id, task_id) = (launched.task, launched.task.0);
            let Some(task) = self.tasks.get(id) else {
                return Err(stop!("SLIME_GRAPH FAIL launched task {task_id} is missing"));
            };
            let (arena, cnode, bits) = (task.cleanup.arena, task.cnode, task.cnode_size_bits);
            let installed = notifications
                .install_instance(
                    generation,
                    launched.instance,
                    id,
                    self.allocator,
                    arena,
                    cnode,
                    bits,
                )
                .map_err(|error| {
                    stop!("SLIME_GRAPH FAIL notification install rejected: {error:?}")
                })?;
            report.bindings += installed;
            // C8.13.3: each install filled a slot the generation declared, so
            // it belongs to the holder's declared-space count -- the space
            // `capabilitySlots` budgets. Credited rather than censused because
            // every install here is the root's own.
            if let Some(task) = self.tasks.get_mut(id) {
                task.cspace.installed(installed as u32);
            }
        }
        let (created, bindings) = (report.created, report.bindings);
        crate::diagnostic_println!(
            "SLIME_GRAPH notifications created={created} bindings={bindings}"
        );
        Ok(())
    }

    /// Declare the clock authority and the wait sources of every launched
    /// task. Every live task gets a row, including one the resource names
    /// nothing for, so each table answers about a live task rather than about
    /// whether it was ever declared.
    fn declare_clocks_and_waits(&mut self) -> Phase {
        let generation = self.generation;
        let named = |instance| {
            generation
                .instance(instance)
                .map_or("?", |instance| instance.name)
        };
        let notifications = unsafe { &mut *ptr::addr_of_mut!(NOTIFICATIONS) };
        // This generation creates one clock service instance. The static lives
        // across the process lifetime, but a boot reaches this path once;
        // resetting here makes that lifetime explicit and prevents stale
        // authority if the launch path ever becomes restartable.
        unsafe { *ptr::addr_of_mut!(CLOCK_SERVICE) = clock::ClockService::new() };
        let clock_service = unsafe { &mut *ptr::addr_of_mut!(CLOCK_SERVICE) };
        for launched in self.instances.iter() {
            let (id, task_id, instance) = (launched.task, launched.task.0, launched.instance);
            let Some(task) = self.tasks.get(id) else {
                return Err(stop!("SLIME_CLOCK FAIL launched task {task_id} is missing"));
            };
            let (declared, arena) = (self.clock_authority.as_ref(), task.cleanup.arena);
            let authority = clock_service
                .declare(
                    declared,
                    generation,
                    notifications,
                    self.allocator,
                    arena,
                    id,
                    instance,
                )
                .map_err(|error| {
                    stop!("SLIME_CLOCK FAIL authority install task={task_id} error={error:?}")
                })?;
            crate::diagnostic_println!(
                "SLIME_CLOCK authority task={task_id} instance={} flags={:#x} timers={} badge={:#x}",
                named(instance),
                authority.flags(),
                authority.timer_quota(),
                authority.timer_badge(),
            );
        }

        // C9.2's supervision-source delivery, declared per launched task.
        unsafe { *ptr::addr_of_mut!(WAIT_SET_SERVICE) = wait_set::WaitSetService::new() };
        let wait_set_service = unsafe { &mut *ptr::addr_of_mut!(WAIT_SET_SERVICE) };
        for launched in self.instances.iter() {
            let (id, task_id, instance) = (launched.task, launched.task.0, launched.instance);
            let Some(task) = self.tasks.get(id) else {
                return Err(stop!("SLIME_WAIT FAIL launched task {task_id} is missing"));
            };
            let (sources, arena) = (self.wait_sources.as_ref(), task.cleanup.arena);
            let declared = wait_set_service
                .declare(
                    sources,
                    generation,
                    notifications,
                    self.allocator,
                    arena,
                    id,
                    instance,
                )
                .map_err(|error| {
                    stop!("SLIME_WAIT FAIL source install task={task_id} error={error:?}")
                })?;
            if declared != 0 {
                crate::diagnostic_println!(
                    "SLIME_WAIT supervision task={task_id} instance={} sources={declared}",
                    named(instance),
                );
            }
        }
        Ok(())
    }

    /// Record the declared class (C9.3) and state (C9.4) of every launched
    /// task, on the same rule as the clock authority: a row for every live
    /// task.
    ///
    /// The band's priority is *already* on each thread: it travels in the
    /// plan's `ScheduleRecord`, which the builder wrote from this same
    /// resource, and `TaskTable::create` applied it before this runs. What the
    /// class install adds is the root's own view — which class each task is
    /// at, so `CLASS_READ` can answer and `CLASS_PROMOTE` can find a subject.
    /// Deriving the priority twice is exactly the drift B71 closed, so the
    /// marker prints the class beside the priority the schedule record
    /// already carries.
    fn declare_classes_and_states(&mut self) -> Phase {
        use boot_contracts::lifecycle_policy::state_name;
        use boot_contracts::scheduling_class::{UNDECLARED_CLASS_ID, class_name};
        let generation = self.generation;
        let named = |instance| {
            generation
                .instance(instance)
                .map_or("?", |instance| instance.name)
        };
        let classes = self.scheduling_policy.as_ref();
        unsafe { *ptr::addr_of_mut!(SCHEDULING_SERVICE) = scheduling::SchedulingService::new() };
        let scheduling_service = unsafe { &mut *ptr::addr_of_mut!(SCHEDULING_SERVICE) };
        for launched in self.instances.iter() {
            let (id, task_id, instance) = (launched.task, launched.task.0, launched.instance);
            let class = scheduling_service
                .declare(classes, generation, id, instance)
                .map_err(|error| {
                    stop!("SLIME_SCHED FAIL class install task={task_id} error={error:?}")
                })?;
            if classes.is_some() {
                crate::diagnostic_println!(
                    "SLIME_SCHED class task={task_id} instance={} class={} priority={} worker={} worker_priority={}",
                    named(instance),
                    class.name(),
                    class.priority(),
                    class_name(class.worker_class_id()),
                    class.worker_priority(),
                );
            }
        }
        if let Some(policy) = classes {
            crate::diagnostic_println!(
                "SLIME_SCHED policy bands={} instances={} promotions={} unnamed={}",
                policy.class_count(),
                policy.instance_count(),
                policy.promotion_count(),
                class_name(UNDECLARED_CLASS_ID),
            );
            for index in 0..policy.class_count() {
                let Some(band) = policy.band(index) else {
                    return Err(stop!("SLIME_SCHED FAIL band {index} is missing"));
                };
                let (class, priority) = (class_name(band.class_id), band.priority);
                crate::diagnostic_println!("SLIME_SCHED band class={class} priority={priority}");
            }
        }
        let states = self.lifecycle_policy.as_ref();
        unsafe { *ptr::addr_of_mut!(LIFECYCLE_SERVICE) = lifecycle::LifecycleService::new() };
        let lifecycle_service = unsafe { &mut *ptr::addr_of_mut!(LIFECYCLE_SERVICE) };
        for launched in self.instances.iter() {
            let (id, task_id, instance) = (launched.task, launched.task.0, launched.instance);
            let state = lifecycle_service
                .declare(states, id, instance)
                .map_err(|error| {
                    stop!("SLIME_LIFECYCLE FAIL state install task={task_id} error={error:?}")
                })?;
            if states.is_some() {
                crate::diagnostic_println!(
                    "SLIME_LIFECYCLE state task={task_id} instance={} state={} attempts={}",
                    named(instance),
                    state_name(state),
                    lifecycle_service.attempts_remaining(states, instance, generation),
                );
            }
        }
        let Some(policy) = states else {
            return Ok(());
        };
        // `admitted=` is the count *admission* resolved, printed beside the
        // count the resource decodes to. Two producers of one number, exactly
        // as C9.3's class marker is cross-checked against the `ScheduleRecord`
        // the builder wrote: admission walks every restart row and proves its
        // subject is owner-spawned, so a disagreement here means the policy the
        // root validated is not the policy it is about to install (B71's
        // shape).
        let (admitted, restarts) = (
            self.admission.lifecycle_restarts.unwrap_or(0),
            policy.restart_count(),
        );
        if admitted != restarts {
            return Err(stop!(
                "SLIME_LIFECYCLE FAIL admission counted {admitted} restart policies, resource declares {restarts}"
            ));
        }
        crate::diagnostic_println!(
            "SLIME_LIFECYCLE policy transitions={} restarts={restarts} admitted={admitted} dependencies={} parameters={} initial={} terminal={}",
            policy.transition_count(),
            policy.dependency_count(),
            policy.parameter_count(),
            state_name(policy.initial_state()),
            state_name(policy.terminal_state()),
        );
        for index in 0..policy.transition_count() {
            let Some(edge) = policy.transition(index) else {
                return Err(stop!("SLIME_LIFECYCLE FAIL transition {index} is missing"));
            };
            let (from, to) = (state_name(edge.from_state), state_name(edge.to_state));
            crate::diagnostic_println!("SLIME_LIFECYCLE edge from={from} to={to}");
        }
        Ok(())
    }

    /// Print the capability layout of the bootstrap instance.
    fn report_layout(&self) {
        let generation = self.generation;
        let bootstrap = self
            .instances
            .task_for_instance(self.admission.bootstrap_instance);
        let table = bootstrap.and_then(|id| self.tasks.authority(id));
        crate::diagnostic_println!(
            "[layout] path={} slots={} max={}",
            generation
                .instance(self.admission.bootstrap_instance)
                .map_or("?", |instance| instance.name),
            table.map_or(0, |table| table.len()),
            graph::MAX_TASK_CAPS,
        );
        if let Some(table) = table {
            for (slot, capability) in table.slots() {
                let Some(capability) = capability else {
                    continue;
                };
                crate::diagnostic_println!(
                    "[layout] {slot} {} {} {:#x}",
                    capability.kind_name(),
                    resource_label(generation, capability),
                    capability.rights_bits(),
                );
            }
        }
        crate::diagnostic_println!("[layout] end");
    }

    /// Report whether the headroom of the admitted envelope fits this machine.
    ///
    /// The qualification the *admitted* envelope supports, not a larger one the
    /// planner can merely represent. The per-holder figure is the target's
    /// declared region ceiling, and the holder count is the headroom the
    /// aggregate ceiling still admits beyond the quotas this generation already
    /// declares: admission refuses anything past that ceiling, so counting the
    /// declared graph plus a second full aggregate would report a population no
    /// image can install. MEM-1G raises the contract row; this report follows it.
    #[cfg(slime_private_fail_large_map)]
    fn qualify_capacity(&mut self, bootinfo: &sel4::BootInfo) -> Phase {
        const PAGES_PER_HOLDER: usize = private_memory::MAX_REGION_PAGES;
        const ROOT_STACK_BYTES: usize = 1024 * 1024;
        const ROOT_HEAP_BYTES: usize = 512 * 1024;
        let (generation, allocator) = (self.generation, &mut *self.allocator);
        let overflow = || stop!("SLIME_MEM FAIL capacity arithmetic overflow");
        let declared_pages = self.private_budget.as_ref().map_or(0, |budget| {
            (0..budget.holder_count())
                .filter_map(|index| budget.holder(index))
                .fold(0usize, |total, holder| {
                    total.saturating_add(holder.page_quota as usize)
                })
        });
        let holders =
            private_memory::MAX_TOTAL_PAGES.saturating_sub(declared_pages) / PAGES_PER_HOLDER;
        let exemplar_instance = (0..generation.instance_count()).find(|index| {
            generation
                .instance(*index)
                .is_ok_and(|instance| instance.name == "private-memory-granted")
        });
        let Some(exemplar_task) = exemplar_instance
            .and_then(|instance| self.instances.task_for_instance(instance))
            .and_then(|id| self.tasks.get(id))
        else {
            return Err(stop!("SLIME_MEM FAIL capacity exemplar missing"));
        };
        let Some(static_backing) = allocator.task_static_backing(exemplar_task.cleanup.arena)
        else {
            return Err(stop!(
                "SLIME_MEM FAIL capacity exemplar backing unavailable"
            ));
        };
        let plan = object_allocator::plan_task_backing(PAGES_PER_HOLDER).ok_or_else(overflow)?;
        let required_descriptors = plan
            .allocation_descriptors
            .checked_add(static_backing.allocation_descriptors)
            .and_then(|per_holder| per_holder.checked_mul(holders))
            .ok_or_else(overflow)?;
        allocator
            .ensure_allocation_descriptors(required_descriptors)
            .map_err(|error| stop!("SLIME_MEM FAIL capacity metadata backing: {error:?}"))?;
        allocator
            .ensure_extent_descriptors((plan.extent_descriptors + 1) * holders)
            .map_err(|error| stop!("SLIME_MEM FAIL capacity extent metadata: {error:?}"))?;
        // Planning may fund metadata or CSpace growth from admitted ordinary
        // resources, so every availability figure is read after it settles.
        let ordinary_layout = allocator.task_backing_extents_fit(plan, static_backing, holders);
        let capacity = object_allocator::TaskBackingCapacity {
            plan,
            static_backing,
            holders,
            cslots_available: allocator.free_slots(),
            allocation_descriptors_available: allocator.allocation_descriptors_free(),
            extent_descriptors_available: allocator.extent_descriptors_free(),
            ordinary_bytes_available: allocator.untyped_bytes_remaining()
                + allocator.preserved_bytes_remaining(),
            ordinary_layout,
            root_image_bytes: bootinfo.user_image_frames().len() * child_vspace::GRANULE_SIZE,
            root_stack_bytes: ROOT_STACK_BYTES,
            root_heap_bytes: ROOT_HEAP_BYTES,
        };
        let required = capacity.requirements().ok_or_else(overflow)?;
        let private_allocations = plan.allocation_descriptors * holders;
        let private_extents = plan.extent_descriptors * holders;
        let private_cslots = plan.required_cslots * holders;
        let private_reserved = plan.reserved_bytes * holders;
        crate::diagnostic_println!(
            "SLIME_MEM qualification scope=contract-aggregate-headroom holders={} pages={} private_allocations={} private_extents={} private_cslots={} private_reserved={} payload={} tables={} alignment={} static_allocations={} static_reserved={} required_allocations={} required_extents={} required_cslots={} required_reserved={} allocation_capacity={} allocations_available={} extent_capacity={} extents_available={} cslots_available={} ordinary_available={} ordinary_layout={} root_image={} root_metadata={} root_stack={} root_heap={} fit={} limit={}",
            capacity.holders,
            plan.private_pages,
            private_allocations,
            private_extents,
            private_cslots,
            private_reserved,
            plan.payload_bytes * holders,
            plan.page_table_bytes * holders,
            plan.alignment_waste * holders,
            static_backing.allocation_descriptors,
            static_backing.reserved_bytes,
            required.allocation_descriptors,
            required.extent_descriptors,
            required.cslots,
            required.reserved_bytes,
            allocator.allocation_descriptor_capacity(),
            capacity.allocation_descriptors_available,
            allocator.extent_descriptor_capacity(),
            capacity.extent_descriptors_available,
            capacity.cslots_available,
            capacity.ordinary_bytes_available,
            capacity.ordinary_layout.is_ok() as u8,
            capacity.root_image_bytes,
            // Static root structures plus every byte the allocator's dynamic
            // metadata and CSpace bootstrap retains, charged exactly once.
            core::mem::size_of::<ObjectAllocator>()
                + core::mem::size_of::<TaskTable<MAX_TASKS>>()
                + allocator.infrastructure_owned_bytes(),
            capacity.root_stack_bytes,
            capacity.root_heap_bytes,
            capacity.fits() as u8,
            capacity.limiting_resource().unwrap_or("none"),
        );
        Ok(())
    }

    /// Start the staged tasks, each after the instances it depends on.
    fn activate(&mut self, launched: usize) -> Phase {
        let generation = self.generation;
        let mut active = [false; MAX_TASKS];
        let mut activated = 0;
        while activated < launched {
            let before = activated;
            for launched_instance in self.instances.iter() {
                if active[launched_instance.instance] {
                    continue;
                }
                let instance = match generation.instance(launched_instance.instance) {
                    Ok(instance) => instance,
                    Err(error) => {
                        return Err(stop!(
                            "SLIME_GRAPH FAIL activation instance rejected: {error:?}"
                        ));
                    }
                };
                let name = instance.name;
                let mut ready = true;
                for dependency_index in 0..instance.dependency_count() {
                    let dependency = match generation.dependency(instance, dependency_index) {
                        Ok(dependency) => dependency,
                        Err(error) => {
                            return Err(stop!("SLIME_GRAPH FAIL dependency rejected: {error:?}"));
                        }
                    };
                    let dependency_index = (0..generation.instance_count())
                        .find(|index| {
                            generation
                                .instance(*index)
                                .is_ok_and(|candidate| candidate.name == dependency.name)
                        })
                        .unwrap_or(usize::MAX);
                    if dependency_index >= active.len()
                        || self.instances.task_for_instance(dependency_index).is_none()
                    {
                        return Err(stop!(
                            "SLIME_GRAPH FAIL instance {name} has non-root dependency {}",
                            dependency.name
                        ));
                    }
                    ready &= active[dependency_index];
                }
                if !ready {
                    continue;
                }
                self.tasks
                    .activate(launched_instance.task)
                    .map_err(|error| {
                        stop!("SLIME_GRAPH FAIL activation failed instance={name}: {error:?}")
                    })?;
                active[launched_instance.instance] = true;
                activated += 1;
            }
            if activated == before {
                return Err(stop!(
                    "SLIME_GRAPH FAIL root instance dependency barrier unsatisfied"
                ));
            }
        }
        crate::diagnostic_println!("SLIME_GRAPH activated instances={activated}");
        Ok(())
    }

    /// Declare the shared-buffer quota of every launched task in `buffers`,
    /// and print what each task holds.
    fn declare_quotas(&mut self, buffers: &mut SharedBufferTable) -> Phase {
        let generation = self.generation;
        let budget = shared_buffer_budget(generation);
        let mut budgeted = 0;
        for launched_instance in self.instances.iter() {
            let instance = generation.instance(launched_instance.instance).unwrap();
            let (name, task_id) = (instance.name, launched_instance.task.0);
            let quota = declared_quota(budget.as_ref(), name);
            if quota != HolderQuota::DENY {
                budgeted += 1;
            }
            buffers
                .declare_quota(HolderId(u64::from(task_id)), quota)
                .map_err(|error| {
                    stop!("SLIME_GRAPH FAIL quota rejected task={task_id}: {error:?}")
                })?;
            // The same record the spawn path emits. The boot path declared its
            // quotas silently and printed only the aggregate, so a per-instance
            // ceiling could be wrong in the generation and invisible in the
            // transcript -- and a gate checking the declared ceilings against
            // the observed ones saw only the spawned children (B52).
            crate::diagnostic_println!(
                "SLIME_GRAPH quota task={task_id} instance={name} executable={} pages={} buffers={} mappings={} loans={}",
                generation
                    .executable(launched_instance.executable)
                    .map_or("<unknown>", |record| record.name),
                quota.byte_pages,
                quota.buffer_count,
                quota.mapping_count,
                quota.loan_count,
            );
            let task = self.tasks.get(launched_instance.task);
            // The private-memory ceiling actually installed on the task, read
            // back from the task record rather than from the budget (C10.2).
            // Reading it back is the point: the declared number and the live
            // one are two different facts, and a gate comparing the
            // generation's declaration against this line is what proves the
            // declared quota *is* the ceiling rather than something the root
            // recomputed on its own.
            crate::diagnostic_println!(
                "SLIME_MEM quota task={task_id} instance={name} declared={} installed={} base={:#x}",
                declared_private_memory_pages(self.private_budget.as_ref(), name),
                task.map_or(0, |task| task.private_memory.quota()),
                task.map_or(0, |task| task.private_memory.base()),
            );
            // The adaptive counterpart of the quota line above, read back from
            // the task record rather than from the policy, and printed for
            // every constructed task on a policy-carrying plane including one
            // the policy names no subject for.
            if let Some(policy) = self.adaptive.as_ref() {
                policy.report_task(
                    launched_instance.task,
                    name,
                    task.and_then(|task| task.private_binding),
                    // The address maximum installed on the record, not the
                    // pages committed so far: an adaptive holder starts with
                    // none.
                    task.map_or(0, |task| task.private_memory.reservation()),
                    task.map_or(0, |task| task.private_memory.base()),
                );
            }
            // The fixed path's pre-provisioned backing, priced only for a
            // holder that actually has one. An adaptive holder reserves
            // address space and no backing, so pricing its whole address
            // maximum as provisioned frames would refuse a window the machine
            // was never asked to fill.
            let installed = task
                .filter(|task| task.private_binding.is_none())
                .map_or(0, |task| task.private_memory.quota());
            if installed != 0 {
                let Some(plan) = object_allocator::plan_task_backing(installed) else {
                    return Err(stop!("SLIME_MEM FAIL accounting overflow task={task_id}"));
                };
                crate::diagnostic_println!(
                    "SLIME_MEM accounting task={task_id} instance={name} reservation={} reserved={} payload={} tables={} alignment={} frames_large={} frames_base={} descriptors={} extents={} cslots={}",
                    installed * crate::child_vspace::GRANULE_SIZE,
                    plan.reserved_bytes,
                    plan.payload_bytes,
                    plan.page_table_bytes,
                    plan.alignment_waste,
                    plan.data_extents,
                    plan.private_pages,
                    plan.allocation_descriptors,
                    plan.extent_descriptors,
                    plan.required_cslots,
                );
            }
        }
        crate::diagnostic_println!(
            "SLIME_GRAPH quotas declared={} budgeted={budgeted} holders={}",
            self.instances.len(),
            budget.as_ref().map_or(0, SharedBufferBudget::holder_count),
        );
        Ok(())
    }
}

/// A resource the generation may declare. `Admission::admit` accepted the
/// generation, so one that will not decode stops the launch; `record` opens
/// the record that says which.
fn admitted<T, D: core::fmt::Debug, E>(
    resource: Option<Result<T, D>>,
    record: &str,
    mut refuse: impl FnMut(Record<'_>) -> E,
) -> Result<Option<T>, E> {
    resource
        .transpose()
        .map_err(|error| refuse(format_args!("{record} will not decode: {error:?}")))
}

/// The pure decisions of the launch print nothing and invoke no kernel
/// operation, so a host test can call them. Each hands the record of a plan it
/// refuses to the caller's `refuse` and returns what `refuse` makes of it: the
/// launch passes [`stopped`], and a test reads the record.
type Record<'r> = core::fmt::Arguments<'r>;

/// Print the record of a refused plan and stop.
fn stopped(record: Record<'_>) -> Stop {
    stop!("{record}")
}

/// What the plan declares for one instance the root starts.
struct InstancePlan<'g> {
    instance: Instance<'g>,
    executable: &'g str,
    image: ChildImage<'g>,
    authority: crate::generation::Authority,
    cspace_size_bits: usize,
    priority: sel4::Word,
    threads: usize,
    worker_priorities: [sel4::Word; child_vspace::MAX_CHILD_THREADS],
    child_slots: task::ChildSlots,
}

/// Resolve what the plan declares for the instance at `index`, or `None` for
/// an instance the root does not start. `note` receives each record of the
/// plan, in the order the launch prints them.
fn plan_instance<'g, E>(
    generation: &Generation<'g>,
    admission: &Admission,
    index: usize,
    mut note: impl FnMut(Record<'_>),
    mut refuse: impl FnMut(Record<'_>) -> E,
) -> Result<Option<InstancePlan<'g>>, E> {
    macro_rules! no {
        ($($record:tt)*) => { refuse(format_args!($($record)*)) };
    }
    let instance = generation
        .instance(index)
        .map_err(|error| no!("SLIME_GRAPH FAIL instance rejected: {error:?}"))?;
    if !instance.is_root_autostart() {
        return Ok(None);
    }
    let executable = generation
        .executable(instance.executable)
        .map_err(|error| no!("SLIME_GRAPH FAIL executable rejected: {error:?}"))?;
    let (name, program) = (instance.name, executable.name);
    let Some(plan) = admission.executable_plan(instance.executable) else {
        return Err(no!(
            "SLIME_GRAPH FAIL executable {program} was not admitted"
        ));
    };
    if !plan.format.is_loadable() {
        return Err(no!(
            "SLIME_GRAPH FAIL root instance {name} executable {program} is not loadable"
        ));
    }
    let object = generation
        .object(executable.object)
        .map_err(|error| no!("SLIME_GRAPH FAIL object rejected: {error:?}"))?;
    let profile = boot_contracts::target_profile::TargetProfile::by_name(TARGET_PROFILE)
        .map_err(|error| no!("SLIME_GRAPH FAIL profile unavailable: {error:?}"))?;
    let elf = boot_contracts::component_image::admit_elf(object.bytes, profile)
        .map_err(|error| no!("SLIME_GRAPH FAIL executable {program} refused: {error:?}"))?;
    let image = ChildImage::parse(elf)
        .map_err(|error| no!("SLIME_GRAPH FAIL executable {program} image rejected: {error:?}"))?;
    let authority = bound_authority(generation, instance)
        .map_err(|error| no!("SLIME_GRAPH FAIL binding authority rejected: {error:?}"))?;
    // The child's CSpace is exactly as large as the admitted plan says its
    // declared authority needs, not a compiled-in shell.
    let cspace_size_bits = generation
        .instance_cspace_size_bits(index)
        .map_err(|error| no!("SLIME_GRAPH FAIL CSpace plan rejected: {error:?}"))?
        .ok_or_else(|| no!("SLIME_GRAPH FAIL instance {name} has no planned CSpace"))?
        as usize;
    // Priority likewise. An instance that declares none resolves to the
    // root's default, which is what every child ran at before the plan's
    // `ScheduleRecord` was consulted at all (B48).
    let priority = generation
        .instance_priority(index)
        .map_err(|error| no!("SLIME_GRAPH FAIL schedule plan rejected: {error:?}"))?
        .map_or(task::CHILD_PRIORITY, sel4::Word::from);
    // Its own record rather than a field on `staged`: the priority a thread
    // runs at is not observable from anything else in the transcript, and a
    // declaration nothing can check is indistinguishable from the constant it
    // replaced (B48).
    note(format_args!(
        "SLIME_GRAPH schedule instance={name} priority={priority} default={}",
        task::CHILD_PRIORITY,
    ));
    // Threads the plan declares for this instance (B47). One unless the
    // manifest asked for more; the root builds exactly this many TCBs, so a
    // declared thread that never runs would be visible here as a count the
    // transcript disagrees with.
    let threads = generation
        .instance_threads(index)
        .map_err(|error| no!("SLIME_GRAPH FAIL thread plan rejected: {error:?}"))?
        .unwrap_or(1);
    note(format_args!(
        "SLIME_GRAPH threads instance={name} count={threads}"
    ));
    // Each worker's own declared priority (B48). Resolved here rather than in
    // `task::create` so the transcript records what the plan asked for, the
    // same way the main thread's priority is recorded above.
    let mut worker_priorities = [priority; child_vspace::MAX_CHILD_THREADS];
    for (thread, slot) in worker_priorities
        .iter_mut()
        .enumerate()
        .take(threads)
        .skip(1)
    {
        let resolved = generation
            .thread_priority(index, thread)
            .map_err(|error| no!("SLIME_GRAPH FAIL thread schedule rejected: {error:?}"))?
            .map_or(priority, sel4::Word::from);
        *slot = resolved;
        note(format_args!(
            "SLIME_GRAPH schedule instance={name} thread={thread} priority={resolved}"
        ));
    }
    // The child's own TCB and fault endpoint go where the plan declared them.
    // A plan that omits either leaves the root nowhere to install authority
    // the child needs, so it is refused rather than defaulted.
    let child_slots = match generation.instance_child_slots(index) {
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
        .map_err(|error| {
            no!("SLIME_GRAPH FAIL instance {name} declares an unusable child layout: {error:?}")
        })?,
        Ok(_) => {
            return Err(no!(
                "SLIME_GRAPH FAIL instance {name} has no planned service, console, TCB, or fault slot"
            ));
        }
        Err(error) => {
            return Err(no!("SLIME_GRAPH FAIL child slot plan rejected: {error:?}"));
        }
    };
    Ok(Some(InstancePlan {
        instance,
        executable: program,
        image,
        authority,
        cspace_size_bits,
        priority,
        threads,
        worker_priorities,
        child_slots,
    }))
}

/// The size in bits of the arena a large image's task needs, or `None` for
/// an instance the root starts itself, an image this target does not load,
/// and an image the common arena holds.
fn image_arena_bits<E>(
    generation: &Generation<'_>,
    index: usize,
    private_budget: Option<&PrivateMemoryBudget<'_>>,
    mut refuse: impl FnMut(Record<'_>) -> E,
) -> Result<Option<usize>, E> {
    use sel4::{CapTypeForObjectOfFixedSize, CapTypeForObjectOfVariableSize};
    macro_rules! no {
        ($($record:tt)*) => { refuse(format_args!($($record)*)) };
    }
    let instance = generation
        .instance(index)
        .map_err(|error| no!("image instance rejected: {error:?}"))?;
    if instance.is_root_autostart() {
        return Ok(None);
    }
    let executable = generation
        .executable(instance.executable)
        .map_err(|error| no!("image executable rejected: {error:?}"))?;
    let object = generation
        .object(executable.object)
        .map_err(|error| no!("image object rejected: {error:?}"))?;
    let profile = boot_contracts::target_profile::TargetProfile::by_name(TARGET_PROFILE)
        .map_err(|error| no!("image target rejected: {error:?}"))?;
    let Ok(elf) = boot_contracts::component_image::admit_elf(object.bytes, profile) else {
        return Ok(None);
    };
    let image =
        ChildImage::parse(elf).map_err(|error| no!("image preflight rejected: {error:?}"))?;
    if image.image_pages() + 2 <= 512 {
        return Ok(None);
    }
    let threads = generation
        .instance_threads(index)
        .map_err(|error| no!("image threads rejected: {error:?}"))?
        .unwrap_or(1);
    let cspace = generation
        .instance_cspace_size_bits(index)
        .map_err(|error| no!("image CSpace rejected: {error:?}"))?
        .unwrap_or(task::CHILD_CNODE_SIZE_BITS as u32) as usize;
    let reservation = match declared_private_memory_pages(private_budget, instance.name) {
        0 => 0,
        _ => private_memory::MAX_REGION_PAGES,
    };
    let mut plan = image
        .vspace_arena_plan(threads, reservation)
        .map_err(|error| no!("image arena rejected: {error:?}"))?;
    let mut fits = plan
        .add(sel4::cap_type::CNode::object_blueprint(cspace))
        .is_some();
    for _ in 0..threads {
        fits = fits && plan.add(sel4::cap_type::Tcb::object_blueprint()).is_some();
    }
    match plan.required_size_bits().filter(|_| fits) {
        Some(bits) => Ok(Some(bits)),
        None => Err(no!("image arena overflow")),
    }
}

/// Component arrivals the graph service loop will handle before declaring the
/// graph wedged. Bound timer-Notification wakes are serviced independently and
/// do not consume this request-path progress ceiling.
///
/// Generous against what the declared components actually issue — each binds a
/// window, and spawn-service additionally runs a shared-buffer probe and spawns
/// two children — while still bounding a request livelock so it fails in seconds
/// rather than burning the gate's whole timeout.
///
/// component that blocks now costs two iterations where it cost one — the
/// `recv` that reports `WouldBlock` and the `wait` that parks.
///
/// The stream plane's nine tasks provision four route roles and broker seven
/// samples in **136** iterations. The **QoS** plane is far denser and is what
/// set this number: it drives a simulated clock through scheduled deadline,
/// lifespan, liveliness, and retry boundaries, and each boundary is a park/wake
/// cycle for the broker plus a sweep of every participant. At 512 it exhausted
/// the bound with `fabric-publisher`'s send still queued — diagnosed at length
/// as B28 and mistaken in turn for a lost wake, a scheduler fault, and an
/// always-ready park source before the cause turned out to be this constant.
/// Measured directly: **768 completes, 512 does not.** 2048 is that floor with
/// Raised for P5.4.3's dango plane, which is the densest composition
/// this port runs: a scripted console session is one round trip *per keystroke*
/// — 96 bytes of script — on top of four components' startup, every command's
/// profile resolution, and a spawn plus a supervised wait per launch. Measured
/// the same way B28 was: 2048 exhausted with the session still parked.
///
/// Raised again for `sel4-io-tcp-buffers`: two holders each stream 1310720
/// bytes through the virtio link, and every frame costs root arrivals for its
/// DMA pin, release and interrupt besides the service's clock reads. That plane
/// needs about 50000 arrivals; 32768 exhausted it with the second holder's
/// throughput stream half sent.
const MAX_GRAPH_ITERATIONS: usize = 131072;

/// The arrival count at which a resident product graph reports a checkpoint.
/// Product has no request limit; this only marks that the dispatcher is still
/// serving, and `check-duo-slisp.py` pins the number.
const RESIDENT_CHECKPOINT_ITERATIONS: usize = 32768;

#[cfg(test)]
mod launch_tests;
mod services;
pub use services::reclaim::private_memory_cause;
use services::{serve_instance_graph, spawn::resource_label};
