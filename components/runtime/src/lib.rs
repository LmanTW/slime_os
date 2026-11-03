#![no_std]

// Two allocators, never both: `#[global_allocator]` is one symbol per link, and
// the choice is a property of the component rather than of an allocation.
// `heap` is CP3's fixed `.bss` bump allocator for the store plane; C10.3's
// `private-heap` is a free list over the generation-declared private region.
#[cfg(all(feature = "heap", feature = "private-heap"))]
compile_error!(
    "slime-rt: `heap` and `private-heap` both register a #[global_allocator]; \
     a component declares exactly one"
);

mod clock;
/// Whole-record console lines: build a line, then submit it in one write.
pub mod console_line;
#[cfg(feature = "heap")]
mod heap;
#[cfg(feature = "private-heap")]
mod private_heap;
/// C10.3's startup self-check over the private-region allocator. A module
/// rather than flat re-exports, mirroring
/// `slime_components::shared_buffer_probe`: `probe` and `ProbeOutcome` are only
/// meaningful under the name of the thing they probe.
#[cfg(feature = "private-heap")]
pub mod private_heap_probe;
mod syscall;

mod runtime;
/// C9.2's bounded wait set over one declared Notification. A module rather than
/// flat re-exports, on `private_heap_probe`'s rule: `Source`, `Ready`, and the
/// three ceilings are only meaningful under the name of the thing they bound.
pub mod wait_set;

#[cfg(feature = "heap")]
pub use heap::{BumpHeap, HEAP_BYTES, heap_used};
#[cfg(feature = "private-heap")]
pub use private_heap::{GROWTH_PAGES, PrivateHeap, PrivateHeapStats, private_heap_stats};
// One SHA-256 in the workspace: `boot_contracts::sha256` is a facade over
// RustCrypto's `sha2`, and this crate already links `boot-contracts`.
pub use boot_contracts::sha256::digest as sha256;
pub use clock::{monotonic_frequency, monotonic_read};
pub use syscall::{
    BufferLoan, BufferOccupancy, CapabilityDisposition, DIRECTORY_ROOT_BYTES, DmaDirection,
    DmaMapping, ERR_BAD_CAP, ERR_INVALID_ARG, ERR_OUT_OF_MEMORY, ERR_PEER_DEAD, ERR_SUCCESS,
    ERR_WOULDBLOCK, InputEvent, InputKey, IoDevice, IoMapping, IrqEvent, LifecycleStateInfo,
    Lifetime, MAX_CAPS_PER_MSG, MAX_DIRECTORY_PATH, MAX_MSG, PARAMETER_SELF_SLOT, PrivateMemory,
    RecordingParticipation, RecordingRole, RestartAdmission, Rights, SchedulingClassInfo,
    SharedBuffer, SlotOccupancy, SpawnGrant, Spawned, Termination, block_ring_authority_read,
    boot_action, call, cap_drop, capability_delegate, capability_import, capability_slot_occupancy,
    debug_write, directory_commit, directory_derive, directory_inspect, entropy_authority_read,
    exit, graph_query, graph_read, graph_route_index, input_read, io_device_bind, io_dma_map,
    io_dma_release, io_irq_ack, io_mmio_map, io_mmio_read32, io_mmio_write32, io_queue_map,
    io_request_begin, io_request_settle, lifecycle_parameter_read, lifecycle_parameter_write,
    lifecycle_restart_admit, lifecycle_state_advance, lifecycle_state_read, lifetime,
    network_application_read, network_destinations_read, network_interface_read, notification_poll,
    notification_signal, notification_wait, private_memory_grow, recording_participation, recv,
    recv_blocking, reply, resolve_binding, scheduling_class_promote, scheduling_class_read, send,
    shared_buffer_create, shared_buffer_loan, shared_buffer_loan_map, shared_buffer_map,
    shared_buffer_occupancy, shared_buffer_release, shared_buffer_return, shared_buffer_revoke,
    shared_buffer_seal, shared_buffer_unmap, simulated_time_advance, simulated_time_read, spawn,
    spawn_budget, supervision_derive, supervision_status, timer_arm, timer_cancel, try_send,
    unhealthy, wait_sources, yield_now, zenoh_grants_read,
};

/// C9.2's wait set, re-exported for the common case: a component builds one over
/// its declared Notification and registers the sources it cares about.
pub use wait_set::{WaitError, WaitSet};

/// The CSpace slot holding this component's root service endpoint — its only
/// root authority on the native seL4 transport.
pub use syscall::ROOT_SERVICE_SLOT;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}

/// Defines the component's seL4 entry point, calling `$main` and exiting 0 if
/// it returns. Startup installs the stack, Rust language runtime, IPC buffer,
/// and bound transfer window before component code runs.
///
/// `$main` takes the authenticated startup argument the root placed in this
/// thread's first C parameter. It is the generation's boot action for the
/// bootstrap instance and zero for every other component, so a component
/// composes its graph from admitted data rather than from a build flag.
#[macro_export]
macro_rules! entry {
    ($main:path, worker = $worker:path) => {
        $crate::entry!($main);

        /// The worker thread's stack.
        ///
        /// Its own, not a slice of the main thread's: two threads sharing a
        /// stack is immediate corruption. `declare_stack!` hardcodes the symbol
        /// `sel4-runtime-common`'s assembly entry reads, so this declares a
        /// separate one the root points the second TCB's stack pointer at.
        ///
        /// `#[used]` because nothing in the image references either symbol: the
        /// root resolves both from the symbol table and writes them into a TCB.
        /// Without it the linker's `--gc-sections` drops them and the root
        /// refuses the instance with `MissingWorkerImage`.
        #[used]
        #[unsafe(no_mangle)]
        static __slime_rt_worker_stack: $crate::_private::WorkerStack =
            $crate::_private::WorkerStack::new();

        /// The worker thread's entry point.
        ///
        /// The root writes this address into the second TCB's program counter,
        /// so it must be a plain `extern "C"` symbol with no prologue
        /// expectations — the stack-init shim the main thread uses runs once
        /// per process, not once per thread.
        #[unsafe(no_mangle)]
        extern "C" fn __slime_rt_worker_entrypoint(startup_arg: u32) -> ! {
            let worker: fn(u32) = $worker;
            unsafe { $crate::_private::start_thread(worker, startup_arg) }
        }

        /// Anchors the entry point against `--gc-sections`.
        ///
        /// `#[used]` applies to statics only, and nothing in the image calls
        /// the worker entry — the root resolves it from the symbol table and
        /// writes it into a TCB's program counter. Holding its address in a
        /// retained static is what keeps the function itself alive; without
        /// this the linker drops it and the root refuses the instance with
        /// `MissingWorkerImage`.
        #[used]
        static __slime_rt_worker_anchor: extern "C" fn(u32) -> ! = __slime_rt_worker_entrypoint;
    };
    ($main:path) => {
        $crate::_private::declare_stack!($crate::_private::STACK_SIZE);
        $crate::_private::declare_entrypoint_with_stack_init!();
        $crate::_private::declare_rust_entrypoint! {
            __slime_rt_entrypoint(startup_arg: u32)
        }

        fn __slime_rt_entrypoint(startup_arg: u32) -> ! {
            let main: fn(u32) = $main;
            unsafe { $crate::_private::start(main, startup_arg) }
        }
    };
}

pub mod _private {
    pub use sel4_runtime_common::{
        declare_entrypoint_with_stack_init, declare_rust_entrypoint, declare_stack,
    };

    pub use crate::runtime::{STACK_SIZE, WorkerStack, start, start_thread};
}
