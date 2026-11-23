//! `slime-root`: the seL4 root task that owns Slime's dynamic mechanism.
//!
//! This binary is the entry point; the library holds the stages. Authority
//! always follows a generation declaration, so the order is fixed:
//!
//! 1. `main` takes deterministic ownership of BootInfo CSlots and kernel
//!    untypeds, and installs the root's console where the platform has one;
//! 2. `slime_root::boot::run` proves the root's foundations, then decodes and
//!    admits the generation, classifying every component payload;
//! 3. `slime_root::graph_runtime` derives each child's authority from declared
//!    grants and builds every child task — CSpace, VSpace, TCB, IPC buffer,
//!    badged root endpoint, fault handler — without running any of them;
//! 4. it activates only after every allocation has succeeded, one task at a
//!    time so the serial record is ordered;
//! 5. it serves requests and faults, and reclaims each task's recorded CSlots.
//!
//! A stage that cannot go on prints its record and returns; `main` halts.
//!
//! A root built with `SLIME_ROOT_FIXTURE=1` runs `fixture_runtime::run` in
//! place of stages 3 to 5. No other root compiles that module or embeds the
//! child image.

#![no_main]
#![no_std]
// Startup exercises the allocation, task, IPC, and fault paths; the scheduling,
// timer, and shared-buffer state machines are owned by the library but driven
// by callers a parent integration adds, so not every item is reachable here.
#![allow(dead_code)]

// The mechanism modules live in `slime_root`, the library half of this package
// (B23), so their unit tests can run under `just test_host`. This binary links
// that library rather than recompiling the modules, which is what makes a host
// test result evidence about the root the seL4 image boots.
#[cfg(slime_root_console_pl011)]
use slime_root::device;

#[cfg(slime_root_console_pl011)]
use core::ptr;

use sel4_root_task::root_task;

#[cfg(slime_root_console_pl011)]
use slime_root::child_vspace::{GRANULE_SIZE, ScratchPage};
use slime_root::object_allocator::ObjectAllocator;

use slime_root::fatal;
#[cfg(slime_root_console_pl011)]
use slime_root::graph_runtime::FreePage;
#[cfg(not(slime_root_fixture))]
use slime_root::graph_runtime::{RootEndpoints, RuntimeDevices, launch_instance_graph};

/// The generation this root task admits and launches.
///
/// Supplied by the build harness through `SLIME_GENERATION`, which
/// `scripts/build/build-sel4.py` points at the generation for this build's
/// exact seL4 target profile. The checked-in fixture is the fallback, and it is
/// the retained x86 generation P5.1 admitted: its component payloads are the
/// retired kernel's segment-carrying images, which are admitted for authority
/// derivation and never activated. Which one is compiled in therefore decides
/// whether this boot launches a graph or reports that it cannot — and the boot
/// markers say which, rather than leaving it to be inferred.
/// Aligned to 8: the component ELFs this
/// generation carries are parsed in place, at their address inside this
/// constant, and `object`'s ELF64 parser requires an 8-byte-aligned buffer.
/// Each image's payload sits at a multiple of 8 from the start of the
/// generation, so aligning the whole blob aligns every ELF within it.
/// Selected once here so the two `include_bytes!` sites — the length and the
/// value — can never disagree about which file they read. A `match` cannot do
/// this: the two arms are arrays of different lengths, so they have different
/// types and will not unify.
#[cfg(all(not(slime_boot_selector), slime_generation_supplied))]
macro_rules! generation_bytes {
    () => {
        include_bytes!(env!("SLIME_GENERATION"))
    };
}
#[cfg(all(not(slime_boot_selector), not(slime_generation_supplied)))]
macro_rules! generation_bytes {
    () => {
        include_bytes!("../fixtures/generation.bin")
    };
}

#[cfg(not(slime_boot_selector))]
static GENERATION: Aligned<{ generation_bytes!().len() }> = Aligned(*generation_bytes!());

#[cfg(not(slime_boot_selector))]
const GENERATION_BYTES: &[u8] = &GENERATION.0;

/// `include_bytes!` only guarantees byte alignment, but `object`'s ELF64 parser
/// requires an 8-byte-aligned buffer; `Aligned` forces that without a runtime
/// copy into a new allocation.
#[repr(align(8))]
struct Aligned<const N: usize>([u8; N]);

/// Standing window for the root's own console UART.
///
/// Every image for QEMU `virt` maps the PL011 at `0x0900_0000` here and writes
/// its transcript through it. The interactive product reads its keyboard from
/// the same page: a device page is retyped once per boot.
#[cfg(slime_root_console_pl011)]
static mut ROOT_CONSOLE_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// The allocator's descriptor tables.
///
/// `const`-initialized, so the `MAX`-valued record sentinels place this in
/// `.data` and the image carries its bytes. It must stay a static initializer:
/// the value is multi-megabyte, and any form that constructs it before storing
/// it — `MaybeUninit::new(ObjectAllocator::empty())`, or a local moved into
/// place — materializes it in a frame and overruns the root's 1 MiB stack.
/// Reducing the image cost therefore requires zero-valued sentinels, not a
/// different storage class.
static mut OBJECT_ALLOCATOR: ObjectAllocator = ObjectAllocator::empty();

// The stack must clear the deepest frame the service loop reaches, which is a
// shared-buffer teardown. At 256 KiB that frame ran off the bottom of the
// stack and the root task took a VM fault on `FREE_PAGE` — the scratch page
// `ScratchPage` deliberately leaves unmapped, which is the only reason the
// overflow was visible rather than silent corruption of whatever `.bss` lay
// below.
//
// This is backlog B3's failure mode, in the same repository, for the same
// reason: a table sized for the graph, built in a stack frame. Raising the
// stack to 1 MiB was not enough — `ActionList` reached 144 KiB and every
// by-value return stacked a second copy, so the stream plane's loan teardown
// overflowed again, this time faulting inside `build_actions` itself. It lives
// on the heap now (`ActionList::boxed`), which is why the heap is sized for
// two of them plus room: one held by a teardown in progress, one being built.
//
// The bound is stated here rather than discovered a third time.
#[root_task(stack_size = 1024 * 1024, heap_size = 1024 * 512)]
fn main(bootinfo: &sel4::BootInfoPtr) -> ! {
    // SAFETY: root startup is single-threaded, this is the sole initialization,
    // and the returned reference is held for the root task's lifetime.
    let allocator = unsafe { &mut *core::ptr::addr_of_mut!(OBJECT_ALLOCATOR) };
    if let Err(error) = allocator.initialize(bootinfo) {
        fatal!("allocator rejected bootinfo: {error:?}")
    }
    let root_node = allocator
        .allocate(slime_root::root_cspace::blueprint())
        .unwrap_or_else(|error| fatal!("root CSpace backing: {error:?}"));
    slime_root::root_cspace::install(root_node.cap().downcast())
        .unwrap_or_else(|error| fatal!("root CSpace cutover: {error:?}"));
    allocator.release_slot(root_node.index());
    allocator
        .initialize_metadata(bootinfo)
        .unwrap_or_else(|error| fatal!("root metadata bootstrap: {error:?}"));
    // The first record `main` itself emits: every later byte goes to the
    // root's own UART. The allocator's bring-up records and a fatal error
    // before this line reach the kernel's console only.
    #[cfg(slime_root_console_pl011)]
    #[cfg_attr(not(slime_qemu_keyboard), allow(unused_variables))]
    let console_registers = {
        let console_addr = ptr::addr_of!(ROOT_CONSOLE_PAGE) as usize;
        if let Err(error) = ScratchPage::claim(bootinfo, console_addr) {
            fatal!("root console page unavailable: {error:?}")
        }
        let registers = match device::DeviceRegion::map(
            allocator,
            sel4::init_thread::slot::VSPACE.cap(),
            console_addr,
            device::QEMU_PL011_PADDR,
        ) {
            Ok(registers) => registers,
            Err(error) => fatal!("root console UART unavailable: {error:?}"),
        };
        slime_root::diagnostic::install(console_addr);
        slime_root::diagnostic_println!(
            "SLIME_ROOT console uart=pl011 paddr={:#x}",
            device::QEMU_PL011_PADDR
        );
        registers
    };
    #[cfg_attr(slime_root_fixture, allow(unused_mut))]
    let mut booted = slime_root::boot::run(
        bootinfo,
        allocator,
        slime_root::boot::Inputs {
            #[cfg(not(slime_boot_selector))]
            generation: GENERATION_BYTES,
            #[cfg(slime_root_console_pl011)]
            console_registers,
        },
    )
    .unwrap_or_else(|stop| slime_root::graph_runtime::halt(stop));
    // A v4 generation launches only explicitly declared root-owned autostart
    // instances. Catalogue-only executables remain inert until a bound exec
    // capability authorizes a userspace spawn.
    #[cfg(not(slime_root_fixture))]
    {
        if booted.admission.loadable == 0 {
            fatal!("generation has no loadable executable")
        }
        launch_instance_graph(
            &booted.generation,
            &booted.admission,
            bootinfo,
            allocator,
            &booted.scratch,
            RootEndpoints {
                service: booted.service_endpoint,
                console: booted.console_endpoint,
            },
            RuntimeDevices {
                timer: &mut booted.timer_adapter,
                #[cfg(slime_boot_selector)]
                boot_blocks: &mut booted.block_devices,
                input: booted.product_input.take(),
                io_authority: &mut booted.io_authority,
            },
            #[cfg(slime_boot_selector)]
            &mut booted.boot_runtime,
        )
        .unwrap_or_else(|stop| slime_root::graph_runtime::halt(stop));
        #[cfg(all(slime_cv1800b_duo, not(slime_product_uart)))]
        slime_root::boot::request_duo_cold_reset(booted.timer_registers, booted.reset_registers);
        loop {
            core::hint::spin_loop();
        }
    }
    #[cfg(slime_root_fixture)]
    fixture_runtime::run(booted, allocator)
}

#[cfg(slime_root_fixture)]
mod fixture_runtime;
