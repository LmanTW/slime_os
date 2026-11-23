//! The boot sequence that the product root and the fixture root share.
//!
//! `main` initializes the allocator and installs the console, then calls
//! [`run`]. Everything from the qualification roles to the two service
//! endpoints happens here, in one order for every root image.
//!
//! [`run`] is a list of phases. A phase makes its kernel calls in a fixed
//! order, prints its own records, and returns [`Stop`] when it cannot go on.
//! A decision that needs no kernel call is a function of its own, so a host
//! test can call it: [`image_funding`], [`foundation_accounted`] and
//! [`beyond_legacy`]. Those functions print nothing.

#[cfg(slime_boot_selector)]
use crate::boot_selector;
use crate::graph_runtime::{FreePage, Stop, TARGET_PROFILE, prove_timer};
use crate::stop;
// The panel is P6.6's only readiness channel on a machine with no serial port,
// and the record it carries is reached through an x86 extra-BootInfo entry.
#[cfg(target_arch = "x86_64")]
use crate::{boot_record, framebuffer};
use crate::{
    buffer_adapter, child_vspace, generation, object_allocator, platform_timer, vm_attributes,
};
#[cfg(slime_duo_early_fault)]
use crate::{event, timer::PlatformTimer};
use core::ptr;

use boot_contracts::generation::Generation;
use buffer_adapter::BufferAdapter;
use child_vspace::{GRANULE_SIZE, ScratchPage};
use generation::Admission;
use object_allocator::ObjectAllocator;
use platform_timer::{PhysicalTimerAdapter, TIMER_IRQ};

#[cfg(slime_boot_selector)]
const BOOT_BUNDLE_IDENTITY: [u8; 32] = decode_hex32(env!("SLIME_BOOT_BUNDLE_IDENTITY"));

const fn decode_hex32(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 64);
    let mut out = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    out
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid boot bundle identity"),
    }
}

#[cfg(slime_duo_early_fault)]
fn run_duo_early_fault_control(
    timer_adapter: &mut PhysicalTimerAdapter,
    reset_registers: crate::device::MappedGranule,
) {
    let refused = timer_adapter.program_deadline(event::MonotonicInstant(u64::MAX));
    if !matches!(
        refused,
        Err(platform_timer::PlatformTimerAckError::RegisterAccess)
    ) {
        crate::fatal!("Duo early-fault control did not refuse an out-of-range RTC deadline")
    }
    crate::diagnostic_println!(
        "SLIME_DUO EARLY_FAULT phase=post-timer cause=timer-range-refused bounded=1"
    );
    crate::diagnostic_println!("SLIME_DUO reset request kind=cold");
    if !timer_adapter.request_cold_reset(reset_registers) {
        crate::fatal!("CV1800B cold-reset register access failed after early fault")
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(slime_cv1800b_duo)]
pub fn request_duo_cold_reset(
    timer_registers: crate::device::MappedGranule,
    reset_registers: crate::device::MappedGranule,
) -> ! {
    crate::diagnostic_println!("SLIME_DUO reset request kind=cold");
    if !platform_timer::request_cv1800b_cold_reset(timer_registers, reset_registers) {
        crate::fatal!("CV1800B cold-reset register access failed")
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(slime_product_test_terminator, slime_cv1800b_duo))]
fn request_duo_test_reset() -> ! {
    crate::diagnostic_println!("SLIME_DUO test terminator accepted");
    // SAFETY: root startup writes both `Some` values before the console thread
    // starts; the two MMIO mappings remain live for the root's lifetime.
    let timer = unsafe { ptr::addr_of!(DUO_TIMER_REGISTERS).read() };
    let reset = unsafe { ptr::addr_of!(DUO_RESET_REGISTERS).read() };
    match (timer, reset) {
        (Some(timer), Some(reset)) => request_duo_cold_reset(timer, reset),
        _ => crate::fatal!("Duo test reset registers unavailable"),
    }
}

#[cfg(any(slime_product_uart, slime_pc99_com1))]
const fn const_parse_hex_usize(value: &str) -> usize {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() > 2 && bytes[0] == b'0' && bytes[1] == b'x',
        "hex prefix required"
    );
    let mut index = 2;
    let mut parsed = 0usize;
    while index < bytes.len() {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'a'..=b'f' => bytes[index] - b'a' + 10,
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("invalid hexadecimal integer"),
        };
        parsed = parsed * 16 + digit as usize;
        index += 1;
    }
    assert!(parsed != 0, "integer must be nonzero");
    parsed
}

/// A root-image page whose virtual address becomes the loader's scratch window.
static mut FREE_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// Standing window for a physical board's product terminal receiver.
///
/// The board's product maps UART0 at the address supplied from its pinned
/// board profile. Plane images do not map it.
#[cfg(slime_product_uart)]
static mut PRODUCT_UART_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// Two root-image pages reclaimed as temporary mappings for the foundation
/// non-alias probe. Separate from the loader scratch page: the proof needs both
/// frames mapped simultaneously.
static mut FOUNDATION_PAGES: [FreePage; 2] = [const { FreePage([0; GRANULE_SIZE]) }; 2];

/// Root-image page reclaimed as the temporary mapping for the high ordinary
/// memory probe. It is distinct from every standing or loader scratch window,
/// so mapping the probe cannot displace a live frame.
static mut ORDINARY_PROBE_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// Standing window for the platform's memory-mapped timer registers, on the
/// profiles whose monotonic source is a device rather than an architected
/// register the kernel grants userspace access to.
#[cfg(slime_timer_registers)]
static mut TIMER_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// Scratch window the boot framebuffer's granules are mapped through in turn.
///
/// One page rather than a standing mapping of the whole mode: a panel-sized
/// linear framebuffer is megabytes, the root writes it once from top to
/// bottom, and `DeviceRegion::unmap` exists so one claimed root-image page can
/// walk a region larger than a granule. It is its own page rather than
/// `DEVICE_PAGE` or the loader's, because the walk runs while those hold their
/// own mappings.
#[cfg(target_arch = "x86_64")]
static mut FRAMEBUFFER_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);

/// Standing window for the CV1800B RTC control granule used to reset the board
/// after an autonomous physical proof completes. It must be mapped before the
/// timer granule: both come from one device untyped and retype is monotonic.
#[cfg(slime_cv1800b_duo)]
static mut RESET_PAGE: FreePage = FreePage([0; GRANULE_SIZE]);
#[cfg(all(slime_product_test_terminator, slime_cv1800b_duo))]
static mut DUO_RESET_REGISTERS: Option<crate::device::MappedGranule> = None;
#[cfg(all(slime_product_test_terminator, slime_cv1800b_duo))]
static mut DUO_TIMER_REGISTERS: Option<crate::device::MappedGranule> = None;

#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const TIMER_PADDR: usize = 0x0010_1000;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const TIMER_PADDR: usize = 0x0502_6000;
/// The IA-PC HPET's architectural base address on QEMU q35.
///
/// A pinned machine fact, not discovery: firmware reports it in the ACPI HPET
/// table, and P6 reads no ACPI (H1 owns the real inventory). This is the
/// address that machine's HPET is fixed at, and a machine whose firmware
/// relocates it is a different platform profile.
#[cfg(target_arch = "x86_64")]
const TIMER_PADDR: usize = 0xfed0_0000;
/// `timer@7c003000` of the BCM2712, behind the `soc` range at `0x10_0000_0000`.
#[cfg(slime_bcm2835_system_timer)]
const TIMER_PADDR: usize = 0x10_7c00_3000;
#[cfg(slime_cv1800b_duo)]
const RESET_PADDR: usize = 0x0502_5000;

#[cfg(slime_product_uart)]
const PRODUCT_UART_PADDR: usize = const_parse_hex_usize(env!("SLIME_PRODUCT_UART_PADDR"));
/// pc99's COM1 base I/O port, supplied by the build from `[qemu_pc99].serial`
/// so the emulator fact and the compiled-in port cannot disagree.
///
/// Narrowed with a compile-time bound rather than an `as` cast: x86 I/O ports
/// are 16 bits, and a truncating cast would turn an out-of-range pin into a
/// plausible-looking port instead of a build failure.
#[cfg(slime_pc99_com1)]
const PC99_COM1_PORT: u16 = {
    let port = const_parse_hex_usize(env!("SLIME_PC99_COM1_PORT"));
    assert!(port <= u16::MAX as usize, "I/O port must fit in 16 bits");
    port as u16
};

/// What the binary supplies: the bytes it embeds and the console it installed.
pub struct Inputs {
    #[cfg(not(slime_boot_selector))]
    pub generation: &'static [u8],
    #[cfg(slime_root_console_pl011)]
    pub console_registers: crate::device::DeviceRegion,
}

/// What the shared sequence leaves for the product launch or the fixture.
pub struct Booted {
    pub generation: Generation<'static>,
    pub admission: Admission,
    pub scratch: ScratchPage,
    pub service_endpoint: sel4::cap::Endpoint,
    pub console_endpoint: sel4::cap::Endpoint,
    pub timer_adapter: PhysicalTimerAdapter,
    #[cfg(not(slime_root_fixture))]
    pub product_input: Option<crate::device::TerminalInput>,
    #[cfg(not(slime_root_fixture))]
    pub io_authority: crate::graph_runtime::platform::AuthorityInventory,
    #[cfg(slime_boot_selector)]
    pub block_devices: crate::device::BlockDevices,
    #[cfg(slime_boot_selector)]
    pub boot_runtime: boot_selector::BootRuntime,
    #[cfg(all(slime_cv1800b_duo, not(slime_product_uart)))]
    pub timer_registers: crate::device::MappedGranule,
    #[cfg(slime_cv1800b_duo)]
    pub reset_registers: crate::device::MappedGranule,
}

/// The allocation descriptors and root slots that a generation with a large
/// image funds before launch, as `(descriptors, slots)`.
///
/// `pages` is the sum of the images' frames and `largest` the frames of the
/// largest one. An image above one leaf table is large. `None` without one:
/// the plan's own `required` slots are then the whole demand. `levels` is the
/// platform's count of translation levels.
pub fn image_funding(
    pages: usize,
    largest: usize,
    instances: usize,
    required: usize,
    levels: usize,
) -> Option<(usize, usize)> {
    let tables = pages.div_ceil(512) * levels;
    let margin = tables + instances * 32;
    (largest > 512).then_some((pages + margin, required + margin))
}

/// The (objects, slots, bytes) an allocator has handed out.
pub type Spent = (usize, usize, usize);

/// Whether the frame-independence proof spent exactly two frames, two slots
/// and its `anchors`.
pub fn foundation_accounted(before: Spent, after: Spent, anchors: usize) -> bool {
    after.0 == before.0 + 2 + anchors
        && after.1 == before.1 + 2 + anchors
        && after.2 == before.2 + 2 * GRANULE_SIZE
}

/// 1 when a probe frame at `probe_paddr` lies at or above the end of the
/// superseded ordinary-memory window of `profile`, else 0. Only QEMU ARM has
/// such a window. The result is reported, never enforced: capacity is whatever
/// the booted kernel hands root, and a smaller qualified inventory is not a
/// fault. The pinned product image's gate asserts `beyond_legacy=1`.
pub fn beyond_legacy(profile: &str, probe_paddr: usize) -> u8 {
    let legacy_platform_ram_end = match profile {
        "aarch64-sel4-qemu-virt" => Some(0x8000_0000),
        _ => None,
    };
    u8::from(legacy_platform_ram_end.is_some_and(|legacy_end| probe_paddr >= legacy_end))
}

/// Name a boot stage on the panel. A machine with no panel shows nothing.
#[cfg(target_arch = "x86_64")]
pub(crate) fn show_stage(allocator: &mut ObjectAllocator, stage: &str) {
    // SAFETY: the caller is the root's first thread, the only renderer; no
    // other thread of the root touches the panel.
    unsafe {
        framebuffer::with_panel(allocator, |panel, allocator| {
            let _ = boot_record::render_stage(panel, allocator, stage);
        });
    }
}

/// What a phase with nothing to hand on returns.
type Phase = Result<(), Stop>;

/// Claim the root-image `page` and map the device granule at `paddr` through
/// it. `what` names the registers in the two records of a failure.
#[cfg(slime_timer_registers)]
fn map_page(
    bootinfo: &sel4::BootInfoPtr,
    allocator: &mut ObjectAllocator,
    page: *const FreePage,
    paddr: usize,
    what: &str,
) -> Result<crate::device::MappedGranule, Stop> {
    ScratchPage::claim(bootinfo, page as usize)
        .map_err(|error| stop!("{what} page unavailable: {error:?}"))?;
    let vspace = sel4::init_thread::slot::VSPACE.cap();
    let region = crate::device::DeviceRegion::map(allocator, vspace, page as usize, paddr)
        .map_err(|error| stop!("{what} registers unavailable: {error:?}"))?;
    Ok(region.granule())
}

/// Report what the allocator took from BootInfo. An empty inventory stops the boot.
fn report_inventory(allocator: &ObjectAllocator) -> Phase {
    let initial_slots = allocator.slots_remaining();
    let initial_untypeds = allocator.untyped_count();
    let initial_bytes = allocator.untyped_bytes_remaining();
    if initial_slots == 0 || initial_untypeds == 0 || initial_bytes == 0 {
        return Err(stop!(
            "SLIME_FOUNDATION FAIL allocator slots={initial_slots} untypeds={initial_untypeds} bytes={initial_bytes}"
        ));
    }
    crate::diagnostic_println!(
        "SLIME_ROOT allocator slots={initial_slots} untypeds={initial_untypeds} bytes={initial_bytes}",
    );
    let mut ordinary_ranges = 0usize;
    let mut ordinary_bytes = 0usize;
    for (index, range) in allocator.ordinary_ranges().enumerate() {
        crate::diagnostic_println!(
            "SLIME_ROOT ordinary range={index} paddr={:#x} bytes={}",
            range.paddr,
            range.bytes,
        );
        ordinary_ranges += 1;
        ordinary_bytes = ordinary_bytes.saturating_add(range.bytes);
    }
    crate::diagnostic_println!(
        "SLIME_ROOT ordinary ranges={ordinary_ranges} bytes={ordinary_bytes} end={:#x}",
        allocator.ordinary_physical_end(),
    );
    Ok(())
}

/// Map the highest free ordinary frame, write and read it back, and release it.
fn probe_ordinary_memory(bootinfo: &sel4::BootInfoPtr, allocator: &mut ObjectAllocator) -> Phase {
    let probe_addr = ptr::addr_of!(ORDINARY_PROBE_PAGE) as usize;
    ScratchPage::claim(bootinfo, probe_addr)
        .map_err(|error| stop!("ordinary memory probe scratch unavailable: {error:?}"))?;
    let probe_slot = allocator
        .allocate_last_ordinary_granule()
        .map_err(|error| stop!("ordinary memory probe allocation failed: {error:?}"))?;
    let probe_paddr = allocator
        .physical_address_of(probe_slot.index())
        .ok_or_else(|| stop!("ordinary memory probe lost physical provenance"))?;
    let beyond_legacy = beyond_legacy(TARGET_PROFILE, probe_paddr);
    let probe_frame = probe_slot.cap();
    probe_frame
        .frame_map(
            sel4::init_thread::slot::VSPACE.cap(),
            probe_addr,
            sel4::CapRights::read_write(),
            vm_attributes::data(),
        )
        .map_err(|error| stop!("ordinary memory probe map failed: {error:?}"))?;
    const ORDINARY_PROBE_SENTINEL: u64 = 0x534c_494d_454d_454d;
    // SAFETY: `probe_addr` names the one mapped writable granule above and the
    // root task is single-threaded during startup, so no alias accesses it.
    unsafe { (probe_addr as *mut u64).write_volatile(ORDINARY_PROBE_SENTINEL) };
    // SAFETY: the same live mapping remains in place and is readable.
    let observed = unsafe { (probe_addr as *const u64).read_volatile() };
    if observed != ORDINARY_PROBE_SENTINEL {
        return Err(stop!(
            "ordinary memory probe readback failed: observed={observed:#x} expected={ORDINARY_PROBE_SENTINEL:#x}"
        ));
    }
    probe_frame
        .frame_unmap()
        .map_err(|error| stop!("ordinary memory probe unmap failed: {error:?}"))?;
    sel4::init_thread::slot::CNODE
        .cap()
        .absolute_cptr(probe_frame)
        .delete()
        .map_err(|error| stop!("ordinary memory probe capability delete failed: {error:?}"))?;
    allocator.release_slot(probe_slot.index());
    crate::diagnostic_println!(
        "SLIME_ROOT ordinary probe paddr={probe_paddr:#x} bytes={GRANULE_SIZE} beyond_legacy={beyond_legacy} verified=1"
    );
    Ok(())
}

/// Claim the boot framebuffer and name the first stage on it.
///
/// This runs before the input and timer phases, which is the earliest point
/// the allocator can retype a device frame. A machine with no serial port
/// has no other channel, so a root that renders only at readiness leaves
/// the panel showing whatever the bootloader last printed, which is
/// indistinguishable from the bootloader itself having hung. Each phase
/// past this point reports as it passes, so the last line on the panel
/// names the furthest point the boot reached.
///
/// The panel comes before the timer: the framebuffer is a PCI BAR low in the
/// physical map and the HPET is at `0xfed00000`, so claiming the panel first
/// keeps both device-untyped walks ascending.
///
/// Absent is not an error. Every emulated plane other than the media gate
/// boots through a route that negotiates no mode, and those planes assert
/// the serial chain; a stop here would turn a text-mode boot into a dead
/// root instead of an unobserved panel.
#[cfg(target_arch = "x86_64")]
fn start_display(bootinfo: &sel4::BootInfoPtr, allocator: &mut ObjectAllocator) -> Phase {
    match framebuffer::describe(bootinfo) {
        Ok(info) => {
            let address = ptr::addr_of!(FRAMEBUFFER_PAGE) as usize;
            ScratchPage::claim(bootinfo, address)
                .map_err(|error| stop!("framebuffer page unavailable: {error:?}"))?;
            crate::diagnostic_println!(
                "SLIME_DISPLAY mode={}x{}x{} paddr={:#x}",
                info.width(),
                info.height(),
                info.bits_per_pixel(),
                info.physical_address(),
            );
            let framebuffer = framebuffer::Framebuffer::claim(
                info,
                sel4::init_thread::slot::VSPACE.cap(),
                address,
            );
            // Installed into the root's single panel slot rather than held
            // here: `halt` renders through it from callers that hold no
            // display handle, and the readiness record is written from the
            // service loop, which has no reason to know about displays.
            //
            // SAFETY: root startup is single-threaded and this runs once; the
            // allocator pointer names the root's own `static` storage, which
            // is initialized before this function and lives for the whole boot.
            unsafe { framebuffer::install_panel(framebuffer, allocator) };
            // The first thing on the panel is proof the root is executing at
            // all, which is exactly what a boot that stops in the bootloader
            // cannot produce.
            //
            // SAFETY: as above: single-threaded startup, no reentrancy.
            unsafe {
                framebuffer::with_panel(allocator, |panel, allocator| {
                    match boot_record::render_stage(panel, allocator, "SLIME OS - ROOT RUNNING") {
                        Ok(()) => crate::diagnostic_println!("SLIME_DISPLAY stage root"),
                        Err(error) => {
                            crate::diagnostic_println!("SLIME_DISPLAY stage failed {error:?}")
                        }
                    }
                });
            }
        }
        Err(error) => crate::diagnostic_println!("SLIME_DISPLAY absent {error:?}"),
    }
    Ok(())
}

/// Claim the product's terminal receiver for this platform.
// Each platform reads a different subset of the three arguments.
#[cfg(all(
    any(slime_qemu_keyboard, slime_product_uart, slime_pc99_com1),
    not(slime_root_fixture)
))]
#[allow(unused_variables)]
fn claim_product_input(
    bootinfo: &sel4::BootInfoPtr,
    allocator: &mut ObjectAllocator,
    inputs: Inputs,
) -> Result<crate::device::TerminalInput, Stop> {
    #[cfg(slime_product_uart)]
    let uart_addr = ptr::addr_of!(PRODUCT_UART_PAGE) as usize;
    #[cfg(slime_product_uart)]
    ScratchPage::claim(bootinfo, uart_addr)
        .map_err(|error| stop!("product input page unavailable: {error:?}"))?;
    #[cfg(slime_qemu_keyboard)]
    let (paddr, receiver) = (
        crate::device::QEMU_PL011_PADDR,
        crate::device::TerminalReceiver::Pl011(crate::device::Pl011Input::new(
            inputs.console_registers,
        )),
    );
    #[cfg(slime_product_uart)]
    let (paddr, receiver) = {
        let registers = crate::device::DeviceRegion::map(
            allocator,
            sel4::init_thread::slot::VSPACE.cap(),
            uart_addr,
            PRODUCT_UART_PADDR,
        )
        .map_err(|error| stop!("product UART unavailable: {error:?}"))?;
        (
            PRODUCT_UART_PADDR,
            crate::device::TerminalReceiver::DwApb(crate::device::DwApbInput::new(registers)),
        )
    };
    // pc99 legacy serial is behind I/O ports rather than a mapped page, so
    // this arm claims a capability over the COM1 port range instead of a
    // device frame.
    #[cfg(slime_pc99_com1)]
    let (paddr, receiver) = {
        let port_slot = allocator
            .reserve_slot::<sel4::cap_type::IOPort>()
            .map_err(|error| stop!("COM1 port slot unavailable: {error:?}"))?;
        let first = PC99_COM1_PORT;
        // The 16550's eight registers, no wider: `IOPortControl` will issue
        // any span, and a wider one would hand the root authority over
        // neighbouring legacy devices it does not drive.
        //
        // Checked rather than wrapped: a pinned base near the top of the
        // port space would otherwise wrap to a reversed range, and a range
        // whose end precedes its start is authority over nothing that
        // nonetheless issues successfully.
        let Some(last) = first.checked_add(7) else {
            return Err(stop!(
                "COM1 port base {first:#x} leaves no room for the 16550's eight registers"
            ));
        };
        let root_cnode = sel4::init_thread::slot::CNODE.cap();
        sel4::init_thread::slot::IO_PORT_CONTROL
            .cap()
            .ioport_control_issue(
                first.into(),
                last.into(),
                &root_cnode.absolute_cptr(port_slot.cptr()),
            )
            .map_err(|error| stop!("COM1 port authority refused: {error:?}"))?;
        (
            usize::from(first),
            crate::device::TerminalReceiver::Com1(crate::device::Com1Input::new(
                port_slot.cap(),
                first,
            )),
        )
    };
    crate::diagnostic_println!("SLIME_ROOT product input ready uart={paddr:#x}");
    let input = crate::device::TerminalInput::new(receiver);
    #[cfg(all(slime_product_test_terminator, slime_cv1800b_duo))]
    let input = input.with_test_terminator(0x1d, request_duo_test_reset);
    Ok(input)
}

/// Prove that two frames the allocator hands out are independent, and that
/// the proof spent exactly what it should.
fn prove_foundation(bootinfo: &sel4::BootInfoPtr, allocator: &mut ObjectAllocator) -> Phase {
    let foundation_first = ptr::addr_of!(FOUNDATION_PAGES) as usize;
    let foundation_second = foundation_first + GRANULE_SIZE;
    for address in [foundation_first, foundation_second] {
        ScratchPage::claim(bootinfo, address).map_err(|error| {
            stop!("SLIME_FOUNDATION FAIL scratch unmap address={address:#x}: {error:?}")
        })?;
    }
    let foundation_before = (
        allocator.objects_allocated(),
        allocator.slots_allocated(),
        allocator.bytes_allocated(),
    );
    let foundation_anchors_before = allocator.preserved_anchor_count();
    let mut foundation_adapter = BufferAdapter::new(allocator);
    foundation_adapter
        .prove_frame_independence(
            sel4::init_thread::slot::VSPACE.cap(),
            foundation_first,
            foundation_second,
        )
        .map_err(|error| stop!("SLIME_FOUNDATION FAIL frame independence: {error:?}"))?;
    let foundation_after = (
        allocator.objects_allocated(),
        allocator.slots_allocated(),
        allocator.bytes_allocated(),
    );
    let foundation_anchors = allocator.preserved_anchor_count() - foundation_anchors_before;
    if !foundation_accounted(foundation_before, foundation_after, foundation_anchors) {
        return Err(stop!(
            "SLIME_FOUNDATION FAIL accounting before={foundation_before:?} after={foundation_after:?}"
        ));
    }
    crate::diagnostic_println!(
        "SLIME_FOUNDATION frames independent objects_delta=2 slots_delta=2 bytes_delta={} caps_deleted=2 preserved_anchors={}",
        2 * GRANULE_SIZE,
        foundation_anchors,
    );
    Ok(())
}

/// Fund the admitted plan from the root's CSpace and report the admission.
///
/// The plan's total is held against the root's actual CSpace, which only the
/// allocator knows (B49). Per-instance ceilings say each process fits; this
/// says they all fit together, before any component starts rather than
/// partway through construction with children already running.
///
/// Root CSpace grows from admitted ordinary memory, so the first call only
/// prices the plan and the pool is grown to it; the decision then compares
/// the price against what this platform could actually fund.
fn fund_plan(
    allocator: &mut ObjectAllocator,
    generation: &Generation,
    admission: &mut Admission,
) -> Phase {
    if let Ok(required) = generation::admit_total_slots(generation, usize::MAX) {
        let (mut pages, mut largest) = (0usize, 0usize);
        for index in 0..generation.resource_quota_count() {
            let quota = generation
                .resource_quota(index)
                .map_err(|error| stop!("generation quota rejected: {error:?}"))?;
            pages += quota.frame_count as usize;
            largest = largest.max(quota.frame_count as usize);
        }
        let instances = generation.instance_count();
        let levels = sel4::vspace_levels::NUM_LEVELS;
        match image_funding(pages, largest, instances, required, levels) {
            // Metadata remains generation-owned after child teardown. Fund the
            // admitted graph before launch so a large child's reclamation returns
            // to its baseline rather than retaining first-use table growth.
            Some((descriptors, slots)) => {
                allocator
                    .ensure_allocation_descriptors(descriptors)
                    .map_err(|error| stop!("image metadata funding rejected: {error:?}"))?;
                allocator
                    .ensure_extent_descriptors(instances)
                    .map_err(|error| stop!("image extent funding rejected: {error:?}"))?;
                allocator.fund_root_slots(slots);
                if allocator.free_slots() < slots {
                    return Err(stop!(
                        "image CSpace funding rejected: required={slots} available={}",
                        allocator.free_slots()
                    ));
                }
            }
            None => allocator.fund_root_slots(required),
        }
    }
    let planned_slots = generation::admit_total_slots(generation, allocator.free_slots())
        .map_err(|error| stop!("generation admission rejected: {error:?}"))?;
    admission.required_root_slots = planned_slots;
    crate::diagnostic_println!(
        "SLIME_ROOT plan slots required={planned_slots} available={}",
        allocator.free_slots(),
    );
    crate::diagnostic_println!(
        "SLIME_ROOT generation admitted number={} executables={} instances={} grants={} health={} bootstrap={}",
        generation.number,
        admission.executable_len(),
        admission.instance_len(),
        admission.grants,
        admission.health,
        admission.bootstrap_objects,
    );
    Ok(())
}

/// Report the admitted fabric graph, the authority manifest and the image counts.
fn report_graph(generation: &Generation, admission: &Admission) {
    // C8.2: the declared fabric graph, checked against this root's own ceilings
    // before any component launches. `absent` for the generations that declare
    // none; `admitted` is the wiring being observable, which no unit test over
    // a hand-built graph can show.
    //
    // The counts are C8.4's structural arm (P5.4.10). A transcript proves
    // samples moved; only reading the authenticated resource proves they moved
    // along edges the *generation* fixed. `kernel/tests/fabric_stream.rs` says
    // exactly this about itself — "the two things a transcript cannot show" —
    // and reports the shape rather than asserting a number here, because the
    // number is a property of the generation rather than of the root.
    crate::diagnostic_println!(
        "SLIME_ROOT fabric graph={} schemas={} routes={} participants={} interpositions={}",
        if admission.fabric_graph_admitted {
            "admitted"
        } else {
            "absent"
        },
        admission.fabric_schemas,
        admission.fabric_routes,
        admission.fabric_participants,
        admission.fabric_interpositions,
    );
    // B70. The hop *count* above says a chain exists; it cannot say which
    // component the generation put on it. Both fabric brokers used to answer
    // that from a build-time table compiled into the component — a table that
    // could only agree with itself. The name is a generation fact, so the root
    // that admitted the generation is what states it, and the plane gates
    // assert against this line rather than against a constant in the component
    // they are checking.
    for name in generation::interposition_hop_names(generation)
        .iter()
        .flatten()
    {
        crate::diagnostic_println!("SLIME_ROOT fabric interposition hop={name}");
    }
    crate::diagnostic_println!(
        "SLIME_ROOT authority manifest={:02x?}",
        generation.authority_manifest_identity()
    );
    crate::diagnostic_println!(
        "SLIME_ROOT graph admitted executables={} instances={} slimecm={} elf={} unrecognized={}",
        admission.executable_len(),
        admission.instance_len(),
        admission.slime_component_images,
        admission.loadable,
        admission.unrecognized_images,
    );
}

/// Run the qualification role this image was built for, if any.
///
/// The roles run before any task exists, so a refusal they provoke cannot
/// reach a published component.
// An image built for no role reads neither argument.
#[allow(unused_variables)]
fn qualify(bootinfo: &sel4::BootInfoPtr, allocator: &mut ObjectAllocator) -> Phase {
    #[cfg(slime_cspace_expanded)]
    {
        allocator.pressure_initial_namespace();
        allocator
            .exercise_expanded_cspace(bootinfo)
            .map_err(|error| stop!("expanded CSpace qualification: {error:?}"))?;
    }
    #[cfg(slime_metadata_lifecycle)]
    allocator
        .exercise_metadata_lifecycle()
        .map_err(|error| stop!("metadata lifecycle qualification: {error:?}"))?;
    #[cfg(slime_bootstrap_boundaries)]
    allocator
        .exercise_bootstrap_boundaries()
        .map_err(|error| stop!("bootstrap boundary qualification: {error:?}"))?;
    // Demand-backed private memory runs here for the same reason: its holders
    // live in windows of the root's own address space, so a refusal, a
    // rollback or a revoke it provokes cannot reach a component.
    #[cfg(slime_private_elastic)]
    crate::private_memory::qualification::exercise_idle_and_guarantee(allocator)
        .map_err(|error| stop!("elastic guarantee qualification: {error:?}"))?;
    #[cfg(slime_private_fragmentation)]
    crate::private_memory::qualification::exercise_mixed_fragmentation(allocator)
        .map_err(|error| stop!("elastic fragmentation qualification: {error:?}"))?;
    #[cfg(slime_private_rollback)]
    crate::private_memory::qualification::exercise_failure_rollback(allocator)
        .map_err(|error| stop!("elastic rollback qualification: {error:?}"))?;
    #[cfg(slime_private_conservation)]
    crate::private_memory::qualification::exercise_cross_holder_conservation(allocator)
        .map_err(|error| stop!("elastic conservation qualification: {error:?}"))?;
    Ok(())
}

/// Run the shared boot phases on an initialized allocator.
///
/// Every root image runs these phases in this order. A phase that cannot go on
/// has printed its record when it returns [`Stop`]; the caller halts.
pub fn run(
    bootinfo: &sel4::BootInfoPtr,
    allocator: &mut ObjectAllocator,
    #[cfg_attr(slime_boot_selector, allow(unused_variables))] inputs: Inputs,
) -> Result<Booted, Stop> {
    qualify(bootinfo, allocator)?;
    report_inventory(allocator)?;
    probe_ordinary_memory(bootinfo, allocator)?;
    #[cfg(target_arch = "x86_64")]
    start_display(bootinfo, allocator)?;

    #[cfg(not(slime_boot_selector))]
    let generation_bytes = inputs.generation;
    #[cfg(all(
        any(slime_qemu_keyboard, slime_product_uart, slime_pc99_com1),
        not(slime_root_fixture)
    ))]
    let product_input = Some(claim_product_input(bootinfo, allocator, inputs)?);
    #[cfg(all(
        not(any(slime_qemu_keyboard, slime_product_uart, slime_pc99_com1)),
        not(slime_root_fixture)
    ))]
    let product_input: Option<crate::device::TerminalInput> = None;

    // ---- timer phase ----
    // Proves `TimerScheduler` (see `timer.rs`) is driven by a real seL4 IRQ
    // before any fixture task exists: acquire the one architected-timer PPI
    // seL4 leaves for userspace on this platform (`platform_timer.rs`),
    // schedule a short deadline, wait for the interrupt it raises, then
    // confirm the monotonic counter it reads actually advanced. The wait is
    // bounded by wall-clock ticks read directly from hardware rather than by
    // IRQ delivery, so a broken wiring fails loudly instead of hanging boot.
    let mut timer_adapter = PhysicalTimerAdapter::acquire(allocator)
        .map_err(|error| stop!("timer source unavailable: {error:?}"))?;
    // The reset granule is mapped before the timer granule: both come from one
    // device untyped and retype is monotonic.
    #[cfg(slime_cv1800b_duo)]
    let reset_registers = map_page(
        bootinfo,
        allocator,
        ptr::addr_of!(RESET_PAGE),
        RESET_PADDR,
        "reset",
    )?;
    #[cfg(slime_timer_registers)]
    let timer_registers = map_page(
        bootinfo,
        allocator,
        ptr::addr_of!(TIMER_PAGE),
        TIMER_PADDR,
        "timer",
    )?;
    #[cfg(all(slime_product_test_terminator, slime_cv1800b_duo))]
    unsafe {
        ptr::addr_of_mut!(DUO_TIMER_REGISTERS).write(Some(timer_registers));
        ptr::addr_of_mut!(DUO_RESET_REGISTERS).write(Some(reset_registers));
    }
    #[cfg(slime_timer_registers)]
    timer_adapter.attach_registers(timer_registers);
    crate::diagnostic_println!(
        "SLIME_TIMER acquired irq={TIMER_IRQ} freq_hz={}",
        timer_adapter.frequency_hz(),
    );
    // Two markers around `prove_timer`, not one. It blocks until a real timer
    // interrupt arrives, so on a machine whose timer this profile has assumed
    // rather than observed it is the most likely place for the boot to stop
    // forever. `TIMER MAPPED` without `TIMER TICKING` says the registers were
    // reachable but no interrupt was delivered, which is a different defect
    // from a mapping that failed.
    #[cfg(target_arch = "x86_64")]
    show_stage(allocator, "TIMER MAPPED - AWAITING TICK");
    prove_timer(&mut timer_adapter, "startup")?;
    #[cfg(target_arch = "x86_64")]
    show_stage(allocator, "TIMER TICKING");
    #[cfg(slime_duo_early_fault)]
    run_duo_early_fault_control(&mut timer_adapter, reset_registers);
    timer_adapter
        .bind_to(sel4::init_thread::slot::TCB.cap())
        .map_err(|error| stop!("timer notification could not bind to root: {error:?}"))?;
    // ---- end timer phase ----

    let scratch = ScratchPage::claim(bootinfo, ptr::addr_of!(FREE_PAGE) as usize)
        .map_err(|error| stop!("scratch page unavailable: {error:?}"))?;
    prove_foundation(bootinfo, allocator)?;

    // ---- device phase ----
    //
    // The immutable boot selector is the one ordering exception: it must read
    // the generation from the boot disk before decoded generation policy can
    // assign that device. Ordinary embedded-generation images never construct
    // the retired root block driver; after admission, an IO-resource budget
    // grants raw MMIO/IRQ/DMA authority to supervised userspace drivers.
    #[cfg(slime_boot_selector)]
    let mut block_devices = crate::graph_runtime::platform::probe_devices(bootinfo, allocator);
    #[cfg(slime_boot_selector)]
    let boot_selector::SelectedGeneration {
        generation,
        runtime: boot_runtime,
    } = {
        let device = block_devices
            .get_mut(0)
            .ok_or_else(|| stop!("boot selector has no boot device"))?;
        boot_selector::select(device, &BOOT_BUNDLE_IDENTITY)
            .map_err(|error| stop!("boot selection rejected: {error:?}"))?
    };
    #[cfg(not(slime_boot_selector))]
    let generation = Generation::decode(generation_bytes)
        .map_err(|error| stop!("generation rejected: {error:?}"))?;
    #[cfg(slime_boot_selector)]
    crate::diagnostic_println!(
        "SLIME_BOOT selected identity={:02x?} number={} pending={} attempts={}",
        boot_runtime.running_identity(),
        generation.number,
        usize::from(boot_runtime.running_pending()),
        boot_runtime.remaining_attempts(),
    );
    // The profile this root task runs. Every component payload is admitted
    // against it before the loader is offered a byte, so an executable built
    // for another target is refused rather than mapped (roadmap invariant 9).
    let profile = boot_contracts::target_profile::TargetProfile::by_name(TARGET_PROFILE)
        .map_err(|error| stop!("target profile {TARGET_PROFILE} unavailable: {error:?}"))?;
    let mut admission = Admission::admit(&generation, profile)
        .map_err(|error| stop!("generation admission rejected: {error:?}"))?;
    #[cfg(all(not(slime_boot_selector), not(slime_root_fixture)))]
    let io_authority = if admission.io_resource_drivers.is_some() {
        crate::graph_runtime::probe_authority_devices(bootinfo, allocator)
    } else {
        crate::graph_runtime::platform::AuthorityInventory::new()
    };
    #[cfg(all(slime_boot_selector, not(slime_root_fixture)))]
    let io_authority = crate::graph_runtime::platform::AuthorityInventory::new();
    fund_plan(allocator, &generation, &mut admission)?;
    // The last stage before components launch, so a panel stopping here says
    // the generation was admitted but the graph did not come up.
    #[cfg(target_arch = "x86_64")]
    show_stage(allocator, "GENERATION ADMITTED");
    report_graph(&generation, &admission);
    // ---- end device phase ----

    let service_endpoint = allocator
        .allocate_fixed::<sel4::cap_type::Endpoint>()
        .map_err(|error| stop!("service endpoint unavailable: {error:?}"))?
        .cap();
    // B41: console and debug traffic gets its own endpoint object. A noisy or
    // faulting console client then cannot consume the lifecycle dispatcher's
    // queue, and the two no longer share a fault domain.
    let console_endpoint = allocator
        .allocate_fixed::<sel4::cap_type::Endpoint>()
        .map_err(|error| stop!("console endpoint unavailable: {error:?}"))?
        .cap();

    Ok(Booted {
        generation,
        admission,
        scratch,
        service_endpoint,
        console_endpoint,
        timer_adapter,
        #[cfg(not(slime_root_fixture))]
        product_input,
        #[cfg(not(slime_root_fixture))]
        io_authority,
        #[cfg(slime_boot_selector)]
        block_devices,
        #[cfg(slime_boot_selector)]
        boot_runtime,
        #[cfg(all(slime_cv1800b_duo, not(slime_product_uart)))]
        timer_registers,
        #[cfg(slime_cv1800b_duo)]
        reset_registers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_within_one_leaf_table_need_no_funding_of_their_own() {
        assert_eq!(image_funding(513, 512, 2, 100, 4), None);
        assert_eq!(image_funding(0, 0, 0, 0, 4), None);
    }

    #[test]
    fn a_large_image_funds_tables_and_a_margin_for_each_instance() {
        // 1024 pages need two leaf tables at each of four levels.
        assert_eq!(
            image_funding(1024, 513, 3, 100, 4),
            Some((1024 + 8 + 3 * 32, 100 + 8 + 3 * 32))
        );
    }

    #[test]
    fn a_partial_leaf_table_counts_as_a_whole_one() {
        assert_eq!(
            image_funding(513, 513, 1, 0, 3),
            Some((513 + 6 + 32, 6 + 32))
        );
    }

    #[test]
    fn the_foundation_proof_spends_two_frames_and_its_anchors() {
        let before = (10, 20, 4 * GRANULE_SIZE);
        assert!(foundation_accounted(before, (12, 22, 6 * GRANULE_SIZE), 0));
        assert!(foundation_accounted(before, (15, 25, 6 * GRANULE_SIZE), 3));
    }

    #[test]
    fn a_foundation_proof_that_spent_anything_else_is_refused() {
        let before = (10, 20, 4 * GRANULE_SIZE);
        let honest = (12, 22, 6 * GRANULE_SIZE);
        assert!(!foundation_accounted(before, (13, honest.1, honest.2), 0));
        assert!(!foundation_accounted(before, (honest.0, 21, honest.2), 0));
        assert!(!foundation_accounted(
            before,
            (honest.0, honest.1, 7 * GRANULE_SIZE),
            0
        ));
        assert!(!foundation_accounted(before, honest, 1));
        assert!(!foundation_accounted(before, before, 0));
    }

    #[test]
    fn only_qemu_arm_has_a_legacy_window_to_exceed() {
        assert_eq!(beyond_legacy("aarch64-sel4-qemu-virt", 0x7fff_f000), 0);
        assert_eq!(beyond_legacy("aarch64-sel4-qemu-virt", 0x8000_0000), 1);
        assert_eq!(beyond_legacy("aarch64-sel4-qemu-virt", 0x1_3fd6_3000), 1);
        assert_eq!(beyond_legacy("riscv64-sel4-qemu-virt", 0x1_3fd6_3000), 0);
        assert_eq!(beyond_legacy("x86_64-sel4-qemu-pc99", usize::MAX), 0);
    }
}
