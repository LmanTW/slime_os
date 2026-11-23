//! Real seL4 timer-IRQ backing for [`crate::timer::PlatformTimer`].
//!
//! # Register scheme
//!
//! `sel4/config/qemu-arm-virt.cmake` builds seL4 with
//! `KernelArmHypervisorSupport ON`, so the kernel itself runs at EL2 and uses
//! the EL2 hypervisor physical timer (`CNTHP_*`, PPI 26 on this platform —
//! `KERNEL_TIMER_IRQ` in the generated `devices_gen.h`) for its own non-MCS
//! scheduling tick; that IRQ is claimed by `setIRQState(IRQTimer, ...)` at
//! kernel boot (`deps/sel4/src/arch/arm/kernel/boot.c::init_irqs`) and is
//! never available to a root task. The EL1 virtual timer (`CNTV_*`, PPI 27,
//! `INTERRUPT_VTIMER_EVENT`) is *also* claimed unconditionally at the same
//! boot step — `setIRQState(IRQReserved, ...)` runs whenever
//! `CONFIG_ARM_HYPERVISOR_SUPPORT` is compiled in, independent of whether any
//! VCPU is ever created, because it is reserved for VCPU virtual-timer
//! maintenance. That leaves exactly one architected-timer PPI seL4 does not
//! claim for itself under this configuration: the EL1 **physical** timer
//! (`CNTP_*`), non-secure, PPI 30 (`<GIC_PPI 14 ...>` in the platform device
//! tree, offset by the PPI base of 16). [`TIMER_IRQ`] is that IRQ number.
//!
//! Reading and writing `CNTPCT_EL0`/`CNTFRQ_EL0`/`CNTP_CVAL_EL0`/
//! `CNTP_CTL_EL0` directly from this EL0 root task requires the kernel to
//! grant PL0 access explicitly; `sel4/config/qemu-arm-virt.cmake` enables
//! exactly the two config options this scheme needs —
//! `KernelArmExportPCNTUser` (physical counter + frequency) and
//! `KernelArmExportPTMRUser` (physical timer control + compare) — and leaves
//! `KernelArmExportVCNTUser`/`KernelArmExportVTMRUser` off, since nothing
//! here touches the virtual timer registers. The kernel applies both grants
//! once, globally, at boot (`armv_init_user_access` in
//! `deps/sel4/src/arch/arm/armv/armv8-a/64/user_access.c`), so no
//! capability invocation is needed at runtime to unlock the registers
//! themselves — only to claim the IRQ and bind it to a notification.
//!
//! # What this establishes, and what it does not
//!
//! Acquiring [`PhysicalTimerAdapter`] proves the root task holds the one
//! architected-timer IRQ seL4 leaves for userspace on this platform, binds it
//! to a notification the root can wait on, and can read/program/acknowledge
//! the EL1 physical timer directly. It does **not** make the control registers
//! root-exclusive: `KernelArmExportPTMRUser` applies globally, so hostile EL0
//! component code can disable or overwrite the same `CNTP_*` comparator and
//! disrupt the root-brokered service without possessing C9.1 timer authority.
//! Closing that integrity wall requires a kernel/platform change. It also does
//! not establish temporal isolation, a CPU reservation, or any deadline
//! guarantee: this is a plain non-MCS one-shot compare timer, and a scheduling
//! delay of arbitrary length can still separate the compare condition becoming
//! true from this task next running.
//!
//! # The BCM2835 system timer
//!
//! A Raspberry Pi 5 root built with `SLIME_SYSTEM_TIMER=1` uses none of the
//! registers above, so the kernel needs neither export for it. It maps the
//! SoC's system timer, counts its 1 MHz counter, and takes compare channel 3,
//! whose interrupt is [`TIMER_IRQ`]. The device page belongs to the root
//! alone, which closes the integrity gap named above for this backend. No
//! gate boots it: only the board has the device.

#[cfg(any(slime_timer_registers, test))]
use crate::device::MappedGranule;
use crate::event::MonotonicInstant;
use crate::object_allocator::{AllocError, ObjectAllocator};
use crate::timer::PlatformTimer;

/// Userspace timer interrupt for the selected product platform.
#[cfg(slime_arm_generic_timer)]
pub const TIMER_IRQ: sel4::Word = 30;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
pub const TIMER_IRQ: sel4::Word = 11;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
pub const TIMER_IRQ: sel4::Word = 17;
/// The QEMU q35 HPET's first comparator, on IOAPIC pin 20.
///
/// x86 pc99 does not export a userspace timer the way the other two profiles
/// do. seL4 claims the local APIC timer for its own non-MCS tick at boot
/// (`setIRQState(IRQTimer, irq_timer)` in
/// `deps/sel4/src/arch/x86/kernel/boot.c`), leaves `EXPORT_PMC_USER` off, and
/// sets no `CR4.TSD` grant, so there is neither a spare architected comparator
/// nor a root-readable cycle counter. A monotonic source must therefore come
/// from a firmware-described device this root task maps and drives itself.
///
/// Pin 20 rather than 2, and the choice is load-bearing. q35 advertises this
/// comparator's routing capability as `0xff0104`, whose set bits are pins 2,
/// 8, and 16 through 23; only those are legal, and the kernel does not check —
/// [`hpet_timer0_base_config`]'s 5-bit field accepts any value, so an illegal
/// pin is programmed silently and simply never delivers.
///
/// Of the legal pins, 2 and 8 are shared with legacy devices that are *still
/// running*: the firmware's MADT remaps ISA IRQ 0 to GSI 2 for the 8254 PIT,
/// which QEMU leaves enabled unless the HPET is put in legacy-replacement
/// mode, and pin 8 is the RTC. Routing here to pin 2 makes the root's handler
/// receive PIT ticks it never armed; each is serviced, finds nothing due,
/// reprograms, and is immediately followed by the next, so the condition never
/// settles.
///
/// Pin 20 is in the 16-23 range, all of which sits above the legacy ISA pins
/// and drives no legacy device, so the interrupt this root acknowledges is only
/// ever the comparator it armed. Legacy replacement mode is deliberately not
/// used to silence the PIT instead: it would route comparator 0 to pin 0 and
/// take over the RTC, claiming two devices this milestone does not own.
#[cfg(target_arch = "x86_64")]
pub const TIMER_IRQ: sel4::Word = 20;
/// Compare channel 3 of the system timer: SPI 67 in `rpi5b.dts`.
#[cfg(slime_bcm2835_system_timer)]
pub const TIMER_IRQ: sel4::Word = 99;

/// Badge minted onto the notification copy bound to the IRQ handler. The
/// notification object's own (unbadged, full-rights) capability is used to
/// wait/poll; without a distinct nonzero badge on the *sender* side, a
/// woken/polled badge of `0` would be indistinguishable from "nothing
/// pending yet".
const SIGNAL_BADGE: sel4::Badge = 1;

#[cfg(slime_arm_generic_timer)]
/// `CNTP_CTL_EL0.ENABLE`: the timer counts down to (and compares against)
/// `CNTP_CVAL_EL0` and can assert its interrupt line.
const CNTP_CTL_ENABLE: u64 = 1 << 0;

/// Failure to acquire and wire the timer IRQ. Every step names exactly which
/// seL4 invocation or allocator call failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformTimerSetupError {
    /// A CSlot or the notification object itself could not be allocated.
    Allocator(AllocError),
    /// Minting the badged sender copy of the notification failed.
    MintSignalCap(sel4::Error),
    /// `seL4_IRQControl_GetTrigger` for [`TIMER_IRQ`] failed — most likely
    /// because it is already active (claimed by the kernel or a prior boot
    /// attempt) rather than free for this root task.
    IrqAcquire(sel4::Error),
    /// `seL4_IRQHandler_SetNotification` failed to bind the acquired handler
    /// to the badged notification copy.
    BindNotification(sel4::Error),
}

/// Failure while operating the platform timer after acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformTimerAckError {
    /// The RV64 adapter was used before its timer register page was attached.
    RegistersUnavailable,
    /// A timer register offset was outside the mapped granule.
    RegisterAccess,
    /// seL4 refused the IRQ acknowledgement.
    Acknowledge(sel4::Error),
}

/// A live, IRQ-backed timer source this root task owns.
pub struct PhysicalTimerAdapter {
    irq_handler: sel4::cap::IrqHandler,
    /// The unbadged, full-rights notification capability.
    notification: sel4::cap::Notification,
    #[cfg(slime_timer_registers)]
    registers: Option<MappedGranule>,
    /// The deadline compare channel 3 is armed for; `u64::MAX` parks it.
    #[cfg(slime_bcm2835_system_timer)]
    armed: u64,
}

impl PhysicalTimerAdapter {
    /// Claim [`TIMER_IRQ`], create and bind a notification, and return the
    /// live adapter. Every seL4 invocation and allocator call along the way
    /// returns a typed [`PlatformTimerSetupError`] instead of panicking.
    pub fn acquire(allocator: &mut ObjectAllocator) -> Result<Self, PlatformTimerSetupError> {
        let notification_slot = allocator
            .allocate_fixed::<sel4::cap_type::Notification>()
            .map_err(PlatformTimerSetupError::Allocator)?;
        let signal_slot = allocator
            .reserve_slot::<sel4::cap_type::Notification>()
            .map_err(PlatformTimerSetupError::Allocator)?;
        let irq_handler_slot = allocator
            .reserve_slot::<sel4::cap_type::IrqHandler>()
            .map_err(PlatformTimerSetupError::Allocator)?;

        let root_cnode = sel4::init_thread::slot::CNODE.cap();

        // A badged sender-only copy of the notification, bound to the IRQ
        // handler below. Signals through it accumulate a badge distinct from
        // the "nothing pending" `0` a `Poll`/`Wait` on the original
        // (unbadged) capability reports.
        root_cnode
            .absolute_cptr(signal_slot.cptr())
            .mint(
                &root_cnode.absolute_cptr(notification_slot.cptr()),
                sel4::CapRightsBuilder::none().write(true).build(),
                SIGNAL_BADGE,
            )
            .map_err(PlatformTimerSetupError::MintSignalCap)?;

        // Level-triggered: the architected timer's interrupt line stays
        // asserted for as long as the compare condition holds, exactly like
        // seL4's own generic-timer driver treats it
        // (`deps/sel4/include/drivers/timer/arm_generic.h`).
        crate::irq_control::acquire_handler(
            TIMER_IRQ,
            true,
            &root_cnode.absolute_cptr(irq_handler_slot.cptr()),
        )
        .map_err(PlatformTimerSetupError::IrqAcquire)?;

        irq_handler_slot
            .cap()
            .irq_handler_set_notification(signal_slot.cap())
            .map_err(PlatformTimerSetupError::BindNotification)?;

        Ok(Self {
            irq_handler: irq_handler_slot.cap(),
            notification: notification_slot.cap(),
            #[cfg(slime_timer_registers)]
            registers: None,
            #[cfg(slime_bcm2835_system_timer)]
            armed: u64::MAX,
        })
    }

    /// Attach the mapped register page for a memory-mapped timer device.
    ///
    /// Required on the profiles whose monotonic source is a device rather than
    /// an architected register the kernel grants EL0/U-mode access to.
    #[cfg(slime_timer_registers)]
    pub fn attach_registers(&mut self, registers: MappedGranule) {
        self.registers = Some(registers);
    }

    /// Run one step of the system timer on its page with the armed deadline.
    #[cfg(slime_bcm2835_system_timer)]
    fn on_page(&self, step: fn(MappedGranule, u64) -> bool) -> Result<(), PlatformTimerAckError> {
        let registers = self
            .registers
            .ok_or(PlatformTimerAckError::RegistersUnavailable)?;
        step(registers, self.armed)
            .then_some(())
            .ok_or(PlatformTimerAckError::RegisterAccess)
    }

    /// The capability a caller waits or polls on to observe delivery. Full
    /// rights, but signalling only ever happens through the badged copy
    /// bound to the IRQ handler in [`Self::acquire`], never through this one.
    pub const fn notification(&self) -> sel4::cap::Notification {
        self.notification
    }

    /// The badge a genuine timer signal carries, as opposed to `0` for "no
    /// signal yet" on a [`seL4_Poll`]-style non-blocking check.
    pub const fn signal_badge(&self) -> sel4::Badge {
        SIGNAL_BADGE
    }

    /// Bind the timer IRQ's notification to the root service thread.
    ///
    /// With a bound Notification, a blocking `seL4_Recv` on the root service
    /// endpoint returns a badge-only wake when the timer fires. Requests and
    /// timer delivery therefore share one blocking point without a polling
    /// thread or lost-wake window.
    pub fn bind_to(&self, tcb: sel4::cap::Tcb) -> Result<(), sel4::Error> {
        tcb.tcb_bind_notification(self.notification)
    }

    /// Timer ticks per second for this platform's monotonic source.
    pub fn frequency_hz(&self) -> u64 {
        #[cfg(slime_arm_generic_timer)]
        {
            read_cntfrq()
        }
        #[cfg(slime_bcm2835_system_timer)]
        {
            1_000_000
        }
        #[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
        {
            1_000_000_000
        }
        #[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
        {
            1
        }
        // The QEMU q35 HPET's fixed 10 MHz main-counter period
        // (100 ns per tick). A physical machine reports its own period in the
        // HPET capability register, which P6.3 reads once it drives the
        // device; this constant is the pinned emulator fact the reference
        // profile boots against.
        #[cfg(target_arch = "x86_64")]
        {
            10_000_000
        }
    }

    /// Trigger the CV1800B RTC block's cold power-cycle request.
    ///
    /// `control` maps `0x0502_5000`; this adapter already owns the adjacent
    /// `0x0502_6000` timer granule. The sequence is the SoC restart handler's:
    /// enable power cycling, unlock `CTRL0`, then request the cycle. Success
    /// means every bounded register write was issued; working hardware resets
    /// before the caller can continue.
    #[cfg(slime_cv1800b_duo)]
    pub fn request_cold_reset(&self, control: MappedGranule) -> bool {
        self.registers
            .is_some_and(|timer| request_cv1800b_cold_reset(timer, control))
    }
}

/// Trigger the CV1800B RTC block's cold power-cycle request from already-mapped
/// timer and control granules.
#[cfg(slime_cv1800b_duo)]
pub fn request_cv1800b_cold_reset(timer: MappedGranule, control: MappedGranule) -> bool {
    const CTRL_UNLOCK_KEY: usize = 0x004;
    const CTRL0: usize = 0x008;
    const ENABLE_POWER_CYCLE: usize = 0x0c8;
    const UNLOCK_KEY: u32 = 0xab18;
    const POWER_CYCLE_REQUEST: u32 = 0xffff_0808;

    timer.write32(ENABLE_POWER_CYCLE, 1)
        && control.write32(CTRL_UNLOCK_KEY, UNLOCK_KEY)
        && control.write32(CTRL0, POWER_CYCLE_REQUEST)
}

impl PlatformTimer for PhysicalTimerAdapter {
    type Error = PlatformTimerAckError;

    fn monotonic_now(&mut self) -> Result<MonotonicInstant, Self::Error> {
        #[cfg(slime_arm_generic_timer)]
        {
            Ok(MonotonicInstant(read_cntpct()))
        }
        #[cfg(slime_bcm2835_system_timer)]
        {
            let registers = self
                .registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?;
            Ok(MonotonicInstant(
                system_timer::read(registers).ok_or(PlatformTimerAckError::RegisterAccess)?,
            ))
        }
        #[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
        {
            let registers = self
                .registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?;
            Ok(MonotonicInstant(
                read_goldfish_rtc(registers).ok_or(PlatformTimerAckError::RegisterAccess)?,
            ))
        }
        #[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
        {
            let registers = self
                .registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?;
            Ok(MonotonicInstant(
                read_cv1800b_rtc(registers).ok_or(PlatformTimerAckError::RegisterAccess)?,
            ))
        }
        #[cfg(target_arch = "x86_64")]
        {
            let registers = self
                .registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?;
            Ok(MonotonicInstant(
                read_hpet_counter(registers).ok_or(PlatformTimerAckError::RegisterAccess)?,
            ))
        }
    }

    fn program_deadline(&mut self, deadline: MonotonicInstant) -> Result<(), Self::Error> {
        #[cfg(slime_arm_generic_timer)]
        {
            write_cntp_cval(deadline.0);
            write_cntp_ctl(CNTP_CTL_ENABLE);
        }
        #[cfg(slime_bcm2835_system_timer)]
        {
            self.armed = deadline.0;
            self.on_page(system_timer::program)?;
        }
        #[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
        program_goldfish_rtc(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
            deadline.0,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        #[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
        program_cv1800b_rtc(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
            deadline.0,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        #[cfg(target_arch = "x86_64")]
        program_hpet(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
            deadline.0,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        Ok(())
    }

    fn disarm_timer(&mut self) -> Result<(), Self::Error> {
        #[cfg(slime_arm_generic_timer)]
        write_cntp_ctl(0);
        // The channel has no enable bit, so a disarmed channel is parked.
        #[cfg(slime_bcm2835_system_timer)]
        {
            self.armed = u64::MAX;
            self.on_page(system_timer::program)?;
        }
        #[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
        disarm_goldfish_rtc(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        #[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
        disarm_cv1800b_rtc(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        #[cfg(target_arch = "x86_64")]
        disarm_hpet(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        Ok(())
    }

    fn acknowledge_timer_irq(&mut self) -> Result<(), Self::Error> {
        // `service_timer_source` installs the next deadline before this call.
        // A platform acknowledgement must therefore clear only the expired
        // condition and must not invalidate the newly installed deadline.
        #[cfg(slime_arm_generic_timer)]
        isb();
        // The match bit is level-triggered too. `service_timer_source` clears
        // it only when it installs a deadline, and a wake with nothing due
        // installs none.
        #[cfg(slime_bcm2835_system_timer)]
        self.on_page(system_timer::settle)?;
        #[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
        clear_goldfish_rtc_interrupt(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        // The HPET latches its comparator interrupt in a level-triggered
        // status register, so the expired condition must be cleared before the
        // handler ack below or the line re-asserts immediately.
        // `program_deadline` has already installed the next comparator value,
        // and clearing status does not disturb it.
        #[cfg(target_arch = "x86_64")]
        clear_hpet_interrupt(
            self.registers
                .ok_or(PlatformTimerAckError::RegistersUnavailable)?,
        )
        .then_some(())
        .ok_or(PlatformTimerAckError::RegisterAccess)?;
        // CV1800B has no independent alarm-pending clear. Both programming
        // paths write ALARM_ENABLE=0 before either leaving the timer disabled
        // or installing the next alarm, so another write here would cancel
        // that freshly installed deadline. The common IRQ-handler ack below
        // is the only remaining acknowledgement on this platform.
        self.irq_handler
            .irq_handler_ack()
            .map_err(PlatformTimerAckError::Acknowledge)
    }
}
/// The BCM2835 system timer: a free-running 64-bit counter at 1 MHz and four
/// 32-bit compare channels that match its low word.
#[cfg(any(slime_bcm2835_system_timer, test))]
mod system_timer {
    use super::MappedGranule;

    pub(super) const CS: usize = 0x00;
    pub(super) const CLO: usize = 0x04;
    pub(super) const CHI: usize = 0x08;
    /// Compare channel 3. The firmware keeps channels 0 and 2, and Linux's
    /// driver takes this one.
    pub(super) const C3: usize = 0x18;
    /// The match bit of channel 3 in the status register; a write of 1 clears
    /// it.
    pub(super) const M3: u32 = 1 << 3;
    /// The shortest distance the root programs ahead of the counter, in ticks.
    /// A compare value the counter has already passed matches one wrap later.
    const MIN_DELTA: u64 = 16;

    /// The compare value for `deadline`, seen at counter `now`, and its
    /// distance in ticks. The channel reaches at most one wrap of the low word
    /// ahead, so a later deadline wakes the root early and `settle` installs it
    /// again. A deadline of `u64::MAX` parks the channel one wrap ahead.
    pub(super) fn compare(now: u64, deadline: u64) -> (u32, u64) {
        let delta = deadline
            .saturating_sub(now)
            .clamp(MIN_DELTA, u64::from(u32::MAX));
        ((now as u32).wrapping_add(delta as u32), delta)
    }

    pub(super) fn read(registers: MappedGranule) -> Option<u64> {
        // Two 32-bit halves: read the high half again and retry when it moved.
        (0..3).find_map(|_| {
            let high = registers.read32(CHI)?;
            let low = registers.read32(CLO)?;
            (registers.read32(CHI)? == high).then(|| u64::from(low) | (u64::from(high) << 32))
        })
    }

    /// Clear the expired match, then install `deadline`. The level-triggered
    /// line stays low until the new value matches, so the handler
    /// acknowledgement that follows cannot lose it.
    pub(super) fn program(registers: MappedGranule, deadline: u64) -> bool {
        if !registers.write32(CS, M3) {
            return false;
        }
        for _ in 0..3 {
            let Some(now) = read(registers) else {
                return false;
            };
            let (value, delta) = compare(now, deadline);
            if !registers.write32(C3, value) {
                return false;
            }
            // The counter may pass `value` before the write lands. Then no
            // match is latched, and the next one is a wrap away.
            let (Some(after), Some(status)) = (read(registers), registers.read32(CS)) else {
                return false;
            };
            if after.wrapping_sub(now) < delta || status & M3 != 0 {
                return true;
            }
        }
        false
    }

    /// Acknowledge a wake of the channel armed for `armed`. A match while the
    /// counter is short of `armed` is the wrap of the low word: the channel
    /// woke the root early, or while parked. Install `armed` again, which
    /// clears that match. A match at or past `armed` stays, so the line rises
    /// again and the root services the deadline.
    pub(super) fn settle(registers: MappedGranule, armed: u64) -> bool {
        let (Some(status), Some(now)) = (registers.read32(CS), read(registers)) else {
            return false;
        };
        status & M3 == 0 || now >= armed || program(registers, armed)
    }
}

#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_TIME_LOW: usize = 0x00;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_TIME_HIGH: usize = 0x04;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_ALARM_LOW: usize = 0x08;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_ALARM_HIGH: usize = 0x0c;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_IRQ_ENABLED: usize = 0x10;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_CLEAR_ALARM: usize = 0x14;
#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
const GOLDFISH_RTC_CLEAR_INTERRUPT: usize = 0x1c;

#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
fn read_goldfish_rtc(registers: MappedGranule) -> Option<u64> {
    let low = registers.read32(GOLDFISH_RTC_TIME_LOW)? as u64;
    let high = registers.read32(GOLDFISH_RTC_TIME_HIGH)? as u64;
    Some(low | (high << 32))
}

#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
fn program_goldfish_rtc(registers: MappedGranule, deadline: u64) -> bool {
    registers.write32(GOLDFISH_RTC_ALARM_HIGH, (deadline >> 32) as u32)
        && registers.write32(GOLDFISH_RTC_ALARM_LOW, deadline as u32)
        && registers.write32(GOLDFISH_RTC_IRQ_ENABLED, 1)
}

#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
fn disarm_goldfish_rtc(registers: MappedGranule) -> bool {
    registers.write32(GOLDFISH_RTC_IRQ_ENABLED, 0)
        && registers.write32(GOLDFISH_RTC_CLEAR_ALARM, 1)
        && registers.write32(GOLDFISH_RTC_CLEAR_INTERRUPT, 1)
}

#[cfg(all(target_arch = "riscv64", not(slime_cv1800b_duo)))]
fn clear_goldfish_rtc_interrupt(registers: MappedGranule) -> bool {
    registers.write32(GOLDFISH_RTC_CLEAR_INTERRUPT, 1)
}

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_ALARM_TIME: usize = 0x08;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_ALARM_ENABLE: usize = 0x0c;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_ANA_CALIB: usize = 0x00;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_SEC_PULSE_GEN: usize = 0x04;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_SECONDS: usize = 0x18;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_APB_RDATA_SEL: usize = 0x3c;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_ENABLE_POWER_WAKEUP: usize = 0xbc;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_EXTERNAL_PULSE_SELECT: u32 = 1 << 31;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_APB_READ_SECONDS: u32 = 1;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_ALARM_ENABLED: u32 = 1;
#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const CV1800B_RTC_ALARM_WAKEUP_SOURCES: u32 = 0x30;

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
fn read_cv1800b_rtc(registers: MappedGranule) -> Option<u64> {
    Some(registers.read32(CV1800B_RTC_SECONDS)? as u64)
}

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
fn program_cv1800b_rtc(registers: MappedGranule, deadline: u64) -> bool {
    u32::try_from(deadline).is_ok_and(|deadline| {
        let Some(pulse_generator) = registers.read32(CV1800B_RTC_SEC_PULSE_GEN) else {
            return false;
        };
        let Some(analog_calibration) = registers.read32(CV1800B_RTC_ANA_CALIB) else {
            return false;
        };
        let Some(wakeup_sources) = registers.read32(CV1800B_RTC_ENABLE_POWER_WAKEUP) else {
            return false;
        };
        // Bit 31 selects an external seconds pulse. Firmware does not leave
        // that source running across the FIT handoff, so the vendor driver
        // clears it in both control registers before reading or arming the RTC.
        // Preserve the calibrated low bits: only the source selector belongs
        // to this transition.
        registers.write32(
            CV1800B_RTC_SEC_PULSE_GEN,
            pulse_generator & !CV1800B_RTC_EXTERNAL_PULSE_SELECT,
        ) && registers.write32(
            CV1800B_RTC_ANA_CALIB,
            analog_calibration & !CV1800B_RTC_EXTERNAL_PULSE_SELECT,
        ) && registers.write32(CV1800B_RTC_ALARM_ENABLE, 0)
            && wait_cv1800b_rtc_settle()
            && registers.write32(CV1800B_RTC_ALARM_TIME, deadline)
            && registers.write32(CV1800B_RTC_APB_RDATA_SEL, CV1800B_RTC_APB_READ_SECONDS)
            && registers.write32(CV1800B_RTC_ALARM_ENABLE, CV1800B_RTC_ALARM_ENABLED)
            && registers.write32(
                CV1800B_RTC_ENABLE_POWER_WAKEUP,
                wakeup_sources | CV1800B_RTC_ALARM_WAKEUP_SOURCES,
            )
            && registers.read32(CV1800B_RTC_SECONDS).is_some()
    })
}

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
fn wait_cv1800b_rtc_settle() -> bool {
    // The vendor driver waits 200 us after disabling the alarm. The kernel
    // sets `scounteren.TM` for this platform before entering userspace, and
    // the root build receives the timebase from the pinned board profile.
    // Bound both time and iterations so a stopped or non-advancing counter
    // becomes `RegisterAccess` instead of wedging startup.
    const TIMEBASE_HZ: u64 = const_parse_u64(env!("SLIME_DUO_TIMEBASE_HZ"));
    const SETTLE_MICROSECONDS: u64 = 200;
    const SETTLE_TICKS: u64 = (TIMEBASE_HZ * SETTLE_MICROSECONDS).div_ceil(1_000_000);
    const MAX_POLLS: usize = 1_000_000;

    let start = read_riscv_time();
    (0..MAX_POLLS).any(|_| {
        if read_riscv_time().wrapping_sub(start) >= SETTLE_TICKS {
            true
        } else {
            core::hint::spin_loop();
            false
        }
    })
}

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
const fn const_parse_u64(value: &str) -> u64 {
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut parsed = 0u64;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(digit.is_ascii_digit(), "invalid decimal integer");
        parsed = parsed * 10 + (digit - b'0') as u64;
        index += 1;
    }
    assert!(parsed > 0, "integer must be positive");
    parsed
}

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
#[inline]
fn read_riscv_time() -> u64 {
    let value: u64;
    // SAFETY: `rdtime` is a pure counter read. The selected kernel sets only
    // `scounteren.TM` before entering userspace, granting this instruction
    // without exposing the cycle or instret counters.
    unsafe {
        core::arch::asm!(
            "rdtime {value}",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

#[cfg(all(target_arch = "riscv64", slime_cv1800b_duo))]
fn disarm_cv1800b_rtc(registers: MappedGranule) -> bool {
    registers.write32(CV1800B_RTC_ALARM_ENABLE, 0)
}
// QEMU q35's HPET, as described by the IA-PC HPET specification. `MappedGranule`
// exposes 32-bit accesses only, and every register used here is either 32 bits
// wide or a 64-bit register whose halves may be accessed independently.
//
// Only comparator 0 is touched, in 32-bit non-periodic mode: the main counter
// is read as a low/high pair, and `T0_32MODE` makes the comparator compare
// only the low half, so a deadline is a 32-bit value and no 64-bit atomic
// register write is required.
#[cfg(target_arch = "x86_64")]
const HPET_GENERAL_CONFIG: usize = 0x010;
#[cfg(target_arch = "x86_64")]
const HPET_INTERRUPT_STATUS: usize = 0x020;
#[cfg(target_arch = "x86_64")]
const HPET_MAIN_COUNTER_LOW: usize = 0x0f0;
#[cfg(target_arch = "x86_64")]
const HPET_MAIN_COUNTER_HIGH: usize = 0x0f4;
#[cfg(target_arch = "x86_64")]
const HPET_TIMER0_CONFIG: usize = 0x100;
#[cfg(target_arch = "x86_64")]
const HPET_TIMER0_COMPARATOR: usize = 0x108;
/// `GEN_CONF.ENABLE_CNF`: run the main counter and allow comparator delivery.
#[cfg(target_arch = "x86_64")]
const HPET_ENABLE: u32 = 1 << 0;
/// `Tn_CONF.Tn_INT_TYPE_CNF`: 1 selects level-triggered delivery.
///
/// Load-bearing rather than cosmetic. `PhysicalTimerAdapter::acquire` claims
/// this interrupt as level-triggered, and `acknowledge_timer_irq` clears the
/// latched `GINTR_STA` bit before acknowledging the handler. Both are only
/// correct for a level-triggered source: left edge-triggered, the status bit is
/// never set, so the write-1-to-clear would be a no-op against a condition the
/// hardware already dropped.
#[cfg(target_arch = "x86_64")]
const HPET_T0_LEVEL_TRIGGERED: u32 = 1 << 1;
/// `Tn_CONF.Tn_INT_ENB_CNF`: allow this comparator to raise its interrupt.
#[cfg(target_arch = "x86_64")]
const HPET_T0_INTERRUPT_ENABLE: u32 = 1 << 2;
/// `Tn_CONF.Tn_32MODE_CNF`: compare against the low 32 bits of the counter.
#[cfg(target_arch = "x86_64")]
const HPET_T0_32BIT_MODE: u32 = 1 << 8;
/// `Tn_CONF.Tn_INT_ROUTE_CNF`, a 5-bit IOAPIC input number at bit 9.
///
/// Programming it is what makes the interrupt arrive where the root claimed a
/// handler. `GEN_CONF.LEG_RT_CNF` is deliberately left clear — legacy
/// replacement routing would send comparator 0 to PIC IRQ 0, and this profile
/// builds the kernel with `IRQ_PIC` off — so with this field zero the device
/// would instead drive IOAPIC input 0 while the root waits on the pin
/// [`TIMER_IRQ`] names. That mismatch delivers no interrupt at all.
#[cfg(target_arch = "x86_64")]
const HPET_T0_ROUTE_SHIFT: u32 = 9;
#[cfg(target_arch = "x86_64")]
const HPET_T0_ROUTE_MASK: u32 = 0x1f << HPET_T0_ROUTE_SHIFT;

#[cfg(target_arch = "x86_64")]
fn read_hpet_counter(registers: MappedGranule) -> Option<u64> {
    // The counter is 64 bits behind a 32-bit access port, so a naive
    // low-then-high pair can straddle a low-half rollover. Re-read the high
    // half and retry when it moved; at 10 MHz the low half wraps roughly every
    // seven minutes, so one retry is always enough in practice and the bound
    // keeps a stopped counter from looping.
    (0..3).find_map(|_| {
        let high = registers.read32(HPET_MAIN_COUNTER_HIGH)?;
        let low = registers.read32(HPET_MAIN_COUNTER_LOW)?;
        (registers.read32(HPET_MAIN_COUNTER_HIGH)? == high)
            .then(|| u64::from(low) | (u64::from(high) << 32))
    })
}

/// Comparator 0's configuration for this profile, without interrupt delivery.
///
/// One place so `program_hpet` and `disarm_hpet` cannot disagree about the
/// route or the trigger mode: the two differ only in whether delivery is
/// enabled, and a disarm that dropped the route would silently misdeliver the
/// next armed deadline.
#[cfg(target_arch = "x86_64")]
fn hpet_timer0_base_config() -> Option<u32> {
    let route = (TIMER_IRQ as u32) << HPET_T0_ROUTE_SHIFT;
    if route & !HPET_T0_ROUTE_MASK != 0 {
        return None;
    }
    Some(HPET_T0_32BIT_MODE | HPET_T0_LEVEL_TRIGGERED | route)
}

#[cfg(target_arch = "x86_64")]
fn program_hpet(registers: MappedGranule, deadline: u64) -> bool {
    let Some(base) = hpet_timer0_base_config() else {
        return false;
    };
    // Configure, then arm, then clear, then enable — in that order.
    //
    // The route and trigger mode must be in place before delivery is enabled,
    // or the first expiry can be delivered on the wrong input. The latched
    // status must be cleared before delivery is enabled for a separate reason:
    // `GINTR_STA` accumulates comparator expiries whether or not delivery is
    // enabled, so a deadline that elapsed while the comparator was disarmed
    // leaves its bit set. Enabling delivery with that bit set asserts the line
    // immediately, and the root then services an expiry for a deadline it has
    // already retired: each such wake finds nothing due, reprograms, and
    // re-asserts, so the condition does not settle on its own.
    //
    // Clearing after writing the comparator rather than before is what makes
    // this sound: writing either register re-arms the device against the value
    // then present, so a clear that preceded the comparator write could be
    // followed by a fresh latch from the stale deadline.
    //
    // 32-bit comparator mode, so only the low half of the deadline is
    // compared. Truncating is correct rather than lossy: the caller's deadline
    // came from `monotonic_now`, and a deadline beyond the low half's range
    // would already exceed the wrap this mode inherently has.
    registers.write32(HPET_TIMER0_CONFIG, base)
        && registers.write32(HPET_TIMER0_COMPARATOR, deadline as u32)
        && clear_hpet_interrupt(registers)
        && registers.write32(HPET_TIMER0_CONFIG, base | HPET_T0_INTERRUPT_ENABLE)
        && registers.write32(HPET_GENERAL_CONFIG, HPET_ENABLE)
}

#[cfg(target_arch = "x86_64")]
fn disarm_hpet(registers: MappedGranule) -> bool {
    // Leave the main counter running: `monotonic_now` must keep working with
    // no deadline installed, so only comparator delivery is disabled. The
    // route and trigger mode are preserved for the same reason they are
    // programmed at all — the next `program_hpet` must not have to reinstate
    // them before the comparator can fire on the claimed input.
    //
    // The status clear here is best-effort tidiness, not the invariant: the
    // retained comparator value can latch again at any point after this
    // returns, so what actually prevents a spurious delivery is
    // `program_hpet` clearing immediately before it enables the line.
    let Some(base) = hpet_timer0_base_config() else {
        return false;
    };
    registers.write32(HPET_TIMER0_CONFIG, base) && clear_hpet_interrupt(registers)
}

#[cfg(target_arch = "x86_64")]
fn clear_hpet_interrupt(registers: MappedGranule) -> bool {
    // `GINTR_STA` is write-1-to-clear per bit, so writing the comparator-0 bit
    // clears exactly that latched status and leaves every other bit alone.
    registers.write32(HPET_INTERRUPT_STATUS, 1 << 0)
}

/// Reads the EL1 physical counter (`CNTPCT_EL0`), the free-running clock the
/// EL1 physical timer's compare register is measured against.
#[cfg(slime_arm_generic_timer)]
#[inline]
fn read_cntpct() -> u64 {
    let value: u64;
    // SAFETY: `mrs` from `cntpct_el0` is a pure register read with no memory
    // or control-flow side effects. It is legal at EL0 because
    // `KernelArmExportPCNTUser` (set in `sel4/config/qemu-arm-virt.cmake`)
    // makes the kernel set `CNTKCTL_EL1.EL0PCTEN` for every core once at
    // boot, before any thread runs; without that bit this instruction traps
    // instead of completing.
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntpct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}
/// Reads `CNTFRQ_EL0`, the counter frequency firmware programmed for
/// [`read_cntpct`]'s domain.
#[cfg(slime_arm_generic_timer)]
#[inline]
fn read_cntfrq() -> u64 {
    let value: u64;
    // SAFETY: `mrs` from `cntfrq_el0` is a pure register read with no memory
    // or control-flow side effects; EL0 access is granted by the same
    // `EL0PCTEN` bit as `cntpct_el0` — `KernelArmExportPCNTUser`'s own
    // description covers both registers.
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntfrq_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}
/// Writes the EL1 physical timer's compare value (`CNTP_CVAL_EL0`).
#[cfg(slime_arm_generic_timer)]
#[inline]
fn write_cntp_cval(value: u64) {
    // SAFETY: `msr` to `cntp_cval_el0` only changes this timer's own compare
    // register; it has no effect on memory this crate's Rust code observes
    // and cannot fault once `KernelArmExportPTMRUser` has granted
    // `CNTKCTL_EL1.EL0PTEN` (set once at boot before any thread runs — see
    // `sel4/config/qemu-arm-virt.cmake`).
    unsafe {
        core::arch::asm!(
            "msr cntp_cval_el0, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
}
/// Writes the EL1 physical timer's control register (`CNTP_CTL_EL0`).
#[cfg(slime_arm_generic_timer)]
#[inline]
fn write_cntp_ctl(value: u64) {
    // SAFETY: `msr` to `cntp_ctl_el0` only toggles this timer's own
    // ENABLE/IMASK bits; legal at EL0 under the same `EL0PTEN` grant as
    // `write_cntp_cval`, and has no effect on memory this crate's Rust code
    // observes.
    unsafe {
        core::arch::asm!(
            "msr cntp_ctl_el0, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
}
/// Instruction Synchronization Barrier: forces every instruction before it
/// (in particular, the `msr` writes above) to complete and become visible to
/// the timer hardware before anything after it executes.
#[cfg(slime_arm_generic_timer)]
#[inline]
fn isb() {
    // SAFETY: `isb` reads and writes no memory; it only orders instruction
    // execution and completion, which is exactly the ordering
    // `acknowledge_timer_irq` documents needing against the preceding
    // `program_deadline`/`disarm_timer` register write.
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::system_timer::{C3, CHI, CLO, CS, M3, compare, program, read, settle};
    use super::*;

    const WORDS: usize = 1024;

    #[test]
    fn a_deadline_ahead_is_its_low_word() {
        assert_eq!(compare(0x1_0000_0100, 0x1_0000_0500), (0x500, 0x400));
    }

    #[test]
    fn a_deadline_behind_or_too_close_is_the_minimum_ahead() {
        assert_eq!(compare(1000, 0), (1016, 16));
        assert_eq!(compare(1000, 1005), (1016, 16));
    }

    #[test]
    fn a_deadline_beyond_one_wrap_is_one_wrap_ahead() {
        assert_eq!(compare(0x10, u64::MAX), (0x0f, 0xffff_ffff));
    }

    #[test]
    fn the_compare_value_wraps_with_the_low_word() {
        assert_eq!(compare(0xffff_fff0, 0x1_0000_0010).0, 0x10);
    }

    #[test]
    fn the_counter_is_one_word_from_two_halves() {
        let mut page = [0u32; WORDS];
        page[CLO / 4] = 5;
        page[CHI / 4] = 7;
        assert_eq!(read(MappedGranule::over(&mut page)), Some(0x7_0000_0005));
    }

    #[test]
    fn programming_clears_the_match_and_writes_channel_three() {
        let mut page = [0u32; WORDS];
        page[CLO / 4] = 1000;
        assert!(program(MappedGranule::over(&mut page), 5000));
        assert_eq!(page[CS / 4], M3);
        assert_eq!(page[C3 / 4], 5000);
        assert_eq!(page[0x0c / 4..0x18 / 4], [0, 0, 0]);
    }

    #[test]
    fn disarming_parks_the_channel_one_wrap_ahead() {
        let mut page = [0u32; WORDS];
        page[CLO / 4] = 1000;
        assert!(program(MappedGranule::over(&mut page), u64::MAX));
        assert_eq!(page[C3 / 4], 999);
        assert_eq!(page[CS / 4], M3);
    }

    /// A page whose counter reads `now`, with the match of channel 3 as given
    /// and a compare value no case writes.
    fn woken(now: u32, matched: bool) -> [u32; WORDS] {
        let mut page = [0u32; WORDS];
        page[CLO / 4] = now;
        page[CS / 4] = if matched { M3 } else { 0 };
        page[C3 / 4] = 77;
        page
    }

    #[test]
    fn a_wake_short_of_the_deadline_installs_it_again() {
        let mut page = woken(1000, true);
        assert!(settle(MappedGranule::over(&mut page), 5000));
        assert_eq!(page[C3 / 4], 5000);
    }

    #[test]
    fn a_wake_while_parked_parks_again() {
        let mut page = woken(1000, true);
        assert!(settle(MappedGranule::over(&mut page), u64::MAX));
        assert_eq!(page[C3 / 4], 999);
    }

    #[test]
    fn a_wake_at_the_deadline_leaves_its_match() {
        for now in [5000, 6000] {
            let mut page = woken(now, true);
            assert!(settle(MappedGranule::over(&mut page), 5000));
            assert_eq!((page[C3 / 4], page[CS / 4]), (77, M3));
        }
    }

    #[test]
    fn a_wake_without_a_match_writes_nothing() {
        let mut page = woken(1000, false);
        assert!(settle(MappedGranule::over(&mut page), 5000));
        assert_eq!((page[C3 / 4], page[CS / 4]), (77, 0));
    }
}
