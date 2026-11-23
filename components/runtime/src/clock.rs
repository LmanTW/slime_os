//! Ambient monotonic clock reads (`clock-authority/v2`).
//!
//! Reading the counter needs no authority. On AArch64 the kernel exports
//! `CNTPCT_EL0` and `CNTFRQ_EL0` to every EL0 thread and the root's timers
//! count that same counter, so a read stays in the calling thread. On RISC-V
//! and x86_64 the root's clock is a device register userspace cannot read, so
//! the read is the root call `crate::syscall` already owns.
//!
//! An AArch64 image built with `SLIME_SYSTEM_TIMER=1` is in the second group:
//! its root counts the SoC's system timer, and no code of the image reads or
//! writes a generic-timer register.

/// Whether the root of this image counts a device timer on AArch64. The image
/// builder sets the variable for the root and for every component alike.
#[cfg(target_arch = "aarch64")]
const ROOT_SERVES_THE_CLOCK: bool = match option_env!("SLIME_SYSTEM_TIMER") {
    Some(value) => matches!(value.as_bytes(), b"1"),
    None => false,
};

/// Read the hardware monotonic counter that the root's timers count.
pub fn monotonic_read() -> Result<u64, i64> {
    #[cfg(target_arch = "aarch64")]
    {
        if ROOT_SERVES_THE_CLOCK {
            crate::syscall::monotonic_read()
        } else {
            Ok(read_cntpct())
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::syscall::monotonic_read()
    }
}

/// Read the hardware monotonic counter's rate in ticks per second.
///
/// Ambient like [`monotonic_read`] and the same register the root reads. It is
/// constant for the life of the boot and turns a tick count into a duration
/// and a duration into a [`crate::timer_arm`] delay.
pub fn monotonic_frequency() -> Result<u64, i64> {
    #[cfg(target_arch = "aarch64")]
    {
        if ROOT_SERVES_THE_CLOCK {
            crate::syscall::monotonic_frequency()
        } else {
            Ok(read_cntfrq())
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::syscall::monotonic_frequency()
    }
}

// The root-call readers in `crate::syscall` are byte-frozen by the
// console-record qualification and stay compiled on AArch64, where only the
// other architectures call them. Naming them keeps them live.
#[cfg(target_arch = "aarch64")]
const _: [fn() -> Result<u64, i64>; 2] = [
    crate::syscall::monotonic_read,
    crate::syscall::monotonic_frequency,
];

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_cntpct() -> u64 {
    let value: u64;
    // SAFETY: a pure register read with no memory or control-flow effect.
    // `KernelArmExportPCNTUser` grants EL0 access on every AArch64 profile,
    // because the root itself reads this counter from EL0.
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntpct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_cntfrq() -> u64 {
    let value: u64;
    // SAFETY: as `read_cntpct`; the same `EL0PCTEN` bit grants this register.
    unsafe {
        core::arch::asm!(
            "mrs {value}, cntfrq_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}
