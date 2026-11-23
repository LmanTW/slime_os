//! Serialized root diagnostic records.
//!
//! The root task's service loop and its console dispatcher are separate threads
//! at the same priority, and the kernel prints one byte per syscall, so a record
//! must be emitted entirely while its producer owns the output. Ownership is a
//! FIFO ticket: a waiter yields to the runnable owner instead of spinning, and a
//! producer that has just finished cannot overtake one already waiting.
//!
//! The waiting rule relies on every producer being a root thread at that same
//! priority on a single non-MCS core, where `seL4_Yield` queues the caller behind
//! the owner; a lower-priority owner would never be scheduled by a yield.
//!
//! A record is validated, and a formatted record fully rendered into a bounded
//! buffer, before a ticket is taken. A refused record therefore emits nothing,
//! and an owner never formats, allocates, or blocks while it holds the output.
//! Nothing called while holding the output may itself produce a record.
//!
//! # Where the bytes go
//!
//! Until [`install`] names a UART, each byte goes to the kernel's debug
//! console. After it, each byte goes to that UART's registers and the kernel
//! receives none. The UART is a PL011 the root mapped from device authority;
//! firmware and the loader configured its line, and this module changes no
//! setting. A line feed is preceded by a carriage return, as the kernel's
//! console does, so the bytes on the line do not depend on the route.

use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicUsize, Ordering};

/// The largest record accepted: the staged console payload bound.
const MAX_RECORD_BYTES: usize = 1024;

static NEXT_TICKET: AtomicUsize = AtomicUsize::new(0);
static NOW_SERVING: AtomicUsize = AtomicUsize::new(0);

/// Address of the installed UART's register page, or zero while none is.
static UART: AtomicUsize = AtomicUsize::new(0);

/// Send every later byte to the PL011 whose register page is mapped at
/// `registers`.
///
/// The page must stay mapped for the life of the root, and `registers` must be
/// nonzero. The caller is the root's startup, before a second thread exists.
pub fn install(registers: usize) {
    UART.store(registers, Ordering::Release);
}

/// Emit one complete record, or refuse it whole.
///
/// The bytes must be UTF-8 and at most [`MAX_RECORD_BYTES`]; anything else is
/// refused before output, so no part of it reaches the transcript.
pub fn write(bytes: &[u8]) -> Result<(), fmt::Error> {
    if bytes.len() > MAX_RECORD_BYTES || core::str::from_utf8(bytes).is_err() {
        return Err(fmt::Error);
    }
    let ticket = NEXT_TICKET.fetch_add(1, Ordering::Relaxed);
    while NOW_SERVING.load(Ordering::Acquire) != ticket {
        sel4::r#yield();
    }
    let uart = UART.load(Ordering::Acquire);
    for byte in bytes {
        if uart == 0 {
            sel4::debug_put_char(*byte);
        } else {
            if *byte == b'\n' {
                put(uart, b'\r');
            }
            put(uart, *byte);
        }
    }
    NOW_SERVING.store(ticket.wrapping_add(1), Ordering::Release);
    Ok(())
}

/// Transmit one byte through the PL011 at `uart`.
///
/// The data register is written only while the transmit FIFO has room. The
/// wait holds the output, as the kernel's own driver does inside the syscall
/// this replaces.
fn put(uart: usize, byte: u8) {
    const DATA: usize = 0x000;
    const FLAGS: usize = 0x018;
    const TRANSMIT_FULL: u32 = 1 << 5;
    // SAFETY: `install` received the address of a mapped PL011 register page,
    // and both offsets are 32-bit registers inside it. The accesses are
    // volatile because they are effects on a device.
    unsafe {
        while ((uart + FLAGS) as *const u32).read_volatile() & TRANSMIT_FULL != 0 {
            core::hint::spin_loop();
        }
        ((uart + DATA) as *mut u32).write_volatile(u32::from(byte));
    }
}

/// Render one record completely, then emit it through [`write`].
///
/// A record that does not fit the bound is refused whole rather than truncated.
pub fn print(args: fmt::Arguments<'_>) {
    let mut record = Record {
        bytes: [0; MAX_RECORD_BYTES],
        len: 0,
    };
    if record.write_fmt(args).is_ok() {
        let _ = write(&record.bytes[..record.len]);
    }
}

/// A bounded rendering buffer; overflow fails the whole format.
struct Record {
    bytes: [u8; MAX_RECORD_BYTES],
    len: usize,
}

impl fmt::Write for Record {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self
            .len
            .checked_add(text.len())
            .filter(|end| *end <= MAX_RECORD_BYTES)
            .ok_or(fmt::Error)?;
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Like `crate::diagnostic_print!`, but emitted as one serialized record.
#[macro_export]
macro_rules! diagnostic_print {
    ($($arg:tt)*) => {
        $crate::diagnostic::print(format_args!($($arg)*))
    };
}

/// Like `crate::diagnostic_println!`, but emitted as one serialized record.
#[macro_export]
macro_rules! diagnostic_println {
    () => {
        $crate::diagnostic::print(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::diagnostic::print(format_args!("{}\n", format_args!($($arg)*)))
    };
}
