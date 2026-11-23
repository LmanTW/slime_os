//! Once-per-key gating for the root's per-operation diagnostic lines.
//!
//! Every clock request and every payload DMA once printed one serial line.
//! Under QEMU TCG each UART byte is a trapped write on the one CPU, so those
//! lines stalled the whole graph. Each line is now printed the first time its
//! key occurs; later occurrences are counted and reported in one summary
//! before `SLIME_GRAPH served`. Plane checkers test these lines for presence
//! only, so the first occurrence keeps every one of them satisfied.
//!
//! Keys live in fixed tables. When a table is full the line is printed as
//! before, so a key is never hidden: overflow costs volume, not evidence.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Distinct `(task, label)` keys remembered for `SLIME_CLOCK served`, and
/// `(task, label, class)` keys for `SLIME_CLOCK refused`. A composition holds
/// at most 48 tasks and six clock labels; restarts and spawns mint new ids.
const KEYS: usize = 256;

static SERVED: [AtomicU64; KEYS] = [const { AtomicU64::new(0) }; KEYS];
static REFUSED: [AtomicU64; KEYS] = [const { AtomicU64::new(0) }; KEYS];
/// Bit 0: a device-read payload DMA was printed; bit 1: a device-write one.
static DMA_PRINTED: AtomicU64 = AtomicU64::new(0);
static SERVED_REPEATS: AtomicU64 = AtomicU64::new(0);
static REFUSED_REPEATS: AtomicU64 = AtomicU64::new(0);
static READ_REPEATS: AtomicU64 = AtomicU64::new(0);
static WRITE_REPEATS: AtomicU64 = AtomicU64::new(0);

/// Whether `key` is new to `table`, remembering it. A full table answers
/// "new", so the caller prints. The root dispatcher is the only caller and
/// runs on one thread, so a load-then-store cannot race.
fn first(table: &[AtomicU64; KEYS], key: u64) -> bool {
    // Zero marks an empty entry, so stored keys are offset by one.
    let stored = key.wrapping_add(1).max(1);
    for entry in table {
        match entry.load(Relaxed) {
            0 => {
                entry.store(stored, Relaxed);
                return true;
            }
            value if value == stored => return false,
            _ => {}
        }
    }
    true
}

/// Whether to print `SLIME_CLOCK served` for this request; a repeat is counted.
pub(super) fn clock_served(task: u32, label: u64) -> bool {
    let key = (u64::from(task) << 32) | (label & 0xffff_ffff);
    let print = first(&SERVED, key);
    if !print {
        SERVED_REPEATS.fetch_add(1, Relaxed);
    }
    print
}

/// Whether to print `SLIME_CLOCK refused` for this request; a repeat is counted.
/// `class` is the refusal's index in `clock_requests::clock_error_index`.
pub(super) fn clock_refused(task: u32, label: u64, class: u8) -> bool {
    let key = (u64::from(task) << 32) | ((label & 0xff_ffff) << 8) | u64::from(class);
    let print = first(&REFUSED, key);
    if !print {
        REFUSED_REPEATS.fetch_add(1, Relaxed);
    }
    print
}

/// Whether to print this payload DMA and its frame lines; a repeat is counted.
pub(super) fn payload_dma(device_read: bool) -> bool {
    let bit = if device_read { 1 } else { 2 };
    let print = DMA_PRINTED.fetch_or(bit, Relaxed) & bit == 0;
    if !print {
        if device_read {
            &READ_REPEATS
        } else {
            &WRITE_REPEATS
        }
        .fetch_add(1, Relaxed);
    }
    print
}

/// Print the one summary of every unprinted occurrence.
pub(super) fn report() {
    crate::diagnostic_println!(
        "SLIME_ROOT diagnostic repeats clock_served={} clock_refused={} io_device_read={} io_device_write={}",
        SERVED_REPEATS.load(Relaxed),
        REFUSED_REPEATS.load(Relaxed),
        READ_REPEATS.load(Relaxed),
        WRITE_REPEATS.load(Relaxed),
    );
}
