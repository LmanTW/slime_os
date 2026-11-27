//! The stack the service used in one run, measured on seL4.
//!
//! The runtime reserves one stack for the component and starts the stack pointer at its top. `paint` fills the stack below
//! the frame of its caller with a known byte, and `used` finds the lowest byte the run changed. The depth is counted from the
//! top of the reserved stack, so it includes the frame of `main` and the frames above the painted region.

use core::ptr::{read_volatile, write_volatile};

/// The byte that fills the free stack.
const PAINT: u8 = 0xa5;
/// How far under the top of the reserved stack `main` paints. The runtime reserves 64 KiB, so the paint stays inside it.
pub const PAINT_DEPTH: usize = 60 * 1024;
/// The bytes left unpainted just below the caller. The painting loop's own frame lives there.
const MARGIN: usize = 512;

unsafe extern "C" {
    /// The runtime's record of the stack's top. Its value, and not its address, is the address the stack pointer starts at: the
    /// entry code loads the symbol's contents into the stack pointer.
    static __sel4_runtime_common__stack_bottom: usize;
}

/// A reading of the stack pointer, taken in a function that is not inlined so it names a real frame.
#[inline(never)]
fn stack_pointer() -> usize {
    let marker = 0u8;
    core::ptr::addr_of!(marker) as usize
}

/// The region `paint` filled.
pub struct Painted {
    /// The top of the reserved stack.
    top: usize,
    /// The first byte below the margin, where the paint starts.
    start: usize,
    /// The lowest painted byte.
    floor: usize,
}

/// Fills the stack from just below the current frame down to `depth` bytes under the top of the reserved stack.
pub fn paint(depth: usize) -> Painted {
    // SAFETY: the symbol is a static of one word that the runtime declares and never writes after link time.
    let top = unsafe { core::ptr::read(core::ptr::addr_of!(__sel4_runtime_common__stack_bottom)) };
    let start = stack_pointer() - MARGIN;
    let floor = top - depth;
    let mut at = floor;
    while at < start {
        // SAFETY: the range lies inside the stack the runtime reserved for this thread and below the live frame, so no live
        // value is in it.
        unsafe { write_volatile(at as *mut u8, PAINT) };
        at += 1;
    }
    Painted { top, start, floor }
}

impl Painted {
    /// The bytes of stack the run used, counted from the top of the reserved stack, or `None` when the run changed no
    /// painted byte. A run that reached `floor` used at least `top - floor`.
    pub fn used(&self) -> Option<usize> {
        let mut at = self.floor;
        while at < self.start {
            // SAFETY: the same range `paint` wrote.
            if unsafe { read_volatile(at as *const u8) } != PAINT {
                return Some(self.top - at);
            }
            at += 1;
        }
        None
    }

    /// The bytes between the top of the stack and the lowest painted byte. A run that changed the lowest painted byte used
    /// at least this much, and its measurement is a bound.
    pub fn span(&self) -> usize {
        self.top - self.floor
    }

    /// The bytes of the main frame and everything above the painted region, which the paint does not cover.
    pub fn above(&self) -> usize {
        self.top - self.start
    }
}
