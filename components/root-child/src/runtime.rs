//! Minimal seL4 task runtime for the `slime-root` native child fixture.
//!
//! The root task maps this image, places the child's IPC buffer in the granule
//! directly above the image footprint, and enters at `_start` with no register
//! arguments. This module establishes the stack, binds the IPC buffer, and calls
//! [`crate::main`]. It deliberately has no heap: the fixture allocates nothing.

use core::panic::PanicInfo;
use core::ptr;

use sel4::CapTypeForFrameObjectOfFixedSize;

const STACK_SIZE: usize = 4096 * 4;

sel4_runtime_common::declare_stack!(STACK_SIZE);
sel4_runtime_common::declare_entrypoint_with_stack_init!();

sel4_runtime_common::declare_rust_entrypoint! {
    entrypoint()
}

sel4_panicking_env::register_debug_put_char!(sel4::debug_put_char);

fn entrypoint() -> ! {
    // SAFETY: `ipc_buffer_addr` names the granule the root task mapped
    // read-write for this thread's IPC buffer, and no other reference to it
    // exists in this task.
    unsafe {
        sel4::set_ipc_buffer(
            ipc_buffer_addr()
                .as_mut()
                .expect("root task mapped an IPC buffer"),
        );
    }
    crate::main()
}

/// The root task places the IPC buffer immediately above the image footprint,
/// which is `_end` rounded up to a granule boundary.
fn ipc_buffer_addr() -> *mut sel4::IpcBuffer {
    unsafe extern "C" {
        static _end: usize;
    }
    (ptr::addr_of!(_end) as usize)
        .next_multiple_of(sel4::cap_type::Granule::FRAME_OBJECT_TYPE.bytes())
        as *mut sel4::IpcBuffer
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    sel4::debug_println!("SLIME_CHILD panic {info}");
    sel4_panicking_env::abort_without_info()
}
