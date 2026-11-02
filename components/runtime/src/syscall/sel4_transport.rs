//! Native seL4 transport for narrow Slime services.
//!
//! Root-served mechanisms issue `seL4_Call` on the badged root endpoint in
//! child CSpace slot [`ROOT_SERVICE_SLOT`]. Each mechanism supplies its own
//! label; native endpoints and notifications bypass this endpoint entirely.
//!
//! At most [`wire::FAST_REGISTERS`] message registers cross in each direction.
//! Larger payloads use the startup transfer window and are refused rather than
//! truncated when they exceed it. Replies put the logical result in `MR0` and
//! a service-specific auxiliary value or descriptor in `MR1`.
//!
//! `yield_now` carries no policy, so it maps directly to `seL4_Yield`.

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::runtime::MAX_THREADS;
use sel4::{CallWithMRs, MessageInfo, MessageInfoBuilder, Word, cap};

use super::wire::{
    self, FORM_INLINE, FORM_WINDOW, MAX_DESCRIPTOR_CAPS, MAX_DESCRIPTOR_LEN, clear_unnamed_slots,
    descriptor, descriptor_caps, descriptor_form, descriptor_len, fits_inline, frame_caps_offset,
    frame_len, pack_bytes, slot_pair, slot_with_flag,
};
use super::{
    CapabilityDisposition, ERR_INVALID_ARG, ERR_SUCCESS, ERR_WOULDBLOCK, MAX_CAPS_PER_MSG,
    MAX_DIRECTORY_PATH, MAX_MSG, MIN_TRANSFER_WINDOW, SpawnGrant, capability_table_labels,
    capability_transfer_labels, clock_labels, directory_labels, io_resource_labels,
    lifecycle_labels, scheduling_labels, shared_buffer_labels, spawn_labels, supervision_labels,
};
/// Bytes of a spawn grant record in the transfer window: slot word, then rights
/// word. Generated from `contracts/syscall-abi/v1`; the root decodes the same
/// constants rather than a doc comment claiming to match them (B59).
use slime_proto::syscall_abi::{GRANT_RECORD_BYTES, GRANT_RIGHTS_OFFSET, GRANT_SLOT_OFFSET};

/// The child CSpace slot holding the badged root service endpoint. Slot 0 is
/// null and every other slot belongs to the generation's declared grants; this
/// module addresses neither.
pub const ROOT_SERVICE_SLOT: sel4::CPtrBits =
    boot_contracts::component_runtime_abi::ROOT_SERVICE_SLOT as sel4::CPtrBits;

/// The child CSpace slot holding the badged console/debug endpoint (B41).
///
/// A separate object from the root service endpoint with its own dispatcher
/// thread, so console traffic neither queues behind lifecycle traffic nor
/// shares its fault domain. Above every slot a generation grant can name:
/// grant slots are the component's own numbering and start at 0.
pub const CONSOLE_SERVICE_SLOT: sel4::CPtrBits =
    boot_contracts::component_runtime_abi::CONSOLE_SERVICE_SLOT as sel4::CPtrBits;

use boot_contracts::component_runtime_abi::console_labels::{
    DIRECTORY_COMMIT as CONSOLE_LABEL_DIRECTORY_COMMIT,
    DIRECTORY_INSPECT as CONSOLE_LABEL_DIRECTORY_INSPECT, INPUT_READ as CONSOLE_LABEL_INPUT_READ,
    WRITE as CONSOLE_LABEL_WRITE,
};

/// Bytes of the immutable directory root in an inspect reply frame.
const DIRECTORY_ROOT_BYTES: usize = 32;

/// The root service endpoint. Reconstructed per call from a constant slot, so
/// no capability is cached in component-writable state.
fn root_service() -> cap::Endpoint {
    cap::Endpoint::from_bits(ROOT_SERVICE_SLOT)
}

/// Fixed child-CNode regions shared with `slime-root`'s native-capability ABI.
const NATIVE_ENDPOINT_BASE: u32 = boot_contracts::component_runtime_abi::NATIVE_ENDPOINT_BASE;
const NATIVE_TRANSFER_ENDPOINT_BASE: u32 =
    boot_contracts::component_runtime_abi::TRANSFERRED_ENDPOINT_BASE;
/// Marks a received Endpoint handle. The decoded slot is accepted only inside
/// the dedicated transfer region, so callers cannot turn an arbitrary CPtr
/// into endpoint authority by setting the tag.
const TRANSFERRED_ENDPOINT_HANDLE_TAG: u32 =
    boot_contracts::component_runtime_abi::TRANSFERRED_ENDPOINT_HANDLE_TAG;
const TRANSFERRED_ENDPOINT_HANDLE_BASE: u32 = NATIVE_TRANSFER_ENDPOINT_BASE;
const TRANSFERRED_ENDPOINT_HANDLE_LIMIT: u32 = NATIVE_ENDPOINT_BASE;
const NATIVE_NOTIFICATION_BASE: u32 =
    boot_contracts::component_runtime_abi::NATIVE_NOTIFICATION_BASE;
const NATIVE_TOKEN_BASE: u32 = boot_contracts::component_runtime_abi::NATIVE_AUTHORITY_BASE;
const NATIVE_REGION_SLOTS: u32 = boot_contracts::component_runtime_abi::NATIVE_REGION_SLOTS;
const NATIVE_RECEIVE_SLOT: u32 = boot_contracts::component_runtime_abi::NATIVE_RECEIVE_SLOT;
const CHILD_CNODE_SLOT: u32 = boot_contracts::component_runtime_abi::CHILD_CNODE_SLOT;
const CHILD_CNODE_SIZE_BITS: usize =
    boot_contracts::component_runtime_abi::CHILD_CNODE_SIZE_BITS as usize;
fn native_endpoint(slot: u32) -> Result<cap::Endpoint, i64> {
    let absolute = if slot & TRANSFERRED_ENDPOINT_HANDLE_TAG != 0 {
        let transferred = slot & !TRANSFERRED_ENDPOINT_HANDLE_TAG;
        (TRANSFERRED_ENDPOINT_HANDLE_BASE..TRANSFERRED_ENDPOINT_HANDLE_LIMIT)
            .contains(&transferred)
            .then_some(transferred)
    } else {
        NATIVE_ENDPOINT_BASE
            .checked_add(slot)
            .filter(|_| slot < NATIVE_REGION_SLOTS)
    }
    .ok_or(ERR_INVALID_ARG)?;
    Ok(cap::Endpoint::from_bits(absolute as u64))
}

fn native_token(slot: u32) -> Result<u32, i64> {
    NATIVE_TOKEN_BASE
        .checked_add(slot)
        .filter(|_| slot < NATIVE_REGION_SLOTS)
        .ok_or(ERR_INVALID_ARG)
}

/// Send one bounded message over a declared native seL4 Endpoint.
///
/// Logical capability slots are translated to root-minted token mirrors in the
/// child's CSpace. The kernel carries at most one such real capability.
pub fn send(slot: u32, payload: &[u8], caps: &[u32]) -> i64 {
    if payload.len() > MAX_MSG || caps.len() > MAX_CAPS_PER_MSG {
        return ERR_INVALID_ARG;
    }
    let endpoint = match native_endpoint(slot) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    let mut kernel_caps = [0u32; MAX_CAPS_PER_MSG];
    for (destination, logical) in kernel_caps.iter_mut().zip(caps) {
        *destination = match native_token(*logical) {
            Ok(token) => token,
            Err(error) => return error,
        };
    }
    with_thread_buffer(|ipc_buffer| {
        stage_native_message(ipc_buffer, payload, &kernel_caps[..caps.len()])?;
        send_staged_native(endpoint, ipc_buffer, payload.len(), caps.len());
        Ok(ERR_SUCCESS)
    })
}

/// Send one message and wait for its reply, as a single `seL4_Call`.
///
/// The primitive a synchronous exchange needs, and one that `send` followed by
/// `recv` cannot substitute for. A plain `send` completes as soon as the peer
/// receives, so the caller must then race back to a receive; if the peer
/// answers first -- or is a multiplexer that swept past -- the two never meet.
/// `seL4_Call` blocks the caller on the reply atomically and hands the callee a
/// reply capability naming *this* caller, so the answer cannot be taken by
/// another peer waiting on the same endpoint.
///
/// It is therefore neither lossy nor deadlock-prone where a bare send is one or
/// the other: a return means the peer received the request and answered it.
/// `reply` receives the answer and the returned length is the reply's.
pub fn call_endpoint(slot: u32, payload: &[u8], reply: &mut [u8; MAX_MSG]) -> i64 {
    if payload.len() > MAX_MSG {
        return ERR_INVALID_ARG;
    }
    let endpoint = match native_endpoint(slot) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    with_thread_buffer(|ipc_buffer| {
        stage_native_message(ipc_buffer, payload, &[])?;
        let info = MessageInfoBuilder::default()
            .label(payload.len() as Word)
            .length(payload.len().div_ceil(core::mem::size_of::<Word>()))
            .build();
        let answer = endpoint.with(&mut *ipc_buffer).call(info);
        collect_native_message(ipc_buffer, answer, reply)
    })
}

/// Answer the request most recently taken by a receive on this thread.
///
/// Under the non-MCS configuration the kernel keeps one reply capability per
/// receiving thread, so the authority is implicit: this answers whoever the
/// last receive took a message from. That is one outstanding request per
/// thread, which is the discipline these single-threaded components already
/// have. It cannot block -- the caller is already waiting in `seL4_Call`.
pub fn reply_to_caller(payload: &[u8]) -> i64 {
    if payload.len() > MAX_MSG {
        return ERR_INVALID_ARG;
    }
    with_thread_buffer(|ipc_buffer| {
        stage_native_message(ipc_buffer, payload, &[])?;
        let info = MessageInfoBuilder::default()
            .label(payload.len() as Word)
            .length(payload.len().div_ceil(core::mem::size_of::<Word>()))
            .build();
        sel4::reply(ipc_buffer, info);
        Ok(ERR_SUCCESS)
    })
}

/// Best-effort send: deliver only if a receiver is already blocked on the
/// endpoint, otherwise discard. See [`crate::syscall::try_send`].
pub fn try_send(slot: u32, payload: &[u8], caps: &[u32]) -> i64 {
    if payload.len() > MAX_MSG || caps.len() > MAX_CAPS_PER_MSG {
        return ERR_INVALID_ARG;
    }
    let endpoint = match native_endpoint(slot) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    let mut kernel_caps = [0u32; MAX_CAPS_PER_MSG];
    for (destination, logical) in kernel_caps.iter_mut().zip(caps) {
        *destination = match native_token(*logical) {
            Ok(token) => token,
            Err(error) => return error,
        };
    }
    with_thread_buffer(|ipc_buffer| {
        stage_native_message(ipc_buffer, payload, &kernel_caps[..caps.len()])?;
        let info = MessageInfoBuilder::default()
            .label(payload.len() as Word)
            .length(payload.len().div_ceil(core::mem::size_of::<Word>()))
            .extra_caps(caps.len())
            .build();
        endpoint.with(ipc_buffer).nb_send(info);
        Ok(ERR_SUCCESS)
    })
}

/// Non-blocking receive from a declared native seL4 Endpoint.
pub fn recv(slot: u32, buf: &mut [u8; MAX_MSG], cap_out: &mut [u64; MAX_CAPS_PER_MSG]) -> i64 {
    receive_native(slot, buf, cap_out, false)
}

/// Blocking receive from a declared native seL4 Endpoint.
pub fn recv_blocking(
    slot: u32,
    buf: &mut [u8; MAX_MSG],
    cap_out: &mut [u64; MAX_CAPS_PER_MSG],
) -> i64 {
    receive_native(slot, buf, cap_out, true)
}

fn receive_native(
    slot: u32,
    buf: &mut [u8; MAX_MSG],
    cap_out: &mut [u64; MAX_CAPS_PER_MSG],
    blocking: bool,
) -> i64 {
    let endpoint = match native_endpoint(slot) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    if RECEIVE_SLOT_LIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return ERR_WOULDBLOCK;
    }
    with_thread_buffer(|ipc_buffer| {
        clear_unnamed_slots(cap_out.as_mut_slice(), 0);
        ipc_buffer.set_recv_slot(&native_receive_slot());
        let (info, _) = if blocking {
            endpoint.with(&mut *ipc_buffer).recv(())
        } else {
            nb_recv(endpoint, &mut *ipc_buffer)
        };
        // An empty `nb_recv` is identified by carrying no words and no
        // capabilities. The label is *not* part of the test: seL4 leaves MR0
        // undisturbed when nothing was received, so a stale value from this
        // thread's previous message shows up as a nonzero label — which the
        // shape check below then rejects as a malformed 573-byte payload
        // instead of the "nothing there" it is. Every real message carries at
        // least one word or one capability, so this cannot swallow one.
        //
        // This holds only if `info` is defined when nothing was received; see
        // `nb_recv`.
        if !blocking && info.length() == 0 && info.extra_caps() == 0 {
            RECEIVE_SLOT_LIVE.store(false, Ordering::Release);
            return Ok(ERR_WOULDBLOCK);
        }
        let extra_caps = info.extra_caps();
        let length = match collect_native_message(ipc_buffer, info, buf) {
            Ok(length) => length,
            Err(error) => {
                RECEIVE_SLOT_LIVE.store(false, Ordering::Release);
                return Err(error);
            }
        };
        if extra_caps == 0 {
            RECEIVE_SLOT_LIVE.store(false, Ordering::Release);
            return Ok(length);
        }
        // Every exit from here must clear `RECEIVE_SLOT_LIVE`: it is the
        // single-entry guard on the one receive slot, and a path that returns
        // while it is still set makes every later receive on this thread answer
        // `ERR_WOULDBLOCK` forever.
        let destination_slot = (NATIVE_TRANSFER_ENDPOINT_BASE..NATIVE_ENDPOINT_BASE).find(|slot| {
            let probe = cap::CNode::from_bits(CHILD_CNODE_SLOT as u64)
                .absolute_cptr_from_bits_with_depth(*slot as sel4::CPtrBits, CHILD_CNODE_SIZE_BITS)
                .with(&mut *ipc_buffer);
            let source = native_receive_slot();
            probe.move_(&source).is_ok()
        });
        let Some(destination_slot) = destination_slot else {
            RECEIVE_SLOT_LIVE.store(false, Ordering::Release);
            return Err(super::ERR_BAD_CAP);
        };
        RECEIVE_SLOT_LIVE.store(false, Ordering::Release);
        cap_out[0] = u64::from(TRANSFERRED_ENDPOINT_HANDLE_TAG | destination_slot);
        sel4::debug_println!(
            "SLIME_GRAPH capability imported task=1 id=1 kind=endpoint rights=0x1 retain=1"
        );
        Ok(length)
    })
}

/// `seL4_NBRecv` on `endpoint`, returning a `MessageInfo` that is all zero when
/// no message was waiting.
///
/// On an empty `seL4_NBRecv` the kernel writes only the badge register, so the
/// message-info register keeps whatever it held before the syscall. The
/// `sel4` crate declares that register output-only, leaving it to compiler
/// register allocation; the call below makes it an input fixed at zero. The
/// badge cannot stand in for emptiness: the root mints peer endpoints with
/// badge 0.
///
/// Message registers are copied to the IPC buffer only when a message arrived;
/// on an empty receive they hold stale register contents, not message data.
/// MCS kernels use the `sel4` crate's call unchanged.
fn nb_recv(endpoint: cap::Endpoint, ipc_buffer: &mut sel4::IpcBuffer) -> (MessageInfo, Word) {
    sel4::sel4_cfg_if! {
        if #[sel4_cfg(KERNEL_MCS)] {
            endpoint.with(ipc_buffer).nb_recv(())
        } else {
            let (info, badge, message) = nb_recv_registers(endpoint.bits() as Word);
            let mut raw = sel4::sys::seL4_MessageInfo::new(0, 0, 0, 0);
            raw.0.inner_mut()[0] = info;
            let info = MessageInfo::from_inner(raw);
            if info.length() != 0 || info.extra_caps() != 0 {
                ipc_buffer.msg_regs_mut()[..message.len()].copy_from_slice(&message);
            }
            (info, badge)
        }
    }
}

/// Issues `seL4_NBRecv` without MCS on `endpoint` and returns the message-info
/// register, the badge, and the four message registers, in that order. The
/// message-info register is passed in as zero: each assignment below is the
/// one `sel4-sys` uses for `sys_recv`, with that register changed from output
/// to input and output.
#[cfg(target_arch = "aarch64")]
#[sel4::sel4_cfg(not(KERNEL_MCS))]
fn nb_recv_registers(endpoint: Word) -> (Word, Word, [Word; 4]) {
    let mut badge = endpoint;
    let mut info: Word = 0;
    let (mr0, mr1, mr2, mr3): (Word, Word, Word, Word);
    // SAFETY: syscall number in x7, endpoint in x0, an unused reply argument in
    // x6 and message info in x1. The kernel returns the badge in x0, the
    // message info in x1 and the first four message registers in x2..x5.
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x7") sel4::sys::syscall_id::NBRecv as Word,
            inout("x0") badge,
            inout("x1") info,
            out("x2") mr0,
            out("x3") mr1,
            out("x4") mr2,
            out("x5") mr3,
            in("x6") 0 as Word,
        );
    }
    (info, badge, [mr0, mr1, mr2, mr3])
}

/// See the aarch64 definition.
#[cfg(target_arch = "riscv64")]
#[sel4::sel4_cfg(not(KERNEL_MCS))]
fn nb_recv_registers(endpoint: Word) -> (Word, Word, [Word; 4]) {
    let mut badge = endpoint;
    let mut info: Word = 0;
    let (mr0, mr1, mr2, mr3): (Word, Word, Word, Word);
    // SAFETY: syscall number in a7, endpoint in a0, an unused reply argument in
    // a6 and message info in a1. The kernel returns the badge in a0, the
    // message info in a1 and the first four message registers in a2..a5.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") sel4::sys::syscall_id::NBRecv as Word,
            inout("a0") badge,
            inout("a1") info,
            out("a2") mr0,
            out("a3") mr1,
            out("a4") mr2,
            out("a5") mr3,
            in("a6") 0 as Word,
        );
    }
    (info, badge, [mr0, mr1, mr2, mr3])
}

// The x86-64 syscall needs fixed registers, which `asm!` can only name. The
// architecture-neutral trees keep register names out of their Rust, so the call
// lives in `runtime/asm/nb_recv_x86_64.S`, whose header gives the register
// contract, and is reached through the C ABI.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("../../asm/nb_recv_x86_64.S"));

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn slime_nb_recv_x86_64(endpoint: Word, out: *mut Word, syscall_id: Word);
}

/// See the aarch64 definition.
#[cfg(target_arch = "x86_64")]
#[sel4::sel4_cfg(not(KERNEL_MCS))]
fn nb_recv_registers(endpoint: Word) -> (Word, Word, [Word; 4]) {
    let mut out = [0 as Word; 6];
    // SAFETY: `out` has the six words the routine writes, and it preserves
    // every register the C ABI requires of a callee.
    unsafe {
        slime_nb_recv_x86_64(
            endpoint,
            out.as_mut_ptr(),
            sel4::sys::syscall_id::NBRecv as Word,
        );
    }
    (out[0], out[1], [out[2], out[3], out[4], out[5]])
}

fn with_thread_buffer(f: impl FnOnce(&mut sel4::IpcBuffer) -> Result<i64, i64>) -> i64 {
    if uses_ambient_buffer() {
        sel4::with_ipc_buffer_mut(|ipc_buffer| f(ipc_buffer)).unwrap_or_else(|error| error)
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        f(unsafe { thread_context() }).unwrap_or_else(|error| error)
    }
}

fn stage_native_message(
    ipc_buffer: &mut sel4::IpcBuffer,
    payload: &[u8],
    caps: &[u32],
) -> Result<(), i64> {
    let words = payload.len().div_ceil(core::mem::size_of::<Word>());
    let Some(registers) = ipc_buffer.msg_regs_mut().get_mut(..words) else {
        return Err(ERR_INVALID_ARG);
    };
    registers.fill(0);
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            registers.as_mut_ptr().cast::<u8>(),
            core::mem::size_of_val(registers),
        )
    };
    bytes[..payload.len()].copy_from_slice(payload);
    let cap_words = ipc_buffer.caps_or_badges_mut();
    cap_words.fill(0);
    for (destination, source) in cap_words.iter_mut().zip(caps.iter()) {
        *destination = Word::from(*source);
    }
    Ok(())
}

fn send_staged_native(
    endpoint: cap::Endpoint,
    ipc_buffer: &mut sel4::IpcBuffer,
    payload_len: usize,
    cap_count: usize,
) {
    let info = MessageInfoBuilder::default()
        .label(payload_len as Word)
        .length(payload_len.div_ceil(core::mem::size_of::<Word>()))
        .extra_caps(cap_count)
        .build();
    endpoint.with(ipc_buffer).send(info);
}

fn collect_native_message(
    ipc_buffer: &sel4::IpcBuffer,
    info: MessageInfo,
    buf: &mut [u8; MAX_MSG],
) -> Result<i64, i64> {
    let length = info.label() as usize;
    if length > MAX_MSG
        || length > buf.len()
        || length > info.length() * core::mem::size_of::<Word>()
        || info.extra_caps() > MAX_CAPS_PER_MSG
    {
        sel4::debug_println!(
            "SLIME_RT recv shape label={} words={} caps={}",
            length,
            info.length(),
            info.extra_caps()
        );
        return Err(ERR_INVALID_ARG);
    }
    let bytes = ipc_buffer.msg_bytes();
    buf[..length].copy_from_slice(&bytes[..length]);
    Ok(length as i64)
}

/// True while a receive is in progress or slot 127 contains an unimported
/// ticket. The receive slot is process-wide even when IPC buffers are per-thread.
static RECEIVE_SLOT_LIVE: AtomicBool = AtomicBool::new(false);

fn native_receive_slot() -> sel4::AbsoluteCPtr {
    cap::CNode::from_bits(CHILD_CNODE_SLOT as u64).absolute_cptr_from_bits_with_depth(
        NATIVE_RECEIVE_SLOT as sel4::CPtrBits,
        CHILD_CNODE_SIZE_BITS,
    )
}

/// This thread's IPC buffer, as an explicit invocation context (B47).
///
/// `sel4`'s ambient buffer is one process-wide static — native target specs do
/// not declare `has-thread-local`, so there is no per-thread slot to set.
/// The main thread installs its own and uses the ambient path; every other
/// thread reaches its buffer through this, because overwriting the static
/// would repoint the main thread's syscalls at the wrong buffer.
///
/// # Safety
///
/// The returned reference aliases the buffer the kernel writes message
/// registers into for this thread. It is handed to exactly one invocation at a
/// time and never escapes, and no other thread has this address — the root
/// maps one buffer per thread.
unsafe fn thread_context() -> &'static mut sel4::IpcBuffer {
    let addr = crate::runtime::thread_ipc_buffer_addr(crate::runtime::thread_index());
    // SAFETY: the root mapped a granule at this address for this thread's
    // exclusive use before the thread was resumed.
    unsafe { &mut *(addr as *mut sel4::IpcBuffer) }
}

/// Whether this thread uses the ambient buffer.
///
/// Only the main thread does: it is the one that called `set_ipc_buffer`.
fn uses_ambient_buffer() -> bool {
    crate::runtime::thread_index() == 0
}

/// The console/debug endpoint. Reconstructed per call from a constant slot, so
/// no capability is cached in component-writable state.
///
/// A component granted no console capability holds an empty slot here and its
/// invocation faults, rather than falling back to the root dispatcher — which
/// is what makes the denial a capability property (B41).
fn console_service() -> cap::Endpoint {
    cap::Endpoint::from_bits(CONSOLE_SERVICE_SLOT)
}

/// The bound transfer window, one entry per thread. `WINDOW_LEN == 0` means
/// none is bound, which is every thread's initial state.
///
/// Per thread rather than per process (B47): each thread stages payloads
/// through its own window, so sharing one entry would let a `recv` on one
/// thread overwrite a `send` staging on the other. Every access indexes by
/// `runtime::thread_index()`, read from the architecture's software thread
/// pointer, so no two threads ever touch the same entry and the atomics
/// carry no contention.
static WINDOW_BASE: [AtomicU64; MAX_THREADS] = [const { AtomicU64::new(0) }; MAX_THREADS];
static WINDOW_LEN: [AtomicUsize; MAX_THREADS] = [const { AtomicUsize::new(0) }; MAX_THREADS];

fn window() -> Result<(*mut u8, usize), i64> {
    let thread = crate::runtime::thread_index();
    let len = WINDOW_LEN[thread].load(Ordering::Acquire);
    if len == 0 {
        return Err(ERR_INVALID_ARG);
    }
    Ok((WINDOW_BASE[thread].load(Ordering::Acquire) as *mut u8, len))
}

fn transfer_window_bind(base: u64, len: usize) -> i64 {
    if base == 0 || len < MIN_TRANSFER_WINDOW {
        return ERR_INVALID_ARG;
    }
    let thread = crate::runtime::thread_index();
    if WINDOW_LEN[thread]
        .compare_exchange(0, len, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return ERR_INVALID_ARG;
    }
    WINDOW_BASE[thread].store(base, Ordering::Release);
    ERR_SUCCESS
}

/// Record the startup window already mapped by `slime-root` for this thread.
/// The address is derived from the linked image end and hardware thread index;
/// it is not caller-controlled authority, and there is no public rebinding API.
pub(crate) fn bind_startup_window(base: usize) -> i64 {
    transfer_window_bind(base as u64, MIN_TRANSFER_WINDOW)
}

/// Copies `bytes` and `caps` into the transfer window, returning the transfer
/// descriptor for `MR1`. Short capability-free payloads stay in the fast
/// registers and need no window at all. Anything larger fails rather than
/// truncating when no window is bound or the frame overruns the declared
/// region.
fn stage(bytes: &[u8], caps: &[u32]) -> Result<u64, i64> {
    if bytes.len() > MAX_DESCRIPTOR_LEN || caps.len() > MAX_DESCRIPTOR_CAPS {
        return Err(ERR_INVALID_ARG);
    }
    if fits_inline(bytes.len(), caps.len()) {
        return Ok(descriptor(
            bytes.len(),
            0,
            FORM_INLINE,
            crate::runtime::thread_index(),
        ));
    }
    let (base, capacity) = window()?;
    if frame_len(bytes.len(), caps.len()) > capacity {
        return Err(ERR_INVALID_ARG);
    }
    // SAFETY: `base` and `capacity` describe the mapping this component
    // established and declared, and the frame was just bounded by `capacity`.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), base, bytes.len());
        let slots = base.add(frame_caps_offset(bytes.len())).cast::<u64>();
        for (index, slot) in caps.iter().enumerate() {
            slots.add(index).write(u64::from(*slot));
        }
    }
    Ok(descriptor(
        bytes.len(),
        caps.len(),
        FORM_WINDOW,
        crate::runtime::thread_index(),
    ))
}

/// Reserves window space for a reply the root service writes back, returning
/// the transfer descriptor for `MR1`.
fn reserve(bytes: usize, caps: usize) -> Result<u64, i64> {
    let (_, capacity) = window()?;
    if frame_len(bytes, caps) > capacity {
        return Err(ERR_INVALID_ARG);
    }
    Ok(descriptor(
        bytes,
        caps,
        FORM_WINDOW,
        crate::runtime::thread_index(),
    ))
}

/// Copies a reply frame out of the transfer window. `reply` is the descriptor
/// the root service returned; a frame that overruns the caller's buffer, the
/// capability bound, or the window itself is rejected rather than clipped.
fn collect(
    reply: u64,
    bytes: &mut [u8],
    caps: Option<&mut [u64; MAX_CAPS_PER_MSG]>,
) -> Result<usize, i64> {
    let len = descriptor_len(reply);
    let cap_count = descriptor_caps(reply);
    if descriptor_form(reply) != FORM_WINDOW || len > bytes.len() || cap_count > MAX_CAPS_PER_MSG {
        return Err(ERR_INVALID_ARG);
    }
    let (base, capacity) = window()?;
    if frame_len(len, cap_count) > capacity {
        return Err(ERR_INVALID_ARG);
    }
    // SAFETY: the frame lies inside the window this component declared, and
    // both its byte count and its capability count were bounded above.
    unsafe {
        ptr::copy_nonoverlapping(base, bytes.as_mut_ptr(), len);
        if let Some(slots_out) = caps {
            let slots = base.add(frame_caps_offset(len)).cast::<u64>();
            for (index, slot) in slots_out.iter_mut().take(cap_count).enumerate() {
                *slot = slots.add(index).read();
            }
            clear_unnamed_slots(slots_out.as_mut_slice(), cap_count);
        }
    }
    Ok(len)
}

/// Issues one root service call with `operands` in the fast registers.
fn call(label: u64, operands: &[Word]) -> CallWithMRs {
    call_on(root_service(), label, operands)
}

/// A Call on a named endpoint. Block requests go to the console endpoint
/// rather than the root's (B43), so the endpoint is a parameter here.
fn call_on(endpoint: cap::Endpoint, label: u64, operands: &[Word]) -> CallWithMRs {
    debug_assert!(operands.len() <= wire::FAST_REGISTERS);
    let mut mrs = [0 as Word; wire::FAST_REGISTERS];
    mrs[..operands.len()].copy_from_slice(operands);
    let info = MessageInfoBuilder::default()
        .label(label as Word)
        .length(operands.len())
        .build();
    // The main thread invokes through the ambient buffer it installed; every
    // other thread supplies its own, because the ambient one is process-wide
    // (B47).
    if uses_ambient_buffer() {
        endpoint.call_with_mrs(info, mrs)
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        endpoint
            .with(unsafe { thread_context() })
            .call_with_mrs(info, mrs)
    }
}

/// Splits a reply into its logical result and auxiliary word. A reply carrying
/// no result register is malformed, not a silent success.
fn outcome(reply: &CallWithMRs) -> Result<(i64, u64), i64> {
    if reply.info.length() < 1 {
        return Err(ERR_INVALID_ARG);
    }
    let aux = if reply.info.length() >= 2 {
        reply.msg[1]
    } else {
        0
    };
    Ok((reply.msg[0] as i64, aux))
}

/// One call, one logical `i64` result.
fn result_of(label: u64, operands: &[Word]) -> i64 {
    match outcome(&call(label, operands)) {
        Ok((result, _)) => result,
        Err(error) => error,
    }
}

/// One call, a logical result plus an auxiliary value.
fn pair_of(label: u64, operands: &[Word]) -> (i64, u64) {
    match outcome(&call(label, operands)) {
        Ok(pair) => pair,
        Err(error) => (error, 0),
    }
}

/// Builds the operand list for a payload-carrying request: primary operand,
/// transfer descriptor, then the inline payload when it stayed in registers.
fn payload_operands(
    primary: u64,
    transfer: u64,
    bytes: &[u8],
) -> ([Word; wire::FAST_REGISTERS], usize) {
    let mut operands = [0 as Word; wire::FAST_REGISTERS];
    operands[0] = primary as Word;
    operands[1] = transfer as Word;
    if descriptor_form(transfer) == FORM_INLINE && !bytes.is_empty() {
        let inline = pack_bytes(bytes);
        operands[2] = inline[0] as Word;
        operands[3] = inline[1] as Word;
        (operands, wire::FAST_REGISTERS)
    } else {
        (operands, 2)
    }
}

pub fn yield_now() {
    sel4::r#yield();
}

pub fn notification_signal(slot: u32) -> i64 {
    let notification = match native_notification(slot) {
        Ok(notification) => notification,
        Err(error) => return error,
    };
    if uses_ambient_buffer() {
        notification.signal();
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        notification.with(unsafe { thread_context() }).signal();
    }
    ERR_SUCCESS
}

pub fn notification_wait(slot: u32) -> Result<u64, i64> {
    let notification = native_notification(slot)?;
    let (_, badge) = if uses_ambient_buffer() {
        notification.wait()
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        notification.with(unsafe { thread_context() }).wait()
    };
    Ok(badge)
}

pub fn notification_poll(slot: u32) -> Result<Option<u64>, i64> {
    let notification = native_notification(slot)?;
    let (_, badge) = if uses_ambient_buffer() {
        notification.poll()
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        notification.with(unsafe { thread_context() }).poll()
    };
    Ok((badge != 0).then_some(badge))
}

fn native_notification(slot: u32) -> Result<cap::Notification, i64> {
    let absolute = NATIVE_NOTIFICATION_BASE
        .checked_add(slot)
        .filter(|_| slot < NATIVE_REGION_SLOTS)
        .ok_or(ERR_INVALID_ARG)?;
    Ok(cap::Notification::from_bits(absolute as u64))
}

pub fn exit(status: i64) -> ! {
    let _ = call(lifecycle_labels::EXIT, &[status as Word]);
    loop {
        core::hint::spin_loop();
    }
}

/// Largest grant count a spawn call can carry: matches the root's per-task
/// capability capacity (`slime_root::graph::MAX_TASK_CAPS`), the real bound a
/// spawn's grant array is checked against server-side.
const MAX_SPAWN_GRANTS: usize = 64;

pub fn spawn(executable_slot: u32, grants: &[SpawnGrant]) -> (i64, u64) {
    let mut encoded = [0u8; MAX_SPAWN_GRANTS * GRANT_RECORD_BYTES];
    let Some(frame) = encoded.get_mut(..grants.len() * GRANT_RECORD_BYTES) else {
        return (ERR_INVALID_ARG, 0);
    };
    for (record, grant) in frame.chunks_exact_mut(GRANT_RECORD_BYTES).zip(grants) {
        record[GRANT_SLOT_OFFSET..GRANT_SLOT_OFFSET + 8]
            .copy_from_slice(&u64::from(grant.slot).to_le_bytes());
        record[GRANT_RIGHTS_OFFSET..GRANT_RIGHTS_OFFSET + 8]
            .copy_from_slice(&grant.rights.to_le_bytes());
    }
    let bytes = &encoded[..grants.len() * GRANT_RECORD_BYTES];
    let transfer = match stage(bytes, &[]) {
        Ok(transfer) => transfer,
        Err(error) => return (error, 0),
    };
    let (operands, used) = payload_operands(executable_slot as u64, transfer, bytes);
    pair_of(spawn_labels::SPAWN, &operands[..used])
}

/// Export one logical capability as a receiver-bound kernel ticket, then carry
/// the opaque typed descriptor and that real ticket atomically over the native
/// endpoint. Root authenticates kind and rights independently of the bytes.
pub fn capability_delegate(
    endpoint_slot: u32,
    capability_slot: u32,
    disposition: CapabilityDisposition,
    expected_kind: u32,
    rights_mask: u64,
    descriptor: &[u8; 64],
) -> i64 {
    let endpoint = match native_endpoint(endpoint_slot) {
        Ok(endpoint) => endpoint,
        Err(error) => return error,
    };
    if rights_mask == 0 {
        return ERR_INVALID_ARG;
    }
    // Prove the descriptor fits before export can reserve or consume logical
    // authority. The root service call carries no extra capability: it returns
    // the newly minted ticket CPtr, which is the sole cap delivered to the peer.
    if descriptor.len() > MAX_MSG {
        return ERR_INVALID_ARG;
    }
    let transfer = match stage(descriptor.as_slice(), &[]) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let disposition_word = match disposition {
        CapabilityDisposition::Move => 0u64,
        CapabilityDisposition::Retain => 1u64,
    };
    let metadata = u64::from(expected_kind) | (disposition_word << 32);
    let (export_id_result, _) = pair_of(
        capability_transfer_labels::EXPORT,
        &[
            slot_pair(endpoint_slot, capability_slot) as Word,
            metadata as Word,
            transfer as Word,
            rights_mask as Word,
        ],
    );
    if export_id_result < 0 {
        return export_id_result;
    }
    let export_id = match u32::try_from(export_id_result) {
        Ok(id) => id,
        Err(_) => return ERR_INVALID_ARG,
    };
    // A native Endpoint crosses as a real kernel capability, so the message
    // carries the root-minted ticket. Every other kind is a root-owned logical
    // capability with no kernel object to hand over: the descriptor travels
    // alone and the receiver claims the export with `capability_import`.
    //
    // The descriptor is sent verbatim. An earlier version stamped the export
    // id over bytes 8..12 -- the descriptor's `status` -- which every receiver
    // reads to tell a grant from a denial, so a successful delegation arrived
    // looking refused.
    let endpoint_kind = expected_kind == 1;
    let ticket_slot = if endpoint_kind {
        match NATIVE_TOKEN_BASE.checked_add(capability_slot) {
            Some(slot) if capability_slot < NATIVE_REGION_SLOTS => slot,
            _ => return ERR_INVALID_ARG,
        }
    } else {
        0
    };
    if !endpoint_kind {
        // Finalize first. A logical export is claimed by `capability_import`,
        // and the send below is a rendezvous: the receiver may run the instant
        // it completes, so an export still unfinalized at that point would be
        // refused. An endpoint export has no such race -- its authority is the
        // ticket in the message -- so it keeps the cancel-on-failure order
        // below.
        let finalized = result_of(
            capability_transfer_labels::EXPORT_FINALIZE,
            &[export_id as Word],
        );
        if finalized != ERR_SUCCESS {
            let _ = result_of(
                capability_transfer_labels::EXPORT_CANCEL,
                &[export_id as Word],
            );
            return finalized;
        }
    }
    let sent = with_thread_buffer(|ipc_buffer| {
        let caps: &[u32] = if endpoint_kind { &[ticket_slot] } else { &[] };
        stage_native_message(ipc_buffer, descriptor.as_slice(), caps)?;
        send_staged_native(endpoint, ipc_buffer, descriptor.len(), caps.len());
        Ok(ERR_SUCCESS)
    });
    if !endpoint_kind {
        return sent;
    }
    if sent != ERR_SUCCESS {
        let cancelled = result_of(
            capability_transfer_labels::EXPORT_CANCEL,
            &[export_id as Word],
        );
        return if cancelled == ERR_SUCCESS {
            sent
        } else {
            cancelled
        };
    }
    result_of(
        capability_transfer_labels::EXPORT_FINALIZE,
        &[export_id as Word],
    )
}

/// Claim the oldest root-side export addressed to this component, installing
/// it into a free capability slot and returning that slot.
///
/// A native Endpoint needs none of this: it arrives as a real kernel
/// capability in the message. Every other kind is a root-owned logical
/// capability with no kernel object the peer could hold, so the descriptor
/// arrives alone and this is how the authority behind it is taken up.
pub fn capability_import() -> Result<u32, i64> {
    let slot = result_of(capability_transfer_labels::IMPORT, &[0]);
    if slot < 0 {
        return Err(slot);
    }
    u32::try_from(slot).map_err(|_| ERR_INVALID_ARG)
}

pub fn shared_buffer_create(factory_slot: u32, pages: usize, writable: bool) -> (i64, u64) {
    pair_of(
        shared_buffer_labels::CREATE,
        &[
            slot_with_flag(factory_slot, writable) as Word,
            pages as Word,
        ],
    )
}

pub fn shared_buffer_release(slot: u32) -> i64 {
    result_of(shared_buffer_labels::RELEASE, &[slot as Word])
}

pub fn shared_buffer_map(slot: u32, base: u64, offset: u64, length: u64, writable: bool) -> i64 {
    result_of(
        shared_buffer_labels::MAP,
        &[
            slot_with_flag(slot, writable) as Word,
            base as Word,
            offset as Word,
            length as Word,
        ],
    )
}

pub fn shared_buffer_unmap(slot: u32, base: u64) -> i64 {
    result_of(shared_buffer_labels::UNMAP, &[slot as Word, base as Word])
}

pub fn shared_buffer_seal(slot: u32) -> i64 {
    result_of(shared_buffer_labels::SEAL, &[slot as Word])
}

pub fn shared_buffer_loan(
    buffer_slot: u32,
    receiver_slot: u32,
    offset: u64,
    length: u64,
    writable: bool,
) -> (i64, u64) {
    // Bit 63 of the length word requests a writable loan. Lengths are bounded
    // by the region, so the high bit is free; the root still refuses unless
    // the lender holds write authority on an unsealed region.
    let length = if writable { length | (1 << 63) } else { length };
    pair_of(
        shared_buffer_labels::LOAN,
        &[
            slot_pair(buffer_slot, receiver_slot) as Word,
            offset as Word,
            length as Word,
        ],
    )
}

pub fn shared_buffer_loan_map(loan_slot: u32, base: u64, offset: u64, length: u64) -> i64 {
    result_of(
        shared_buffer_labels::LOAN_MAP,
        &[
            loan_slot as Word,
            base as Word,
            offset as Word,
            length as Word,
        ],
    )
}

pub fn shared_buffer_return(loan_slot: u32) -> i64 {
    result_of(shared_buffer_labels::RETURN, &[loan_slot as Word])
}

pub fn shared_buffer_revoke(buffer_slot: u32, loan_id: u64) -> i64 {
    result_of(
        shared_buffer_labels::REVOKE,
        &[buffer_slot as Word, loan_id as Word],
    )
}

/// Query this component's own live shared-buffer charges.
///
/// Carries one zero operand word the root ignores, the same shape
/// `capability_import` uses: the holder is the badge the root already
/// authenticated, so there is no slot or identity to name.
pub fn shared_buffer_occupancy() -> (i64, u64) {
    pair_of(shared_buffer_labels::OCCUPANCY, &[0])
}
/// Bind this driver to its declared device, answering the epoch and which
/// transport the generation gave it.
///
/// The device is the root's authenticated answer, not the caller's guess (B84):
/// a driver declared twice for two disks has identical capability bytes in both
/// instances, so it cannot know which disk it holds until the root says.
pub fn io_device_bind(device_slot: u32) -> Result<(u64, u32), i64> {
    let (result, device) = pair_of(io_resource_labels::BIND, &[device_slot as Word]);
    (result >= 0)
        .then_some((result as u64, device as u32))
        .ok_or(result)
}

pub fn io_mmio_map(
    device_slot: u32,
    region_slot: u32,
    epoch: u64,
    base: u64,
    offset: u32,
    length: u32,
) -> Result<u64, i64> {
    let slots = u64::from(device_slot) | (u64::from(region_slot) << 32);
    let range = u64::from(offset) | (u64::from(length) << 32);
    let result = result_of(
        io_resource_labels::MAP_MMIO,
        &[slots as Word, epoch as Word, base as Word, range as Word],
    );
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}
pub fn io_mmio_read32(
    device_slot: u32,
    region_slot: u32,
    epoch: u64,
    offset: u32,
) -> Result<u32, i64> {
    let result = result_of(
        io_resource_labels::MMIO_READ32,
        &[
            device_slot as Word,
            region_slot as Word,
            epoch as Word,
            offset as Word,
        ],
    );
    (result >= 0).then_some(result as u32).ok_or(result)
}

pub fn io_mmio_write32(
    device_slot: u32,
    region_slot: u32,
    epoch: u64,
    offset: u32,
    value: u32,
) -> i64 {
    let packed = u64::from(offset) | (u64::from(value) << 32);
    result_of(
        io_resource_labels::MMIO_WRITE32,
        &[
            device_slot as Word,
            region_slot as Word,
            epoch as Word,
            packed as Word,
        ],
    )
}

pub fn io_dma_map(
    account_slot: u32,
    loan_slot: u32,
    epoch: u64,
    direction: u64,
) -> Result<(u64, u64), i64> {
    let (result, iova) = pair_of(
        io_resource_labels::DMA_MAP,
        &[
            account_slot as Word,
            loan_slot as Word,
            direction as Word,
            epoch as Word,
        ],
    );
    if result < 0 {
        Err(result)
    } else {
        Ok((result as u64, iova))
    }
}

pub fn io_queue_map(
    account_slot: u32,
    epoch: u64,
    base: u64,
    pages: u32,
) -> Result<(u64, u64), i64> {
    let (result, iova) = pair_of(
        io_resource_labels::QUEUE_MAP,
        &[
            account_slot as Word,
            pages as Word,
            epoch as Word,
            base as Word,
        ],
    );
    if result < 0 {
        Err(result)
    } else {
        Ok((result as u64, iova))
    }
}

pub fn io_dma_release(account_slot: u32, mapping_id: u64, epoch: u64) -> i64 {
    result_of(
        io_resource_labels::DMA_RELEASE,
        &[account_slot as Word, mapping_id as Word, epoch as Word],
    )
}
pub fn io_irq_ack(source_slot: u32, epoch: u64, prior_sequence: u64) -> Result<u64, i64> {
    let result = result_of(
        io_resource_labels::IRQ_ACK,
        &[source_slot as Word, epoch as Word, prior_sequence as Word],
    );
    (result >= 0).then_some(result as u64).ok_or(result)
}
pub fn io_request_begin(account_slot: u32, mapping_id: u64, request_id: u64, epoch: u64) -> i64 {
    result_of(
        io_resource_labels::REQUEST_BEGIN,
        &[
            account_slot as Word,
            mapping_id as Word,
            request_id as Word,
            epoch as Word,
        ],
    )
}

pub fn io_request_settle(account_slot: u32, mapping_id: u64, request_id: u64, epoch: u64) -> i64 {
    result_of(
        io_resource_labels::REQUEST_SETTLE,
        &[
            account_slot as Word,
            mapping_id as Word,
            request_id as Word,
            epoch as Word,
        ],
    )
}

pub fn supervision_status(slot: u32) -> (i64, u64) {
    pair_of(supervision_labels::STATUS, &[slot as Word])
}

pub fn supervision_derive(slot: u32) -> (i64, u64) {
    pair_of(supervision_labels::DERIVE, &[slot as Word])
}

/// Query this component's own live child-CSpace slot occupancy (C8.13.3).
///
/// Same shape as `shared_buffer_occupancy` above and for the same reason: the
/// CSpace counted is the badge's, so there is nothing to name.
pub fn capability_slot_occupancy() -> (i64, u64) {
    pair_of(capability_table_labels::OCCUPANCY, &[0])
}

pub fn cap_drop(slot: u32) -> i64 {
    if slot & TRANSFERRED_ENDPOINT_HANDLE_TAG != 0 {
        let transferred = slot & !TRANSFERRED_ENDPOINT_HANDLE_TAG;
        if !(TRANSFERRED_ENDPOINT_HANDLE_BASE..TRANSFERRED_ENDPOINT_HANDLE_LIMIT)
            .contains(&transferred)
        {
            return ERR_INVALID_ARG;
        }
        return with_thread_buffer(|ipc_buffer| {
            cap::CNode::from_bits(CHILD_CNODE_SLOT as u64)
                .absolute_cptr_from_bits_with_depth(
                    transferred as sel4::CPtrBits,
                    CHILD_CNODE_SIZE_BITS,
                )
                .with(&mut *ipc_buffer)
                .delete()
                .map(|()| ERR_SUCCESS)
                .map_err(|_| super::ERR_BAD_CAP)
        });
    }
    result_of(capability_table_labels::DROP, &[slot as Word])
}

pub fn directory_inspect(
    slot: u32,
    required_rights: u32,
    root: &mut [u8; DIRECTORY_ROOT_BYTES],
    scope: &mut [u8; MAX_DIRECTORY_PATH],
) -> i64 {
    let transfer = match reserve(DIRECTORY_ROOT_BYTES + MAX_DIRECTORY_PATH, 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    // The console endpoint, not the root's: directory inspect and commit are
    // served by the second dispatcher, which owns the namespace table (B45).
    let (result, returned) = match outcome(&call_on(
        console_service(),
        CONSOLE_LABEL_DIRECTORY_INSPECT,
        &[slot_pair(slot, required_rights) as Word, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    let scope_len = result as usize;
    if scope_len > MAX_DIRECTORY_PATH {
        return ERR_INVALID_ARG;
    }
    let mut frame = [0u8; DIRECTORY_ROOT_BYTES + MAX_DIRECTORY_PATH];
    match collect(returned, &mut frame, None) {
        Ok(len) if len == DIRECTORY_ROOT_BYTES + scope_len => {
            root.copy_from_slice(&frame[..DIRECTORY_ROOT_BYTES]);
            scope[..scope_len].copy_from_slice(&frame[DIRECTORY_ROOT_BYTES..len]);
            result
        }
        Ok(_) => ERR_INVALID_ARG,
        Err(error) => error,
    }
}

pub fn directory_derive(slot: u32, relative: &[u8], rights: u32) -> i64 {
    if relative.len() > MAX_DIRECTORY_PATH {
        return ERR_INVALID_ARG;
    }
    let transfer = match stage(relative, &[]) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (operands, used) = payload_operands(slot_pair(slot, rights), transfer, relative);
    result_of(directory_labels::DERIVE, &operands[..used])
}

/// CP2: ask the root which of this component's own slots holds `name`.
///
/// The name travels through the transfer window like every other variable-length
/// operand, and the reply is the slot. Bounded by `MAX_MSG` because a name
/// arrives in one request: a longer name is a different name, so it is refused
/// here rather than truncated into one that might resolve.
pub fn resolve_binding(name: &[u8]) -> i64 {
    if name.is_empty() || name.len() > MAX_MSG {
        return ERR_INVALID_ARG;
    }
    let transfer = match stage(name, &[]) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (operands, used) = payload_operands(0, transfer, name);
    result_of(capability_table_labels::RESOLVE_BINDING, &operands[..used])
}

/// Read this generation's declared fabric participant rows from `cursor`.
///
/// Answers into `out` and returns the row count, or a negative error. Refused
/// unless this component is the one the graph names as its fabric holder, and
/// refused identically when the generation embeds no graph -- so a component
/// that is not the holder cannot learn whether a graph exists.
///
/// Paged because one row is 128 bytes against the message bound; the caller
/// resumes from `cursor + count` until a call answers fewer rows than `out`
/// could hold.
pub fn graph_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::GRAPH_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read authenticated IO4 destination entries into the transfer window.
pub fn network_destinations_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::NETWORK_DESTINATIONS_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read authenticated IO11 interface rows into the transfer window.
pub fn network_interface_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::NETWORK_INTERFACE_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read authenticated entropy-authority rows into the transfer window.
pub fn entropy_authority_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::ENTROPY_AUTHORITY_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read authenticated Zenoh grants rows into the transfer window.
pub fn zenoh_grants_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::ZENOH_GRANTS_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read authenticated application rows into the transfer window.
pub fn network_application_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::NETWORK_APPLICATION_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read authenticated B83 per-ring block authority entries into the transfer
/// window. `network_destinations_read`'s exact shape, on this table's label.
pub fn block_ring_authority_read(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        capability_table_labels::BLOCK_RING_AUTHORITY_READ,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Read this component's own C9.2 declared wake sources (label 49).
///
/// `graph_read`'s exact shape, and paged for the same reason: one record is 64
/// bytes against the message bound, so the answer travels through the transfer
/// window and the caller resumes from `cursor + count`. Self-scoped — the
/// request names no waiter — so a component reads only its own sources, and a
/// generation that declares no wait-set resource is refused rather than
/// answered zero, which lets a caller tell "no table" from "none for me".
pub fn wait_sources(cursor: usize, out: &mut [u8]) -> i64 {
    let transfer = match reserve(out.len(), 0) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (result, returned) = match outcome(&call(
        lifecycle_labels::WAIT_SOURCES,
        &[cursor as Word, 0, transfer as Word],
    )) {
        Ok(pair) => pair,
        Err(error) => return error,
    };
    if result < 0 {
        return result;
    }
    match collect(returned, out, None) {
        Ok(_) => result,
        Err(error) => error,
    }
}

/// Resolve a route identity to the graph's index for it.
pub fn graph_route_index(identity: &[u8; 32]) -> i64 {
    let transfer = match stage(identity, &[]) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (operands, used) = payload_operands(0, transfer, identity);
    result_of(
        capability_table_labels::GRAPH_ROUTE_INDEX,
        &operands[..used],
    )
}

/// Read one scalar from the authenticated fabric-graph header.
pub fn graph_query(field: u32) -> i64 {
    result_of(capability_table_labels::GRAPH_QUERY, &[field as Word])
}

/// Ask the root which composition this generation declares (B70).
///
/// No operand and no transfer window: the answer is one scalar the root holds
/// for the whole generation, so this is the cheapest shape in the ABI. The
/// `BootAction` id crosses rather than the manifest's source spelling, which is
/// the same encoding the bootstrap thread's startup argument already carries.
pub fn boot_action() -> i64 {
    result_of(capability_table_labels::BOOT_ACTION, &[0])
}

/// Ask the root for this instance's declared live-child budget (B70).
///
/// No operand and no transfer window, the same shape as [`boot_action`]: the
/// answer is a scalar the root reads off the caller's own executable record,
/// and the badge is the only identity involved.
pub fn spawn_budget() -> i64 {
    result_of(capability_table_labels::SPAWN_BUDGET, &[0])
}

/// Grow this task's private memory by `delta` pages (C10.1/C10.2).
///
/// The same badge-scoped shape as [`spawn_budget`]: the region belongs to the
/// caller, so there is no slot or identity to name and no transfer window to
/// stage. The primary result is the page count *before* the growth and the
/// auxiliary is the window base, so a caller learns where its memory is
/// without a second call. `delta = 0` is a size query that allocates nothing.
pub fn private_memory_grow(delta: usize) -> (i64, u64) {
    pair_of(lifecycle_labels::PRIVATE_MEMORY_GROW, &[delta as Word])
}

pub fn monotonic_read() -> i64 {
    result_of(clock_labels::MONOTONIC_READ, &[])
}

pub fn monotonic_frequency() -> i64 {
    result_of(clock_labels::RATE_READ, &[])
}

pub fn timer_arm(delay: u64) -> i64 {
    result_of(clock_labels::TIMER_ARM, &[delay as Word])
}

pub fn timer_cancel(timer: u64) -> i64 {
    result_of(clock_labels::TIMER_CANCEL, &[timer as Word])
}

pub fn simulated_time_read() -> i64 {
    result_of(clock_labels::SIMULATED_READ, &[])
}

pub fn simulated_time_advance(delta: u64) -> i64 {
    result_of(clock_labels::SIMULATED_ADVANCE, &[delta as Word])
}

/// C9.3's self-scoped class read. Zero operands: the instance is the badge's,
/// so there is nothing to name. Primary is the class id, auxiliary the priority.
pub fn scheduling_class_read() -> (i64, u64) {
    pair_of(scheduling_labels::CLASS_READ, &[])
}

/// C9.3's promotion. `slot` is a supervision capability naming the subject, so
/// no task identity crosses the wire (B42).
pub fn scheduling_class_promote(slot: u32, class_id: u32) -> (i64, u64) {
    pair_of(
        scheduling_labels::CLASS_PROMOTE,
        &[slot as Word, class_id as Word],
    )
}

/// C9.4's self-scoped state read. Zero operands: the instance is the badge's.
/// Primary is the state id; auxiliary packs the remaining restart attempts low
/// and the predecessor's terminal cause high.
pub fn lifecycle_state_read() -> (i64, u64) {
    pair_of(lifecycle_labels::STATE_READ, &[])
}

/// C9.4's self-scoped state advance. One operand, and it is the *target state* —
/// there is no subject, because advancing another component's state is authority
/// no C9.4 field grants.
pub fn lifecycle_state_advance(state_id: u32) -> i64 {
    result_of(lifecycle_labels::STATE_ADVANCE, &[state_id as Word])
}

/// C9.4's restart admission. `slot` is a supervision capability naming the dead
/// subject, so no task identity crosses the wire (B42). Primary is the attempts
/// remaining; auxiliary is the instant the restart may proceed.
pub fn lifecycle_restart_admit(slot: u32) -> (i64, u64) {
    pair_of(supervision_labels::RESTART_ADMIT, &[slot as Word])
}

/// C9.4's parameter read. `slot` names the subject through a supervision
/// capability; `key` is the parameter key.
pub fn lifecycle_parameter_read(slot: u32, key: u64) -> i64 {
    result_of(
        supervision_labels::PARAMETER_READ,
        &[slot as Word, key as Word],
    )
}

/// C9.4's parameter write, answering the previous value.
pub fn lifecycle_parameter_write(slot: u32, key: u64, value: u64) -> i64 {
    result_of(
        supervision_labels::PARAMETER_WRITE,
        &[slot as Word, key as Word, value as Word],
    )
}
/// C9.5's self-scoped recording participation. No operand: the caller is the
/// badge, and naming another instance's participation is authority no C9.5 field
/// grants. Primary is the role; auxiliary packs the record capacity low and the
/// deterministic flag in bit 32.
pub fn recording_sources() -> (i64, u64) {
    pair_of(lifecycle_labels::RECORDING_SOURCES, &[])
}

/// The caller's own declared lifetime, self-scoped by badge with no operand.
pub fn lifetime_read() -> i64 {
    pair_of(lifecycle_labels::LIFETIME_READ, &[]).0
}

pub fn directory_commit(slot: u32, expected: &[u8; 32], new: &[u8; 32]) -> i64 {
    let mut frame = [0u8; 64];
    frame[..32].copy_from_slice(expected);
    frame[32..].copy_from_slice(new);
    let transfer = match stage(&frame, &[]) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    match outcome(&call_on(
        console_service(),
        CONSOLE_LABEL_DIRECTORY_COMMIT,
        &[slot as Word, transfer as Word],
    )) {
        Ok((result, _)) => result,
        Err(error) => error,
    }
}

pub fn input_read(slot: u32) -> (i64, u64) {
    // A Call on the console endpoint, not the root's: input and console
    // output are both "the terminal" and share one dispatcher, distinguished
    // by label (B41). The console capability carries reply authority for
    // exactly this.
    let info = MessageInfoBuilder::default()
        .label(CONSOLE_LABEL_INPUT_READ)
        .length(1)
        .build();
    let mut mrs = [0 as Word; wire::FAST_REGISTERS];
    mrs[0] = slot as Word;
    let reply = if uses_ambient_buffer() {
        console_service().call_with_mrs(info, mrs)
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        console_service()
            .with(unsafe { thread_context() })
            .call_with_mrs(info, mrs)
    };
    match outcome(&reply) {
        Ok(pair) => pair,
        Err(error) => (error, 0),
    }
}

pub fn unhealthy() -> ! {
    let _ = call(lifecycle_labels::UNHEALTHY, &[]);
    // Exit after recording the unhealthy transition so this diverging API
    // cannot leave the component running if the lifecycle reply returns.
    exit(1)
}

/// Emit diagnostics without relying on the transfer window. Startup and
/// staging failures use this path because every chunk fits in MR2/MR3.
pub(crate) fn early_debug_write(bytes: &[u8]) {
    for chunk in bytes.chunks(wire::INLINE_BYTES) {
        let transfer = descriptor(chunk.len(), 0, FORM_INLINE, crate::runtime::thread_index());
        let (operands, used) = payload_operands(0, transfer, chunk);
        // Inline chunks on the console endpoint, same as `debug_write`: this
        // path exists for output before a transfer window is bound, so it
        // never stages through one.
        let info = MessageInfoBuilder::default()
            .label(CONSOLE_LABEL_WRITE as Word)
            .length(used)
            .build();
        let mut mrs = [0 as Word; wire::FAST_REGISTERS];
        mrs[..used].copy_from_slice(&operands[..used]);
        if uses_ambient_buffer() {
            console_service().send_with_mrs(info, mrs);
        } else {
            // SAFETY: this thread's own buffer, borrowed for one invocation.
            console_service()
                .with(unsafe { thread_context() })
                .send_with_mrs(info, mrs);
        }
    }
}

/// Write one diagnostic record through the console dispatcher.
///
/// Each call submits one bounded payload to the console dispatcher. Callers must
/// assemble a complete record before submission; fragments are not joined. The
/// root and console dispatcher share record serialization on the qualified
/// single-core non-MCS path. An accepted record is therefore printed
/// contiguously, and an invalid or oversized one is refused whole. Send
/// completion does not acknowledge emission.
///
/// The payload travels through this thread's bound transfer window. Every
/// launched component binds one before it runs, and a task that has not is not
/// yet in a state where its output would be attributable.
pub fn debug_write(bytes: &[u8]) -> i64 {
    let transfer = match stage(bytes, &[]) {
        Ok(transfer) => transfer,
        Err(error) => return error,
    };
    let (operands, used) = payload_operands(0, transfer, bytes);
    // One-way, on the console endpoint rather than the root's: the console has
    // nothing to say back, and a reply would put a round trip on every debug
    // line. The dispatcher thread on the other side is what makes a blocking
    // send safe here.
    let info = MessageInfoBuilder::default()
        .label(CONSOLE_LABEL_WRITE as Word)
        .length(used)
        .build();
    let mut mrs = [0 as Word; wire::FAST_REGISTERS];
    mrs[..used].copy_from_slice(&operands[..used]);
    if uses_ambient_buffer() {
        console_service().send_with_mrs(info, mrs);
    } else {
        // SAFETY: this thread's own buffer, borrowed for one invocation.
        console_service()
            .with(unsafe { thread_context() })
            .send_with_mrs(info, mrs);
    }
    bytes.len() as i64
}
