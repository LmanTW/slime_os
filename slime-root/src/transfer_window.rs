//! Per-thread transfer windows: bounded regions oversized payloads cross in.
//!
//! The seL4 fast path carries four message registers. A Slime operation whose
//! payload does not fit them stages it in a page both ends can address instead
//! of growing the message. Each component thread owns one such page.
//!
//! `slime-root/src/child_vspace.rs` maps one granule per thread directly above
//! that thread's IPC buffer and keeps an alias capability in root CSpace. The
//! transfer descriptor carries the hardware thread index; the authenticated
//! process badge plus that index selects the root-created `(task, thread)`
//! entry.
//!
//! The child never declares or reallocates this mapping. That matters twice:
//! a component with no `SharedBufferFactory` still has a staging region, and
//! the root never trusts a child-supplied address because it maps the exact
//! frame it created for that process and thread.
//!
//! Thread identity here is routing metadata, not authority. The badge chooses
//! the process; a forged or out-of-range thread index names no window and the
//! request is refused.

use crate::ipc::IpcError;
use crate::task::TaskId;

/// Bytes of one transfer window. One granule, matching both the frame the
/// loader maps and `slime_rt`'s `MIN_TRANSFER_WINDOW`; the two are the same
/// agreement seen from either end.
pub const WINDOW_BYTES: usize = crate::child_vspace::GRANULE_SIZE;

/// Retired startup-bind slot, retained only by host regressions proving a
/// child-supplied base could never select a different mapping.
#[cfg(test)]
pub const STARTUP_WINDOW_SLOT: u32 = 0;

/// One thread's declared window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    pub task: TaskId,
    pub thread: usize,
    /// Child virtual address of the window, as the loader mapped it.
    pub base: usize,
    pub len: usize,
    /// Root-held capability for the frame backing it. The root stages through
    /// this, never through `base`, which is only meaningful in the child.
    pub frame: sel4::cap::Granule,
    /// A second capability to the same frame, for the root's own transient
    /// mapping at the scratch address.
    ///
    /// A frame capability records exactly one mapping, and `frame`'s is the
    /// child's — live for as long as the child is. Staging therefore cannot go
    /// through `frame` without first tearing down the mapping the child is
    /// using, so the copy is made once at construction and mapped and unmapped
    /// around each staged transfer instead.
    ///
    /// It is a copy of the same authority, not a widening: the frame is one the
    /// root allocated and mapped for this child, and the alias never leaves the
    /// root's CSpace.
    pub alias: sel4::cap::Granule,
}

/// Windows the root mapped for admitted component threads.
///
/// Entries are usable immediately because their addresses and capabilities
/// come from root-side VSpace construction, not a child declaration.
pub struct WindowTable<const CAPACITY: usize> {
    entries: [Option<(Window, bool)>; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> WindowTable<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Record the window the loader mapped for `task` and `thread`. Called
    /// during task construction, before the task runs.
    ///
    /// `alias` is a second capability to the same frame; see [`Window::alias`]
    /// for why staging needs one. A declaration is immediately usable: the
    /// address is not accepted from a child syscall, but comes from the VSpace
    /// mapping the root itself just constructed (B46).
    pub fn declare(
        &mut self,
        task: TaskId,
        thread: usize,
        base: usize,
        frame: sel4::cap::Granule,
        alias: sel4::cap::Granule,
    ) -> Result<(), IpcError> {
        // Keyed by task and thread. Two declarations for the same thread are
        // the conflict; different threads deliberately have distinct windows.
        if self
            .entries
            .iter()
            .flatten()
            .any(|(w, _)| w.task == task && w.thread == thread)
        {
            return Err(IpcError::WaiterConflict);
        }
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return Err(IpcError::DestinationSlotsExhausted);
        };
        *slot = Some((
            Window {
                task,
                thread,
                base,
                len: WINDOW_BYTES,
                frame,
                alias,
            },
            true,
        ));
        self.len += 1;
        Ok(())
    }

    /// The window `task`'s descriptor names, if that thread was declared.
    ///
    /// Thread identity is not trusted as authority: the badge authenticates
    /// `task`, and this index only chooses among that task's root-created
    /// windows. An out-of-range or undeclared index resolves to none.
    pub fn bound(&self, task: TaskId, thread: usize) -> Option<Window> {
        self.entries
            .iter()
            .flatten()
            .find(|(w, bound)| *bound && w.task == task && w.thread == thread)
            .map(|(window, _)| *window)
    }

    /// Drop every window owned by a task as part of reclaiming it. The frames
    /// themselves are released by the task cleanup record.
    pub fn release(&mut self, task: TaskId) -> bool {
        // Every window the task declared, not just the first: a multi-threaded
        // process has one per thread, and leaving the others behind would keep
        // the table's count above the entries actually in use (B47).
        let mut released = 0;
        for entry in self.entries.iter_mut() {
            if entry.is_some_and(|(w, _)| w.task == task) {
                *entry = None;
                released += 1;
            }
        }
        self.len -= released;
        released > 0
    }
}

#[cfg(test)]
impl<const CAPACITY: usize> WindowTable<CAPACITY> {
    /// Retained only for host-side regression checks of the retired startup
    /// bind contract. Product code declares windows from root-owned mappings
    /// and never accepts a child-supplied base (B46).
    pub fn bind(
        &mut self,
        task: TaskId,
        slot: u32,
        base: usize,
        len: usize,
    ) -> Result<Window, IpcError> {
        if slot != STARTUP_WINDOW_SLOT {
            return Err(IpcError::InvalidOperation);
        }
        if !self.entries.iter().flatten().any(|(w, _)| w.task == task) {
            return Err(IpcError::InvalidOperation);
        }
        let Some((window, bound)) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|(w, _)| w.task == task && w.base == base)
        else {
            return Err(IpcError::InvalidLength);
        };
        if window.len != len {
            return Err(IpcError::InvalidLength);
        }
        if !*bound {
            *bound = true;
        }
        Ok(*window)
    }
}

impl<const CAPACITY: usize> Default for WindowTable<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

// ---- transfer descriptors ----
//
// The calling convention is generated once from
// `contracts/component-runtime-abi/v1/schema.zt` for the root, Rust runtime,
// and non-Rust runtimes.

pub use boot_contracts::component_runtime_abi::{
    DESCRIPTOR_FORM_INLINE as FORM_INLINE, DESCRIPTOR_FORM_WINDOW as FORM_WINDOW,
};

const LENGTH_MASK: u64 = (1 << boot_contracts::component_runtime_abi::DESCRIPTOR_LENGTH_BITS) - 1;
const CAPS_MASK: u64 = (1 << boot_contracts::component_runtime_abi::DESCRIPTOR_CAPS_BITS) - 1;
const FORM_MASK: u64 = (1 << boot_contracts::component_runtime_abi::DESCRIPTOR_FORM_BITS) - 1;

/// Builds the transfer descriptor: length, capability count, carrier, and
/// sending thread index.
pub const fn descriptor(len: usize, caps: usize, form: u64, thread: usize) -> u64 {
    (len as u64)
        | ((caps as u64) << boot_contracts::component_runtime_abi::DESCRIPTOR_CAPS_SHIFT)
        | (form << boot_contracts::component_runtime_abi::DESCRIPTOR_FORM_SHIFT)
        | ((thread as u64) << boot_contracts::component_runtime_abi::DESCRIPTOR_THREAD_SHIFT)
}

pub const fn descriptor_len(descriptor: u64) -> usize {
    ((descriptor >> boot_contracts::component_runtime_abi::DESCRIPTOR_LENGTH_SHIFT) & LENGTH_MASK)
        as usize
}

pub const fn descriptor_caps(descriptor: u64) -> usize {
    ((descriptor >> boot_contracts::component_runtime_abi::DESCRIPTOR_CAPS_SHIFT) & CAPS_MASK)
        as usize
}

pub const fn descriptor_form(descriptor: u64) -> u64 {
    (descriptor >> boot_contracts::component_runtime_abi::DESCRIPTOR_FORM_SHIFT) & FORM_MASK
}

pub const fn descriptor_thread(descriptor: u64) -> usize {
    (descriptor >> boot_contracts::component_runtime_abi::DESCRIPTOR_THREAD_SHIFT) as usize
}

/// Byte offset of the capability vector in a frame whose payload is `len`
/// bytes. Word-aligned so neither side takes an unaligned access.
pub const fn frame_caps_offset(len: usize) -> usize {
    len.next_multiple_of(8)
}

/// Total frame bytes for `len` payload bytes and `caps` capability slots.
pub const fn frame_len(len: usize, caps: usize) -> usize {
    frame_caps_offset(len) + caps * 8
}

// ---- staging through a window ----
//
// The root reads and writes a child's window through its own frame capability
// at the scratch address, never through the child's `base`: `base` is only
// meaningful inside that child's VSpace, and trusting it would let a task point
// the root at memory it does not own. The frame is mapped for the duration of
// one copy and unmapped after, so the root holds no standing alias of a region
// a child can write.

/// Payload bytes one staged frame may carry. The logical message bound, which
/// is what every windowed operation actually stages.
pub const MAX_STAGED_BYTES: usize = crate::ipc::MAX_MESSAGE_BYTES;

/// Capability slots one staged frame may carry.
pub const MAX_STAGED_CAPS: usize = crate::ipc::MAX_MESSAGE_CAPS;

/// Payload bytes one staged **array** may carry (B15).
///
/// A second, wider bound beside [`MAX_STAGED_BYTES`], for the one operation
/// whose payload is not a message: a spawn's grant array. The two are separate
/// numbers because they bound different things, and collapsing them would be
/// wrong in both directions.
///
/// [`MAX_STAGED_BYTES`] is `ipc::MAX_MESSAGE_BYTES` because a `send` payload
/// becomes an [`ipc::Message`](crate::ipc::Message), which is that many bytes
/// wide by construction. Raising it would not let a longer message through; it
/// would only move the refusal from the window reader to `Message::new`.
///
/// A grant array becomes no message at all. It is decoded into a
/// [`SpawnPlan`](crate::main) and discarded, so the only real constraints are
/// the window it crosses and the plan array it fills. The retired kernel reads
/// the same array straight out of caller memory bounded by
/// `kernel/src/capability/mod.rs::MAX_CAPS` (64), and
/// `sel4_transport::spawn` already stages up to `64 * 16` bytes without
/// complaint — the 64-byte refusal was entirely this side.
///
/// 1024 is that same 64 records at `SPAWN_GRANT_RECORD_BYTES`, which restores
/// parity with the oracle rather than picking a new number. It is a quarter of
/// [`WINDOW_BYTES`], so a staged array cannot approach the window's own bound.
pub const MAX_STAGED_ARRAY_BYTES: usize = 1024;

// The wide frame must fit the window it is read out of, with room for the
// capability vector `frame_len` word-aligns after it. A bound larger than the
// window would be refused at every call rather than at this line.
const _: () = assert!(MAX_STAGED_ARRAY_BYTES < WINDOW_BYTES);
const _: () = assert!(MAX_STAGED_ARRAY_BYTES > MAX_STAGED_BYTES);

/// One frame read out of, or to be written into, a task's transfer window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedFrame {
    bytes: [u8; MAX_STAGED_BYTES],
    len: usize,
    caps: [u64; MAX_STAGED_CAPS],
    cap_count: usize,
}

impl StagedFrame {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_STAGED_BYTES],
            len: 0,
            caps: [0; MAX_STAGED_CAPS],
            cap_count: 0,
        }
    }

    /// A frame carrying `bytes` and no capabilities.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IpcError> {
        let mut frame = Self::empty();
        let destination = frame
            .bytes
            .get_mut(..bytes.len())
            .ok_or(IpcError::InvalidLength)?;
        destination.copy_from_slice(bytes);
        frame.len = bytes.len();
        Ok(frame)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn caps(&self) -> &[u64] {
        &self.caps[..self.cap_count]
    }

    /// The capability slots this frame names, as logical slot numbers.
    ///
    /// The wire carries them as `u64` because the window is word-addressed, but
    /// a logical slot is a `u32` — the same width every operation's slot
    /// argument takes. A value that does not fit is refused rather than
    /// truncated: truncating would turn a nonsense slot into a plausible one
    /// and resolve it against the sender's table.
    pub fn cap_slots(&self) -> Result<[u32; MAX_STAGED_CAPS], IpcError> {
        let mut slots = [0u32; MAX_STAGED_CAPS];
        for (destination, source) in slots.iter_mut().zip(self.caps()) {
            *destination = u32::try_from(*source).map_err(|_| IpcError::InvalidOperation)?;
        }
        Ok(slots)
    }

    /// A frame carrying `bytes` and the capability slots `caps` names.
    pub fn from_parts(bytes: &[u8], caps: &[u32]) -> Result<Self, IpcError> {
        let mut frame = Self::from_bytes(bytes)?;
        let destination = frame
            .caps
            .get_mut(..caps.len())
            .ok_or(IpcError::InvalidLength)?;
        for (slot, value) in destination.iter_mut().zip(caps) {
            *slot = u64::from(*value);
        }
        frame.cap_count = caps.len();
        Ok(frame)
    }

    pub const fn cap_count(&self) -> usize {
        self.cap_count
    }
}

/// Read the frame a caller staged, whether it rode inline or through the
/// window.
///
/// `words` are the fast message registers as received: `words[1]` is the
/// transfer descriptor and `words[2..]` the inline payload. An inline frame
/// needs no window at all, which is what lets a short `send` work before a task
/// has bound one.
pub fn read_staged(
    window: Option<Window>,
    transfer: u64,
    words: &[sel4::Word],
    scratch: &crate::child_vspace::ScratchPage,
) -> Result<StagedFrame, IpcError> {
    let len = descriptor_len(transfer);
    let caps = descriptor_caps(transfer);
    if len > MAX_STAGED_BYTES || caps > MAX_STAGED_CAPS {
        return Err(IpcError::InvalidLength);
    }
    let mut frame = StagedFrame::empty();
    frame.len = len;
    frame.cap_count = caps;
    if descriptor_form(transfer) == FORM_INLINE {
        // The two payload registers, little-endian, exactly as `pack_bytes`
        // wrote them. A descriptor claiming more bytes than they hold is
        // refused rather than read past.
        if caps != 0 || len > INLINE_BYTES {
            return Err(IpcError::InvalidLength);
        }
        let mut inline = [0u8; INLINE_BYTES];
        for (index, word) in words.iter().skip(2).take(2).enumerate() {
            inline[index * 8..][..8].copy_from_slice(&word.to_le_bytes());
        }
        frame.bytes[..len].copy_from_slice(&inline[..len]);
        return Ok(frame);
    }
    let window = window.ok_or(IpcError::InvalidLength)?;
    if frame_len(len, caps) > window.len {
        return Err(IpcError::InvalidLength);
    }
    with_window_mapped(window, scratch, |base| {
        // SAFETY: `base` is the scratch address, where `window.frame` is mapped
        // read-write for the duration of this closure and aliased by no live
        // Rust reference. `frame_len(len, caps)` was bounded by `window.len`
        // above, and the window is one granule, so every read is in bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(base, frame.bytes.as_mut_ptr(), len);
            let slots = base.add(frame_caps_offset(len)).cast::<u64>();
            for (index, slot) in frame.caps.iter_mut().take(caps).enumerate() {
                *slot = slots.add(index).read();
            }
        }
    })?;
    Ok(frame)
}

/// One wide byte array read out of a task's transfer window (B15).
///
/// Deliberately not a [`StagedFrame`]: it carries no capability vector at all.
/// The one operation that stages an array — a spawn's grant list — encodes
/// *logical slot numbers* in its payload, and `serve_spawn` already refuses a
/// spawn carrying real capabilities. Giving this type a cap vector it would
/// only ever refuse would make the wide path look like a widening of what may
/// cross a window, which it is not: exactly the same kinds of thing cross, one
/// operation may carry more bytes of them.
pub struct StagedArray {
    bytes: [u8; MAX_STAGED_ARRAY_BYTES],
    len: usize,
}

impl StagedArray {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Read a wide byte array a caller staged (B15).
///
/// [`read_staged`]'s shape, with three differences, each of which is why this
/// is a second function rather than a parameter on the first:
///
/// - the byte bound is [`MAX_STAGED_ARRAY_BYTES`], not the message bound;
/// - a descriptor naming any capability is refused here rather than accepted
///   and refused by the caller, so the wide path never parks a capability;
/// - the inline form is still honored, because a short grant list rides the
///   fast registers exactly as it does today and must not start requiring a
///   bound window.
///
/// The returned array is heap-free and lives in the caller's frame. At 1 KiB
/// against the root task's 1 MiB stack that is comfortable, but it is the
/// reason the bound is stated rather than raised to the window's own size —
/// backlog B3 records what an oversized stack temporary costs here.
pub fn read_staged_array(
    window: Option<Window>,
    transfer: u64,
    words: &[sel4::Word],
    scratch: &crate::child_vspace::ScratchPage,
) -> Result<StagedArray, IpcError> {
    read_staged_array_in(window, transfer, words, scratch, None)
}

/// Write a reply larger than one message into a caller's window (P5.4.2c).
///
/// [`write_staged`] carries a [`StagedFrame`], whose bound is
/// [`MAX_STAGED_BYTES`] — the *message* bound. A block reply is a 64-byte
/// record plus a 512-byte sector, and a sector is not a message: it crosses no
/// channel and is bounded by the window it is written into. This is the same
/// write path with the window as the only ceiling, mirroring
/// [`read_staged_array`] on the read side.
///
/// Returns the descriptor the caller's `collect` reads the region back at.
pub fn write_staged_region(
    window: Option<Window>,
    bytes: &[u8],
    scratch: &crate::child_vspace::ScratchPage,
) -> Result<u64, IpcError> {
    write_staged_region_in(window, bytes, scratch, None)
}

/// [`write_staged_region`] naming the console thread's own IPC buffer (B43).
pub fn write_staged_region_with(
    window: Option<Window>,
    bytes: &[u8],
    scratch: &crate::child_vspace::ScratchPage,
    buffer: &mut sel4::IpcBuffer,
) -> Result<u64, IpcError> {
    write_staged_region_in(window, bytes, scratch, Some(buffer))
}

fn write_staged_region_in(
    window: Option<Window>,
    bytes: &[u8],
    scratch: &crate::child_vspace::ScratchPage,
    buffer: Option<&mut sel4::IpcBuffer>,
) -> Result<u64, IpcError> {
    if bytes.len() > MAX_STAGED_ARRAY_BYTES {
        return Err(IpcError::InvalidLength);
    }
    let window = window.ok_or(IpcError::InvalidLength)?;
    if frame_len(bytes.len(), 0) > window.len {
        return Err(IpcError::InvalidLength);
    }
    with_window_mapped_in(window, scratch, buffer, |base| {
        // SAFETY: `base` is the scratch address, where `window.frame` is mapped
        // read-write for the duration of this closure and aliased by no live
        // Rust reference. The length was bounded by `window.len` above.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), base, bytes.len());
        }
    })?;
    Ok(descriptor(bytes.len(), 0, FORM_WINDOW, window.thread))
}
/// Write a reply frame into a caller's selected window.
pub fn write_staged(
    window: Option<Window>,
    frame: &StagedFrame,
    scratch: &crate::child_vspace::ScratchPage,
) -> Result<(), IpcError> {
    let window = window.ok_or(IpcError::InvalidLength)?;
    if frame_len(frame.len, frame.cap_count) > window.len {
        return Err(IpcError::InvalidLength);
    }
    with_window_mapped(window, scratch, |base| {
        // SAFETY: as for `read_staged` — the same mapping, bounded by the same
        // `window.len` check, for the duration of this closure.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.bytes.as_ptr(), base, frame.len);
            let slots = base.add(frame_caps_offset(frame.len)).cast::<u64>();
            for (index, slot) in frame.caps.iter().take(frame.cap_count).enumerate() {
                slots.add(index).write(*slot);
            }
        }
    })
}

/// Map `window`'s frame at the scratch address, run `body`, and unmap.
///
/// Through the window's *alias* capability, never through `frame`. A frame
/// capability records exactly one mapping — the same constraint the shared
/// buffer phase already works around by unmapping before it reads — and
/// `frame` is spent on the child's own mapping, which is live for as long as
/// the child is. Mapping through it here would silently fail and leave the root
/// reading an unmapped scratch address, which faults the root task.
///
/// The alias is unmapped again on both paths: a standing root mapping of a page
/// a child can write is an alias the root does not need, and it would break the
/// next caller that needs the scratch address.
/// [`read_staged_array`] against an explicit IPC buffer.
///
/// The console dispatcher (B41) runs on a second root thread and names its own
/// buffer rather than the crate's ambient slot, which a blocked receive holds
/// borrowed. Mapping the caller's frame is a capability invocation, so it
/// needs the same treatment.
pub fn read_staged_array_with(
    window: Option<Window>,
    transfer: u64,
    words: &[sel4::Word],
    scratch: &crate::child_vspace::ScratchPage,
    buffer: &mut sel4::IpcBuffer,
) -> Result<StagedArray, IpcError> {
    read_staged_array_in(window, transfer, words, scratch, Some(buffer))
}

fn read_staged_array_in(
    window: Option<Window>,
    transfer: u64,
    words: &[sel4::Word],
    scratch: &crate::child_vspace::ScratchPage,
    buffer: Option<&mut sel4::IpcBuffer>,
) -> Result<StagedArray, IpcError> {
    let len = descriptor_len(transfer);
    if len > MAX_STAGED_ARRAY_BYTES || descriptor_caps(transfer) != 0 {
        return Err(IpcError::InvalidLength);
    }
    let mut array = StagedArray {
        bytes: [0; MAX_STAGED_ARRAY_BYTES],
        len,
    };
    if descriptor_form(transfer) == FORM_INLINE {
        // Inline payloads ride the fast registers the receive already copied
        // out, so nothing is invoked and no buffer is needed.
        let inline = read_staged(window, transfer, words, scratch)?;
        array.bytes[..len].copy_from_slice(inline.bytes());
        return Ok(array);
    }
    let window = window.ok_or(IpcError::InvalidLength)?;
    if frame_len(len, 0) > window.len {
        return Err(IpcError::InvalidLength);
    }
    with_window_mapped_in(window, scratch, buffer, |base| {
        // SAFETY: `base` is the scratch address, where `window.frame` is
        // mapped read-write for the duration of this closure and aliased by no
        // live Rust reference. `len` was bounded by `window.len` above, and
        // the window is one granule.
        unsafe {
            core::ptr::copy_nonoverlapping(base, array.bytes.as_mut_ptr(), len);
        }
    })?;
    Ok(array)
}

fn with_window_mapped(
    window: Window,
    scratch: &crate::child_vspace::ScratchPage,
    body: impl FnOnce(*mut u8),
) -> Result<(), IpcError> {
    with_window_mapped_in(window, scratch, None, body)
}

/// Map a caller's window at `scratch`, run `body` over it, and unmap.
///
/// `buffer` names the IPC buffer the two `frame_map`/`frame_unmap`
/// invocations use. The main dispatcher passes `None` and gets the crate's
/// ambient slot; the console thread passes its own, because there is one
/// ambient slot per address space and a blocked receive holds it borrowed —
/// so a second thread reaching for it deadlocks on the borrow rather than on
/// the endpoint (B41, B43).
fn with_window_mapped_in(
    window: Window,
    scratch: &crate::child_vspace::ScratchPage,
    buffer: Option<&mut sel4::IpcBuffer>,
    body: impl FnOnce(*mut u8),
) -> Result<(), IpcError> {
    let vspace = sel4::init_thread::slot::VSPACE.cap();
    let rights = sel4::CapRights::read_write();
    let attributes = crate::vm_attributes::data();
    match buffer {
        Some(buffer) => {
            window
                .alias
                .with(&mut *buffer)
                .frame_map(vspace, scratch.addr(), rights, attributes)
                .map_err(|_| IpcError::TransferFailed)?;
            body(scratch.addr() as *mut u8);
            window
                .alias
                .with(buffer)
                .frame_unmap()
                .map_err(|_| IpcError::TransferFailed)
        }
        None => {
            window
                .alias
                .frame_map(vspace, scratch.addr(), rights, attributes)
                .map_err(|_| IpcError::TransferFailed)?;
            body(scratch.addr() as *mut u8);
            window
                .alias
                .frame_unmap()
                .map_err(|_| IpcError::TransferFailed)
        }
    }
}

/// Payload bytes the two inline registers carry. Mirrors
/// `components/runtime/src/syscall/wire.rs::INLINE_BYTES`.
pub const INLINE_BYTES: usize = 16;

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    #[test]
    fn a_descriptor_round_trips_its_three_fields() {
        let value = descriptor(64, 4, FORM_WINDOW, 1);
        assert_eq!(descriptor_len(value), 64);
        assert_eq!(descriptor_caps(value), 4);
        assert_eq!(descriptor_form(value), FORM_WINDOW);
        assert_eq!(descriptor_thread(value), 1);
    }

    #[test]
    fn capability_slots_follow_the_payload_word_aligned() {
        // A 64-byte payload is already aligned; a 5-byte one is padded to 8, so
        // the reader never takes an unaligned load of a slot.
        assert_eq!(frame_caps_offset(64), 64);
        assert_eq!(frame_caps_offset(5), 8);
        assert_eq!(frame_len(64, 4), 96);
        assert_eq!(frame_len(0, 0), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::{STARTUP_WINDOW_SLOT, WINDOW_BYTES, WindowTable};
    use crate::ipc::IpcError;
    use crate::task::TaskId;

    const BASE: usize = 0x21_0000;

    fn frame() -> sel4::cap::Granule {
        sel4::cap::Granule::from_bits(7)
    }

    /// The root-side alias of the same frame. A distinct CPtr, because it is a
    /// distinct capability: one mapping each.
    fn alias() -> sel4::cap::Granule {
        sel4::cap::Granule::from_bits(8)
    }

    fn table() -> WindowTable<4> {
        let mut table = WindowTable::new();
        table.declare(TaskId(0), 0, BASE, frame(), alias()).unwrap();
        table
    }

    #[test]
    fn a_declared_window_is_immediately_usable() {
        let mut table = table();
        let window = table.bound(TaskId(0), 0).unwrap();
        assert_eq!(window.base, BASE);
        assert_eq!(
            table.bind(TaskId(0), STARTUP_WINDOW_SLOT, BASE, WINDOW_BYTES),
            Ok(window),
            "the retired bind declaration cannot change root-owned geometry"
        );
    }

    #[test]
    fn a_window_the_loader_never_mapped_is_refused() {
        let mut table = table();
        assert_eq!(
            table.bind(TaskId(0), STARTUP_WINDOW_SLOT, BASE + 0x1000, WINDOW_BYTES),
            Err(IpcError::InvalidLength),
            "a task cannot name a region it was not given"
        );
        assert_eq!(
            table.bind(TaskId(0), STARTUP_WINDOW_SLOT, BASE, WINDOW_BYTES * 2),
            Err(IpcError::InvalidLength),
            "nor claim more of it than was mapped"
        );
        assert!(table.bound(TaskId(0), 0).is_some());
    }

    #[test]
    fn a_task_with_no_declared_window_cannot_bind_one() {
        let mut table = table();
        assert_eq!(
            table.bind(TaskId(1), STARTUP_WINDOW_SLOT, BASE, WINDOW_BYTES),
            Err(IpcError::InvalidOperation)
        );
    }

    #[test]
    fn only_the_startup_slot_names_the_root_mapped_window() {
        let mut table = table();
        assert_eq!(
            table.bind(TaskId(0), STARTUP_WINDOW_SLOT + 1, BASE, WINDOW_BYTES),
            Err(IpcError::InvalidOperation)
        );
    }

    #[test]
    fn windows_are_per_task_and_released_on_reclaim() {
        let mut table = table();
        table
            .declare(TaskId(1), 0, BASE + 0x8000, frame(), alias())
            .unwrap();
        assert_eq!(table.len(), 2);
        // One task's binding says nothing about another's.
        assert_eq!(table.bound(TaskId(0), 0), Some(table.entries[0].unwrap().0));
        assert!(table.bound(TaskId(1), 0).is_some());

        assert!(table.release(TaskId(1)));
        assert_eq!(table.bound(TaskId(1), 0), None);
        assert_eq!(table.len(), 1);
        assert!(
            !table.release(TaskId(1)),
            "releasing twice is not a release"
        );
    }

    #[test]
    fn a_task_cannot_declare_two_windows_at_one_base() {
        let mut table = table();
        assert_eq!(
            table.declare(TaskId(0), 0, BASE, frame(), alias()),
            Err(IpcError::WaiterConflict),
            "the fixture already declared this task's window at BASE"
        );
    }

    #[test]
    fn a_multi_threaded_task_declares_one_window_per_thread() {
        let mut table = table();
        table
            .declare(TaskId(0), 1, BASE + 0x8000, frame(), alias())
            .expect("a second thread's window is not a conflict");
        assert_eq!(table.bound(TaskId(0), 0).unwrap().base, BASE);
        assert_eq!(table.bound(TaskId(0), 1).unwrap().base, BASE + 0x8000);

        // Releasing the task takes every thread's window with it, and the
        // table's count drops by both.
        let before = table.len();
        assert!(table.release(TaskId(0)));
        assert_eq!(before - table.len(), 2, "both windows were forgotten");
        assert_eq!(table.bound(TaskId(0), 0), None);
    }
}
