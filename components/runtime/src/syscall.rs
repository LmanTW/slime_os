//! Narrow Slime service APIs exposed to components.
//!
//! Each root-served mechanism owns its message labels. [`sel4_transport`]
//! carries those labels over the badged root endpoint in child CSpace slot 1;
//! native endpoints and notifications remain direct seL4 capabilities.

use sel4_transport as transport;

mod sel4_transport;
mod wire;

pub use sel4_transport::ROOT_SERVICE_SLOT;

/// Record the root-mapped startup transfer window locally. The root created
/// and authenticated this mapping while constructing the thread, so no syscall
/// is needed to re-declare it.
pub(crate) fn bind_startup_window(base: usize) -> i64 {
    sel4_transport::bind_startup_window(base)
}

pub(crate) fn early_debug_write(bytes: &[u8]) {
    sel4_transport::early_debug_write(bytes)
}
// B59: the operation labels, status codes, and message bounds are generated
// from `contracts/syscall-abi/v1/schema.zt`. `slime-root` consumes the same
// module, so a renumbering cannot desync the two crates -- which it has done
// before, silently garbling keystrokes (see `slime-root/src/console.rs`).
/// C9.5's role vocabulary, decoded from the same contract the resource is
/// encoded against rather than restated here as three integers.
pub use boot_contracts::instance_lifetime::Lifetime;
pub use boot_contracts::recording_policy::Role as RecordingRole;
pub use slime_proto::syscall_abi::{
    ERR_BAD_CAP, ERR_INVALID_ARG, ERR_OUT_OF_MEMORY, ERR_PEER_DEAD, ERR_SUCCESS, ERR_WOULDBLOCK,
    MAX_CAPS_PER_MSG, MAX_MSG,
};
use slime_proto::syscall_abi::{
    capability_table_labels, capability_transfer_labels, clock_labels, directory_labels,
    io_resource_labels, lifecycle_labels, scheduling_labels, shared_buffer_labels, spawn_labels,
    supervision_labels,
};

/// Whether delegation consumes the source logical capability or retains it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDisposition {
    Move,
    Retain,
}

/// Size of the root-mapped startup transfer window: enough for the largest
/// single service frame.
pub(crate) const MIN_TRANSFER_WINDOW: usize =
    boot_contracts::component_runtime_abi::MIN_TRANSFER_WINDOW_BYTES;

/// A capability rights bitset. The vocabulary and bit numbering are generated
/// from `contracts/generation/v5/schema.zt`; see `boot_contracts::generation`
/// for the named `RIGHT_*` constants (B57).
pub type Rights = u64;

/// One grant a spawner delegates to its child, in memory.
///
/// Not a wire type: [`sel4_transport::spawn`] encodes each grant field by field
/// into a `GRANT_RECORD_BYTES` record staged in the transfer window, and the
/// root decodes the same offsets from `syscall_abi`. This carried `#[repr(C)]`
/// before B59, which suggested its field order was the ABI when the generated
/// record offsets are.
#[derive(Clone, Copy)]
pub struct SpawnGrant {
    pub slot: u32,
    pub rights: Rights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spawned {
    pub supervision_slot: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    Exit(i64),
    Fault(u64),
    Timeout,
    PeerLoss,
    Unhealthy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKey {
    Escape,
    Backspace,
    Tab,
    Enter,
    LeftControl,
    LeftShift,
    RightShift,
    LeftAlt,
    Space,
    Up,
    Down,
    Left,
    Right,
    Character(char),
    Unknown(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub key: InputKey,
    pub pressed: bool,
}

/// Relinquishes the CPU for the rest of this time slice. This is direct
/// `seL4_Yield`, not a root-service request.
pub fn yield_now() {
    transport::yield_now();
}

/// Sends `payload` (at most [`MAX_MSG`] bytes) over the endpoint in
/// capability slot `slot`, transferring the logical capabilities named in
/// `caps` (at most [`MAX_CAPS_PER_MSG`]). Each logical slot names its
/// root-minted kernel token mirror for the native Endpoint send.
pub fn send(slot: u32, payload: &[u8], caps: &[u32]) -> i64 {
    transport::send(slot, payload, caps)
}

/// Sends `payload` over `slot` and waits for the reply, as one `seL4_Call`.
///
/// The primitive B46 names for synchronous RPC. A `send` followed by a `recv`
/// cannot substitute: `send` completes as soon as the peer receives, so the
/// caller must race back to a receive, and a peer that answers first leaves the
/// two never meeting. This blocks on the reply atomically and hands the callee
/// authority naming *this* caller, so the answer cannot be taken by another
/// peer on the same endpoint.
///
/// Use it where a bare send is either lossy or deadlock-prone: [`try_send`]
/// cannot report delivery, and [`send`] blocks against a peer that may itself
/// be sending.
pub fn call(slot: u32, payload: &[u8], reply: &mut [u8; MAX_MSG]) -> i64 {
    transport::call_endpoint(slot, payload, reply)
}

/// Answers the request this thread most recently received. Reaches that caller
/// alone and cannot block: it is already waiting in [`call`].
pub fn reply(payload: &[u8]) -> i64 {
    transport::reply_to_caller(payload)
}

/// Sends `payload` over `slot` only if a receiver is already waiting, dropping
/// it otherwise.
///
/// [`send`] blocks until a receiver arrives, which deadlocks any sender that
/// must stay responsive — a broker pushing an *unsolicited* event to a peer
/// that has moved on to reading its ring, for instance. The kernel's
/// `seL4_NBSend` discards the message rather than blocking and reports nothing
/// either way, so this is best-effort by construction and returns
/// [`ERR_SUCCESS`] for "attempted". Correct only where the message is advisory
/// and the protocol does not require it to arrive; a reply or a handshake step
/// must still use [`send`].
pub fn try_send(slot: u32, payload: &[u8], caps: &[u32]) -> i64 {
    transport::try_send(slot, payload, caps)
}

/// Receives into `buf` (must be [`MAX_MSG`] bytes) and `cap_out` (must be
/// [`MAX_CAPS_PER_MSG`] entries) from the endpoint in capability slot `slot`.
/// A received kernel ticket lands in fixed CSpace slot 127, is authenticated
/// through that ticket endpoint, and is reported as the imported logical slot.
/// Returns the received byte count, or a negative error.
pub fn recv(slot: u32, buf: &mut [u8; MAX_MSG], cap_out: &mut [u64; MAX_CAPS_PER_MSG]) -> i64 {
    transport::recv(slot, buf, cap_out)
}

/// Blocking receive from a declared native endpoint.
pub fn recv_blocking(
    slot: u32,
    buf: &mut [u8; MAX_MSG],
    cap_out: &mut [u64; MAX_CAPS_PER_MSG],
) -> i64 {
    transport::recv_blocking(slot, buf, cap_out)
}

/// Signal the notification paired with one declared endpoint edge.
pub fn notification_signal(slot: u32) -> i64 {
    transport::notification_signal(slot)
}

/// Wait for the notification paired with one declared endpoint edge.
pub fn notification_wait(slot: u32) -> Result<u64, i64> {
    transport::notification_wait(slot)
}

/// Poll the notification paired with one declared endpoint edge.
pub fn notification_poll(slot: u32) -> Result<Option<u64>, i64> {
    transport::notification_poll(slot)
}

pub fn exit(status: i64) -> ! {
    transport::exit(status)
}

/// Spawns the executable in `executable_slot`. Each grant is a non-consuming
/// narrow copy; the source capability remains in the spawner. Success returns
/// only an opaque supervision capability slot; task identity stays root-local.
pub fn spawn(executable_slot: u32, grants: &[SpawnGrant]) -> Result<Spawned, i64> {
    let (result, supervision_slot) = transport::spawn(executable_slot, grants);
    if result < 0 {
        Err(result)
    } else {
        Ok(Spawned {
            supervision_slot: supervision_slot as u32,
        })
    }
}

/// Narrow and transfer one logical capability over a declared native endpoint.
/// The opaque 64-byte typed descriptor is carried atomically with the real
/// kernel ticket. Root authenticates `expected_kind` and attenuates to the
/// nonzero `rights_mask`; neither value is inferred from application bytes.
pub fn capability_delegate(
    endpoint_slot: u32,
    capability_slot: u32,
    disposition: CapabilityDisposition,
    expected_kind: u32,
    rights_mask: Rights,
    descriptor: &[u8; 64],
) -> i64 {
    transport::capability_delegate(
        endpoint_slot,
        capability_slot,
        disposition,
        expected_kind,
        rights_mask,
        descriptor,
    )
}

/// Claim the oldest root-recorded export addressed to this component.
///
/// The counterpart to [`capability_delegate`] for every object kind that is
/// not a native Endpoint: those have no kernel object to travel in the
/// message, so the descriptor arrives alone and this takes up the authority
/// behind it. Returns the slot the capability landed in.
pub fn capability_import() -> Result<u32, i64> {
    transport::capability_import()
}

/// A shared buffer allocated through a `SharedBufferFactory` capability: the
/// slot holding the new `SharedBuffer` handle, plus the assigned unforgeable
/// identity that names it across a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedBuffer {
    pub slot: u32,
    pub id: u64,
}

/// Allocate `pages` of shared memory through a `SharedBufferFactory` capability
/// (C7.2). Charged to this component's generation-declared quota (C7.3); a
/// component with no budget entry is denied. `writable` requests write and seal
/// authority on the returned handle.
pub fn shared_buffer_create(
    factory_slot: u32,
    pages: usize,
    writable: bool,
) -> Result<SharedBuffer, i64> {
    let (slot, id) = transport::shared_buffer_create(factory_slot, pages, writable);
    if slot < 0 {
        Err(slot)
    } else {
        Ok(SharedBuffer {
            slot: slot as u32,
            id,
        })
    }
}

/// Release a shared buffer and invalidate this holder's capability. Pages stay
/// retained while any loan is outstanding.
pub fn shared_buffer_release(slot: u32) -> i64 {
    transport::shared_buffer_release(slot)
}

/// Map an exact page-aligned subrange of a shared buffer at `base`. Requires
/// `RIGHT_BUFFER_MAP`; `writable` additionally requires `RIGHT_BUFFER_WRITE`
/// and fails once the region is sealed.
pub fn shared_buffer_map(slot: u32, base: u64, offset: u64, length: u64, writable: bool) -> i64 {
    transport::shared_buffer_map(slot, base, offset, length, writable)
}

/// Remove this holder's mapping of `slot` at `base` and return its charge.
pub fn shared_buffer_unmap(slot: u32, base: u64) -> i64 {
    transport::shared_buffer_unmap(slot, base)
}

/// Irreversibly seal a shared buffer read-only, downgrading every live writable
/// mapping first. Requires `RIGHT_BUFFER_WRITE`; write access never returns.
pub fn shared_buffer_seal(slot: u32) -> i64 {
    transport::shared_buffer_seal(slot)
}

/// An outstanding loan of a sealed shared-buffer subrange: the slot holding the
/// receiver-bound `SharedBufferLoan` handle, plus its assigned single-return
/// identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferLoan {
    pub slot: u32,
    pub id: u64,
}

/// Loan an exact subrange to the task named by a `RIGHT_SUPERVISE` capability
/// (C7.5). The source needs `RIGHT_BUFFER_LOAN`; the loan is single-return and
/// charged against the lender's `loan_count` quota. The receiver is named
/// through a capability, never an ambient task id.
///
/// `writable` decides what the receiver may map. A C7.6 sample loan is
/// read-only over a sealed region — the receiver reads bytes the lender
/// finished writing. A B46 stream ring is writable over an unsealed one, and
/// requires the lender to hold write authority it is handing on.
pub fn shared_buffer_loan(
    buffer_slot: u32,
    receiver_slot: u32,
    offset: u64,
    length: u64,
    writable: bool,
) -> Result<BufferLoan, i64> {
    let (slot, id) =
        transport::shared_buffer_loan(buffer_slot, receiver_slot, offset, length, writable);
    if slot < 0 {
        Err(slot)
    } else {
        Ok(BufferLoan {
            slot: slot as u32,
            id,
        })
    }
}

/// Map a subrange relative to a loan this task received, at the protection the
/// loan was minted with. Offsets are relative to the loaned region, so the
/// receiver cannot address bytes outside it even by naming the underlying
/// buffer.
pub fn shared_buffer_loan_map(loan_slot: u32, base: u64, offset: u64, length: u64) -> i64 {
    transport::shared_buffer_loan_map(loan_slot, base, offset, length)
}

/// Return a loan as its named receiver, settling it once and releasing the
/// loan capability. A second return fails: the identity is single-use.
pub fn shared_buffer_return(loan_slot: u32) -> i64 {
    transport::shared_buffer_return(loan_slot)
}

/// Revoke an outstanding loan as its lender, naming it by the source buffer and
/// the loan's assigned identity.
pub fn shared_buffer_revoke(buffer_slot: u32, loan_id: u64) -> i64 {
    transport::shared_buffer_revoke(buffer_slot, loan_id)
}

/// Four live charges the root's shared-buffer table holds against this
/// component: retained pages, allocated buffers, exact mappings, and
/// outstanding loans it has lent (C8.13.1). Each is bounded by the matching
/// field of the holder's declared `sharedBufferBudget` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferOccupancy {
    pub pages: u32,
    pub buffers: u32,
    pub mappings: u32,
    pub loans: u32,
}

/// Read-only: how many pages, buffers, mappings, and loans this component
/// currently holds charged against its declared `sharedBufferBudget` entry.
///
/// Self-scoped with no argument to scope it. The root derives the holder from
/// the endpoint badge it already authenticated, so a caller can neither name
/// another holder nor learn anything about one — the same reason the other
/// shared-buffer operations take no holder either. A component the
/// generation's budget does not name is denied outright rather than answered
/// with zeros: holding nothing and being permitted nothing are different
/// facts, and only the second is authority.
pub fn shared_buffer_occupancy() -> Result<BufferOccupancy, i64> {
    let (result, packed) = transport::shared_buffer_occupancy();
    if result < 0 {
        return Err(result);
    }
    // Shifts mirror `pack_occupancy` in `slime-root/src/main.rs`.
    let field = |shift: u32| ((packed >> shift) & 0xffff) as u32;
    Ok(BufferOccupancy {
        pages: field(0),
        buffers: field(16),
        mappings: field(32),
        loans: field(48),
    })
}

/// This component's own child-CSpace occupancy (C8.13.3), in both spaces its
/// slots are counted in.
///
/// `declared` and `declared_peak` are the space the generation budgets as
/// `capabilitySlots`: this component's own logical slot numbering from 0, the
/// numbering its grants and bindings use. `populated` is the physical CNode the
/// root built for it, where a logical index resolves to a fixed higher address.
/// The two are separate because their bounds are: comparing either to the
/// other's ceiling would compare unrelated quantities.
///
/// `declared_peak` is the root's own high-water mark, not the highest value this
/// component happened to observe. Declared occupancy moves on every install,
/// drop, transfer, and retirement — all root operations — so sampling twice
/// would report the higher of two snapshots rather than the run's maximum.
///
/// Every field is a property of this component's own CSpace. The generation's
/// declared `capabilitySlots` ceiling is deliberately absent: it is a
/// graph-wide limit, so reporting it here would turn a self-scoped query into a
/// disclosure of graph shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotOccupancy {
    pub declared: u32,
    pub declared_peak: u32,
    pub populated: u32,
}

/// Read-only: how many capability slots this component's own CSpace holds.
///
/// Self-scoped with no argument to scope it, exactly as
/// [`shared_buffer_occupancy`] is: the CSpace counted is the one belonging to
/// the endpoint badge the root already authenticated, so a caller can neither
/// name another task nor learn anything about one.
///
/// `populated` is a fresh census: the root asks the kernel about every slot,
/// which is what makes the count include capabilities this component installed
/// itself — a received Endpoint moved out of the receive slot has no root-side
/// record at all. `declared` is root-credited, because every install into that
/// space goes through a root operation.
pub fn capability_slot_occupancy() -> Result<SlotOccupancy, i64> {
    let (result, packed) = transport::capability_slot_occupancy();
    if result < 0 {
        return Err(result);
    }
    // Shifts mirror `pack_slot_occupancy` in `slime-root/src/main.rs`.
    let field = |shift: u32| ((packed >> shift) & 0xffff) as u32;
    Ok(SlotOccupancy {
        declared: field(0),
        declared_peak: field(16),
        populated: field(32),
    })
}
/// Direction of a client payload mapping from the device's viewpoint. Queue
/// control memory is not represented here; use [`io_queue_map`] for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum DmaDirection {
    DeviceRead = 1,
    DeviceWrite = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoDevice {
    pub epoch: u64,
    /// Which attached transport the generation gave this driver instance,
    /// zero-based. The root's authenticated answer: an instance's typed
    /// capabilities carry a positional index identical across two instances of
    /// one driver executable, so this is the only way to know (B84).
    pub device: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoMapping {
    pub id: u64,
    pub epoch: u64,
    pub base: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaMapping {
    pub id: u64,
    pub epoch: u64,
    pub iova: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqEvent {
    pub epoch: u64,
    pub sequence: u64,
}

pub fn io_device_bind(device_slot: u32) -> Result<IoDevice, i64> {
    transport::io_device_bind(device_slot).map(|(epoch, device)| IoDevice { epoch, device })
}

pub fn io_mmio_map(
    device_slot: u32,
    region_slot: u32,
    epoch: u64,
    base: u64,
    offset: u32,
    length: u32,
) -> Result<IoMapping, i64> {
    transport::io_mmio_map(device_slot, region_slot, epoch, base, offset, length).map(|id| {
        IoMapping {
            id,
            epoch,
            base,
            length: u64::from(length),
        }
    })
}
pub fn io_mmio_read32(
    device_slot: u32,
    region_slot: u32,
    epoch: u64,
    offset: u32,
) -> Result<u32, i64> {
    transport::io_mmio_read32(device_slot, region_slot, epoch, offset)
}

pub fn io_mmio_write32(
    device_slot: u32,
    region_slot: u32,
    epoch: u64,
    offset: u32,
    value: u32,
) -> i64 {
    transport::io_mmio_write32(device_slot, region_slot, epoch, offset, value)
}

pub fn io_dma_map(
    account_slot: u32,
    loan_slot: u32,
    epoch: u64,
    direction: DmaDirection,
) -> Result<DmaMapping, i64> {
    transport::io_dma_map(account_slot, loan_slot, epoch, direction as u64)
        .map(|(id, iova)| DmaMapping { id, epoch, iova })
}

pub fn io_queue_map(
    account_slot: u32,
    epoch: u64,
    base: u64,
    pages: u32,
) -> Result<DmaMapping, i64> {
    transport::io_queue_map(account_slot, epoch, base, pages).map(|(id, iova)| DmaMapping {
        id,
        epoch,
        iova,
    })
}

pub fn io_dma_release(account_slot: u32, mapping: DmaMapping) -> i64 {
    transport::io_dma_release(account_slot, mapping.id, mapping.epoch)
}

/// Bind the declared interrupt source when `prior_sequence` is zero, or
/// acknowledge an already-dispatched sequence. This call does not wait for
/// hardware arrival; readiness is delivered through the declared notification.
pub fn io_irq_ack(source_slot: u32, epoch: u64, prior_sequence: u64) -> Result<IrqEvent, i64> {
    transport::io_irq_ack(source_slot, epoch, prior_sequence)
        .map(|sequence| IrqEvent { epoch, sequence })
}
pub fn io_request_begin(account_slot: u32, mapping: DmaMapping, request_id: u64) -> i64 {
    transport::io_request_begin(account_slot, mapping.id, request_id, mapping.epoch)
}

pub fn io_request_settle(account_slot: u32, mapping: DmaMapping, request_id: u64) -> i64 {
    transport::io_request_settle(account_slot, mapping.id, request_id, mapping.epoch)
}

/// Query a child supervision handle. `Ok(None)` means the child is live; a
/// completed result consumes the handle slot so it can be reused.
/// Obtain a second supervision handle naming the same task (B25).
///
/// Returns the slot the new capability landed in. The caller keeps `slot`: this
/// is a derive, not a move, so a parent can introduce one child to several
/// others. Rights are the source's own and the task named is the same, so this
/// mints nothing the caller could not already have transferred.
pub fn supervision_derive(slot: u32) -> Result<u32, i64> {
    let (result, derived) = transport::supervision_derive(slot);
    if result < 0 {
        Err(result)
    } else {
        Ok(derived as u32)
    }
}

pub fn supervision_status(slot: u32) -> Result<Option<Termination>, i64> {
    let (kind, detail) = transport::supervision_status(slot);
    match kind {
        ERR_WOULDBLOCK => Ok(None),
        0 => Ok(Some(Termination::Exit(detail as i64))),
        1 => Ok(Some(Termination::Fault(detail))),
        2 => Ok(Some(Termination::Timeout)),
        3 => Ok(Some(Termination::PeerLoss)),
        4 => Ok(Some(Termination::Unhealthy)),
        error => Err(error),
    }
}

/// Releases the capability in `slot`, revoking this task's ownership of it.
pub fn cap_drop(slot: u32) -> i64 {
    transport::cap_drop(slot)
}

pub const MAX_DIRECTORY_PATH: usize = 48;

/// Returns the current immutable root and this capability's enforced scope.
/// A namespace root identity: a SHA-256 over the directory object it names.
/// The mechanism never interprets it; the bound is here so a caller can size
/// its buffer without knowing that.
pub const DIRECTORY_ROOT_BYTES: usize = 32;

pub fn directory_inspect(
    slot: u32,
    required_rights: u32,
    root: &mut [u8; 32],
    scope: &mut [u8; MAX_DIRECTORY_PATH],
) -> Result<usize, i64> {
    let result = transport::directory_inspect(slot, required_rights, root, scope);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Derives a capability scoped below `relative`, with a narrow rights mask.
pub fn directory_derive(slot: u32, relative: &[u8], rights: u32) -> Result<u32, i64> {
    let result = transport::directory_derive(slot, relative, rights);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u32)
    }
}

/// Which of this component's own capability slots holds the binding `name`.
///
/// CP2's replacement for compiling slot numbers in from a `build.rs`-generated
/// constant table. A component asks the root at startup instead of being built
/// against one manifest by one crate's private parser (B70).
///
/// Self-scoped: the request carries no task identity, so a component can resolve
/// its own bindings and only its own. A name this component's instance does not
/// bind is an error, never another instance's slot.
pub fn resolve_binding(name: &[u8]) -> Result<u32, i64> {
    let result = transport::resolve_binding(name);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u32)
    }
}

/// Read this generation's declared fabric participant rows, from `cursor`.
///
/// Fills `out` with contract-encoded `ParticipantEntry` records and returns how
/// many were written; the caller decodes them with
/// `boot_contracts::fabric_graph` and resumes from `cursor + count` until a call
/// answers fewer than `out` could hold.
///
/// Served only to the component the graph names as its fabric holder (B70), and
/// refused identically where no graph exists, so a non-holder cannot learn a
/// graph is present. Every other component asks the fabric over its declared
/// control endpoint, which is where C8.8's per-caller visibility filter lives.
pub fn graph_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::graph_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read this component's own C9.2 declared wake sources, from `cursor`.
///
/// Fills `out` with contract-encoded `wait-set/v1` entry records and returns how
/// many were written; the caller decodes them with `boot_contracts::wait_set`
/// and resumes from `cursor + count` until a call answers fewer than `out` could
/// hold. Records arrive in the contract's ascending-badge dispatch order.
///
/// Self-scoped, like [`resolve_binding`]: the request carries no waiter, so a
/// component reads what the generation declares about it and nothing about a
/// peer. A generation declaring no wait-set resource is refused, which is how a
/// caller tells "this composition has no wait sets" from "none are declared for
/// me" — the second answers zero records.
///
/// [`crate::WaitSet`] is the intended consumer; this exists because the wait set
/// is userspace policy over the ABI rather than part of it.
pub fn wait_sources(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::wait_sources(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read the authenticated IO4 exact-destination entries served to this
/// generation's network service. The request is self-scoped and names no
/// holder or destination; policy is decoded and enforced by the service.
pub fn network_destinations_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::network_destinations_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read the authenticated IO11 interface rows served to this generation's
/// network service. The request is self-scoped and names no holder or
/// interface; the service picks its own row by its holder identity and
/// configures its stack from it.
pub fn network_interface_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::network_interface_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read the authenticated `zenoh-service-grants-table/v1` rows served to this
/// generation's Zenoh service, returning how many rows were copied. The request
/// is self-scoped and names no holder or key; what each row grants is the
/// service's to enforce.
pub fn zenoh_grants_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::zenoh_grants_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read the authenticated `entropy-authority/v1` entries served to this
/// generation's entropy service, returning how many entries were copied. The
/// request is self-scoped and names no holder; budgets and streams are the
/// service's to enforce.
pub fn entropy_authority_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::entropy_authority_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read authenticated application rows for this generation's network service.
/// The root derives the reader from its badge; application policy stays userspace.
pub fn network_application_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::network_application_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read the authenticated B83 per-ring block authority entries served to this
/// generation's block driver. The request is self-scoped and names no holder,
/// device, or ring; the root reads no block right, so refusing a write on a
/// read-only ring is decided by the driver that reads this table.
pub fn block_ring_authority_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {
    let result = transport::block_ring_authority_read(cursor, out);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// The graph's index for the route whose identity is `identity`.
///
/// A participant folds its route name, interface identity, and contract kind
/// into that identity; a participant row names the route by index into a table
/// the resource sorts by identity. This resolves the two without the component
/// assuming that sort order (B70).
pub fn graph_route_index(identity: &[u8; 32]) -> Result<usize, i64> {
    let result = transport::graph_route_index(identity);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as usize)
    }
}

/// Read one schema-declared scalar from this generation's fabric graph.
///
/// `field` is a generated `boot_contracts::fabric_graph::QUERY_*` id. Graph
/// shape is holder-only; the generated `RuntimeLimits` subset is also served to
/// participants with visible rows. This runtime crate keeps the id opaque and
/// leaves that vocabulary and policy to the shared contract and root.
pub fn graph_query(field: u32) -> Result<u32, i64> {
    let result = transport::graph_query(field);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u32)
    }
}

/// Which composition the authenticated generation declares, as a `BootAction`
/// id.
///
/// The id is `boot_contracts::generation::BootAction`'s frozen numeric ABI —
/// the same number the root passes the bootstrap thread as its startup
/// argument. This crate does not depend on `boot-contracts`, so the number is
/// returned raw and the caller folds it back to the enum, exactly as
/// [`graph_read`] returns rows the caller decodes with
/// `boot_contracts::fabric_graph`.
///
/// Unscoped: a boot action is a property of the generation every caller already
/// runs inside, so it names no route, component, slot, or capability and there
/// is no per-caller answer. It exists because only the bootstrap instance is
/// told which composition it booted, which forced every other participant to
/// compile the answer in from a `build.rs`-private per-plane table (B70).
pub fn boot_action() -> Result<u32, i64> {
    let result = transport::boot_action();
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u32)
    }
}

/// The live-child budget this generation declares for the caller's own
/// executable.
///
/// Self-scoped: the executable read is the authenticated caller's, so this
/// names no instance and reports nothing about a peer. `spawn-service` admits
/// one client request per live child against this number and refuses a request
/// whose stated budget disagrees; both ends used to compile it in from a
/// `build.rs`-private manifest parse, which tied each image to one generation
/// (B70).
///
/// A refusal means the generation grants this instance no spawn authority, so
/// the question does not apply to it. A declared budget of zero is a real
/// answer and returns `Ok(0)`.
pub fn spawn_budget() -> Result<u16, i64> {
    let result = transport::spawn_budget();
    match u16::try_from(result) {
        Ok(budget) => Ok(budget),
        Err(_) => Err(if result < 0 { result } else { ERR_INVALID_ARG }),
    }
}

/// This task's private memory region: where it starts and how many pages of it
/// are currently backed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateMemory {
    /// The fixed window base. It never moves, so a pointer into the region
    /// stays valid across every later growth.
    pub base: usize,
    /// Pages currently backed by a frame.
    pub pages: usize,
}

/// A component's resolved scheduling class (C9.3).
///
/// `class_id` is the frozen `CLASS_*` numbering from
/// `contracts/scheduling-class/v1`; `priority` is the seL4 TCB priority the
/// generation's declared band mapping turned it into. Both travel because a
/// component observing its own band should not have to know the mapping to make
/// sense of the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulingClassInfo {
    pub class_id: u32,
    pub priority: u64,
}

/// Grow this task's private memory by `delta` pages, returning the region as it
/// was *before* the growth (C10.1/C10.2).
///
/// Self-scoped, like [`spawn_budget`]: the region belongs to the authenticated
/// caller, so this names no instance and can reach no peer's memory. `delta = 0`
/// is a size query that allocates nothing.
///
/// Growth is all-or-nothing and every new page arrives zeroed, mapped
/// read-write and execute-never; the base never moves. A refusal — the
/// generation-declared quota, the reserved window, or the machine being out of
/// frames — leaves the region exactly as it was, so a caller may keep using
/// what it already had. A component the generation names no quota for is
/// refused at zero pages, which is the deny-by-default answer rather than an
/// error in the request.
pub fn private_memory_grow(delta: usize) -> Result<PrivateMemory, i64> {
    let (result, base) = transport::private_memory_grow(delta);
    if result < 0 {
        return Err(result);
    }
    Ok(PrivateMemory {
        base: base as usize,
        pages: result as usize,
    })
}

/// Read the generation-authorized hardware monotonic counter (C9.1).
pub fn monotonic_read() -> Result<u64, i64> {
    let result = transport::monotonic_read();
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// Read the hardware monotonic counter's rate in ticks per second.
///
/// The same `monotonicRead` authority as [`monotonic_read`] admits it, and the
/// value is the root's own boot-time reading of the platform counter, constant
/// for the life of the boot. It is what turns a tick count into a duration and
/// a duration into a [`timer_arm`] delay.
pub fn monotonic_frequency() -> Result<u64, i64> {
    let result = transport::monotonic_frequency();
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// Arm one relative hardware timer and receive its opaque identifier.
///
/// Expiry signals the Notification and badge declared for this instance in the
/// generation. The per-holder live-timer ceiling is enforced by the root.
pub fn timer_arm(delay: u64) -> Result<u64, i64> {
    let result = transport::timer_arm(delay);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// Cancel one live timer owned by this task.
pub fn timer_cancel(timer: u64) -> i64 {
    transport::timer_cancel(timer)
}

/// Read the generation's deterministic simulated-time clock.
pub fn simulated_time_read() -> Result<u64, i64> {
    let result = transport::simulated_time_read();
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// Advance simulated time, returning its value before the advance.
pub fn simulated_time_advance(delta: u64) -> Result<u64, i64> {
    let result = transport::simulated_time_advance(delta);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// This component's declared scheduling class and the priority it runs at
/// (C9.3).
///
/// Self-scoped and never refused for want of authority: every thread runs at
/// some priority, so a component the generation names no class for is answered
/// rather than refused. Its class id is then `undeclared` (0) and its priority
/// is the root's own child default — not a band, because the generation placed
/// it in none.
pub fn scheduling_class_read() -> Result<SchedulingClassInfo, i64> {
    let (result, priority) = transport::scheduling_class_read();
    if result < 0 {
        return Err(result);
    }
    Ok(SchedulingClassInfo {
        class_id: result as u32,
        priority,
    })
}

/// Set another component's scheduling class, naming it through a supervision
/// capability this component holds (C9.3).
///
/// The request names a *class*, never a priority: the number applied comes from
/// the generation's own declared band mapping. Authority is the `slot`'s
/// supervision capability carrying `schedulingPromote` plus a generation-declared
/// promotion edge whose ceiling admits the requested class. A caller naming
/// itself is refused: promotion is authority over another component's class and
/// never over your own.
pub fn scheduling_class_promote(slot: u32, class_id: u32) -> Result<SchedulingClassInfo, i64> {
    let (result, priority) = transport::scheduling_class_promote(slot, class_id);
    if result < 0 {
        return Err(result);
    }
    Ok(SchedulingClassInfo {
        class_id: result as u32,
        priority,
    })
}

/// A component's resolved lifecycle position (C9.4).
///
/// `state_id` is the frozen `STATE_*` numbering from
/// `contracts/lifecycle-policy/v1`, or `undeclared` (0) for an instance the
/// generation's policy does not name. `attempts_remaining` is how many further
/// restarts the generation admits for this instance, and `predecessor_cause` is
/// the frozen `CAUSE_*` id of how the previous task representing it ended — `0`
/// on a first launch. All three travel together because a replacement deciding
/// what to do needs to know both that it *is* a replacement and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleStateInfo {
    pub state_id: u32,
    pub attempts_remaining: u32,
    pub predecessor_cause: u32,
}

/// What one admitted restart is bounded by (C9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartAdmission {
    /// Declared attempts still admitted after this one.
    pub attempts_remaining: u32,
    /// The monotonic instant before which the spawn is refused. Arm a C9.1
    /// timer for it rather than spinning: the root refuses an early spawn with
    /// the same number it answered here, so a supervisor that guesses is denied.
    pub ready_at: u64,
}

/// The `slot` operand naming the caller's own instance in
/// [`lifecycle_parameter_read`]/[`lifecycle_parameter_write`] (C9.4).
///
/// A component holds no supervision capability naming itself — the root mints one
/// only for a spawner — so this sentinel is the only way to reach a *reflexive*
/// parameter edge the generation declares. It confers nothing: the declared edge
/// is still the whole authority, and a component the policy grants no reflexive
/// edge is refused with it.
pub const PARAMETER_SELF_SLOT: u32 = u32::MAX;

/// This component's own lifecycle state, restart budget, and predecessor cause
/// (C9.4).
///
/// Self-scoped and never refused for want of authority, on
/// [`scheduling_class_read`]'s rule: an instance the generation's policy does not
/// name reads `undeclared` rather than an error.
pub fn lifecycle_state_read() -> Result<LifecycleStateInfo, i64> {
    let (result, packed) = transport::lifecycle_state_read();
    if result < 0 {
        return Err(result);
    }
    Ok(LifecycleStateInfo {
        state_id: result as u32,
        attempts_remaining: (packed & 0xffff_ffff) as u32,
        predecessor_cause: (packed >> 32) as u32,
    })
}

/// Advance this component's own lifecycle state along a declared edge (C9.4).
///
/// Takes no subject: moving another component's state is authority no C9.4 field
/// grants. A transition the generation's graph does not admit is refused and
/// leaves the current state untouched, so a component cannot walk out of its
/// declared lifecycle by asking.
pub fn lifecycle_state_advance(state_id: u32) -> Result<u32, i64> {
    let result = transport::lifecycle_state_advance(state_id);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u32)
    }
}

/// Ask the root to admit one restart of a dead subject, charging its declared
/// attempt budget (C9.4).
///
/// `slot` is a supervision capability this component holds naming the subject,
/// carrying `lifecycleRestart`. The root decides nothing about *whether* to
/// restart: it charges the declared budget, answers the declared backoff, and
/// refuses a cause the policy does not name or a bound already spent. The
/// decision, the wait, and the spawn are this component's.
pub fn lifecycle_restart_admit(slot: u32) -> Result<RestartAdmission, i64> {
    let (result, ready_at) = transport::lifecycle_restart_admit(slot);
    if result < 0 {
        return Err(result);
    }
    Ok(RestartAdmission {
        attempts_remaining: result as u32,
        ready_at,
    })
}

/// Read one parameter of the subject `slot` names (C9.4).
///
/// Requires the `parameterRead` right on that handle *and* a generation-declared
/// parameter edge from this holder to that subject. A refusal for want of
/// authority and an unset key are distinguishable answers, so a caller can tell
/// "I may not ask" from "there is no value".
pub fn lifecycle_parameter_read(slot: u32, key: u64) -> Result<u64, i64> {
    let result = transport::lifecycle_parameter_read(slot, key);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}

/// Write one parameter of the subject `slot` names, answering the previous value
/// (C9.4).
///
/// Requires `parameterWrite`; read authority does not imply it. Parameter state
/// belongs to the declared instance rather than to a task, so a value written
/// here is what a restarted instance is started with.
pub fn lifecycle_parameter_write(slot: u32, key: u64, value: u64) -> Result<u64, i64> {
    let result = transport::lifecycle_parameter_write(slot, key, value);
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}
/// This component's declared C9.5 recording participation.
///
/// `role` is the decoded `recording-policy/v1` role, or `None` for an instance
/// the generation's recording resource does not name. `record_capacity` is
/// records, so the stream is at most
/// `record_capacity * boot_contracts::recording_policy::RECORD_BYTES` bytes —
/// the bound a replayer sizes its input by *before* mapping anything.
///
/// The declared stream identity is deliberately absent: it is the generation's
/// join key between the two participants rather than a handle, and the authority
/// over the bytes is the shared-buffer capability the two ends hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordingParticipation {
    pub role: Option<RecordingRole>,
    pub record_capacity: u32,
    pub deterministic: bool,
}

impl RecordingParticipation {
    /// This participation's stream bound, in bytes.
    ///
    /// Zero for an unnamed instance, which has no stream at all rather than an
    /// empty one.
    pub const fn stream_bytes(&self) -> usize {
        match self.role {
            Some(_) => {
                self.record_capacity as usize * boot_contracts::recording_policy::RECORD_BYTES
            }
            None => 0,
        }
    }
}

/// This component's own recording role, bound, and determinism claim (C9.5).
///
/// Self-scoped and never refused for want of authority, on
/// [`lifecycle_state_read`]'s rule: an instance the resource does not name reads
/// `None` rather than an error, which is what lets one component image run in a
/// generation that records it and one that does not.
///
/// A role outside the contract's vocabulary is `Err(ERR_INVALID_ARG)` rather
/// than silently treated as unnamed: the root answers from a decoded resource,
/// so an unrecognized role means this image and that generation disagree about
/// the format, which a component must not paper over.
pub fn recording_participation() -> Result<RecordingParticipation, i64> {
    let (result, packed) = transport::recording_sources();
    if result < 0 {
        return Err(result);
    }
    let role = match result as u32 {
        0 => None,
        id => match RecordingRole::from_id(id) {
            Some(role) => Some(role),
            None => return Err(ERR_INVALID_ARG),
        },
    };
    Ok(RecordingParticipation {
        role,
        record_capacity: (packed & 0xffff_ffff) as u32,
        deterministic: packed >> 32 != 0,
    })
}

/// This instance's declared lifetime, asked of the root.
///
/// Self-scoped: the answer is the authenticated caller's own, from the
/// generation's `instance-lifetime/v1` object, and a generation without one
/// answers bounded. A resident instance is one whose exit the root treats as a
/// failure, so a service reads this to decide whether to keep serving after its
/// clients are done rather than probing for them.
pub fn lifetime() -> Result<Lifetime, i64> {
    let result = transport::lifetime_read();
    if result < 0 {
        return Err(result);
    }
    u8::try_from(result)
        .ok()
        .and_then(Lifetime::from_id)
        .ok_or(ERR_INVALID_ARG)
}

/// Atomically swaps a directory namespace root after the new snapshot object
/// has been committed. A stale expected root returns `ERR_WOULDBLOCK`.
pub fn directory_commit(slot: u32, expected: &[u8; 32], new: &[u8; 32]) -> i64 {
    transport::directory_commit(slot, expected, new)
}

/// Reads one decoded keyboard event through an explicit input capability.
pub fn input_read(slot: u32) -> Result<Option<InputEvent>, i64> {
    let (result, encoded) = transport::input_read(slot);
    if result == ERR_WOULDBLOCK {
        return Ok(None);
    }
    if result < 0 {
        return Err(result);
    }
    let code = encoded as u32;
    let key = match code {
        1 => InputKey::Escape,
        2 => InputKey::Backspace,
        3 => InputKey::Tab,
        4 => InputKey::Enter,
        5 => InputKey::LeftControl,
        6 => InputKey::LeftShift,
        7 => InputKey::RightShift,
        8 => InputKey::LeftAlt,
        9 => InputKey::Space,
        10 => InputKey::Up,
        11 => InputKey::Down,
        12 => InputKey::Left,
        13 => InputKey::Right,
        value if value & 0x1_0000 != 0 => InputKey::Unknown(value as u16),
        value if value & 0x100 != 0 => {
            let character = char::from_u32(value & !0x100).ok_or(ERR_INVALID_ARG)?;
            InputKey::Character(character)
        }
        _ => return Err(ERR_INVALID_ARG),
    };
    Ok(Some(InputEvent {
        key,
        pressed: encoded >> 32 != 0,
    }))
}

/// Writes `bytes` to the debug/serial log. Returns the byte count written.
pub fn debug_write(bytes: &[u8]) -> i64 {
    transport::debug_write(bytes)
}

/// Terminates the current component with an explicit unhealthy status.
pub fn unhealthy() -> ! {
    transport::unhealthy()
}
