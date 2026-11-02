//! Bounded root-side service IPC.
//!
//! Component-to-component messages use declared seL4 Endpoints directly. This
//! module decodes only the bounded wire envelope received by root services;
//! each service owns the meaning of its request labels.

/// Native messages carry at most one capability, and at most this many payload
/// bytes. Both are generated from `contracts/syscall-abi/v1/schema.zt`, so the
/// bound the root enforces is the one `components/runtime` encodes against
/// (B59).
pub use slime_proto::syscall_abi::{
    MAX_CAPS_PER_MSG as MAX_MESSAGE_CAPS, MAX_MSG as MAX_MESSAGE_BYTES,
};

/// The wake sources one fabric participant may register, re-exported from the
/// contract that declares it (B66).
///
/// This was a local `= 9` in this module, described as a "compatibility value"
/// for a root wait set B46 deleted — a number `ipc.rs` had no business owning,
/// duplicating `fabric_graph`'s own `maxIngressSources`. Admission now reads the
/// one declaration, and `build-generation.py` emits the same value as
/// `FABRIC_MAX_INGRESS_SOURCES` for the workers to size themselves against.
pub use boot_contracts::fabric_graph::MAX_INGRESS_SOURCES as MAX_WAIT_SOURCES;

/// Which root mechanism owns `label`, or `None` when no surviving mechanism
/// does.
///
/// The envelope decode below bounds a request's *shape*; this assigns its
/// *meaning*. Both belong to this module, and B61 moved this here from the
/// binary: it is a pure total function over two generated tables — the operation
/// labels and the service kinds — so leaving it in `main.rs` made it unreachable
/// from `just test_sel4_root` for no benefit.
///
/// A label with no surviving mechanism is refused rather than defaulted. B46
/// deleted the logical channel, wait-set, and endpoint-create operations, and a
/// component image built before that cutover still invokes their labels; each
/// must answer `UnsupportedOperation`, never fall through to a mechanism that now
/// happens to occupy a nearby number.
pub const fn service_for_root_label(label: sel4::Word) -> Option<u32> {
    use boot_contracts::generation::{
        SERVICE_CAPABILITY_TRANSFER, SERVICE_CLOCK, SERVICE_DIRECTORY, SERVICE_IO_RESOURCE,
        SERVICE_LIFECYCLE, SERVICE_SHARED_BUFFER, SERVICE_SPAWN, SERVICE_SUPERVISION,
    };
    use slime_proto::syscall_abi::{
        capability_table_labels, capability_transfer_labels, clock_labels, directory_labels,
        io_resource_labels, lifecycle_labels, scheduling_labels, shared_buffer_labels,
        spawn_labels, supervision_labels,
    };
    match label {
        lifecycle_labels::EXIT | lifecycle_labels::UNHEALTHY => Some(SERVICE_LIFECYCLE),
        // C10.1's private-memory growth. Lifecycle for the same reason
        // `BOOT_ACTION` below is: the service is the *authority gate*, and a
        // private heap is a property of being a task rather than of any grant.
        // Gating it on a capability service would make whether a component can
        // allocate depend on an unrelated grant shape, and `SERVICE_LIFECYCLE`
        // is the one every launched instance declares. What bounds the
        // operation is the caller's own page quota, which is a budget rather
        // than an authority: a task the generation names no quota for is
        // refused by its zero ceiling.
        lifecycle_labels::PRIVATE_MEMORY_GROW => Some(SERVICE_LIFECYCLE),
        // C9.2's declared wake sources. Lifecycle on the same rule: what a
        // component may block on is fixed by the generation's own source table,
        // and every launched instance holds this service, so the gate does not
        // have to stand in for a grant shape it is unrelated to. A waiter the
        // table does not name is answered an empty set, which is the
        // deny-by-default answer rather than a refusal — it has no source to
        // register, and an empty answer discloses nothing about a peer.
        lifecycle_labels::WAIT_SOURCES => Some(SERVICE_LIFECYCLE),
        // C9.5's declared recording participation. Lifecycle for `WAIT_SOURCES`'
        // reason: whether the generation *claims* this instance deterministic is
        // a property of being that instance, not of any grant, and an instance
        // the recording resource does not name is answered a zero role rather
        // than refused — the deny-by-default answer, which discloses nothing
        // about a peer and lets one image run in a generation that records it
        // and one that does not.
        lifecycle_labels::RECORDING_SOURCES => Some(SERVICE_LIFECYCLE),
        // The caller's own declared lifetime, on `RECORDING_SOURCES`' terms:
        // self-scoped by badge and a property of being that instance.
        lifecycle_labels::LIFETIME_READ => Some(SERVICE_LIFECYCLE),
        // B70's boot action. Lifecycle rather than the capability table, though
        // the label sits in that table's namespace, because the service is the
        // *authority gate* and this operation needs the one every instance
        // has. `declared_services` grants `SERVICE_CAPABILITY_TRANSFER` only to
        // an instance with a spawn budget, an endpoint, or a transferable
        // grant, which is not a proxy for "may know which composition it
        // booted into": 30 of the 182 instances the seL4 fixtures declare hold
        // no such grant and would be refused. Every caller here reads a refusal
        // as "not this plane", so gating on an unrelated grant shape would pick
        // a component's schedule by what it can delegate. `SERVICE_LIFECYCLE`
        // is unconditional for every instance (`build-generation.py`'s
        // `declared_services` seeds it, and 0 of 182 lack it), which states the
        // unscoped policy the contract declares instead of approximating it.
        capability_table_labels::BOOT_ACTION => Some(SERVICE_LIFECYCLE),
        spawn_labels::SPAWN => Some(SERVICE_SPAWN),
        // B70's declared spawn budget. The spawn service rather than the
        // capability table its label namespace sits in, for the same reason
        // `BOOT_ACTION` above is gated on lifecycle: the namespace groups the
        // generated constants, the service is the authority the root demands.
        // An instance the generation grants no spawn authority has no budget to
        // report, and `declared_services` gives `SERVICE_SPAWN` to exactly the
        // instances that hold one -- a nonzero `spawnBudget` or an executable
        // grant -- so the gate and the answer are the same fact.
        capability_table_labels::SPAWN_BUDGET => Some(SERVICE_SPAWN),
        supervision_labels::STATUS | supervision_labels::DERIVE => Some(SERVICE_SUPERVISION),
        capability_table_labels::DROP
        | capability_table_labels::OCCUPANCY
        | capability_table_labels::RESOLVE_BINDING
        | capability_table_labels::GRAPH_READ
        | capability_table_labels::NETWORK_DESTINATIONS_READ
        | capability_table_labels::NETWORK_INTERFACE_READ
        | capability_table_labels::NETWORK_APPLICATION_READ
        | capability_table_labels::ENTROPY_AUTHORITY_READ
        | capability_table_labels::ZENOH_GRANTS_READ
        | capability_table_labels::BLOCK_RING_AUTHORITY_READ
        | capability_table_labels::GRAPH_ROUTE_INDEX
        | capability_table_labels::GRAPH_QUERY
        | capability_transfer_labels::EXPORT
        | capability_transfer_labels::IMPORT
        | capability_transfer_labels::EXPORT_CANCEL
        | capability_transfer_labels::EXPORT_FINALIZE => Some(SERVICE_CAPABILITY_TRANSFER),
        shared_buffer_labels::CREATE
        | shared_buffer_labels::RELEASE
        | shared_buffer_labels::MAP
        | shared_buffer_labels::UNMAP
        | shared_buffer_labels::SEAL
        | shared_buffer_labels::LOAN
        | shared_buffer_labels::LOAN_MAP
        | shared_buffer_labels::RETURN
        | shared_buffer_labels::REVOKE
        | shared_buffer_labels::OCCUPANCY => Some(SERVICE_SHARED_BUFFER),
        directory_labels::DERIVE => Some(SERVICE_DIRECTORY),
        // `clock-authority/v2` makes a monotonic or rate read ambient: it is a
        // property of being a task, so it is gated on `lifecycle`, which every
        // launched instance holds. AArch64 components read the counter
        // themselves; RISC-V and x86_64 components, whose root clock is a
        // device register, ask here.
        clock_labels::MONOTONIC_READ | clock_labels::RATE_READ => Some(SERVICE_LIFECYCLE),
        clock_labels::TIMER_ARM
        | clock_labels::TIMER_CANCEL
        | clock_labels::SIMULATED_READ
        | clock_labels::SIMULATED_ADVANCE => Some(SERVICE_CLOCK),
        io_resource_labels::BIND
        | io_resource_labels::MAP_MMIO
        | io_resource_labels::DMA_MAP
        | io_resource_labels::DMA_RELEASE
        | io_resource_labels::IRQ_ACK
        | io_resource_labels::QUEUE_MAP
        | io_resource_labels::REQUEST_BEGIN
        | io_resource_labels::REQUEST_SETTLE
        | io_resource_labels::MMIO_READ32
        | io_resource_labels::MMIO_WRITE32 => Some(SERVICE_IO_RESOURCE),
        // C9.3's class read is self-scoped by badge and grants nothing, so it is
        // gated on `lifecycle` for `WAIT_SOURCES`' reason: the band a thread
        // runs at is a property of being a task, not of any grant.
        scheduling_labels::CLASS_READ => Some(SERVICE_LIFECYCLE),
        // Promotion names another task through a supervision capability, so it
        // is gated on the supervision service that resolves such a slot. The
        // declared `schedulingPromote` right and the generation's promotion edge
        // are checked by the mechanism, exactly as C9.1 checks its own bits.
        scheduling_labels::CLASS_PROMOTE => Some(SERVICE_SUPERVISION),
        // C9.4's lifecycle state. Self-scoped by badge and grants nothing, so
        // both are gated on `lifecycle` for `CLASS_READ`'s reason: which state a
        // component is in, and which state it moves to, are properties of being
        // a task rather than of any grant. `STATE_ADVANCE` is a mutator and
        // still belongs here, because it moves only the *caller's own* state --
        // there is no subject operand to authorize.
        lifecycle_labels::STATE_READ | lifecycle_labels::STATE_ADVANCE => Some(SERVICE_LIFECYCLE),
        // C9.4's restart admission and parameter authority all name another
        // component through a supervision capability, so they are gated on the
        // supervision service that resolves such a slot. The declared
        // `lifecycleRestart`/`parameterRead`/`parameterWrite` rights and the
        // generation's own restart and parameter tables are checked by the
        // mechanism, exactly as C9.3 checks its promotion edge.
        supervision_labels::RESTART_ADMIT
        | supervision_labels::PARAMETER_READ
        | supervision_labels::PARAMETER_WRITE => Some(SERVICE_SUPERVISION),
        _ => None,
    }
}

/// Required fast-register count for each C9.1 clock operation.
///
/// Kept beside label routing so malformed requests are refused before they
/// reach the clock mechanism. A zero-valued extra word is still malformed:
/// request shape is part of the ABI, not merely whether unused data matters.
pub const fn clock_request_len(label: sel4::Word) -> Option<usize> {
    use slime_proto::syscall_abi::clock_labels;
    match label {
        clock_labels::MONOTONIC_READ | clock_labels::SIMULATED_READ | clock_labels::RATE_READ => {
            Some(0)
        }
        clock_labels::TIMER_ARM | clock_labels::TIMER_CANCEL | clock_labels::SIMULATED_ADVANCE => {
            Some(1)
        }
        _ => None,
    }
}

/// Required fast-register count for each C9.3 scheduling operation.
///
/// Beside [`clock_request_len`] and for its reason: a malformed request is
/// refused before it reaches the mechanism, and a zero-valued extra word is
/// still malformed because request shape is part of the ABI.
pub const fn scheduling_request_len(label: sel4::Word) -> Option<usize> {
    use slime_proto::syscall_abi::scheduling_labels;
    match label {
        scheduling_labels::CLASS_READ => Some(0),
        // A slot and a class id. The slot names the subject; the class id is
        // checked against the declared vocabulary by the mechanism.
        scheduling_labels::CLASS_PROMOTE => Some(2),
        _ => None,
    }
}

/// Required fast-register count for each C9.4 lifecycle operation.
///
/// Beside [`clock_request_len`] and [`scheduling_request_len`] and for their
/// reason: a malformed request is refused before it reaches the mechanism, and a
/// zero-valued extra word is still malformed because request shape is part of
/// the ABI.
pub const fn lifecycle_request_len(label: sel4::Word) -> Option<usize> {
    use slime_proto::syscall_abi::{lifecycle_labels, supervision_labels};
    match label {
        lifecycle_labels::STATE_READ => Some(0),
        // One state id. The caller names no subject: advancing another
        // component's state is authority no C9.4 field grants.
        lifecycle_labels::STATE_ADVANCE => Some(1),
        // One supervision slot naming the dead subject.
        supervision_labels::RESTART_ADMIT => Some(1),
        // A slot and a key.
        supervision_labels::PARAMETER_READ => Some(2),
        // A slot, a key, and a value.
        supervision_labels::PARAMETER_WRITE => Some(3),
        // No operand at all: the caller is the badge, and naming another
        // instance's recording participation is authority no C9.5 field grants.
        lifecycle_labels::RECORDING_SOURCES => Some(0),
        lifecycle_labels::LIFETIME_READ => Some(0),
        _ => None,
    }
}
/// Exact fast-register count for IO1 hardware-resource operations.
pub const fn io_resource_request_len(label: sel4::Word) -> Option<usize> {
    use slime_proto::syscall_abi::io_resource_labels;
    match label {
        io_resource_labels::BIND => Some(1),
        io_resource_labels::MAP_MMIO
        | io_resource_labels::DMA_MAP
        | io_resource_labels::QUEUE_MAP
        | io_resource_labels::REQUEST_BEGIN
        | io_resource_labels::REQUEST_SETTLE
        | io_resource_labels::MMIO_READ32
        | io_resource_labels::MMIO_WRITE32 => Some(4),
        io_resource_labels::DMA_RELEASE | io_resource_labels::IRQ_ACK => Some(3),
        _ => None,
    }
}
/// Message registers the AArch64 fast path carries in architectural registers.
pub const FAST_MESSAGE_REGISTERS: usize = sel4::NUM_FAST_MESSAGE_REGISTERS;

// The four-MR fast path and the four-capability logical bound are independent
// facts that happen to agree on AArch64. Pin the transport side so a profile
// with fewer fast registers fails here instead of silently truncating.
const _: () =
    assert!(FAST_MESSAGE_REGISTERS == boot_contracts::component_runtime_abi::FAST_REGISTERS);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    InvalidOperation,
    UnsupportedOperation,
    InvalidLength,
    UnsupportedCapabilityTransfer,
    QueueFull,
    WouldBlock,
    // No `PeerDead`. A native seL4 Endpoint has no closed-peer signal, so no
    // root path can observe that a peer died and no status the root returns can
    // report one. Death travels on a supervision capability instead
    // (`supervision_labels::STATUS`, which the holder polls), and that is this
    // system's sole death-detection mechanism -- not a fallback beside an
    // endpoint error. A variant here that nothing constructs reads as working
    // redundancy to the next author and is what produced B75's shipped defect,
    // so the absence is deliberate and documented rather than left open (B76).
    DestinationSlotsExhausted,
    TransferFailed,
    StalePlan,
    WaiterConflict,
    /// The caller named a slot holding nothing, holding the wrong kind of
    /// resource, or carrying insufficient rights.
    ///
    /// One variant for all three deliberately: they are indistinguishable to
    /// the caller by design, so a component cannot map its own capability table
    /// by watching which error a probe returns.
    ///
    /// Distinct from [`Self::InvalidOperation`] because it is the one the
    /// retired kernel answers `ERR_BAD_CAP` to, and components test for that
    /// code specifically — `sample-receiver` proves a loan is single-return by
    /// requiring exactly `ERR_BAD_CAP` from the second return. Collapsing it
    /// into `InvalidOperation` would answer `ERR_INVALID_ARG` and make that
    /// check fail against a correct implementation.
    ///
    /// [`Self::UnsupportedCapabilityTransfer`] answers the same status for the
    /// same reason and stays separate only so the root's own markers can name
    /// the cause.
    BadCapability,
}

impl IpcError {
    /// Slime-visible status returned in reply MR0 by the root service loop.
    ///
    /// The codes are generated from `contracts/syscall-abi/v1/schema.zt` and are
    /// the same constants `components/runtime` tests against (B59). The mapping
    /// is deliberately many-to-one: a component learns the failure class, not
    /// which internal predicate rejected it.
    pub const fn slime_status(self) -> i64 {
        use slime_proto::syscall_abi::{
            ERR_BAD_CAP, ERR_INVALID_ARG, ERR_OUT_OF_MEMORY, ERR_WOULDBLOCK,
        };
        match self {
            Self::BadCapability => ERR_BAD_CAP,
            Self::QueueFull | Self::WouldBlock => ERR_WOULDBLOCK,
            // `ERR_BAD_CAP`, with the other capability failures: `sys_send`
            // answers that for a capability it will not move, and a component
            // written against the retired kernel tests for it. It stays a
            // distinct variant because the root's own marker distinguishes an
            // unmovable capability from an absent one, which is a diagnosis a
            // component is deliberately not given.
            Self::UnsupportedCapabilityTransfer => ERR_BAD_CAP,
            Self::InvalidOperation
            | Self::UnsupportedOperation
            | Self::InvalidLength
            | Self::StalePlan
            | Self::WaiterConflict => ERR_INVALID_ARG,
            Self::DestinationSlotsExhausted | Self::TransferFailed => ERR_OUT_OF_MEMORY,
        }
    }
}

/// One bounded request received on the root service endpoint.
///
/// The root dispatcher interprets `label` according to the narrow service it
/// selects. Keeping the envelope raw here avoids coupling unrelated services
/// into a single public label namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub badge: sel4::Badge,
    pub label: sel4::Word,
    pub mrs: [sel4::Word; FAST_MESSAGE_REGISTERS],
    pub len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response {
    pub result: i64,
    pub aux: sel4::Word,
}

impl Response {
    pub const fn success(result: i64, aux: sel4::Word) -> Self {
        Self { result, aux }
    }

    pub const fn error(error: IpcError) -> Self {
        Self {
            result: error.slime_status(),
            aux: 0,
        }
    }
}

/// One decoded arrival on the root service endpoint.
///
/// The badge is kept even when decoding fails, because the dispatcher still
/// owes the caller a reply and still attributes the attempt to a task. The raw
/// `MessageInfo` is kept because a fault arrives on this same endpoint and is
/// decoded from it by `fault::decode_fault` before the request envelope is
/// dispatched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reception {
    pub info: sel4::MessageInfo,
    pub badge: sel4::Badge,
    pub request: Result<Request, IpcError>,
}

// Receive one bounded root-service request. Raw seL4 extra-cap transfer is
// not part of this envelope; capability transport uses its declared native
// mechanism instead.

/// One console message: the payload descriptor and the fast registers behind
/// it.
///
/// The console endpoint has its own narrow labels because one thread serves
/// console, input, and directory traffic.
pub struct ConsoleMessage {
    pub badge: sel4::Badge,
    pub kind: ConsoleKind,
    pub mrs: [sel4::Word; FAST_MESSAGE_REGISTERS],
    pub len: usize,
}

/// What a console-endpoint message asks for.
///
/// The kinds share one endpoint because one thread serves them and a second
/// endpoint would need a second blocking receive. They are all console-adjacent
/// services, so one queue between them is the honest shape.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConsoleKind {
    /// One-way debug output.
    Write,
    /// A read returning one decoded key event.
    InputRead,
    /// A directory inspect or commit (B45). The namespace and scope tables came
    /// with the handlers, and a commit racing a lifecycle syscall on one queue
    /// makes each wait for the other for no reason.
    ///
    /// Derive is *not* here: it is the only writer of the caller's capability
    /// table, which the main dispatcher also writes, and two threads writing
    /// one task's table is a data race.
    DirectoryInspect,
    DirectoryCommit,
}

impl ConsoleKind {
    const WRITE: sel4::Word = boot_contracts::component_runtime_abi::console_labels::WRITE;
    const INPUT_READ: sel4::Word =
        boot_contracts::component_runtime_abi::console_labels::INPUT_READ;
    const DIRECTORY_INSPECT: sel4::Word =
        boot_contracts::component_runtime_abi::console_labels::DIRECTORY_INSPECT;
    const DIRECTORY_COMMIT: sel4::Word =
        boot_contracts::component_runtime_abi::console_labels::DIRECTORY_COMMIT;

    const fn from_label(label: sel4::Word) -> Option<Self> {
        match label {
            Self::WRITE => Some(Self::Write),
            Self::INPUT_READ => Some(Self::InputRead),
            Self::DIRECTORY_INSPECT => Some(Self::DirectoryInspect),
            Self::DIRECTORY_COMMIT => Some(Self::DirectoryCommit),
            _ => None,
        }
    }
}

/// Receive one console message through an explicit IPC buffer.
///
/// The `sel4` crate keeps one IPC-buffer slot per address space, and a receive
/// holds it borrowed for as long as it blocks — so the console dispatcher,
/// being a second root thread, names its buffer here rather than using the
/// ambient slot (B41).
pub fn recv_console(
    endpoint: sel4::cap::Endpoint,
    buffer: &mut sel4::IpcBuffer,
) -> Result<ConsoleMessage, IpcError> {
    let reception = endpoint.with(buffer).recv_with_mrs(());
    let len = reception.info.length();
    if len > FAST_MESSAGE_REGISTERS {
        return Err(IpcError::InvalidLength);
    }
    if reception.info.extra_caps() != 0 || reception.info.caps_unwrapped() != 0 {
        return Err(IpcError::UnsupportedCapabilityTransfer);
    }
    let Some(kind) = ConsoleKind::from_label(reception.info.label()) else {
        return Err(IpcError::InvalidOperation);
    };
    Ok(ConsoleMessage {
        badge: reception.badge,
        kind,
        mrs: reception.msg,
        len,
    })
}

/// Answer the previous input read and wait for the next message, in one
/// syscall — the console loop's steady state once a read has been served.
pub fn reply_recv_console(
    endpoint: sel4::cap::Endpoint,
    response: Response,
    buffer: &mut sel4::IpcBuffer,
) -> Result<ConsoleMessage, IpcError> {
    let words = [response.result as sel4::Word, response.aux];
    let info = sel4::MessageInfoBuilder::default()
        .length(words.len())
        .build();
    // `reply_recv` carries its payload in the buffer's message registers
    // rather than the fast ones, so the reply is staged there and the next
    // request is read back out of them.
    buffer.msg_regs_mut()[..words.len()].copy_from_slice(&words);
    let (received, badge) = endpoint.with(&mut *buffer).reply_recv(info, ());
    let len = received.length();
    if len > FAST_MESSAGE_REGISTERS {
        return Err(IpcError::InvalidLength);
    }
    if received.extra_caps() != 0 || received.caps_unwrapped() != 0 {
        return Err(IpcError::UnsupportedCapabilityTransfer);
    }
    let Some(kind) = ConsoleKind::from_label(received.label()) else {
        return Err(IpcError::InvalidOperation);
    };
    let mut mrs = [0 as sel4::Word; FAST_MESSAGE_REGISTERS];
    mrs[..len].copy_from_slice(&buffer.msg_regs()[..len]);
    Ok(ConsoleMessage {
        badge,
        kind,
        mrs,
        len,
    })
}

/// Receive through an explicit IPC buffer rather than the ambient one.
///
/// The `sel4` crate keeps one IPC-buffer slot per address space on this
/// target, and a receive holds it borrowed for as long as it blocks — so a
/// second root thread using the ambient slot would find it permanently taken
/// by whichever thread is parked in `seL4_Recv`. Naming the buffer on the
/// capability sidesteps the slot entirely (B41).
pub fn recv_request_with(endpoint: sel4::cap::Endpoint, buffer: &mut sel4::IpcBuffer) -> Reception {
    let reception = endpoint.with(&mut *buffer).recv_with_mrs(());
    received_request(reception, buffer)
}

pub fn recv_request(endpoint: sel4::cap::Endpoint) -> Reception {
    let reception = endpoint.recv_with_mrs(());
    sel4::with_ipc_buffer_mut(|buffer| received_request(reception, buffer))
}

/// Fast-register receive returns MR0–MR3 outside the IPC buffer. Fault
/// decoding still consumes that buffer, including any kernel-written tail.
/// Synchronize only received words before applying service-message bounds.
fn received_request(reception: sel4::RecvWithMRs, buffer: &mut sel4::IpcBuffer) -> Reception {
    let count = reception.info.length().min(reception.msg.len());
    buffer.msg_regs_mut()[..count].copy_from_slice(&reception.msg[..count]);
    Reception {
        info: reception.info.clone(),
        badge: reception.badge,
        request: decode_request(&reception),
    }
}

fn decode_request(reception: &sel4::RecvWithMRs) -> Result<Request, IpcError> {
    let len = reception.info.length();
    if len > FAST_MESSAGE_REGISTERS {
        return Err(IpcError::InvalidLength);
    }
    let caps = reception.info.extra_caps();
    if reception.info.caps_unwrapped() != 0 || caps > MAX_MESSAGE_CAPS || caps != 0 {
        return Err(IpcError::UnsupportedCapabilityTransfer);
    }
    Ok(Request {
        badge: reception.badge,
        label: reception.info.label(),
        mrs: reception.msg,
        len,
    })
}

/// Reply to the most recent non-MCS request. MR0 carries the bit-exact logical
/// `i64` result and MR1 carries the service-specific auxiliary value.
#[sel4::sel4_cfg(not(KERNEL_MCS))]
pub fn reply(response: Response) {
    let words = [response.result as sel4::Word, response.aux];
    let info = sel4::MessageInfoBuilder::default()
        .length(words.len())
        .build();
    sel4::with_ipc_buffer_mut(|ipc_buffer| {
        ipc_buffer.msg_regs_mut()[..words.len()].copy_from_slice(&words);
        sel4::reply(ipc_buffer, info);
    });
}

/// Poll a notification used to multiplex endpoint, timer, IRQ, and lifecycle
/// readiness. Badges are opaque routing tokens assigned by `slime-root`; no
/// CSpace slot or physical identifier is exposed by this helper.
pub fn poll_notification(notification: sel4::cap::Notification) -> Option<sel4::Badge> {
    let (info, badge) = notification.poll();
    (info.length() != 0 || badge != 0).then_some(badge)
}

/// The maximum binding-name length a `RESOLVE_BINDING` request may carry.
///
/// The message envelope, not the generation string table's 255-byte per-string
/// bound: a name arrives in one request, so a name longer than the envelope
/// cannot be asked about at all and is refused on length rather than silently
/// truncated into a different name. Every grant name in every current fixture is
/// well inside this, and `contracts/component-spec/v1`'s `maxNameBytes` is 64.
pub const MAX_BINDING_NAME: usize = MAX_MESSAGE_BYTES;

/// Which of `instance`'s own capability slots holds the binding named `name`.
///
/// CP2's runtime binding resolution. Before this, a component learned its slot
/// numbers from a constant table `components/bins/build.rs` generated by parsing
/// the generation manifest, compiled them into its own image, and so could not be
/// built outside that one crate against that one manifest (B70). The root already
/// holds the answer: each instance declares its own `InstanceBinding` list of
/// `(grant, slot)`, and each grant carries its name, so this is a lookup over
/// data activation already installed rather than a new authority.
///
/// The instance's *own* binding list is what is searched, not the global
/// `CapBinding` table. The two are different facts and the difference bit during
/// CP2: a `CapBinding` exists once per grant, at whichever holder materializes
/// it, so the endpoint `console` waits on is recorded against `init` alone and
/// resolving through that table answered nothing for `console`. The per-instance
/// list is the one that says which slot *this* instance's CSpace uses.
///
/// `instance` is the caller's own index, taken from the badge the root
/// authenticated. It is a parameter rather than something this function derives:
/// the caller never names it, so there is nothing to forge, and the dispatcher's
/// one job is to pass the authenticated identity through.
///
/// A name the instance does not bind returns `None`, never another instance's
/// slot — the property that makes this answerable for every component. A
/// component learns its own layout, which it already knew at compile time, and
/// nothing else.
use boot_contracts::boot_layout;

pub fn resolve_binding_slot(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    name: &[u8],
) -> Option<usize> {
    if !binding_name_admissible(name) {
        return None;
    }
    let name = core::str::from_utf8(name).ok()?;
    let instance_index = instance;
    let instance = generation.instance(instance_index).ok()?;
    // Each binding names a grant by index, so the grant is decoded per binding
    // rather than the grant table being scanned for the name first: an instance
    // binds a handful of grants, while the generation declares up to 128.
    for index in 0..instance.binding_count() {
        let binding = generation.binding(instance, index).ok()?;
        if generation
            .grant(binding.grant)
            .is_ok_and(|grant| grant.name == name)
        {
            return Some(binding.slot);
        }
    }
    // A capability *role* — `kind:<kind>+<right>,<right>` — resolved over the
    // caller's own bindings by what the capability is rather than by what the
    // generation happened to call it.
    //
    // This axis exists because grant names are not always stable across
    // generations, and a name written into a component that a later manifest
    // spells differently is exactly the coupling B70 exists to remove. Where a
    // name *is* uniform across every generation declaring the component -- as
    // `spawn-service-rpc` and the `spawn-service-<command>` pair are, since B70
    // normalized them -- the unprefixed lookup above answers and this axis is
    // not needed. Where the capability is identified by what it is rather than
    // by what it is called, this one is.
    //
    // `components/bins/build.rs` already demonstrated the right axis: it
    // resolved these same slots by capability kind and rights and never by grant
    // name. Those are properties of the capability the component needs, so they
    // are answerable from any manifest that grants it. This moves that question
    // from a build script parsing a manifest to the root reading the activation
    // record it already holds.
    //
    // The match is exact on kind and a superset on rights: a component asking for
    // `send`+`recv` accepts a grant carrying those and more, which is the same
    // containment `build.rs` applies. Still the caller's own bindings only, so
    // this discloses nothing a name lookup would not.
    if let Some(role) = name.strip_prefix("kind:") {
        return resolve_role_slot(generation, instance, role);
    }
    // A layout role, only when the caller asked for one *explicitly*, and only
    // for the bootstrap instance.
    //
    // The namespace prefix is what makes this sound, and it exists because the
    // unprefixed version was written twice and failed on real boots twice. The
    // boot layout declares the bootstrap component's executables and channel
    // halves; a grant list declares its capability edges; and the two use
    // overlapping names for different things — `console` is a layout executable
    // at slot 1 while `init-console` is a grant at the same slot, and
    // `console-output` is a grant under one generation and absent from the
    // layout under another. A single flat lookup therefore answered a channel
    // question with an executable slot, and `init` sent into an endpoint nobody
    // was waiting on: a hang rather than a visible error.
    //
    // So the caller states which table it means. `executable:` and `channel:`
    // address the layout's two identity domains, which is exactly the
    // distinction the contract already draws to keep a component and a channel
    // sharing a name apart. An unprefixed name is a grant and can never reach
    // the layout, so no existing caller's meaning changes and no layout entry
    // can shadow a grant.
    if instance_index == generation.bootstrap() {
        if let Some(role) = name.strip_prefix("executable:") {
            return resolve_layout_slot(generation, &boot_layout::component_identity(role));
        }
        if let Some(role) = name.strip_prefix("channel:") {
            return resolve_layout_slot(generation, &boot_layout::channel_identity(role));
        }
    }
    // A *notification* binding — `notification:<grant>` or
    // `notification:<grant>+signal`/`+wait`.
    //
    // Notifications are a separate declaration from capability grants:
    // `notificationBindings` names a `(grant, holder, slot, role)` tuple, and one
    // grant binds a slot in *both* peers — the signaller and the waiter — so the
    // same name legitimately answers two different slots depending on which side
    // asks. Scoping to the caller's own holder index is therefore not a
    // restriction here but the whole answer: `fabric-publisher-telemetry-ready`
    // is slot 0 for `fabric-publisher` and slot 0 for `fabric-service` in the
    // stream plane, and slot 4 for the service in others.
    //
    // The role suffix exists because a component can hold both ends of one
    // grant's name space. Without it, a holder appearing twice for one grant
    // would be ambiguous and refused, which is correct but useless; with it the
    // caller says which end it means, in the manifest's own `signal`/`wait`
    // vocabulary.
    if let Some(role) = name.strip_prefix("notification:") {
        return resolve_notification_slot(generation, instance_index, role);
    }
    // A *minted* binding — `minted:<name>`.
    //
    // A third declaration table, for a capability whose *slot* the generation
    // fixes but whose object is created at runtime by the holder's owner: a
    // supervision handle cannot exist before the task it names, so the manifest
    // declares where it will land rather than granting it. `fabric-service` holds
    // one per child it supervises.
    //
    // Its own namespace rather than folded into the grant lookup, on the same
    // rule the layout and notification prefixes follow: these are different
    // tables, and the names in them are not drawn from one pool. Reusing the
    // unprefixed spelling would let a minted binding answer a grant question,
    // which is exactly the shadowing the `executable:` fix exists to prevent.
    if let Some(minted) = name.strip_prefix("minted:") {
        return resolve_minted_slot(generation, instance_index, minted);
    }
    // The same table asked from the other side -- `owned-minted:<name>`.
    //
    // A minted binding names two instances: the `holder` whose slot it fixes,
    // and the `owner` who must create the object and hand it over at spawn. The
    // arm above answers the holder's question, "which of my slots is this?". An
    // owner asks a different one -- "does the child I am about to spawn declare
    // this handle?" -- because what it must supply is a property of the child's
    // declarations, not of its own.
    //
    // Its own prefix rather than a relaxation of the filter above, on the rule
    // the `executable:` fix established: these are two questions over one table,
    // and a name answering both would let an owner-scoped lookup satisfy a
    // holder-scoped one. The slot returned is the *holder's*, which is what a
    // spawn's positional match is against.
    if let Some(minted) = name.strip_prefix("owned-minted:") {
        return resolve_owned_minted_slot(generation, instance_index, minted);
    }
    None
}

/// Which of `holder`'s slots the minted binding named `name` declares.
///
/// Scoped to the caller's authenticated holder index, as every axis here is.
/// `mintedBindings` already keys on `holder`, so this is the same per-holder
/// question the notification lookup answers, over the table that declares a slot
/// for an object created after boot.
///
/// Ambiguity refuses. A holder declaring one minted name twice is a fixture
/// defect, and answering the first would hand out whichever the builder happened
/// to emit first.
fn resolve_minted_slot(
    generation: &boot_contracts::generation::Generation<'_>,
    holder: usize,
    name: &str,
) -> Option<usize> {
    let mut found: Option<usize> = None;
    for index in 0..generation.minted_binding_count() {
        let binding = generation.minted_binding(index).ok()?;
        if binding.holder != holder || binding.name != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(binding.slot);
    }
    found
}

/// Which slot the minted binding named `name` declares, among those `owner`
/// must supply.
///
/// Scoped to the caller's authenticated *owner* index, where `resolve_minted_slot`
/// scopes to `holder`. Both read `mintedBindings`; they differ in which end of
/// the record the caller is standing on. An owner needs this to know whether a
/// child declares a given handle at all, since a spawn is matched positionally
/// against the child's declarations and a composition that omits one expects a
/// shorter vector.
///
/// Returns the holder's slot, not the owner's: the owner holds no slot for a
/// minted binding, and the holder's is the number the positional match uses.
///
/// Ambiguity refuses, as on every axis here. One owner declaring the same minted
/// name for two children is answerable only by naming the child, and this
/// question does not.
fn resolve_owned_minted_slot(
    generation: &boot_contracts::generation::Generation<'_>,
    owner: usize,
    name: &str,
) -> Option<usize> {
    let mut found: Option<usize> = None;
    for index in 0..generation.minted_binding_count() {
        let binding = generation.minted_binding(index).ok()?;
        if binding.owner != owner || binding.name != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(binding.slot);
    }
    found
}

/// Which of `holder`'s notification slots the grant named `role` binds.
///
/// `role` is `<grant>` or `<grant>+signal`/`+wait`. Matching is on the
/// generation's own `notificationGrants` names and `notificationBindings`
/// records, so a component asks in the vocabulary the manifest already uses.
///
/// Scoped to `holder`, the caller's authenticated instance index, for the same
/// reason the capability lookups are: a component learns its own layout and
/// nothing else. Here that scoping also carries the meaning, because one
/// notification grant binds a slot in both peers.
///
/// Ambiguity refuses, as everywhere else in this operation. A holder binding one
/// grant under both roles is answerable only with the suffix, and asking without
/// it is a question that does not identify one slot.
fn resolve_notification_slot(
    generation: &boot_contracts::generation::Generation<'_>,
    holder: usize,
    role: &str,
) -> Option<usize> {
    use boot_contracts::generation::NotificationRole;

    let (name, wanted) = match role.split_once('+') {
        Some((name, "signal")) => (name, Some(NotificationRole::Signal)),
        Some((name, "wait")) => (name, Some(NotificationRole::Wait)),
        // An unrecognized suffix is refused rather than ignored: silently
        // dropping it would answer a different question than the caller asked.
        Some(_) => return None,
        None => (role, None),
    };
    // A *name-free* query: `@<ordinal>+<role>`, answering "my Nth binding in
    // this role, by ascending declared slot".
    //
    // A service declared twice — one instance per device, which is how a plane
    // with two disks is composed, since IO1 grants one device per driver —-
    // cannot ask by grant name: notification grant names are globally unique
    // and each grant has exactly one waiter, so the two instances are bound to
    // differently-named grants. A driver spelling one name would serve only the
    // instance that happened to get it. This is the same compile-time coupling
    // B70 removed for capability slots, reappearing as a name.
    //
    // Ordinal over *this holder's own* bindings, so it discloses nothing about
    // a peer, and by ascending slot rather than declaration order so it is a
    // property of the layout rather than of how the manifest was written.
    if let Some(ordinal) = name.strip_prefix('@') {
        let wanted = wanted?;
        let Ok(ordinal) = ordinal.parse::<usize>() else {
            return None;
        };
        let mut slots = [usize::MAX; MAX_NOTIFICATION_BINDINGS_PER_HOLDER];
        let mut len = 0;
        for index in 0..generation.notification_binding_count() {
            let binding = generation.notification_binding(index).ok()?;
            if binding.holder != holder || binding.role != wanted {
                continue;
            }
            if len == slots.len() {
                return None;
            }
            slots[len] = binding.slot;
            len += 1;
        }
        slots[..len].sort_unstable();
        return slots[..len].get(ordinal).copied();
    }
    let mut found: Option<usize> = None;
    for index in 0..generation.notification_binding_count() {
        let binding = generation.notification_binding(index).ok()?;
        if binding.holder != holder {
            continue;
        }
        if wanted.is_some_and(|role| binding.role != role) {
            continue;
        }
        if !generation
            .notification_grant(binding.grant)
            .is_ok_and(|grant| grant.name == name)
        {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(binding.slot);
    }
    found
}

/// Notification bindings one holder may declare in a single role.
///
/// Bounds the ordinal query's scratch array. A holder declaring more is
/// refused rather than truncated: answering from a partial list would return a
/// different binding than the ordinal names.
const MAX_NOTIFICATION_BINDINGS_PER_HOLDER: usize = 16;

/// Which of `instance`'s slots carries a capability of `kind` bearing `rights`.
///
/// `role` is `<kind>` or `<kind>+<right>,<right>`. The kind names are the
/// manifest's own `capabilityKind` spellings, so a component asks in the
/// vocabulary the contract already defines rather than in a second one invented
/// here.
///
/// Rights are a *superset* test, matching `build.rs`'s containment check: a
/// component needing `send`+`recv` is served by a grant carrying those and more,
/// because extra rights on a capability it already holds do not change whether
/// this is the slot it asked for. Kind is exact — a `block` capability is never
/// an answer to an `endpoint` question, however its rights overlap.
///
/// An *ambiguous* role is refused, not resolved to the lowest slot. The frozen
/// CP1 reference generation binds multiple executable grants to spawn-service;
/// the retired Dango plane carried the same ambiguity for endpoints. A
/// lowest-slot tiebreak can return a valid capability answering the wrong
/// question, which presents as a hang rather than an error. Callers needing to
/// distinguish those bindings must ask by stable generation name.
fn resolve_role_slot(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: boot_contracts::generation::Instance,
    role: &str,
) -> Option<usize> {
    let (kind, rights) = match role.split_once('+') {
        Some((kind, rights)) => (kind, rights),
        None => (role, ""),
    };
    let kind = capability_kind_named(kind)?;
    // An unknown right is refused outright rather than skipped, so a misspelling
    // narrows nothing: `kind:endpoint+snd` must not silently become
    // `kind:endpoint` and match the first endpoint the caller binds.
    for right in rights.split(',').filter(|right| !right.is_empty()) {
        boot_contracts::generation::right_named(right)?;
    }
    let mut found: Option<usize> = None;
    for index in 0..instance.binding_count() {
        let binding = generation.binding(instance, index).ok()?;
        let Ok(grant) = generation.grant(binding.grant) else {
            continue;
        };
        if grant.capability_kind != kind {
            continue;
        }
        if !rights
            .split(',')
            .filter(|right| !right.is_empty())
            .all(|right| {
                boot_contracts::generation::right_named(right)
                    .is_some_and(|bit| grant.rights & bit == bit)
            })
        {
            continue;
        }
        if found.is_some() {
            // Two answers means the question did not identify one capability.
            return None;
        }
        found = Some(binding.slot);
    }
    found
}

/// The `capabilityKind` spelling the generation manifest uses, decoded.
///
/// An unknown kind is `None` rather than a default: a component asking for a kind
/// this root does not know is a question with no answer, and guessing one would
/// hand it a capability of the wrong type.
fn capability_kind_named(name: &str) -> Option<boot_contracts::generation::CapabilityKind> {
    use boot_contracts::generation::CapabilityKind;

    Some(match name {
        "endpoint" => CapabilityKind::Endpoint,
        "executable" => CapabilityKind::Executable,
        "sharedBufferFactory" => CapabilityKind::SharedBufferFactory,
        "directory" => CapabilityKind::Directory,
        "input" => CapabilityKind::Input,
        "supervision" => CapabilityKind::Supervision,
        "sharedBuffer" => CapabilityKind::SharedBuffer,
        "loan" => CapabilityKind::Loan,
        _ => return None,
    })
}

/// Which slot of the bootstrap component's CSpace carries `identity`.
///
/// The layout keys entries by identity hash under two domains, so the caller
/// computes the one it means and this compares it. Resource objects share a
/// kind, so the decode is the discriminator: a shared-buffer budget or a fabric
/// graph fails it and is skipped.
///
/// Ambiguous, like `resolve_role_slot`, refuses rather than returning the first
/// match. No generated layout has ever declared one identity at two slots — the
/// builder derives each label's identity from the manifest's own component and
/// channel names, which are themselves unique — but a hand-authored
/// `SLIME_BOOT_LAYOUT` override is not proven to keep that property, and a
/// silent first-match would repeat the exact failure class the namespace fix
/// above exists to prevent: a plausible slot that is not the one the caller
/// meant.
fn resolve_layout_slot(
    generation: &boot_contracts::generation::Generation<'_>,
    identity: &[u8; 32],
) -> Option<usize> {
    use boot_contracts::generation::KIND_RESOURCE;

    let mut found: Option<usize> = None;
    for index in 0..generation.object_count() {
        let object = generation.object(index).ok()?;
        if object.kind != KIND_RESOURCE {
            continue;
        }
        let Ok(layout) = boot_layout::BootLayout::decode(object.bytes) else {
            continue;
        };
        for entry in 0..layout.entry_count() {
            let entry = layout.entry(entry)?;
            if &entry.name_identity == identity {
                if found.is_some() {
                    return None;
                }
                found = Some(entry.slot as usize);
            }
        }
    }
    found
}

/// Bytes one encoded participant row occupies in a `GRAPH_READ` reply.
///
/// The contract's own record size, not a number chosen here: the caller decodes
/// with `boot_contracts::fabric_graph`, so a reply laid out to any other stride
/// would decode as garbage rather than fail.
pub const GRAPH_ROW_BYTES: usize = boot_contracts::fabric_graph::PARTICIPANT_ENTRY_BYTES;

/// Participant rows one `GRAPH_READ` call may answer.
///
/// One row is 128 bytes against a 64-byte message bound, so the answer travels
/// through the caller's transfer window and is paged. The real graphs need one
/// or two calls (15 participants is the largest any seL4 manifest declares) and
/// the contract ceiling of 32 needs four.
pub const GRAPH_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / GRAPH_ROW_BYTES;

/// Whether `instance` is the component this generation's graph names as its
/// fabric holder.
///
/// The authority test for `GRAPH_READ`, and deliberately the *whole* test. The
/// graph carries a `fabricComponentIdentity`, and admission already folds
/// instance names to that identity to check every participant is declared
/// (`generation::fabric_graph_participants_are_declared`), so this asks a
/// question the generation answers about itself rather than applying a policy.
///
/// Every other caller is refused, including one holding a participant row of its
/// own. C8.8 makes *which routes exist* a filtered, per-caller answer the fabric
/// enforces — `just sel4_visibility_check` asserts an ungranted caller infers
/// nothing — so serving the raw graph to any caller would bypass that gate
/// rather than implement it.
pub fn is_declared_fabric_holder(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
) -> bool {
    let Some(Ok(graph)) = crate::generation::fabric_graph_object(generation) else {
        return false;
    };
    let Ok(instance) = generation.instance(instance) else {
        return false;
    };
    boot_contracts::fabric_graph::component_identity(instance.name)
        == graph.fabric_component_identity()
}

/// Whether `instance` may read the row naming `component`.
///
/// Two ways in, and both are authority the generation already gave the caller.
///
/// **Itself.** A component reads what the generation declares about it, which is
/// the rule `resolve_binding_slot` applies to bindings and is exactly what the
/// generated table used to tell it.
///
/// **A component it holds a declared capability edge with.** A route worker
/// brokers for participants it did not spawn and is not the graph's holder of —
/// `fabric-op-worker` on `sel4-boot` is bound to `fabric-op-client`'s control
/// endpoint and must know that client's declared feedback depth. It already
/// holds an endpoint to that component, placed by the root from the manifest, so
/// the graph row tells it nothing about a peer it could not already reach. What
/// it cannot do is enumerate: a component with no edge to a participant still
/// reads nothing of it, so C8.8's route filtering stays the fabric's to enforce.
///
/// The edge is read from the *caller's own* binding list, so it is the same
/// per-instance scoping every axis here uses, not a search of the global grant
/// table.
fn may_read_row(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    component: &[u8; 32],
) -> bool {
    use boot_contracts::fabric_graph::component_identity;
    use boot_contracts::generation::GrantEndpoint;

    let Ok(caller) = generation.instance(instance) else {
        return false;
    };
    if component_identity(caller.name) == *component {
        return true;
    }
    let names_component = |endpoint: GrantEndpoint| match endpoint {
        GrantEndpoint::Instance(index) => generation
            .instance(index)
            .is_ok_and(|peer| component_identity(peer.name) == *component),
        GrantEndpoint::Executable(_) => false,
    };
    (0..caller.binding_count()).any(|index| {
        generation
            .binding(caller, index)
            .ok()
            .and_then(|binding| generation.grant(binding.grant).ok())
            .is_some_and(|grant| names_component(grant.source) || names_component(grant.target))
    })
}

/// The graph's index for the route whose identity is `identity`.
///
/// A participant knows its route by *identity* — it folds the route name, its
/// interface identity, and the contract kind, exactly as the builder does — but
/// a participant row names the route by *index* into a table sorted by that
/// identity. Resolving the two here keeps the ordering rule inside the decoder
/// that owns it: a component deriving the index locally would be assuming the
/// resource's sort order, which is precisely the coupling this operation
/// removes.
///
/// Unscoped on purpose, and safe to answer for any caller: a route identity is
/// something the asker already holds, so the answer confirms a fold it computed
/// itself and discloses no route it did not already name.
pub fn route_index_for(
    generation: &boot_contracts::generation::Generation<'_>,
    identity: &[u8; 32],
) -> Option<usize> {
    let Some(Ok(graph)) = crate::generation::fabric_graph_object(generation) else {
        return None;
    };
    (0..graph.route_count()).find(|index| {
        graph
            .route(*index)
            .is_some_and(|route| route.route_identity == *identity)
    })
}

/// One schema-declared scalar from this generation's authenticated fabric graph.
///
/// Table cardinalities remain holder-only: they expose hidden graph shape.
/// Declared resource ceilings are available to every graph participant, because
/// workers must admit traffic against the same authenticated limits without
/// compiling a per-generation profile. A caller with no visible participant row
/// still sees the same refusal as a graph-less generation or an unknown field.
pub fn graph_query(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    field: u32,
) -> Option<u32> {
    let Some(Ok(graph)) = crate::generation::fabric_graph_object(generation) else {
        return None;
    };
    let is_limit = boot_contracts::fabric_graph::RuntimeLimits::field_is_limit(field);
    if !is_declared_fabric_holder(generation, instance)
        && (!is_limit
            || !(0..graph.participant_count()).any(|index| {
                graph.participant(index).is_some_and(|participant| {
                    may_read_row(generation, instance, &participant.component_identity)
                })
            }))
    {
        return None;
    }
    graph.query(field)
}

/// The live-child budget this generation declares for `instance`'s executable.
///
/// CP2/B70's last manifest-derived component table. `spawn-service` sized its
/// live-child array and validated every request's `client_budget` against a
/// `CLIENT_BUDGET` its build script parsed out of one generation manifest, and
/// `dango` stated the same number from its own copy; neither component could
/// then be built against another generation. The root already reads exactly
/// this record to bound `serve_spawn`, so this discloses no new fact -- it tells
/// a caller the ceiling it is about to be admitted against.
///
/// `instance` is the caller's own index from the authenticated badge, as in
/// `resolve_binding_slot`: the request names no instance, so there is nothing to
/// forge and no other executable's budget is reachable.
///
/// `None` where the instance or its executable does not decode. A declared
/// budget of zero is answered as zero rather than refused: it is a real
/// declaration, and the authority gate on this operation (`SERVICE_SPAWN`) is
/// what separates "declared none" from "may not ask".
pub fn spawn_budget(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
) -> Option<u16> {
    let instance = generation.instance(instance).ok()?;
    let executable = generation.executable(instance.executable).ok()?;
    Some(executable.spawn_budget)
}

/// Copy participant rows `cursor..` into `out`, returning how many were written.
///
/// **What the caller sees depends on who it is, and only on that.** The graph's
/// declared fabric component reads every row, because brokering is what it is
/// declared to do. Any other instance reads *its own* rows — the ones whose
/// `component_identity` is its own — and nothing else. Both are answered from
/// the same table by the same walk; the filter is the only difference.
///
/// The self-scoped half is the rule `resolve_binding_slot` already applies to
/// bindings: a component learns what the generation declares *about it*, which
/// it knew at compile time from a generated table, and nothing about anyone
/// else. It is not a relaxation of the holder rule — a participant still cannot
/// enumerate the graph, so C8.8's per-caller route filtering stays the fabric's
/// to enforce and `sel4_visibility_check`'s "an ungranted caller inferred
/// nothing" is untouched: a component with no rows reads nothing.
///
/// `None` only when the generation embeds no graph. A caller with no rows gets
/// `Some(0)` rather than a refusal, because "no graph here" and "no rows for
/// you" are different facts and the second is one the caller already knows.
pub fn read_graph_participants(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(graph)) = crate::generation::fabric_graph_object(generation) else {
        return None;
    };
    let holder = is_declared_fabric_holder(generation, instance);
    let mut written = 0;
    let mut seen = 0;
    for index in 0..graph.participant_count() {
        let participant = graph.participant(index)?;
        if !holder && !may_read_row(generation, instance, &participant.component_identity) {
            continue;
        }
        // `cursor` counts the rows this caller may see, not rows of the table.
        // Paging over the unfiltered index would let a participant infer where
        // its rows sit among everyone else's.
        if seen < cursor {
            seen += 1;
            continue;
        }
        seen += 1;
        let end = written + GRAPH_ROW_BYTES;
        if end > out.len() || written / GRAPH_ROW_BYTES >= GRAPH_ROWS_PER_CALL {
            break;
        }
        out[written..end].copy_from_slice(graph.participant_bytes(index)?);
        written = end;
    }
    Some(written / GRAPH_ROW_BYTES)
}

pub const NETWORK_DESTINATION_ROW_BYTES: usize = boot_contracts::network_destination::ENTRY_BYTES;
pub const NETWORK_DESTINATION_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / NETWORK_DESTINATION_ROW_BYTES;

pub const NETWORK_INTERFACE_ROW_BYTES: usize = boot_contracts::network_interface::ENTRY_BYTES;
pub const NETWORK_INTERFACE_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / NETWORK_INTERFACE_ROW_BYTES;

/// Copy authenticated IO11 interface rows only to the generation's declared
/// `network-service`, on `read_network_destinations`' exact shape. Which row
/// is the caller's own is decided by the caller from its holder identity.
pub fn read_network_interface(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(interfaces)) = crate::generation::network_interface_object(generation) else {
        return None;
    };
    let caller = generation.instance(instance).ok()?;
    if caller.name != "network-service" {
        return None;
    }
    let mut written = 0;
    for index in cursor..interfaces.interface_count() {
        let end = written + NETWORK_INTERFACE_ROW_BYTES;
        if end > out.len()
            || written / NETWORK_INTERFACE_ROW_BYTES >= NETWORK_INTERFACE_ROWS_PER_CALL
        {
            break;
        }
        out[written..end].copy_from_slice(interfaces.entry_bytes(index)?);
        written = end;
    }
    Some(written / NETWORK_INTERFACE_ROW_BYTES)
}

pub const ENTROPY_AUTHORITY_ROW_BYTES: usize = boot_contracts::entropy_authority::ENTRY_BYTES;
pub const ENTROPY_AUTHORITY_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / ENTROPY_AUTHORITY_ROW_BYTES;
/// The one instance the entropy table is served to.
pub const ENTROPY_SERVICE_INSTANCE: &str = "entropy-service";

/// Copy authenticated entropy-authority rows only to the instance named
/// `entropy-service`, on `read_network_interface`'s exact shape. The root
/// draws no entropy and charges no budget.
pub fn read_entropy_authority(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(authority)) = crate::generation::entropy_authority_object(generation) else {
        return None;
    };
    let caller = generation.instance(instance).ok()?;
    copy_entropy_authority_rows(&authority, caller.name, cursor, out)
}

/// The caller gate and paging of `read_entropy_authority`, separated from the
/// generation lookup so both can be exercised against a decoded table.
pub fn copy_entropy_authority_rows(
    authority: &boot_contracts::entropy_authority::EntropyAuthority<'_>,
    caller: &str,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    if caller != ENTROPY_SERVICE_INSTANCE {
        return None;
    }
    let mut written = 0;
    for index in cursor..authority.holder_count() {
        let end = written + ENTROPY_AUTHORITY_ROW_BYTES;
        if end > out.len()
            || written / ENTROPY_AUTHORITY_ROW_BYTES >= ENTROPY_AUTHORITY_ROWS_PER_CALL
        {
            break;
        }
        out[written..end].copy_from_slice(authority.entry_bytes(index)?);
        written = end;
    }
    Some(written / ENTROPY_AUTHORITY_ROW_BYTES)
}

pub const ZENOH_GRANTS_ROW_BYTES: usize =
    slime_proto::zenoh_service_grants_table_wire::ENTRY_BYTES;
pub const ZENOH_GRANTS_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / ZENOH_GRANTS_ROW_BYTES;
/// The one instance the grants table is served to.
pub const ZENOH_GRANTS_READER_INSTANCE: &str = "zenoh-service";

/// Copy authenticated Zenoh grants rows only to the instance named `zenoh-service`, on
/// `read_entropy_authority`'s exact shape. The root decides no grant and opens no session.
pub fn read_zenoh_grants(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(table)) = crate::generation::zenoh_grants_object(generation) else {
        return None;
    };
    let caller = generation.instance(instance).ok()?;
    copy_zenoh_grants_rows(&table, caller.name, cursor, out)
}

/// The caller gate and paging of `read_zenoh_grants`, separated from the generation lookup so both
/// can be exercised against a decoded table.
pub fn copy_zenoh_grants_rows(
    table: &slime_proto::zenoh_service_grants_table::Table<'_>,
    caller: &str,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    if caller != ZENOH_GRANTS_READER_INSTANCE {
        return None;
    }
    let mut written = 0;
    for index in cursor..table.row_count() {
        let end = written + ZENOH_GRANTS_ROW_BYTES;
        if end > out.len() || written / ZENOH_GRANTS_ROW_BYTES >= ZENOH_GRANTS_ROWS_PER_CALL {
            break;
        }
        out[written..end].copy_from_slice(table.row_bytes(index)?);
        written = end;
    }
    Some(written / ZENOH_GRANTS_ROW_BYTES)
}

pub const NETWORK_APPLICATION_ROW_BYTES: usize = boot_contracts::network_application::ENTRY_BYTES;
pub const NETWORK_APPLICATION_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / NETWORK_APPLICATION_ROW_BYTES;

/// Copy authenticated application rows only to the badge-derived network service.
/// Binding resolution and application policy belong to that userspace service.
pub fn read_network_application(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let applications = crate::generation::network_application_object(generation)?;
    let caller = generation.instance(instance).ok()?;
    page_network_application(caller.name, applications, cursor, out)
}

fn page_network_application(
    reader: &str,
    applications: Result<
        boot_contracts::network_application::NetworkApplications<'_>,
        boot_contracts::network_application::DecodeError,
    >,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    if reader != "network-service" {
        return None;
    }
    let applications = applications.ok()?;
    let mut written = 0;
    for index in cursor..applications.application_count() {
        let end = written + NETWORK_APPLICATION_ROW_BYTES;
        if end > out.len()
            || written / NETWORK_APPLICATION_ROW_BYTES >= NETWORK_APPLICATION_ROWS_PER_CALL
        {
            break;
        }
        out[written..end].copy_from_slice(applications.entry_bytes(index)?);
        written = end;
    }
    Some(written / NETWORK_APPLICATION_ROW_BYTES)
}

/// Copy authenticated IO4 entries only to the generation's declared
/// `network-service`. This is identity gating, not destination policy.
pub fn read_network_destinations(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(destinations)) = crate::generation::network_destinations_object(generation) else {
        return None;
    };
    let caller = generation.instance(instance).ok()?;
    if caller.name != "network-service" {
        return None;
    }
    let mut written = 0;
    for index in cursor..destinations.destination_count() {
        let end = written + NETWORK_DESTINATION_ROW_BYTES;
        if end > out.len()
            || written / NETWORK_DESTINATION_ROW_BYTES >= NETWORK_DESTINATION_ROWS_PER_CALL
        {
            break;
        }
        out[written..end].copy_from_slice(destinations.entry_bytes(index)?);
        written = end;
    }
    Some(written / NETWORK_DESTINATION_ROW_BYTES)
}

pub const BLOCK_RING_AUTHORITY_ROW_BYTES: usize = boot_contracts::block_authority::ENTRY_BYTES;
pub const BLOCK_RING_AUTHORITY_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / BLOCK_RING_AUTHORITY_ROW_BYTES;

/// The one *executable* authorized to read the B83 authority table.
///
/// The executable rather than the instance name (B84): a plane with two disks
/// declares this same audited binary twice, under two composition-chosen
/// instance names, and both instances enforce the table. Gating on an instance
/// name would mean every such composition had to spell one blessed name or
/// patch this constant, and the property being checked is "is this the driver
/// that enforces these rows", which is a property of the code, not of the name
/// a composition happened to give one copy of it.
///
/// Still a literal rather than a manifest field, matching IO4's
/// `network-service` gate: a second, different block driver would need its own
/// declared name here, which is the review this literal forces.
pub const BLOCK_DRIVER_EXECUTABLE: &str = "virtio-blk-driver";

/// Copy authenticated B83 entries only to the generation's declared block
/// driver, and only the rows for the device that driver instance was installed
/// against. This is identity gating, not block policy: the root reads no right
/// here, because refusing a write on a read-only ring is a device decision.
///
/// Filtering by device is least authority, not convenience. Two driver
/// instances serve two disks; each enforces only its own, so handing either the
/// other's rows would disclose authority it cannot act on and could not have
/// derived. The device comes from the caller's own declared IO1 budget — the
/// same record `install_driver` bound it to — so a driver cannot ask for
/// another device's rows by asking differently.
pub fn read_block_ring_authority(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(authority)) = crate::generation::block_ring_authority_object(generation) else {
        return None;
    };
    let caller = generation.instance(instance).ok()?;
    let executable = generation.executable(caller.executable).ok()?;
    if executable.name != BLOCK_DRIVER_EXECUTABLE {
        return None;
    }
    // Which device this instance drives, from the budget that installed it. A
    // driver with no declared budget holds no device authority at all, so it
    // reads nothing rather than everything.
    let device = crate::generation::io_resource_budget_object(generation)?
        .ok()?
        .quota_for(&boot_contracts::io_resource::driver_identity(caller.name))?
        .device;
    // The cursor counts *this device's* rows, not raw table positions. Skipping
    // raw indices while returning a count of rows written would make a paging
    // caller re-request forever, because the two numbers would not advance
    // together.
    let mut matched = 0;
    let mut written = 0;
    for index in 0..authority.ring_count() {
        if authority.ring(index)?.device != device {
            continue;
        }
        matched += 1;
        if matched <= cursor {
            continue;
        }
        let end = written + BLOCK_RING_AUTHORITY_ROW_BYTES;
        if end > out.len()
            || written / BLOCK_RING_AUTHORITY_ROW_BYTES >= BLOCK_RING_AUTHORITY_ROWS_PER_CALL
        {
            break;
        }
        out[written..end].copy_from_slice(authority.entry_bytes(index)?);
        written = end;
    }
    Some(written / BLOCK_RING_AUTHORITY_ROW_BYTES)
}

/// Bytes one encoded wake-source record occupies in a `WAIT_SOURCES` reply.
///
/// The contract's own record size: the caller decodes with
/// `boot_contracts::wait_set`, so a reply laid out to any other stride would
/// decode as garbage rather than fail.
pub const WAIT_SOURCE_ROW_BYTES: usize = boot_contracts::wait_set::ENTRY_BYTES;

/// Wake-source records one `WAIT_SOURCES` call may answer.
///
/// One record is 64 bytes against the same message bound, so the answer travels
/// through the caller's transfer window and is paged. The per-waiter ceiling is
/// `MAX_SOURCES_PER_WAITER` = 9, so a full source table needs at most two calls.
pub const WAIT_SOURCE_ROWS_PER_CALL: usize =
    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / WAIT_SOURCE_ROW_BYTES;

/// Copy the caller's own wake-source records `cursor..` into `out`, returning
/// how many were written.
///
/// Self-scoped, and that is the whole authority test: the records answered are
/// the ones whose `waiter_identity` is this instance's, so a component reads
/// what the generation declares *about it* and nothing about a peer. Unlike
/// `read_graph_participants` there is no holder case at all — no component
/// brokers another's wait set, because a wait set is not a shared object.
///
/// `None` only when the generation embeds no wait-set resource. A waiter with no
/// records gets `Some(0)`, on the same rule: "no table here" and "no sources for
/// you" are different facts, and both leave the caller with nothing to register.
///
/// The records arrive in the resource's own ascending `(waiter, badge)` order,
/// which the contract fixes as the dispatch tie rule — so a waiter that drains
/// in receive order is already draining in the documented order, and paging
/// cannot reorder it.
pub fn read_wait_sources(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
    cursor: usize,
    out: &mut [u8],
) -> Option<usize> {
    let Some(Ok(sources)) = crate::generation::wait_set_object(generation) else {
        return None;
    };
    let name = generation.instance(instance).ok()?.name;
    let identity = boot_contracts::wait_set::waiter_identity(name);
    let mut written = 0;
    let mut seen = 0;
    for index in 0..sources.entry_count() {
        let entry = sources.entry(index)?;
        if entry.waiter_identity != identity {
            continue;
        }
        // `cursor` counts this waiter's own records, not rows of the table, so
        // paging cannot let a waiter infer where its sources sit among others'.
        if seen < cursor {
            seen += 1;
            continue;
        }
        seen += 1;
        let end = written + WAIT_SOURCE_ROW_BYTES;
        if end > out.len() || written / WAIT_SOURCE_ROW_BYTES >= WAIT_SOURCE_ROWS_PER_CALL {
            break;
        }
        out[written..end].copy_from_slice(sources.entry_bytes(index)?);
        written = end;
    }
    Some(written / WAIT_SOURCE_ROW_BYTES)
}
/// The caller's own C9.5 recording participation: its role, its declared record
/// capacity, and whether the generation claims it deterministic.
///
/// Self-scoped on [`read_wait_sources`]' rule, and the same reason: the entry
/// answered is the one whose `instance_identity` is this instance's, so a
/// component learns what the generation declares *about it* and nothing about a
/// peer.
///
/// The stream identity is not returned, and its absence is the authority
/// boundary rather than an omission. It is the generation's join key between two
/// participants, so answering it would name a peer relationship the caller holds
/// no capability over; what a participant needs is its own role and its own
/// bound, both of which are here. The stream the two ends actually share travels
/// as a declared shared buffer, whose authority is the buffer capability.
///
/// `None` covers both "the generation embeds no recording resource" and "it
/// names no entry for this instance", and here — unlike `read_wait_sources` —
/// they are deliberately *not* distinguished: both mean the caller makes no
/// determinism claim and has no stream, which is one answer rather than two. The
/// wait-set split exists because a waiter can act differently on an empty table
/// than on an absent one; a recording participant cannot.
pub fn read_recording_entry(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
) -> Option<(u32, u32, bool)> {
    let Some(Ok(policy)) = crate::generation::recording_policy_object(generation) else {
        return None;
    };
    let name = generation.instance(instance).ok()?.name;
    let identity = boot_contracts::recording_policy::instance_identity(name);
    let entry = policy.entry_for(&identity)?;
    Some((
        entry.role.id(),
        u32::try_from(entry.record_capacity).ok()?,
        entry.deterministic,
    ))
}

/// The caller's declared lifetime. A generation without the lifetime object,
/// or one that does not name this instance, answers bounded; a malformed object
/// was already refused at admission.
pub fn read_lifetime(
    generation: &boot_contracts::generation::Generation<'_>,
    instance: usize,
) -> boot_contracts::instance_lifetime::Lifetime {
    crate::generation::instance_lifetime(generation, instance)
}

/// The bounds `resolve_binding_slot` applies before it looks anything up.
///
/// Separated from the lookup so the guards are reachable without a decoded
/// generation: building a valid v5 generation by hand in a unit test would test
/// the encoder, not this. The lookup itself is proved on a real boot by
/// `just runtime_binding_resolution_check`, where a component resolves its own
/// slot and a name it was not granted is refused.
pub fn binding_name_admissible(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= MAX_BINDING_NAME && core::str::from_utf8(name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boot_contracts::generation::{
        SERVICE_CAPABILITY_TRANSFER, SERVICE_CLOCK, SERVICE_DIRECTORY, SERVICE_LIFECYCLE,
        SERVICE_SHARED_BUFFER, SERVICE_SPAWN, SERVICE_SUPERVISION,
    };
    use slime_proto::syscall_abi::{
        capability_table_labels, capability_transfer_labels, clock_labels, directory_labels,
        lifecycle_labels, scheduling_labels, shared_buffer_labels, spawn_labels,
        supervision_labels,
    };

    #[test]
    fn receive_synchronizes_only_valid_fast_words_and_preserves_tail() {
        for length in [0, 1, 3, 4, 5, 8] {
            let mut explicit = sel4::IpcBuffer::default();
            explicit.msg_regs_mut().fill(0xa5);
            let unrelated = sel4::IpcBuffer::default();
            let info = sel4::MessageInfoBuilder::default().length(length).build();
            let received = received_request(
                sel4::RecvWithMRs {
                    info,
                    badge: 42,
                    msg: [11, 22, 33, 44],
                },
                &mut explicit,
            );
            let count = length.min(4);
            assert_eq!(&explicit.msg_regs()[..count], &[11, 22, 33, 44][..count]);
            assert!(
                explicit.msg_regs()[count..]
                    .iter()
                    .all(|word| *word == 0xa5)
            );
            assert!(unrelated.msg_regs().iter().all(|word| *word == 0));
            assert_eq!(received.badge, 42);
            if length > FAST_MESSAGE_REGISTERS {
                assert_eq!(received.request.err(), Some(IpcError::InvalidLength));
            } else {
                let request = received.request.unwrap();
                assert_eq!(request.len, length);
                assert_eq!(request.mrs, [11, 22, 33, 44]);
            }
        }
    }

    #[test]
    fn received_vm_fault_replaces_stale_instruction_address_and_status() {
        use crate::fault::{AccessKind, FaultKind};
        let mut buffer = sel4::IpcBuffer::default();
        buffer.msg_regs_mut().fill(9);
        #[cfg(target_arch = "aarch64")]
        let status = (0x24 << 26) | (1 << 6) | 7;
        #[cfg(target_arch = "riscv64")]
        let status = 15;
        #[cfg(target_arch = "x86_64")]
        let status = 2;
        for (prefetch, expected) in [(0, AccessKind::Write), (1, AccessKind::Execute)] {
            let info = sel4::MessageInfoBuilder::default()
                .label(sel4::sys::seL4_Fault_tag::seL4_Fault_VMFault as sel4::Word)
                .length(sel4::sys::seL4_VMFault_Msg::seL4_VMFault_Length as usize)
                .build();
            let reception = received_request(
                sel4::RecvWithMRs {
                    info,
                    badge: 7,
                    msg: [0x1234, 0x20000000, prefetch, status],
                },
                &mut buffer,
            );
            let fault =
                crate::fault::normalize_fault(sel4::Fault::new(&buffer, &reception.info)).unwrap();
            assert_eq!(fault.instruction, Some(0x1234));
            assert_eq!(fault.address, Some(0x20000000));
            assert_eq!(
                fault.kind,
                FaultKind::VirtualMemory {
                    access: expected,
                    status
                }
            );
            assert_eq!(buffer.msg_regs()[4], 9);
        }
    }

    #[test]
    fn receive_preserves_service_capability_refusals() {
        let mut buffer = sel4::IpcBuffer::default();
        for info in [
            sel4::MessageInfoBuilder::default()
                .length(1)
                .extra_caps(1)
                .build(),
            sel4::MessageInfoBuilder::default()
                .length(1)
                .caps_unwrapped(1)
                .build(),
        ] {
            let reception = received_request(
                sel4::RecvWithMRs {
                    info,
                    badge: 2,
                    msg: [17, 0, 0, 0],
                },
                &mut buffer,
            );
            assert_eq!(
                reception.request.err(),
                Some(IpcError::UnsupportedCapabilityTransfer)
            );
            assert_eq!(buffer.msg_regs()[0], 17);
        }
    }

    #[test]
    fn network_application_reads_are_identity_gated_bounded_and_exact() {
        use boot_contracts::network_application::*;
        let mut bytes = [0u8; MAX_BYTES];
        bytes[OFF_HEADER_MAGIC..OFF_HEADER_MAGIC_END].copy_from_slice(&MAGIC);
        for (offset, value) in [
            (OFF_HEADER_FORMAT_VERSION, FORMAT_VERSION),
            (OFF_HEADER_HEADER_SIZE, HEADER_BYTES as u32),
            (OFF_HEADER_APPLICATION_COUNT, MAX_APPLICATIONS as u32),
            (OFF_HEADER_TOTAL_LEN, MAX_BYTES as u32),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for index in 0..MAX_APPLICATIONS {
            let start = HEADER_BYTES + index * ENTRY_BYTES;
            let row = &mut bytes[start..start + ENTRY_BYTES];
            row[OFF_ENTRY_HOLDER_IDENTITY..OFF_ENTRY_HOLDER_IDENTITY_END].fill(index as u8 + 1);
            row[OFF_ENTRY_CONTROL_BINDING..OFF_ENTRY_CONTROL_BINDING + 11]
                .copy_from_slice(b"app-control");
            row[OFF_ENTRY_PROVISION_BINDING..OFF_ENTRY_PROVISION_BINDING + 13]
                .copy_from_slice(b"app-provision");
            row[OFF_ENTRY_ROLE] = ROLE_CLIENT;
            row[OFF_ENTRY_BACKEND] = BACKEND_EXTERNAL;
            row[OFF_ENTRY_IDLE_TIMEOUT_MS..OFF_ENTRY_IDLE_TIMEOUT_MS_END]
                .copy_from_slice(&MIN_IDLE_TIMEOUT_MS.to_le_bytes());
            row[OFF_ENTRY_HOP_LIMIT] = MIN_HOP_LIMIT;
            row[OFF_ENTRY_RX_BUFFER_BYTES..OFF_ENTRY_RX_BUFFER_BYTES_END]
                .copy_from_slice(&MIN_BUFFER_BYTES.to_le_bytes());
            row[OFF_ENTRY_TX_BUFFER_BYTES..OFF_ENTRY_TX_BUFFER_BYTES_END]
                .copy_from_slice(&MIN_BUFFER_BYTES.to_le_bytes());
        }
        let table = NetworkApplications::decode(&bytes).unwrap();
        let mut out = [0xa5; MAX_APPLICATIONS * ENTRY_BYTES];
        assert_eq!(
            page_network_application("network-service", Ok(table), 0, &mut out),
            Some(NETWORK_APPLICATION_ROWS_PER_CALL)
        );
        let copied = NETWORK_APPLICATION_ROWS_PER_CALL * ENTRY_BYTES;
        assert_eq!(&out[..copied], &bytes[HEADER_BYTES..HEADER_BYTES + copied]);
        assert!(out[copied..].iter().all(|byte| *byte == 0xa5));
        assert_eq!(
            page_network_application("network-service", Ok(table), 3, &mut out),
            Some(1)
        );
        assert_eq!(&out[..ENTRY_BYTES], table.entry_bytes(3).unwrap());
        for cursor in [MAX_APPLICATIONS, usize::MAX] {
            assert_eq!(
                page_network_application("network-service", Ok(table), cursor, &mut out),
                Some(0)
            );
        }
        let before = out;
        assert_eq!(
            page_network_application("ungranted-reader", Ok(table), 0, &mut out),
            None
        );
        assert_eq!(out, before);
        assert_eq!(
            page_network_application("network-service", Ok(table), 0, &mut out[..ENTRY_BYTES - 1]),
            Some(0)
        );
        assert_eq!(out, before);
        bytes[OFF_HEADER_REQUIRED_FLAGS] = 1;
        assert_eq!(
            page_network_application(
                "network-service",
                NetworkApplications::decode(&bytes),
                0,
                &mut out
            ),
            None
        );
        assert_eq!(out, before);
    }

    /// Every declared operation routes to the mechanism that owns it. B61 moved
    /// this out of the binary so the routing is checkable without a boot; before
    /// that, a label mapped to the wrong service was observable only as a
    /// component's request being refused on a real plane.
    #[test]
    fn every_declared_label_routes_to_its_owning_service() {
        for (label, service) in [
            (lifecycle_labels::EXIT, SERVICE_LIFECYCLE),
            (lifecycle_labels::UNHEALTHY, SERVICE_LIFECYCLE),
            // C10.1: gated on the one service every launched instance declares,
            // because a private heap is a property of being a task rather than
            // of any grant.
            (lifecycle_labels::PRIVATE_MEMORY_GROW, SERVICE_LIFECYCLE),
            (spawn_labels::SPAWN, SERVICE_SPAWN),
            (supervision_labels::STATUS, SERVICE_SUPERVISION),
            (supervision_labels::DERIVE, SERVICE_SUPERVISION),
            (capability_table_labels::DROP, SERVICE_CAPABILITY_TRANSFER),
            (
                capability_table_labels::OCCUPANCY,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::RESOLVE_BINDING,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::NETWORK_DESTINATIONS_READ,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::NETWORK_INTERFACE_READ,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::NETWORK_APPLICATION_READ,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::ENTROPY_AUTHORITY_READ,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::ZENOH_GRANTS_READ,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::BLOCK_RING_AUTHORITY_READ,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_table_labels::GRAPH_QUERY,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            // B70's boot action is in the capability-table label namespace but
            // gated on lifecycle, the one service every instance declares. The
            // pairing is the point of this assertion: the namespace a label
            // sits in and the authority it needs are separate facts.
            (capability_table_labels::BOOT_ACTION, SERVICE_LIFECYCLE),
            // B70's spawn budget, in that same namespace and gated on the spawn
            // service: an instance the generation grants no spawn authority has
            // no declared budget to report.
            (capability_table_labels::SPAWN_BUDGET, SERVICE_SPAWN),
            (
                capability_transfer_labels::EXPORT,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_transfer_labels::IMPORT,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_transfer_labels::EXPORT_CANCEL,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (
                capability_transfer_labels::EXPORT_FINALIZE,
                SERVICE_CAPABILITY_TRANSFER,
            ),
            (shared_buffer_labels::CREATE, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::RELEASE, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::MAP, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::UNMAP, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::SEAL, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::LOAN, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::LOAN_MAP, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::RETURN, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::REVOKE, SERVICE_SHARED_BUFFER),
            (shared_buffer_labels::OCCUPANCY, SERVICE_SHARED_BUFFER),
            (directory_labels::DERIVE, SERVICE_DIRECTORY),
            (clock_labels::MONOTONIC_READ, SERVICE_LIFECYCLE),
            (clock_labels::TIMER_ARM, SERVICE_CLOCK),
            (clock_labels::TIMER_CANCEL, SERVICE_CLOCK),
            (clock_labels::SIMULATED_READ, SERVICE_CLOCK),
            (clock_labels::SIMULATED_ADVANCE, SERVICE_CLOCK),
            (clock_labels::RATE_READ, SERVICE_LIFECYCLE),
            // C9.5's recording participation, gated on lifecycle for
            // `WAIT_SOURCES`' reason: whether the generation claims this instance
            // deterministic is a property of being that instance, not of a grant.
            (lifecycle_labels::RECORDING_SOURCES, SERVICE_LIFECYCLE),
            (lifecycle_labels::LIFETIME_READ, SERVICE_LIFECYCLE),
        ] {
            assert_eq!(
                service_for_root_label(label),
                Some(service),
                "label {label} routed to the wrong mechanism"
            );
        }
    }

    /// B46 deleted the logical channel, wait-set, and endpoint-create operations
    /// and their labels were not reused. A component image built before that
    /// cutover still invokes them, so each must be refused rather than falling
    /// through to whichever mechanism now sits at a nearby number — a
    /// re-meaning would hand an old caller authority it never asked for.
    #[test]
    fn retired_and_unknown_labels_are_refused() {
        // The gaps `contracts/syscall-abi/v1/schema.zt` documents as retired,
        // plus the fixture label (not part of the component ABI) and values
        // outside the table entirely.
        for label in [
            0,
            1,
            2,
            6,
            7,
            8,
            10,
            11,
            14,
            16,
            17,
            18,
            19,
            20,
            // 37 was here until CP2 assigned it to `RESOLVE_BINDING`, 38 until
            // B70's `GRAPH_READ`, 39 until `GRAPH_ROUTE_INDEX`, 40 until
            // `BOOT_ACTION`, 41 until `GRAPH_QUERY`, 42 until `SPAWN_BUDGET`,
            // 43 until C10.1's `PRIVATE_MEMORY_GROW`, 44-48 until C9.1's clock
            // service, 49 until C9.2's `WAIT_SOURCES`, 50-51 until C9.3's
            // scheduling class, 52-56 until C9.4's lifecycle state and
            // restart/parameter operations, 57 until C9.5's
            // `RECORDING_SOURCES`, 58-63 and 65-68 until IO1's hardware-resource
            // service claimed them, 64 until IO4's
            // `NETWORK_DESTINATIONS_READ`, and 69 until B83's
            // `BLOCK_RING_AUTHORITY_READ`. Moving one out of this list is the
            // whole change: a number this test asserts routes nowhere and a
            // number the contract declares are the same fact stated twice, so
            // assigning a label must fail here first.
            sel4::Word::MAX,
        ] {
            assert_eq!(
                service_for_root_label(label),
                None,
                "retired or unknown label {label} was routed to a mechanism"
            );
        }
    }

    #[test]
    fn clock_request_shapes_are_exact() {
        assert_eq!(clock_request_len(clock_labels::MONOTONIC_READ), Some(0));
        assert_eq!(clock_request_len(clock_labels::SIMULATED_READ), Some(0));
        assert_eq!(clock_request_len(clock_labels::RATE_READ), Some(0));
        assert_eq!(clock_request_len(clock_labels::TIMER_ARM), Some(1));
        assert_eq!(clock_request_len(clock_labels::TIMER_CANCEL), Some(1));
        assert_eq!(clock_request_len(clock_labels::SIMULATED_ADVANCE), Some(1));
        assert_eq!(clock_request_len(lifecycle_labels::EXIT), None);
    }

    #[test]
    fn scheduling_request_shapes_are_exact() {
        assert_eq!(
            scheduling_request_len(scheduling_labels::CLASS_READ),
            Some(0)
        );
        // A slot and a class id, both required. A caller sending one word has
        // named no class and must be refused rather than defaulted.
        assert_eq!(
            scheduling_request_len(scheduling_labels::CLASS_PROMOTE),
            Some(2)
        );
        assert_eq!(scheduling_request_len(lifecycle_labels::EXIT), None);
    }

    /// C9.3's two operations reach the two services their authority stories
    /// require: the self-scoped read is gated on `lifecycle`, because the band a
    /// thread runs at is a property of being a task, and promotion is gated on
    /// `supervision`, because it names its subject through a supervision
    /// capability.
    #[test]
    fn scheduling_labels_route_to_their_declared_services() {
        assert_eq!(
            service_for_root_label(scheduling_labels::CLASS_READ),
            Some(SERVICE_LIFECYCLE)
        );
        assert_eq!(
            service_for_root_label(scheduling_labels::CLASS_PROMOTE),
            Some(SERVICE_SUPERVISION)
        );
    }

    #[test]
    fn lifecycle_request_shapes_are_exact() {
        use slime_proto::syscall_abi::supervision_labels;
        assert_eq!(lifecycle_request_len(lifecycle_labels::STATE_READ), Some(0));
        // One word, and it is the *target state*. A caller sending two has named
        // something the operation does not accept — there is no subject operand,
        // because advancing another component's state is authority no C9.4 field
        // grants — so the extra word is refused rather than ignored.
        assert_eq!(
            lifecycle_request_len(lifecycle_labels::STATE_ADVANCE),
            Some(1)
        );
        assert_eq!(
            lifecycle_request_len(supervision_labels::RESTART_ADMIT),
            Some(1)
        );
        assert_eq!(
            lifecycle_request_len(supervision_labels::PARAMETER_READ),
            Some(2)
        );
        assert_eq!(
            lifecycle_request_len(supervision_labels::PARAMETER_WRITE),
            Some(3)
        );
        // C9.5's read takes no operand at all: the caller is the badge, and
        // naming another instance's recording participation is authority no C9.5
        // field grants. A caller sending one word is refused rather than having
        // it ignored, because request shape is part of the ABI.
        assert_eq!(
            lifecycle_request_len(lifecycle_labels::RECORDING_SOURCES),
            Some(0)
        );
        assert_eq!(
            lifecycle_request_len(lifecycle_labels::LIFETIME_READ),
            Some(0)
        );
        // A label this table does not own reports no shape, so the dispatcher's
        // length guard cannot accidentally bound an unrelated operation.
        assert_eq!(lifecycle_request_len(lifecycle_labels::EXIT), None);
        assert_eq!(
            lifecycle_request_len(slime_proto::syscall_abi::scheduling_labels::CLASS_PROMOTE),
            None
        );
    }

    /// C9.4's five operations reach the two services their authority stories
    /// require: both self-scoped state operations are gated on `lifecycle`,
    /// because which state a component is in and which edge it takes are
    /// properties of being a task, and the three that name another component
    /// through a supervision capability are gated on `supervision`.
    #[test]
    fn lifecycle_labels_route_to_their_declared_services() {
        use slime_proto::syscall_abi::supervision_labels;
        for label in [
            lifecycle_labels::STATE_READ,
            lifecycle_labels::STATE_ADVANCE,
        ] {
            assert_eq!(service_for_root_label(label), Some(SERVICE_LIFECYCLE));
        }
        for label in [
            supervision_labels::RESTART_ADMIT,
            supervision_labels::PARAMETER_READ,
            supervision_labels::PARAMETER_WRITE,
        ] {
            assert_eq!(service_for_root_label(label), Some(SERVICE_SUPERVISION));
        }
    }

    /// The fixture directive shares the root endpoint but is not a component
    /// operation: it is the two-fixture boot proof's handshake. Routing it to a
    /// mechanism would expose it to any component that guessed the label.
    #[test]
    fn the_fixture_directive_is_not_a_component_service() {
        assert_eq!(
            service_for_root_label(slime_proto::syscall_abi::fixture_labels::DIRECTIVE),
            None
        );
    }

    /// A binding name must be non-empty, fit one message, and be UTF-8.
    ///
    /// Each is a refusal a component could otherwise turn into a lookup: an empty
    /// name matches no grant but would still walk the table, a name longer than
    /// the envelope would be a truncated *different* name, and non-UTF-8 bytes
    /// cannot name a grant at all. Refusing before the lookup is what keeps the
    /// operation's cost a function of the generation rather than of the request.
    #[test]
    fn binding_names_are_bounded_before_any_lookup() {
        assert!(binding_name_admissible(b"console-output"));
        assert!(binding_name_admissible(&[b'a'; MAX_BINDING_NAME]));
        assert!(!binding_name_admissible(b""));
        assert!(!binding_name_admissible(&[b'a'; MAX_BINDING_NAME + 1]));
        // A lone continuation byte: valid length, not a valid name.
        assert!(!binding_name_admissible(&[0x80]));
    }

    /// The name bound is the message envelope's, not the string table's.
    ///
    /// `MAX_STRING_BYTES` is 255 and a request carries 64 bytes, so binding the
    /// name to the string table would admit names no request could deliver and
    /// silently compare a truncation.
    #[test]
    fn binding_name_bound_fits_one_request() {
        assert_eq!(MAX_BINDING_NAME, MAX_MESSAGE_BYTES);
        assert!(MAX_BINDING_NAME <= boot_contracts::generation::MAX_STRING_BYTES);
    }

    /// The two layout namespaces are distinct domains, and neither collides with
    /// the other for the same text.
    ///
    /// This is what lets one query serve grants and layout roles without a layout
    /// entry shadowing a grant. The unprefixed-name version of this operation was
    /// written twice and failed on real boots twice: `console` is a layout
    /// executable at slot 1 while `init-console` is a grant at the same slot, and
    /// a flat lookup answered a channel question with an executable slot. The
    /// prefix makes the caller state which table it means, so the domains below
    /// must genuinely differ.
    #[test]
    fn layout_namespaces_are_distinct_domains() {
        use boot_contracts::boot_layout::{channel_identity, component_identity};
        assert_ne!(component_identity("console"), channel_identity("console"));
        assert_ne!(
            component_identity("console-output"),
            channel_identity("console-output")
        );
        // And a prefixed request never matches the grant name it contains, so a
        // grant called `executable:x` could not be reached as a layout role.
        assert!(binding_name_admissible(b"executable:console"));
        assert!(binding_name_admissible(b"channel:console-output"));
    }

    /// Every `capabilityKind` the manifest can spell decodes, and nothing else
    /// does.
    ///
    /// The role query is only manifest-independent if it speaks the manifest's own
    /// vocabulary. A kind this table missed would be unaskable while looking
    /// askable, and an unknown kind must be no answer rather than a default, since
    /// defaulting would hand out a capability of the wrong type.
    #[test]
    fn every_manifest_capability_kind_is_askable() {
        use boot_contracts::generation::CapabilityKind;
        for (spelling, kind) in [
            ("endpoint", CapabilityKind::Endpoint),
            ("executable", CapabilityKind::Executable),
            ("sharedBufferFactory", CapabilityKind::SharedBufferFactory),
            ("directory", CapabilityKind::Directory),
            ("input", CapabilityKind::Input),
            ("supervision", CapabilityKind::Supervision),
            ("sharedBuffer", CapabilityKind::SharedBuffer),
            ("loan", CapabilityKind::Loan),
        ] {
            assert_eq!(capability_kind_named(spelling), Some(kind), "{spelling}");
        }
        assert_eq!(capability_kind_named("Endpoint"), None);
        assert_eq!(capability_kind_named(""), None);
        assert_eq!(capability_kind_named("notAKind"), None);
    }

    /// Rights names come from the schema, so the generated lookup agrees with the
    /// generated constants.
    ///
    /// Both sides are rendered from `rightBits` in
    /// `contracts/generation/v5/gen_rust.zt`; this asserts the pairing rather than
    /// trusting that two emitters stayed in step.
    #[test]
    fn manifest_right_spellings_match_their_bits() {
        use boot_contracts::generation::{
            RIGHT_BUFFER_CREATE, RIGHT_EXEC, RIGHT_INPUT_READ, RIGHT_RECV, RIGHT_SEND, right_named,
        };
        assert_eq!(right_named("send"), Some(RIGHT_SEND));
        assert_eq!(right_named("recv"), Some(RIGHT_RECV));
        assert_eq!(right_named("exec"), Some(RIGHT_EXEC));
        assert_eq!(right_named("bufferCreate"), Some(RIGHT_BUFFER_CREATE));
        assert_eq!(right_named("inputRead"), Some(RIGHT_INPUT_READ));
        // B90 retired both block rights, so their manifest spellings are now
        // unaskable rather than mapped to a reserved bit.
        assert_eq!(right_named("blockRead"), None);
        assert_eq!(right_named("blockWrite"), None);
        // Rust spellings are not manifest spellings, and only the latter is asked.
        assert_eq!(right_named("RIGHT_SEND"), None);
        assert_eq!(right_named("buffer_create"), None);
        assert_eq!(right_named(""), None);
    }

    /// An ambiguous role parses but resolves to nothing, and the refusal is not
    /// an accident of parsing.
    ///
    /// This is a non-vacuous pairing (B67): the same spelling that must be
    /// refused when several bindings match is well-formed. The frozen Dango
    /// composition supplied the observed multi-endpoint case; B70 subsequently
    /// gave the request endpoint a stable name, so the active service asks by
    /// name and role ambiguity remains a refusal rather than a guessed slot.
    #[test]
    fn an_ambiguous_role_is_well_formed_yet_unanswerable() {
        use boot_contracts::generation::{CapabilityKind, right_named};
        // Every part of `kind:endpoint+send,recv` decodes, so nothing about the
        // spelling explains a `None`.
        assert_eq!(
            capability_kind_named("endpoint"),
            Some(CapabilityKind::Endpoint)
        );
        assert!(right_named("send").is_some());
        assert!(right_named("recv").is_some());
        // And an unknown right does not silently widen the query to "any endpoint":
        // it must be refused, or a misspelling would match the first endpoint bound.
        assert_eq!(right_named("snd"), None);
    }

    /// The notification axis is its own namespace, and its role suffix is
    /// closed.
    ///
    /// `notificationBindings` is a separate declaration from capability grants,
    /// and one grant binds a slot in *both* peers, so a bare name is answered
    /// per-holder rather than globally. The suffix vocabulary is the manifest's
    /// own `signal`/`wait`; anything else must be refused rather than dropped,
    /// because silently ignoring it answers a different question than the caller
    /// asked — the failure mode this whole operation has been bitten by twice.
    #[test]
    fn notification_names_are_their_own_namespace() {
        // The prefix is admissible as a name, so refusal can only come from the
        // lookup rather than from the bounds check.
        assert!(binding_name_admissible(
            b"notification:fabric-publisher-telemetry-ready"
        ));
        assert!(binding_name_admissible(
            b"notification:fabric-publisher-telemetry-ready+wait"
        ));
        // A notification grant name is not a capability grant name: the two
        // tables are declared separately, so an unprefixed lookup must not reach
        // this one.
        assert!(!"fabric-publisher-telemetry-ready".starts_with("notification:"));
        // `kind:` and `notification:` cannot both claim one name.
        assert!(!"notification:x".starts_with("kind:"));
        assert!(!"kind:endpoint".starts_with("notification:"));
    }

    /// The name-free notification query, and why it must require a role.
    ///
    /// A service declared twice — one instance per device, which is how a plane
    /// with two disks is composed since IO1 grants one device per driver — is
    /// bound to differently-named notification grants, because grant names are
    /// globally unique and each grant has exactly one waiter. A driver spelling
    /// one name serves only the instance that received it. `@<ordinal>+<role>`
    /// asks by position in the caller's *own* role-filtered bindings instead.
    ///
    /// A bare `@0` with no role is refused: "my first binding" spans two roles
    /// and identifies no slot, which is the same ambiguity rule every other axis
    /// in this operation follows.
    #[test]
    fn the_ordinal_notification_query_requires_a_role() {
        assert!(binding_name_admissible(b"notification:@0+wait"));
        assert!(binding_name_admissible(b"notification:@1+signal"));
        // An ordinal is not a grant name, so a grant literally named `@0` could
        // not be reached by this query and vice versa — the namespaces stay
        // disjoint by the `@` sigil rather than by convention.
        assert!("@0".starts_with('@'));
        assert!(!"io-block-request-ready".starts_with('@'));
    }

    /// The minted-binding axis is its own namespace too, disjoint from grants
    /// and notifications.
    ///
    /// `mintedBindings` is a third declaration table -- a slot the generation
    /// fixes for an object its holder's *owner* creates at runtime, because a
    /// supervision handle cannot exist before the task it names. Its names are
    /// not drawn from the grant or notification pools, so `minted:` must not
    /// silently answer from either of those tables, the same shadowing every
    /// other prefix here exists to prevent.
    #[test]
    fn minted_binding_names_are_their_own_namespace() {
        assert!(binding_name_admissible(
            b"minted:fabric-publisher-supervision"
        ));
        assert!(!"fabric-publisher-supervision".starts_with("minted:"));
        assert!(!"minted:x".starts_with("kind:"));
        assert!(!"minted:x".starts_with("notification:"));
        assert!(!"kind:endpoint".starts_with("minted:"));
    }

    /// The owner-scoped view of `mintedBindings` is a distinct namespace from
    /// the holder-scoped one, and the two prefixes cannot claim one name.
    ///
    /// One minted record names two instances: the `holder` whose slot it fixes
    /// and the `owner` who creates the object and supplies it at spawn. Which
    /// end asks changes the answer, so `owned-minted:` cannot be a synonym for
    /// `minted:`. The property that matters for dispatch is that the arms are
    /// unreachable from each other: `owned-minted:x` must not be routed by the
    /// `minted:` arm, which is what the prefix test below fixes -- the arms are
    /// matched in order and a name starting with `owned-minted:` does not start
    /// with `minted:`.
    #[test]
    fn owned_minted_names_are_their_own_namespace() {
        assert!(binding_name_admissible(
            b"owned-minted:fabric-intruder-supervision"
        ));
        // The dispatch property. If this were false the holder arm would answer
        // an owner's question against the wrong instance index.
        assert!(!"owned-minted:fabric-intruder-supervision".starts_with("minted:"));
        // ...and the reverse, so the owner arm cannot claim a holder's name.
        assert!(!"minted:fabric-intruder-supervision".starts_with("owned-minted:"));
        // Unprefixed grant names reach neither.
        assert!(!"fabric-intruder-supervision".starts_with("owned-minted:"));
        assert!(!"owned-minted:x".starts_with("kind:"));
        assert!(!"owned-minted:x".starts_with("notification:"));
    }

    /// A table of `count` hardware holders named `holder-<n>`, in canonical
    /// identity order, written into `bytes`; returns its length.
    fn entropy_table(count: usize, bytes: &mut [u8]) -> usize {
        use boot_contracts::entropy_authority as ea;
        const NAMES: [&str; 10] = [
            "holder-0", "holder-1", "holder-2", "holder-3", "holder-4", "holder-5", "holder-6",
            "holder-7", "holder-8", "holder-9",
        ];
        let mut entries = [[0u8; ea::ENTRY_BYTES]; 10];
        for (entry, name) in entries.iter_mut().zip(NAMES).take(count) {
            entry[ea::OFF_ENTRY_HOLDER_IDENTITY..ea::OFF_ENTRY_HOLDER_IDENTITY_END]
                .copy_from_slice(&ea::holder_identity(name));
            entry[ea::OFF_ENTRY_HOLDER_NAME..ea::OFF_ENTRY_HOLDER_NAME + name.len()]
                .copy_from_slice(name.as_bytes());
            entry[ea::OFF_ENTRY_HOLDER_NAME_LEN] = name.len() as u8;
            entry[ea::OFF_ENTRY_SOURCE] = ea::SOURCE_HARDWARE;
            entry[ea::OFF_ENTRY_BYTE_BUDGET..ea::OFF_ENTRY_BYTE_BUDGET_END]
                .copy_from_slice(&96u32.to_le_bytes());
        }
        entries[..count].sort_unstable();
        bytes[..ea::HEADER_BYTES].copy_from_slice(&ea::header(count).unwrap());
        for (index, entry) in entries[..count].iter().enumerate() {
            let at = ea::HEADER_BYTES + index * ea::ENTRY_BYTES;
            bytes[at..at + ea::ENTRY_BYTES].copy_from_slice(entry);
        }
        ea::HEADER_BYTES + count * ea::ENTRY_BYTES
    }

    #[test]
    fn entropy_authority_rows_are_served_only_to_the_entropy_service() {
        use boot_contracts::entropy_authority::EntropyAuthority;
        let mut bytes = [0u8; boot_contracts::entropy_authority::MAX_BYTES];
        let len = entropy_table(3, &mut bytes);
        let table = EntropyAuthority::decode(&bytes[..len]).unwrap();
        let mut out = [0u8; ENTROPY_AUTHORITY_ROWS_PER_CALL * ENTROPY_AUTHORITY_ROW_BYTES];
        for caller in [
            "entropy-probe",
            "entropy-hw-a",
            "virtio-rng-driver",
            "entropy-service2",
            "",
        ] {
            assert_eq!(
                copy_entropy_authority_rows(&table, caller, 0, &mut out),
                None,
                "{caller}"
            );
        }
        assert!(
            out.iter().all(|byte| *byte == 0),
            "a refused caller receives no byte"
        );
        assert_eq!(
            copy_entropy_authority_rows(&table, "entropy-service", 0, &mut out),
            Some(3)
        );
        for index in 0..3 {
            let at = index * ENTROPY_AUTHORITY_ROW_BYTES;
            assert_eq!(
                &out[at..at + ENTROPY_AUTHORITY_ROW_BYTES],
                table.entry_bytes(index).unwrap()
            );
        }
    }

    #[test]
    fn entropy_authority_pages_by_entry_cursor_within_the_staged_bound() {
        use boot_contracts::entropy_authority::EntropyAuthority;
        assert_eq!(ENTROPY_AUTHORITY_ROWS_PER_CALL, 9);
        let mut bytes = [0u8; boot_contracts::entropy_authority::MAX_BYTES];
        let len = entropy_table(10, &mut bytes);
        let table = EntropyAuthority::decode(&bytes[..len]).unwrap();
        let mut out = [0u8; 2 * ENTROPY_AUTHORITY_ROWS_PER_CALL * ENTROPY_AUTHORITY_ROW_BYTES];
        let service = ENTROPY_SERVICE_INSTANCE;
        assert_eq!(
            copy_entropy_authority_rows(&table, service, 0, &mut out),
            Some(9)
        );
        assert_eq!(
            copy_entropy_authority_rows(&table, service, 9, &mut out),
            Some(1)
        );
        assert_eq!(
            &out[..ENTROPY_AUTHORITY_ROW_BYTES],
            table.entry_bytes(9).unwrap()
        );
        assert_eq!(
            copy_entropy_authority_rows(&table, service, 10, &mut out),
            Some(0)
        );
        assert_eq!(
            copy_entropy_authority_rows(&table, service, usize::MAX, &mut out),
            Some(0)
        );
        let mut short = [0u8; 2 * ENTROPY_AUTHORITY_ROW_BYTES + ENTROPY_AUTHORITY_ROW_BYTES / 2];
        assert_eq!(
            copy_entropy_authority_rows(&table, service, 0, &mut short),
            Some(2)
        );
        assert_eq!(
            copy_entropy_authority_rows(&table, service, 0, &mut []),
            Some(0)
        );
    }

    trait ConcatInto {
        fn concat_into<const N: usize>(&self) -> [u8; N];
    }

    impl ConcatInto for [&[u8]; 2] {
        fn concat_into<const N: usize>(&self) -> [u8; N] {
            let mut out = [0u8; N];
            let mut at = 0;
            for part in self {
                out[at..at + part.len()].copy_from_slice(part);
                at += part.len();
            }
            assert_eq!(at, N, "the parts fill the array");
            out
        }
    }

    /// A table of `count` rows, holder `holder-<n>`, each holding the key `0/zenoh/<n>` with both rights,
    /// written into `bytes`; returns its length. The rows are in the table's sort order.
    fn zenoh_grants_table(count: usize, bytes: &mut [u8]) -> usize {
        use slime_proto::zenoh_service_grants_table_wire as wire;
        let header = wire::WireGrantsHeader {
            magic: wire::TABLE_MAGIC,
            format_version: wire::FORMAT_VERSION,
            header_size: wire::HEADER_BYTES as u32,
            required_flags: 0,
            row_count: count as u32,
            total_len: (wire::HEADER_BYTES + count * wire::ENTRY_BYTES) as u32,
        };
        bytes[..wire::HEADER_BYTES].copy_from_slice(&header.encode());
        for index in 0..count {
            let digits = [b'0' + (index / 10) as u8, b'0' + (index % 10) as u8];
            let name = [b"holder-".as_slice(), &digits].concat_into::<9>();
            let key = [b"0/zenoh/".as_slice(), &digits].concat_into::<10>();
            let mut holder_name = [0u8; 32];
            holder_name[..name.len()].copy_from_slice(&name);
            let mut key_bytes = [0u8; 129];
            key_bytes[..key.len()].copy_from_slice(&key);
            let entry = wire::WireGrantsEntry {
                holder_name,
                holder_name_len: name.len() as u8,
                rights: wire::KNOWN_RIGHTS as u8,
                key_len: key.len() as u16,
                key: key_bytes,
                reserved: [0; 3],
            };
            let at = wire::HEADER_BYTES + index * wire::ENTRY_BYTES;
            bytes[at..at + wire::ENTRY_BYTES].copy_from_slice(&entry.encode());
        }
        wire::HEADER_BYTES + count * wire::ENTRY_BYTES
    }

    #[test]
    fn zenoh_grants_rows_are_served_only_to_the_zenoh_service() {
        use slime_proto::zenoh_service_grants_table::Table;
        let mut bytes = [0u8; 4 * 1024];
        let len = zenoh_grants_table(3, &mut bytes);
        let table = Table::decode(&bytes[..len]).unwrap();
        let mut out = [0u8; ZENOH_GRANTS_ROWS_PER_CALL * ZENOH_GRANTS_ROW_BYTES];
        for caller in [
            "ros2-demo-publisher",
            "zenoh-service2",
            "zenoh",
            "entropy-service",
            "",
        ] {
            assert_eq!(
                copy_zenoh_grants_rows(&table, caller, 0, &mut out),
                None,
                "{caller}"
            );
        }
        assert!(
            out.iter().all(|byte| *byte == 0),
            "a refused caller receives no byte"
        );
        assert_eq!(
            copy_zenoh_grants_rows(&table, ZENOH_GRANTS_READER_INSTANCE, 0, &mut out),
            Some(3)
        );
        for index in 0..3 {
            let at = index * ZENOH_GRANTS_ROW_BYTES;
            assert_eq!(
                &out[at..at + ZENOH_GRANTS_ROW_BYTES],
                table.row_bytes(index).unwrap()
            );
        }
    }

    #[test]
    fn zenoh_grants_pages_by_row_cursor_within_the_staged_bound() {
        use slime_proto::zenoh_service_grants_table::Table;
        assert_eq!(ZENOH_GRANTS_ROW_BYTES, 168);
        assert_eq!(ZENOH_GRANTS_ROWS_PER_CALL, 6);
        let mut bytes = [0u8; 4 * 1024];
        let len = zenoh_grants_table(7, &mut bytes);
        let table = Table::decode(&bytes[..len]).unwrap();
        let mut out = [0u8; 2 * ZENOH_GRANTS_ROWS_PER_CALL * ZENOH_GRANTS_ROW_BYTES];
        let service = ZENOH_GRANTS_READER_INSTANCE;
        assert_eq!(copy_zenoh_grants_rows(&table, service, 0, &mut out), Some(6));
        assert_eq!(copy_zenoh_grants_rows(&table, service, 6, &mut out), Some(1));
        assert_eq!(&out[..ZENOH_GRANTS_ROW_BYTES], table.row_bytes(6).unwrap());
        assert_eq!(copy_zenoh_grants_rows(&table, service, 7, &mut out), Some(0));
        assert_eq!(
            copy_zenoh_grants_rows(&table, service, usize::MAX, &mut out),
            Some(0)
        );
        let mut short = [0u8; 2 * ZENOH_GRANTS_ROW_BYTES + ZENOH_GRANTS_ROW_BYTES / 2];
        assert_eq!(copy_zenoh_grants_rows(&table, service, 0, &mut short), Some(2));
        assert_eq!(copy_zenoh_grants_rows(&table, service, 0, &mut []), Some(0));
    }
}
