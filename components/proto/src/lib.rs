#![no_std]

// Protocol modules are generated from contracts/*/v1 schemas.
pub mod block;
pub mod block_v2;
pub mod capability_transfer;
pub mod component;
pub mod fabric_call;
pub mod fabric_operation;
pub mod fabric_qos;
pub mod fabric_ring;
pub mod fabric_stream;
pub mod fabric_time;
pub mod fabric_trace;
pub mod fabric_visibility;
pub mod fs;
pub mod generation;
pub mod interface_schema;
pub mod io_queue;
pub mod io_queue_ring;
// IO0 proof harnesses. Compiled only by Kani, which is why they may name
// crate-private helpers: the `kani` cfg is never set for a product build, so
// this module does not exist in any shipped artifact. Driven through
// `verification/io-proofs/Cargo.toml`, which compiles this very file.
#[cfg(kani)]
mod io_queue_proofs;
pub mod link_device;
pub mod mavlink;
pub mod mavlink_heartbeat;
pub mod network_service;
pub mod powerbox;
pub mod private_memory_probe;
pub mod pwm_servo;
pub mod recording_stream;
pub mod ring;
pub mod sample_descriptor;
pub mod serial_device;
pub mod spawn;
pub mod spawn_arguments;
pub mod store;
pub mod syscall_abi;
pub mod trace_sink;
pub mod zenoh_profile;

pub fn valid_fs_request(request: &fs::WireFsRequest) -> bool {
    let name_len = request.name_len as usize;
    let base_valid = request.magic == fs::FS_MAGIC
        && request.version == fs::FORMAT_VERSION
        && matches!(
            request.op,
            fs::OP_LIST | fs::OP_READ | fs::OP_WRITE | fs::OP_DERIVE
        )
        && request.flags == 0
        && request.reserved0 == 0
        && name_len <= fs::MAX_NAME_BYTES
        && request.name[name_len..].iter().all(|byte| *byte == 0)
        && valid_name(&request.name[..name_len], request.op == fs::OP_LIST);
    if !base_valid {
        return false;
    }
    let zero_hash =
        request.hash0 == 0 && request.hash1 == 0 && request.hash2 == 0 && request.hash3 == 0;
    match request.op {
        fs::OP_LIST | fs::OP_READ | fs::OP_DERIVE => request.payload_len == 0 && zero_hash,
        fs::OP_WRITE => request.payload_len <= 32 * 1024 && !zero_hash,
        _ => false,
    }
}

pub fn valid_fs_reply(reply: &fs::WireFsReply) -> bool {
    reply.magic == fs::FS_MAGIC
        && reply.version == fs::FORMAT_VERSION
        && reply.entry_count as usize <= fs::MAX_ENTRIES
        && reply.reserved == 0
}
fn valid_name(name: &[u8], allow_empty: bool) -> bool {
    if name.is_empty() {
        return allow_empty;
    }
    name != b"."
        && name != b".."
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
}

pub fn valid_powerbox_request(request: &powerbox::WirePowerboxRequest) -> bool {
    let purpose_len = request.purpose_len as usize;
    request.magic == powerbox::POWERBOX_MAGIC
        && request.version == powerbox::FORMAT_VERSION
        && request.object_kind == powerbox::OBJECT_KIND_FILE
        && request.reserved0 == 0
        && request.reserved.iter().all(|byte| *byte == 0)
        && purpose_len > 0
        && purpose_len <= powerbox::MAX_PURPOSE_BYTES
        && request.purpose[purpose_len..].iter().all(|byte| *byte == 0)
        && request.purpose[..purpose_len]
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        && request.requested_rights != 0
}

pub fn valid_powerbox_reply(reply: &powerbox::WirePowerboxReply) -> bool {
    if reply.magic != powerbox::POWERBOX_MAGIC
        || reply.version != powerbox::FORMAT_VERSION
        || reply.object_kind != powerbox::OBJECT_KIND_FILE
        || reply.reserved0 != 0
        || reply.purpose_len as usize > reply.purpose.len()
        || reply.purpose[reply.purpose_len as usize..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return false;
    }
    match reply.flags {
        powerbox::REPLY_FLAG_SELECTED => {
            reply.status == 0 && reply.granted_rights != 0 && reply.event_id != 0
        }
        powerbox::REPLY_FLAG_CANCELLED => {
            reply.status == 0 && reply.granted_rights == 0 && reply.event_id == 0
        }
        _ => reply.status < 0 && reply.granted_rights == 0 && reply.event_id == 0,
    }
}

pub fn valid_spawn_request(request: &spawn::WireSpawnRequest) -> bool {
    let lengths = spawn_arguments::argument_lengths(request);
    let count = usize::from(request.argument_count);
    if request.magic != spawn::SPAWN_MAGIC
        || request.version != spawn::FORMAT_VERSION
        || request.reserved.iter().any(|byte| *byte != 0)
        || count > spawn::MAX_ARGUMENTS
        || usize::from(request.argument_bytes) > spawn::MAX_ARGUMENT_BYTES
        || lengths[count..].iter().any(|length| *length != 0)
        || lengths
            .iter()
            .map(|length| usize::from(*length))
            .sum::<usize>()
            != usize::from(request.argument_bytes)
    {
        return false;
    }
    if request.flags == spawn::REQUEST_FLAG_WAIT || request.flags == spawn::REQUEST_FLAG_SHUTDOWN {
        return request.command_len == 0
            && request.argument_count == 0
            && request.environment_count == 0
            && request.capability_roles == 0
            && request.command.iter().all(|byte| *byte == 0)
            && request.environment.iter().all(|byte| *byte == 0)
            && request.grant_rights == 0
            && ((request.flags == spawn::REQUEST_FLAG_WAIT && request.supervision_handle != 0)
                || (request.flags == spawn::REQUEST_FLAG_SHUTDOWN
                    && request.supervision_handle == 0));
    }
    (request.flags == 0 || request.flags == spawn::REQUEST_FLAG_DETACHED)
        && request.command_len > 0
        && usize::from(request.command_len) <= spawn::MAX_COMMAND_BYTES
        && request.command[usize::from(request.command_len)..]
            .iter()
            .all(|byte| *byte == 0)
        && request.environment_count as usize <= spawn::MAX_ENVIRONMENT
        && packed_fields_valid(&request.environment, request.environment_count as usize)
        && request.supervision_handle == 0
        && (request.flags != spawn::REQUEST_FLAG_DETACHED || request.client_budget == 0)
}

fn packed_fields_valid<const N: usize>(bytes: &[u8; N], count: usize) -> bool {
    let mut offset = 0;
    for _ in 0..count {
        let Some(length) = bytes.get(offset).copied().map(usize::from) else {
            return false;
        };
        if length == 0 || offset + 1 + length > bytes.len() {
            return false;
        }
        offset += 1 + length;
    }
    bytes[offset..].iter().all(|byte| *byte == 0)
}

pub fn valid_spawn_reply(reply: &spawn::WireSpawnReply) -> bool {
    reply.magic == spawn::SPAWN_MAGIC && reply.version == spawn::FORMAT_VERSION
}

/// Structural validity of a pwm-servo request: the protocol identity, no
/// flags (none are defined), and zeroed reserved bytes. The channel, period,
/// and pulse bounds are deliberately not checked here: the driver answers each
/// with its own status so a client learns which bound it crossed.
pub fn valid_pwm_servo_request(request: &pwm_servo::WirePwmServoRequest) -> bool {
    request.magic == pwm_servo::PWM_SERVO_MAGIC
        && request.version == pwm_servo::FORMAT_VERSION
        && request.flags == 0
        && request.reserved.iter().all(|byte| *byte == 0)
}

/// A pwm-servo reply carries the protocol identity and one of its statuses.
pub fn valid_pwm_servo_reply(reply: &pwm_servo::WirePwmServoReply) -> bool {
    reply.magic == pwm_servo::PWM_SERVO_MAGIC
        && reply.version == pwm_servo::FORMAT_VERSION
        && matches!(
            reply.status,
            pwm_servo::STATUS_OK
                | pwm_servo::STATUS_BAD_CHANNEL
                | pwm_servo::STATUS_BAD_PERIOD
                | pwm_servo::STATUS_BAD_PULSE
                | pwm_servo::STATUS_NO_DEVICE
                | pwm_servo::STATUS_DEVICE_ERROR
                | pwm_servo::STATUS_MALFORMED
        )
}

/// Structural validity of a serial-device request: the protocol identity, the
/// one defined operation, no flags, a length the payload can hold, and zeroed
/// reserved storage and unused payload, so every admissible encoding is
/// canonical.
pub fn valid_serial_request(request: &serial_device::WireSerialRequest) -> bool {
    let length = request.length as usize;
    request.magic == serial_device::SERIAL_MAGIC
        && request.version == serial_device::FORMAT_VERSION
        && request.op == serial_device::OP_WRITE
        && request.flags & !serial_device::KNOWN_REQUEST_FLAGS == 0
        && (1..=serial_device::MAX_PAYLOAD).contains(&length)
        && request.reserved.iter().all(|byte| *byte == 0)
        && request.payload[length..].iter().all(|byte| *byte == 0)
}

/// A serial-device reply carries the protocol identity, one of its statuses,
/// and a byte count the request could have carried.
pub fn valid_serial_reply(reply: &serial_device::WireSerialReply) -> bool {
    reply.magic == serial_device::SERIAL_MAGIC
        && reply.version == serial_device::FORMAT_VERSION
        && reply.bytes_written as usize <= serial_device::MAX_PAYLOAD
        && matches!(
            reply.status,
            serial_device::STATUS_OK
                | serial_device::STATUS_BAD_LENGTH
                | serial_device::STATUS_BAD_OP
                | serial_device::STATUS_NO_DEVICE
                | serial_device::STATUS_DEVICE_ERROR
                | serial_device::STATUS_TIMEOUT
                | serial_device::STATUS_MALFORMED
        )
}

/// Validate a versioned sample descriptor before a receiver maps the loaned
/// bytes or allocates receiver state. Every field that could steer a mapping or
/// allocation is bounded here: version, known flags, capability kind, a live
/// loan identity, a page-aligned in-bounds offset/length within `MAX_SAMPLE_BYTES`,
/// a non-zero type identity, and zeroed reserved bytes. `expected_type` binds the
/// descriptor to the receiver's declared type; `expected_loan` binds it to the
/// exact transferred loan the receiver holds.
pub fn valid_sample_descriptor(
    descriptor: &sample_descriptor::WireSampleDescriptor,
    expected_loan: u64,
    expected_type: u64,
    page_size: u64,
) -> bool {
    if descriptor.magic != sample_descriptor::SAMPLE_DESCRIPTOR_MAGIC
        || descriptor.version != sample_descriptor::FORMAT_VERSION
    {
        return false;
    }
    if descriptor.capability_kind != sample_descriptor::CAPABILITY_KIND_LOAN {
        return false;
    }
    if descriptor.flags & !sample_descriptor::KNOWN_FLAGS != 0 {
        return false;
    }
    if descriptor.reserved.iter().any(|byte| *byte != 0) {
        return false;
    }
    if descriptor.loan_id == 0 || descriptor.loan_id != expected_loan {
        return false;
    }
    if descriptor.type_identity == 0 || descriptor.type_identity != expected_type {
        return false;
    }
    if page_size == 0 || !page_size.is_power_of_two() {
        return false;
    }
    let Some(end) = descriptor.offset.checked_add(descriptor.length) else {
        return false;
    };
    descriptor.length != 0
        && descriptor.offset.is_multiple_of(page_size)
        && descriptor.length.is_multiple_of(page_size)
        && end <= sample_descriptor::MAX_SAMPLE_BYTES as u64
}

/// Validate a capability-transfer descriptor a component received alongside a
/// moved capability (C8.3), binding it to the role the receiver expects.
///
/// The kernel already enforced the structural rules and installed exactly
/// `rights_mask` (minus `RIGHT_TRANSFER` without `FLAG_RETAIN_TRANSFER`), so a
/// descriptor cannot overstate what arrived. What the kernel cannot check is
/// the fabric's own role binding: it knows nothing of routes or directions.
/// This checks that half — the descriptor names the exact
/// (route identity, direction) edge the receiver was provisioned for, and
/// carries the object kind that role implies.
pub fn valid_capability_transfer(
    descriptor: &capability_transfer::WireCapabilityTransfer,
    expected_route: &[u8; 32],
    expected_direction: u32,
    expected_kind: u32,
) -> bool {
    descriptor.magic == capability_transfer::CAPABILITY_TRANSFER_MAGIC
        && descriptor.version == capability_transfer::FORMAT_VERSION
        && descriptor.status == 0
        && descriptor.flags & !capability_transfer::KNOWN_FLAGS == 0
        && descriptor.rights_mask != 0
        && descriptor.object_kind == expected_kind
        && descriptor.direction == expected_direction
        && descriptor.route_identity == *expected_route
        && *expected_route != [0; 32]
}

/// Structural validity of a fabric provisioning request, before the service
/// looks at anything it claims.
///
/// Deliberately shallow: the route name, direction, and type identity a
/// request carries are caller-supplied and grant nothing. The fabric
/// authenticates by the control endpoint the request arrived on and answers
/// from the generation graph, so this only rejects bytes that are not a
/// request at all.
pub fn valid_fabric_request(request: &capability_transfer::WireFabricRequest) -> bool {
    request.magic == capability_transfer::FABRIC_REQUEST_MAGIC
        && request.version == capability_transfer::FORMAT_VERSION
        && request.flags == 0
        && request.reserved.iter().all(|byte| *byte == 0)
        && (request.route_name_len as usize) <= capability_transfer::MAX_ROUTE_NAME_BYTES
        && request.route_name[request.route_name_len as usize..]
            .iter()
            .all(|byte| *byte == 0)
}
/// Structural validity of one C8.8 introspection page request. The cursor is a
/// bounded `u8` by construction; the service filters it against the caller's
/// generation-derived view and returns the same terminal record for an empty
/// view and an out-of-range cursor.
pub fn valid_visibility_request(request: &fabric_visibility::WireVisibilityRequest) -> bool {
    request.magic == fabric_visibility::VISIBILITY_REQUEST_MAGIC
        && request.version == fabric_visibility::FORMAT_VERSION
        && request.flags & !fabric_visibility::KNOWN_REQUEST_FLAGS == 0
        && request.reserved.iter().all(|byte| *byte == 0)
}

/// Validate a route page returned by the read-only graph service. An end page
/// carries no graph-dependent bytes; this is what prevents an ungranted caller
/// from learning protected counts or identities through error detail.
pub fn valid_visibility_route_record(
    record: &fabric_visibility::WireVisibilityRouteRecord,
) -> bool {
    if record.magic != fabric_visibility::VISIBILITY_ROUTE_MAGIC
        || record.version != fabric_visibility::FORMAT_VERSION
        || record.flags & !fabric_visibility::KNOWN_ROUTE_FLAGS != 0
        || record.reserved0.iter().any(|byte| *byte != 0)
    {
        return false;
    }
    if record.status == fabric_visibility::STATUS_END {
        return record.contract_kind == 0
            && record.route_name_len == 0
            && record.route_name.iter().all(|byte| *byte == 0)
            && record.schema_identity.iter().all(|byte| *byte == 0)
            && record.flags == 0;
    }
    let name_len = record.route_name_len as usize;
    record.status == fabric_visibility::STATUS_RECORD
        && matches!(record.contract_kind, 1..=3)
        && name_len > 0
        && name_len <= fabric_visibility::ROUTE_NAME_BYTES
        && record.route_name[name_len..].iter().all(|byte| *byte == 0)
        && record.route_name[..name_len]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
        && record.schema_identity.iter().any(|byte| *byte != 0)
}

/// Validate the complete QoS half of one introspection page.
pub fn valid_visibility_qos_record(record: &fabric_visibility::WireVisibilityQosRecord) -> bool {
    record.magic == fabric_visibility::VISIBILITY_QOS_MAGIC
        && record.version == fabric_visibility::FORMAT_VERSION
        && record.status == fabric_visibility::STATUS_RECORD
        && record.flags & !fabric_visibility::KNOWN_QOS_FLAGS == 0
        && fixed_name_valid(&record.route_name)
        && matches!(record.reliability, 1 | 2)
        && matches!(record.durability, 1 | 2)
        && matches!(record.liveliness, 1 | 2)
        && record.matched <= 1
        && record.event_mask & !fabric_visibility::EVENT_PROXY_LOST == 0
}

/// Validate a trace record before accepting it from an authenticated interposer
/// or delivering the resulting route event.
pub fn valid_interposition_trace(record: &fabric_visibility::WireInterpositionTrace) -> bool {
    record.magic == fabric_visibility::INTERPOSITION_TRACE_MAGIC
        && record.version == fabric_visibility::FORMAT_VERSION
        && matches!(
            record.event,
            fabric_visibility::TRACE_RELAYED | fabric_visibility::TRACE_PROXY_LOST
        )
        && record.flags & !fabric_visibility::KNOWN_TRACE_FLAGS == 0
        && record.route_identity.iter().any(|byte| *byte != 0)
        && record.sequence != 0
        && record.reserved.iter().all(|byte| *byte == 0)
}

fn fixed_name_valid(name: &[u8]) -> bool {
    let length = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    length > 0
        && name[length..].iter().all(|byte| *byte == 0)
        && name[..length]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
}

/// Structural validity of an inline stream sample, before a subscriber reads
/// its payload or a broker forwards it (C8.4).
///
/// Inline delivery is the path a control-bound sample takes; anything larger
/// travels as a C7.6 descriptor over a receiver-bound loan. So this bounds
/// every field that could steer a copy: version, known flags, a payload length
/// inside `MAX_INLINE_BYTES`, zeroed padding past that length, and the exact
/// admitted type identity. `expected_type` binds the sample to the route's
/// declared interface, so a publisher cannot inject another type's bytes into
/// a route that carries this one.
pub fn valid_stream_sample(
    sample: &fabric_stream::WireStreamSample,
    expected_type: u64,
    max_inline: usize,
) -> bool {
    if sample.magic != fabric_stream::STREAM_SAMPLE_MAGIC
        || sample.version != fabric_stream::FORMAT_VERSION
    {
        return false;
    }
    if sample.flags & !fabric_stream::KNOWN_SAMPLE_FLAGS != 0 {
        return false;
    }
    if sample.type_identity == 0 || sample.type_identity != expected_type {
        return false;
    }
    let bound = max_inline.min(fabric_stream::MAX_INLINE_BYTES);
    let length = sample.payload_len as usize;
    if length == 0 || length > bound {
        return false;
    }
    // Padding past the declared length must be zero: two byte-distinct samples
    // that decode to the same payload would otherwise both be admissible, and
    // a KEEP_LAST ring comparing stored bytes could not treat them as one.
    sample.payload[length..].iter().all(|byte| *byte == 0)
}

/// Structural validity of a delivery-slot release (C8.4).
///
/// An ack names the sequence it releases, so the fabric can reject a
/// subscriber that tries to free a slot it never consumed. That check needs the
/// fabric's own delivery state and lives there; this bounds only the bytes:
/// version, no unknown flags, zeroed padding, the route's exact type identity,
/// and a nonzero sequence, since publishers number from one.
pub fn valid_stream_ack(ack: &fabric_stream::WireStreamAck, expected_type: u64) -> bool {
    ack.magic == fabric_stream::STREAM_ACK_MAGIC
        && ack.version == fabric_stream::FORMAT_VERSION
        && ack.flags & !fabric_stream::KNOWN_ACK_FLAGS == 0
        && ack.reserved0 == 0
        && ack.reserved.iter().all(|byte| *byte == 0)
        && ack.sequence != 0
        && ack.type_identity != 0
        && ack.type_identity == expected_type
}

/// Structural validity of a stream event (C8.4). An event never carries data,
/// so it must never be mistaken for a sample: the kind is checked against the
/// three this version defines, and each is bound to the fields it may name.
pub fn valid_stream_event(event: &fabric_stream::WireStreamEvent, expected_type: u64) -> bool {
    if event.magic != fabric_stream::STREAM_EVENT_MAGIC
        || event.version != fabric_stream::FORMAT_VERSION
    {
        return false;
    }
    if event.flags & !fabric_stream::KNOWN_EVENT_FLAGS != 0 {
        return false;
    }
    if event.reserved.iter().any(|byte| *byte != 0) {
        return false;
    }
    if event.type_identity == 0 || event.type_identity != expected_type {
        return false;
    }
    match event.event {
        // A loss report must name a loss and the oldest sequence it covers.
        fabric_stream::EVENT_SAMPLE_LOST => event.lost != 0 && event.sequence != 0,
        // A terminal notice covers the route, not a sample, so it names neither.
        fabric_stream::EVENT_STREAM_END => event.lost == 0 && event.sequence == 0,
        // A credit settles one exact sample, so it names that sequence.
        fabric_stream::EVENT_SAMPLE_TAKEN => event.lost == 0 && event.sequence != 0,
        _ => false,
    }
}

/// Structural validity of a ring header (B46).
///
/// A ring is shared memory, so every field here was written by a peer this
/// reader does not trust to be correct — a publisher with a wild pointer or a
/// stale mapping produces bytes, not an error. The reader's own bound comes
/// from `expected_slots`, which the fabric fixed at provisioning; a header
/// claiming more is refused rather than believed, because believing it is how
/// a reader walks off the end of its own mapping.
pub fn valid_ring_header(
    header: &fabric_ring::WireRingHeader,
    expected_type: u64,
    expected_slots: usize,
) -> bool {
    if header.magic != fabric_ring::RING_MAGIC || header.version != fabric_ring::FORMAT_VERSION {
        return false;
    }
    if header.slot_len as usize != fabric_ring::RING_SLOT_LEN {
        return false;
    }
    let slots = header.slot_count as usize;
    if slots != expected_slots
        || !(fabric_ring::MIN_RING_SLOTS..=fabric_ring::MAX_RING_SLOTS).contains(&slots)
        || !slots.is_power_of_two()
    {
        return false;
    }
    // `head - tail` is the occupancy, so `tail` past `head` is not a full ring
    // or an empty one — it is a header no correct writer produces, and a
    // reader that subtracted anyway would get a huge count and try to consume
    // it.
    if header.tail > header.head || header.head - header.tail > slots as u64 {
        return false;
    }
    if !matches!(
        header.producer_state,
        fabric_ring::PRODUCER_ACTIVE | fabric_ring::PRODUCER_FINISHED | fabric_ring::PRODUCER_DEAD
    ) {
        return false;
    }
    header.type_identity != 0
        && header.type_identity == expected_type
        && header.reserved.iter().all(|byte| *byte == 0)
}

/// Structural validity of one ring slot (B46).
///
/// `sequence` is absolute, and `expected_sequence` is the one this reader is
/// owed. A slot carrying anything else is a wrap the reader fell behind on,
/// not a sample it may consume — which is the distinction that lets a lagging
/// subscriber count drops instead of silently reading stale bytes as new.
///
/// Only `SLOT_READY` is admissible. `SLOT_CLAIMED` means the publisher is
/// mid-copy: refusing it is what makes a torn write unobservable rather than
/// merely unlikely.
pub fn valid_ring_slot(
    slot: &fabric_ring::WireRingSlot,
    expected_type: u64,
    expected_sequence: u64,
) -> bool {
    if slot.magic != fabric_ring::SLOT_MAGIC || slot.state != fabric_ring::SLOT_READY {
        return false;
    }
    if slot.flags & !fabric_ring::KNOWN_SLOT_FLAGS != 0 {
        return false;
    }
    if slot.sequence == 0 || slot.sequence != expected_sequence {
        return false;
    }
    if slot.type_identity == 0 || slot.type_identity != expected_type {
        return false;
    }
    let length = slot.payload_len as usize;
    if length == 0 || length > fabric_ring::MAX_INLINE_BYTES {
        return false;
    }
    // As with v1's inline sample: padding past the declared length must be
    // zero, so two byte-distinct slots cannot decode to the same payload.
    slot.payload[length..].iter().all(|byte| *byte == 0)
}

/// Which slot a sequence occupies, given a validated `slot_count`.
///
/// Masking rather than a remainder, which is why the count is required to be a
/// power of two. Callers must validate the header first: this cannot be
/// checked here without making every read pay for it.
pub fn ring_slot_index(sequence: u64, slot_count: usize) -> usize {
    (sequence as usize) & (slot_count - 1)
}

/// Whether a badge word carries only bits this version defines (B46).
///
/// A notification word is OR-ed, so an unknown bit means a peer signalling
/// something this reader cannot interpret. Refusing it is the same discipline
/// as an unknown message label: the alternative is treating it as one of the
/// bits that *is* known.
pub fn valid_ring_badge(badge: u64) -> bool {
    badge != 0 && badge & !fabric_ring::KNOWN_BADGE_BITS == 0
}

/// Structural validity of an I/O queue header (IO0).
///
/// The same discipline as [`valid_ring_header`], and for the same reason: a
/// queue is shared memory, so every field was written by a peer this reader
/// does not trust. The bounds come from the caller's own provisioning record,
/// never from the mapping.
///
/// What differs is that a queue is duplex, so there are two occupancies to
/// bound rather than one, and both must hold: a submission ring whose tail
/// passed its head, or a completion backlog larger than the ring, is a header
/// no correct peer produces.
pub fn valid_queue_header(header: &io_queue::WireQueueHeader, expected_slots: usize) -> bool {
    if header.magic != io_queue::QUEUE_MAGIC || header.version != io_queue::FORMAT_VERSION {
        return false;
    }
    if header.request_slot_len as usize != io_queue::REQUEST_SLOT_LEN
        || header.completion_slot_len as usize != io_queue::COMPLETION_SLOT_LEN
    {
        return false;
    }
    let slots = header.slot_count as usize;
    if slots != expected_slots
        || !(io_queue::MIN_QUEUE_SLOTS..=io_queue::MAX_QUEUE_SLOTS).contains(&slots)
        || !slots.is_power_of_two()
    {
        return false;
    }
    if header.submit_tail > header.submit_head
        || header.submit_head - header.submit_tail > slots as u64
    {
        return false;
    }
    if header.complete_tail > header.complete_head
        || header.complete_head - header.complete_tail > slots as u64
    {
        return false;
    }
    // A completion can only answer a request that was submitted. More
    // completions than submissions means the driver invented one, and a client
    // that consumed it would settle a request it never made.
    if header.complete_head > header.submit_head {
        return false;
    }
    if !matches!(
        header.driver_state,
        io_queue::DRIVER_ACTIVE | io_queue::DRIVER_RESETTING | io_queue::DRIVER_DEAD
    ) {
        return false;
    }
    // Epoch zero is reserved for "no driver has claimed this queue", so an
    // active driver must have advanced past it. A dead or resetting queue may
    // still read zero if it was never claimed at all.
    if header.driver_state == io_queue::DRIVER_ACTIVE && header.epoch == 0 {
        return false;
    }
    header.client_reserved.iter().all(|byte| *byte == 0)
        && header.client_padding.iter().all(|byte| *byte == 0)
        && header.driver_reserved.iter().all(|byte| *byte == 0)
        && header.driver_padding.iter().all(|byte| *byte == 0)
}

/// Whether a buffer slice names bytes the substrate may act on (IO0).
///
/// `mapped_len` is the length of the lease's own mapping as the *validator's*
/// side knows it — not a number from the wire. That is the whole point: a slice
/// is a claim about which bytes of a buffer an operation touches, and the check
/// that matters is whether those bytes are inside the region the lease actually
/// covers. Overflow is checked explicitly rather than relying on wrapping,
/// because `offset + length` is exactly where a hostile descriptor aims.
///
/// A `DIRECTION_NONE` slice belongs to a control request that touches no
/// buffer, and every other field must be zero. Admitting a half-filled
/// no-direction slice would let a control request carry a lease identity the
/// substrate would then have to decide whether to settle.
pub fn valid_buffer_slice(slice: &io_queue::WireBufferSlice, mapped_len: u64) -> bool {
    if slice.reserved.iter().any(|byte| *byte != 0) {
        return false;
    }
    match slice.direction {
        io_queue::DIRECTION_NONE => {
            slice.buffer == 0 && slice.lease == 0 && slice.offset == 0 && slice.length == 0
        }
        io_queue::DIRECTION_DEVICE_READ | io_queue::DIRECTION_DEVICE_WRITE => {
            if slice.buffer == 0 || slice.lease == 0 || slice.length == 0 {
                return false;
            }
            match slice.offset.checked_add(slice.length) {
                Some(end) => end <= mapped_len,
                None => false,
            }
        }
        _ => false,
    }
}

/// Structural validity of one submission slot (IO0).
///
/// `expected_epoch` is the epoch the reader is serving. A slot carrying any
/// other epoch is work from a driver incarnation that no longer exists, and
/// refusing it here is what makes a stale submission unable to reach a device.
///
/// Only `SLOT_READY` is admissible, for the same reason as the fabric ring:
/// `SLOT_CLAIMED` means the writer is mid-copy.
pub fn valid_request_slot(
    slot: &io_queue::WireRequestSlot,
    expected_epoch: u64,
    mapped_len: u64,
) -> bool {
    if slot.magic != io_queue::REQUEST_MAGIC || slot.state != io_queue::SLOT_READY {
        return false;
    }
    if slot.flags & !io_queue::KNOWN_REQUEST_FLAGS != 0 {
        return false;
    }
    // Request identity zero is reserved so a zeroed slot cannot be mistaken
    // for a request, and the epoch must be the one being served.
    if slot.request_id == 0 || slot.epoch == 0 || slot.epoch != expected_epoch {
        return false;
    }
    let length = slot.payload_len as usize;
    if length > io_queue::REQUEST_PAYLOAD_BYTES {
        return false;
    }
    if slot.payload[length..].iter().any(|byte| *byte != 0) {
        return false;
    }
    let slice = io_queue::WireBufferSlice {
        buffer: slot.slice_buffer,
        lease: slot.slice_lease,
        offset: slot.slice_offset,
        length: slot.slice_length,
        direction: slot.slice_direction,
        reserved: slot.slice_reserved,
    };
    valid_buffer_slice(&slice, mapped_len)
}

/// Structural validity of one completion slot (IO0).
///
/// A completion is only meaningful against the request it answers, so both the
/// identity and the epoch are supplied by the caller from its own outstanding
/// table. This is the check that rejects a late completion after cancellation,
/// reset, or peer death: the caller has already settled that request and no
/// longer holds it, so there is no `expected_request` to match.
///
/// `transferred` is bounded by the request's own slice length, which the caller
/// passes because the completion does not restate it. A driver reporting more
/// bytes than the slice covered is claiming to have touched memory the lease
/// did not authorize.
pub fn valid_completion_slot(
    slot: &io_queue::WireCompletionSlot,
    expected_request: u64,
    expected_epoch: u64,
    slice_length: u64,
) -> bool {
    if slot.magic != io_queue::COMPLETION_MAGIC {
        return false;
    }
    if slot.flags & !io_queue::KNOWN_COMPLETION_FLAGS != 0 {
        return false;
    }
    if slot.request_id == 0
        || slot.request_id != expected_request
        || slot.epoch == 0
        || slot.epoch != expected_epoch
    {
        return false;
    }
    if !valid_completion_status(slot.status) {
        return false;
    }
    // Only a successful completion moved bytes. A refusal that also claimed a
    // transfer would be reporting two different outcomes at once, and a caller
    // reading `transferred` without first branching on status would trust it.
    if slot.status != io_queue::STATUS_OK && slot.transferred != 0 {
        return false;
    }
    if slot.transferred > slice_length {
        return false;
    }
    let length = slot.payload_len as usize;
    length <= io_queue::COMPLETION_PAYLOAD_BYTES
        && slot.payload[length..].iter().all(|byte| *byte == 0)
}

/// Whether a status word is one this version defines (IO0).
pub fn valid_completion_status(status: u32) -> bool {
    matches!(
        status,
        io_queue::STATUS_OK
            | io_queue::STATUS_CANCELLED
            | io_queue::STATUS_RESET
            | io_queue::STATUS_PEER_DEAD
            | io_queue::STATUS_MALFORMED
            | io_queue::STATUS_BAD_SLICE
            | io_queue::STATUS_BAD_EPOCH
            | io_queue::STATUS_BAD_RIGHTS
            | io_queue::STATUS_EXHAUSTED
            | io_queue::STATUS_DEVICE_ERROR
            | io_queue::STATUS_UNSUPPORTED
    )
}

/// Which slot a sequence occupies in a queue ring, given a validated count.
///
/// Separate from [`ring_slot_index`] only so the two substrates do not share a
/// helper whose power-of-two precondition is validated by different code.
pub fn queue_slot_index(sequence: u64, slot_count: usize) -> usize {
    (sequence as usize) & (slot_count - 1)
}

/// Whether an I/O queue badge word carries only defined bits (IO0).
pub fn valid_queue_badge(badge: u64) -> bool {
    badge != 0 && badge & !io_queue::KNOWN_BADGE_BITS == 0
}

/// Whether a request-lifecycle state is terminal (IO0).
///
/// Single-assignment is the invariant this supports: a caller that finds a
/// request already in a terminal state must refuse the transition rather than
/// overwrite it, which is what makes a lease release exactly once.
pub fn terminal_request_state(state: u32) -> bool {
    matches!(
        state,
        io_queue::STATE_COMPLETE
            | io_queue::STATE_CANCELLED
            | io_queue::STATE_RESET
            | io_queue::STATE_PEER_DEAD
    )
}

/// The terminal state a completion status settles a request into (IO0).
///
/// Total over defined statuses so a caller cannot forget a case: every status
/// this version defines resolves to exactly one terminal state, which is what
/// makes "every submitted request reaches one terminal state" checkable rather
/// than aspirational. An undefined status yields `None` and must be refused.
pub fn terminal_state_for_status(status: u32) -> Option<u32> {
    match status {
        io_queue::STATUS_CANCELLED => Some(io_queue::STATE_CANCELLED),
        io_queue::STATUS_RESET => Some(io_queue::STATE_RESET),
        io_queue::STATUS_PEER_DEAD => Some(io_queue::STATE_PEER_DEAD),
        // Every other defined status is an answer the driver produced for this
        // request -- successfully or not -- so the request completed. The
        // distinction between "it worked" and "it was refused" is the status
        // itself, not the lifecycle state.
        status if valid_completion_status(status) => Some(io_queue::STATE_COMPLETE),
        _ => None,
    }
}

pub fn valid_time_advance(value: &fabric_time::WireTimeAdvance) -> bool {
    value.magic == fabric_time::TIME_ADVANCE_MAGIC
        && value.version == fabric_time::FORMAT_VERSION
        && value.flags == 0
        && value.reserved0 == 0
        && value.reserved.iter().all(|byte| *byte == 0)
}

pub fn valid_qos_event(value: &fabric_qos::WireQosEvent, expected_type: u64) -> bool {
    use fabric_qos::*;
    value.magic == QOS_EVENT_MAGIC
        && value.version == FORMAT_VERSION
        && value.flags == 0
        && value.type_identity == expected_type
        && value.reserved.iter().all(|byte| *byte == 0)
        && matches!(
            value.event,
            EVENT_MATCHED
                | EVENT_UNMATCHED
                | EVENT_INCOMPATIBLE_QOS
                | EVENT_LIFESPAN_EXPIRED
                | EVENT_RETRY_EXHAUSTED
                | EVENT_DEADLINE_MISSED
                | EVENT_LIVELINESS_LOST
                | EVENT_PEER_DEAD
        )
}

/// Structural validity of one C8.6 inline call envelope. Correlation/session
/// checks that require live broker state stay in the fabric service; this
/// rejects malformed bytes before they can allocate an in-flight entry or
/// steer data. Shared payloads use `SampleDescriptor`, never this envelope.
pub fn valid_call_envelope(value: &fabric_call::WireCallEnvelope, expected_type: u64) -> bool {
    use fabric_call::*;
    if value.magic != CALL_MAGIC
        || value.version != FORMAT_VERSION
        || value.flags & !FLAG_NON_IDEMPOTENT != 0
        || value.session == 0
        || value.request_id == 0
        || value.type_identity == 0
        || value.type_identity != expected_type
        || (!matches!(
            value.kind,
            KIND_TERMINAL | KIND_TERMINAL_ACK | KIND_REPLY_ACK
        ) && value.payload_len as usize > INLINE_BYTES)
        || (matches!(
            value.kind,
            KIND_TERMINAL | KIND_TERMINAL_ACK | KIND_REPLY_ACK
        ) && value.payload_len != 0)
        || value.payload[value.payload_len.min(value.payload.len() as u32) as usize..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return false;
    }
    match value.kind {
        KIND_REQUEST => value.status == STATUS_SUCCESS,
        KIND_REPLY => matches!(
            value.status,
            STATUS_SUCCESS | STATUS_REJECTED | STATUS_CANCELLED
        ),
        // The client's word that it took an inline reply, naming the request
        // that reply answered. It mirrors the reply's own status so a broker
        // cannot retire a record on an ack for some other outcome.
        //
        // Unlike a terminal ack this does not require `flags == 0`: a reply
        // carries whatever flags its server chose, and the non-idempotent bit
        // is echoed back from the request it answers.
        KIND_REPLY_ACK => matches!(
            value.status,
            STATUS_SUCCESS | STATUS_REJECTED | STATUS_CANCELLED
        ),
        KIND_CANCEL => {
            value.flags == 0 && value.status == STATUS_CANCELLED && value.payload_len == 0
        }
        KIND_TERMINAL => {
            value.flags == 0
                && matches!(
                    value.status,
                    STATUS_SUCCESS
                        | STATUS_REJECTED
                        | STATUS_TIMEOUT
                        | STATUS_CANCELLED
                        | STATUS_RETRY_EXHAUSTED
                        | STATUS_MALFORMED_REPLY
                        | STATUS_PEER_DEAD
                        | STATUS_DUPLICATE
                        | STATUS_STALE
                )
                && value.payload_len == 0
        }
        // The client's word that it took a terminal, naming the request that
        // terminal settled. It carries the settled status back so a broker
        // cannot retire a record on an ack for some other outcome.
        KIND_TERMINAL_ACK => {
            value.flags == 0
                && matches!(
                    value.status,
                    STATUS_SUCCESS
                        | STATUS_REJECTED
                        | STATUS_TIMEOUT
                        | STATUS_CANCELLED
                        | STATUS_RETRY_EXHAUSTED
                        | STATUS_MALFORMED_REPLY
                        | STATUS_PEER_DEAD
                        | STATUS_DUPLICATE
                        | STATUS_STALE
                )
                && value.payload_len == 0
        }
        _ => false,
    }
}

pub fn valid_call_time_advance(value: &fabric_call::WireCallTimeAdvance) -> bool {
    value.magic == fabric_call::CALL_TIME_MAGIC
        && value.version == fabric_call::FORMAT_VERSION
        && value.flags == 0
        && value.reserved0 == 0
        && value.reserved.iter().all(|byte| *byte == 0)
}

/// Structural validity of one C8.7 operation envelope, before it can allocate
/// an active-operation entry, a feedback slot, or a retained result.
///
/// C8.7 composes an operation from a start-goal call, an operation-keyed
/// feedback stream, a result call, and a cancellation request. Every leg rides
/// this one record, so the checks are per-kind: a field that means nothing on a
/// leg must be zero there rather than merely ignored, or a peer could smuggle a
/// feedback sequence into a cancellation and have it survive into broker state.
///
/// Correlation, authority, and duplicate/stale suppression need live broker
/// state and stay in the fabric; this rejects bytes that are not a well-formed
/// leg at all. Shared payloads travel as `SampleDescriptor`, never here.
pub fn valid_operation_envelope(
    value: &fabric_operation::WireOperationEnvelope,
    expected_type: u64,
) -> bool {
    use fabric_operation::*;
    if value.magic != OPERATION_MAGIC
        || value.version != FORMAT_VERSION
        || value.session == 0
        || value.operation_id == 0
        || value.type_identity == 0
        || value.type_identity != expected_type
        || value.payload_len as usize > INLINE_BYTES
        || value.payload[value.payload_len as usize..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return false;
    }
    // Only feedback is ordered within an operation; a sequence anywhere else is
    // a field the sender had no business setting. The server-idle fence carries
    // no payload, but names the handled request so the broker can match it.
    if value.kind != KIND_FEEDBACK && value.sequence != 0 {
        return false;
    }
    match value.kind {
        KIND_GOAL => value.status == STATUS_SUCCESS,
        // The transport's answer to a goal: refused, running, or winding down.
        KIND_ACCEPTED => {
            value.payload_len == 0
                && matches!(
                    value.status,
                    STATUS_SUCCESS | STATUS_REJECTED | STATUS_ACTIVE | STATUS_CANCEL_REQUESTED
                )
        }
        // Feedback is progress, never an outcome, and is numbered from one.
        KIND_FEEDBACK => value.status == STATUS_ACTIVE && value.sequence != 0,
        KIND_RESULT => matches!(
            value.status,
            STATUS_SUCCESS | STATUS_REJECTED | STATUS_CANCELLED
        ),
        KIND_RESULT_REQUEST | KIND_CANCEL => {
            value.payload_len == 0 && value.status == STATUS_SUCCESS
        }
        KIND_TERMINAL => {
            value.payload_len == 0
                && matches!(
                    value.status,
                    STATUS_SUCCESS
                        | STATUS_REJECTED
                        | STATUS_CANCELLED
                        | STATUS_EXPIRED
                        | STATUS_TIMEOUT
                        | STATUS_PEER_DEAD
                        | STATUS_DUPLICATE
                        | STATUS_STALE
                        | STATUS_MALFORMED
                        | STATUS_RETRY_EXHAUSTED
                )
        }
        KIND_SERVER_IDLE => value.payload_len == 0 && value.status == STATUS_SUCCESS,
        _ => false,
    }
}

/// Structural validity of one C8.11 semantic-trace record.
///
/// The record is the deterministic evidence stream the repeated-boot comparison
/// reads, so "structural" is stricter here than on a transport envelope: a
/// field that means nothing for a family must be zero in that family rather
/// than merely ignored. A trace whose unused fields carried whatever the
/// emitter happened to hold would not be byte-comparable across two runs of
/// the same inputs, which is the whole property C8.11 claims.
///
/// What is deliberately *not* checked here is anything requiring live state:
/// whether a route identity is admitted, whether a correlation is outstanding,
/// or whether the clock actually reached `now_ns`. Those belong to the emitting
/// worker, which holds the graph. This rejects bytes that are not a well-formed
/// record of any family.
pub fn valid_trace_record(value: &fabric_trace::WireTraceRecord) -> bool {
    use fabric_trace::*;
    if value.magic != TRACE_MAGIC
        || value.version != FORMAT_VERSION
        || value.kind == 0
        || value.kind > MAX_KIND
        || value.flags & !KNOWN_FLAGS != 0
        || value.order_class == 0
        || u32::from(value.order_class) > MAX_ORDER_CLASS
        || value.reserved.iter().any(|byte| *byte != 0)
    {
        return false;
    }
    // The two flags answer different questions and cannot both be true: a
    // saturation report is not the record that ends the stream.
    if value.flags == KNOWN_FLAGS {
        return false;
    }
    // A saturation report counts refused records; that count is what makes the
    // loss observable rather than silent, so zero would defeat the record.
    if value.flags & FLAG_DROPPED != 0 && value.high_water == 0 {
        return false;
    }
    // The time class closes an instant rather than occurring within it, so a
    // record claiming it must name neither an edge nor a correlation: it is not
    // an event *on* anything. Equivalently, an edge-bearing record can never
    // sort after everything at its own instant, which is what makes the tie
    // order meaningful. Two families may close an instant — the clock advance
    // itself, and the sink's own accounting at that boundary.
    let time_class = u32::from(value.order_class) == ORDER_TIME;
    if time_class && (value.route_identity != 0 || value.correlation != 0) {
        return false;
    }
    if time_class && !matches!(value.kind, KIND_QOS | KIND_RESOURCE) {
        return false;
    }
    match value.kind {
        // Schema admission is a per-generation fact: it names no route edge, no
        // correlation, and no outcome, only the sequence it was admitted in.
        KIND_SCHEMA => {
            value.route_identity == 0
                && value.correlation == 0
                && value.status == 0
                && value.event == 0
        }
        // Route provisioning names its edge and reports no correlation.
        KIND_ROUTE => value.route_identity != 0 && value.correlation == 0 && value.event == 0,
        // A QoS record is either the clock advance that closes an instant or a
        // policy event on a declared edge. The two are told apart by the edge,
        // not by the order class: an advance names no edge, and a policy event
        // always does. Deriving it from the fields rather than the class keeps
        // the class free to be checked independently above.
        KIND_QOS => {
            if value.route_identity == 0 {
                // A clock advance. It carries the emitting worker's sequence like
                // any other record -- that is the sort's tie-break key, and two
                // records closing one instant must not share it -- but it names
                // no correlation, no outcome, and no event, because it is not an
                // event on anything.
                u32::from(value.order_class) == ORDER_TIME
                    && value.correlation == 0
                    && value.status == 0
                    && value.event == 0
            } else {
                u32::from(value.order_class) != ORDER_TIME && value.event != 0
            }
        }
        // Request/response families correlate a request with its outcome, so
        // both the edge and the correlation are load-bearing.
        KIND_CALL | KIND_OPERATION => value.route_identity != 0 && value.correlation != 0,
        // Visibility and interposition are graph-shaped: an edge, no outcome
        // code, and an event naming what was observed or traversed.
        //
        // The event is bounded, for the same reason a resource counter is: it
        // is the only field on these families carrying meaning, so a number
        // outside the declared vocabulary is not evidence a reader can compare
        // across runs.
        KIND_VISIBILITY | KIND_INTERPOSITION => {
            value.route_identity != 0
                && value.correlation == 0
                && value.event != 0
                && value.event <= fabric_trace::MAX_GRAPH_EVENT
        }
        // A denial is a refusal, and it names nothing.
        //
        // Enforced by the format rather than left to each call site. A refusal
        // that carried the route identity would confirm to the caller that the
        // edge exists — the protected graph metadata the refusal is there to
        // withhold — and one that echoed the caller's correlation would
        // republish an identity the broker just rejected, which on a shared
        // route may belong to a different client. What a denial carries is the
        // fact that something was refused, and the status saying what kind of
        // refusal it was.
        KIND_DENIAL => {
            value.route_identity == 0
                && value.correlation == 0
                && value.event == 0
                && value.status < 0
        }
        // A fault is attributed to an edge and reports a failure status.
        KIND_FAULT => value.route_identity != 0 && value.status < 0,
        // A resource record is a count, not an event on an edge, and its
        // `event` names *which* count. A bare number with no counter identity
        // is not evidence: a reader could not tell frames from operations, and
        // two runs reporting different counters would compare as equal.
        KIND_RESOURCE => {
            value.route_identity == 0
                && value.correlation == 0
                && value.status == 0
                && value.event != 0
                && value.event <= MAX_RESOURCE_COUNTER
        }
        // C9.5's recording families. Each names the one field carrying its
        // captured value and zeroes the rest, on `KIND_RESOURCE`'s rule: a
        // recording is only replayable if every field a family does not use is
        // fixed, or two runs would differ on bytes neither of them meant.
        //
        // All four carry `flags == 0`, and that is load-bearing rather than
        // tidy. Both declared flags belong to the sink's own accounting —
        // `terminal` marks the record that says a stream ended and `dropped` the
        // one that counts refusals — and both are `KIND_RESOURCE` facts. A
        // recording family carrying `terminal` would make the end of a replayed
        // stream ambiguous, which is exactly the truncated-versus-complete
        // distinction C9.5's third required check rests on.
        //
        // None of the four names a route edge. A recorded clock read, timer
        // expiry, or lifecycle transition is an event on the *component*, not on
        // an edge, and an output is the component's own product. Recorded route
        // traffic keeps using `KIND_ROUTE`/`KIND_QOS`, which already carry the
        // identity — so C9.5 adds families for the three sources that had none
        // rather than a second way to say "route".
        //
        // A clock read carries the value the clock answered in `correlation`,
        // and that value may legitimately be zero: the first read of a simulated
        // clock answers zero, and refusing it would make the recording of a
        // deterministic clock's own starting instant unrepresentable.
        // `event` distinguishes which clock answered, so the two reads are never
        // confused, and it is bounded because an unnamed clock is not evidence.
        KIND_CLOCK_READ => {
            value.flags == 0
                && value.route_identity == 0
                && value.status == 0
                && value.high_water == 0
                && value.event != 0
                && value.event <= MAX_CLOCK_SOURCE
        }
        // A timer expiry names the timer that fired, in `correlation`.
        //
        // Zero is admitted, and that is not laxity: `CLOCK TIMER ARM` documents
        // its primary result as "an opaque timer id; zero is valid", and the root
        // does assign it — the first timer a holder arms on this plane is id 0.
        // An earlier revision here required a nonzero identity on the theory that
        // zero names no timer, and it refused the first real expiry the recorder
        // observed. The identity is opaque, so no value is reserved, and the
        // record's meaning comes from its kind rather than from its payload being
        // nonzero.
        KIND_TIMER_EXPIRY => {
            value.flags == 0
                && value.route_identity == 0
                && value.status == 0
                && value.event == 0
                && value.high_water == 0
        }
        // A lifecycle transition names the state it reached in `event`, from
        // `lifecycle-policy/v1`'s closed vocabulary. Bounded here against that
        // contract's own ceiling rather than by convention, and nonzero because
        // `undeclared` is an answer rather than a transition.
        KIND_LIFECYCLE => {
            value.flags == 0
                && value.route_identity == 0
                && value.correlation == 0
                && value.status == 0
                && value.high_water == 0
                && value.event != 0
                && value.event <= MAX_LIFECYCLE_STATE
        }
        // A typed output carries its value in `correlation` and which output it
        // is in `event`. This is the family two boots are compared on, so it
        // holds the tightest rule: `status` and `high_water` are fixed, and the
        // output ordinal is bounded, because a comparison over an unbounded
        // event space could not tell a new output from a corrupted one.
        KIND_OUTPUT => {
            value.flags == 0
                && value.route_identity == 0
                && value.status == 0
                && value.high_water == 0
                && value.event != 0
                && value.event <= MAX_OUTPUT_CHANNEL
        }
        _ => false,
    }
}

/// Whether `later` may follow `earlier` under C8.11's declared total order.
///
/// The rule is lexicographic on `(now_ns, order_class, sequence)`. It is a
/// separate function from [`valid_trace_record`] because ordering is a property
/// of a *pair* of records: a reader validates each record on arrival and the
/// order as it walks the sink, and a sink that mixed the two checks could not
/// report which of them a bad trace violated.
pub fn trace_records_ordered(
    earlier: &fabric_trace::WireTraceRecord,
    later: &fabric_trace::WireTraceRecord,
) -> bool {
    (earlier.now_ns, earlier.order_class, earlier.sequence)
        <= (later.now_ns, later.order_class, later.sequence)
}
/// Whether a LinkDevice operation is defined by version 1 (IO3).
fn valid_link_op(op: u8) -> bool {
    matches!(
        op,
        link_device::OP_TRANSMIT
            | link_device::OP_PROVIDE_RECEIVE
            | link_device::OP_QUERY_LINK
            | link_device::OP_STATISTICS
            | link_device::OP_RESET
            | link_device::OP_CLOSE
    )
}

/// Whether a frame length is a complete Ethernet frame admitted by LinkDevice.
pub fn valid_link_frame_bounds(frame_len: usize) -> bool {
    (link_device::MIN_FRAME_BYTES..=link_device::MAX_FRAME_BYTES).contains(&frame_len)
}

/// Whether a link-state value is one this version defines.
pub fn valid_link_state(state: u8) -> bool {
    matches!(
        state,
        link_device::LINK_UNKNOWN | link_device::LINK_DOWN | link_device::LINK_UP
    )
}

/// Structural and operation-specific validity of an IO0 LinkDevice request payload.
pub fn valid_link_request(request: &link_device::WireLinkRequest) -> bool {
    if request.magic != link_device::LINK_MAGIC
        || request.version != link_device::FORMAT_VERSION
        || !valid_link_op(request.op)
        || request.flags & !link_device::KNOWN_REQUEST_FLAGS != 0
        || request.reserved.iter().any(|byte| *byte != 0)
    {
        return false;
    }

    let frame_len = request.frame_len as usize;
    let length_valid = match request.op {
        link_device::OP_TRANSMIT => valid_link_frame_bounds(frame_len),
        // A receive lease must be able to hold every frame this contract admits;
        // the completion reports the actual received length.
        link_device::OP_PROVIDE_RECEIVE => frame_len == link_device::MAX_FRAME_BYTES,
        link_device::OP_QUERY_LINK
        | link_device::OP_STATISTICS
        | link_device::OP_RESET
        | link_device::OP_CLOSE => frame_len == 0,
        _ => false,
    };
    length_valid && request.padding.iter().all(|byte| *byte == 0)
}

/// Structural and operation-specific validity of an IO0 LinkDevice reply payload.
pub fn valid_link_reply(reply: &link_device::WireLinkReply) -> bool {
    if reply.magic != link_device::LINK_MAGIC
        || reply.version != link_device::FORMAT_VERSION
        || !valid_link_op(reply.op)
        || !valid_link_state(reply.link_state)
        || reply.reserved.iter().any(|byte| *byte != 0)
    {
        return false;
    }

    let frame_len = reply.frame_len as usize;
    match reply.op {
        link_device::OP_TRANSMIT | link_device::OP_PROVIDE_RECEIVE => {
            valid_link_frame_bounds(frame_len) && reply.tx_frames == 0 && reply.rx_frames == 0
        }
        link_device::OP_STATISTICS => frame_len == 0,
        link_device::OP_QUERY_LINK | link_device::OP_RESET | link_device::OP_CLOSE => {
            frame_len == 0 && reply.tx_frames == 0 && reply.rx_frames == 0
        }
        _ => false,
    }
}

/// Validate one launch chunk; the receiver additionally enforces endpoint role
/// and contiguous, single-message assembly before using the supplied bytes.
pub fn valid_network_launch(frame: &network_service::WireNetworkLaunch) -> bool {
    use network_service as net;
    let length = usize::from(frame.length);
    let total = usize::from(frame.total_len);
    let offset = usize::from(frame.offset);
    frame.magic == net::NETWORK_MAGIC
        && frame.version == net::FORMAT_VERSION
        && frame.reserved == 0
        && frame.reserved2 == [0; 2]
        && length > 0
        && length <= net::LAUNCH_PAYLOAD_BYTES
        && offset.checked_add(length).is_some_and(|end| end <= total)
        && frame.payload[length..].iter().all(|byte| *byte == 0)
        && match frame.kind {
            net::LAUNCH_SEED => total == 32 && offset == 0 && length == 32,
            net::LAUNCH_URL => total > 0 && total <= net::LAUNCH_URL_BYTES,
            _ => false,
        }
}

/// Validate a NetworkService provisioning loan before importing or mapping it.
/// The expected role comes from the receiver; each role has one contract-defined size.
pub fn valid_network_loan(
    descriptor: &network_service::WireNetworkLoan,
    expected_role: u8,
) -> bool {
    let length = match expected_role {
        network_service::LOAN_ROLE_RING => network_service::RING_BYTES,
        network_service::LOAN_ROLE_DATA => network_service::DATA_BYTES,
        _ => return false,
    };
    descriptor.magic == network_service::NETWORK_MAGIC
        && descriptor.version == network_service::FORMAT_VERSION
        && descriptor.role == expected_role
        && descriptor.reserved0 == [0; 1]
        && descriptor.reserved == [0; 32]
        && descriptor.length == length as u64
        && descriptor.buffer != 0
        && descriptor.lease != 0
}

/// Control-only abort never goes through an application ring or names a peer.
/// The nontransferable control endpoint identifies the session to discard.
pub fn valid_network_abort(request: &network_service::WireNetworkRequest) -> bool {
    use network_service as net;
    request.magic == net::NETWORK_MAGIC
        && request.version == net::FORMAT_VERSION
        && request.op == net::OP_ABORT
        && request.transport == net::TRANSPORT_NONE
        && request.flags == 0
        && request.port == 0
        && request.name_len == 0
        && request.capability == u64::MAX
        && request.address_kind == net::ADDRESS_NONE
        && request.reserved == [0; 7]
        && request.endpoint == [0; 24]
}

/// Structural and operation-specific validity of a NetworkService IO0 request payload.
pub fn valid_network_request(request: &network_service::WireNetworkRequest) -> bool {
    if request.magic != network_service::NETWORK_MAGIC
        || request.version != network_service::FORMAT_VERSION
        || request.flags & !network_service::KNOWN_REQUEST_FLAGS != 0
        || request.reserved.iter().any(|byte| *byte != 0)
        || request.name_len as usize > network_service::MAX_NAME_BYTES
    {
        return false;
    }
    let name_len = request.name_len as usize;
    let address_tail_zero = request.endpoint[16..].iter().all(|byte| *byte == 0);
    let endpoint_zero = request.endpoint.iter().all(|byte| *byte == 0);
    let valid_destination = request.port != 0
        && match request.address_kind {
            network_service::ADDRESS_IPV4 => {
                request.name_len == 0 && request.endpoint[4..].iter().all(|byte| *byte == 0)
            }
            network_service::ADDRESS_IPV6 => request.name_len == 0 && address_tail_zero,
            network_service::ADDRESS_DNS => {
                name_len > 0
                    && request.endpoint[name_len..].iter().all(|byte| *byte == 0)
                    && valid_network_name(&request.endpoint[..name_len])
            }
            _ => false,
        };
    match request.op {
        network_service::OP_CONNECT => {
            matches!(
                request.transport,
                network_service::TRANSPORT_TCP | network_service::TRANSPORT_UDP
            ) && request.capability == 0
                && valid_destination
        }
        network_service::OP_LISTEN => {
            request.transport == network_service::TRANSPORT_TCP
                && request.capability == 0
                && valid_destination
        }
        network_service::OP_RESOLVE => {
            request.transport == network_service::TRANSPORT_NONE
                && request.capability == 0
                && request.port == 0
                && request.address_kind == network_service::ADDRESS_DNS
                && name_len > 0
                && request.endpoint[name_len..].iter().all(|byte| *byte == 0)
                && valid_network_name(&request.endpoint[..name_len])
        }
        network_service::OP_SEND
        | network_service::OP_RECV
        | network_service::OP_CLOSE
        | network_service::OP_SHUTDOWN => {
            request.transport == network_service::TRANSPORT_NONE
                && request.capability != 0
                && request.port == 0
                && request.name_len == 0
                && request.address_kind == network_service::ADDRESS_NONE
                && endpoint_zero
        }
        network_service::OP_ACCEPT => {
            request.transport == network_service::TRANSPORT_TCP
                && request.capability != 0
                && request.port == 0
                && request.name_len == 0
                && request.address_kind == network_service::ADDRESS_NONE
                && endpoint_zero
        }
        _ => false,
    }
}

/// Reserve a terminal request identity before judging its envelope or payload.
/// Malformed requests consume identities too; old epochs must not be completed
/// as if they belonged to the current session.
pub fn admit_network_request_id(last: &mut u64, id: u64, epoch: u64, current_epoch: u64) -> bool {
    if id <= *last || epoch != current_epoch || current_epoch == 0 {
        return false;
    }
    *last = id;
    true
}

/// Bind a network request's payload to the service-owned session mapping.
/// Expected identities and mapping length come from root allocation/loan results,
/// never from the application's request or provisioning descriptor claims.
pub fn valid_network_payload_slice(
    request: &network_service::WireNetworkRequest,
    slice: &io_queue::WireBufferSlice,
    expected_buffer: u64,
    expected_lease: u64,
    mapped_len: u64,
) -> bool {
    if !valid_network_request(request) || !valid_buffer_slice(slice, mapped_len) {
        return false;
    }
    let direction = match request.op {
        network_service::OP_SEND => io_queue::DIRECTION_DEVICE_READ,
        network_service::OP_RECV => io_queue::DIRECTION_DEVICE_WRITE,
        _ => return slice.direction == io_queue::DIRECTION_NONE,
    };
    slice.direction == direction && slice.buffer == expected_buffer && slice.lease == expected_lease
}

fn valid_network_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name[0] != b'.'
        && name[name.len() - 1] != b'.'
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-'))
        && !name.windows(2).any(|pair| pair == b"..")
}

/// Structural and typed-capability validity of a NetworkService completion payload.
pub fn valid_network_completion(completion: &network_service::WireNetworkCompletion) -> bool {
    if completion.magic != network_service::NETWORK_MAGIC
        || completion.version != network_service::FORMAT_VERSION
        || completion.flags & !network_service::KNOWN_COMPLETION_FLAGS != 0
        || !(network_service::STATUS_RESET..=network_service::STATUS_SUCCESS)
            .contains(&completion.status_detail)
        || (completion.flags != 0
            && (completion.op != network_service::OP_RECV || completion.status_detail != 0))
    {
        return false;
    }
    if completion.status_detail != 0 {
        return completion.capability == 0
            && completion.capability_kind == network_service::CAPABILITY_NONE;
    }
    match completion.op {
        network_service::OP_CONNECT => {
            completion.capability != 0
                && matches!(
                    completion.capability_kind,
                    network_service::CAPABILITY_TCP_CONNECTION
                        | network_service::CAPABILITY_UDP_ENDPOINT
                )
        }
        network_service::OP_LISTEN => {
            completion.capability != 0
                && completion.capability_kind == network_service::CAPABILITY_TCP_LISTENER
        }
        network_service::OP_ACCEPT => {
            completion.capability != 0
                && completion.capability_kind == network_service::CAPABILITY_TCP_CONNECTION
        }
        network_service::OP_RESOLVE => {
            completion.capability != 0
                && completion.capability_kind == network_service::CAPABILITY_DNS_RECORD
        }
        network_service::OP_SEND
        | network_service::OP_RECV
        | network_service::OP_CLOSE
        | network_service::OP_SHUTDOWN
        | network_service::OP_ATTACH
        | network_service::OP_ABORT => {
            completion.capability == 0
                && completion.capability_kind == network_service::CAPABILITY_NONE
        }
        _ => false,
    }
}

/// Validate one BlockDevice v2 request payload before any DMA mapping or
/// descriptor allocation. The IO0 envelope separately validates identity,
/// epoch, lease, slice bounds, and direction.
pub fn valid_block_v2_request(request: &block_v2::WireBlockRequest) -> bool {
    if request.magic != block_v2::BLOCK_MAGIC
        || request.version != block_v2::FORMAT_VERSION
        || request.flags & !block_v2::KNOWN_REQUEST_FLAGS != 0
        || request.reserved.iter().any(|byte| *byte != 0)
        || request.padding.iter().any(|byte| *byte != 0)
    {
        return false;
    }
    match request.op {
        block_v2::OP_READ | block_v2::OP_WRITE => {
            request.sector_count != 0
                && request.sector_count <= block_v2::MAX_SECTORS_PER_REQUEST
                && request
                    .lba
                    .checked_add(u64::from(request.sector_count))
                    .is_some()
        }
        block_v2::OP_FLUSH | block_v2::OP_GEOMETRY => request.lba == 0 && request.sector_count == 0,
        _ => false,
    }
}

/// Validate the device-semantic completion payload. Substrate status decides
/// whether device_status/detail are meaningful; this checks canonical bytes and
/// the bounded completed prefix independently.
pub fn valid_block_v2_completion(
    completion: &block_v2::WireBlockReply,
    requested_sectors: u32,
) -> bool {
    completion.magic == block_v2::BLOCK_MAGIC
        && completion.version == block_v2::FORMAT_VERSION
        && completion.reserved == [0]
        && matches!(
            completion.op,
            block_v2::OP_READ | block_v2::OP_WRITE | block_v2::OP_FLUSH | block_v2::OP_GEOMETRY
        )
        && completion.sectors_done <= requested_sectors
        && matches!(
            completion.device_status,
            block_v2::DEVICE_STATUS_OK
                | block_v2::DEVICE_STATUS_IO_ERR
                | block_v2::DEVICE_STATUS_UNSUPPORTED
        )
}
