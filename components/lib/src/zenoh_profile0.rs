//! Zenoh Profile 0: the bounded wire subset of one static peer link.
//!
//! The decoder admits the messages `contracts/rpi5-ros2-demo/v2` lists:
//! INIT and OPEN handshakes for wire version 0x09 in peer mode, reliable FRAME
//! batches carrying DECLARE_SUBSCRIBER, UNDECLARE_SUBSCRIBER and PUSH with a Put
//! body, and CLOSE. A stock eclipse-zenoh 1.0 peer adds, and only for the plain demo topic:
//! the optional QoS extension where one was seen on the wire, KEEP_ALIVE, an OAM and a
//! DeclareFinal that are accepted and ignored, and one key-expression alias declared once with
//! DeclareKeyExpr. Everything else is refused with a class from
//! `contracts/zenoh-profile/v1`, never tolerated. Every length is checked
//! against its bound before any byte is taken, nothing allocates, and decoded
//! values borrow from the input batch.
//!
//! A frame is validated in full by [`decode_batch`]; iterating its network
//! messages afterwards cannot fail. Session state, leases and the TCP link are
//! the caller's.

#[cfg(test)]
#[path = "zenoh_profile0/tests.rs"]
mod tests;

pub mod encode;
pub mod fragment;
pub mod graph;
pub mod limits;
pub mod reassembly;
pub mod session;
pub mod tables;

use slime_proto::zenoh_profile as p;

const ID_INIT: u8 = p::ID_INIT as u8;
const ID_OPEN: u8 = p::ID_OPEN as u8;
const ID_CLOSE: u8 = p::ID_CLOSE as u8;
const ID_KEEP_ALIVE: u8 = p::ID_KEEP_ALIVE as u8;
const ID_FRAME: u8 = p::ID_FRAME as u8;
const ID_PUSH: u8 = p::ID_PUSH as u8;
const ID_DECLARE: u8 = p::ID_DECLARE as u8;
const ID_OAM: u8 = p::ID_OAM as u8;
const ID_D_KEYEXPR: u8 = p::ID_DECLARE_KEYEXPR as u8;
const ID_D_FINAL: u8 = p::ID_DECLARE_FINAL as u8;
const ID_D_SUBSCRIBER: u8 = p::ID_DECLARE_SUBSCRIBER as u8;
const ID_U_SUBSCRIBER: u8 = p::ID_UNDECLARE_SUBSCRIBER as u8;
const ID_PUT: u8 = p::ID_PUT as u8;
const FLAG_BIT5: u8 = p::FLAG_BIT5 as u8;
const FLAG_BIT6: u8 = p::FLAG_BIT6 as u8;
const FLAG_Z: u8 = p::FLAG_EXTENSIONS as u8;
const ID_MASK: u8 = 0x1F;
const EXT_WIRE_EXPR: u8 = p::EXT_WIRE_EXPR as u8;
const EXT_ATTACHMENT: u8 = p::EXT_ATTACHMENT as u8;
const EXT_QOS_UNIT: u8 = p::EXT_QOS_UNIT as u8;
const EXT_QOS_NETWORK: u8 = p::EXT_QOS_NETWORK as u8;
/// An OAM as a stock peer sends it: a ZBuf body behind a QoS extension.
const OAM_HEADER: u8 = FLAG_Z | FLAG_BIT6 | ID_OAM;
/// The only OAM id seen on the wire, the link-state one.
const OAM_LINK_STATE: u32 = 1;
/// The largest value the network QoS extension carries: priority, congestion and express.
const QOS_NETWORK_MAX: u32 = 0x1F;
const RESOLUTION_RESERVED: u8 = 0xF0;
const PACKED_RESERVED: u8 = 0x0C;
const U_SUBSCRIBER_HEADER: u8 = FLAG_Z | ID_U_SUBSCRIBER;
/// The WireExpr extension inside U_SUBSCRIBER: flags, scope, then the suffix.
const WIRE_EXPR_FLAG_NAMED: u8 = 0x01;
const WIRE_EXPR_FLAG_SENDER: u8 = 0x02;
const WIRE_EXPR_FLAG_MASK: u8 = WIRE_EXPR_FLAG_NAMED | WIRE_EXPR_FLAG_SENDER;
const WIRE_EXPR_HEADER_BYTES: usize = 2;
/// Bytes before the GID-length byte in the attachment: two little-endian `i64`.
const ATTACHMENT_GID_LEN_AT: usize = 16;

pub use p::{
    GID_BYTES, MAX_ATTACHMENT_BYTES, MAX_BATCH_BYTES, MAX_COOKIE_BYTES, MAX_KEY_BYTES,
    MAX_PAYLOAD_BYTES, STREAM_LENGTH_BYTES,
};

/// How large a batch, a key and a payload a link will read or write. The first release's are the
/// constants of `slime_proto::zenoh_profile`; a configured link states its own. A FRAGMENT is not a
/// batch this decoder reads: a heap session recognises it by header first, and a fixed one refuses it
/// here as unsupported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// The longest batch body, the stream length not included.
    pub batch: usize,
    /// The longest key, in encoded bytes.
    pub key: usize,
    /// The largest payload of one Put.
    pub payload: usize,
}

impl Bounds {
    /// The first release's bounds: a 512-byte batch, a 129-byte key, a 12-byte payload.
    pub const DEMO: Self = Self {
        batch: MAX_BATCH_BYTES,
        key: MAX_KEY_BYTES,
        payload: MAX_PAYLOAD_BYTES,
    };
}

/// Why the decoder refuses input. The vocabulary is `refusalClasses` in the
/// contract; each variant's [`code`](Refusal::code) is that class's code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    EmptyBatch,
    LengthExceedsBatch,
    Truncated,
    TrailingBytes,
    UnsupportedVersion,
    UnsupportedWhatami,
    UnsupportedResolution,
    UnsupportedExtension,
    UnsupportedMessage,
    MalformedMessage,
    OverBound,
    Leb128Overflow,
    Leb128Noncanonical,
    WildcardKeyexpr,
    InvalidKeyexpr,
}

impl Refusal {
    pub const fn code(self) -> u8 {
        match self {
            Self::EmptyBatch => p::REFUSAL_EMPTY_BATCH,
            Self::LengthExceedsBatch => p::REFUSAL_LENGTH_EXCEEDS_BATCH,
            Self::Truncated => p::REFUSAL_TRUNCATED,
            Self::TrailingBytes => p::REFUSAL_TRAILING_BYTES,
            Self::UnsupportedVersion => p::REFUSAL_UNSUPPORTED_VERSION,
            Self::UnsupportedWhatami => p::REFUSAL_UNSUPPORTED_WHATAMI,
            Self::UnsupportedResolution => p::REFUSAL_UNSUPPORTED_RESOLUTION,
            Self::UnsupportedExtension => p::REFUSAL_UNSUPPORTED_EXTENSION,
            Self::UnsupportedMessage => p::REFUSAL_UNSUPPORTED_MESSAGE,
            Self::MalformedMessage => p::REFUSAL_MALFORMED_MESSAGE,
            Self::OverBound => p::REFUSAL_OVER_BOUND,
            Self::Leb128Overflow => p::REFUSAL_LEB128_OVERFLOW,
            Self::Leb128Noncanonical => p::REFUSAL_LEB128_NONCANONICAL,
            Self::WildcardKeyexpr => p::REFUSAL_WILDCARD_KEYEXPR,
            Self::InvalidKeyexpr => p::REFUSAL_INVALID_KEYEXPR,
        }
    }

    /// The class name as the contract spells it.
    pub const fn name(self) -> &'static str {
        match p::refusal_name(self.code()) {
            Some(name) => name,
            None => "unknown",
        }
    }
}

/// Which side's key-expression mapping a wire expression is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    Sender,
    Receiver,
}

impl Mapping {
    const fn from_flag(set: bool) -> Self {
        if set { Self::Sender } else { Self::Receiver }
    }
}

/// The 33-byte `rmw_zenoh` attachment: sequence number, source timestamp and a
/// 16-byte source GID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attachment<'a> {
    pub raw: &'a [u8],
    pub sequence: i64,
    pub timestamp: i64,
    pub gid: &'a [u8],
}

/// One network message inside a FRAME. The alias, OAM and DeclareFinal variants are what a stock
/// peer adds; the session resolves the first and ignores the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network<'a> {
    DeclareSubscriber {
        id: u32,
        mapping: Mapping,
        key: &'a str,
    },
    UndeclareSubscriber {
        id: u32,
        mapping: Mapping,
        key: &'a str,
    },
    /// A stock peer's undeclaration, which names the subscriber by id and restates no key.
    UndeclareSubscriberById { id: u32 },
    PushPut {
        mapping: Mapping,
        key: &'a str,
        attachment: Attachment<'a>,
        payload: &'a [u8],
    },
    /// A numeric alias for a key, declared once; the session resolves messages that name it.
    DeclareKeyExpr { id: u32, key: &'a str },
    /// A subscriber declaration whose key is the alias `alias`, with no suffix.
    DeclareSubscriberAlias {
        id: u32,
        mapping: Mapping,
        alias: u32,
    },
    /// A Put whose key is the alias `alias`, with no suffix.
    PushPutAlias {
        mapping: Mapping,
        alias: u32,
        attachment: Attachment<'a>,
        payload: &'a [u8],
    },
    /// An OAM a stock peer announces itself with; accepted and ignored.
    Oam,
    /// The end of a declaration sequence; accepted and ignored.
    DeclareFinal,
}

/// A validated reliable FRAME. Its network messages parse without failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub sn: u32,
    body: &'a [u8],
    bounds: Bounds,
}

impl<'a> Frame<'a> {
    pub fn messages(&self) -> Networks<'a> {
        Networks {
            reader: Reader::new(self.body),
            bounds: self.bounds,
        }
    }
}

/// Iterator over a validated frame's network messages.
pub struct Networks<'a> {
    reader: Reader<'a>,
    bounds: Bounds,
}

impl<'a> Iterator for Networks<'a> {
    type Item = Network<'a>;

    fn next(&mut self) -> Option<Network<'a>> {
        if self.reader.left() == 0 {
            return None;
        }
        // `decode_batch` validated every message, so an error here is unreachable;
        // ending the iteration is the safe answer if it ever were not.
        match parse_network(&mut self.reader, &self.bounds) {
            Ok(message) => Some(message),
            Err(_) => {
                self.reader.at = self.reader.data.len();
                None
            }
        }
    }
}

/// One decoded batch body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    InitSyn {
        zid: &'a [u8],
        batch_size: u16,
    },
    InitAck {
        zid: &'a [u8],
        batch_size: u16,
        cookie: &'a [u8],
    },
    OpenSyn {
        lease_ms: u64,
        initial_sn: u32,
        cookie: &'a [u8],
    },
    OpenAck {
        lease_ms: u64,
        initial_sn: u32,
    },
    Close {
        reason: u8,
        session: bool,
    },
    /// The single byte `0x04`: traffic that renews the lease and carries nothing else.
    KeepAlive,
    Frame(Frame<'a>),
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    const fn left(&self) -> usize {
        self.data.len() - self.at
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Refusal> {
        let end = self.at.checked_add(count).ok_or(Refusal::Truncated)?;
        let chunk = self.data.get(self.at..end).ok_or(Refusal::Truncated)?;
        self.at = end;
        Ok(chunk)
    }

    fn u8(&mut self) -> Result<u8, Refusal> {
        let byte = *self.data.get(self.at).ok_or(Refusal::Truncated)?;
        self.at += 1;
        Ok(byte)
    }

    /// A canonical LEB128 unsigned integer that fits `bits`.
    fn leb(&mut self, bits: u32) -> Result<u32, Refusal> {
        let maximum = bits.div_ceil(7);
        let mut value: u64 = 0;
        let mut count: u32 = 0;
        let mut last: u8;
        loop {
            let byte = self.u8()?;
            last = byte & 0x7F;
            value |= u64::from(last) << (7 * count);
            count += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if count == maximum {
                return Err(Refusal::Leb128Overflow);
            }
        }
        if value >> bits != 0 {
            return Err(Refusal::Leb128Overflow);
        }
        if count > 1 && last == 0 {
            return Err(Refusal::Leb128Noncanonical);
        }
        u32::try_from(value).map_err(|_| Refusal::Leb128Overflow)
    }

    fn finish(&self) -> Result<(), Refusal> {
        if self.left() == 0 {
            Ok(())
        } else {
            Err(Refusal::TrailingBytes)
        }
    }
}

const fn no_extension(header: u8) -> Result<(), Refusal> {
    if header & FLAG_Z != 0 {
        Err(Refusal::UnsupportedExtension)
    } else {
        Ok(())
    }
}

/// The unit QoS extension on a stock peer's INIT_SYN: optional, id 1, the only extension in its
/// chain. Any other extension byte, a mandatory QoS and a chain that goes on are all refused.
fn init_qos_extension(reader: &mut Reader<'_>) -> Result<(), Refusal> {
    if reader.u8()? == EXT_QOS_UNIT {
        Ok(())
    } else {
        Err(Refusal::UnsupportedExtension)
    }
}

/// The QoS extension on an OAM and on the DECLARE that wraps a DeclareKeyExpr or DeclareSubscriber:
/// optional, id 1, a Z64 value (priority, congestion and express in the low five bits), and the only
/// extension in its chain.
fn network_qos_extension(reader: &mut Reader<'_>) -> Result<(), Refusal> {
    if reader.u8()? != EXT_QOS_NETWORK {
        return Err(Refusal::UnsupportedExtension);
    }
    if reader.leb(p::LEB128_MAX_BITS)? > QOS_NETWORK_MAX {
        return Err(Refusal::MalformedMessage);
    }
    Ok(())
}

fn cookie<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Refusal> {
    let length = reader.leb(p::LEB128_SHORT_BITS)? as usize;
    if length > MAX_COOKIE_BYTES {
        return Err(Refusal::OverBound);
    }
    if length == 0 {
        return Err(Refusal::MalformedMessage);
    }
    reader.take(length)
}

fn init<'a>(mut reader: Reader<'a>, header: u8, graph: bool) -> Result<Message<'a>, Refusal> {
    // An extension is refused before anything else is read, as it always was, except the QoS unit
    // extension a stock peer puts on an INIT_SYN that states its resolution and batch size.
    if header & FLAG_Z != 0 && (header & FLAG_BIT5 != 0 || header & FLAG_BIT6 == 0) {
        return Err(Refusal::UnsupportedExtension);
    }
    if u32::from(reader.u8()?) != p::PROTOCOL_VERSION {
        return Err(Refusal::UnsupportedVersion);
    }
    let packed = reader.u8()?;
    if packed & PACKED_RESERVED != 0 {
        return Err(Refusal::MalformedMessage);
    }
    match u32::from(packed & 0x03) {
        p::WHATAMI_PEER => {}
        3 => return Err(Refusal::MalformedMessage),
        _ => return Err(Refusal::UnsupportedWhatami),
    }
    let zid = reader.take(1 + usize::from(packed >> 4))?;
    // Upstream normalises a trailing zero byte away and refuses the zero ID; a ZID that is not in
    // that canonical form is refused here rather than left with two readings of its length.
    if zid.last() == Some(&0) {
        return Err(Refusal::MalformedMessage);
    }
    let mut batch_size = u16::MAX;
    if header & FLAG_BIT6 != 0 {
        let resolution = reader.u8()?;
        if resolution & RESOLUTION_RESERVED != 0 {
            return Err(Refusal::MalformedMessage);
        }
        if u32::from(resolution) != p::DEFAULT_RESOLUTION {
            return Err(Refusal::UnsupportedResolution);
        }
        let bytes = reader.take(2)?;
        batch_size = u16::from_le_bytes([bytes[0], bytes[1]]);
        if batch_size == 0 {
            return Err(Refusal::MalformedMessage);
        }
    }
    if header & FLAG_BIT5 != 0 {
        let cookie = cookie(&mut reader)?;
        reader.finish()?;
        Ok(Message::InitAck {
            zid,
            batch_size,
            cookie,
        })
    } else {
        if header & FLAG_Z != 0 {
            if graph {
                graph::init_extensions(&mut reader)?;
            } else {
                init_qos_extension(&mut reader)?;
            }
        }
        reader.finish()?;
        Ok(Message::InitSyn { zid, batch_size })
    }
}

fn open<'a>(mut reader: Reader<'a>, header: u8) -> Result<Message<'a>, Refusal> {
    no_extension(header)?;
    let lease = reader.leb(p::LEB128_MAX_BITS)?;
    if lease == 0 {
        return Err(Refusal::MalformedMessage);
    }
    let initial_sn = reader.leb(p::LEB128_MAX_BITS)?;
    let lease_ms = if header & FLAG_BIT6 != 0 {
        u64::from(lease) * 1000
    } else {
        u64::from(lease)
    };
    if header & FLAG_BIT5 != 0 {
        reader.finish()?;
        Ok(Message::OpenAck {
            lease_ms,
            initial_sn,
        })
    } else {
        let cookie = cookie(&mut reader)?;
        reader.finish()?;
        Ok(Message::OpenSyn {
            lease_ms,
            initial_sn,
            cookie,
        })
    }
}

fn close<'a>(mut reader: Reader<'a>, header: u8) -> Result<Message<'a>, Refusal> {
    no_extension(header)?;
    if header & FLAG_BIT6 != 0 {
        return Err(Refusal::MalformedMessage);
    }
    let reason = reader.u8()?;
    if u32::from(reason) > p::CLOSE_CONNECTION_TO_SELF {
        return Err(Refusal::MalformedMessage);
    }
    reader.finish()?;
    Ok(Message::Close {
        reason,
        session: header & FLAG_BIT5 != 0,
    })
}

/// KEEP_ALIVE is the single byte `04`: no flag, no extension and no body.
fn keep_alive(reader: Reader<'_>, header: u8) -> Result<Message<'_>, Refusal> {
    no_extension(header)?;
    if header & (FLAG_BIT5 | FLAG_BIT6) != 0 {
        return Err(Refusal::MalformedMessage);
    }
    reader.finish()?;
    Ok(Message::KeepAlive)
}

fn key_expression(bytes: &[u8]) -> Result<&str, Refusal> {
    let key = core::str::from_utf8(bytes).map_err(|_| Refusal::InvalidKeyexpr)?;
    if key.bytes().any(|byte| byte == b'*' || byte == b'$') {
        return Err(Refusal::WildcardKeyexpr);
    }
    if key.bytes().any(|byte| byte == b'?' || byte == b'#')
        || key.starts_with('/')
        || key.ends_with('/')
        || key.contains("//")
    {
        return Err(Refusal::InvalidKeyexpr);
    }
    Ok(key)
}

/// What a wire expression names: a key in full, or the alias a stock peer declared for it.
enum KeyRef<'a> {
    Full(&'a str),
    Alias(u32),
}

/// A wire expression, `<scope:z16>[<suffix:<u8;z16>>]`. A suffix in the global scope is a key in
/// full. A nonzero scope with no suffix is an alias reference. A suffix after a nonzero scope would
/// extend the declared key, and the alias resolves to that key and no other, so it is refused; the
/// suffix is judged first, so a wildcard or an oversized key keeps its own class.
fn key_reference<'a>(
    reader: &mut Reader<'a>,
    named: bool,
    bounds: &Bounds,
) -> Result<KeyRef<'a>, Refusal> {
    let scope = reader.leb(p::LEB128_SHORT_BITS)?;
    if !named {
        return if scope == 0 {
            Err(Refusal::InvalidKeyexpr)
        } else {
            Ok(KeyRef::Alias(scope))
        };
    }
    let length = reader.leb(p::LEB128_SHORT_BITS)? as usize;
    if length > bounds.key {
        return Err(Refusal::OverBound);
    }
    if length == 0 {
        return Err(Refusal::InvalidKeyexpr);
    }
    let key = key_expression(reader.take(length)?)?;
    if scope != 0 {
        return Err(Refusal::InvalidKeyexpr);
    }
    Ok(KeyRef::Full(key))
}

fn declare<'a>(
    reader: &mut Reader<'a>,
    header: u8,
    bounds: &Bounds,
) -> Result<Network<'a>, Refusal> {
    // The interest flag carries an interest id before the declaration. Every declaration with it
    // was refused as an unsupported message; the one a stock peer ends its declarations with, a
    // DeclareFinal, is now accepted and ignored, and anything else with the flag stays that way.
    if header & FLAG_BIT5 != 0 {
        return declare_final(reader, header);
    }
    if header & FLAG_BIT6 != 0 {
        return Err(Refusal::MalformedMessage);
    }
    let qos = header & FLAG_Z != 0;
    if qos {
        network_qos_extension(reader)?;
    }
    let sub = reader.u8()?;
    match sub & ID_MASK {
        ID_D_KEYEXPR => {
            // Only the form that names its key in full: an alias for a key the peer states.
            if sub & FLAG_BIT5 == 0 {
                return Err(Refusal::UnsupportedMessage);
            }
            if sub & FLAG_BIT6 != 0 {
                return Err(Refusal::MalformedMessage);
            }
            if sub & FLAG_Z != 0 {
                return Err(Refusal::UnsupportedExtension);
            }
            // The id is the scope every reference to the alias carries, so it has the same 16 bits;
            // a wider one could never be named and would only take the single alias slot.
            let id = reader.leb(p::LEB128_SHORT_BITS)?;
            // Scope 0 is the global scope, so no reference can name an alias with id 0.
            if id == 0 {
                return Err(Refusal::InvalidKeyexpr);
            }
            match key_reference(reader, true, bounds)? {
                KeyRef::Full(key) => Ok(Network::DeclareKeyExpr { id, key }),
                KeyRef::Alias(_) => Err(Refusal::InvalidKeyexpr),
            }
        }
        ID_D_SUBSCRIBER => {
            if sub & FLAG_Z != 0 {
                return Err(Refusal::UnsupportedExtension);
            }
            let id = reader.leb(p::LEB128_MAX_BITS)?;
            let mapping = Mapping::from_flag(sub & FLAG_BIT6 != 0);
            match key_reference(reader, sub & FLAG_BIT5 != 0, bounds)? {
                KeyRef::Full(key) => Ok(Network::DeclareSubscriber { id, mapping, key }),
                KeyRef::Alias(alias) => Ok(Network::DeclareSubscriberAlias { id, mapping, alias }),
            }
        }
        ID_U_SUBSCRIBER => {
            // Behind the QoS extension only the form a stock peer sends is taken: no extension, so no
            // wire expression and no key, and the subscriber is named by its id alone.
            if qos {
                if sub & FLAG_Z != 0 {
                    return Err(Refusal::UnsupportedExtension);
                }
                if sub != ID_U_SUBSCRIBER {
                    return Err(Refusal::MalformedMessage);
                }
                let id = reader.leb(p::LEB128_MAX_BITS)?;
                return Ok(Network::UndeclareSubscriberById { id });
            }
            if sub != U_SUBSCRIBER_HEADER {
                return Err(Refusal::MalformedMessage);
            }
            let id = reader.leb(p::LEB128_MAX_BITS)?;
            if reader.u8()? != EXT_WIRE_EXPR {
                return Err(Refusal::UnsupportedExtension);
            }
            let length = reader.leb(p::LEB128_MAX_BITS)? as usize;
            if length > WIRE_EXPR_HEADER_BYTES + bounds.key {
                return Err(Refusal::OverBound);
            }
            let mut inner = Reader::new(reader.take(length)?);
            let flags = inner.u8()?;
            if flags & !WIRE_EXPR_FLAG_MASK != 0 {
                return Err(Refusal::MalformedMessage);
            }
            if inner.leb(p::LEB128_SHORT_BITS)? != 0
                || flags & WIRE_EXPR_FLAG_NAMED == 0
                || inner.left() == 0
            {
                return Err(Refusal::InvalidKeyexpr);
            }
            let rest = inner.left();
            let key = key_expression(inner.take(rest)?)?;
            Ok(Network::UndeclareSubscriber {
                id,
                mapping: Mapping::from_flag(flags & WIRE_EXPR_FLAG_SENDER != 0),
                key,
            })
        }
        _ => Err(Refusal::UnsupportedMessage),
    }
}

/// A DECLARE with the interest flag: `<interest id>` and a DeclareFinal. The DECLARE around a
/// DeclareFinal carried no extension on the wire, so an extension on it is refused.
fn declare_final<'a>(reader: &mut Reader<'a>, header: u8) -> Result<Network<'a>, Refusal> {
    if header & FLAG_BIT6 != 0 {
        return Err(Refusal::UnsupportedMessage);
    }
    reader
        .leb(p::LEB128_MAX_BITS)
        .map_err(|_| Refusal::UnsupportedMessage)?;
    if header & FLAG_Z != 0 {
        return Err(Refusal::UnsupportedExtension);
    }
    match reader.u8().map_err(|_| Refusal::UnsupportedMessage)? {
        ID_D_FINAL => Ok(Network::DeclareFinal),
        other if other & ID_MASK == ID_D_FINAL => Err(Refusal::MalformedMessage),
        _ => Err(Refusal::UnsupportedMessage),
    }
}

/// An OAM as a stock peer announces itself: the link-state id behind a QoS extension, with a ZBuf
/// body that is bounded by the batch and ignored.
fn oam<'a>(reader: &mut Reader<'a>, header: u8) -> Result<Network<'a>, Refusal> {
    if header != OAM_HEADER {
        return Err(Refusal::UnsupportedMessage);
    }
    if reader.leb(p::LEB128_SHORT_BITS)? != OAM_LINK_STATE {
        return Err(Refusal::UnsupportedMessage);
    }
    network_qos_extension(reader)?;
    let length = reader.leb(p::LEB128_SHORT_BITS)? as usize;
    reader.take(length)?;
    Ok(Network::Oam)
}

fn push<'a>(reader: &mut Reader<'a>, header: u8, bounds: &Bounds) -> Result<Network<'a>, Refusal> {
    no_extension(header)?;
    let key = key_reference(reader, header & FLAG_BIT5 != 0, bounds)?;
    let body = reader.u8()?;
    if body & ID_MASK != ID_PUT || body & (FLAG_BIT5 | FLAG_BIT6) != 0 {
        return Err(Refusal::UnsupportedMessage);
    }
    if body & FLAG_Z == 0 {
        return Err(Refusal::MalformedMessage);
    }
    if reader.u8()? != EXT_ATTACHMENT {
        return Err(Refusal::UnsupportedExtension);
    }
    let length = reader.leb(p::LEB128_MAX_BITS)? as usize;
    if length > MAX_ATTACHMENT_BYTES {
        return Err(Refusal::OverBound);
    }
    if length < MAX_ATTACHMENT_BYTES {
        return Err(Refusal::MalformedMessage);
    }
    let raw = reader.take(length)?;
    if usize::from(raw[ATTACHMENT_GID_LEN_AT]) != GID_BYTES {
        return Err(Refusal::MalformedMessage);
    }
    let attachment = Attachment {
        raw,
        sequence: i64::from_le_bytes(word(raw, 0)),
        timestamp: i64::from_le_bytes(word(raw, 8)),
        gid: &raw[ATTACHMENT_GID_LEN_AT + 1..],
    };
    let size = reader.leb(p::LEB128_MAX_BITS)? as usize;
    if size > bounds.payload {
        return Err(Refusal::OverBound);
    }
    let mapping = Mapping::from_flag(header & FLAG_BIT6 != 0);
    let payload = reader.take(size)?;
    Ok(match key {
        KeyRef::Full(key) => Network::PushPut {
            mapping,
            key,
            attachment,
            payload,
        },
        KeyRef::Alias(alias) => Network::PushPutAlias {
            mapping,
            alias,
            attachment,
            payload,
        },
    })
}

fn word(bytes: &[u8], at: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    out
}

fn parse_network<'a>(reader: &mut Reader<'a>, bounds: &Bounds) -> Result<Network<'a>, Refusal> {
    let header = reader.u8()?;
    match header & ID_MASK {
        ID_DECLARE => declare(reader, header, bounds),
        ID_PUSH => push(reader, header, bounds),
        ID_OAM => oam(reader, header),
        _ => Err(Refusal::UnsupportedMessage),
    }
}

fn frame<'a>(mut reader: Reader<'a>, header: u8, bounds: &Bounds) -> Result<Message<'a>, Refusal> {
    if header & FLAG_BIT5 == 0 {
        return Err(Refusal::UnsupportedMessage);
    }
    no_extension(header)?;
    if header & FLAG_BIT6 != 0 {
        return Err(Refusal::MalformedMessage);
    }
    let sn = reader.leb(p::LEB128_MAX_BITS)?;
    if reader.left() == 0 {
        return Err(Refusal::MalformedMessage);
    }
    let body = Reader::new(&reader.data[reader.at..]);
    let mut check = body;
    while check.left() != 0 {
        parse_network(&mut check, bounds)?;
    }
    Ok(Message::Frame(Frame {
        sn,
        body: body.data,
        bounds: *bounds,
    }))
}

/// Decodes one batch body, the bytes after a stream length prefix, under the first release's bounds.
pub fn decode_batch(batch: &[u8]) -> Result<Message<'_>, Refusal> {
    decode_batch_with(batch, &Bounds::DEMO)
}

/// Decodes one batch body under `bounds`.
pub fn decode_batch_with<'a>(batch: &'a [u8], bounds: &Bounds) -> Result<Message<'a>, Refusal> {
    decode_batch_in(batch, bounds, false)
}

/// Decodes one batch body. `graph` is the one difference a graph session makes to a handshake message:
/// the INIT extensions an rmw_zenoh peer sends. Its FRAMEs are read by [`graph::decode_graph_batch`].
fn decode_batch_in<'a>(
    batch: &'a [u8],
    bounds: &Bounds,
    graph: bool,
) -> Result<Message<'a>, Refusal> {
    if batch.is_empty() {
        return Err(Refusal::EmptyBatch);
    }
    if batch.len() > bounds.batch {
        return Err(Refusal::LengthExceedsBatch);
    }
    let mut reader = Reader::new(batch);
    let header = reader.u8()?;
    match header & ID_MASK {
        ID_INIT => init(reader, header, graph),
        ID_OPEN => open(reader, header),
        ID_CLOSE => close(reader, header),
        ID_KEEP_ALIVE => keep_alive(reader, header),
        ID_FRAME => frame(reader, header, bounds),
        _ => Err(Refusal::UnsupportedMessage),
    }
}

/// Reassembles length-prefixed batches from a TCP byte stream in fixed storage.
///
/// [`push`](Self::push) copies what fits and reports how much it took, so a
/// caller loops: push, drain every complete batch, push the remainder. A prefix
/// is judged as soon as both its bytes have arrived, wherever the chunk
/// boundaries fall.
pub struct StreamFramerOf<const N: usize> {
    buffer: [u8; N],
    len: usize,
}

/// The first release's framer: a 512-byte batch and its two-byte length.
pub type StreamFramer = StreamFramerOf<{ STREAM_LENGTH_BYTES + MAX_BATCH_BYTES }>;

impl<const N: usize> Default for StreamFramerOf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> StreamFramerOf<N> {
    pub const fn new() -> Self {
        Self {
            buffer: [0; N],
            len: 0,
        }
    }

    /// Bytes held that do not yet form a complete batch, plus any complete one.
    pub const fn pending(&self) -> usize {
        self.len
    }

    /// Copies as much of `chunk` as fits and returns the number of bytes taken.
    pub fn push(&mut self, chunk: &[u8]) -> usize {
        let take = chunk.len().min(self.buffer.len() - self.len);
        self.buffer[self.len..self.len + take].copy_from_slice(&chunk[..take]);
        self.len += take;
        take
    }

    /// The next complete batch, `None` while more bytes are needed, or the
    /// refusal a length prefix draws. A refusal leaves the framer unusable.
    pub fn peek_batch(&self) -> Result<Option<&[u8]>, Refusal> {
        if self.len < STREAM_LENGTH_BYTES {
            return Ok(None);
        }
        let length = usize::from(u16::from_le_bytes([self.buffer[0], self.buffer[1]]));
        if length == 0 {
            return Err(Refusal::EmptyBatch);
        }
        if length > N.saturating_sub(STREAM_LENGTH_BYTES) {
            return Err(Refusal::LengthExceedsBatch);
        }
        let end = STREAM_LENGTH_BYTES + length;
        if self.len < end {
            return Ok(None);
        }
        Ok(Some(&self.buffer[STREAM_LENGTH_BYTES..end]))
    }

    /// Drops the batch [`peek_batch`](Self::peek_batch) returned.
    pub fn consume_batch(&mut self) {
        if self.len < STREAM_LENGTH_BYTES {
            return;
        }
        let length = usize::from(u16::from_le_bytes([self.buffer[0], self.buffer[1]]));
        let end = (STREAM_LENGTH_BYTES + length).min(self.len);
        self.buffer.copy_within(end..self.len, 0);
        self.len -= end;
    }
}
