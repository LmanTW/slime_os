//! A Profile 0 session that holds the graph an rmw_zenoh peer declares.
//!
//! An rmw_zenoh node declares, before it publishes, key-expression aliases, queryables, subscribers and
//! one liveliness token for each node, publisher, subscription and service. It sends a timestamp with
//! every Put and two extensions in its INIT. The plain session refuses all of it, and keeps refusing it:
//! [`GraphSessionOf`] is a separate type, selected by `Params::graph`, so no plain decoder, event or
//! error gains a variant and the stock-peer exams keep their pinned refusals.
//!
//! A graph session records declarations and sends nothing in reply. It holds no subscription of its own,
//! so every PUSH is dropped and counted. A FRAME is applied whole or not at all, as in the plain session.
//! Keys and counts are bounded by the const parameters, and nothing allocates.

use super::session::{Config, Event, Outcome, Params, Role, SessionError, SessionOf, State};
use super::tables::{InsertError, Keys, SlotTable};
use super::{
    Bounds, FLAG_BIT5, FLAG_BIT6, FLAG_Z, ID_D_FINAL, ID_DECLARE, ID_FRAME, ID_MASK, ID_PUSH,
    ID_PUT, MAX_ATTACHMENT_BYTES, Message, Reader, Refusal, decode_batch_in, key_reference,
    network_qos_extension,
};
use slime_proto::zenoh_profile as p;

/// The longest key a graph session takes: the longest alias an rmw_zenoh peer declared for a liveliness
/// token.
pub const GRAPH_KEY_BYTES: usize = 253;
/// The batch a graph listener announces. An rmw_zenoh peer told this keeps each batch within it.
pub const GRAPH_BATCH_BYTES: usize = 512;
/// The aliases and the declarations a graph session holds, and the table changes one FRAME may make.
pub const GRAPH_SLOTS: usize = 32;
const JOURNAL: usize = 48;

const EXT_ID_MASK: u8 = 0x0F;
const EXT_MANDATORY: u8 = 0x10;
const EXT_ENCODING_MASK: u8 = 0x60;
const EXT_ZBUF: u8 = 0x40;
const EXT_MORE: u8 = 0x80;
/// The unit extension an INIT_SYN starts its chain with: id 1, optional.
const INIT_EXT_UNIT: u8 = 0x01;
/// The extension that ends the chain: id 7, optional, carrying a Z64 value.
const INIT_EXT_PATCH: u8 = 0x27;
const INIT_PATCH_MAX: u32 = 1;
/// A queryable's extension: id 1, optional, carrying a Z64 value.
const QUERYABLE_EXT: u8 = 0x21;
const SOURCE_INFO_EXT: u8 = 1;
const ATTACHMENT_EXT: u8 = 3;
const SOURCE_INFO_MAX: usize = 64;
const TIMESTAMP_ZID_MAX: usize = 16;

const ID_D_QUERYABLE: u8 = 4;
const ID_D_TOKEN: u8 = 6;
const ID_D_SUBSCRIBER: u8 = p::ID_DECLARE_SUBSCRIBER as u8;
const ID_D_KEYEXPR: u8 = p::ID_DECLARE_KEYEXPR as u8;
const ID_U_QUERYABLE: u8 = 5;
const ID_U_TOKEN: u8 = 7;
const EXT_WIRE_EXPR: u8 = p::EXT_WIRE_EXPR as u8;

/// What a declaration declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Subscriber,
    Queryable,
    Token,
}

impl Kind {
    const fn tag(self) -> u64 {
        match self {
            Self::Subscriber => ID_D_SUBSCRIBER as u64,
            Self::Queryable => ID_D_QUERYABLE as u64,
            Self::Token => ID_D_TOKEN as u64,
        }
    }

    const fn from_tag(tag: u64) -> Option<Self> {
        match tag {
            2 => Some(Self::Subscriber),
            4 => Some(Self::Queryable),
            6 => Some(Self::Token),
            _ => None,
        }
    }
}

/// A wire expression: an alias and a suffix, or a key in full when `scope` is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireKey<'a> {
    pub scope: u32,
    pub suffix: Option<&'a str>,
    /// The sender's mapping: the alias is one the peer declared.
    pub sender: bool,
}

/// One network message of a graph FRAME.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphNetwork<'a> {
    KeyExpr {
        id: u32,
        key: &'a str,
    },
    Declare {
        kind: Kind,
        id: u32,
        key: WireKey<'a>,
    },
    /// An undeclaration of a queryable or a token, by id.
    Withdraw {
        kind: Kind,
        id: u32,
    },
    Final,
    Push {
        key: WireKey<'a>,
    },
}

/// A validated reliable FRAME of a graph session. Its network messages parse without failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphFrame<'a> {
    pub sn: u32,
    body: &'a [u8],
    bounds: Bounds,
}

impl<'a> GraphFrame<'a> {
    pub fn messages(&self) -> GraphNetworks<'a> {
        GraphNetworks {
            reader: Reader::new(self.body),
            bounds: self.bounds,
        }
    }
}

pub struct GraphNetworks<'a> {
    reader: Reader<'a>,
    bounds: Bounds,
}

impl<'a> Iterator for GraphNetworks<'a> {
    type Item = GraphNetwork<'a>;

    fn next(&mut self) -> Option<GraphNetwork<'a>> {
        if self.reader.left() == 0 {
            return None;
        }
        // `decode_graph_batch` validated every message, so an error here is unreachable; ending the
        // iteration is the safe answer if it ever were not.
        match parse_graph_network(&mut self.reader, &self.bounds) {
            Ok(message) => Some(message),
            Err(_) => {
                self.reader.at = self.reader.data.len();
                None
            }
        }
    }
}

/// One decoded batch body of a graph session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphMessage<'a> {
    /// A handshake, keep-alive or close, read as the plain decoder reads it except that an INIT may
    /// carry the extensions an rmw_zenoh peer sends.
    Plain(Message<'a>),
    Frame(GraphFrame<'a>),
}

/// The extension chain an rmw_zenoh peer ends its INIT_SYN with: the unit extension, then optionally
/// the patch extension with a value of at most 1. Every other chain is refused.
pub(super) fn init_extensions(reader: &mut Reader<'_>) -> Result<(), Refusal> {
    let first = reader.u8()?;
    if first & (EXT_ID_MASK | EXT_MANDATORY | EXT_ENCODING_MASK) != INIT_EXT_UNIT {
        return Err(Refusal::UnsupportedExtension);
    }
    if first & EXT_MORE == 0 {
        return Ok(());
    }
    if reader.u8()? != INIT_EXT_PATCH {
        return Err(Refusal::UnsupportedExtension);
    }
    if reader.leb(p::LEB128_MAX_BITS)? > INIT_PATCH_MAX {
        return Err(Refusal::UnsupportedExtension);
    }
    Ok(())
}

fn leb64(reader: &mut Reader<'_>) -> Result<u64, Refusal> {
    let mut value: u64 = 0;
    for count in 0..10u32 {
        let byte = reader.u8()?;
        let low = u64::from(byte & 0x7F);
        if count == 9 && low > 1 {
            return Err(Refusal::Leb128Overflow);
        }
        value |= low << (7 * count);
        if byte & 0x80 == 0 {
            if count > 0 && byte == 0 {
                return Err(Refusal::Leb128Noncanonical);
            }
            return Ok(value);
        }
    }
    Err(Refusal::Leb128Overflow)
}

fn has_wildcard(bytes: &[u8]) -> bool {
    bytes.iter().any(|&byte| byte == b'*' || byte == b'$')
}

/// The suffix of a wire expression. A wildcard is the declaration's to judge, because a subscriber and a
/// queryable take one and a token does not. A suffix after an alias starts with `/`, so a leading slash
/// is judged when the key is joined.
fn suffix_text(raw: &[u8], scope: u32) -> Result<&str, Refusal> {
    let text = core::str::from_utf8(raw).map_err(|_| Refusal::InvalidKeyexpr)?;
    if raw.iter().any(|&byte| byte == b'?' || byte == b'#') || text.contains("//") {
        return Err(Refusal::InvalidKeyexpr);
    }
    if scope == 0 && (text.starts_with('/') || text.ends_with('/')) {
        return Err(Refusal::InvalidKeyexpr);
    }
    Ok(text)
}

fn wire_key<'a>(
    reader: &mut Reader<'a>,
    named: bool,
    sender: bool,
    bounds: &Bounds,
) -> Result<WireKey<'a>, Refusal> {
    let scope = reader.leb(p::LEB128_SHORT_BITS)?;
    let suffix = if named {
        let length = reader.leb(p::LEB128_SHORT_BITS)? as usize;
        if length > bounds.key {
            return Err(Refusal::OverBound);
        }
        if length == 0 {
            return Err(Refusal::InvalidKeyexpr);
        }
        Some(suffix_text(reader.take(length)?, scope)?)
    } else {
        None
    };
    if scope == 0 && suffix.is_none() {
        return Err(Refusal::InvalidKeyexpr);
    }
    Ok(WireKey {
        scope,
        suffix,
        sender,
    })
}

/// A queryable's extension: id 1, optional, one Z64 value.
fn queryable_extension(reader: &mut Reader<'_>) -> Result<(), Refusal> {
    if reader.u8()? != QUERYABLE_EXT {
        return Err(Refusal::UnsupportedExtension);
    }
    reader.leb(p::LEB128_MAX_BITS)?;
    Ok(())
}

/// The wire-expression extension of an undeclaration, in the one form a peer sent: empty flags and the
/// global scope, so it restates no key.
fn empty_wire_expr_extension(reader: &mut Reader<'_>) -> Result<(), Refusal> {
    if reader.u8()? != EXT_WIRE_EXPR {
        return Err(Refusal::UnsupportedExtension);
    }
    if reader.leb(p::LEB128_MAX_BITS)? != 2
        || reader.u8()? != 0
        || reader.leb(p::LEB128_SHORT_BITS)? != 0
    {
        return Err(Refusal::UnsupportedExtension);
    }
    Ok(())
}

fn declare<'a>(
    reader: &mut Reader<'a>,
    header: u8,
    bounds: &Bounds,
) -> Result<GraphNetwork<'a>, Refusal> {
    if header & FLAG_BIT5 != 0 {
        // The interest flag carries an interest id, and the only declaration with it is a DeclareFinal.
        reader
            .leb(p::LEB128_MAX_BITS)
            .map_err(|_| Refusal::UnsupportedMessage)?;
        if header & FLAG_BIT6 != 0 {
            return Err(Refusal::UnsupportedMessage);
        }
        if header & FLAG_Z != 0 {
            network_qos_extension(reader)?;
        }
        return match reader.u8().map_err(|_| Refusal::UnsupportedMessage)? {
            ID_D_FINAL => Ok(GraphNetwork::Final),
            other if other & ID_MASK == ID_D_FINAL => Err(Refusal::MalformedMessage),
            _ => Err(Refusal::UnsupportedMessage),
        };
    }
    if header & FLAG_BIT6 != 0 {
        return Err(Refusal::MalformedMessage);
    }
    if header & FLAG_Z != 0 {
        network_qos_extension(reader)?;
    }
    let sub = reader.u8()?;
    match sub & ID_MASK {
        ID_D_KEYEXPR => {
            if sub & FLAG_BIT5 == 0 {
                return Err(Refusal::UnsupportedMessage);
            }
            if sub & FLAG_BIT6 != 0 {
                return Err(Refusal::MalformedMessage);
            }
            if sub & FLAG_Z != 0 {
                return Err(Refusal::UnsupportedExtension);
            }
            let id = reader.leb(p::LEB128_SHORT_BITS)?;
            if id == 0 {
                return Err(Refusal::InvalidKeyexpr);
            }
            match key_reference(reader, true, bounds)? {
                super::KeyRef::Full(key) => Ok(GraphNetwork::KeyExpr { id, key }),
                super::KeyRef::Alias(_) => Err(Refusal::InvalidKeyexpr),
            }
        }
        tag @ (ID_D_SUBSCRIBER | ID_D_QUERYABLE | ID_D_TOKEN) => {
            let kind = Kind::from_tag(u64::from(tag)).ok_or(Refusal::UnsupportedMessage)?;
            if sub & FLAG_Z != 0 && kind != Kind::Queryable {
                return Err(Refusal::UnsupportedExtension);
            }
            let id = reader.leb(p::LEB128_MAX_BITS)?;
            let key = wire_key(reader, sub & FLAG_BIT5 != 0, sub & FLAG_BIT6 != 0, bounds)?;
            if kind == Kind::Token && key.suffix.is_some_and(|text| has_wildcard(text.as_bytes())) {
                return Err(Refusal::WildcardKeyexpr);
            }
            if sub & FLAG_Z != 0 {
                queryable_extension(reader)?;
            }
            Ok(GraphNetwork::Declare { kind, id, key })
        }
        tag @ (ID_U_QUERYABLE | ID_U_TOKEN) => {
            if sub & (FLAG_BIT5 | FLAG_BIT6) != 0 {
                return Err(Refusal::MalformedMessage);
            }
            let id = reader.leb(p::LEB128_MAX_BITS)?;
            if sub & FLAG_Z != 0 {
                empty_wire_expr_extension(reader)?;
            }
            let kind = if tag == ID_U_QUERYABLE {
                Kind::Queryable
            } else {
                Kind::Token
            };
            Ok(GraphNetwork::Withdraw { kind, id })
        }
        _ => Err(Refusal::UnsupportedMessage),
    }
}

/// The extensions of a Put a graph session takes: source info, then the attachment, each optional and
/// each a ZBuf.
fn put_extensions(reader: &mut Reader<'_>) -> Result<(), Refusal> {
    let mut last = 0u8;
    loop {
        let header = reader.u8()?;
        if header & EXT_MANDATORY != 0 || header & EXT_ENCODING_MASK != EXT_ZBUF {
            return Err(Refusal::UnsupportedExtension);
        }
        let id = header & EXT_ID_MASK;
        let length = reader.leb(p::LEB128_MAX_BITS)? as usize;
        match id {
            SOURCE_INFO_EXT if last == 0 => {
                if length > SOURCE_INFO_MAX {
                    return Err(Refusal::OverBound);
                }
            }
            ATTACHMENT_EXT if last < ATTACHMENT_EXT => {
                if length > MAX_ATTACHMENT_BYTES {
                    return Err(Refusal::OverBound);
                }
                if length < MAX_ATTACHMENT_BYTES {
                    return Err(Refusal::MalformedMessage);
                }
            }
            _ => return Err(Refusal::UnsupportedExtension),
        }
        reader.take(length)?;
        last = id;
        if header & EXT_MORE == 0 {
            return Ok(());
        }
    }
}

fn push<'a>(
    reader: &mut Reader<'a>,
    header: u8,
    bounds: &Bounds,
) -> Result<GraphNetwork<'a>, Refusal> {
    let key = wire_key(
        reader,
        header & FLAG_BIT5 != 0,
        header & FLAG_BIT6 != 0,
        bounds,
    )?;
    if header & FLAG_Z != 0 {
        network_qos_extension(reader)?;
    }
    let put = reader.u8()?;
    if put & ID_MASK != ID_PUT || put & FLAG_BIT6 != 0 {
        return Err(Refusal::UnsupportedMessage);
    }
    if put & FLAG_BIT5 != 0 {
        leb64(reader)?;
        let zid = reader.leb(p::LEB128_SHORT_BITS)? as usize;
        if zid > TIMESTAMP_ZID_MAX {
            return Err(Refusal::OverBound);
        }
        reader.take(zid)?;
    }
    if put & FLAG_Z != 0 {
        put_extensions(reader)?;
    }
    let size = reader.leb(p::LEB128_MAX_BITS)? as usize;
    if size > bounds.payload {
        return Err(Refusal::OverBound);
    }
    reader.take(size)?;
    Ok(GraphNetwork::Push { key })
}

fn parse_graph_network<'a>(
    reader: &mut Reader<'a>,
    bounds: &Bounds,
) -> Result<GraphNetwork<'a>, Refusal> {
    let header = reader.u8()?;
    match header & ID_MASK {
        ID_DECLARE => declare(reader, header, bounds),
        ID_PUSH => push(reader, header, bounds),
        _ => Err(Refusal::UnsupportedMessage),
    }
}

fn graph_frame<'a>(
    mut reader: Reader<'a>,
    header: u8,
    bounds: &Bounds,
) -> Result<GraphMessage<'a>, Refusal> {
    if header & FLAG_BIT5 == 0 {
        return Err(Refusal::UnsupportedMessage);
    }
    if header & FLAG_Z != 0 {
        return Err(Refusal::UnsupportedExtension);
    }
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
        parse_graph_network(&mut check, bounds)?;
    }
    Ok(GraphMessage::Frame(GraphFrame {
        sn,
        body: body.data,
        bounds: *bounds,
    }))
}

/// Decodes one batch body, the bytes after a stream length prefix, under `bounds`.
pub fn decode_graph_batch<'a>(
    batch: &'a [u8],
    bounds: &Bounds,
) -> Result<GraphMessage<'a>, Refusal> {
    if batch.is_empty() {
        return Err(Refusal::EmptyBatch);
    }
    if batch.len() > bounds.batch {
        return Err(Refusal::LengthExceedsBatch);
    }
    let mut reader = Reader::new(batch);
    let header = reader.u8()?;
    if header & ID_MASK == ID_FRAME {
        return graph_frame(reader, header, bounds);
    }
    decode_batch_in(batch, bounds, true).map(GraphMessage::Plain)
}

/// Why a graph session refuses a call. Every error leaves the session unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// The decoder, the handshake or the sequence number refused it.
    Session(SessionError),
    /// An undeclaration of a declaration the session does not hold.
    UnknownDeclaration,
}

impl From<SessionError> for GraphError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<Refusal> for GraphError {
    fn from(refusal: Refusal) -> Self {
        Self::Session(SessionError::Decode(refusal))
    }
}

impl GraphError {
    /// The class name the exams pin: the decoder's own, or the session's.
    pub fn class(self) -> &'static str {
        match self {
            Self::UnknownDeclaration => "unknown-declaration",
            Self::Session(error) => match error {
                SessionError::Decode(refusal) => refusal.name(),
                SessionError::SubscriberLimit => "subscriber-limit",
                SessionError::UnknownSubscriber => "unknown-subscriber",
                SessionError::TooManyMessages => "too-many-messages",
                SessionError::UnexpectedMessage => "unexpected-message",
                SessionError::UndeclaredKey => "undeclared-key",
                SessionError::SequenceMismatch => "sequence-mismatch",
                SessionError::CookieMismatch => "cookie-mismatch",
                SessionError::NotOpen => "not-open",
                SessionError::Closed => "closed",
                SessionError::InvalidConfig => "invalid-config",
                SessionError::Encode(_) => "encode",
                SessionError::Fragment(error) => error.class(),
                SessionError::OutOfMemory => "out-of-memory",
                SessionError::NeedsFragments => "needs-fragments",
            },
        }
    }
}

/// How many of each network message a graph session accepted. A FRAME that is refused counts nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub keyexpr: u32,
    pub subscriber: u32,
    pub queryable: u32,
    pub token: u32,
    pub unqueryable: u32,
    pub untoken: u32,
    pub finals: u32,
    pub push: u32,
}

impl Counts {
    /// The count of each kind by the name the exam uses, in the order of those names.
    pub const fn each(&self) -> [(&'static str, u32); 8] {
        [
            ("final", self.finals),
            ("keyexpr", self.keyexpr),
            ("push", self.push),
            ("queryable", self.queryable),
            ("subscriber", self.subscriber),
            ("token", self.token),
            ("unqueryable", self.unqueryable),
            ("untoken", self.untoken),
        ]
    }

    fn add(&mut self, other: &Self) {
        self.keyexpr += other.keyexpr;
        self.subscriber += other.subscriber;
        self.queryable += other.queryable;
        self.token += other.token;
        self.unqueryable += other.unqueryable;
        self.untoken += other.untoken;
        self.finals += other.finals;
        self.push += other.push;
    }
}

/// A declaration a FRAME made or withdrew, reported after the FRAME was applied whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change<'a> {
    pub kind: Kind,
    pub declared: bool,
    pub id: u32,
    /// The full key: the alias and the suffix joined.
    pub key: &'a [u8],
}

/// The result of one accepted call: the batch written, if any, and what the call changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphOutcome {
    /// Length of the batch body written at the start of the lent storage; 0 means nothing to send.
    pub sent: usize,
    pub counts: Counts,
    pub handshake: bool,
    pub closed: Option<u8>,
}

impl GraphOutcome {
    pub fn batch<'b>(&self, out: &'b [u8]) -> &'b [u8] {
        out.get(..self.sent).unwrap_or(&[])
    }
}

/// A table change a FRAME made, so a frame that fails midway can be undone.
#[derive(Clone, Copy, Debug)]
enum Journal {
    Alias(usize),
    Declared(usize),
    Withdrawn(usize),
}

/// What a check of a joined key refuses: a wildcard where one is not allowed, or a malformed key.
fn check_key(bytes: &[u8], wildcards: bool) -> Result<(), Refusal> {
    let key = core::str::from_utf8(bytes).map_err(|_| Refusal::InvalidKeyexpr)?;
    if !wildcards && has_wildcard(bytes) {
        return Err(Refusal::WildcardKeyexpr);
    }
    if bytes.iter().any(|&byte| byte == b'?' || byte == b'#')
        || key.starts_with('/')
        || key.ends_with('/')
        || key.contains("//")
    {
        return Err(Refusal::InvalidKeyexpr);
    }
    Ok(())
}

fn insert_error(error: InsertError) -> GraphError {
    match error {
        InsertError::Duplicate => Refusal::InvalidKeyexpr.into(),
        InsertError::Full | InsertError::KeyTooLong => Refusal::OverBound.into(),
    }
}

/// A listener or a connector that takes an rmw_zenoh peer's declarations: `A` key aliases and `D`
/// declarations, of keys up to `B` bytes.
#[derive(Clone, Debug)]
pub struct GraphSessionOf<const A: usize, const D: usize, const B: usize> {
    inner: SessionOf<1, 2, B, 1>,
    params: Params,
    aliases: SlotTable<A, B>,
    /// Subscribers, queryables and tokens, by `(kind tag << 32) | id`.
    decls: SlotTable<D, B>,
    counts: Counts,
}

/// The graph session an rmw_zenoh peer's declarations fit: 32 aliases and declarations of 253 bytes.
pub type GraphSession = GraphSessionOf<GRAPH_SLOTS, GRAPH_SLOTS, GRAPH_KEY_BYTES>;

impl Params {
    /// A graph session's: a 512-byte batch, a 253-byte key and 32 aliases and declarations.
    pub const GRAPH: Self = Self {
        bounds: Bounds {
            batch: GRAPH_BATCH_BYTES - super::STREAM_LENGTH_BYTES,
            key: GRAPH_KEY_BYTES,
            payload: GRAPH_BATCH_BYTES,
        },
        announced: GRAPH_BATCH_BYTES as u16,
        fragments: false,
        timeout_ms: 0,
        message_limit: 0,
        per_side: GRAPH_SLOTS,
        local: 1,
        events: 1,
        aliases: GRAPH_SLOTS,
        samples: 1,
        graph: true,
    };
}

impl<const A: usize, const D: usize, const B: usize> GraphSessionOf<A, D, B> {
    /// A session in [`State::Idle`], or [`SessionError::InvalidConfig`] when `params` is not a graph
    /// configuration of this size. `per_side` is the declarations the peer may hold.
    pub fn new(role: Role, config: &Config<'_>, params: Params) -> Result<Self, SessionError> {
        if !params.graph || params.bounds.key != B || params.aliases != A || params.per_side != D {
            return Err(SessionError::InvalidConfig);
        }
        let inner_params = Params {
            graph: false,
            aliases: 1,
            per_side: 1,
            local: 1,
            events: 1,
            samples: 1,
            fragments: false,
            ..params
        };
        Ok(Self {
            inner: SessionOf::with_params(role, config, inner_params)?,
            params,
            aliases: SlotTable::new(),
            decls: SlotTable::new(),
            counts: Counts::default(),
        })
    }

    pub const fn state(&self) -> State {
        self.inner.state()
    }

    pub const fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// Every message the session accepted, from its start.
    pub const fn counts(&self) -> &Counts {
        &self.counts
    }

    /// The key aliases the peer declared and still holds.
    pub const fn aliases(&self) -> usize {
        self.aliases.len()
    }

    /// The declarations of `kind` the peer holds.
    pub fn declared(&self, kind: Kind) -> usize {
        (0..D)
            .filter(|&index| {
                self.decls
                    .get(index)
                    .is_some_and(|(id, _)| id >> 32 == kind.tag())
            })
            .count()
    }

    /// The batch the peer announced; the session sends nothing but a handshake reply and keep-alives.
    pub const fn peer_batch(&self) -> usize {
        self.inner.peer_batch()
    }

    /// Connector only: writes INIT_SYN.
    pub fn connect(&mut self, now_ms: u64, out: &mut [u8]) -> Result<GraphOutcome, GraphError> {
        let outcome = self.inner.connect(now_ms, out)?;
        Ok(self.plain(&outcome))
    }

    /// The lease check and the keep-alive, as in the plain session.
    pub fn tick(&mut self, now_ms: u64, out: &mut [u8]) -> Result<GraphOutcome, GraphError> {
        let outcome = self.inner.tick(now_ms, out)?;
        Ok(self.plain(&outcome))
    }

    /// The lease check without a keep-alive, for a link whose single send slot is occupied.
    pub fn tick_lease(&mut self, now_ms: u64, out: &mut [u8]) -> Result<GraphOutcome, GraphError> {
        let outcome = self.inner.tick_lease(now_ms, out)?;
        Ok(self.plain(&outcome))
    }

    /// Tells the session a batch reached the wire at `now_ms`, which restarts the keep-alive cadence.
    pub fn note_sent(&mut self, now_ms: u64) {
        self.inner.note_sent(now_ms);
    }

    /// Closes the session locally with a CLOSE batch.
    pub fn close(&mut self, reason: u8, out: &mut [u8]) -> Result<GraphOutcome, GraphError> {
        let outcome = self.inner.close(reason, out)?;
        Ok(self.plain(&outcome))
    }

    /// Decodes `batch` and applies it.
    pub fn on_batch(
        &mut self,
        batch: &[u8],
        now_ms: u64,
        out: &mut [u8],
    ) -> Result<GraphOutcome, GraphError> {
        self.on_batch_visit(batch, now_ms, out, &mut |_| {})
    }

    /// Decodes `batch` and applies it, then reports each declaration the FRAME made or withdrew, in the
    /// order it made them. A FRAME that is refused reports nothing.
    pub fn on_batch_visit(
        &mut self,
        batch: &[u8],
        now_ms: u64,
        out: &mut [u8],
        visit: &mut dyn FnMut(Change<'_>),
    ) -> Result<GraphOutcome, GraphError> {
        if self.inner.state() == State::Closed {
            return Err(SessionError::Closed.into());
        }
        match decode_graph_batch(batch, &self.params.bounds)? {
            GraphMessage::Frame(frame) => self.on_frame(&frame, now_ms, visit),
            GraphMessage::Plain(message) => {
                let outcome = self.inner.on_message(message, now_ms, out)?;
                Ok(self.plain(&outcome))
            }
        }
    }

    /// What a plain outcome of the inner session means here. A closed session holds nothing.
    fn plain(&mut self, outcome: &Outcome<'_, 1>) -> GraphOutcome {
        let mut result = GraphOutcome {
            sent: outcome.sent,
            ..GraphOutcome::default()
        };
        for event in outcome.events.iter() {
            match *event {
                Event::HandshakeComplete => result.handshake = true,
                Event::Closed { reason } => {
                    result.closed = Some(reason);
                    self.aliases.clear();
                    self.decls.clear();
                }
                _ => {}
            }
        }
        result
    }

    fn resolve(&self, key: &WireKey<'_>, joined: &mut [u8; B]) -> Result<usize, GraphError> {
        let base: &[u8] = if key.scope == 0 {
            &[]
        } else {
            if !key.sender {
                return Err(Refusal::InvalidKeyexpr.into());
            }
            self.aliases
                .key_of(u64::from(key.scope))
                .ok_or(Refusal::InvalidKeyexpr)?
        };
        let suffix = key.suffix.map_or(&[][..], str::as_bytes);
        let total = base.len() + suffix.len();
        let (head, tail) = joined
            .get_mut(..total)
            .ok_or(Refusal::OverBound)?
            .split_at_mut(base.len());
        head.copy_from_slice(base);
        tail.copy_from_slice(suffix);
        Ok(total)
    }

    fn on_frame(
        &mut self,
        frame: &GraphFrame<'_>,
        now_ms: u64,
        visit: &mut dyn FnMut(Change<'_>),
    ) -> Result<GraphOutcome, GraphError> {
        self.inner.graph_frame_expected(frame.sn)?;
        let mut journal = [None; JOURNAL];
        let mut used = 0;
        let mut counts = Counts::default();
        match self.apply(frame, &mut journal, &mut used, &mut counts) {
            Ok(()) => {
                for change in journal.iter().take(used).flatten() {
                    let (declared, at) = match *change {
                        Journal::Declared(at) => (true, at),
                        Journal::Withdrawn(at) => (false, at),
                        Journal::Alias(_) => continue,
                    };
                    let held = if declared {
                        self.decls.get(at)
                    } else {
                        self.decls.pending(at)
                    };
                    if let Some((tagged, key)) = held
                        && let Some(kind) = Kind::from_tag(tagged >> 32)
                    {
                        visit(Change {
                            kind,
                            declared,
                            id: tagged as u32,
                            key,
                        });
                    }
                }
                for change in journal.iter().take(used).flatten() {
                    if let Journal::Withdrawn(at) = *change {
                        self.decls.settle(at);
                    }
                }
                self.inner.graph_frame_accepted(now_ms);
                self.counts.add(&counts);
                Ok(GraphOutcome {
                    counts,
                    ..GraphOutcome::default()
                })
            }
            Err(error) => {
                for change in journal.iter().take(used).rev().flatten() {
                    match *change {
                        Journal::Alias(at) => self.aliases.remove(at),
                        Journal::Declared(at) => self.decls.remove(at),
                        Journal::Withdrawn(at) => self.decls.restore(at),
                    }
                }
                Err(error)
            }
        }
    }

    fn apply(
        &mut self,
        frame: &GraphFrame<'_>,
        journal: &mut [Option<Journal>; JOURNAL],
        used: &mut usize,
        counts: &mut Counts,
    ) -> Result<(), GraphError> {
        fn note(
            journal: &mut [Option<Journal>; JOURNAL],
            used: &mut usize,
            change: Journal,
        ) -> Result<(), GraphError> {
            let slot = journal
                .get_mut(*used)
                .ok_or(SessionError::TooManyMessages)?;
            *slot = Some(change);
            *used += 1;
            Ok(())
        }
        for network in frame.messages() {
            // Room in the journal is claimed before a table is changed, so a frame that could not be
            // undone is refused before it does anything.
            if *used >= JOURNAL {
                return Err(SessionError::TooManyMessages.into());
            }
            match network {
                GraphNetwork::KeyExpr { id, key } => {
                    if self.aliases.find(u64::from(id)).is_some() {
                        return Err(Refusal::InvalidKeyexpr.into());
                    }
                    let at = self
                        .aliases
                        .insert(u64::from(id), key.as_bytes())
                        .map_err(insert_error)?;
                    note(journal, used, Journal::Alias(at))?;
                    counts.keyexpr += 1;
                }
                GraphNetwork::Declare { kind, id, key } => {
                    let mut joined = [0u8; B];
                    let length = self.resolve(&key, &mut joined)?;
                    let joined = joined.get(..length).ok_or(Refusal::OverBound)?;
                    check_key(joined, kind != Kind::Token)?;
                    let tagged = (kind.tag() << 32) | u64::from(id);
                    let at = self.decls.insert(tagged, joined).map_err(insert_error)?;
                    note(journal, used, Journal::Declared(at))?;
                    match kind {
                        Kind::Subscriber => counts.subscriber += 1,
                        Kind::Queryable => counts.queryable += 1,
                        Kind::Token => counts.token += 1,
                    }
                }
                GraphNetwork::Withdraw { kind, id } => {
                    let tagged = (kind.tag() << 32) | u64::from(id);
                    let at = self
                        .decls
                        .find(tagged)
                        .ok_or(GraphError::UnknownDeclaration)?;
                    self.decls.defer_remove(at);
                    note(journal, used, Journal::Withdrawn(at))?;
                    match kind {
                        Kind::Queryable => counts.unqueryable += 1,
                        _ => counts.untoken += 1,
                    }
                }
                GraphNetwork::Final => counts.finals += 1,
                GraphNetwork::Push { key } => {
                    // The session holds no subscription, so a push is to a key nobody subscribed to: it
                    // is dropped and counted once its key is known to be one.
                    let mut joined = [0u8; B];
                    let length = self.resolve(&key, &mut joined)?;
                    check_key(joined.get(..length).ok_or(Refusal::OverBound)?, false)?;
                    counts.push += 1;
                }
            }
        }
        Ok(())
    }
}
