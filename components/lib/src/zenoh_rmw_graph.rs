//! The ROS 2 graph an rmw_zenoh peer's liveliness tokens declare.
//!
//! A token is a key expression under `@ros2_lv`:
//!
//! ```text
//! @ros2_lv/<domain>/<zid>/<nid>/<id>/<kind>/<enclave>/<namespace>/<node>[/<topic>/<type>/<hash>/<qos>]
//! ```
//!
//! `kind` is `NN` (node), `MP` (publisher), `MS` (subscription), `SS` (service server) or `SC` (service
//! client). A node token has 9 parts and every other kind has 13. A `/` inside the enclave, namespace,
//! node, topic, type or hash is written `%`, because a key-expression field cannot hold a slash. The QoS
//! substring leaves a field empty when it equals rmw_zenoh's default.
//!
//! The rules are those of `rmw_zenoh_cpp` 0.6.10 `liveliness_utils.cpp`, with one difference: this graph
//! refuses a token that has more or fewer parts than its kind, a number that is not canonical decimal and
//! a Zenoh ID that is not 1 to 32 lowercase hexadecimal digits, where upstream reads them loosely. The
//! graph is bounded and deterministic, so a token has one reading.
//!
//! The graph is read-only. It holds at most `N` entities, refuses the `N + 1`th with
//! [`GraphError::GraphFull`] and never evicts. It allocates nothing.

use core::fmt::{self, Write as _};

#[cfg(test)]
mod fixtures;

pub const ADMIN_SPACE: &str = "@ros2_lv";
pub const NODE_PARTS: usize = 9;
pub const TOPIC_PARTS: usize = 13;
/// The longest token a graph holds: the session's key bound.
pub const KEY_BYTES: usize = super::zenoh_profile0::graph::GRAPH_KEY_BYTES;
const MAX_PARTS: usize = TOPIC_PARTS;

/// rmw_zenoh's infinite duration, as seconds and nanoseconds.
pub const INFINITE: (u64, u64) = (9_223_372_036, 854_775_807);

const DEFAULT_RELIABILITY: u8 = 1;
const DEFAULT_DURABILITY: u8 = 2;
const DEFAULT_HISTORY: u8 = 1;
const DEFAULT_DEPTH: u64 = 42;
const DEFAULT_LIVELINESS: u8 = 1;
/// The largest value of each policy in rmw 7.8.3 `rmw/types.h`.
const MAX_RELIABILITY: u64 = 4;
const MAX_DURABILITY: u64 = 4;
const MAX_HISTORY: u64 = 3;
const MAX_LIVELINESS: u64 = 5;

/// Why the graph refuses a key. Every refusal leaves the graph unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphError {
    InvalidToken,
    UnknownEntity,
    WrongDomain,
    InvalidQos,
    GraphFull,
}

impl GraphError {
    /// The class name the exam pins.
    pub const fn class(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid-token",
            Self::UnknownEntity => "unknown-entity",
            Self::WrongDomain => "wrong-domain",
            Self::InvalidQos => "invalid-qos",
            Self::GraphFull => "graph-full",
        }
    }
}

/// What a token declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Node,
    Publisher,
    Subscription,
    Service,
    Client,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Node => "NN",
            Self::Publisher => "MP",
            Self::Subscription => "MS",
            Self::Service => "SS",
            Self::Client => "SC",
        }
    }

    fn from_name(text: &str) -> Option<Self> {
        match text {
            "NN" => Some(Self::Node),
            "MP" => Some(Self::Publisher),
            "MS" => Some(Self::Subscription),
            "SS" => Some(Self::Service),
            "SC" => Some(Self::Client),
            _ => None,
        }
    }
}

/// A topic's or service's QoS, as the token's substring states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qos {
    pub reliability: u8,
    pub durability: u8,
    pub history: u8,
    pub depth: u64,
    pub deadline: (u64, u64),
    pub lifespan: (u64, u64),
    pub liveliness: u8,
    pub lease: (u64, u64),
}

impl Qos {
    /// rmw_zenoh's defaults: reliable, volatile, keep-last, depth 42, infinite deadline, lifespan and
    /// lease, automatic liveliness.
    pub const DEFAULT: Self = Self {
        reliability: DEFAULT_RELIABILITY,
        durability: DEFAULT_DURABILITY,
        history: DEFAULT_HISTORY,
        depth: DEFAULT_DEPTH,
        deadline: INFINITE,
        lifespan: INFINITE,
        liveliness: DEFAULT_LIVELINESS,
        lease: INFINITE,
    };

    /// The substring `qos_to_keyexpr` writes: a field is written only when it differs from the default.
    pub fn write_keyexpr(&self, out: &mut impl fmt::Write) -> fmt::Result {
        let d = Self::DEFAULT;
        fn field<T: PartialEq + fmt::Display>(
            out: &mut impl fmt::Write,
            value: T,
            default: T,
        ) -> fmt::Result {
            if value != default {
                write!(out, "{value}")?;
            }
            Ok(())
        }
        field(out, self.reliability, d.reliability)?;
        out.write_char(':')?;
        field(out, self.durability, d.durability)?;
        out.write_char(':')?;
        field(out, self.history, d.history)?;
        out.write_char(',')?;
        field(out, self.depth, d.depth)?;
        out.write_char(':')?;
        field(out, self.deadline.0, d.deadline.0)?;
        out.write_char(',')?;
        field(out, self.deadline.1, d.deadline.1)?;
        out.write_char(':')?;
        field(out, self.lifespan.0, d.lifespan.0)?;
        out.write_char(',')?;
        field(out, self.lifespan.1, d.lifespan.1)?;
        out.write_char(':')?;
        field(out, self.liveliness, d.liveliness)?;
        out.write_char(',')?;
        field(out, self.lease.0, d.lease.0)?;
        out.write_char(',')?;
        field(out, self.lease.1, d.lease.1)
    }
}

/// The first `M` pieces of `text` split at `delimiter`, or `None` when it has fewer. Further pieces are
/// ignored, as `keyexpr_to_qos` ignores them.
fn pieces<const M: usize>(text: &str, delimiter: char) -> Option<[&str; M]> {
    let mut out = [""; M];
    let mut count = 0;
    for piece in text.split(delimiter) {
        if let Some(slot) = out.get_mut(count) {
            *slot = piece;
        }
        count += 1;
    }
    (count >= M).then_some(out)
}

/// `str_to_size_t`: empty is the default, otherwise ASCII digits that fit 64 bits.
fn size(text: &str, default: u64) -> Result<u64, GraphError> {
    if text.is_empty() {
        return Ok(default);
    }
    let mut value: u64 = 0;
    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            return Err(GraphError::InvalidQos);
        }
        value = value
            .checked_mul(10)
            .and_then(|shifted| shifted.checked_add(u64::from(byte - b'0')))
            .ok_or(GraphError::InvalidQos)?;
    }
    Ok(value)
}

fn policy(text: &str, largest: u64, default: u8) -> Result<u8, GraphError> {
    if text.is_empty() {
        return Ok(default);
    }
    let value = size(text, 0)?;
    if value > largest {
        return Err(GraphError::InvalidQos);
    }
    u8::try_from(value).map_err(|_| GraphError::InvalidQos)
}

/// `keyexpr_to_qos`: six colon-separated parts, then 2, 2, 2 and 3 comma-separated components.
pub fn parse_qos(text: &str) -> Result<Qos, GraphError> {
    let [
        reliability,
        durability,
        history,
        deadline,
        lifespan,
        liveliness,
    ] = pieces::<6>(text, ':').ok_or(GraphError::InvalidQos)?;
    let [history_policy, depth] = pieces::<2>(history, ',').ok_or(GraphError::InvalidQos)?;
    let [deadline_s, deadline_ns] = pieces::<2>(deadline, ',').ok_or(GraphError::InvalidQos)?;
    let [lifespan_s, lifespan_ns] = pieces::<2>(lifespan, ',').ok_or(GraphError::InvalidQos)?;
    let [liveliness_policy, lease_s, lease_ns] =
        pieces::<3>(liveliness, ',').ok_or(GraphError::InvalidQos)?;
    let d = Qos::DEFAULT;
    Ok(Qos {
        reliability: policy(reliability, MAX_RELIABILITY, d.reliability)?,
        durability: policy(durability, MAX_DURABILITY, d.durability)?,
        history: policy(history_policy, MAX_HISTORY, d.history)?,
        depth: size(depth, d.depth)?,
        deadline: (
            size(deadline_s, d.deadline.0)?,
            size(deadline_ns, d.deadline.1)?,
        ),
        lifespan: (
            size(lifespan_s, d.lifespan.0)?,
            size(lifespan_ns, d.lifespan.1)?,
        ),
        liveliness: policy(liveliness_policy, MAX_LIVELINESS, d.liveliness)?,
        lease: (size(lease_s, d.lease.0)?, size(lease_ns, d.lease.1)?),
    })
}

/// A field with its `%` read as `/`.
#[derive(Clone, Copy, Debug)]
pub struct Demangled<'a>(pub &'a str);

impl fmt::Display for Demangled<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            out.write_char(if character == '%' { '/' } else { character })?;
        }
        Ok(())
    }
}

/// A field with its `/` written `%`.
struct Mangled<'a>(Demangled<'a>);

impl Mangled<'_> {
    fn write(&self, out: &mut impl fmt::Write) -> fmt::Result {
        let mut text = Sink::<KEY_BYTES>::new();
        write!(text, "{}", self.0)?;
        for character in text.as_str().chars() {
            out.write_char(if character == '/' { '%' } else { character })?;
        }
        Ok(())
    }
}

/// A fixed buffer that takes formatted text.
struct Sink<const B: usize> {
    bytes: [u8; B],
    len: usize,
}

impl<const B: usize> Sink<B> {
    const fn new() -> Self {
        Self {
            bytes: [0; B],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(self.bytes.get(..self.len).unwrap_or(&[])).unwrap_or("")
    }
}

impl<const B: usize> fmt::Write for Sink<B> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// `0` or a number of 1 to 10 digits with no leading zero.
fn decimal(text: &str) -> Result<u64, GraphError> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 10
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes.first() == Some(&b'0'))
    {
        return Err(GraphError::InvalidToken);
    }
    text.parse().map_err(|_| GraphError::InvalidToken)
}

fn zid_ok(text: &str) -> bool {
    (1..=32).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One live entity: a node, publisher, subscription, service server or service client.
#[derive(Clone, Copy, Debug)]
pub struct Entity {
    key: [u8; KEY_BYTES],
    len: usize,
    parts: usize,
    /// Where each part of the key starts and ends.
    spans: [(u16, u16); MAX_PARTS],
    kind: Kind,
    domain: u64,
    nid: u64,
    id: u64,
    qos: Option<Qos>,
}

impl Entity {
    /// `Entity::make`: `Ok(None)` for a key outside the `@ros2_lv` admin space, which the graph ignores.
    pub fn parse(key: &str, domain: u64) -> Result<Option<Self>, GraphError> {
        let mut spans = [(0u16, 0u16); MAX_PARTS];
        let mut parts = 0;
        let mut start = 0usize;
        let mut first = true;
        for piece in key.split('/') {
            if first {
                if piece != ADMIN_SPACE {
                    return Ok(None);
                }
                first = false;
            }
            if key.len() > KEY_BYTES {
                return Err(GraphError::InvalidToken);
            }
            if let Some(slot) = spans.get_mut(parts) {
                *slot = (start as u16, (start + piece.len()) as u16);
            }
            parts += 1;
            start += piece.len() + 1;
        }
        if parts < NODE_PARTS {
            return Err(GraphError::InvalidToken);
        }
        let text = |at: usize| -> &str {
            spans
                .get(at)
                .and_then(|&(from, to)| key.get(usize::from(from)..usize::from(to)))
                .unwrap_or("")
        };
        if (0..parts.min(MAX_PARTS)).any(|at| text(at).is_empty()) {
            return Err(GraphError::InvalidToken);
        }
        let kind = Kind::from_name(text(5)).ok_or(GraphError::UnknownEntity)?;
        let wanted = if kind == Kind::Node {
            NODE_PARTS
        } else {
            TOPIC_PARTS
        };
        if parts != wanted {
            return Err(GraphError::InvalidToken);
        }
        let token_domain = decimal(text(1))?;
        if token_domain != domain {
            return Err(GraphError::WrongDomain);
        }
        if !zid_ok(text(2)) {
            return Err(GraphError::InvalidToken);
        }
        let nid = decimal(text(3))?;
        let id = decimal(text(4))?;
        let qos = if kind == Kind::Node {
            None
        } else {
            Some(parse_qos(text(12))?)
        };
        let mut held = [0u8; KEY_BYTES];
        held.get_mut(..key.len())
            .ok_or(GraphError::InvalidToken)?
            .copy_from_slice(key.as_bytes());
        Ok(Some(Self {
            key: held,
            len: key.len(),
            parts,
            spans,
            kind,
            domain: token_domain,
            nid,
            id,
            qos,
        }))
    }

    fn part(&self, at: usize) -> &str {
        let (from, to) = self.spans.get(at).copied().unwrap_or((0, 0));
        self.key
            .get(usize::from(from)..usize::from(to))
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }

    /// The token as the peer declared it.
    pub fn token(&self) -> &str {
        self.key
            .get(..self.len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }

    pub const fn kind(&self) -> Kind {
        self.kind
    }

    pub const fn domain(&self) -> u64 {
        self.domain
    }

    pub fn zid(&self) -> &str {
        self.part(2)
    }

    pub const fn nid(&self) -> u64 {
        self.nid
    }

    pub const fn id(&self) -> u64 {
        self.id
    }

    /// The enclave, namespace and node as the token spells them, `%` for `/`.
    pub fn enclave(&self) -> &str {
        self.part(6)
    }

    pub fn namespace(&self) -> &str {
        self.part(7)
    }

    pub fn node(&self) -> &str {
        self.part(8)
    }

    /// The topic, type and type hash of a token that is not a node's, `%` for `/`.
    pub fn topic(&self) -> Option<&str> {
        (self.parts == TOPIC_PARTS).then(|| self.part(9))
    }

    pub fn type_name(&self) -> Option<&str> {
        (self.parts == TOPIC_PARTS).then(|| self.part(10))
    }

    pub fn type_hash(&self) -> Option<&str> {
        (self.parts == TOPIC_PARTS).then(|| self.part(11))
    }

    pub const fn qos(&self) -> Option<&Qos> {
        self.qos.as_ref()
    }

    /// The token written again from the fields this entity read, and not from the bytes it was read from.
    /// Returns the length written, or `None` when `out` is too small.
    pub fn rebuild(&self, out: &mut [u8]) -> Option<usize> {
        let mut sink = Sink::<KEY_BYTES>::new();
        write!(
            sink,
            "{ADMIN_SPACE}/{}/{}/{}/{}/{}/",
            self.domain,
            self.zid(),
            self.nid,
            self.id,
            self.kind.name()
        )
        .ok()?;
        for (at, last) in [(6, false), (7, false), (8, self.parts == NODE_PARTS)] {
            Mangled(Demangled(self.part(at))).write(&mut sink).ok()?;
            if !last {
                sink.write_char('/').ok()?;
            }
        }
        if let Some(qos) = &self.qos {
            for at in [9, 10, 11] {
                Mangled(Demangled(self.part(at))).write(&mut sink).ok()?;
                sink.write_char('/').ok()?;
            }
            qos.write_keyexpr(&mut sink).ok()?;
        }
        let text = sink.as_str().as_bytes();
        out.get_mut(..text.len())?.copy_from_slice(text);
        Some(text.len())
    }

    fn same_entity(&self, other: &Self) -> bool {
        self.zid() == other.zid() && self.nid == other.nid && self.id == other.id
    }
}

/// What a declaration did to the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Declared {
    /// The key names an entity, now held.
    Entity,
    /// The key is outside the `@ros2_lv` admin space, and was counted and dropped.
    Ignored,
}

/// The live entities of one domain, at most `N`.
#[derive(Clone, Debug)]
pub struct Graph<const N: usize> {
    domain: u64,
    live: [Option<Entity>; N],
    ignored: u32,
}

impl<const N: usize> Graph<N> {
    pub const fn new(domain: u64) -> Self {
        Self {
            domain,
            live: [None; N],
            ignored: 0,
        }
    }

    pub const fn domain(&self) -> u64 {
        self.domain
    }

    /// Keys outside the admin space the graph dropped.
    pub const fn ignored(&self) -> u32 {
        self.ignored
    }

    pub fn len(&self) -> usize {
        self.live.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The live entities, in no order.
    pub fn iter(&self) -> impl Iterator<Item = &Entity> {
        self.live.iter().flatten()
    }

    /// Takes the entity a token declares. An entity declared again replaces itself.
    pub fn declare(&mut self, key: &str) -> Result<Declared, GraphError> {
        let Some(entity) = Entity::parse(key, self.domain)? else {
            self.ignored += 1;
            return Ok(Declared::Ignored);
        };
        let at = self
            .live
            .iter()
            .position(|held| held.as_ref().is_some_and(|held| held.same_entity(&entity)))
            .or_else(|| self.live.iter().position(Option::is_none))
            .ok_or(GraphError::GraphFull)?;
        if let Some(slot) = self.live.get_mut(at) {
            *slot = Some(entity);
        }
        Ok(Declared::Entity)
    }

    /// Drops every entity. A link whose session ended holds no graph.
    pub fn clear(&mut self) {
        self.live = [None; N];
    }

    /// Drops the entity a withdrawn token names. A token that names none is ignored.
    pub fn withdraw(&mut self, key: &str) -> Result<(), GraphError> {
        let Some(entity) = Entity::parse(key, self.domain)? else {
            return Ok(());
        };
        for slot in &mut self.live {
            if slot.as_ref().is_some_and(|held| held.same_entity(&entity)) {
                *slot = None;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
include!("zenoh_rmw_graph/exam.rs");
