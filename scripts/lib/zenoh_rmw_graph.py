"""Host reference for rmw_zenoh's liveliness tokens and the graph built from them.

Written from `rmw_zenoh_cpp` 0.6.10 `src/detail/liveliness_utils.cpp` (`Entity::make`, `keyexpr_to_qos`,
`qos_to_keyexpr`, `mangle_name`) and from the rmw 7.8.3 `rmw/types.h` enums, never from the Rust
implementation. The source tarball is pinned in `zenoh_rmw_peer.py`.

A token is a key expression under `@ros2_lv`:

  @ros2_lv/<domain>/<zid>/<nid>/<id>/<kind>/<enclave>/<namespace>/<node>[/<topic>/<type>/<hash>/<qos>]

`kind` is NN (node), MP (publisher), MS (subscription), SS (service server) or SC (service client). A node
token has 9 parts and every other kind has 13. Upstream ignores extra parts and Profile 0's graph refuses
them, so the graph is stricter than upstream there and nowhere else. The enclave, namespace, node, topic,
type and hash have `/` replaced by `%`, because a key expression field cannot hold a slash.

The QoS substring is `<reliability>:<durability>:<history>,<depth>:<deadline s>,<deadline ns>:<lifespan
s>,<lifespan ns>:<liveliness>,<lease s>,<lease ns>`. A field equal to the default is left empty. The
defaults are rmw_zenoh's: reliable, volatile, keep-last, depth 42, infinite deadline, lifespan and lease,
automatic liveliness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ADMIN_SPACE = "@ros2_lv"
KINDS = ("NN", "MP", "MS", "SS", "SC")
NODE_PARTS = 9
TOPIC_PARTS = 13
SLASH = "%"

INFINITE = (9223372036, 854775807)

# rmw 7.8.3 rmw/types.h, in declaration order. The liveliness enum gives its values explicitly.
RELIABILITY = {0: "system-default", 1: "reliable", 2: "best-effort", 3: "unknown", 4: "best-available"}
DURABILITY = {0: "system-default", 1: "transient-local", 2: "volatile", 3: "unknown", 4: "best-available"}
HISTORY = {0: "system-default", 1: "keep-last", 2: "keep-all", 3: "unknown"}
LIVELINESS = {0: "system-default", 1: "automatic", 2: "manual-by-node", 3: "manual-by-topic", 4: "unknown", 5: "best-available"}

DEFAULT_RELIABILITY, DEFAULT_DURABILITY, DEFAULT_HISTORY, DEFAULT_DEPTH, DEFAULT_LIVELINESS = 1, 2, 1, 42, 1

U64_MAX = 2**64 - 1


class GraphError(ValueError):
    """A token or QoS substring the graph refuses. `cls` is the class name the exam pins."""

    def __init__(self, cls: str, message: str) -> None:
        super().__init__(message)
        self.cls = cls


def mangle(name: str) -> str:
    return name.replace("/", SLASH)


def demangle(name: str) -> str:
    return name.replace(SLASH, "/")


@dataclass(frozen=True)
class Qos:
    reliability: int
    durability: int
    history: int
    depth: int
    deadline: tuple[int, int]
    lifespan: tuple[int, int]
    liveliness: int
    lease: tuple[int, int]

    def canonical(self) -> str:
        """One token with no spaces, the form the Rust test prints and the judge compares."""
        sec = lambda pair: f"{pair[0]}.{pair[1]}"  # noqa: E731
        return (
            f"rel={self.reliability},dur={self.durability},his={self.history},dep={self.depth},"
            f"dl={sec(self.deadline)},ls={sec(self.lifespan)},lv={self.liveliness},le={sec(self.lease)}"
        )


DEFAULT_QOS = Qos(DEFAULT_RELIABILITY, DEFAULT_DURABILITY, DEFAULT_HISTORY, DEFAULT_DEPTH, INFINITE, INFINITE, DEFAULT_LIVELINESS, INFINITE)


def qos_to_keyexpr(qos: Qos) -> str:
    """`qos_to_keyexpr`: a field is written only when it differs from the default."""
    d = DEFAULT_QOS
    out = ""
    out += str(qos.reliability) if qos.reliability != d.reliability else ""
    out += ":"
    out += str(qos.durability) if qos.durability != d.durability else ""
    out += ":"
    out += str(qos.history) if qos.history != d.history else ""
    out += ","
    out += str(qos.depth) if qos.depth != d.depth else ""
    out += ":"
    out += str(qos.deadline[0]) if qos.deadline[0] != d.deadline[0] else ""
    out += ","
    out += str(qos.deadline[1]) if qos.deadline[1] != d.deadline[1] else ""
    out += ":"
    out += str(qos.lifespan[0]) if qos.lifespan[0] != d.lifespan[0] else ""
    out += ","
    out += str(qos.lifespan[1]) if qos.lifespan[1] != d.lifespan[1] else ""
    out += ":"
    out += str(qos.liveliness) if qos.liveliness != d.liveliness else ""
    out += ","
    out += str(qos.lease[0]) if qos.lease[0] != d.lease[0] else ""
    out += ","
    out += str(qos.lease[1]) if qos.lease[1] != d.lease[1] else ""
    return out


def _size(text: str, default: int) -> int:
    """`str_to_size_t`: empty is the default; digits only; at most 2**64 - 1."""
    if text == "":
        return default
    if not re.fullmatch(r"[0-9]+", text):
        raise GraphError("invalid-qos", f"{text!r} is not an unsigned decimal")
    value = int(text)
    if value > U64_MAX:
        raise GraphError("invalid-qos", f"{text!r} overflows 64 bits")
    return value


def _policy(text: str, table: dict[int, str], default: int) -> int:
    if text == "":
        return default
    if not re.fullmatch(r"[0-9]+", text) or int(text) not in table:
        raise GraphError("invalid-qos", f"{text!r} is not a policy value")
    return int(text)


def keyexpr_to_qos(text: str) -> Qos:
    """`keyexpr_to_qos`, with its component counts: 6 parts, then 2, 2, 2 and 3 components."""
    parts = text.split(":")
    if len(parts) < 6:
        raise GraphError("invalid-qos", "fewer than 6 colon-separated parts")
    history = parts[2].split(",")
    deadline = parts[3].split(",")
    lifespan = parts[4].split(",")
    liveliness = parts[5].split(",")
    if len(history) < 2 or len(deadline) < 2 or len(lifespan) < 2 or len(liveliness) < 3:
        raise GraphError("invalid-qos", "too few comma-separated components")
    return Qos(
        _policy(parts[0], RELIABILITY, DEFAULT_RELIABILITY),
        _policy(parts[1], DURABILITY, DEFAULT_DURABILITY),
        _policy(history[0], HISTORY, DEFAULT_HISTORY),
        _size(history[1], DEFAULT_DEPTH),
        (_size(deadline[0], INFINITE[0]), _size(deadline[1], INFINITE[1])),
        (_size(lifespan[0], INFINITE[0]), _size(lifespan[1], INFINITE[1])),
        _policy(liveliness[0], LIVELINESS, DEFAULT_LIVELINESS),
        (_size(liveliness[1], INFINITE[0]), _size(liveliness[2], INFINITE[1])),
    )


@dataclass(frozen=True)
class Entity:
    domain: int
    zid: str
    nid: int
    ident: int
    kind: str
    enclave: str
    namespace: str
    node: str
    topic: str | None = None
    type_name: str | None = None
    type_hash: str | None = None
    qos: Qos | None = None

    def line(self) -> str:
        """The fields the judge compares, with `-` for what a node does not have. No spaces."""
        none = "-"
        return " ".join(
            (
                self.kind,
                self.zid,
                str(self.nid),
                str(self.ident),
                self.enclave,
                self.namespace,
                self.node,
                self.topic or none,
                self.type_name or none,
                self.type_hash or none,
                self.qos.canonical() if self.qos else none,
            )
        )

    def sort_key(self) -> tuple[str, int, int]:
        return (self.zid, self.nid, self.ident)


def _decimal(text: str, what: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", text):
        raise GraphError("invalid-token", f"{what} {text!r} is not a canonical decimal of at most 10 digits")
    return int(text)


def parse_token(key: str, domain: int) -> Entity | None:
    """`Entity::make`. Returns None for a key outside `@ros2_lv`, which the graph ignores."""
    parts = key.split("/")
    if parts[0] != ADMIN_SPACE:
        return None
    if len(parts) < NODE_PARTS:
        raise GraphError("invalid-token", f"{len(parts)} parts, a token has at least {NODE_PARTS}")
    if any(part == "" for part in parts):
        raise GraphError("invalid-token", "an empty part")
    kind = parts[5]
    if kind not in KINDS:
        raise GraphError("unknown-entity", f"{kind!r} is not a token kind")
    if len(parts) != (NODE_PARTS if kind == "NN" else TOPIC_PARTS):
        raise GraphError("invalid-token", f"{len(parts)} parts for a {kind} token")
    token_domain = _decimal(parts[1], "domain")
    if token_domain != domain:
        raise GraphError("wrong-domain", f"domain {token_domain}, the graph is for {domain}")
    if not re.fullmatch(r"[0-9a-f]{1,32}", parts[2]):
        raise GraphError("invalid-token", "a Zenoh ID is 1 to 32 lowercase hexadecimal digits")
    nid, ident = _decimal(parts[3], "nid"), _decimal(parts[4], "id")
    base = dict(domain=token_domain, zid=parts[2], nid=nid, ident=ident, kind=kind, enclave=demangle(parts[6]), namespace=demangle(parts[7]), node=demangle(parts[8]))
    if kind == "NN":
        return Entity(**base)
    return Entity(**base, topic=demangle(parts[9]), type_name=demangle(parts[10]), type_hash=demangle(parts[11]), qos=keyexpr_to_qos(parts[12]))


def build_token(entity: Entity) -> str:
    fields = [ADMIN_SPACE, str(entity.domain), entity.zid, str(entity.nid), str(entity.ident), entity.kind, mangle(entity.enclave), mangle(entity.namespace), mangle(entity.node)]
    if entity.kind != "NN":
        assert entity.topic is not None and entity.type_name is not None and entity.type_hash is not None and entity.qos is not None
        fields += [mangle(entity.topic), mangle(entity.type_name), mangle(entity.type_hash), qos_to_keyexpr(entity.qos)]
    return "/".join(fields)


class Graph:
    """The expected graph: live entities, at most `capacity`, keyed by (zid, nid, id)."""

    def __init__(self, domain: int, capacity: int) -> None:
        self.domain = domain
        self.capacity = capacity
        self.live: dict[tuple[str, int, int], Entity] = {}
        self.ignored = 0

    def declare(self, key: str) -> Entity | None:
        entity = parse_token(key, self.domain)
        if entity is None:
            self.ignored += 1
            return None
        if entity.sort_key() not in self.live and len(self.live) >= self.capacity:
            raise GraphError("graph-full", f"the graph holds {self.capacity} entities")
        self.live[entity.sort_key()] = entity
        return entity

    def withdraw(self, key: str) -> None:
        entity = parse_token(key, self.domain)
        if entity is not None:
            self.live.pop(entity.sort_key(), None)

    def entities(self) -> list[Entity]:
        return sorted(self.live.values(), key=Entity.sort_key)

    def counts(self) -> dict[str, tuple[int, int]]:
        """Per topic: (publishers, subscriptions)."""
        out: dict[str, list[int]] = {}
        for entity in self.live.values():
            if entity.kind in ("MP", "MS") and entity.topic:
                row = out.setdefault(entity.topic, [0, 0])
                row[0 if entity.kind == "MP" else 1] += 1
        return {topic: (row[0], row[1]) for topic, row in sorted(out.items())}

    def services(self) -> dict[str, tuple[int, int]]:
        """Per service name: (servers, clients)."""
        out: dict[str, list[int]] = {}
        for entity in self.live.values():
            if entity.kind in ("SS", "SC") and entity.topic:
                row = out.setdefault(entity.topic, [0, 0])
                row[0 if entity.kind == "SS" else 1] += 1
        return {name: (row[0], row[1]) for name, row in sorted(out.items())}

    def nodes(self) -> list[str]:
        return sorted({entity.node for entity in self.live.values() if entity.kind == "NN"})
