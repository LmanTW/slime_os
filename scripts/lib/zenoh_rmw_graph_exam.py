"""Judge the rmw_zenoh graph exam from what the Rust tests print.

The session item (`zenoh_rmw_exam`) makes a Profile 0 listener take the declarations an rmw_zenoh peer
sends. This exam judges what the listener does with the 26 `@ros2_lv` tokens among them: it parses each one
into an entity, keeps the live ones in a bounded graph, drops an entity when its token is withdrawn, and
answers the queries a ROS 2 graph needs (nodes, publishers and subscriptions of a topic, servers and clients
of a service).

`zenoh_rmw_graph` is the host reference, written from rmw_zenoh's source. The judge builds the whole
transcript the Rust tests must print from that reference, so no expected value is copied from the Rust, and
compares the printed transcript with it line for line:

* the replay of each captured session into the graph, and the entities, topics, services and nodes left;
* the QoS substring of every captured publisher and subscription, and 8 more the peer did not send;
* eight synthetic tokens, one of each kind and one with a mangled slash, parsed and built again;
* the keys the graph must refuse, each as the class the exam pins;
* the graph filled to its capacity and refusing one more.

Like the other judges, this one is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import zenoh_rmw_exam
import zenoh_rmw_graph as graph
import zenoh_rmw_wire as wire
import zutai_cli
from harness import ROOT

SCHEMA = ROOT / "contracts" / "zenoh-rmw-graph" / "v1" / "schema.zt"
ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-graph.zt"

DOMAIN = 0
CAPACITY = 16
MAX_KEY_BYTES = 253
GROUPS = tuple(name for name, _rows in zenoh_rmw_exam.GROUPS)

ZID = "7abf42d448a5a4fdeb112b7a1f051072"
HASH_STRING = "RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18"
STRING_TYPE = "std_msgs::msg::dds_::String_"


class GraphExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise GraphExamError(message)


# --------------------------------------------------------------------------------- the rows


def _token(kind: str, ident: int, node: str, topic: str | None = None, qos: str = "::,10:,:,:,,", namespace: str = "%", zid: str = ZID, nid: int = 0, domain: int = 0) -> str:
    base = f"@ros2_lv/{domain}/{zid}/{nid}/{ident}/{kind}/%/{namespace}/{node}"
    return base if kind == "NN" else f"{base}/{topic}/{STRING_TYPE}/{HASH_STRING}/{qos}"


# Default QoS written by `qos_to_keyexpr`, so the row is not typed by hand.
DEFAULT_QOS_TEXT = graph.qos_to_keyexpr(graph.DEFAULT_QOS)

QOS_ROWS = (
    ("qos-captured-rosout", ":1:,1000:,:10,0:,,"),
    ("qos-captured-services", "::,1000:,:,:,,"),
    ("qos-captured-depth-10", "::,10:,:,:,,"),
    ("qos-captured-depth-7", "::,7:,:,:,,"),
    ("qos-all-default", DEFAULT_QOS_TEXT),
    ("qos-best-effort", "2::,5:,:,:,,"),
    ("qos-transient-local-keep-all", ":1:2,:,:,:,,"),
    ("qos-deadline-and-lifespan", "::,:3,500:4,0:,,"),
    ("qos-manual-by-topic-lease", "::,:,:,:3,2,9"),
    ("qos-best-available", "4:4:,:,:,:5,,"),
    ("qos-depth-at-u64-max", "::,18446744073709551615:,:,:,,"),
    ("qos-system-default-policies", "0:0:0,:,:,:0,,"),
)

TOKEN_ROWS = (
    ("token-node", _token("NN", 0, "talker")),
    ("token-node-in-namespace", _token("NN", 0, "talker", namespace="%robot%arm")),
    ("token-publisher", _token("MP", 1, "talker", "%chatter", qos="::,7:,:,:,,")),
    ("token-subscription", _token("MS", 2, "listener", "%chatter", qos="2::,10:,:,:,,")),
    ("token-service-server", _token("SS", 3, "talker", "%talker%get_parameters", qos="::,1000:,:,:,,")),
    ("token-service-client", _token("SC", 4, "listener", "%talker%get_parameters", qos="::,1000:,:,:,,")),
    ("token-topic-in-namespace", _token("MP", 5, "talker", "%robot%arm%joint_states", qos="::,10:,:,:,,")),
    ("token-zid-of-one-digit", _token("NN", 0, "x", zid="a")),
)

# (name, key, class). Each is one change to a token the peer sent, and the class it is refused as.
_base = _token("MP", 1, "talker", "%chatter", qos="::,7:,:,:,,")
_node = _token("NN", 0, "talker")
REFUSE_ROWS = (
    ("refuse-token-too-few-parts", "@ros2_lv/0/" + ZID + "/0/0/NN/%/%", "invalid-token"),
    ("refuse-token-empty-part", _node.replace("/NN/%/%/", "/NN//%/"), "invalid-token"),
    ("refuse-node-token-with-a-topic", _node + "/%chatter", "invalid-token"),
    ("refuse-publisher-token-with-a-part-short", _base.rsplit("/", 1)[0], "invalid-token"),
    ("refuse-publisher-token-with-a-part-over", _base + "/x", "invalid-token"),
    ("refuse-token-unknown-entity", _node.replace("/NN/", "/XX/"), "unknown-entity"),
    ("refuse-token-lowercase-kind", _node.replace("/NN/", "/nn/"), "unknown-entity"),
    ("refuse-token-other-domain", _token("NN", 0, "talker", domain=1), "wrong-domain"),
    ("refuse-token-domain-not-canonical", _node.replace("@ros2_lv/0/", "@ros2_lv/00/"), "invalid-token"),
    ("refuse-token-zid-uppercase", _token("NN", 0, "talker", zid=ZID.upper()), "invalid-token"),
    ("refuse-token-zid-of-33-digits", _token("NN", 0, "talker", zid=ZID + "0"), "invalid-token"),
    ("refuse-token-nid-not-canonical", _token("NN", 0, "talker", nid=0).replace(f"/{ZID}/0/0/", f"/{ZID}/01/0/"), "invalid-token"),
    ("refuse-token-id-of-11-digits", _node.replace(f"/{ZID}/0/0/", f"/{ZID}/0/12345678901/"), "invalid-token"),
    ("refuse-token-id-signed", _node.replace(f"/{ZID}/0/0/", f"/{ZID}/0/-1/"), "invalid-token"),
    ("refuse-qos-with-five-parts", _base.rsplit("/", 1)[0] + "/::,7:,:,:,", "invalid-qos"),
    ("refuse-qos-with-letters", _base.rsplit("/", 1)[0] + "/x::,7:,:,:,,", "invalid-qos"),
    ("refuse-qos-policy-out-of-range", _base.rsplit("/", 1)[0] + "/9::,7:,:,:,,", "invalid-qos"),
    ("refuse-qos-depth-negative", _base.rsplit("/", 1)[0] + "/::,-1:,:,:,,", "invalid-qos"),
    ("refuse-qos-depth-over-64-bits", _base.rsplit("/", 1)[0] + "/::,18446744073709551616:,:,:,,", "invalid-qos"),
    ("refuse-qos-history-without-depth", _base.rsplit("/", 1)[0] + "/:::,:,:,:,,", "invalid-qos"),
    ("refuse-qos-liveliness-with-two-parts", _base.rsplit("/", 1)[0] + "/::,7:,:,:,", "invalid-qos"),
)
QOS_REFUSE_ROWS = (
    ("refuse-qos-substring-five-parts", "::,7:,:,:,", "invalid-qos"),
    ("refuse-qos-substring-policy-letters", "x::,7:,:,:,,", "invalid-qos"),
    ("refuse-qos-substring-depth-hex", "::,0x7:,:,:,,", "invalid-qos"),
    ("refuse-qos-substring-empty", "", "invalid-qos"),
)

# A key outside `@ros2_lv` is ignored and counted. The third is the advanced publisher token the peer
# sends beside each publisher.
IGNORED_ROWS = (
    ("ignored-adv-token", "0/rosout/rcl_interfaces::msg::dds_::Log_/RIHS01_e28ce254ca8abc06abf92773b74602cdbf116ed34fbaf294fb9f81da9f318eac/@adv/pub/" + ZID + "/12/_"),
    ("ignored-other-admin-space", "@ros2_lvx/0/" + ZID + "/0/0/NN/%/%/talker"),
)


def check_rows() -> None:
    """The rows are what the exam claims: each refusal is one the reference refuses, and each accepted row parses."""
    for name, key in TOKEN_ROWS:
        try:
            entity = graph.parse_token(key, DOMAIN)
        except graph.GraphError as error:
            raise GraphExamError(f"{name} is refused by the reference as {error.cls}") from error
        _need(entity is not None and graph.build_token(entity) == key, f"{name} does not build back to its own key")
        _need(len(key.encode()) <= MAX_KEY_BYTES, f"{name} is over the {MAX_KEY_BYTES}-byte key bound")
    for name, key, cls in REFUSE_ROWS:
        try:
            graph.parse_token(key, DOMAIN)
        except graph.GraphError as error:
            _need(error.cls == cls, f"{name} is refused as {error.cls}, the exam pins {cls}")
            continue
        raise GraphExamError(f"{name} is accepted by the reference")
    for name, text, cls in QOS_REFUSE_ROWS:
        try:
            graph.keyexpr_to_qos(text)
        except graph.GraphError as error:
            _need(error.cls == cls, f"{name} is refused as {error.cls}, the exam pins {cls}")
            continue
        raise GraphExamError(f"{name} is accepted by the reference")
    for name, key in IGNORED_ROWS:
        _need(graph.parse_token(key, DOMAIN) is None, f"{name} is not ignored by the reference")
    names = [n for n, *_ in (*QOS_ROWS, *TOKEN_ROWS, *REFUSE_ROWS, *QOS_REFUSE_ROWS, *IGNORED_ROWS)]
    _need(len(set(names)) == len(names), "a row name is used twice")


# --------------------------------------------------------------------------------- the transcript


def session_tokens(group: str) -> list[tuple[str, str]]:
    """The captured session's token declarations and withdrawals, in order: ('declare' | 'withdraw', key)."""
    table: dict[int, str] = {}
    held: dict[int, str] = {}
    out: list[tuple[str, str]] = []
    for _name, hexed in dict(zenoh_rmw_exam.GROUPS)[group]:
        batch = bytes.fromhex(hexed)
        if batch[0] & 0x1F != wire.ID_FRAME:
            continue
        for message, full in wire.resolve(wire.frame(batch)[1], table):
            if message.kind == "token" and full is not None and message.ident is not None:
                held[message.ident] = full
                out.append(("declare", full))
            elif message.kind == "untoken" and message.ident in held:
                out.append(("withdraw", held.pop(message.ident)))
    return out


def replay_group(group: str) -> graph.Graph:
    state = graph.Graph(DOMAIN, CAPACITY)
    for action, key in session_tokens(group):
        state.declare(key) if action == "declare" else state.withdraw(key)
    return state


def capacity_run() -> tuple[int, str]:
    """Fill a graph with node tokens until the reference refuses one: (entities held, class of the refusal)."""
    state = graph.Graph(DOMAIN, CAPACITY)
    for number in range(CAPACITY + 1):
        try:
            state.declare(_token("NN", number, f"n{number}"))
        except graph.GraphError as error:
            return len(state.live), error.cls
    raise GraphExamError("the reference never refused a token past its capacity")


def good_lines() -> list[str]:
    check_rows()
    lines: list[str] = []
    for group in GROUPS:
        state = replay_group(group)
        lines += [f"graph entity {group} {entity.line()}" for entity in state.entities()]
        lines += [f"graph topic {group} {topic} {p} {s}" for topic, (p, s) in state.counts().items()]
        lines += [f"graph service {group} {name} {a} {c}" for name, (a, c) in state.services().items()]
        lines += [f"graph node {group} {name}" for name in state.nodes()]
        lines.append(f"graph ignored {group} {state.ignored}")
        lines.append(f"graph ok {group}-graph")
    for name, text in QOS_ROWS:
        lines.append(f"graph qos {name} {graph.keyexpr_to_qos(text).canonical()}")
    for name, key in TOKEN_ROWS:
        entity = graph.parse_token(key, DOMAIN)
        assert entity is not None
        lines.append(f"graph token {name} {entity.line()}")
        lines.append(f"graph build {name} ok")
    for name, _key in IGNORED_ROWS:
        lines.append(f"graph ignored-key {name} ok")
    lines += [f"graph refused {name} {cls}" for name, _key, cls in (*REFUSE_ROWS, *QOS_REFUSE_ROWS)]
    held, cls = capacity_run()
    lines.append(f"graph capacity {held} {cls}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one the reference builds, line for line.

    Returns (cases, refusals): a refusal is a `refused` line, a case is every other line.
    """
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("graph "), f"graph: a record that is not a graph exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"graph: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"graph lines missing: {missing[:3]}")
    _need(not extra, f"graph lines the reference does not build: {extra[:3]}")
    _need(len(lines) == len(wanted), f"graph: {len(lines)} lines, the reference builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "graph: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("graph refused ") or line.startswith("graph capacity "))
    return len(wanted) - refusals, refusals


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a graph exam line", [*good, "rmw ok talker-session-opens-and-closes"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[0].replace(" ", "  ", 1), *good[1:]]),
        ("a line with trailing space", [good[0] + " ", *good[1:]]),
        ("the first two lines swapped", [good[1], good[0], *good[2:]]),
        ("the first and last lines swapped", [good[-1], *good[1:-1], good[0]]),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:48]})", [*good[:index], *good[index + 1 :]]))
    seen_kinds: dict[str, int] = {}
    for index, line in enumerate(good):
        fields = line.split(" ")
        kind = fields[1]
        if kind in ("entity", "topic", "service", "qos", "token") and seen_kinds.get(kind, 0) < 40:
            seen_kinds[kind] = seen_kinds.get(kind, 0) + 1
            last = fields[-1]
            changed = last + "0" if last[-1:].isdigit() else last + "x"
            out.append((f"line {index} with a changed last field ({line[:48]})", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    out.append(("a graph that held one entity more than its capacity", [line.replace(f"graph capacity {CAPACITY} ", f"graph capacity {CAPACITY + 1} ") for line in good]))
    out.append(("a graph that held one entity fewer than its capacity", [line.replace(f"graph capacity {CAPACITY} ", f"graph capacity {CAPACITY - 1} ") for line in good]))
    out.append(("a full graph that refused as another class", [line.replace(" graph-full", " invalid-token") for line in good]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("graph refused ")})
    first_refusal = next(i for i, line in enumerate(good) if line.startswith("graph refused "))
    for cls in classes:
        index = next(i for i, line in enumerate(good) if line.startswith("graph refused ") and line.endswith(f" {cls}"))
        other = next(c for c in classes if c != cls)
        out.append((f"the first {cls} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls}", f" {other}"), *good[index + 1 :]]))
    out.append(("the first two refusals swapped", [*good[:first_refusal], good[first_refusal + 1], good[first_refusal], *good[first_refusal + 2 :]]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"graph: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise GraphExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except GraphExamError:
            refused += 1
            continue
        raise GraphExamError(f"control: the graph judge accepted {label}")
    return refused


def reference_controls() -> int:
    """Each guard in the host reference is corrupted in turn, and the row check must notice."""
    check_rows()
    refused = 0
    real = (graph.keyexpr_to_qos, graph.parse_token)
    cases: list[tuple[str, Callable[[], None], str]] = []

    def depth_unchecked() -> None:
        graph.keyexpr_to_qos = lambda text: graph.Qos(1, 2, 1, 42, graph.INFINITE, graph.INFINITE, 1, graph.INFINITE) if text.startswith("::,18446744073709551616") else real[0](text)

    def domain_unchecked() -> None:
        graph.parse_token = lambda key, domain: real[1](key, 1 if key.startswith("@ros2_lv/1/") else domain)

    def mangle_unchecked() -> None:
        graph.parse_token = lambda key, domain: real[1](key.replace("%robot%arm", "robot"), domain)

    cases = [
        ("a reference that takes a depth over 64 bits", depth_unchecked, "refuse-qos-depth-over-64-bits"),
        ("a reference that takes another domain", domain_unchecked, "refuse-token-other-domain"),
        ("a reference that does not demangle", mangle_unchecked, "token-node-in-namespace"),
    ]
    for label, corrupt, reason in cases:
        corrupt()
        try:
            check_rows()
        except GraphExamError as error:
            graph.keyexpr_to_qos, graph.parse_token = real
            _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
            refused += 1
            continue
        finally:
            graph.keyexpr_to_qos, graph.parse_token = real
        raise GraphExamError(f"control: the row check accepted {label}")
    return refused


# --------------------------------------------------------------------------------- the hand-off record

DECODED_ENTRY = re.compile(r'\s*\{ key = "([^"\\]*)";\s+name = "([^"\\]*)" \}\s*')
GROUPS_OF_ROWS = ("qos", "tokens", "refuse")


def fixture_zti() -> str:
    """The synthetic rows as one `contracts/zenoh-rmw-graph/v1` record."""

    def rows(items: tuple[tuple[str, str], ...]) -> str:
        return "".join(f'    {{ name = "{name}"; key = "{key}"; }};\n' for name, key in items)

    refuse = tuple((name, key) for name, key, _cls in REFUSE_ROWS)
    qos_refuse = tuple((name, text) for name, text, _cls in QOS_REFUSE_ROWS)
    ignored = IGNORED_ROWS
    return (
        "{\n  formatVersion = 1;\n"
        f"  qos = [\n{rows(QOS_ROWS)}  ];\n"
        f"  tokens = [\n{rows(TOKEN_ROWS)}  ];\n"
        f"  refuse = [\n{rows(refuse)}  ];\n"
        f"  qosRefuse = [\n{rows(qos_refuse)}  ];\n"
        f"  ignored = [\n{rows(ignored)}  ];\n"
        "}\n"
    )


def _decoded_rows(decoded: str, group: str) -> list[tuple[str, str]]:
    start = re.search(rf"\b{group} = \[", decoded)
    _need(start is not None, f"graph hand-off: the decoded record has no {group} group")
    assert start is not None
    position, rows = start.end(), []
    if decoded[position : position + 1] == "]":
        return rows
    while True:
        entry = DECODED_ENTRY.match(decoded, position)
        _need(entry is not None, f"graph hand-off: {group} holds an entry the checker cannot read at offset {position}")
        assert entry is not None
        rows.append((entry.group(2), entry.group(1)))
        position = entry.end()
        if decoded[position : position + 1] == "]":
            return rows
        _need(decoded[position : position + 1] == ";", f"graph hand-off: {group} is not a list of entries at offset {position}")
        position += 1


def validate_handoff(text: str) -> None:
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="zenoh-rmw-graph-", dir=ROOT / "build"))
    try:
        shutil.copyfile(SCHEMA, scratch / "schema.zt")
        (scratch / "decode.zt").write_text(
            's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
            "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Graph ! { * env.GetEffects; * load.ZtiEffects; } "
            '= caps => [ path := env.get caps.env "SLIME_ZENOH_RMW_GRAPH_FIXTURES_PATH" ?? ""; s.decodeGraph (load.zti caps.load path) ]; main\n'
        )
        record = scratch / "fixtures.zti"
        record.write_text(text)
        try:
            decoded = zutai_cli.evaluate("run", scratch / "decode.zt", input_path=record, env_var="SLIME_ZENOH_RMW_GRAPH_FIXTURES_PATH")
        except zutai_cli.ZutaiError as error:
            raise GraphExamError(f"graph hand-off does not decode under contracts/zenoh-rmw-graph/v1: {error}") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _need(decoded.startswith("#valid"), f"graph hand-off is refused by contracts/zenoh-rmw-graph/v1: {decoded[:200]}")
    version = re.search(r"\bformatVersion = (\d+)", decoded)
    _need(version is not None and int(version.group(1)) == 1, "graph hand-off: formatVersion is not 1")
    sizes = {"qos": len(QOS_ROWS), "tokens": len(TOKEN_ROWS), "refuse": len(REFUSE_ROWS), "qosRefuse": len(QOS_REFUSE_ROWS), "ignored": len(IGNORED_ROWS)}
    for group, count in sizes.items():
        rows = _decoded_rows(decoded, group)
        _need(len(rows) == count, f"graph hand-off: {group} has {len(rows)} rows, the contract fixes {count}")
        for name, key in rows:
            _need(len(name.encode("utf-8")) <= 64 and len(key.encode("utf-8")) <= MAX_KEY_BYTES, f"graph hand-off: {group}/{name} breaks the contract's bounds")


def handoff_controls() -> int:
    honest = fixture_zti()
    first_name, first_key = QOS_ROWS[0]
    first = f'    {{ name = "{first_name}"; key = "{first_key}"; }};\n'
    respelled = honest.replace(first, f'    {{\n      name = "{first_name}";\n      key = "{first_key}";\n    }};\n', 1).replace("formatVersion = 1;", "formatVersion =\n    1;", 1)
    _need(respelled != honest, "control: the respelled honest hand-off equals the original")
    validate_handoff(honest)
    validate_handoff(respelled)
    mutations = [
        ("a missing group", honest.replace("  ignored = [", "  ignorex = [")),
        ("a wrong format version", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("a qos group of the wrong size", honest.replace(first, "", 1)),
        ("a key of 254 bytes", honest.replace(f'key = "{first_key}"', 'key = "' + "k" * 254 + '"', 1)),
        ("a name of 65 bytes", honest.replace(f'"{first_name}"', '"' + "n" * 65 + '"', 1)),
        ("a row with no key", honest.replace('key = "', 'kex = "', 1)),
        ("an unknown extra field", honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise = 1;")),
        ("an unknown extra field inside an entry", honest.replace(first, f'    {{ name = "{first_name}"; key = "{first_key}"; extra = 1; }};\n', 1)),
        ("a wrong format version written over several lines", honest.replace("formatVersion = 1;", "formatVersion =\n    2;", 1)),
        ("an extra tokens entry written over several lines", honest.replace("  tokens = [\n", '  tokens = [\n    {\n      name = "extra";\n      key = "x";\n    };\n', 1)),
    ]
    for label, text in mutations:
        if text == honest:
            raise GraphExamError(f"control: {label} did not change the hand-off")
        try:
            validate_handoff(text)
        except GraphExamError:
            continue
        raise GraphExamError(f"control: {label} was accepted by the graph fixture contract")
    return len(mutations)


def all_controls() -> int:
    return transcript_controls() + handoff_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 106
PINNED_REFUSALS = 26
PINNED_CONTROLS = 196


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
