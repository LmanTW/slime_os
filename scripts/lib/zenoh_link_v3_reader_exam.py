"""Judge the Rust reader of a version 3 link configuration and the service's use of it.

`contracts/zenoh-link-limits/v3` declares a link's local subscriptions and runs. The component `zenoh-service` builds its
session parameters from a constant configuration of that contract instead of from a literal. The Rust test under the module
path `zenoh_link_limits_v3::` prints one `[zenoh-exam] linkv3 ...` line per thing it did. This module owns what those lines
must be. Nothing here reads the Rust of the test.

* The configuration the test printed is the one pinned here, and the contract's decoder accepts a record that carries it.
* The stack the Rust arithmetic returns equals the stack `zenoh_link_v3_limits_exam` computes, and the declared stack covers it.
* The session parameters the Rust derives equal the ones this module derives from the same configuration.
* Each refusal the Rust names is a record the contract refuses, and the class it names is the one pinned here.

The files hold declarations that no transcript shows, so they are read as facts, as in `zenoh_service_four_exam`. A fact shows that
a declaration exists and not what the code does. The judge is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
import zenoh_link_v3_limits_exam as v3
import zenoh_links_exam as links
from harness import ROOT

MAIN = "components/services/zenoh-service/src/main.rs"
LIB = "components/lib/src/lib.rs"
NAME = "service"
# The configuration the service's link is built from: the name, mode, batch, payload, key, attachment, keys, subscribers,
# local subscriptions, runs, outstanding samples, stack, timeout and heap. The batch is the framed 514 bytes of the link type.
CONFIG = (NAME, "fixed", 514, 12, 129, 33, 2, 2, 3, 0, 4, 32768, 0, 0)
FIELDS = (
    "name", "mode", "batchBytes", "payloadBytes", "keyBytes", "attachmentBytes", "maxKeys", "maxSubscribers",
    "localSubscriptions", "maxRuns", "outstandingSamples", "stackBytes", "reassemblyTimeoutMs", "heapBytes",
)
# The refusals the test prints, in order: the label, the field changed from CONFIG, its new value, and the class the Rust
# names. `stack-under` is one byte under the required stack. `ok` is the unchanged configuration.
CASES = (
    ("exact", None, None, "ok"),
    ("stack-under", "stackBytes", "under", "stack"),
    ("zero-local", "localSubscriptions", 0, "count"),
    ("local-65536", "localSubscriptions", 65536, "count"),
    ("subscribers-over-keys", "maxSubscribers", 3, "count"),
    ("fixed-with-runs", "maxRuns", 1, "fixed"),
)

FACTS: tuple[facts.Fact, ...] = (
    ("link-alias", MAIN, r"^pub type Link<'a, 'b> = LinkOf<Stream<Wire<'a, 'b>>, 514, 2, 5, 129, PAYLOAD, 8, 4>;$",
     "pub type Link<'a, 'b> = LinkOf<Stream<Wire<'a, 'b>>, 514, 2, 5, 129, PAYLOAD, 8, 4>;"),
    ("service-config", MAIN, r"^use slime_components::zenoh_link_limits_v3::SERVICE;$", "use slime_components::zenoh_link_limits_v3::SERVICE;"),
    ("service-params", MAIN, r"^\s*let params = SERVICE\.params\(\);$", "    let params = SERVICE.params();"),
    ("reader-module", LIB, r"^pub mod zenoh_link_limits_v3;$", "pub mod zenoh_link_limits_v3;"),
)
# Declarations the component no longer holds: the literal that the configuration replaces.
ABSENT = (("params-literal", MAIN, r"\blocal:\s*3\b", "        local: 3,"),)

LINE = re.compile(
    r"config (\S+) (fixed|heap)((?: \d+){12})|required (\S+) (\d+)|params (\S+)((?: \d+){7}) (fixed|heap)|case (\S+) (\S+)"
)


class ReaderError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ReaderError(message)


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise ReaderError(f"{path} cannot be read: {error}") from error


def check_facts() -> int:
    try:
        count = facts.check(FACTS, read_file)
    except facts.FactsError as error:
        raise ReaderError(str(error)) from error
    for name, path, pattern, _example in ABSENT:
        _need(re.search(pattern, read_file(path), re.MULTILINE) is None, f"{name}: {path} still matches {pattern}")
    return count + len(ABSENT)


def config_dict(change: tuple[str | None, object] = (None, None), base: dict | None = None) -> dict:
    config = dict(zip(FIELDS, CONFIG, strict=True)) if base is None else dict(base)
    field, value = change
    if field == "stackBytes" and value == "under":
        config["stackBytes"] = v3.stack_v3(config) - 1
    elif field is not None:
        config[field] = value
    return config


def params_of(config: dict) -> tuple[int, ...]:
    """The session parameters a configuration describes: batch body, announced batch, aliases, subscribers of the peer, local
    subscriptions, events in one batch and outstanding samples."""
    body = config["batchBytes"] - 2
    return (body, config["batchBytes"], config["maxKeys"], config["maxSubscribers"], config["localSubscriptions"],
            min(config["outstandingSamples"], config["batchBytes"] // 4), config["outstandingSamples"])


def contract_takes(config: dict) -> bool:
    demo, large, heap = links.pinned_configs()
    return v3.contract_accepts(v3.render_record([config, v3.config_v3(large, 1, 0), v3.config_v3(heap, 1, 1)]))


def good_lines(config: dict | None = None, cases: tuple = CASES) -> list[str]:
    """What an honest run prints for `config` and the refusal `cases`. The defaults are the service's."""
    config = config_dict() if config is None else config
    out = [
        f"config {NAME} {config['mode']}" + "".join(f" {config[f]}" for f in FIELDS[2:]),
        f"required {NAME} {v3.stack_v3(config)}",
        f"params {NAME}" + "".join(f" {v}" for v in params_of(config)) + " fixed",
    ]
    out += [f"case {label} {result}" for label, _field, _value, result in cases]
    return out


def judge(lines: list[str], config: dict | None = None, cases: tuple = CASES) -> int:
    """Returns the number of cases that hold. Any case that fails raises."""
    config = config_dict() if config is None else config
    expected = good_lines(config, cases)
    _need(len(lines) == len(expected), f"linkv3: the test printed {len(lines)} lines, the exam requires {len(expected)}")
    for index, (line, want) in enumerate(zip(lines, expected, strict=True)):
        if index == 1:
            found = re.fullmatch(rf"required {NAME} (\d+)", line)
            _need(found is not None, f"linkv3: line {index} is {line!r}, not a required stack")
            _need(int(found.group(1)) == v3.stack_v3(config), f"linkv3: the Rust requires {found.group(1)} bytes, the arithmetic of the contract gives {v3.stack_v3(config)}")
            continue
        _need(line == want, f"linkv3: line {index} is {line!r}, the exam requires {want!r}")
    count = 3
    for label, field, value, result in cases:
        changed = config_dict((field, value), config)
        taken = contract_takes(changed)
        _need(taken == (result == "ok"), f"linkv3: the contract {'takes' if taken else 'refuses'} case {label}, the Rust says {result}")
        count += 1
    return count


def check_absence_controls() -> int:
    refused = 0
    for name, _path, pattern, example in ABSENT:
        _need(re.search(pattern, example, re.MULTILINE) is not None, f"{name}: its example does not match its own pattern")
        refused += 1
    return refused


def fact_controls() -> int:
    try:
        return facts.controls(FACTS) + check_absence_controls()
    except facts.FactsError as error:
        raise ReaderError(str(error)) from error


def _refused(label: str, lines: list[str]) -> int:
    try:
        judge(lines)
    except ReaderError:
        return 1
    raise ReaderError(f"control: the reader judge accepted {label}")


def _refused_with(label: str, config: dict | None = None, cases: tuple = CASES) -> int:
    """Honest lines for a configuration or a case list the judge must not take: only the contract can refuse them."""
    try:
        judge(good_lines(config, cases), config, cases)
    except ReaderError:
        return 1
    raise ReaderError(f"control: the reader judge accepted {label}")


def transcript_controls() -> int:
    good = good_lines()
    judge(good)
    refused = 0
    for index in range(len(good)):
        refused += _refused(f"line {index} missing", good[:index] + good[index + 1:])
        refused += _refused(f"line {index} repeated", good[: index + 1] + good[index:])
    config = config_dict()
    required = v3.stack_v3(config)
    for label, lines in (
        ("a required stack one byte under", [good[0], f"required {NAME} {required - 1}", *good[2:]]),
        ("a required stack one byte over", [good[0], f"required {NAME} {required + 1}", *good[2:]]),
        ("a configuration with one subscriber", [good[0].replace(" 2 2 3 0", " 2 1 3 0"), *good[1:]]),
        ("a configuration with two local subscriptions", [good[0].replace(" 3 0 4", " 2 0 4"), *good[1:]]),
        ("a batch of 512", [good[0].replace(" 514 ", " 512 "), *good[1:]]),
        ("an announced batch of 512", [*good[:2], good[2].replace(" 514 ", " 512 "), *good[3:]]),
        ("a peer table of 1 subscriber", [*good[:2], good[2].replace(" 2 2 3 ", " 2 1 3 "), *good[3:]]),
        ("one local subscription in the parameters", [*good[:2], good[2].replace(" 3 4 4", " 1 4 4"), *good[3:]]),
        ("events above the samples", [*good[:2], good[2].replace(" 4 4 fixed", " 5 4 fixed"), *good[3:]]),
        ("the under-stack case accepted", [*good[:4], "case stack-under ok", *good[5:]]),
        ("the zero-local case accepted", [*good[:5], "case zero-local ok", *good[6:]]),
        ("the exact case refused", [*good[:3], "case exact stack", *good[4:]]),
        ("a refusal under the wrong class", [*good[:4], "case stack-under count", *good[5:]]),
        ("a required stack that is not a number", [good[0], f"required {NAME} many", *good[2:]]),
    ):
        refused += _refused(label, lines)
    config = config_dict()
    refused += _refused_with("a configuration of 3 subscribers and 2 keys", config_dict(("maxSubscribers", 3), config))
    refused += _refused_with("a configuration with the stack one byte under", config_dict(("stackBytes", "under"), config))
    refused += _refused_with("the zero-local case marked as taken", cases=(*CASES[:2], ("zero-local", "localSubscriptions", 0, "ok"), *CASES[3:]))
    refused += _refused_with("the exact case marked as refused", cases=(("exact", None, None, "stack"), *CASES[1:]))
    return refused


def all_controls() -> int:
    return transcript_controls() + fact_controls()


ITEM = ROOT / ".tasks" / "items" / "zenoh-link-v3-reader.zt"


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptance fixes, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
