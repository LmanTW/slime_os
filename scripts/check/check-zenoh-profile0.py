#!/usr/bin/env python3

"""Zenoh Profile 0 host gate for R0: encoder, session, CDR, transport and composition.

Each Rust slice prints one `[zenoh-exam] ...` line per case it judges:

  encode  ok <name> <hex>               a batch the encoder produced
  encode  refused <control>             an input the encoder refused
  session ok <scenario>                 a scenario the session machine completed
  session refused <control>             an input the session machine refused
  cdr     ok <sequence> <value> <hex>   a sample the CDR codec produced
  cdr     refused <control>             an input the CDR decoder refused
  link    ok <scenario>                 a transport-runtime scenario over a scripted byte link
  link    refused <control>             a link input the runtime refused

This checker owns the expectation, never the tests: it counts the lines it reads
and compares each against bytes from an independent source. The decoder corpus's
accepted batches were produced by the upstream eclipse-zenoh 1.0.0 encoder, and
`scripts/lib/zenoh_wire.py` re-derives every one from its summary before it is
trusted; the CDR samples are recomputed from the demo fixture's field values.
`--controls-only` proves, without Rust, that each judge refuses missing, extra,
duplicated, reordered and corrupted evidence.

`--slice composition` judges the derived `sel4-zenoh` composition against the
demo contract's authority and refuses 15 mutations of an honest one. It is the
static half of the QEMU arm; the boot is `check-sel4-io-network-plane.py --arm zenoh`.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import re
import struct
import subprocess
from collections.abc import Callable
from typing import NoReturn

import devloop_observations
import zenoh_exchange
import zenoh_wire
from harness import GENERATION_COMPOSITIONS, ROOT

CORPUS = ROOT / "components" / "lib" / "src" / "zenoh_profile0" / "vectors.txt"
COMPOSITION = GENERATION_COMPOSITIONS / "sel4-zenoh.zti"
EXAM_LINE = re.compile(r"\[zenoh-exam\] (.*)$")

ENCODE_REFUSALS = (
    "key-over-129-bytes",
    "attachment-not-33-bytes",
    "payload-over-12-bytes",
    "cookie-over-64-bytes",
    "zid-empty-or-over-16-bytes",
    "wildcard-key",
    "batch-over-512-bytes",
)
SESSION_SCENARIOS = (
    "connect-handshake",
    "listen-handshake",
    "declare-then-push-delivered",
    "teardown-undeclare-then-close",
    "lease-expiry-closes",
)
SESSION_REFUSALS = (
    "router-peer",
    "version-mismatch",
    "wildcard-key-declaration",
    "push-to-undeclared-key",
    "replayed-sequence",
    "frame-before-open",
    "cookie-mismatch",
)
CDR_REFUSALS = (
    "truncated-header",
    "truncated-body",
    "trailing-bytes",
    "big-endian-encapsulation",
    "unknown-encapsulation",
    "nonzero-options",
    "over-max-serialized",
)
LINK_SCENARIOS = (
    "connector-opens-and-publishes",
    "listener-accepts-and-delivers",
    "split-and-coalesced-batches",
    "backpressure-resumes",
    "peer-close-ends-session",
    "restart-uses-fresh-session",
)
LINK_REFUSALS = (
    "oversized-length-prefix",
    "zero-length-prefix",
    "garbage-after-open",
    "receive-queue-full",
    "retry-limit-reached",
    "send-after-close",
    "stale-session-handle",
)

# slice -> (the Rust test filter, scenario names, refusal names, word on the exam line)
RUST = {
    "encoder": ("zenoh_profile0::", None, ENCODE_REFUSALS, "encode"),
    "session": ("zenoh_profile0::", SESSION_SCENARIOS, SESSION_REFUSALS, "session"),
    "cdr": ("ros_cdr::", None, CDR_REFUSALS, "cdr"),
    "transport": ("zenoh_link::", LINK_SCENARIOS, LINK_REFUSALS, "link"),
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"zenoh profile 0 check failed: {message}")


def reference() -> list[tuple[str, str, str]]:
    """The corpus's accepted batches, after proving the reference reproduces each."""
    if not CORPUS.is_file():
        fail(f"{CORPUS.relative_to(ROOT)} is missing; the decoder corpus must land first")
    try:
        zenoh_wire.self_test(CORPUS)
    except zenoh_wire.WireError as error:
        fail(f"the host wire reference disagrees with the upstream corpus: {error}")
    return zenoh_wire.corpus_accepted(CORPUS)


def demo_samples() -> dict[int, tuple[int, str]]:
    contract = zenoh_exchange.demo()
    samples = {seq: (value, hexed) for seq, value, hexed in contract["samples"]}
    for seq, (value, hexed) in samples.items():
        # Classic CDR_LE: representation id and options are big-endian (00 01, 00 00)
        # and name the byte order of the body that follows.
        independent = (struct.pack(">HH", 1, 0) + struct.pack("<Ii", seq, value)).hex()
        if hexed != independent:
            fail(f"demo sample {seq}: contract hex {hexed} differs from {independent}")
    return samples


def exam_lines(output: str) -> list[str]:
    return [match.group(1).strip() for line in output.splitlines() if (match := EXAM_LINE.search(line))]


def exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    duplicated = sorted({name for name in seen if seen.count(name) > 1})
    if duplicated:
        fail(f"{label}: reported twice: {', '.join(duplicated)}")
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    if missing:
        fail(f"{label}: not reported: {', '.join(missing)}")
    if extra:
        fail(f"{label}: not in the exam: {', '.join(extra)}")


def names(lines: list[str], word: str, verdict: str) -> list[str]:
    split = [line.split() for line in lines]
    return [fields[2] for fields in split if len(fields) == 3 and fields[0] == word and fields[1] == verdict]


def judge_encoder(lines: list[str]) -> tuple[int, int]:
    golden = {name: hexed for name, hexed, _ in reference()}
    produced: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 4 and fields[:2] == ["encode", "ok"]:
            if fields[2] in produced:
                fail(f"encoder reported {fields[2]} twice")
            produced[fields[2]] = fields[3]
    exactly("encoder batches", tuple(golden), list(produced))
    for name, hexed in produced.items():
        if hexed != golden[name]:
            fail(f"encoder batch {name}: produced {hexed}, upstream bytes are {golden[name]}")
    refused = names(lines, "encode", "refused")
    exactly("encoder refusals", ENCODE_REFUSALS, refused)
    return len(produced), len(refused)


def judge_named(slice_name: str) -> Callable[[list[str]], tuple[int, int]]:
    _, scenarios, refusals, word = RUST[slice_name]

    def judge(lines: list[str]) -> tuple[int, int]:
        done = names(lines, word, "ok")
        refused = names(lines, word, "refused")
        exactly(f"{slice_name} scenarios", scenarios, done)
        exactly(f"{slice_name} refusals", refusals, refused)
        return len(done), len(refused)

    return judge


def judge_cdr(lines: list[str]) -> tuple[int, int]:
    wanted = demo_samples()
    produced: dict[int, tuple[int, str]] = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 5 and fields[:2] == ["cdr", "ok"] and fields[2].isdigit() and fields[3].isdigit():
            seq = int(fields[2])
            if seq in produced:
                fail(f"CDR reported sample {seq} twice")
            produced[seq] = (int(fields[3]), fields[4])
    if sorted(produced) != sorted(wanted):
        fail(f"CDR samples reported {sorted(produced)}, the demo contract has {sorted(wanted)}")
    for seq, (value, hexed) in produced.items():
        if (value, hexed) != wanted[seq]:
            fail(f"CDR sample {seq}: produced {value} {hexed}, contract has {wanted[seq]}")
    refused = names(lines, "cdr", "refused")
    exactly("CDR refusals", CDR_REFUSALS, refused)
    return len(produced), len(refused)


JUDGES: dict[str, Callable[[list[str]], tuple[int, int]]] = {
    "encoder": judge_encoder,
    "session": judge_named("session"),
    "cdr": judge_cdr,
    "transport": judge_named("transport"),
}


def good_lines(slice_name: str) -> list[str]:
    _, scenarios, refusals, word = RUST[slice_name]
    refused = [f"{word} refused {c}" for c in refusals]
    if slice_name == "encoder":
        return [f"encode ok {n} {h}" for n, h, _ in reference()] + refused
    if slice_name == "cdr":
        return [f"cdr ok {seq} {value} {hexed}" for seq, (value, hexed) in demo_samples().items()] + refused
    return [f"{word} ok {s}" for s in scenarios] + refused


def controls(slice_name: str) -> int:
    """Refuse corrupted evidence before trusting the judge; returns the count."""
    judge = JUDGES[slice_name]
    good = good_lines(slice_name)
    judge(good)
    word = RUST[slice_name][3]
    mutations: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a dropped first line", good[1:]),
        ("a dropped last line", good[:-1]),
        ("a duplicated line", good + [good[0]]),
        ("an unknown refusal", good + [f"{word} refused invented"]),
        ("every refusal removed", [line for line in good if " refused " not in line]),
    ]
    if slice_name in ("encoder", "cdr"):
        at = next(i for i, line in enumerate(good) if " ok " in line)
        fields = good[at].split()
        flipped = fields[-1][:-1] + ("0" if fields[-1][-1] != "0" else "1")
        mutations.append(("a corrupted byte", good[:at] + [" ".join(fields[:-1] + [flipped])] + good[at + 1 :]))
        mutations.append(("a truncated hex string", good[:at] + [" ".join(fields[:-1] + [fields[-1][:-2]])] + good[at + 1 :]))
    for label, mutated in mutations:
        try:
            judge(mutated)
        except SystemExit:
            continue
        fail(f"control: {label} was accepted by the {slice_name} judge")
    return len(mutations)


def run_tests(slice_name: str) -> list[str]:
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    filter_ = RUST[slice_name][0]
    command = [
        "cargo", "test", "--target", target, "-p", "slime-components", "--no-default-features",
        filter_, "--", "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", output)
    if not any(status == "ok" and int(passed) > 0 for status, passed, _ in results) or any(
        status != "ok" or int(failed) for status, _, failed in results
    ):
        fail(f"no passing test result for filter {filter_!r}")
    return exam_lines(result.stdout)


def composition_main(controls_only: bool) -> int:
    contract = zenoh_exchange.demo()
    try:
        facts, refused = zenoh_exchange.composition_controls(contract)
    except zenoh_exchange.ExchangeError as error:
        fail(str(error))
    if controls_only:
        print(f"zenoh composition judge: {facts} authority facts on an honest composition, {refused} mutations refused")
        return 0
    if not COMPOSITION.is_file():
        fail(f"{COMPOSITION.relative_to(ROOT)} does not exist; the sel4-zenoh composition has not landed")
    try:
        verified = zenoh_exchange.check_composition_rows(*zenoh_exchange.composition_from_text(COMPOSITION.read_text()), contract)
    except zenoh_exchange.ExchangeError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=composition facts={verified} controls={refused}")
    devloop_observations.record(casesObserved=verified, negativeControlsRefused=refused)
    print("zenoh profile 0 composition check: the derived composition grants the nodes exactly the demo's authority")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--slice", choices=(*JUDGES, "composition"), required=True)
    parser.add_argument("--controls-only", action="store_true")
    arguments = parser.parse_args()
    if arguments.slice == "composition":
        return composition_main(arguments.controls_only)
    refused_controls = controls(arguments.slice)
    if arguments.controls_only:
        print(f"zenoh profile 0 {arguments.slice} judge: refused {refused_controls} corrupted transcripts")
        return 0
    cases, refusals = JUDGES[arguments.slice](run_tests(arguments.slice))
    print(f"[zenoh-profile0] slice={arguments.slice} cases={cases} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refusals)
    print(f"zenoh profile 0 {arguments.slice} check: every case matched independent bytes and every refusal was observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
