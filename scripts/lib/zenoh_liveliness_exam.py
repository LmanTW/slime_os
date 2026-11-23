"""Judge the Zenoh Profile 0 exam for liveliness tokens and the client role.

Profile 0 admitted Peer as its only role and refused DECLARE_TOKEN, UNDECLARE_TOKEN and INTEREST. The
session gains a table of liveliness tokens, answers an INTEREST for tokens, and can be built as a Client.

The Rust tests under `zenoh_liveliness::` print one `[zenoh-exam] liveliness ...` line for each thing they
did. This module owns what those lines must be, and nothing here reads the Rust:

* the scenarios, each printed once and in order;
* the frames and the INIT the session wrote, which `zenoh_wire` must reproduce byte for byte. The
  reference is held to bytes the upstream eclipse-zenoh 1.0.0 encoder produced before it judges anything
  (`zenoh_wire.liveliness_self_test`);
* how many tokens each side held after a step;
* every refusal, by name and class.

Like the other judges it is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_wire

LISTENER_SN = 7000
ZID = bytes.fromhex("11223344")
KEY = zenoh_wire.KEY_LIVELINESS
KEY_SECOND = "@/liveliness/slime/second"

OK_SCENARIOS = (
    "declare-token-reaches-the-peer",
    "peer-declares-and-undeclares-a-token",
    "undeclare-token-by-id",
    "interest-current-answers-tokens-then-final",
    "interest-future-answers-no-final",
    "interest-current-future-answers-then-final",
    "interest-final-ends-an-interest",
    "refused-frame-changes-no-token",
    "close-releases-every-token",
    "client-sends-a-client-init",
    "listener-admits-a-client-when-configured",
    "default-configuration-unchanged",
)

# (name, bytes the session wrote). Frames are the listener's, in sequence from LISTENER_SN. An answer to an
# INTEREST is one frame: a DECLARE_TOKEN for each held token carrying the interest id, then the DeclareFinal.
FRAMES = (
    ("declare-token-1", zenoh_wire.frame(LISTENER_SN, zenoh_wire.declare_token(1, KEY, True)).hex()),
    ("undeclare-token-1", zenoh_wire.frame(LISTENER_SN + 1, zenoh_wire.undeclare_token(1, KEY)).hex()),
    (
        "answer-current-interest-7",
        zenoh_wire.frame(
            LISTENER_SN + 2,
            zenoh_wire.declare_token(1, KEY, True, 7),
            zenoh_wire.declare_token(2, KEY_SECOND, True, 7),
            zenoh_wire.declare_final(7),
        ).hex(),
    ),
    (
        "answer-current-future-interest-8",
        zenoh_wire.frame(
            LISTENER_SN + 3,
            zenoh_wire.declare_token(1, KEY, True, 8),
            zenoh_wire.declare_token(2, KEY_SECOND, True, 8),
            zenoh_wire.declare_final(8),
        ).hex(),
    ),
    ("answer-empty-interest-9", zenoh_wire.frame(LISTENER_SN + 4, zenoh_wire.declare_final(9)).hex()),
    ("client-init-syn", zenoh_wire.init_as(zenoh_wire.WHATAMI_CLIENT, ZID, 512).hex()),
)

# (label, tokens this side holds, tokens the peer holds) after a step.
HELD = (
    ("declared-one", 1, 0),
    ("peer-declared-one", 0, 1),
    ("peer-undeclared-it", 0, 0),
    ("undeclared-one", 0, 0),
    ("frame-refused", 1, 0),
    ("closed", 0, 0),
)

REFUSED_SCENARIOS = (
    ("token-declared-twice-under-one-id", "token-limit"),
    ("token-declared-beyond-the-table", "token-limit"),
    ("peer-token-repeated-id", "token-limit"),
    ("peer-token-beyond-the-table", "token-limit"),
    ("undeclare-unknown-token", "unknown-token"),
    ("peer-undeclares-unknown-token", "unknown-token"),
    ("token-with-a-wildcard-key", "wildcard-keyexpr"),
    ("token-key-over-the-bound", "over-bound"),
    ("token-before-open", "not-open"),
    ("interest-in-subscribers", "unsupported-message"),
    ("interest-in-queryables", "unsupported-message"),
    ("interest-in-key-expressions", "unsupported-message"),
    ("interest-restricted-to-a-key", "unsupported-message"),
    ("interest-with-an-extension", "unsupported-extension"),
    ("interest-in-tokens-and-subscribers", "unsupported-message"),
    ("router-init-to-a-listener", "unsupported-whatami"),
    ("client-init-to-a-listener-that-admits-none", "unsupported-whatami"),
    ("router-init-ack-to-a-connector", "unsupported-whatami"),
    ("reserved-role-init", "malformed-message"),
    ("client-with-no-token-slot", "invalid-config"),
)

SHAPES = {
    ("liveliness", "ok"): 3,
    ("liveliness", "frame"): 4,
    ("liveliness", "held"): 5,
    ("liveliness", "refused"): 4,
}


class LivelinessError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LivelinessError(message)


def good_lines() -> list[str]:
    return (
        [f"liveliness ok {name}" for name in OK_SCENARIOS]
        + [f"liveliness frame {name} {hexed}" for name, hexed in FRAMES]
        + [f"liveliness held {label} {mine} {theirs}" for label, mine, theirs in HELD]
        + [f"liveliness refused {name} {cls}" for name, cls in REFUSED_SCENARIOS]
    )


def _exactly(label: str, wanted: tuple[str, ...], seen: list[str]) -> None:
    missing = [name for name in wanted if name not in seen]
    extra = [name for name in seen if name not in wanted]
    repeated = sorted({name for name in seen if seen.count(name) > 1})
    _need(not missing, f"liveliness {label} missing: {', '.join(missing[:4])}")
    _need(not extra, f"liveliness {label} not in the exam: {', '.join(extra[:4])}")
    _need(not repeated, f"liveliness {label} reported more than once: {', '.join(repeated[:4])}")


def judge(lines: list[str]) -> tuple[int, int]:
    """Check a transcript against the exam; returns (cases, refusals), a case being a scenario or a frame."""
    split = [line.split() for line in lines]
    for line, fields in zip(lines, split, strict=True):
        _need(fields[:1] == ["liveliness"], f"liveliness: a record that is not a liveliness exam line: {line!r}")
        kind = tuple(fields[:2])
        _need(kind in SHAPES, f"liveliness: unrecognised line: {line}")
        _need(len(fields) == SHAPES[kind], f"liveliness: a {kind[1]} line has {len(fields)} fields, expected {SHAPES[kind]}: {line}")

    done = [f[2] for f in split if f[:2] == ["liveliness", "ok"]]
    _exactly("scenarios", OK_SCENARIOS, done)
    _need(done == list(OK_SCENARIOS), f"liveliness scenarios are out of order: {done}")

    frames = [(f[2], f[3]) for f in split if f[:2] == ["liveliness", "frame"]]
    _exactly("frames", tuple(name for name, _ in FRAMES), [name for name, _ in frames])
    _need([name for name, _ in frames] == [name for name, _ in FRAMES], "liveliness frames are out of order")
    for (name, hexed), (_, wanted) in zip(frames, FRAMES, strict=True):
        _need(re.fullmatch(r"[0-9a-f]+", hexed) is not None, f"liveliness frame {name} is not lowercase hexadecimal")
        _need(hexed == wanted, f"liveliness frame {name} is {hexed}, the host reference writes {wanted}")

    held = [(f[2], f[3], f[4]) for f in split if f[:2] == ["liveliness", "held"]]
    _exactly("counts", tuple(label for label, _, _ in HELD), [label for label, _, _ in held])
    _need([label for label, _, _ in held] == [label for label, _, _ in HELD], "liveliness counts are out of order")
    for (label, mine, theirs), (_, want_mine, want_theirs) in zip(held, HELD, strict=True):
        _need(
            (mine, theirs) == (str(want_mine), str(want_theirs)),
            f"liveliness held {label}: {mine} and {theirs}, the exam requires {want_mine} and {want_theirs}",
        )

    refused = [(f[2], f[3]) for f in split if f[:2] == ["liveliness", "refused"]]
    _exactly("refusals", tuple(name for name, _ in REFUSED_SCENARIOS), [name for name, _ in refused])
    _need([name for name, _ in refused] == [name for name, _ in REFUSED_SCENARIOS], "liveliness refusals are out of order")
    wanted_class = dict(REFUSED_SCENARIOS)
    wrong = [f"{name}={cls} (expected {wanted_class[name]})" for name, cls in refused if cls != wanted_class[name]]
    _need(not wrong, f"liveliness refusal classes differ: {', '.join(wrong)}")
    return len(done) + len(frames), len(refused)


def _replaced(good: list[str], old: str, new: str) -> list[str]:
    _need(old in good, f"control: {old!r} is not in the honest transcript")
    return [new if line == old else line for line in good]


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a liveliness exam line", [*good, "subscribers ok declare-several-own-subscribers"]),
        ("an unrecognised kind of line", [*good, "liveliness dropped 1 2"]),
        ("a scenario line with an extra field", [*good[:-1], good[-1] + " extra"]),
        ("the first two scenarios swapped", [good[1], good[0], *good[2:]]),
    ]
    for index, line in enumerate(good):
        fields = line.split()
        out.append((f"the line {fields[1]} {fields[2]} missing", good[:index] + good[index + 1 :]))
    for line in good:
        fields = line.split()
        if fields[1] == "ok":
            out.append((f"the scenario {fields[2]} reported twice", [*good, line]))
    classes = sorted({cls for _, cls in REFUSED_SCENARIOS})
    for name, cls in REFUSED_SCENARIOS:
        other = next(candidate for candidate in classes if candidate != cls)
        out.append((f"{name} refused as {other}", _replaced(good, f"liveliness refused {name} {cls}", f"liveliness refused {name} {other}")))
    for label, mine, theirs in HELD:
        line = f"liveliness held {label} {mine} {theirs}"
        out.append((f"{label}: this side holds {mine + 1}", _replaced(good, line, f"liveliness held {label} {mine + 1} {theirs}")))
        out.append((f"{label}: the peer holds {theirs + 1}", _replaced(good, line, f"liveliness held {label} {mine} {theirs + 1}")))
    for name, hexed in FRAMES:
        flipped = hexed[:-1] + ("0" if hexed[-1] != "0" else "1")
        line = f"liveliness frame {name} {hexed}"
        out.append((f"the frame {name} with its last digit changed", _replaced(good, line, f"liveliness frame {name} {flipped}")))
        out.append((f"the frame {name} in capitals", _replaced(good, line, f"liveliness frame {name} {hexed.upper()}")))
        out.append((f"the frame {name} cut by one byte", _replaced(good, line, f"liveliness frame {name} {hexed[:-2]}")))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (len(OK_SCENARIOS) + len(FRAMES), len(REFUSED_SCENARIOS)), f"liveliness: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise LivelinessError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except LivelinessError:
            refused += 1
            continue
        raise LivelinessError(f"control: the liveliness judge accepted {label}")
    return refused


def reference_agrees() -> None:
    """The reference matches upstream's bytes, and the exam's names, frames and keys are distinct."""
    zenoh_wire.liveliness_self_test()
    _need(len({name for name, _ in FRAMES}) == len(FRAMES), "a frame name is used twice")
    _need(len({hexed for _, hexed in FRAMES}) == len(FRAMES), "two frames are the same bytes")
    _need(KEY != KEY_SECOND, "a key is used twice")
    _need(len({name for name, _ in REFUSED_SCENARIOS}) == len(REFUSED_SCENARIOS), "a refused scenario name is used twice")


def reference_controls() -> int:
    """Each guard of `reference_agrees`, tripped in turn, and the upstream table corrupted in turn."""
    saved = (FRAMES, KEY_SECOND, REFUSED_SCENARIOS)
    cases = 0
    try:
        for label, change, reason in (
            ("a frame name used twice", {"FRAMES": (FRAMES[0], FRAMES[0], *FRAMES[2:])}, "a frame name is used twice"),
            ("two frames of the same bytes", {"FRAMES": (FRAMES[0], (FRAMES[1][0], FRAMES[0][1]), *FRAMES[2:])}, "two frames are the same bytes"),
            ("a key used twice", {"KEY_SECOND": KEY}, "a key is used twice"),
            ("a refused scenario name used twice", {"REFUSED_SCENARIOS": (REFUSED_SCENARIOS[0], REFUSED_SCENARIOS[0], *REFUSED_SCENARIOS[2:])}, "a refused scenario name is used twice"),
        ):
            globals().update(change)
            try:
                reference_agrees()
            except LivelinessError as error:
                _need(reason in str(error), f"control: {label} was refused for another reason: {error}")
                cases += 1
                continue
            finally:
                globals().update(FRAMES=saved[0], KEY_SECOND=saved[1], REFUSED_SCENARIOS=saved[2])
            raise LivelinessError(f"control: the reference check accepted {label}")
    finally:
        globals().update(FRAMES=saved[0], KEY_SECOND=saved[1], REFUSED_SCENARIOS=saved[2])
    # The reference is judged against upstream's bytes: one digit changed in any of them must be refused.
    upstream = dict(zenoh_wire.UPSTREAM_LIVELINESS)
    try:
        for name, hexed in upstream.items():
            flipped = hexed[:-1] + ("0" if hexed[-1] != "0" else "1")
            zenoh_wire.UPSTREAM_LIVELINESS[name] = flipped
            try:
                zenoh_wire.liveliness_self_test()
            except zenoh_wire.WireError:
                cases += 1
                continue
            finally:
                zenoh_wire.UPSTREAM_LIVELINESS[name] = hexed
            raise LivelinessError(f"control: the reference accepted upstream bytes of {name} with a digit changed")
    finally:
        zenoh_wire.UPSTREAM_LIVELINESS.clear()
        zenoh_wire.UPSTREAM_LIVELINESS.update(upstream)
    return cases


def all_controls() -> int:
    reference_agrees()
    return transcript_controls() + reference_controls()


# The exact counts the exam fixes. The checker compares both with a run.
PINNED_CASES = 38
PINNED_CONTROLS = 131
