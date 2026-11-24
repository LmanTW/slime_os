"""Judge the Zenoh Profile 0 exam for a client-role session that answers a token INTEREST, and a listener that admits clients.

A router asks a client for the liveliness tokens it holds with an INTEREST. A client-role session declares and
withdraws tokens (`send_declare_token`, `send_undeclare_token`, landed by zenoh-rmw-token) and refuses that
INTEREST as an unsupported message. This exam judges the answer: one frame holding a DECLARE_TOKEN for each token
the session holds whose key the INTEREST selects, each carrying the interest id, then the DeclareFinal for that id.
An INTEREST selects every key, or the keys under one `<prefix>/**`. It also judges a listener that takes a Client
INIT_SYN only when it is configured to, and the INIT_ACK it answers with.

The Rust tests under `zenoh_liveliness::` print one `[zenoh-exam] liveliness ...` line for each thing they did.
This module owns what those lines must be, and nothing here reads the Rust:

* the scenarios, each printed once and in order;
* the answer frames the session wrote, which `zenoh_wire` must reproduce byte for byte. The reference is held to
  bytes the upstream eclipse-zenoh 1.0.0 encoder produced before it judges anything
  (`zenoh_wire.liveliness_self_test`);
* how many tokens the session held after a step;
* every refusal, by name and class.

Like the other judges it is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_wire

# The sequence number of the first FRAME the answering side sends: the Rust tests configure it with this number.
ANSWERER_SN = 7000
ZID = bytes.fromhex("11223344")
KEY = zenoh_wire.KEY_LIVELINESS
KEY_SECOND = "@/liveliness/slime/second"

OK_SCENARIOS = (
    "current-interest-answers-each-token-then-final",
    "current-future-interest-answers-like-current",
    "future-interest-answers-nothing",
    "final-interest-answers-nothing",
    "no-token-answers-final-alone",
    "withdrawn-token-is-not-answered",
    "restricted-interest-answers-the-tokens-under-its-key",
    "interest-with-the-qos-extension-is-answered",
    "refused-answer-spends-no-sequence-number",
    "listener-admits-a-client-when-configured",
    "default-configuration-unchanged",
)

# The keys the answer frames carry. A restricted INTEREST names the prefix `KEY_ROS`, so the node token under it is
# answered and the token under `KEY_OTHER` is not.
KEY_UNDER = f"{zenoh_wire.KEY_ROS}/slime_node"
KEY_OTHER = "@/liveliness/slime/elsewhere"

# (name, bytes the session wrote). Each frame is written by a session built for its scenario with initial number
# ANSWERER_SN, so its sequence number is ANSWERER_SN plus the frames that session sent before it. A token enters the
# table only through `send_declare_token`, which sends a frame, so each declaration and each withdrawal counts.
FRAMES = (
    (
        "answer-current-interest-7",
        zenoh_wire.frame(
            ANSWERER_SN + 2,  # after the declarations of tokens 1 and 2
            zenoh_wire.declare_token(1, KEY, True, 7),
            zenoh_wire.declare_token(2, KEY_SECOND, True, 7),
            zenoh_wire.declare_final(7),
        ).hex(),
    ),
    (
        "answer-current-future-interest-8",
        zenoh_wire.frame(
            ANSWERER_SN + 2,  # after the declarations of tokens 1 and 2
            zenoh_wire.declare_token(1, KEY, True, 8),
            zenoh_wire.declare_token(2, KEY_SECOND, True, 8),
            zenoh_wire.declare_final(8),
        ).hex(),
    ),
    ("answer-empty-interest-9", zenoh_wire.frame(ANSWERER_SN, zenoh_wire.declare_final(9)).hex()),
    (
        "answer-restricted-interest-11",
        zenoh_wire.frame(
            ANSWERER_SN + 2,  # after the declarations of tokens 1 and 2
            zenoh_wire.declare_token(1, KEY_UNDER, True, 11),
            zenoh_wire.declare_final(11),
        ).hex(),
    ),
    (
        "answer-interest-with-qos-12",
        zenoh_wire.frame(
            ANSWERER_SN + 1,  # after the declaration of token 1
            zenoh_wire.declare_token(1, KEY_UNDER, True, 12),
            zenoh_wire.declare_final(12),
        ).hex(),
    ),
    (
        "next-frame-after-refused-answer",
        # after the declaration of token 1; the refused answer spent no number, so the withdrawal takes the next one
        zenoh_wire.frame(ANSWERER_SN + 1, zenoh_wire.undeclare_token_by_id(1)).hex(),
    ),
    ("init-ack-to-a-client", zenoh_wire.init(bytes([0xB2] * 8), 512, bytes([0xC0] * 32)).hex()),
    (
        "answer-after-withdrawal-interest-10",
        zenoh_wire.frame(
            ANSWERER_SN + 3,  # after the declarations of tokens 1 and 2 and the withdrawal of token 1
            zenoh_wire.declare_token(2, KEY_SECOND, True, 10),
            zenoh_wire.declare_final(10),
        ).hex(),
    ),
)

# (label, tokens the answering session holds) after a step.
HELD = (
    ("answered-two", 2),
    ("after-withdrawal", 1),
    ("refused-answer", 1),
    ("after-restricted-answer", 2),
)

REFUSED_SCENARIOS = (
    ("interest-in-subscribers", "unsupported-message"),
    ("interest-in-queryables", "unsupported-message"),
    ("interest-in-key-expressions", "unsupported-message"),
    ("interest-restricted-to-a-key-without-a-wildcard-suffix", "unsupported-message"),
    ("interest-restricted-with-a-wildcard-inside-the-key", "unsupported-message"),
    ("interest-restricted-and-in-key-expressions-only", "unsupported-message"),
    ("interest-in-key-expressions-and-tokens-unrestricted", "unsupported-message"),
    ("interest-in-tokens-and-subscribers", "unsupported-message"),
    ("interest-with-an-unknown-extension", "unsupported-extension"),
    ("interest-to-a-session-with-no-client-role", "unsupported-message"),
    ("two-interests-in-one-frame", "too-many-messages"),
    ("answer-beyond-the-peer-batch", "encode"),
    ("client-init-to-a-listener-that-admits-none", "unsupported-whatami"),
    ("router-init-to-a-listener", "unsupported-whatami"),
    ("reserved-role-init", "malformed-message"),
)

SHAPES = {
    ("liveliness", "ok"): 3,
    ("liveliness", "frame"): 4,
    ("liveliness", "held"): 4,
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
        + [f"liveliness held {label} {count}" for label, count in HELD]
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

    held = [(f[2], f[3]) for f in split if f[:2] == ["liveliness", "held"]]
    _exactly("counts", tuple(label for label, _ in HELD), [label for label, _ in held])
    _need([label for label, _ in held] == [label for label, _ in HELD], "liveliness counts are out of order")
    for (label, count), (_, wanted) in zip(held, HELD, strict=True):
        _need(count == str(wanted), f"liveliness held {label}: {count}, the exam requires {wanted}")

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
    for label, count in HELD:
        line = f"liveliness held {label} {count}"
        out.append((f"{label}: the session holds {count + 1}", _replaced(good, line, f"liveliness held {label} {count + 1}")))
        out.append((f"{label}: the session holds {count - 1}", _replaced(good, line, f"liveliness held {label} {count - 1}")))
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
PINNED_CASES = 34
PINNED_CONTROLS = 128
