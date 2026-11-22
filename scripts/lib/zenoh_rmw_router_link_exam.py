"""Judge a client-role link that subscribes through a router from what the Rust tests print.

`rmw_zenoh_cpp` stamps every Put it publishes, and a router forwards the stamp unchanged. The PUT header carries the
timestamp flag, and a 64-bit time and a 16-byte ID follow it, before the attachment extension. The plain Profile 0
decoder refuses that header, so a link that opened a session with a router would end on the first forwarded sample.
This exam judges the opt-in that changes that: a link with the client role takes the timestamp, and the plain decoder
still refuses it without the role. The graph decoder already takes it, and the fragment decoder refuses it.

The Rust tests under `zenoh_link::router_tests` drive a client-role link against the two captures of
`zenoh_rmw_router_data` through a scripted byte stream, three ways: each batch written whole, every byte read alone,
and every batch written at once. They print one `[zenoh-exam] routerlink ...` line for each thing they did. This
module builds the whole transcript from the captured bytes and `zenoh_wire`, and the Rust must print it, line for line:

* the bytes the link wrote: the client INIT_SYN, the OPEN_SYN that echoes the router's cookie, and the FRAME that
  declares the owner's subscription on the chatter key;
* the four samples the link delivered, with the sequence number and source timestamp of each attachment and its text.
  The Put's own timestamp is checked and not delivered;
* the CLOSE the link wrote when the owner closed it, and that the queue is then empty and the link holds no
  subscription;
* four refusals, each with the class it is refused as.

Like the other judges, this one is trusted only after it refuses a mutation of an honest transcript.
"""

from __future__ import annotations

import re

import zenoh_rmw_router_data as router
import zenoh_wire
from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-router-link.zt"

MODES = ("whole", "bytewise", "coalesced")
LEASE_MS = 10_000
INITIAL_SN = 7
SAMPLES = 4
PUT_WITH_TIMESTAMP = 0xA1
EXT_ATTACHMENT = 0x43
ID_BYTES = 16

REFUSALS = (
    ("default-decoder-takes-a-timestamp", "unsupported-message"),
    ("client-decoder-takes-a-short-id", "malformed-message"),
    ("client-decoder-takes-an-encoding", "unsupported-message"),
    ("client-link-as-a-listener", "invalid-config"),
)


class RouterLinkExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RouterLinkExamError(message)


def hexed(data: bytes) -> str:
    return data.hex() if data else "-"


def framed(batch: bytes) -> bytes:
    return zenoh_wire.stream(batch)


# ----------------------------------------------------------------------------------------------- the capture


def client_syn() -> bytes:
    out = bytearray(zenoh_wire.init(router.CLIENT_ZID, batch=router.CLIENT_BATCH))
    out[2] = (out[2] & ~3) | 2
    return bytes(out)


def init_ack_cookie(ack: bytes) -> bytes:
    at = 3 + (ack[2] >> 4) + 1 + 3
    length = ack[at]
    cookie = ack[at + 1 : at + 1 + length]
    _need(len(cookie) == length and at + 1 + length == len(ack), "an INIT_ACK whose cookie does not end the batch")
    return cookie


def read_wide_leb128(data: bytes, at: int) -> tuple[int, int]:
    """A LEB128 of up to 64 bits, which the Put's timestamp needs and `zenoh_wire.read_leb128` refuses."""
    value = 0
    for count in range(10):
        _need(at < len(data), "a LEB128 that runs off the batch")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << (7 * count)
        if not byte & 0x80:
            _need(count == 0 or byte != 0, "a LEB128 that is not canonical")
            return value, at
    raise RouterLinkExamError("a LEB128 over 64 bits")


def parse_forwarded(batch: bytes) -> dict:
    """One forwarded FRAME: a PUSH of the chatter key, a PUT with the timestamp flag, the Put's timestamp and the
    attachment. Anything else is refused, so the transcript is about what the router wrote."""
    _need(bool(batch) and batch[0] == zenoh_wire.ID_FRAME | zenoh_wire.FLAG_R, "a forwarded batch that is not a reliable FRAME")
    sn, at = zenoh_wire.read_leb128(batch, 1)
    _need(batch[at] == zenoh_wire.ID_PUSH | zenoh_wire.FLAG_N | zenoh_wire.FLAG_M, "a forwarded message that is not a named sender-mapped PUSH")
    at += 1
    scope, at = zenoh_wire.read_leb128(batch, at)
    length, at = zenoh_wire.read_leb128(batch, at)
    _need(scope == 0 and batch[at : at + length].decode() == router.KEY, "a forwarded Put on another key")
    at += length
    _need(batch[at] == PUT_WITH_TIMESTAMP, "a forwarded PUT whose header is not the timestamp form")
    at += 1
    _, at = read_wide_leb128(batch, at)
    _need(batch[at] == ID_BYTES, "a forwarded timestamp whose ID is not 16 bytes")
    at += 1 + ID_BYTES
    _need(batch[at] == EXT_ATTACHMENT, "a forwarded PUT without the attachment extension")
    at += 1
    attachment_length, at = zenoh_wire.read_leb128(batch, at)
    _need(attachment_length == zenoh_wire.ATTACHMENT_BYTES, "a forwarded attachment that is not 33 bytes")
    attachment = batch[at : at + attachment_length]
    at += attachment_length
    size, at = zenoh_wire.read_leb128(batch, at)
    _need(at + size == len(batch), "a forwarded payload that does not end the batch")
    payload = batch[at:]
    _need(payload[:4] == bytes([0, 1, 0, 0]) and int.from_bytes(payload[4:8], "little") == len(payload) - 8, "a forwarded payload that is not a CDR string")
    return {
        "sn": sn,
        "sequence": int.from_bytes(attachment[0:8], "little", signed=True),
        "timestamp": int.from_bytes(attachment[8:16], "little", signed=True),
        "text": payload[8:-1].decode(),
    }


def check_runs() -> None:
    """What the captures say, so the transcript is about the router and not about the exam's own bytes."""
    _need(len(router.RUNS) == 2, f"{len(router.RUNS)} router runs, the item says 2")
    for name, syn, ack, open_ack, forwarded in router.RUNS:
        got = bytes.fromhex(ack)
        _need(bytes.fromhex(syn) == client_syn(), f"{name}: the client INIT_SYN is not the peer form with whatami 2")
        _need(got[2] & 3 == 0, f"{name}: the router did not announce whatami 0")
        _need(len(init_ack_cookie(got)) <= 64, f"{name}: the cookie is over the 64 bytes a session holds")
        _need(len(forwarded) == SAMPLES, f"{name}: {len(forwarded)} forwarded batches, the item says {SAMPLES}")
        done = bytes.fromhex(open_ack)
        _need(done[0] & 0x1F == 0x02 and done[0] & 0x20 != 0, f"{name}: the last handshake batch is not an OPEN_ACK")
        _, at = zenoh_wire.read_leb128(done, 1)
        first_sn, _ = zenoh_wire.read_leb128(done, at)
        parsed = [parse_forwarded(bytes.fromhex(batch)) for batch in forwarded]
        _need([p["sn"] for p in parsed] == [first_sn + n for n in range(SAMPLES)], f"{name}: the frames do not follow the OPEN_ACK's sequence number")
        _need([p["sequence"] for p in parsed] == [router.FIRST_SEQUENCE + n for n in range(SAMPLES)], f"{name}: the samples are not consecutive")
        _need(all(p["text"] == f"Hello World: {p['sequence']}" for p in parsed), f"{name}: a payload is not the talker's string")
    _need(router.RUNS[0][2] != router.RUNS[1][2], "the two runs carry the same cookie")


def open_syn(ack: bytes) -> bytes:
    return zenoh_wire.open_(LEASE_MS, INITIAL_SN, cookie=init_ack_cookie(ack))


def subscriber_frame() -> bytes:
    return zenoh_wire.frame(INITIAL_SN, zenoh_wire.declare_subscriber(router.SUBSCRIPTION_ID, router.KEY, True))


def written(ack_hex: str) -> bytes:
    """Everything the link wrote before it was closed."""
    return framed(client_syn()) + framed(open_syn(bytes.fromhex(ack_hex))) + framed(subscriber_frame())


def samples(forwarded: tuple[str, ...]) -> list[dict]:
    return [parse_forwarded(bytes.fromhex(batch)) for batch in forwarded]


def sample_line(name: str, mode: str, sample: dict) -> str:
    return f"routerlink sample {name} {mode} {router.SUBSCRIPTION_ID} {sample['sequence']} {sample['timestamp']} {sample['text'].replace(' ', '_')}"


# -------------------------------------------------------------------------------------------- the transcript


def good_lines() -> list[str]:
    check_runs()
    lines: list[str] = []
    for name, _syn, ack, open_ack, forwarded in router.RUNS:
        lines.append(f"routerlink fed {name} {ack} {open_ack} {' '.join(forwarded)}")
        for mode in MODES:
            lines.append(f"routerlink sent {name} {mode} {hexed(written(ack))}")
            lines += [sample_line(name, mode, sample) for sample in samples(forwarded)]
            lines.append(f"routerlink pushes {name} {mode} dropped=0")
            lines.append(f"routerlink closed {name} {mode} reason=0 wrote={hexed(framed(zenoh_wire.close(0, True)))} queue=0 subscription=none")
            lines.append(f"routerlink ok {name}-{mode}")
    for refused, cls in REFUSALS:
        lines.append(f"routerlink refused {refused} {cls}")
    return lines


def judge(lines: list[str]) -> tuple[int, int]:
    """The printed transcript must equal the one built here, line for line. Returns (cases, refusals)."""
    wanted = good_lines()
    for line in lines:
        _need(line.startswith("routerlink "), f"routerlink: a record that is not a router link exam line: {line!r}")
        _need(line == line.strip() and "  " not in line, f"routerlink: a line with stray spaces: {line!r}")
    missing = [line for line in wanted if line not in lines]
    extra = [line for line in lines if line not in wanted]
    _need(not missing, f"routerlink lines missing: {[m[:90] for m in missing[:3]]}")
    _need(not extra, f"routerlink lines the exam does not build: {[e[:90] for e in extra[:3]]}")
    _need(len(lines) == len(wanted), f"routerlink: {len(lines)} lines, the exam builds {len(wanted)}; a line is repeated")
    _need(lines == wanted, "routerlink: the lines are not in the order the exam runs them")
    refusals = sum(1 for line in wanted if line.startswith("routerlink refused "))
    return len(wanted) - refusals, refusals


# ------------------------------------------------------------------------------------------------ the controls


def reference_controls() -> int:
    check_runs()
    saved = router.RUNS
    name, syn, ack, open_ack, forwarded = saved[0]

    def mutate(index: int, change) -> tuple:
        batches = list(forwarded)
        batches[index] = change(bytes.fromhex(batches[index])).hex()
        return ((name, syn, ack, open_ack, tuple(batches)), saved[1])

    def at_put(batch: bytes) -> int:
        return batch.index(router.KEY.encode()) + len(router.KEY)

    cases: list[tuple[str, tuple, str]] = [
        ("a client INIT_SYN written as a peer", (((name, zenoh_wire.init(router.CLIENT_ZID, batch=router.CLIENT_BATCH).hex(), ack, open_ack, forwarded)), saved[1]), "peer form with whatami 2"),
        ("a forwarded Put with the peer header", mutate(0, lambda b: b[: at_put(b)] + bytes([0x81]) + b[at_put(b) + 1 :]), "not the timestamp form"),
        ("a forwarded Put with a 15-byte ID", mutate(0, lambda b: b[: at_put(b) + 10] + bytes([15]) + b[at_put(b) + 11 : at_put(b) + 26] + b[at_put(b) + 27 :]), "ID is not 16 bytes"),
        ("a forwarded Put on another key", mutate(0, lambda b: b.replace(b"chatter", b"chatted", 1)), "another key"),
        ("a forwarded frame without the attachment", mutate(0, lambda b: b[: at_put(b) + 27] + bytes([0x44]) + b[at_put(b) + 28 :]), "without the attachment"),
        ("a sample out of sequence", mutate(2, lambda b: b[:-2] + bytes([b[-2] ^ 1]) + b[-1:]), "not the talker's string"),
        ("a frame that skips a sequence number", mutate(1, lambda b: b[:1] + bytes([b[1] ^ 1]) + b[2:]), "do not follow"),
        ("three forwarded batches", ((name, syn, ack, open_ack, forwarded[:3]), saved[1]), "forwarded batches"),
        ("one run only", (saved[0],), "the item says 2"),
        ("the same run twice", (saved[0], (saved[1][0], *saved[0][1:])), "the same cookie"),
    ]
    refused = 0
    try:
        for label, runs, reason in cases:
            router.RUNS = tuple(runs)
            try:
                check_runs()
            except (RouterLinkExamError, IndexError, ValueError, UnicodeDecodeError) as error:
                _need(isinstance(error, RouterLinkExamError) and reason in str(error), f"control: {label} was refused for another reason: {error!r}")
                refused += 1
                continue
            raise RouterLinkExamError(f"control: the reference check accepted {label}")
    finally:
        router.RUNS = saved
    return refused


def transcript_mutations() -> list[tuple[str, list[str]]]:
    good = good_lines()

    def swapped(first: int, second: int) -> list[str]:
        out = list(good)
        out[first], out[second] = out[second], out[first]
        return out

    kinds = {
        kind: [i for i, line in enumerate(good) if line.startswith(f"routerlink {kind} ")]
        for kind in ("fed", "sent", "sample", "pushes", "closed", "ok", "refused")
    }
    out: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a line that is not a router link exam line", [*good, "client opened router-1 state=open"]),
        ("a line repeated", [*good, good[0]]),
        ("a line with a doubled space", [good[1].replace(" ", "  ", 1), *good[:1], *good[2:]]),
        ("a line with trailing space", [good[1] + " ", *good[:1], *good[2:]]),
        ("the first two lines swapped", swapped(0, 1)),
        ("the first and last lines swapped", swapped(0, len(good) - 1)),
        ("two samples swapped", swapped(kinds["sample"][0], kinds["sample"][1])),
        ("two modes of one run swapped", swapped(kinds["sent"][0], kinds["sent"][1])),
        ("the first two refusals swapped", swapped(kinds["refused"][0], kinds["refused"][1])),
        ("a refusal moved ahead of the runs", swapped(kinds["fed"][0], kinds["refused"][0])),
    ]
    for index, line in enumerate(good):
        out.append((f"line {index} missing ({line[:44]})", [*good[:index], *good[index + 1 :]]))
    for kind in ("fed", "sent", "sample", "pushes", "closed"):
        for index in kinds[kind][:8]:
            fields = good[index].split(" ")
            last = fields[-1]
            changed = last[:-1] + ("0" if last[-1] != "0" else "1")
            out.append((f"{kind} line {index} with a changed last field", [*good[:index], " ".join([*fields[:-1], changed]), *good[index + 1 :]]))
    classes = sorted({line.split(" ")[3] for line in good if line.startswith("routerlink refused ")})
    for cls in classes:
        index = next(i for i in kinds["refused"] if good[i].split(" ")[3] == cls)
        other = next(c for c in classes if c != cls)
        out.append((f"the {good[index].split(' ')[2]} refusal reported as {other}", [*good[:index], good[index].replace(f" {cls}", f" {other}", 1), *good[index + 1 :]]))
    out.append(("a sample delivered after the close", [*good, "routerlink sample router-data-1 whole 1 7 1 Hello_World:_7"]))
    out.append(("a sample queue left full after the close", [good[i].replace("queue=0", "queue=4", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a subscription kept after the close", [good[i].replace("subscription=none", "subscription=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a local close that wrote nothing", [good[i].replace("wrote=02002300", "wrote=-", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("a subscription declared on another key", [good[i].replace(router.KEY.encode().hex()[:40], "00" * 20, 1) if i == kinds["sent"][0] else good[i] for i in range(len(good))]))
    out.append(("a close with another reason", [good[i].replace("reason=0", "reason=1", 1) if i == kinds["closed"][0] else good[i] for i in range(len(good))]))
    out.append(("the Put's own timestamp delivered as the sample's", [good[i].replace(str(samples(router.RUNS[0][4])[0]["timestamp"]), "7710881841417541488", 1) if i == kinds["sample"][0] else good[i] for i in range(len(good))]))
    return out


def transcript_controls() -> int:
    good = good_lines()
    cases, refusals = judge(good)
    _need((cases, refusals) == (PINNED_CASES - PINNED_REFUSALS, PINNED_REFUSALS), f"routerlink: the honest transcript is {cases} cases and {refusals} refusals")
    refused = 0
    for label, lines in transcript_mutations():
        if lines == good:
            raise RouterLinkExamError(f"control: {label} did not change the transcript")
        try:
            judge(lines)
        except RouterLinkExamError:
            refused += 1
            continue
        raise RouterLinkExamError(f"control: the router link judge accepted {label}")
    return refused


def all_controls() -> int:
    return transcript_controls() + reference_controls()


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 54
PINNED_REFUSALS = len(REFUSALS)
PINNED_CONTROLS = 113


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
