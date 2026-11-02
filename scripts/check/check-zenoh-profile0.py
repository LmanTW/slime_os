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

`--slice xcheck` runs `verification/zenoh-xcheck`, which drives this repository's codec
and session against the real eclipse-zenoh 1.0.0 crates (`zenoh-codec`,
`zenoh-protocol`, `zenoh-buffers`), and judges the `[zenoh-xcheck] ...` lines it
prints. The expectation is pinned here, never read from the harness: the 17 corpus
batches as upstream's own encoder now produces them, a 6000-case sweep in which
our encoder equals upstream's byte for byte (5993 compared, 7 refused as a
non-canonical Zenoh ID), our decoder accepts what upstream encodes, upstream reads
and re-encodes ours, an 11-batch session read back identically, and eight Zenoh ID
probes whose outcome this file derives from the byte pattern. It needs the crates
from a registry, so it is explicit and not in CI.

The harness prints one `[zenoh-xcheck] <word> ...` line per result:

  corpus <name> <hex>                              upstream's encoding of a corpus batch
  encoder cases=N compared=N differ=N refused=N    sweep, our encoder against upstream's
  refusal <reason> <count>                         why the sweep's refused cases were refused
  decoder cases=N differ=N                         our decoder against upstream's bytes
  reader compared=N differ=N                       upstream reading and re-encoding ours
  session batches=N checked=N differ=N             one session, every batch read back
  zid <hex> upstream=<v> encode=<v> wire-upstream=<v> wire-ours=<v>
                                                   one Zenoh ID probe, in both directions

`--slice stock` judges this repository's session against batches a stock eclipse-zenoh 1.0.0
peer put on a TCP link (`scripts/lib/zenoh_stock_peer.py`, captured once from the Python
wheel, with its hash and the way each batch was obtained). A Rust test module,
`zenoh_stock::`, replays every captured batch into the session, prints one
`[zenoh-exam] stock ...` line per scenario, and the checker owns the expectation:

  stock ok <scenario>                     a stock-peer interaction the session completed
  stock replay <fixture> ok               a captured batch the session took
  stock refused <name> <class>            a captured or constructed batch refused, with its class
  stock delivered <sequence> <hex> <ts>   a sample the subscriber side delivered: its payload from the demo
                                          contract, its timestamp from the captured attachment
  stock attachment <seq>:<ts> <gid-hex>   the attachment the decoder read from a captured push; the session
                                          event carries no GID, so the exam reads it from the decoded push
  stock property <fixture> ok             the decoder's properties held on a captured batch: no proper prefix is
                                          accepted unless it is a shorter frame, a flipped bit never panics or
                                          exceeds a bound, and every two-chunk split of the framed batch
                                          reassembles to it. One line per captured batch, in capture order

It also pins the captured pushes to the demo contract's four samples and attachments, so a
fixture cannot drift from the topic the demo exchanges. The recipe fails until the session
accepts a stock peer; nothing here claims `rmw_zenoh` interoperability or liveliness.

`--slice links` judges the link-limits and fragmentation change: the three configurations a link is
declared with (`demo`, `large`, `heap`), pinned and validated through `contracts/zenoh-link-limits/v1`;
the fragments a stock peer put on the wire for one large Put, reproduced byte for byte by the host
reference `scripts/lib/zenoh_fragment.py`; our own Put fragmented the same way; the edge between a
message that travels whole and one that is fragmented; and the refusals. The retained decoder, session,
encoder and link suites and the stock-peer tests are run and required by name beside it, so the
fixed decoder keeps refusing a fragment and the pinned corpus does not move.

`--slice undeclare` judges the one thing the stock-peer exam did not capture: a stock peer ending its
subscription with an UndeclareSubscriber that names the subscriber by id alone, inside a DECLARE that
carries the network QoS extension. It replays the eight batches that peer sent, in order, into a
connector session; checks that the host reference reproduces the undeclaration byte for byte; and
requires the ten variants of it the profile keeps refusing, by name and class. The stock corpus
judge, the retained suites and the stock-peer exam are run beside it, so accepting the bare form
cannot move a pinned refusal or a stock case.

`--slice subscribers` judges a session that holds several subscriptions of its own. The session held
exactly one, whatever the link was declared with; it now holds as many as its parameters say. The exam
declares three, delivers to each key, undeclares one and keeps the others, reuses the freed slot,
delivers once for two subscriptions on one key, and releases all on close. It refuses a fourth, a
repeated id, an undeclaration of an id or key not held, a Put to a key not declared, a peer past its
own limit and three configurations whose slots do not add up; and the demo's parameters still hold
one. The links exam and the stock-peer exam run beside it, since both pin the subscriber limit.

`--slice composition` judges the derived `sel4-zenoh` composition against the
demo contract's authority and refuses 15 mutations of an honest one. It is the
static half of the QEMU arm; the boot is `check-sel4-io-network-plane.py --arm zenoh`.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import hashlib
import os as _os
import re
import shutil
import struct
import subprocess
import tempfile
from collections.abc import Callable
from typing import NoReturn

import devloop_observations
import zenoh_exchange
import zenoh_links_exam
import zenoh_grants_exam
import zenoh_client_exam
import zenoh_client_abort_exam
import zenoh_client_io_exam
import zenoh_client_wire_exam
import zenoh_grants_reader_exam
import zenoh_server_exam
import zenoh_service_arm
import zenoh_service_component_exam
import zenoh_grants_table_exam
import zenoh_service_exam
import zenoh_service_link_exam
import zenoh_stock_peer
import zenoh_subscribers_exam
import zenoh_undeclare_exam
import zenoh_wire
import zutai_cli
from harness import GENERATION_COMPOSITIONS, ROOT

CORPUS = ROOT / "components" / "lib" / "src" / "zenoh_profile0" / "vectors.txt"
COMPOSITION = GENERATION_COMPOSITIONS / "sel4-zenoh.zti"
EXAM_LINE = re.compile(r"\[zenoh-exam\] (.*)$")

STOCK_FIXTURES = ROOT / "build" / "zenoh-stock" / "fixtures.zti"
ZENOH_DECODER = ROOT / "build" / "zenoh-stock" / "decode-fixtures.zt"
STOCK_FILTER = "zenoh_stock::"
# The decoder is held to the pinned corpus by running it: the digests above prove the corpus text is
# unchanged, and this test proves the decoder still gives every pinned row its pinned verdict.
STOCK_CORPUS_TEST = "zenoh_profile0::tests::corpus_agrees"
# The decoder's properties beside it: no prefix of an accepted batch is mistaken for a whole one,
# a flipped byte never panics or exceeds the bounds, every two-chunk split reassembles, and the
# framer holds exactly a maximum batch. They run over inputs the pinned rows do not list, so they
# catch a QoS or alias change that the corpus text cannot.
STOCK_DECODER_FILTER = "zenoh_profile0::tests"
STOCK_DECODER_TESTS = tuple(f"zenoh_profile0::tests::{name}" for name in (
    "a_refusal_does_not_poison_the_next_decode",
    "bounds_equal_the_frozen_demo_contract",
    "byte_flips_never_panic_and_stay_bounded",
    "corpus_agrees",
    "decoded_values_borrow_from_the_batch",
    "every_prefix_of_every_accepted_batch_is_refused_or_a_shorter_frame",
    "every_refusal_class_is_drawn",
    "every_two_chunk_split_reassembles",
    "framer_holds_a_maximum_batch_and_refuses_the_next_byte_of_overflow",
    "framer_refuses_a_bad_prefix_before_the_body_arrives",
    "refusal_codes_and_names_round_trip",
))
# The session refusals and behaviours the item keeps ("every unnamed refusal"): none of them is a
# stock scenario, so a filter on zenoh_stock:: would not run them. The alias and keep-alive change
# edits the session, so each is run and required by name. Two of them assert the current lease
# behaviour (no keep-alive); the implementation updates those two knowingly, in its own diff, and
# the gate still requires them to pass afterwards.
STOCK_SESSION_FILTER = "zenoh_profile0::session::tests"
# The encoder and link suites: key, payload, cookie and batch bounds, and the link's refusals
# (send after close, stale handles, a full receive queue) and its stream handling. A keep-alive and
# alias change edits the link and the session, so these are run and required by name too.
STOCK_ENCODE_FILTER = "zenoh_profile0::encode::tests"
STOCK_LINK_FILTER = "zenoh_link::tests"
STOCK_ENCODE_TESTS = tuple(f"zenoh_profile0::encode::tests::{name}" for name in (
    "corpus_has_seventeen_accepted_batches",
    "encoded_batches_decode_to_the_corpus_summary",
    "encoder_refuses_what_the_profile_forbids",
    "encoder_reproduces_every_upstream_batch",
    "failed_message_leaves_the_frame_unchanged",
    "small_storage_is_refused_not_truncated",
    "stream_framer_reads_back_what_the_encoder_wrote",
    "stream_prefix_is_two_little_endian_bytes",
    "values_the_decoder_refuses_are_not_encoded",
))
STOCK_LINK_TESTS = tuple(f"zenoh_link::tests::{name}" for name in (
    "backpressure_resumes",
    "close_with_a_frame_pending_is_refused_and_leaves_the_link_open",
    "connector_opens_and_publishes",
    "end_of_stream_before_the_handshake_ends_the_link",
    "end_of_stream_does_not_discard_a_batch_already_received",
    "listener_accepts_and_delivers",
    "peer_close_ends_session",
    "receiving_close_closes_the_link_and_stops_reading",
    "refusals",
    "restart_uses_fresh_session",
    "split_and_coalesced_batches",
    "taps_hold_the_exact_batches_exchanged",
    "the_received_tap_names_the_batch_behind_each_notice",
))
STOCK_SESSION_TESTS = tuple(f"zenoh_profile0::session::tests::{name}" for name in (
    "a_quiet_link_closes_at_the_lease_and_traffic_renews_it",
    "a_refused_tick_does_not_advance_the_clock",
    "a_tiny_own_lease_still_spaces_keep_alives",
    "connect_handshake",
    "declare_then_push_delivered",
    "frames_the_session_sends_use_the_sender_key_mapping",
    "keep_alives_follow_the_lease_this_side_announced",
    "lease_expiry_closes",
    "listen_handshake",
    "refuses_cookie_mismatch",
    "refuses_frame_before_open",
    "refuses_push_to_undeclared_key",
    "refuses_replayed_sequence",
    "refuses_router_peer",
    "refuses_version_mismatch",
    "refuses_wildcard_key_declaration",
    "teardown_undeclare_then_close",
))
# Everything run by the second invocation, in the order the gate reports a missing one.
STOCK_RETAINED_TESTS = (*STOCK_DECODER_TESTS, *STOCK_SESSION_TESTS, *STOCK_ENCODE_TESTS, *STOCK_LINK_TESTS)
# The refused vectors in components/lib/src/zenoh_profile0/vectors.txt that the stock-peer change
# may turn from refused to accepted: only those whose bytes a captured stock batch repeats exactly.
# The KEEP_ALIVE vector is the single byte 0x04, and the stock peer sent that byte four times.
# Every other refused vector stays refused, including the ones whose names sound related (an
# extension flag, an alias, a scope, a suffix, an OAM): each was compared byte for byte against the
# capture and none matches, because the stock peer attaches a QoS extension and a body those
# vectors do not have. An implementation accepts the shapes the capture shows, and the 19 replays
# below prove it does.
STOCK_MAY_CHANGE = frozenset({"transport_keep_alive", "transport_fragment"})
# transport_fragment is the single reliable final fragment `2601aa`. Once the decoder reads a
# FRAGMENT message it is a valid one, so the row cannot stay refused; it cannot become an accepted
# row either, for the reason the keep-alive row cannot. The link-limits change removes it
# (`--slice links` requires fragments to be taken, and the stock slice allows the row to go).
STOCK_MAY_CHANGE_BYTES = {"transport_keep_alive": "04", "transport_fragment": "2601aa"}
# The class it is refused with today. While the row stays it keeps its class too: the retained
# corpus test agrees with whatever the row says, so a class changed in the row and the decoder
# together would otherwise pass.
STOCK_MAY_CHANGE_CLASS = {"transport_keep_alive": "unsupported-message", "transport_fragment": "unsupported-message"}
# The refused vectors that must stay exactly as they were when the exam landed, by name, with a
# digest of `<name> <class> <bytes>` for each in name order. The checker reads the working tree's
# corpus and compares; a refused vector may be added, and transport_keep_alive may go, but none of
# these may move and no accepted row may be added.
STOCK_CORPUS = ROOT / "components" / "lib" / "src" / "zenoh_profile0" / "vectors.txt"
STOCK_FIXED_NAMES = tuple((
    "batch_513_bytes close_extension_present close_reason_unknown close_reserved_flag "
    "close_trailing_byte close_truncated declare_extension_flag declare_interest_flag "
    "declare_keyexpr_alias declare_queryable declare_reserved_flag declare_token "
    "declare_truncated_kind dsub_double_slash dsub_empty_suffix dsub_extension_flag "
    "dsub_id_overflow dsub_invalid_utf8 dsub_key_130_bytes dsub_leading_slash dsub_no_suffix "
    "dsub_nonzero_scope dsub_truncated_suffix dsub_wildcard_double_star dsub_wildcard_star "
    "dsub_wildcard_sub empty_batch frame_best_effort frame_empty frame_extension_present "
    "frame_network_interest frame_network_oam frame_network_request frame_network_response "
    "frame_partial_network_message frame_reserved_flag frame_sn_missing frame_sn_overflow "
    "init_ack_cookie_65_bytes init_ack_cookie_empty init_ack_cookie_len_noncanonical "
    "init_ack_cookie_len_over_u16 init_ack_cookie_len_u16_max init_ack_cookie_truncated "
    "init_ack_zid_trailing_zero init_batch_size_zero init_extension_present "
    "init_reserved_packed_bits init_resolution_64bit init_trailing_byte "
    "init_truncated_after_version init_truncated_zid init_version_8 init_whatami_client "
    "init_whatami_router init_zid_all_zero init_zid_one_byte_zero init_zid_trailing_zero "
    "open_ack_extension_present open_ack_truncated open_syn_cookie_65_bytes "
    "open_syn_cookie_empty open_syn_cookie_truncated open_syn_lease_over_32_bits "
    "open_syn_lease_zero open_syn_sn_overflow push_del_body push_extension_flag "
    "push_key_130_bytes push_no_suffix push_nonzero_scope "
    "push_put_no_attachment_upstream_valid push_truncated_body push_wildcard_key "
    "put_attachment_32_bytes put_attachment_34_bytes put_attachment_gid_len_15 "
    "put_attachment_truncated put_encoding_flag put_extension_chained put_payload_13_bytes "
    "put_payload_len_noncanonical put_payload_len_overflow put_payload_truncated "
    "put_timestamp_flag put_unknown_extension transport_join transport_oam "
    "transport_unknown_id usub_ext_chained usub_ext_not_mandatory usub_flags_reserved_bits "
    "usub_missing_wire_expr_ext usub_no_suffix usub_nonzero_scope usub_reserved_header_bit "
    "usub_wildcard usub_wrong_ext_id usub_zbuf_length_132 usub_zbuf_truncated"
).split())
STOCK_FIXED_DIGEST = "4422567dd0966737e41d7e7fb79f0bd66c1fa4c15744ceff4942b36fdaf54987"
# The accepted batches are the upstream encoder's output and are pinned by name, bytes and
# summary: replacing one, dropping one or renaming a copy all change the digest.
STOCK_ACCEPTED_NAMES = tuple((
    "close_link_invalid close_session_generic close_session_unsupported "
    "frame_declare_and_push_coalesced_sn2 frame_declare_recv_mapping_id300_sn4294967295 "
    "frame_declare_subscriber_sn0 frame_push_put_sn1 frame_undeclare_subscriber_sn7 "
    "init_ack_batch512_cookie3 init_ack_default_zid1_cookie1 init_syn_batch512 "
    "init_syn_default init_syn_default_zid16 open_ack_lease2s_sn9 "
    "open_syn_lease1500ms_sn300_cookie1 open_syn_lease2s_sn5_cookie3 "
    "open_syn_lease60s_snmax_cookie16"
).split())
STOCK_ACCEPTED_DIGEST = "1260d9d725d5fb2055d1ffb2be8f4e33f73e029f950901389c6ca586b350f7ef"
# The stream-framing rows (ten accepted, four refused) carry the 512-byte stream bound and the
# reassembly rules. None of them is something a stock peer sent, so none may change: each is pinned
# by name and by a digest of everything after its kind, which covers its verdict, class, chunks
# and summary.
STOCK_STREAM_NAMES = tuple((
    "stream_batch_split_mid_body stream_byte_at_a_time stream_complete_then_partial "
    "stream_empty_chunks_interleaved stream_incomplete_body_pending "
    "stream_incomplete_prefix_pending stream_length_513 stream_length_65535 "
    "stream_length_zero stream_max_batch_512 stream_prefix_split_across_chunks "
    "stream_refusal_after_valid_batch stream_single_batch stream_two_batches_one_chunk"
).split())
STOCK_STREAM_DIGEST = "e25ae97153255e290cab357f9a5b97bbb862a40a7caf8ffec63ac784663ca070"
STOCK_PUSHES = tuple(f"connects/connects-{n:02d}-push-{n - 4}" for n in (5, 6, 7, 8))

XCHECK_CRATE = ROOT / "verification" / "zenoh-xcheck"
XCHECK_LINE = re.compile(r"\[zenoh-xcheck\] (.*)$")
XCHECK_SWEEP = 6000
XCHECK_REFUSED = 7
XCHECK_SESSION_BATCHES = 11
XCHECK_SESSION_CHECKED = 27
# Zenoh IDs: upstream holds one as a little-endian integer, so it refuses zero and
# drops trailing zero bytes; Profile 0 refuses a trailing zero byte so that every
# ID it accepts round-trips.
XCHECK_ZIDS = (
    "0000000000000000",
    "00",
    "0102030405060700",
    "0102030405000000",
    "0002030405060708",
    "0102000405060708",
    "a1a1a1a1a1a1a1a1",
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
)

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


# The four slices judged by `run_tests` keep every marker, so a bare `[zenoh-exam]`, or one with text glued to it,
# reaches the judge as a line it does not recognise. `exam_lines` drops those, and the other slices still use it.
EXAM_MARKER = re.compile(r"\[zenoh-exam\](.*)$")


def exam_lines_strict(output: str) -> list[str]:
    """Every marker line, with the marker kept in front of any text that is not set off by a space.

    A marker followed by a space gives its text. A bare marker, or text glued to it or set off by another
    character, gives a line that starts with the marker, which no judge recognises, so the delimiter is enforced
    and a payload glued to the marker cannot pass as a valid line.
    """
    lines = []
    for line in output.splitlines():
        if (match := EXAM_MARKER.search(line)) is None:
            continue
        text = match.group(1)
        lines.append(text.strip() if text.startswith(" ") else "[zenoh-exam]" + text)
    return lines


# The shape of every line a Rust slice may print, by its word: the verdict and the number of fields that
# verdict carries, the word included. The encoder and the session slice share one cargo filter, so a run
# of either prints the lines of both words.
LINE_SHAPES: dict[str, dict[str, int]] = {
    "encode": {"ok": 4, "refused": 3},
    "session": {"ok": 3, "refused": 3},
    "cdr": {"ok": 5, "refused": 3},
    "link": {"ok": 3, "refused": 3},
}
RUN_WORDS: dict[str, tuple[str, ...]] = {
    "encoder": ("encode", "session"),
    "session": ("encode", "session"),
    "cdr": ("cdr",),
    "transport": ("link",),
}


def known_names(word: str, verdict: str) -> set[str]:
    """The names an honest run may print for a word and verdict. A `cdr ok` row is judged by its own judge."""
    if word == "encode":
        return {name for name, _hexed, _ in reference()} if verdict == "ok" else set(ENCODE_REFUSALS)
    if word == "session":
        return set(SESSION_SCENARIOS) if verdict == "ok" else set(SESSION_REFUSALS)
    if word == "link":
        return set(LINK_SCENARIOS) if verdict == "ok" else set(LINK_REFUSALS)
    return set(CDR_REFUSALS) if verdict == "refused" else set()


def require_consumed(slice_name: str, lines: list[str]) -> None:
    """Refuse any exam line that no judge of this run reads, so an invented or malformed line cannot pass.

    The encoder and session slices share one cargo filter, so each run prints the lines of both words and only one
    judge reads each word. A line of the other word is checked here against the names that word may print. A
    repeated line is refused for every word.
    """
    allowed = RUN_WORDS[slice_name]
    repeated = sorted({line for line in lines if lines.count(line) > 1})
    if repeated:
        fail(f"{slice_name}: exam line repeated: {repeated[0]!r}")
    for line in lines:
        fields = line.split()
        shape = LINE_SHAPES[fields[0]] if fields and fields[0] in allowed else {}
        if len(fields) < 2 or shape.get(fields[1]) != len(fields):
            fail(f"{slice_name}: unrecognised exam line {line!r}")
        if fields[0] != "cdr" or fields[1] == "refused":
            if fields[2] not in known_names(fields[0], fields[1]):
                fail(f"{slice_name}: exam line {line!r} names something no honest run prints")


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
    """The encoder's cases and refusals. The shared cargo filter also prints the session rows, which are judged too."""
    require_consumed("encoder", lines)
    result = encode_rows(lines)
    named_rows("session")(lines)
    return result


def encode_rows(lines: list[str]) -> tuple[int, int]:
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


def named_rows(slice_name: str) -> Callable[[list[str]], tuple[int, int]]:
    _, scenarios, refusals, word = RUST[slice_name]

    def rows(lines: list[str]) -> tuple[int, int]:
        done = names(lines, word, "ok")
        refused = names(lines, word, "refused")
        exactly(f"{slice_name} scenarios", scenarios, done)
        exactly(f"{slice_name} refusals", refusals, refused)
        return len(done), len(refused)

    return rows


def judge_named(slice_name: str) -> Callable[[list[str]], tuple[int, int]]:
    rows = named_rows(slice_name)

    def judge(lines: list[str]) -> tuple[int, int]:
        require_consumed(slice_name, lines)
        result = rows(lines)
        if slice_name == "session":
            # The shared cargo filter also prints the encoder rows, so their bytes are judged in this run too.
            encode_rows(lines)
        return result

    return judge


def judge_cdr(lines: list[str]) -> tuple[int, int]:
    require_consumed("cdr", lines)
    wanted = demo_samples()
    produced: dict[int, tuple[int, str]] = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 5 and fields[:2] == ["cdr", "ok"]:
            if not (fields[2].isdigit() and fields[3].isdigit()):
                fail(f"CDR sample row {line!r} does not carry a numeric sequence and value")
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
    if slice_name in ("encoder", "session"):
        # One cargo filter serves both slices, so a real run of either prints the rows of both words.
        encode = [f"encode ok {n} {h}" for n, h, _ in reference()] + [f"encode refused {c}" for c in ENCODE_REFUSALS]
        session = [f"session ok {s}" for s in SESSION_SCENARIOS] + [f"session refused {c}" for c in SESSION_REFUSALS]
        return encode + session
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
        ("an unrecognised line", good + ["invented line"]),
        ("a line of an unknown word", good + ["bogus ok invented"]),
        ("a known word with an unknown verdict", good + [f"{word} bogus invented"]),
        ("a known word and verdict with an unknown field count", good + [f"{word} refused invented extra"]),
        ("an ok line with too few fields", good + [f"{word} ok"]),
        ("an ok line with too many fields", good + [f"{word} ok invented a b c d"]),
        ("a refused line that names no honest control", good + [f"{word} refused invented"]),
    ]
    # These go through the serialized stdout and `exam_lines_strict`, the path a real run takes, so a marker that
    # carries no text, or text glued to it, reaches the judge instead of being dropped on the way.
    stdout = "".join(f"[zenoh-exam] {line}\n" for line in good)
    for label, tail in (
        ("a bare exam marker", "[zenoh-exam]\n"),
        ("an exam marker followed only by spaces", "[zenoh-exam]   \n"),
        ("an exam marker with text glued to it", "[zenoh-exam]invented\n"),
    ):
        mutations.append((label, exam_lines_strict(stdout + tail)))
    # A valid payload with the delimiter removed or replaced must fail too, not only an unknown word glued on.
    mutations.append(("every marker glued to its payload", exam_lines_strict("".join(f"[zenoh-exam]{line}\n" for line in good))))
    mutations.append(("one marker glued to its payload", exam_lines_strict(f"[zenoh-exam]{good[0]}\n" + "".join(f"[zenoh-exam] {line}\n" for line in good[1:]))))
    mutations.append(("a tab after the marker", exam_lines_strict("".join(f"[zenoh-exam]\t{line}\n" for line in good))))
    if slice_name in ("encoder", "session"):
        # The two slices share one cargo filter, so a real run prints the other word's lines too.
        other, honest = ("session", f"session ok {SESSION_SCENARIOS[0]}") if word == "encode" else ("encode", f"encode refused {ENCODE_REFUSALS[0]}")
        mutations.append(("a line of the shared word that names nothing honest", good + [f"{other} refused invented"]))
        mutations.append(("a repeated line of the shared word", good + [honest, honest]))
        # Both runs judge the bytes of the encode rows and the names of the session rows, whichever slice was asked for.
        encode_at = [i for i, line in enumerate(good) if line.startswith("encode ok ")]
        first, second = (good[i].split() for i in encode_at[:2])
        swapped = list(good)
        swapped[encode_at[0]] = " ".join([*first[:3], second[3]])
        swapped[encode_at[1]] = " ".join([*second[:3], first[3]])
        mutations.append(("two encode batches with their bytes swapped", swapped))
        mutations.append(("an encode batch reported again with wrong bytes", good + [f"encode ok {first[2]} 00"]))
        mutations.append(("an encode batch no honest run prints", good + ["encode ok invented-batch 00"]))
        mutations.append(("a session scenario reported again", good + [f"session ok {SESSION_SCENARIOS[1]}"]))
        mutations.append(("every encode row removed", [line for line in good if not line.startswith("encode ")]))
        mutations.append(("every session row removed", [line for line in good if not line.startswith("session ")]))
    if slice_name == "cdr":
        mutations.append(("a sample with a non-numeric sequence and value", good + ["cdr ok bogus bogus 00"]))
        mutations.append(("a sample with a non-numeric value", good + ["cdr ok 1 bogus 00"]))
        mutations.append(("a sample with a non-numeric sequence", good + ["cdr ok bogus 5 00"]))
    if slice_name in ("encoder", "session", "cdr"):
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
    return exam_lines_strict(result.stdout)


def keyed(lines: list[str], word: str) -> dict[str, str]:
    """The `key=value` fields of the one `[zenoh-xcheck] <word> ...` line."""
    found = [line.split()[1:] for line in lines if line.split()[:1] == [word]]
    if len(found) != 1:
        fail(f"xcheck: {len(found)} {word!r} lines, expected exactly one")
    pairs = [field.partition("=") for field in found[0]]
    if any(not sep for _, sep, _ in pairs):
        fail(f"xcheck: malformed {word!r} line: {' '.join(found[0])}")
    return {key: value for key, _, value in pairs}


def expect(word: str, actual: dict[str, str], wanted: dict[str, int]) -> None:
    if set(actual) != set(wanted):
        fail(f"xcheck {word}: fields {sorted(actual)}, expected {sorted(wanted)}")
    for key, value in wanted.items():
        if actual[key] != str(value):
            fail(f"xcheck {word}: {key}={actual[key]}, expected {value}")


def judge_xcheck(lines: list[str]) -> tuple[int, int]:
    golden = {name: hexed for name, hexed, _ in reference()}
    corpus: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 3 and fields[0] == "corpus":
            if fields[1] in corpus:
                fail(f"xcheck: corpus batch {fields[1]} reported twice")
            corpus[fields[1]] = fields[2]
    exactly("xcheck corpus batches", tuple(golden), list(corpus))
    for name, hexed in corpus.items():
        if hexed != golden[name]:
            fail(f"xcheck corpus {name}: upstream encodes {hexed}, the corpus has {golden[name]}")

    compared = XCHECK_SWEEP - XCHECK_REFUSED
    expect("encoder", keyed(lines, "encoder"), {"cases": XCHECK_SWEEP, "compared": compared, "differ": 0, "refused": XCHECK_REFUSED})
    expect("decoder", keyed(lines, "decoder"), {"cases": XCHECK_SWEEP, "differ": 0})
    expect("reader", keyed(lines, "reader"), {"compared": compared, "differ": 0})
    expect("session", keyed(lines, "session"), {"batches": XCHECK_SESSION_BATCHES, "checked": XCHECK_SESSION_CHECKED, "differ": 0})

    reasons = [line.split()[1:] for line in lines if line.split()[:1] == ["refusal"]]
    if reasons != [["ZidNotCanonical", str(XCHECK_REFUSED)]]:
        fail(f"xcheck: sweep refusals {reasons}, expected only ZidNotCanonical x {XCHECK_REFUSED}")

    probes: dict[str, dict[str, str]] = {}
    for line in lines:
        fields = line.split()
        if fields[:1] == ["zid"] and len(fields) == 6:
            if fields[1] in probes:
                fail(f"xcheck: Zenoh ID probe {fields[1]} reported twice")
            probes[fields[1]] = dict(field.partition("=")[::2] for field in fields[2:])
    exactly("xcheck Zenoh ID probes", XCHECK_ZIDS, list(probes))
    for zid, seen in probes.items():
        raw = bytes.fromhex(zid)
        wanted = {
            "upstream": "refuses" if not any(raw) else "accepts",
            "encode": "refuses" if raw[-1] == 0 else "encodes",
            "wire-upstream": "refuses" if not any(raw) else "accepts",
            "wire-ours": "refuses" if raw[-1] == 0 else "accepts",
        }
        if seen != wanted:
            fail(f"xcheck Zenoh ID {zid}: {seen}, expected {wanted}")
    return len(corpus) + XCHECK_SWEEP + XCHECK_SESSION_BATCHES + len(probes), XCHECK_REFUSED


def xcheck_good_lines() -> list[str]:
    lines = [f"corpus {name} {hexed}" for name, hexed, _ in reference()]
    compared = XCHECK_SWEEP - XCHECK_REFUSED
    lines += [
        f"encoder cases={XCHECK_SWEEP} compared={compared} differ=0 refused={XCHECK_REFUSED}",
        f"refusal ZidNotCanonical {XCHECK_REFUSED}",
        f"decoder cases={XCHECK_SWEEP} differ=0",
        f"reader compared={compared} differ=0",
        f"session batches={XCHECK_SESSION_BATCHES} checked={XCHECK_SESSION_CHECKED} differ=0",
    ]
    for zid in XCHECK_ZIDS:
        raw = bytes.fromhex(zid)
        up = "refuses" if not any(raw) else "accepts"
        ours = "refuses" if raw[-1] == 0 else None
        lines.append(f"zid {zid} upstream={up} encode={ours or 'encodes'} wire-upstream={up} wire-ours={'refuses' if ours else 'accepts'}")
    return lines


def xcheck_controls() -> int:
    """Refuse corrupted or hollowed-out harness output before trusting a real one."""
    good = xcheck_good_lines()
    judge_xcheck(good)

    def swap(prefix: str, new: str) -> list[str]:
        at = next(i for i, line in enumerate(good) if line.startswith(prefix))
        return good[:at] + [new] + good[at + 1 :]

    first = next(i for i, line in enumerate(good) if line.startswith("corpus "))
    fields = good[first].split()
    flipped = fields[2][:-1] + ("0" if fields[2][-1] != "0" else "1")
    compared = XCHECK_SWEEP - XCHECK_REFUSED
    mutations: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a dropped corpus batch", good[:first] + good[first + 1 :]),
        ("a corrupted corpus byte", swap("corpus ", f"corpus {fields[1]} {flipped}")),
        ("a duplicated corpus batch", good + [good[first]]),
        ("an encoder difference", swap("encoder ", f"encoder cases={XCHECK_SWEEP} compared={compared} differ=1 refused={XCHECK_REFUSED}")),
        ("a decoder difference", swap("decoder ", f"decoder cases={XCHECK_SWEEP} differ=1")),
        ("a reader difference", swap("reader ", f"reader compared={compared} differ=1")),
        ("a session difference", swap("session ", f"session batches={XCHECK_SESSION_BATCHES} checked={XCHECK_SESSION_CHECKED} differ=1")),
        ("a short session", swap("session ", f"session batches=10 checked={XCHECK_SESSION_CHECKED} differ=0")),
        ("a short sweep", swap("encoder ", f"encoder cases=5999 compared={compared - 1} differ=0 refused={XCHECK_REFUSED}")),
        ("the Zenoh ID rule silently dropped", swap("encoder ", f"encoder cases={XCHECK_SWEEP} compared={XCHECK_SWEEP} differ=0 refused=0")),
        ("an unexplained refusal", good + ["refusal KeyTooLong 1"]),
        ("a wrong refusal count", swap("refusal ", "refusal ZidNotCanonical 6")),
        ("an all-zero Zenoh ID that upstream accepts", [line.replace("upstream=refuses", "upstream=accepts", 1) if line.startswith("zid 0000") else line for line in good]),
        ("a trailing-zero Zenoh ID that the encoder emits", [line.replace("encode=refuses", "encode=encodes", 1) if line.startswith("zid 0102030405060700") else line for line in good]),
        ("a dropped Zenoh ID probe", [line for line in good if not line.startswith("zid 5a")]),
        ("a duplicated encoder line", good + [good[next(i for i, line in enumerate(good) if line.startswith("encoder "))]]),
    ]
    for label, mutated in mutations:
        try:
            judge_xcheck(mutated)
        except SystemExit:
            continue
        fail(f"control: {label} was accepted by the xcheck judge")
    return len(mutations)


def run_xcheck() -> list[str]:
    manifest = XCHECK_CRATE / "Cargo.toml"
    if not manifest.is_file():
        fail(f"{manifest.relative_to(ROOT)} does not exist; the cross-check harness has not landed")
    command = [
        "cargo", "run", "--release", "--locked", "--manifest-path", str(manifest),
        "--target-dir", str(ROOT / "build" / "zenoh-xcheck-target"), "--", str(XCHECK_SWEEP),
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        _sys.stderr.write((result.stdout + result.stderr)[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    return [match.group(1).strip() for line in result.stdout.splitlines() if (match := XCHECK_LINE.search(line))]


def xcheck_main(controls_only: bool) -> int:
    refused_controls = xcheck_controls()
    if controls_only:
        print(f"zenoh profile 0 xcheck judge: refused {refused_controls} corrupted transcripts")
        return 0
    cases, refusals = judge_xcheck(run_xcheck())
    print(f"[zenoh-profile0] slice=xcheck cases={cases} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 xcheck: the codec and session agree with the upstream eclipse-zenoh 1.0.0 crates")
    return 0


def stock_fixtures() -> list[tuple[str, str]]:
    """The captured batches as `group/name`, after tying the pushes to the demo contract."""
    rows = [(f"{group}/{name}", hexed) for group in ("connects", "listens", "refuse") for name, hexed in zenoh_stock_peer.batches(group)]
    names = [name for name, _ in rows]
    if len(set(names)) != len(names):
        fail("stock fixtures: a fixture name is used twice")
    by_name = dict(rows)
    attachments: list[tuple[int, str]] = []
    samples = zenoh_exchange.demo()["samples"]
    if len(STOCK_PUSHES) != len(samples):
        fail("stock fixtures: the captured pushes do not match the demo's sample count")
    for push, (sequence, _value, payload) in zip(STOCK_PUSHES, samples, strict=True):
        raw = bytes.fromhex(by_name.get(push, ""))
        if len(raw) < 12 + 1 + 33 or raw[-12:].hex() != payload:
            fail(f"stock fixtures: {push} does not end in the demo payload for sample {sequence}")
        attachment = raw[-12 - 1 - 33 : -12 - 1]
        if int.from_bytes(attachment[:8], "little") != sequence or attachment[16] != 16:
            fail(f"stock fixtures: {push} has attachment sequence/GID length differing from sample {sequence}")
        if raw[-13] != 12 or raw[-47] != 33:
            fail(f"stock fixtures: {push} does not carry the 12-byte payload and 33-byte attachment lengths")
        attachments.append((int.from_bytes(attachment[8:16], "little", signed=True), attachment[17:].hex()))
    # The demo contract's attachments come from one publisher: one GID, and timestamps that never go
    # back. The expected transcript is derived from these bytes, so they are checked here and not
    # taken on trust from the capture they came from.
    if len({gid for _ts, gid in attachments}) != 1:
        fail("stock fixtures: the captured pushes carry more than one GID")
    if [ts for ts, _gid in attachments] != sorted(ts for ts, _gid in attachments):
        fail("stock fixtures: the captured pushes' timestamps go backwards")
    # The wrong-position batches are captured batches plus the two-byte QoS extension and a set
    # extension flag, and nothing else: anything more would make them a different test.
    undeclare_source = next(
        (fields[3] for fields in (line.split() for line in STOCK_CORPUS.read_text().splitlines())
         if len(fields) == 5 and fields[:3] == ["batch", "frame_undeclare_subscriber_sn7", "ok"]),
        "",
    ) if STOCK_CORPUS.is_file() else zenoh_stock_peer.UNDECLARE_SOURCE
    if undeclare_source != zenoh_stock_peer.UNDECLARE_SOURCE:
        fail("stock fixtures: the UndeclareSubscriber source is not the corpus row frame_undeclare_subscriber_sn7")
    # (source batch, whether the extension flag is set on a header byte of the source, the extension
    # bytes: in a Put the QoS extension is followed by the attachment, so it carries the more-flag)
    sources = {
        "frame": (by_name["connects/connects-05-push-1"], True, b"\x21\x08"),
        "push": (by_name["connects/connects-05-push-1"], True, b"\x21\x08"),
        "put": (by_name["connects/connects-05-push-1"], False, b"\xa1\x08"),
        "inner-subscriber-header": (by_name["listens/listens-05-declare-subscriber-declare-final"], True, b"\x21\x08"),
        "declare-final": (by_name["listens/listens-05-declare-subscriber-declare-final"], True, b"\x21\x08"),
        "undeclare-subscriber": (undeclare_source, True, b"\x21\x08"),
    }
    key_source = bytes.fromhex(by_name["connects/connects-04-declare-keyexpr-declare-subscriber"])
    key_built = bytes.fromhex(by_name.get("refuse/refuse-alias-key-130-bytes", ""))
    at = key_source.find(bytes.fromhex("2001008101"))
    key_end = at + 5 + 129
    if not (
        at >= 0
        and len(key_built) == len(key_source) + 1
        and key_built[: at + 3] == key_source[: at + 3]
        and key_built[at + 3 : at + 5] == bytes.fromhex("8201")
        and key_built[at + 5 : key_end] == key_source[at + 5 : key_end]
        and key_built[key_end : key_end + 1] == b"a"
        and key_built[key_end + 1 :] == key_source[key_end:]
    ):
        fail("stock fixtures: refuse-alias-key-130-bytes is not the captured DeclareKeyExpr with a 130-byte key")
    for suffix_path, suffix_source in (("subscriber", "listens/listens-05-declare-subscriber-declare-final"), ("put", "connects/connects-05-push-1")):
        suffixed = bytes.fromhex(by_name.get(f"refuse/refuse-alias-suffix-on-{suffix_path}", ""))
        original_bytes = bytes.fromhex(by_name[suffix_source])
        if len(suffixed) != len(original_bytes) + 2 or b"\x01a" not in suffixed or suffixed == original_bytes:
            fail(f"stock fixtures: refuse-alias-suffix-on-{suffix_path} is not {suffix_source} plus a one-byte suffix on the alias")
    undeclare_alias = bytes.fromhex(by_name.get("refuse/refuse-alias-on-undeclare", ""))
    undeclare_row = bytes.fromhex(undeclare_source)
    if not (len(undeclare_alias) == 9 and undeclare_alias[:6] == undeclare_row[:6] and undeclare_alias[6:] == bytes.fromhex("020201")):
        fail("stock fixtures: refuse-alias-on-undeclare is not the corpus undeclaration with scope 1 and no suffix")
    for position, (source_hex, sets_flag, extension) in sources.items():
        built = bytes.fromhex(by_name.get(f"refuse/refuse-qos-on-{position}", ""))
        original = bytes.fromhex(source_hex)
        # Removing the two extension bytes at some offset and clearing the extension flag on one
        # header byte must give the source back exactly, so the batch is the source plus the extension.
        restored = False
        for at in range(len(built) - 1):
            if built[at : at + 2] != extension or len(built) != len(original) + 2:
                continue
            candidate = built[:at] + built[at + 2 :]
            differing = [i for i in range(len(original)) if candidate[i] != original[i]]
            if sets_flag and len(differing) == 1 and candidate[differing[0]] == original[differing[0]] | 0x80:
                restored = True
                break
            if not sets_flag and not differing:
                restored = True
                break
        if not restored:
            fail(f"stock fixtures: refuse-qos-on-{position} is not its source batch plus the QoS extension and flag")
    for name, hexed in rows:
        try:
            bytes.fromhex(hexed)
        except ValueError:
            fail(f"stock fixtures: {name} is not hexadecimal")
    return rows


# What the admitted item fixes, held here as well so the gate stays correct after the item is
# completed and retired to .tasks/terminal, where its body is no longer an active item. While the
# item is active its stored body is compared with these; once it is gone these still bind.
STOCK_PINNED_CASES = 69
STOCK_PINNED_CONTROLS = 138


def stock_item_pins() -> tuple[int, int]:
    """The case count and the control floor the admitted stock-peer item fixes, read from its stored
    body, so the number the checker reports and the number the acceptance requires cannot drift."""
    items = sorted((ROOT / ".tasks" / "items").glob("*.md"))
    for path in items:
        text = path.read_text()
        if "zenoh_stock_check" not in text or "slime-zenoh-profile0-stock-peer-" not in text:
            continue
        cases = re.search(r'id = "all-cases-observed";.*?intValue = (\d+);', text, re.S)
        floor = re.search(r'observation = "negativeControlsRefused";.*?lower = (\d+);', text, re.S)
        if cases and floor:
            return int(cases.group(1)), int(floor.group(1))
    return 0, 0


def stock_attachments() -> list[tuple[int, int, str]]:
    """Sequence, source timestamp and GID of each captured push, read from the captured bytes."""
    by_name = {f"{group}/{name}": hexed for group in ("connects", "listens") for name, hexed in zenoh_stock_peer.batches(group)}
    rows = []
    for push in STOCK_PUSHES:
        raw = bytes.fromhex(by_name[push])
        attachment = raw[-12 - 1 - 33 : -12 - 1]
        rows.append((int.from_bytes(attachment[:8], "little"), int.from_bytes(attachment[8:16], "little", signed=True), attachment[17:].hex()))
    return rows


def judge_stock_corpus(text: str) -> int:
    """The corpus the stock-peer change may not widen: the refused vectors outside
    STOCK_MAY_CHANGE keep their name, class and bytes, STOCK_MAY_CHANGE may go but not become
    accepted, and the accepted batches are exactly the 17 with their name, bytes and summary. A
    refused vector may be added; none may be duplicated."""
    refused: dict[str, tuple[str, str]] = {}
    accepted: dict[str, tuple[str, str]] = {}
    streams: dict[str, list[str]] = {}
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if fields[:1] == ["stream"] and len(fields) >= 3:
            if fields[1] in streams or fields[1] in refused or fields[1] in accepted:
                fail(f"stock corpus: line {number}: vector {fields[1]} appears twice")
            streams[fields[1]] = fields[2:]
            continue
        if len(fields) != 5 or fields[0] != "batch":
            continue
        name, kind = fields[1], fields[2]
        if kind == "refused":
            table = refused
        elif kind == "ok":
            table = accepted
        else:
            continue
        if name in refused or name in accepted or name in streams:
            fail(f"stock corpus: line {number}: vector {name} appears twice")
        table[name] = (fields[3], fields[4])
    missing = sorted(set(STOCK_FIXED_NAMES) - set(refused))
    if missing:
        fail(f"stock corpus: refused vectors removed or renamed: {', '.join(missing[:6])}")
    digest = hashlib.sha256(
        "\n".join(f"{name} {refused[name][0]} {refused[name][1]}" for name in sorted(STOCK_FIXED_NAMES)).encode()
    ).hexdigest()
    if digest != STOCK_FIXED_DIGEST:
        fail(f"stock corpus: a refused vector outside the stock-peer change has a different class or bytes (digest {digest[:16]}, pinned {STOCK_FIXED_DIGEST[:16]})")
    # The one row allowed to change is the vector the stock peer sent, and only by going: while it
    # exists it is refused, with the captured bytes. It cannot become an accepted row, because every
    # accepted row is read by consumers the implementation cannot change (the encoder gate rebuilds
    # each from its summary, the cross-check harness encodes each, and a Rust test counts them).
    for name, captured_bytes in STOCK_MAY_CHANGE_BYTES.items():
        if name in accepted:
            fail(f"stock corpus: {name} is an accepted row; it may be removed or stay refused, not become accepted")
        row = refused.get(name)
        if row is not None and row[1] != captured_bytes:
            fail(f"stock corpus: {name} must keep the captured bytes {captured_bytes}, not {row[1]}")
        if row is not None and row[0] != STOCK_MAY_CHANGE_CLASS[name]:
            fail(f"stock corpus: {name} must stay refused as {STOCK_MAY_CHANGE_CLASS[name]}, not {row[0]}")
    absent = sorted(set(STOCK_ACCEPTED_NAMES) - set(accepted))
    if absent:
        fail(f"stock corpus: accepted upstream batches removed or renamed: {', '.join(absent[:6])}")
    # No accepted row is added, whatever its name or bytes: the accepted rows are exactly the 17 the
    # upstream encoder produced. The stock batches are exercised by the stock tests, not the corpus.
    extra = sorted(set(accepted) - set(STOCK_ACCEPTED_NAMES))
    if extra:
        fail(f"stock corpus: accepted rows outside the 17 the upstream encoder produced: {', '.join(extra[:6])}")
    accepted_digest = hashlib.sha256(
        "\n".join(f"{name} {accepted[name][0]} {accepted[name][1]}" for name in sorted(STOCK_ACCEPTED_NAMES)).encode()
    ).hexdigest()
    if accepted_digest != STOCK_ACCEPTED_DIGEST:
        fail(f"stock corpus: an accepted upstream batch has different bytes or summary (digest {accepted_digest[:16]}, pinned {STOCK_ACCEPTED_DIGEST[:16]})")
    missing_streams = sorted(set(STOCK_STREAM_NAMES) - set(streams))
    if missing_streams:
        fail(f"stock corpus: stream vectors removed or renamed: {', '.join(missing_streams[:6])}")
    added_streams = sorted(set(streams) - set(STOCK_STREAM_NAMES))
    if added_streams:
        fail(f"stock corpus: stream vectors outside the pinned set: {', '.join(added_streams[:6])}")
    stream_digest = hashlib.sha256(
        "\n".join(f"{name} {' '.join(streams[name])}" for name in sorted(STOCK_STREAM_NAMES)).encode()
    ).hexdigest()
    if stream_digest != STOCK_STREAM_DIGEST:
        fail(f"stock corpus: a stream-framing vector has a different verdict, class or chunks (digest {stream_digest[:16]}, pinned {STOCK_STREAM_DIGEST[:16]})")
    return len(STOCK_FIXED_NAMES) + len(STOCK_ACCEPTED_NAMES) + len(STOCK_STREAM_NAMES)


def stock_expected() -> tuple[tuple[str, ...], tuple[tuple[str, str], ...], tuple[str, ...]]:
    return zenoh_stock_peer.OK_SCENARIOS, zenoh_stock_peer.REFUSED_SCENARIOS, zenoh_stock_peer.replay_names()


def judge_stock(lines: list[str]) -> tuple[int, int]:
    ok_wanted, refused_wanted, replay_wanted = stock_expected()
    split = [line.split() for line in lines]
    done = [f[2] for f in split if len(f) == 3 and f[0] == "stock" and f[1] == "ok"]
    replays = [f[2] for f in split if len(f) == 4 and f[:2] == ["stock", "replay"] and f[3] == "ok"]
    refused = [(f[2], f[3]) for f in split if len(f) == 4 and f[:2] == ["stock", "refused"]]
    pushes = [(f[2], f[3]) for f in split if len(f) == 4 and f[:2] == ["stock", "attachment"]]
    attachments = stock_attachments()
    expected_pushes = [(f"{sequence}:{timestamp}", gid) for sequence, timestamp, gid in attachments]
    if pushes != expected_pushes:
        fail(f"stock attachments decoded {pushes}, the captured pushes carry {expected_pushes}")
    delivered = [(f[2], f[3], f[4]) for f in split if len(f) == 5 and f[:2] == ["stock", "delivered"]]
    wanted = [(str(sequence), payload, str(attachments[index][1])) for index, (sequence, _value, payload) in enumerate(zenoh_exchange.demo()["samples"])]
    if [seq for seq, _, _ in delivered] != [seq for seq, _, _ in wanted]:
        fail(f"stock delivered samples {[seq for seq, _, _ in delivered]}, the demo contract has {[seq for seq, _, _ in wanted]}")
    for (seq, got, stamp), (_, payload, source) in zip(delivered, wanted, strict=True):
        if got != payload:
            fail(f"stock delivered sample {seq}: {got}, the demo contract has {payload}")
        if stamp != source:
            fail(f"stock delivered sample {seq}: timestamp {stamp}, the captured attachment has {source}")
    exactly("stock scenarios", ok_wanted, done)
    if done != list(ok_wanted):
        fail(f"stock scenarios are out of order: {done}, the exam runs them as {list(ok_wanted)}")
    reported = [f for f in split if f[:2] == ["stock", "property"]]
    unsuccessful = [" ".join(f) for f in reported if f[3:] != ["ok"]]
    if unsuccessful:
        fail(f"stock properties reported a failure or a malformed record: {', '.join(unsuccessful[:3])}")
    properties = [f[2] for f in reported]
    if properties != [name[len("replay:") :] for name in replay_wanted]:
        fail(f"stock properties held for {properties}, the exam requires every captured batch in capture order")
    exactly("stock replays", replay_wanted, [f"replay:{name}" for name in replays])
    if [f"replay:{name}" for name in replays] != list(replay_wanted):
        fail(f"stock replays are out of order: {[f'replay:{name}' for name in replays]}, the exam replays {list(replay_wanted)}")
    for group in ("connects", "listens"):
        seen = [name for name in replays if name.startswith(f"{group}-")]
        order = [name[len("replay:") :] for name in replay_wanted if name.startswith(f"replay:{group}-")]
        if seen != order:
            fail(f"stock replays of {group} are out of capture order: {seen}, captured as {order}")
    exactly("stock refusals", tuple(name for name, _ in refused_wanted), [name for name, _ in refused])
    wrong = [f"{name}={cls} (expected {dict(refused_wanted)[name]})" for name, cls in refused if cls != dict(refused_wanted)[name]]
    if wrong:
        fail(f"stock refusal classes differ: {', '.join(wrong)}")
    shapes = {
        ("stock", "ok"): 3,
        ("stock", "replay"): 4,
        ("stock", "refused"): 4,
        ("stock", "delivered"): 5,
        ("stock", "attachment"): 4,
        ("stock", "property"): 4,
    }
    for line, fields in zip(lines, split, strict=True):
        if fields[:1] != ["stock"]:
            fail(f"stock: a record that is not a stock exam line: {line!r}")
        kind = tuple(fields[:2])
        if kind not in shapes:
            fail(f"stock: unrecognised line: {line}")
        if len(fields) != shapes[kind]:
            fail(f"stock: a {kind[1]} line has {len(fields)} fields, expected {shapes[kind]}: {line}")
        if kind == ("stock", "replay") and fields[3] != "ok":
            fail(f"stock: a replay line must end in ok: {line}")
    # The attachment lines are validated above but are not cases: the item fixes the count at the
    # scenarios, replays and delivered samples plus the refusals.
    return len(done) + len(replays) + len(delivered), len(refused)


def stock_good_lines() -> list[str]:
    ok_wanted, refused_wanted, replay_wanted = stock_expected()
    return (
        [f"stock ok {name}" for name in ok_wanted]
        + [f"stock replay {name[len('replay:'):]} ok" for name in replay_wanted]
        + [f"stock delivered {sequence} {payload} {stock_attachments()[index][1]}" for index, (sequence, _value, payload) in enumerate(zenoh_exchange.demo()["samples"])]
        + [f"stock attachment {sequence}:{timestamp} {gid}" for sequence, timestamp, gid in stock_attachments()]
        + [f"stock property {name[len('replay:'):]} ok" for name in replay_wanted]
        + [f"stock refused {name} {cls}" for name, cls in refused_wanted]
    )


def first_replay_index(lines: list[str], prefix: str) -> int:
    return next(i for i, line in enumerate(lines) if line.startswith(f"stock replay {prefix}"))


def swap_lines(lines: list[str], first: int, second: int) -> list[str]:
    swapped = list(lines)
    swapped[first], swapped[second] = swapped[second], swapped[first]
    return swapped


def stock_handoff_controls() -> int:
    """The contract's decoder accepts the honest hand-off and refuses each corrupted one."""
    import tempfile

    honest = zenoh_stock_peer.fixture_zti()
    # The same record spelled across lines is still the same record: the contract's decoder reads
    # both, so the exam must too (checked below, beside the refusals).
    respelled = honest.replace(
        '    { name = "connects-11-close"; hex = "0300"; };\n',
        '    {\n      name = "connects-11-close";\n      hex = "0300";\n    };\n',
        1,
    ).replace("formatVersion = 1;", "formatVersion =\n    1;", 1)
    mutations = [
        ("a missing group", honest.replace("  refuse = [", "  refuze = [")),
        ("a wrong format version", honest.replace("formatVersion = 1;", "formatVersion = 2;")),
        ("a group of the wrong size", honest.replace('    { name = "connects-11-close"; hex = "0300"; };\n', "", 1)),
        ("a name of 64 two-byte characters, 128 bytes", honest.replace('"connects-11-close"', '"' + "\u00e9" * 64 + '"', 1)),
        ("a hex string with an odd length", honest.replace('hex = "0300"', 'hex = "030"', 1)),
        ("a hex string in capitals", honest.replace('hex = "0300"', 'hex = "03AB"', 1)),
        ("a cookie of the right length but another value", honest.replace(zenoh_stock_peer.COOKIE.encode().hex(), "a" * 58, 1)),
        ("a cookie followed by extra characters", honest.replace(f'"{zenoh_stock_peer.COOKIE.encode().hex()}"', f'"{zenoh_stock_peer.COOKIE.encode().hex()}zz"', 1)),
        ("a cookie of the wrong length", re.sub(r'cookieHex = "[0-9a-f]{2}', 'cookieHex = "', honest, count=1)),
        ("a row with no hex", honest.replace('hex = "', 'hxx = "', 1)),
        ("a hex that is not text", honest.replace('hex = "', "hex = 7; zz = \"", 1)),
        ("an unknown extra field", honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise = 1;")),
        ("a twelfth connects entry written over several lines", honest.replace("  connects = [\n", "  connects = [\n" + '    {\n      name = "extra";\n      hex = "00";\n    };\n', 1)),
        ("an unknown extra field on the same line as a known one", honest.replace("formatVersion = 1;", "formatVersion = 1; surprise = 1;", 1)),
        ("an unknown extra field on the opening line", honest.replace("{\n  formatVersion", "{ surprise = 1;\n  formatVersion", 1)),
        ("an unknown extra field inside an entry", honest.replace('{ name = "connects-11-close"; hex = "0300"; };', '{ name = "connects-11-close"; hex = "0300"; extra = 1; };', 1)),
        ("an unknown extra field written over several lines", honest.replace("formatVersion = 1;", "formatVersion = 1;\n  surprise =\n    1;", 1)),
        ("a wrong format version written over several lines", honest.replace("formatVersion = 1;", "formatVersion =\n    2;", 1)),
        ("a sixteenth refuse entry written over several lines", honest.replace("  refuse = [\n", "  refuse = [\n" + '    {\n      name = "extra";\n      hex = "00";\n    };\n', 1)),
    ]
    (ROOT / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / "build") as scratch:
        path = _Path(scratch) / "handoff.zti"
        path.write_text(honest)
        stock_validate_handoff(path)
        if respelled == honest:
            fail("control: the respelled honest hand-off equals the original")
        path.write_text(respelled)
        stock_validate_handoff(path)
        for label, text in mutations:
            path.write_text(text)
            try:
                stock_validate_handoff(path)
            except SystemExit:
                continue
            fail(f"control: {label} was accepted by the fixture contract")
    return len(mutations)


def stock_controls() -> int:
    """Refuse corrupted or hollowed-out stock evidence before trusting a real transcript."""
    stock_fixtures()
    good = stock_good_lines()
    judge_stock(good)

    def swap(prefix: str, new: str) -> list[str]:
        at = next(i for i, line in enumerate(good) if line.startswith(prefix))
        return good[:at] + [new] + good[at + 1 :]

    without_replays = [line for line in good if not line.startswith("stock replay ")]
    connects_replays = [line for line in good if line.startswith("stock replay connects-")]
    listens_replays = [line for line in good if line.startswith("stock replay listens-")]
    interleaved_replays = [
        line
        for pair in zip(connects_replays, listens_replays, strict=False)
        for line in pair
    ] + connects_replays[len(listens_replays) :]
    first_ok = good[0]
    first_replay = next(line for line in good if line.startswith("stock replay "))
    first_refused = next(line for line in good if line.startswith("stock refused "))
    mutations: list[tuple[str, list[str]]] = [
        ("an empty transcript", []),
        ("a dropped scenario", [line for line in good if line != first_ok]),
        ("a duplicated scenario", good + [first_ok]),
        ("an unknown scenario", good + ["stock ok invented-scenario"]),
        ("a dropped replay", [line for line in good if line != first_replay]),
        ("a duplicated replay", good + [first_replay]),
        ("a replay of a batch that was never captured", good + ["stock replay stock-connects-99-invented ok"]),
        ("a replay reported refused", [("stock refused " + line.split()[2] + " unsupported-extension") if line == first_replay else line for line in good]),
        ("every refusal removed", [line for line in good if not line.startswith("stock refused ")]),
        ("a dropped refusal", [line for line in good if line != first_refused]),
        ("the second subscriber admitted instead of refused", [line for line in good if not line.startswith("stock refused second-subscriber-received ")]),
        ("the two replay groups swapped", without_replays + listens_replays + connects_replays),
        ("the replay groups interleaved, each in its own order", without_replays + interleaved_replays),
        ("a keep-alive with a trailing byte admitted instead of refused", [line for line in good if not line.startswith("stock refused keep-alive-trailing-byte ")]),
        ("a keep-alive with a trailing byte refused with the wrong class", swap("stock refused keep-alive-trailing-byte ", "stock refused keep-alive-trailing-byte unsupported-message")),
        ("a captured batch whose properties were not run", [line for line in good if line != "stock property connects-04-declare-keyexpr-declare-subscriber ok"]),
        ("a property reported for a batch that was never captured", good + ["stock property stock-connects-99-invented ok"]),
        ("a property line that does not end in ok", [line.replace("stock property listens-03-oam ok", "stock property listens-03-oam failed") for line in good]),
        ("the properties run on the batches in another order", [line for line in good if not line.startswith("stock property ")] + list(reversed([line for line in good if line.startswith("stock property ")]))),
        ("a failed property record added to an honest transcript", good + ["stock property invented failed"]),
        ("a failed property record for a captured batch added to an honest transcript", good + ["stock property connects-01-init-syn failed"]),
        ("a property record with no verdict added to an honest transcript", good + ["stock property invented"]),
        ("an alias on an undeclaration admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-alias-on-undeclare ")]),
        ("an alias on an undeclaration refused with the wrong class", swap("stock refused refuse-alias-on-undeclare ", "stock refused refuse-alias-on-undeclare over-bound")),
        ("an identical alias redeclaration admitted instead of refused", [line for line in good if not line.startswith("stock refused alias-redeclared-same-key ")]),
        ("an identical alias redeclaration refused with the wrong class", swap("stock refused alias-redeclared-same-key ", "stock refused alias-redeclared-same-key over-bound")),
        ("a keep-alive sent over pending traffic that was not reported", [line for line in good if line != "stock ok keep-alive-suppressed-by-traffic"]),
        ("a suffix on the declared alias admitted on a subscriber", [line for line in good if not line.startswith("stock refused refuse-alias-suffix-on-subscriber ")]),
        ("a suffix on the declared alias admitted on a Put", [line for line in good if not line.startswith("stock refused refuse-alias-suffix-on-put ")]),
        ("a suffix on the declared alias refused with the wrong class", swap("stock refused refuse-alias-suffix-on-put ", "stock refused refuse-alias-suffix-on-put over-bound")),
        ("an alias key over the bound admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-alias-key-130-bytes ")]),
        ("an alias key over the bound refused with the wrong class", swap("stock refused refuse-alias-key-130-bytes ", "stock refused refuse-alias-key-130-bytes invalid-keyexpr")),
        ("a received unknown undeclaration admitted instead of refused", [line for line in good if not line.startswith("stock refused unknown-subscriber-received ")]),
        ("a sent unknown undeclaration refused with the wrong class", swap("stock refused unknown-subscriber-sent ", "stock refused unknown-subscriber-sent invalid-keyexpr")),
        ("a tick before OPEN that sent something in the idle state", [line for line in good if line != "stock ok tick-silent-in-idle"]),
        ("a tick while awaiting OPEN_ACK that sent something", [line for line in good if line != "stock ok tick-silent-while-awaiting-open-ack"]),
        ("a keep-alive in the idle state admitted instead of refused", [line for line in good if not line.startswith("stock refused keep-alive-in-idle ")]),
        ("a keep-alive while awaiting OPEN_ACK admitted instead of refused", [line for line in good if not line.startswith("stock refused keep-alive-while-awaiting-open-ack ")]),
        ("a keep-alive before open refused with the wrong class", swap("stock refused keep-alive-while-awaiting-open-syn ", "stock refused keep-alive-while-awaiting-open-syn invalid-keyexpr")),
        ("the five-event frame admitted instead of refused", [line for line in good if not line.startswith("stock refused frame-five-events ")]),
        ("the five-event frame refused with the wrong class", swap("stock refused frame-five-events ", "stock refused frame-five-events invalid-keyexpr")),
        ("QoS on a FRAME header admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-qos-on-frame ")]),
        ("QoS on a PUSH admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-qos-on-push ")]),
        ("QoS on the inner header of a subscriber declaration admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-qos-on-inner-subscriber-header ")]),
        ("QoS on a Put admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-qos-on-put ")]),
        ("QoS on a DeclareFinal admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-qos-on-declare-final ")]),
        ("QoS on an UndeclareSubscriber admitted instead of refused", [line for line in good if not line.startswith("stock refused refuse-qos-on-undeclare-subscriber ")]),
        ("QoS on a PUSH refused with the wrong class", swap("stock refused refuse-qos-on-push ", "stock refused refuse-qos-on-push invalid-keyexpr")),
        ("a second subscriber refused with the wrong class", swap("stock refused second-subscriber-sent ", "stock refused second-subscriber-sent invalid-keyexpr")),
        ("a refusal with the wrong class", swap("stock refused refuse-wildcard", "stock refused refuse-wildcard unsupported-message")),
        ("a refusal with no class", swap("stock refused refuse-client", "stock refused refuse-client")),
        ("a stock peer that was accepted as a client", [line for line in good if not line.startswith("stock refused refuse-client")] + ["stock ok refuse-client"]),
        ("an unrecognised line kind", good + ["stock maybe silence-past-lease-closes"]),
        ("a refusal line with no class", good + ["stock refused refuse-client"]),
        ("a replay line with no verdict", good + ["stock replay stock-connects-01-init-syn"]),
        ("a replay line with an extra field", good + [first_replay + " extra"]),
        ("a replay line whose verdict is not ok", good + [first_replay.rsplit(" ", 1)[0] + " refused"]),
        ("an ok line with an extra field", good + [first_ok + " and-more"]),
        ("a bare stock line", good + ["stock"]),
        ("a record that is not a stock line", good + ["session ok invented"]),
        ("a record from another slice", good + ["encode ok somebatch aabb"]),
        ("free text among the stock lines", good + ["random noise"]),
        ("two scenarios reported in the other order", swap_lines(good, good.index(f"stock ok {zenoh_stock_peer.OK_SCENARIOS[0]}"), good.index(f"stock ok {zenoh_stock_peer.OK_SCENARIOS[1]}"))),
        ("the last scenario reported first", [f"stock ok {zenoh_stock_peer.OK_SCENARIOS[-1]}"] + [line for line in good if line != f"stock ok {zenoh_stock_peer.OK_SCENARIOS[-1]}"]),
        ("a delivered sample dropped", [line for line in good if not line.startswith("stock delivered 3 ")]),
        ("a delivered sample duplicated", good + [next(line for line in good if line.startswith("stock delivered 0 "))]),
        ("a delivered sample out of order", [line for line in good if not line.startswith("stock delivered")] + [next(line for line in good if line.startswith(f"stock delivered {n} ")) for n in (1, 0, 2, 3)]),
        ("a delivered payload that differs from the demo's", swap("stock delivered 2 ", f"stock delivered 2 00010000020000001e000001 {stock_attachments()[2][1]}")),
        ("a delivered timestamp that differs from the captured attachment's", swap("stock delivered 1 ", f"stock delivered 1 000100000100000014000000 {stock_attachments()[1][1] + 1}")),
        ("a decoded attachment GID with one byte changed", swap("stock attachment 2:", f"stock attachment 2:{stock_attachments()[2][1]} " + stock_attachments()[2][2][:-2] + "00")),
        ("a decoded attachment with the wrong sequence", swap("stock attachment 1:", f"stock attachment 9:{stock_attachments()[1][1]} {stock_attachments()[1][2]}")),
        ("a decoded attachment dropped", [line for line in good if not line.startswith("stock attachment 3:")]),
        ("a decoded attachment with no GID", swap("stock attachment 0:", f"stock attachment 0:{stock_attachments()[0][1]}")),
        ("a delivered line with no timestamp", swap("stock delivered 0 ", "stock delivered 0 00010000000000000a000000")),
        ("the first two replays of the stock-connects capture swapped", swap_lines(good, first_replay_index(good, "connects-01-"), first_replay_index(good, "connects-02-"))),
        ("the first two replays of the stock-listens capture swapped", swap_lines(good, first_replay_index(good, "listens-01-"), first_replay_index(good, "listens-02-"))),
        ("the close replayed before the handshake it ends", swap_lines(good, first_replay_index(good, "connects-01-"), first_replay_index(good, "connects-11-"))),
        ("the lease-silence scenario missing", [line for line in good if line != "stock ok silence-past-lease-closes"]),
        ("the 2000 ms keep-alive scenario missing", [line for line in good if line != "stock ok keep-alive-sent-lease-2000"]),
        ("the 10000 ms keep-alive scenario missing", [line for line in good if line != "stock ok keep-alive-sent-lease-10000"]),
    ]
    for label, mutated in mutations:
        try:
            judge_stock(mutated)
        except SystemExit:
            continue
        fail(f"control: {label} was accepted by the stock judge")
    handoff_refused = stock_handoff_controls()
    corpus_text = STOCK_CORPUS.read_text() if STOCK_CORPUS.is_file() else ""
    if corpus_text:
        judge_stock_corpus(corpus_text)
        def drop(name: str) -> str:
            return "\n".join(line for line in corpus_text.splitlines() if not line.startswith((f"batch {name} ", f"stream {name} ")))

        def rekeep(tail: str) -> str:
            # The keep-alive row may be gone from the corpus, which the exam allows. The variant is
            # then added as a row, so each control still puts the variant in front of the judge
            # instead of handing it the unchanged corpus.
            row = f"batch transport_keep_alive {tail}"
            lines = corpus_text.splitlines()
            if any(line.startswith("batch transport_keep_alive ") for line in lines):
                return "\n".join(row if line.startswith("batch transport_keep_alive ") else line for line in lines)
            return "\n".join([*lines, row])

        def refragment(tail: str) -> str:
            # As rekeep: the fragment row may be gone, so a variant is added as a row when it is.
            row = f"batch transport_fragment {tail}"
            lines = corpus_text.splitlines()
            if any(line.startswith("batch transport_fragment ") for line in lines):
                return "\n".join(row if line.startswith("batch transport_fragment ") else line for line in lines)
            return "\n".join([*lines, row])

        def restream(name: str, position: int, value: str) -> str:
            return "\n".join(
                " ".join(line.split()[:position] + [value] + line.split()[position + 1 :])
                if line.startswith(f"stream {name} ")
                else line
                for line in corpus_text.splitlines()
            )
        def retarget(name: str, cls: str) -> str:
            return "\n".join(
                " ".join(line.split()[:3] + [cls] + line.split()[4:]) if line.startswith(f"batch {name} ") else line
                for line in corpus_text.splitlines()
            )
        def rebytes(name: str, accepted: bool = False) -> str:
            column = 3 if accepted else 4
            return "\n".join(
                " ".join(
                    line.split()[:column]
                    + [line.split()[column][:-2] + ("00" if line.split()[column][-2:] != "00" else "01")]
                    + line.split()[column + 1 :]
                )
                if line.startswith(f"batch {name} ")
                else line
                for line in corpus_text.splitlines()
            )
        first_accepted = next(line.split()[1] for line in corpus_text.splitlines() if line.startswith("batch ") and line.split()[2:3] == ["ok"])
        corpus_mutations = [
            ("a fixed refused vector removed", drop(STOCK_FIXED_NAMES[0])),
            ("a fixed refused vector reclassified", retarget(STOCK_FIXED_NAMES[1], "invented-class")),
            ("a fixed refused vector with different bytes", rebytes(STOCK_FIXED_NAMES[2])),
            ("a router peer vector reclassified", retarget("init_whatami_router", "unsupported-message")),
            ("an accepted upstream batch removed", drop(first_accepted)),
            ("an accepted upstream batch with different bytes", rebytes(first_accepted, accepted=True)),
            ("an accepted batch dropped and a renamed copy of another added", drop(first_accepted) + "\n" + next(line for line in corpus_text.splitlines() if line.startswith("batch ") and line.split()[2:3] == ["ok"] and line.split()[1] != first_accepted).replace(next(line for line in corpus_text.splitlines() if line.startswith("batch ") and line.split()[2:3] == ["ok"] and line.split()[1] != first_accepted).split()[1], first_accepted, 1)),
            ("an accepted batch repeated", corpus_text + "\n" + next(line for line in corpus_text.splitlines() if line.startswith(f"batch {first_accepted} "))),
            ("an accepted batch the upstream encoder did not produce", corpus_text + "\nbatch invented_by_the_implementation ok 00 invented"),
            ("an unobserved extension position now accepted (frame_extension_present)", retarget("frame_extension_present", "ok")),
            ("an unobserved extension position removed (push_extension_flag)", drop("push_extension_flag")),
            ("a fixed refused vector turned into an accepted one (init_whatami_router)", retarget("init_whatami_router", "ok")),
            ("an invented accepted vector outside the upstream corpus and the stock-peer change", corpus_text + "\nbatch invented_by_the_implementation ok 00 x"),
            ("every stream-framing row deleted", "\n".join(line for line in corpus_text.splitlines() if not line.startswith("stream "))),
            ("the 512-byte stream refusal turned into an accepted one (stream_length_513)", restream("stream_length_513", 2, "ok")),
            ("a stream refusal reclassified (stream_length_zero)", restream("stream_length_zero", 3, "invented-class")),
            ("a stream refusal removed (stream_refusal_after_valid_batch)", drop("stream_refusal_after_valid_batch")),
            ("an accepted stream row with other chunks (stream_single_batch)", restream("stream_single_batch", 3, "00")),
            ("an invented stream row", corpus_text + "\nstream invented_stream_row ok 00 x 0"),
            ("a vector with a stock-sounding name turned accepted (declare_extension_flag)", retarget("declare_extension_flag", "ok")),
            ("a vector with a stock-sounding name turned accepted (declare_keyexpr_alias)", retarget("declare_keyexpr_alias", "ok")),
            ("a vector with a stock-sounding name turned accepted (frame_network_oam)", retarget("frame_network_oam", "ok")),
            ("a vector with a stock-sounding name turned accepted (dsub_nonzero_scope)", retarget("dsub_nonzero_scope", "ok")),
            ("a vector with a stock-sounding name turned accepted (push_no_suffix)", retarget("push_no_suffix", "ok")),
            ("a stock_ row whose bytes are not a captured batch", corpus_text + "\nbatch stock_invented ok 00ff invented"),
            ("a captured batch's bytes under a name that is not stock_", corpus_text + f"\nbatch invented_name ok {zenoh_stock_peer.batches('connects')[0][1]} invented"),
            ("a batch row reusing a stream row's name", corpus_text + "\nbatch stream_single_batch refused empty-batch -"),
            ("a stream row reusing a batch row's name", corpus_text + "\nstream init_syn_default ok 00 x 0"),
            ("a batch row reusing an accepted batch's name", corpus_text + f"\nbatch {first_accepted} refused empty-batch -"),
            ("the keep-alive row accepted with invented bytes", rekeep("ok 00 invented")),
            ("the keep-alive row still refused but with other bytes", rekeep("refused unsupported-message ff")),
            ("the keep-alive row refused with another existing class", rekeep("refused malformed-message 04")),
            ("the keep-alive row refused with an invented class", rekeep("refused invented-class 04")),
            ("the keep-alive row turned into an accepted row with the captured byte", rekeep(f"ok {STOCK_MAY_CHANGE_BYTES['transport_keep_alive']} KEEP_ALIVE;captured")),
            ("the fragment row accepted with invented bytes", refragment("ok 00 invented")),
            ("the fragment row still refused but with other bytes", refragment("refused unsupported-message ff")),
            ("the fragment row refused with another existing class", refragment("refused malformed-message 2601aa")),
            ("the fragment row refused with an invented class", refragment("refused invented-class 2601aa")),
            ("the fragment row turned into an accepted row with the captured bytes", refragment(f"ok {STOCK_MAY_CHANGE_BYTES['transport_fragment']} FRAGMENT;captured")),
            ("an accepted stock_ row for a captured batch", corpus_text + f"\nbatch stock_init_syn ok {zenoh_stock_peer.batches('connects')[0][1]} INIT_SYN;captured"),
        ]
        for label, mutated in corpus_mutations:
            try:
                judge_stock_corpus(mutated)
            except SystemExit:
                continue
            fail(f"control: {label} was accepted by the stock corpus judge")
        # The keep-alive row may go or stay refused with the captured byte: the exam must not stand in
        # the way of the item, whichever of those it chooses.
        for may_change in sorted(STOCK_MAY_CHANGE):
            judge_stock_corpus(drop(may_change))
        judge_stock_corpus(rekeep(f"refused unsupported-message {STOCK_MAY_CHANGE_BYTES['transport_keep_alive']}"))
        judge_stock_corpus(refragment(f"refused unsupported-message {STOCK_MAY_CHANGE_BYTES['transport_fragment']}"))
        extra = len(corpus_mutations)
    else:
        extra = 0
    # The reader of the retained suites: a verdict printed after a test's own output counts, and a
    # failed, unfinished or absent test does not.
    sample = "\n".join((
        "test a::one ... ok",
        "test a::two ... [zenoh-exam] x", "[zenoh-exam] y", "ok",
        "test a::three ... [zenoh-exam] z", "FAILED",
        "test a::four ... [zenoh-exam] w",
        "test a::five ... ok",
    ))
    if tests_passed(sample) != {"a::one", "a::two", "a::five"}:
        fail("control: the retained-test reader misjudged a passed, failed or unfinished test")
    extra += 1
    # The fixtures themselves are held to the demo contract: a push whose payload is changed is refused.
    # The capture itself is held to the demo contract: a push whose payload differs, a push from
    # another GID, and a push whose timestamp goes back are each refused.
    def flip_payload(raw: bytearray) -> None:
        raw[-1] ^= 1

    def flip_gid(raw: bytearray) -> None:
        raw[-13 - 1] ^= 1

    def timestamp_back(raw: bytearray) -> None:
        start = len(raw) - 12 - 1 - 33
        raw[start + 8 : start + 16] = (-1).to_bytes(8, "little", signed=True)

    original = zenoh_stock_peer.CONNECTS
    refused_captures = 0
    try:
        for label, push, mutate in (
            ("a capture whose push payload differs from the demo sample", STOCK_PUSHES[0], flip_payload),
            ("a capture whose second push comes from another GID", STOCK_PUSHES[1], flip_gid),
            ("a capture whose third push has a timestamp that goes back", STOCK_PUSHES[2], timestamp_back),
        ):
            broken = list(original)
            index = next(i for i, (name, _h) in enumerate(broken) if name == push.split("/", 1)[1])
            name, hexed = broken[index]
            raw = bytearray.fromhex(hexed)
            mutate(raw)
            broken[index] = (name, raw.hex())
            zenoh_stock_peer.CONNECTS = tuple(broken)
            try:
                stock_fixtures()
            except SystemExit:
                refused_captures += 1
                continue
            fail(f"control: {label} was accepted")
        zenoh_stock_peer.CONNECTS = original
        stock_fixtures()
    finally:
        zenoh_stock_peer.CONNECTS = original
    return len(mutations) + refused_captures + extra + handoff_refused

STOCK_DECODED_ENTRY = re.compile(r'\s*\{ hex = "([^"\\]*)";\s+name = "([^"\\]*)" \}\s*')


def stock_decoded_rows(decoded: str, group: str) -> list[tuple[str, str]]:
    """The (name, hex) entries of one group in the decoder's own output, which spells every entry
    one way however the source wrote it. The whole group must be consumed: an entry the reader
    cannot parse is refused, not skipped, so no entry the contract's decoder accepted goes uncounted."""
    start = re.search(rf"\b{group} = \[", decoded)
    if not start:
        fail(f"stock hand-off: the decoded record has no {group} group")
    position, rows = start.end(), []
    if decoded[position:position + 1] == "]":
        return rows
    while True:
        entry = STOCK_DECODED_ENTRY.match(decoded, position)
        if not entry:
            fail(f"stock hand-off: {group} holds an entry the checker cannot read at offset {position}")
        rows.append((entry.group(2), entry.group(1)))
        position = entry.end()
        if decoded[position:position + 1] == "]":
            return rows
        if decoded[position:position + 1] != ";":
            fail(f"stock hand-off: {group} is not a list of entries at offset {position}")
        position += 1


def stock_validate_handoff(path: _Path) -> None:
    """Decode the hand-off with the contract's own decoder; the Rust tests read the same file."""
    # Zutai imports stay inside the project, so the decoder and a copy of the schema sit in one
    # scratch directory under build/, rebuilt from the contract on every call.
    scratch = ZENOH_DECODER.parent
    scratch.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "contracts" / "zenoh-stock-fixtures" / "v1" / "schema.zt", scratch / "schema.zt")
    ZENOH_DECODER.write_text(
        's ::= import "schema.zt"; env ::= import stdlib.env; load ::= import stdlib.load; '
        "main :: { env : Env; load : Load; } -> Validation DecodeIssue s.Capture ! { * env.GetEffects; * load.ZtiEffects; } "
        '= caps => [ path := env.get caps.env "SLIME_ZENOH_STOCK_FIXTURES_PATH" ?? ""; s.decodeCapture (load.zti caps.load path) ]; main\n'
    )
    try:
        decoded = zutai_cli.evaluate("run", ZENOH_DECODER, input_path=path, env_var="SLIME_ZENOH_STOCK_FIXTURES_PATH")
    except zutai_cli.ZutaiError as error:
        fail(f"stock hand-off does not decode under contracts/zenoh-stock-fixtures/v1: {error}")
    if not decoded.startswith("#valid"):
        fail(f"stock hand-off is refused by contracts/zenoh-stock-fixtures/v1: {decoded[:200]}")
    # The decoder fixes shape and types; the values the schema names are held here, as the other
    # contracts' exams do: the version, the counts per group, the cookie, and the bounds.
    # The field set is closed by the contract's decoder, wherever a field is written; nothing here
    # reads the source layout.
    version = re.search(r"\bformatVersion = (\d+)", decoded)
    if not version or int(version.group(1)) != 1:
        fail("stock hand-off: formatVersion is not 1")
    for group, count in (("connects", 11), ("listens", 8), ("refuse", 15)):
        rows = stock_decoded_rows(decoded, group)
        if len(rows) != count:
            fail(f"stock hand-off: {group} has {len(rows)} rows, the contract fixes {count}")
        for name, hexed in rows:
            if len(name.encode("utf-8")) > 64 or len(hexed) % 2 or len(hexed) // 2 > 512 or not re.fullmatch(r"[0-9a-f]*", hexed):
                fail(f"stock hand-off: {group}/{name} breaks the contract's bounds or is not lowercase hexadecimal")
    cookie = re.search(r'\bcookieHex = "([^"]*)"', decoded)
    if not cookie or cookie.group(1) != zenoh_stock_peer.COOKIE.encode().hex():
        fail("stock hand-off: cookieHex is not the cookie issued for the capture")


def tests_passed(output: str) -> set[str]:
    """Names of the tests libtest reports as ok. With --nocapture a test that prints puts its
    verdict on a line of its own after everything it printed, so a test counts when its line ends
    `... ok`, or when the first bare `ok` or `FAILED` line before the next test line is `ok`."""
    lines = output.splitlines()
    passed: set[str] = set()
    for index, line in enumerate(lines):
        started = re.match(r"^test (\S+) \.\.\. (.*)$", line)
        if not started:
            continue
        name, rest = started.groups()
        if rest == "ok":
            passed.add(name)
        elif rest != "FAILED":
            for later in lines[index + 1:]:
                if later.startswith("test "):
                    break
                if later in ("ok", "FAILED"):
                    if later == "ok":
                        passed.add(name)
                    break
    return passed


def cargo_tests(filters: tuple[str, ...], environment: dict[str, str]) -> tuple[str, str]:
    """One `cargo test` over the given name filters; returns (stdout, combined output)."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    command = [
        "cargo", "test", "--target", target, "-p", "slime-components", "--no-default-features",
        "--", *filters, "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True, env=environment)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", output)
    if not any(status == "ok" and int(passed) > 0 for status, passed, _ in results) or any(
        status != "ok" or int(failed) for status, _, failed in results
    ):
        fail(f"no passing test result for filters {list(filters)!r}")
    return result.stdout, output


def run_stock() -> list[str]:
    stock_fixtures()
    if not STOCK_CORPUS.is_file():
        fail(f"{STOCK_CORPUS.relative_to(ROOT)} is missing")
    judge_stock_corpus(STOCK_CORPUS.read_text())
    STOCK_FIXTURES.parent.mkdir(parents=True, exist_ok=True)
    STOCK_FIXTURES.write_text(zenoh_stock_peer.fixture_zti())
    stock_validate_handoff(STOCK_FIXTURES)
    environment = {**_os.environ, "ZENOH_STOCK_FIXTURES": str(STOCK_FIXTURES)}
    # The retained suites run in their own process. Their tests print `[zenoh-exam]` lines for the
    # recipes that own them, which are not stock records, so nothing from this process reaches the
    # stock judge; only which tests passed is read, by name, because a filter that matches nothing
    # passes silently.
    _stdout, retained = cargo_tests(
        (STOCK_DECODER_FILTER, STOCK_SESSION_FILTER, STOCK_ENCODE_FILTER, STOCK_LINK_FILTER), environment
    )
    passed = tests_passed(retained)
    missing = [name for name in STOCK_RETAINED_TESTS if name not in passed]
    if missing:
        fail(f"retained tests did not run and pass ({len(missing)} of {len(STOCK_RETAINED_TESTS)}): {', '.join(missing[:4])}")
    # The stock tests run alone, and their evidence is all the stock judge sees.
    stock_stdout, _output = cargo_tests((STOCK_FILTER,), environment)
    return exam_lines(stock_stdout)


def stock_main(controls_only: bool) -> int:
    refused_controls = stock_controls()
    item_cases, item_floor = stock_item_pins()
    positive, refusals_total = judge_stock(stock_good_lines())
    if positive + refusals_total != STOCK_PINNED_CASES:
        fail(f"stock: an honest transcript is {positive + refusals_total} cases, the checker pins {STOCK_PINNED_CASES}")
    if refused_controls < STOCK_PINNED_CONTROLS:
        fail(f"stock: {refused_controls} controls, the checker pins at least {STOCK_PINNED_CONTROLS}")
    # While the item is an active work item, its stored body must say the same. A retired item has no
    # body here, so this comparison is skipped and the pins above are the whole guard.
    if item_cases and item_cases != STOCK_PINNED_CASES:
        fail(f"stock: the admitted item fixes {item_cases} cases, the checker pins {STOCK_PINNED_CASES}")
    if item_floor and item_floor != STOCK_PINNED_CONTROLS:
        fail(f"stock: the admitted item requires {item_floor} controls, the checker pins {STOCK_PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 stock judge: refused {refused_controls} corrupted transcripts")
        return 0
    cases, refusals = judge_stock(run_stock())
    print(f"[zenoh-profile0] slice=stock cases={cases} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 stock check: the session took every batch a stock Zenoh peer sent and refused what a bounded profile must")
    return 0


LINKS_FILTER = "zenoh_links::"
# The stock-peer exam's own Rust tests, by name. They print the stock transcript the stock judge
# grades, so a link implementation that deletes or renames one, or lets it emit incomplete evidence,
# fails this gate and not only `zenoh_stock_check`.
LINKS_STOCK_TESTS = tuple(f"zenoh_stock::{name}" for name in (
    "alias_id_zero_is_refused_at_its_declaration",
    "an_alias_id_wider_than_a_reference_is_refused_at_its_declaration",
    "an_alias_in_the_receiver_mapping_is_not_resolved",
    "the_constants_are_the_handed_off_record",
    "the_cookie_is_the_captured_one",
    "the_stock_peer_exam",
))
# Everything the stock-peer exam already requires to keep passing, plus its own tests: a fragment
# change edits the decoder, session and link, and the fixed decoder must keep refusing a fragment.
LINKS_RETAINED_TESTS = (*STOCK_RETAINED_TESTS,)
# A mutation of the list above proves the gate would notice a stock test going missing: see links_main.


def links_item_pins() -> tuple[int, int]:
    """The case count and the control floor the admitted links item fixes, read from its stored body,
    so the number the checker reports and the number the acceptance requires cannot drift."""
    for path in sorted((ROOT / ".tasks" / "items").glob("*.md")):
        text = path.read_text()
        if "zenoh_links_check" not in text or "slime-zenoh-profile0-link-limits-" not in text:
            continue
        cases = re.search(r'id = "all-cases-observed";.*?intValue = (\d+);', text, re.S)
        floor = re.search(r'observation = "negativeControlsRefused";.*?lower = (\d+);', text, re.S)
        if cases and floor:
            return int(cases.group(1)), int(floor.group(1))
    return 0, 0


def run_links() -> list[str]:
    # The pinned corpus is judged on this path too, not only by `zenoh_stock_check`: an
    # implementation that removes `transport_fragment` could otherwise drop or alter another pinned
    # refusal and update the Rust corpus count while every named test and the links transcript pass.
    if not STOCK_CORPUS.is_file():
        fail(f"{STOCK_CORPUS.relative_to(ROOT)} is missing")
    judge_stock_corpus(STOCK_CORPUS.read_text())
    environment = dict(_os.environ)
    stock_environment = {**environment, "ZENOH_STOCK_FIXTURES": str(STOCK_FIXTURES)}
    _stdout, retained = cargo_tests(
        (STOCK_DECODER_FILTER, STOCK_SESSION_FILTER, STOCK_ENCODE_FILTER, STOCK_LINK_FILTER), stock_environment
    )
    passed = tests_passed(retained)
    missing = [name for name in LINKS_RETAINED_TESTS if name not in passed]
    if missing:
        fail(f"links: retained tests did not run and pass ({len(missing)} of {len(LINKS_RETAINED_TESTS)}): {', '.join(missing[:4])}")
    # The stock-peer exam's tests run alone, as `run_stock` runs them, and their transcript is
    # judged by the stock judge: all six are required by name and the lines must be the stock exam's.
    stock_stdout, stock_output = cargo_tests((STOCK_FILTER,), stock_environment)
    stock_passed = tests_passed(stock_output)
    stock_missing = [name for name in LINKS_STOCK_TESTS if name not in stock_passed]
    if stock_missing:
        fail(f"links: the stock-peer exam's tests did not run and pass ({len(stock_missing)} of {len(LINKS_STOCK_TESTS)}): {', '.join(stock_missing[:4])}")
    judge_stock(exam_lines(stock_stdout))
    # The links tests run alone, and their evidence is all the links judge sees.
    links_stdout, _output = cargo_tests((LINKS_FILTER,), environment)
    return exam_lines(links_stdout)


def links_main(controls_only: bool) -> int:
    # The corpus judge and its mutations run here as a precondition: this gate relies on them to keep
    # the 100 pinned refused vectors where they are. Their refusals belong to the stock gate's count,
    # so they are not added to this one's.
    stock_controls()
    sample = "\n".join(f"test {name} ... ok" for name in LINKS_STOCK_TESTS[1:])
    if all(name in tests_passed(sample) for name in LINKS_STOCK_TESTS):
        fail("control: a run with a stock-peer exam test missing was read as complete")
    try:
        refused_controls = zenoh_links_exam.all_controls()
        item_cases, item_floor = links_item_pins()
        positive, refusals = zenoh_links_exam.judge(zenoh_links_exam.good_lines())
    except (zenoh_links_exam.LinksError, zenoh_exchange.ExchangeError) as error:
        fail(str(error))
    if positive + refusals != zenoh_links_exam.PINNED_CASES:
        fail(f"links: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_links_exam.PINNED_CASES}")
    if refused_controls < zenoh_links_exam.PINNED_CONTROLS:
        fail(f"links: {refused_controls} controls, the checker pins at least {zenoh_links_exam.PINNED_CONTROLS}")
    # While the item is an active work item, its stored body must say the same. A retired item has no
    # body here, so this comparison is skipped and the pins above are the whole guard.
    if item_cases and item_cases != zenoh_links_exam.PINNED_CASES:
        fail(f"links: the admitted item fixes {item_cases} cases, the checker pins {zenoh_links_exam.PINNED_CASES}")
    if item_floor and item_floor != zenoh_links_exam.PINNED_CONTROLS:
        fail(f"links: the admitted item requires {item_floor} controls, the checker pins {zenoh_links_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 links judge: refused {refused_controls} corrupted records")
        return 0
    stock_fixtures()
    STOCK_FIXTURES.parent.mkdir(parents=True, exist_ok=True)
    STOCK_FIXTURES.write_text(zenoh_stock_peer.fixture_zti())
    try:
        cases, refusals = zenoh_links_exam.judge(run_links())
    except zenoh_links_exam.LinksError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=links cases={cases} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 links check: a link takes the limits it declares, fragments and reassembles as a stock peer does, and refuses what it must")
    return 0


UNDECLARE_FILTER = "zenoh_undeclare::"
UNDECLARE_FIXTURES = ROOT / "build" / "zenoh-undeclare" / "fixtures.zti"
# The exam's own Rust tests, by name: a filter that matches nothing passes silently.
UNDECLARE_TESTS = tuple(f"zenoh_undeclare::{name}" for name in (
    "the_constants_are_the_handed_off_record",
    "the_stock_peer_undeclare_exam",
))


def run_undeclare() -> list[str]:
    # The pinned corpus and the stock-peer exam are judged on this path too: an implementation that
    # accepts the bare undeclaration by loosening the decoder could otherwise move a pinned refusal or
    # a stock case while every undeclare test passes.
    if not STOCK_CORPUS.is_file():
        fail(f"{STOCK_CORPUS.relative_to(ROOT)} is missing")
    judge_stock_corpus(STOCK_CORPUS.read_text())
    stock_fixtures()
    STOCK_FIXTURES.parent.mkdir(parents=True, exist_ok=True)
    STOCK_FIXTURES.write_text(zenoh_stock_peer.fixture_zti())
    UNDECLARE_FIXTURES.parent.mkdir(parents=True, exist_ok=True)
    UNDECLARE_FIXTURES.write_text(zenoh_undeclare_exam.fixture_zti())
    try:
        zenoh_undeclare_exam.validate_handoff(UNDECLARE_FIXTURES.read_text())
    except zenoh_undeclare_exam.UndeclareError as error:
        fail(str(error))
    environment = {**_os.environ, "ZENOH_STOCK_FIXTURES": str(STOCK_FIXTURES), "ZENOH_UNDECLARE_FIXTURES": str(UNDECLARE_FIXTURES)}
    _stdout, retained = cargo_tests(
        (STOCK_DECODER_FILTER, STOCK_SESSION_FILTER, STOCK_ENCODE_FILTER, STOCK_LINK_FILTER), environment
    )
    passed = tests_passed(retained)
    missing = [name for name in LINKS_RETAINED_TESTS if name not in passed]
    if missing:
        fail(f"undeclare: retained tests did not run and pass ({len(missing)} of {len(LINKS_RETAINED_TESTS)}): {', '.join(missing[:4])}")
    stock_stdout, stock_output = cargo_tests((STOCK_FILTER,), environment)
    stock_passed = tests_passed(stock_output)
    stock_missing = [name for name in LINKS_STOCK_TESTS if name not in stock_passed]
    if stock_missing:
        fail(f"undeclare: the stock-peer exam's tests did not run and pass ({len(stock_missing)} of {len(LINKS_STOCK_TESTS)}): {', '.join(stock_missing[:4])}")
    judge_stock(exam_lines(stock_stdout))
    undeclare_stdout, undeclare_output = cargo_tests((UNDECLARE_FILTER,), environment)
    undeclare_passed = tests_passed(undeclare_output)
    undeclare_missing = [name for name in UNDECLARE_TESTS if name not in undeclare_passed]
    if undeclare_missing:
        fail(f"undeclare: the exam's tests did not run and pass ({len(undeclare_missing)} of {len(UNDECLARE_TESTS)}): {', '.join(undeclare_missing[:4])}")
    return exam_lines(undeclare_stdout)


def undeclare_main(controls_only: bool) -> int:
    # The stock corpus judge and its mutations run here as a precondition, as they do for `--slice links`:
    # this gate relies on them to keep the pinned refused vectors where they are, and their refusals
    # belong to the stock gate's count, not to this one's.
    stock_controls()
    sample = "\n".join(f"test {name} ... ok" for name in UNDECLARE_TESTS[1:])
    if all(name in tests_passed(sample) for name in UNDECLARE_TESTS):
        fail("control: a run with an undeclare exam test missing was read as complete")
    try:
        refused_controls = zenoh_undeclare_exam.all_controls()
        item_cases, item_controls = zenoh_undeclare_exam.item_pins()
        positive, refusals = zenoh_undeclare_exam.judge(zenoh_undeclare_exam.good_lines())
    except zenoh_undeclare_exam.UndeclareError as error:
        fail(str(error))
    if positive + refusals != zenoh_undeclare_exam.PINNED_CASES:
        fail(f"undeclare: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_undeclare_exam.PINNED_CASES}")
    if refused_controls != zenoh_undeclare_exam.PINNED_CONTROLS:
        fail(f"undeclare: {refused_controls} controls, the checker pins {zenoh_undeclare_exam.PINNED_CONTROLS}")
    # While the item is an active work item, its stored body must say the same. A retired item has no
    # body here, so this comparison is skipped and the pins above are the whole guard.
    if item_cases and item_cases != zenoh_undeclare_exam.PINNED_CASES:
        fail(f"undeclare: the admitted item fixes {item_cases} cases, the checker pins {zenoh_undeclare_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_undeclare_exam.PINNED_CONTROLS:
        fail(f"undeclare: the admitted item requires {item_controls} controls, the checker pins {zenoh_undeclare_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 undeclare judge: refused {refused_controls} corrupted records")
        return 0
    try:
        cases, refusals = zenoh_undeclare_exam.judge(run_undeclare())
    except zenoh_undeclare_exam.UndeclareError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=undeclare cases={cases} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 undeclare check: the session took the undeclaration a stock Zenoh peer sends and refused every variant of it the profile must")
    return 0


def neighbour_controls(*, subscribers: bool) -> None:
    # A slice that runs a neighbour's tests and judges their transcript relies on that judge's
    # negative controls. They run here as a precondition and their refusals are not counted: they
    # belong to the neighbour's own gate.
    stock_controls()
    try:
        zenoh_links_exam.all_controls()
        if subscribers:
            zenoh_subscribers_exam.all_controls()
    except (zenoh_links_exam.LinksError, zenoh_exchange.ExchangeError, zenoh_subscribers_exam.SubscribersError) as error:
        fail(str(error))


SUBSCRIBERS_FILTER = "zenoh_subscribers::"
# The exam's own Rust test, by name: a filter that matches nothing passes silently.
SUBSCRIBERS_TESTS = ("zenoh_subscribers::the_subscribers_exam",)
assert len(SUBSCRIBERS_TESTS) == 1


def run_subscribers() -> list[str]:
    # The session's subscriber limit is what the links exam and the stock-peer exam pin at one, four, nine
    # and 256, so both run and are judged here: lifting the own-side limit may not move any of them.
    # `run_links` judges the pinned corpus and the stock-peer exam itself and returns the links lines.
    stock_fixtures()
    STOCK_FIXTURES.parent.mkdir(parents=True, exist_ok=True)
    STOCK_FIXTURES.write_text(zenoh_stock_peer.fixture_zti())
    try:
        zenoh_links_exam.judge(run_links())
    except zenoh_links_exam.LinksError as error:
        fail(str(error))
    stdout, output = cargo_tests((SUBSCRIBERS_FILTER,), {**_os.environ})
    passed = tests_passed(output)
    missing = [name for name in SUBSCRIBERS_TESTS if name not in passed]
    if missing:
        fail(f"subscribers: the exam's tests did not run and pass ({len(missing)} of {len(SUBSCRIBERS_TESTS)}): {', '.join(missing[:4])}")
    return exam_lines(stdout)


def subscribers_main(controls_only: bool) -> int:
    neighbour_controls(subscribers=False)
    if all(name in tests_passed("") for name in SUBSCRIBERS_TESTS):
        fail("control: a run with the subscribers exam test missing was read as complete")
    try:
        refused_controls = zenoh_subscribers_exam.all_controls()
        item_cases, item_controls = zenoh_subscribers_exam.item_pins()
        positive, refusals = zenoh_subscribers_exam.judge(zenoh_subscribers_exam.good_lines())
    except zenoh_subscribers_exam.SubscribersError as error:
        fail(str(error))
    if positive + refusals != zenoh_subscribers_exam.PINNED_CASES:
        fail(f"subscribers: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_subscribers_exam.PINNED_CASES}")
    if refused_controls != zenoh_subscribers_exam.PINNED_CONTROLS:
        fail(f"subscribers: {refused_controls} controls, the checker pins {zenoh_subscribers_exam.PINNED_CONTROLS}")
    # While the item is an active work item, its stored body must say the same. A retired item has no
    # body here, so this comparison is skipped and the pins above are the whole guard.
    if item_cases and item_cases != zenoh_subscribers_exam.PINNED_CASES:
        fail(f"subscribers: the admitted item fixes {item_cases} cases, the checker pins {zenoh_subscribers_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_subscribers_exam.PINNED_CONTROLS:
        fail(f"subscribers: the admitted item requires {item_controls} controls, the checker pins {zenoh_subscribers_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 subscribers judge: refused {refused_controls} corrupted records")
        return 0
    try:
        cases, refusals = zenoh_subscribers_exam.judge(run_subscribers())
    except zenoh_subscribers_exam.SubscribersError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=subscribers cases={cases} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 subscribers check: a session holds as many subscriptions of its own as it is declared with and refuses one more")
    return 0


def grants_main(controls_only: bool) -> int:
    try:
        refused_controls = zenoh_grants_exam.all_controls()
        item_cases, item_controls = zenoh_grants_exam.item_pins()
        cases = zenoh_grants_exam.judge_cases()
    except zenoh_grants_exam.GrantsError as error:
        fail(str(error))
    if cases != zenoh_grants_exam.PINNED_CASES:
        fail(f"grants: the exam judges {cases} cases, the checker pins {zenoh_grants_exam.PINNED_CASES}")
    if refused_controls != zenoh_grants_exam.PINNED_CONTROLS:
        fail(f"grants: {refused_controls} controls, the checker pins {zenoh_grants_exam.PINNED_CONTROLS}")
    # While the item is an active work item, its stored body must say the same. A retired item has no
    # body here, so this comparison is skipped and the pins above are the whole guard.
    if item_cases and item_cases != zenoh_grants_exam.PINNED_CASES:
        fail(f"grants: the admitted item fixes {item_cases} cases, the checker pins {zenoh_grants_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_grants_exam.PINNED_CONTROLS:
        fail(f"grants: the admitted item requires {item_controls} controls, the checker pins {zenoh_grants_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 grants judge: refused {refused_controls} corrupted records")
        return 0
    # The generated constants are the implementation's, so the recipe fails until they land.
    try:
        zenoh_grants_exam.check_generated()
    except zenoh_grants_exam.GrantsError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=grants cases={cases} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 grants check: the contract accepts the declarations it must, refuses the ones it must, and its constants are the generated ones")
    return 0


def client_main(controls_only: bool) -> int:
    try:
        refused_controls = zenoh_client_exam.all_controls()
        item_cases, item_controls = zenoh_client_exam.item_pins()
        cases = len(zenoh_client_exam.facts())
    except zenoh_client_exam.ClientError as error:
        fail(str(error))
    if cases != zenoh_client_exam.PINNED_CASES:
        fail(f"client: the exam judges {cases} facts, the checker pins {zenoh_client_exam.PINNED_CASES}")
    if refused_controls != zenoh_client_exam.PINNED_CONTROLS:
        fail(f"client: {refused_controls} controls, the checker pins {zenoh_client_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_client_exam.PINNED_CASES:
        fail(f"client: the admitted item fixes {item_cases} cases, the checker pins {zenoh_client_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_client_exam.PINNED_CONTROLS:
        fail(f"client: the admitted item requires {item_controls} controls, the checker pins {zenoh_client_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 client judge: refused {refused_controls} corrupted schemas and generated files")
        return 0
    # The generated constants are the implementation's, so the recipe fails until they land.
    try:
        zenoh_client_exam.check_generated()
    except zenoh_client_exam.ClientError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=client cases={cases} controls={refused_controls}")
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 client check: the protocol fits IO0, names no key or holder, and its constants are the generated ones")
    return 0


CLIENT_WIRE_TEST = "every_record_encodes_to_the_layout_and_decodes_back"


def run_client_wire() -> list[str]:
    """The proto crate's test for the wire records, run alone: it needs no other crate and no neighbour exam."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    command = [
        "cargo", "test", "--target", target, "-p", "slime-proto", "--test", "zenoh_service_client_wire",
        "--", "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True, env={**_os.environ})
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    if CLIENT_WIRE_TEST not in tests_passed(output):
        fail(f"client-wire: the exam's test did not run and pass: {CLIENT_WIRE_TEST}")
    return exam_lines(result.stdout)


def client_schema_precondition() -> None:
    """The wire records are rendered from the client schema, so the schema's judge and its pins hold first. Its
    refusals are not counted: they belong to the client gate, which pins them."""
    try:
        controls = zenoh_client_exam.all_controls()
        facts = len(zenoh_client_exam.facts())
    except zenoh_client_exam.ClientError as error:
        fail(str(error))
    if facts != zenoh_client_exam.PINNED_CASES or controls != zenoh_client_exam.PINNED_CONTROLS:
        fail(f"client schema: {facts} facts and {controls} controls, the checker pins {zenoh_client_exam.PINNED_CASES} and {zenoh_client_exam.PINNED_CONTROLS}")


def client_wire_main(controls_only: bool) -> int:
    if CLIENT_WIRE_TEST in tests_passed(""):
        fail("control: a run with the wire exam test missing was read as complete")
    client_schema_precondition()
    try:
        refused_controls = zenoh_client_wire_exam.all_controls()
        item_cases, item_controls = zenoh_client_wire_exam.item_pins()
        positive, refusals = zenoh_client_wire_exam.judge(zenoh_client_wire_exam.good_lines())
    except zenoh_client_wire_exam.WireError as error:
        fail(str(error))
    if positive + refusals != zenoh_client_wire_exam.PINNED_CASES:
        fail(f"client-wire: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_client_wire_exam.PINNED_CASES}")
    if refused_controls != zenoh_client_wire_exam.PINNED_CONTROLS:
        fail(f"client-wire: {refused_controls} controls, the checker pins {zenoh_client_wire_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_client_wire_exam.PINNED_CASES:
        fail(f"client-wire: the admitted item fixes {item_cases} cases, the checker pins {zenoh_client_wire_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_client_wire_exam.PINNED_CONTROLS:
        fail(f"client-wire: the admitted item requires {item_controls} controls, the checker pins {zenoh_client_wire_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 client-wire judge: refused {refused_controls} corrupted records")
        return 0
    # The generated file is the implementation's, so the recipe fails until it lands.
    try:
        zenoh_client_wire_exam.check_generated()
        # The test reaches the records through the crate, and the crate exports them. A test that includes the
        # generated file by path passes without the export, so both are read as text.
        zenoh_client_wire_exam.check_exports()
        positive, refusals = zenoh_client_wire_exam.judge(run_client_wire())
    except zenoh_client_wire_exam.WireError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=client-wire cases={positive + refusals} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 client-wire check: every record encodes to the schema's layout, decodes back, and refuses a short buffer")
    return 0


CLIENT_IO_TEST = "zenoh_service_client::tests::the_client_exam"


def run_client_io() -> list[str]:
    """The proto crate's test of the client adapter, run alone: the adapter is compiled into it by path, against a
    stand-in runtime, so it needs no other crate and no neighbour exam."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    command = [
        "cargo", "test", "--target", target, "-p", "slime-proto", "--test", "zenoh_service_client",
        "--", "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True, env={**_os.environ})
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    if CLIENT_IO_TEST not in tests_passed(output):
        fail(f"client-io: the exam's test did not run and pass: {CLIENT_IO_TEST}")
    return exam_lines(result.stdout)


def wire_precondition() -> None:
    """The adapter encodes and decodes with the generated wire records, so their judge and its pins hold first."""
    client_schema_precondition()
    try:
        controls = zenoh_client_wire_exam.all_controls()
        positive, refusals = zenoh_client_wire_exam.judge(zenoh_client_wire_exam.good_lines())
    except zenoh_client_wire_exam.WireError as error:
        fail(str(error))
    if positive + refusals != zenoh_client_wire_exam.PINNED_CASES or controls != zenoh_client_wire_exam.PINNED_CONTROLS:
        fail(f"client wire: {positive + refusals} cases and {controls} controls, the checker pins {zenoh_client_wire_exam.PINNED_CASES} and {zenoh_client_wire_exam.PINNED_CONTROLS}")


def client_io_main(controls_only: bool) -> int:
    if CLIENT_IO_TEST in tests_passed(""):
        fail("control: a run with the client exam test missing was read as complete")
    wire_precondition()
    try:
        refused_controls = zenoh_client_io_exam.all_controls()
        item_cases, item_controls = zenoh_client_io_exam.item_pins()
        positive, refusals = zenoh_client_io_exam.judge(zenoh_client_io_exam.good_lines())
    except (zenoh_client_io_exam.ClientIoError, zenoh_client_wire_exam.WireError) as error:
        fail(str(error))
    if positive + refusals != zenoh_client_io_exam.PINNED_CASES:
        fail(f"client-io: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_client_io_exam.PINNED_CASES}")
    if refused_controls != zenoh_client_io_exam.PINNED_CONTROLS:
        fail(f"client-io: {refused_controls} controls, the checker pins {zenoh_client_io_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_client_io_exam.PINNED_CASES:
        fail(f"client-io: the admitted item fixes {item_cases} cases, the checker pins {zenoh_client_io_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_client_io_exam.PINNED_CONTROLS:
        fail(f"client-io: the admitted item requires {item_controls} controls, the checker pins {zenoh_client_io_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 client-io judge: refused {refused_controls} corrupted records")
        return 0
    # The wire records the adapter is compiled against are the renderer's output, and their own test passes.
    try:
        # The adapter and its stand-in read the committed constants. A stale constant they share passes every
        # transcript, so the committed file is compared with its renderer first.
        zenoh_client_exam.check_generated()
        zenoh_client_wire_exam.check_generated()
        zenoh_client_wire_exam.check_exports()
        zenoh_client_wire_exam.judge(run_client_wire())
        # The adapter's test compiles it by path, which passes without the product crate's export, so the export
        # is checked as text.
        zenoh_client_io_exam.check_export()
        positive, refusals = zenoh_client_io_exam.judge(run_client_io())
    except (zenoh_client_io_exam.ClientIoError, zenoh_client_wire_exam.WireError, zenoh_client_exam.ClientError) as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=client-io cases={positive + refusals} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 client-io check: the adapter bounds every request, checks every answer and returns every loan")
    return 0


CLIENT_ABORT_TEST = "zenoh_service_client::tests::the_abort_exam"
ABORT_LINE = re.compile(r"\[zenoh-abort\] (.*)$")


def abort_run_is_scoped(output: str) -> bool:
    """Whether the run was of the abort test alone: it passed, and nothing else in the target ran. The markers on
    stdout are attributed to the test only when it is the only test that could have printed them."""
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", output)
    return tests_passed(output) == {CLIENT_ABORT_TEST} and results == [("ok", "1", "0")]


def run_client_abort() -> list[str]:
    """The proto crate's test of a failed attach, run alone with `--exact`: the adapter is compiled into it by path
    against the stand-in runtime. Another test in the target could print the same markers while this one prints
    nothing, so only this test runs and the run is checked to have run it alone. Its lines carry their own marker,
    so the adapter exam never reads them."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    command = [
        "cargo", "test", "--target", target, "-p", "slime-proto", "--test", "zenoh_service_client",
        "--", "--exact", CLIENT_ABORT_TEST, "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True, env={**_os.environ})
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    if CLIENT_ABORT_TEST not in tests_passed(output):
        fail(f"client-abort: the exam's test did not run and pass: {CLIENT_ABORT_TEST}")
    if not abort_run_is_scoped(output):
        fail(f"client-abort: the run was not of {CLIENT_ABORT_TEST} alone, so its markers cannot be attributed to it")
    return [match.group(1).strip() for line in result.stdout.splitlines() if (match := ABORT_LINE.search(line))]


def client_abort_main(controls_only: bool) -> int:
    if CLIENT_ABORT_TEST in tests_passed(""):
        fail("control: a run with the abort exam test missing was read as complete")
    passed_alone = f"test {CLIENT_ABORT_TEST} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
    two_tests = f"test {CLIENT_ABORT_TEST} ... ok\ntest zenoh_service_client::tests::the_client_exam ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"
    other_test = "test zenoh_service_client::tests::the_client_exam ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
    if not abort_run_is_scoped(passed_alone):
        fail("control: a run of the abort test alone was read as not scoped")
    if abort_run_is_scoped(two_tests) or abort_run_is_scoped(other_test) or abort_run_is_scoped(""):
        fail("control: a run of more than the abort test, or of another test, was read as scoped")
    wire_precondition()
    try:
        io_controls = zenoh_client_io_exam.all_controls()
        refused_controls = zenoh_client_abort_exam.all_controls()
        item_cases, item_controls = zenoh_client_abort_exam.item_pins()
        positive, refusals = zenoh_client_abort_exam.judge(zenoh_client_abort_exam.good_lines())
    except (zenoh_client_abort_exam.AbortError, zenoh_client_io_exam.ClientIoError, zenoh_client_wire_exam.WireError) as error:
        fail(str(error))
    if io_controls != zenoh_client_io_exam.PINNED_CONTROLS:
        fail(f"client-abort: the adapter judge refuses {io_controls} controls, the checker pins {zenoh_client_io_exam.PINNED_CONTROLS}")
    if positive != zenoh_client_abort_exam.PINNED_CASES:
        fail(f"client-abort: an honest transcript is {positive} cases, the checker pins {zenoh_client_abort_exam.PINNED_CASES}")
    if refused_controls != zenoh_client_abort_exam.PINNED_CONTROLS:
        fail(f"client-abort: {refused_controls} controls, the checker pins {zenoh_client_abort_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_client_abort_exam.PINNED_CASES:
        fail(f"client-abort: the admitted item fixes {item_cases} cases, the checker pins {zenoh_client_abort_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_client_abort_exam.PINNED_CONTROLS:
        fail(f"client-abort: the admitted item requires {item_controls} controls, the checker pins {zenoh_client_abort_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 client-abort judge: refused {refused_controls} corrupted records")
        return 0
    try:
        zenoh_client_exam.check_generated()
        zenoh_client_wire_exam.check_generated()
        zenoh_client_io_exam.check_export()
        positive, refusals = zenoh_client_abort_exam.judge(run_client_abort())
    except (zenoh_client_abort_exam.AbortError, zenoh_client_io_exam.ClientIoError, zenoh_client_wire_exam.WireError, zenoh_client_exam.ClientError) as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=client-abort cases={positive} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 client-abort check: a failed attach returns the loans, reads the attach answer and ends the service session")
    return 0


def grants_reader_main(controls_only: bool) -> int:
    """The product side of the grants path. The exam's controls run on synthetic files and a synthetic transcript. The
    full run reads the real files and runs the two `slime-root` tests alone, so it fails until the reader lands."""
    exam = zenoh_grants_reader_exam
    try:
        positive, refusals = exam.controls()
        if positive != exam.PINNED_CASES:
            fail(f"grants-reader: {positive} honest checks, the checker pins {exam.PINNED_CASES}")
        if refusals != exam.PINNED_CONTROLS:
            fail(f"grants-reader: {refusals} refusals, the checker pins {exam.PINNED_CONTROLS}")
        if controls_only:
            print(f"zenoh profile 0 grants-reader judge: refused {refusals} corrupted inputs")
            return 0
        held = exam.check_facts(exam.read_file)
        ran = exam.judge_run(exam.run_reader_tests())
    except exam.ReaderExamError as error:
        fail(f"grants-reader: {error}")
    cases = held + (1 if ran == len(exam.TESTS) else 0)
    if cases != exam.PINNED_CASES:
        fail(f"grants-reader: {cases} cases, the checker pins {exam.PINNED_CASES}")
    print(f"[zenoh-profile0] slice=grants-reader cases={cases} refusals={refusals} controls={refusals}")
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refusals)
    print("zenoh profile 0 grants-reader check: the label, the schema fields, the root reader and the wrapper are in place and the reader's tests pass")
    return 0


SERVER_PINNED_CASES = 39
SERVER_PINNED_CONTROLS = 104


def server_run_is_scoped(output: str) -> bool:
    """Whether the run was of the server test alone: it passed, and it is the only result cargo printed. The package
    has an integration test as well, and a run that does not name the library prints a result for each binary."""
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", output)
    return tests_passed(output) == {zenoh_server_exam.TEST} and results == [("ok", "1", "0")]


def run_server() -> list[str]:
    """The component library's test of the server half, run alone with `--lib` and `--exact`. The server half is plain
    Rust with no runtime call, so the test drives it with the client protocol's bytes and prints what it answered."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    command = [
        "cargo", "test", "--target", target, "-p", "slime-components", "--no-default-features", "--lib",
        "--", "--exact", zenoh_server_exam.TEST, "--nocapture", "--test-threads=1",
    ]
    result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True, env={**_os.environ})
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    if not server_run_is_scoped(output):
        fail(f"server: the run was not of {zenoh_server_exam.TEST} alone")
    return zenoh_server_exam.exam_lines(result.stdout)


def server_main(controls_only: bool) -> int:
    """The server half of the client protocol: its answers are the bytes the schema's layout gives, and no answer is one
    the client refuses. The exam raises at the first line that differs, so a run that returns has matched every line."""
    exam = zenoh_server_exam
    test = exam.TEST
    alone = f"test {test} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
    library_and_integration = alone + "\ntest result: ok. 0 passed; 0 failed; 0 ignored\n"
    two_tests = f"test {test} ... ok\ntest other ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"
    other = "test other ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
    if not server_run_is_scoped(alone):
        fail("control: a run of the server test alone was read as not scoped")
    for label, text in (("a run that printed a second result", library_and_integration), ("a run of two tests", two_tests), ("a run of another test", other), ("an empty run", "")):
        if server_run_is_scoped(text):
            fail(f"control: {label} was read as scoped")
    try:
        positive, refusals = exam.judge(exam.good_lines())
        refused_controls = exam.all_controls()
    except (exam.ServerExamError, zenoh_client_wire_exam.WireError) as error:
        fail(str(error))
    if positive + refusals != SERVER_PINNED_CASES:
        fail(f"server: an honest transcript is {positive + refusals} cases, the checker pins {SERVER_PINNED_CASES}")
    if refused_controls != SERVER_PINNED_CONTROLS:
        fail(f"server: {refused_controls} controls, the checker pins {SERVER_PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 server judge: refused {refused_controls} corrupted records")
        return 0
    try:
        positive, refusals = exam.judge(run_server())
    except (exam.ServerExamError, zenoh_client_wire_exam.WireError) as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=server cases={positive + refusals} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 server check: the server answers each request with the bytes the schema gives and widens no grant")
    return 0


def service_component_main(controls_only: bool) -> int:
    """The component crate and its registration: declarations the files must hold. The controls run on synthetic files."""
    exam = zenoh_service_component_exam
    try:
        refusals = exam.component_controls()
        if controls_only:
            print(f"zenoh profile 0 service-component judge: refused {refusals} corrupted file sets")
            return 0
        cases = exam.check_component()
    except exam.ComponentExamError as error:
        fail(f"service-component: {error}")
    print(f"[zenoh-profile0] slice=service-component cases={cases} refusals={refusals} controls={refusals}")
    devloop_observations.record(casesObserved=cases, negativeControlsRefused=refusals)
    print("zenoh profile 0 service-component check: the crate, its registration and its library export are in place")
    return 0


SERVICE_BOOTED_CONTROLS = 63


def service_booted_main(controls_only: bool) -> int:
    """The composition and the booted exchange. The facts are read first. The arm then boots the image under QEMU and
    judges its marker chains, so a run that returns has seen the holders exchange through the service."""
    exam = zenoh_service_component_exam
    try:
        refusals = exam.composition_controls() + zenoh_service_arm.controls()
        if refusals != SERVICE_BOOTED_CONTROLS:
            fail(f"service-booted: {refusals} controls, the checker pins {SERVICE_BOOTED_CONTROLS}")
        if controls_only:
            print(f"zenoh profile 0 service-booted judge: refused {refusals} corrupted inputs")
            return 0
        cases = exam.check_composition()
    except (exam.ComponentExamError, zenoh_service_arm.ArmError) as error:
        fail(f"service-booted: {error}")
    arm = subprocess.run(
        [_sys.executable, str(ROOT / "scripts" / "check" / "check-sel4-io-network-plane.py"), "--arm", "zenoh-service"],
        cwd=ROOT, capture_output=True, text=True, env={**_os.environ},
    )
    if arm.returncode != 0:
        _sys.stderr.write((arm.stdout + arm.stderr)[-4000:])
        fail(f"service-booted: the zenoh-service arm exited {arm.returncode}")
    print(f"[zenoh-profile0] slice=service-booted cases={cases + 1} refusals={refusals} controls={refusals}")
    devloop_observations.record(casesObserved=cases + 1, negativeControlsRefused=refusals)
    print("zenoh profile 0 service-booted check: the holders exchanged through the service and an ungranted key was refused")
    return 0


GRANTS_TABLE_TEST = "every_table_decodes_to_its_rows_or_is_refused"
TABLE_LINE = re.compile(r"\[zenoh-exam\] (grantstable .*)$")


def grants_table_run_is_scoped(output: str) -> bool:
    """Whether the run was of the table test alone: it passed and nothing else in the target ran."""
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", output)
    return tests_passed(output) == {GRANTS_TABLE_TEST} and results == [("ok", "1", "0")]


def run_grants_table(tables_text: str | None = None) -> list[str]:
    """The proto crate's test of the table decoder, run alone with `--exact`. The slice writes the tables from the
    Python encoder to a file and the test reads them, so the decoder never judges bytes the Rust wrote. Run twice, on
    the tables and on the tables with one replaced, it shows the test reads the file: a test that prints constants
    prints the same lines both times."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True)
    target = next(line.split(": ", 1)[1] for line in host.stdout.splitlines() if line.startswith("host: "))
    (ROOT / "build").mkdir(exist_ok=True)
    scratch = _Path(tempfile.mkdtemp(prefix="zenoh-grants-table-", dir=ROOT / "build"))
    try:
        tables = scratch / "tables.txt"
        tables.write_text(zenoh_grants_table_exam.input_file_text() if tables_text is None else tables_text, encoding="utf-8")
        command = [
            "cargo", "test", "--target", target, "-p", "slime-proto", "--test", "zenoh_service_grants_table",
            "--", "--exact", GRANTS_TABLE_TEST, "--nocapture", "--test-threads=1",
        ]
        result = subprocess.run(command, cwd=ROOT / "components", capture_output=True, text=True, env={**_os.environ, "SLIME_GRANTS_TABLES": str(tables)})
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        _sys.stderr.write(output[-4000:])
        fail(f"{' '.join(command)} exited {result.returncode}")
    if GRANTS_TABLE_TEST not in tests_passed(output):
        fail(f"grants-table: the exam's test did not run and pass: {GRANTS_TABLE_TEST}")
    if not grants_table_run_is_scoped(output):
        fail(f"grants-table: the run was not of {GRANTS_TABLE_TEST} alone, so its lines cannot be attributed to it")
    return [match.group(1).strip() for line in result.stdout.splitlines() if (match := TABLE_LINE.search(line))]


def grants_table_main(controls_only: bool) -> int:
    if GRANTS_TABLE_TEST in tests_passed(""):
        fail("control: a run with the grants table test missing was read as complete")
    alone = f"test {GRANTS_TABLE_TEST} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
    two = f"test {GRANTS_TABLE_TEST} ... ok\ntest other ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored\n"
    other = "test other ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
    if not grants_table_run_is_scoped(alone):
        fail("control: a run of the grants table test alone was read as not scoped")
    if grants_table_run_is_scoped(two) or grants_table_run_is_scoped(other) or grants_table_run_is_scoped(""):
        fail("control: a run of more than the grants table test, or of another test, was read as scoped")
    try:
        zenoh_grants_table_exam.honest_cases()
        refused_controls = zenoh_grants_table_exam.all_controls()
        item_cases, item_controls = zenoh_grants_table_exam.item_pins()
        positive, refusals = zenoh_grants_table_exam.judge(zenoh_grants_table_exam.good_lines())
    except (zenoh_grants_table_exam.TableExamError, zenoh_client_exam.ClientError) as error:
        fail(str(error))
    if positive + refusals != zenoh_grants_table_exam.PINNED_CASES:
        fail(f"grants-table: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_grants_table_exam.PINNED_CASES}")
    if refused_controls != zenoh_grants_table_exam.PINNED_CONTROLS:
        fail(f"grants-table: {refused_controls} controls, the checker pins {zenoh_grants_table_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_grants_table_exam.PINNED_CASES:
        fail(f"grants-table: the admitted item fixes {item_cases} cases, the checker pins {zenoh_grants_table_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_grants_table_exam.PINNED_CONTROLS:
        fail(f"grants-table: the admitted item requires {item_controls} controls, the checker pins {zenoh_grants_table_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 grants-table judge: refused {refused_controls} corrupted records")
        return 0
    try:
        zenoh_grants_table_exam.check_generated()
        zenoh_grants_table_exam.check_exports()
        positive, refusals = zenoh_grants_table_exam.judge(run_grants_table())
        # The second run replaces one honest table. A test that read the file prints the probe table's line, and a test
        # that prints constants prints the first run's line again.
        zenoh_grants_table_exam.judge_probe(run_grants_table(zenoh_grants_table_exam.probe_file_text()))
    except (zenoh_grants_table_exam.TableExamError, zenoh_client_exam.ClientError) as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=grants-table cases={positive + refusals} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 grants-table check: the encoder, the generated records and the Rust decoder agree on every table")
    return 0


SERVICE_FILTER = "zenoh_service::"
SERVICE_TESTS = ("zenoh_service::the_service_exam",)


def run_service() -> list[str]:
    # The service core stands on the session's subscriptions and on the subscription id an event carries, so
    # the session exam, the links exam and, through it, the stock corpus and the stock-peer exam all run and
    # are judged here: a change to the session that the core needs may not move any of them.
    try:
        zenoh_subscribers_exam.judge(run_subscribers())
    except zenoh_subscribers_exam.SubscribersError as error:
        fail(str(error))
    stdout, output = cargo_tests((SERVICE_FILTER,), {**_os.environ})
    passed = tests_passed(output)
    missing = [name for name in SERVICE_TESTS if name not in passed]
    if missing:
        fail(f"service: the exam's tests did not run and pass ({len(missing)} of {len(SERVICE_TESTS)}): {', '.join(missing[:4])}")
    return exam_lines(stdout)


def service_main(controls_only: bool) -> int:
    neighbour_controls(subscribers=True)
    if all(name in tests_passed("") for name in SERVICE_TESTS):
        fail("control: a run with the service exam test missing was read as complete")
    try:
        refused_controls = zenoh_service_exam.all_controls()
        item_cases, item_controls = zenoh_service_exam.item_pins()
        positive, refusals = zenoh_service_exam.judge(zenoh_service_exam.good_lines())
    except (zenoh_service_exam.ServiceError, zenoh_grants_exam.GrantsError) as error:
        fail(str(error))
    if positive + refusals != zenoh_service_exam.PINNED_CASES:
        fail(f"service: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_service_exam.PINNED_CASES}")
    if refused_controls != zenoh_service_exam.PINNED_CONTROLS:
        fail(f"service: {refused_controls} controls, the checker pins {zenoh_service_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_service_exam.PINNED_CASES:
        fail(f"service: the admitted item fixes {item_cases} cases, the checker pins {zenoh_service_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_service_exam.PINNED_CONTROLS:
        fail(f"service: the admitted item requires {item_controls} controls, the checker pins {zenoh_service_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 service judge: refused {refused_controls} corrupted records")
        return 0
    try:
        positive, refusals = zenoh_service_exam.judge(run_service())
    except zenoh_service_exam.ServiceError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=service cases={positive} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 service check: the core serves each holder what its grants allow, tells a slow one what it lost, and refuses what it cannot serve")
    return 0


SERVICE_LINK_FILTER = "zenoh_service_link::"
SERVICE_LINK_TESTS = ("zenoh_service_link::the_service_link_exam",)


def run_service_link() -> list[str]:
    # The core over a link sits beside the session-based core and shares its type, so the session-based core's
    # exam runs and is judged here with the exams under it (`run_service` runs the subscribers exam, the links
    # exam and the stock-peer exam). A change that regresses the retained core fails this gate too.
    try:
        positive, refusals = zenoh_service_exam.judge(run_service())
    except zenoh_service_exam.ServiceError as error:
        fail(str(error))
    if positive + refusals != zenoh_service_exam.PINNED_CASES:
        fail(f"service-link: the retained service exam is {positive + refusals} cases, the checker pins {zenoh_service_exam.PINNED_CASES}")
    stdout, output = cargo_tests((SERVICE_LINK_FILTER,), {**_os.environ})
    passed = tests_passed(output)
    missing = [name for name in SERVICE_LINK_TESTS if name not in passed]
    if missing:
        fail(f"service-link: the exam's tests did not run and pass ({len(missing)} of {len(SERVICE_LINK_TESTS)}): {', '.join(missing[:4])}")
    return exam_lines(stdout)


def service_link_main(controls_only: bool) -> int:
    neighbour_controls(subscribers=True)
    if all(name in tests_passed("") for name in SERVICE_LINK_TESTS):
        fail("control: a run with the service-link exam test missing was read as complete")
    if all(name in tests_passed("") for name in SERVICE_TESTS):
        fail("control: a run with the retained service exam test missing was read as complete")
    # The retained core's judge and its controls are a precondition, as the neighbours' are. Its refusals are
    # not counted: they belong to the service gate, which pins them.
    try:
        retained_controls = zenoh_service_exam.all_controls()
        retained_positive, retained_refusals = zenoh_service_exam.judge(zenoh_service_exam.good_lines())
    except (zenoh_service_exam.ServiceError, zenoh_grants_exam.GrantsError) as error:
        fail(str(error))
    if retained_positive + retained_refusals != zenoh_service_exam.PINNED_CASES or retained_controls != zenoh_service_exam.PINNED_CONTROLS:
        fail(f"service-link: the retained service exam is {retained_positive + retained_refusals} cases and {retained_controls} controls, the checker pins {zenoh_service_exam.PINNED_CASES} and {zenoh_service_exam.PINNED_CONTROLS}")
    try:
        refused_controls = zenoh_service_link_exam.all_controls()
        item_cases, item_controls = zenoh_service_link_exam.item_pins()
        positive, refusals = zenoh_service_link_exam.judge(zenoh_service_link_exam.good_lines())
    except (zenoh_service_link_exam.ServiceLinkError, zenoh_grants_exam.GrantsError) as error:
        fail(str(error))
    if positive + refusals != zenoh_service_link_exam.PINNED_CASES:
        fail(f"service-link: an honest transcript is {positive + refusals} cases, the checker pins {zenoh_service_link_exam.PINNED_CASES}")
    if refused_controls != zenoh_service_link_exam.PINNED_CONTROLS:
        fail(f"service-link: {refused_controls} controls, the checker pins {zenoh_service_link_exam.PINNED_CONTROLS}")
    if item_cases and item_cases != zenoh_service_link_exam.PINNED_CASES:
        fail(f"service-link: the admitted item fixes {item_cases} cases, the checker pins {zenoh_service_link_exam.PINNED_CASES}")
    if item_controls and item_controls != zenoh_service_link_exam.PINNED_CONTROLS:
        fail(f"service-link: the admitted item requires {item_controls} controls, the checker pins {zenoh_service_link_exam.PINNED_CONTROLS}")
    if controls_only:
        print(f"zenoh profile 0 service-link judge: refused {refused_controls} corrupted records")
        return 0
    try:
        positive, refusals = zenoh_service_link_exam.judge(run_service_link())
    except zenoh_service_link_exam.ServiceLinkError as error:
        fail(str(error))
    print(f"[zenoh-profile0] slice=service-link cases={positive + refusals} refusals={refusals} controls={refused_controls}")
    devloop_observations.record(casesObserved=positive + refusals, negativeControlsRefused=refused_controls)
    print("zenoh profile 0 service-link check: the core queues through the link, delivers to its rings after the flush, and reports a frame the stream took and then lost")
    return 0


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
    parser.add_argument("--slice", choices=(*JUDGES, "composition", "xcheck", "stock", "links", "undeclare", "subscribers", "grants", "client", "client-wire", "client-io", "client-abort", "grants-table", "grants-reader", "server", "service-component", "service-booted", "service", "service-link"), required=True)
    parser.add_argument("--controls-only", action="store_true")
    arguments = parser.parse_args()
    if arguments.slice == "composition":
        return composition_main(arguments.controls_only)
    if arguments.slice == "xcheck":
        return xcheck_main(arguments.controls_only)
    if arguments.slice == "stock":
        return stock_main(arguments.controls_only)
    if arguments.slice == "links":
        return links_main(arguments.controls_only)
    if arguments.slice == "undeclare":
        return undeclare_main(arguments.controls_only)
    if arguments.slice == "subscribers":
        return subscribers_main(arguments.controls_only)
    if arguments.slice == "grants":
        return grants_main(arguments.controls_only)
    if arguments.slice == "client":
        return client_main(arguments.controls_only)
    if arguments.slice == "client-wire":
        return client_wire_main(arguments.controls_only)
    if arguments.slice == "client-io":
        return client_io_main(arguments.controls_only)
    if arguments.slice == "client-abort":
        return client_abort_main(arguments.controls_only)
    if arguments.slice == "grants-table":
        return grants_table_main(arguments.controls_only)
    if arguments.slice == "grants-reader":
        return grants_reader_main(arguments.controls_only)
    if arguments.slice == "server":
        return server_main(arguments.controls_only)
    if arguments.slice == "service-component":
        return service_component_main(arguments.controls_only)
    if arguments.slice == "service-booted":
        return service_booted_main(arguments.controls_only)
    if arguments.slice == "service":
        return service_main(arguments.controls_only)
    if arguments.slice == "service-link":
        return service_link_main(arguments.controls_only)
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
