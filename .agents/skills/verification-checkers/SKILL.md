---
name: verification-checkers
description: Discipline for Slime OS verification code — when a new `scripts/check/check-*.py` is justified, where seL4 plane mechanism lives, how `just` targets map to checkers, and what an independent judge (host reference, capture reader, receipt comparator) and a pinned external artifact must guarantee. Use when adding or changing anything under `scripts/check/`, `scripts/lib/sel4_*`, an exam judge, a host reference decoder, a `just` recipe, or a negative-control set.
---

# Verification checkers

`AGENTS.md` keeps the two-sentence summary. This skill is the full rule set.

## When a new checker is justified

Do not create a new `scripts/check/check-*.py` merely because a change adds
an invariant or roadmap gate. Identify the verification mechanism that owns
the invariant, extend its checker when one exists, and add a case or module
when execution and evidence collection are shared.

Add a top-level checker only for a genuinely new mechanism or independently
reusable boundary:

- a different execution environment;
- a distinct input/output protocol;
- a stable subsystem boundary with multiple checks;
- independent reuse;
- materially different semantics.

Roadmap items, backlog IDs, compositions, individual regressions, and
individual QEMU planes do not by themselves justify top-level checker
executables. Public `just` targets remain narrow and descriptive; several
targets may invoke one checker with different cases (`--arm`, `--slice`,
`--controls-only`).

## seL4 planes

The shared mechanism lives in `scripts/lib/sel4_plane.py` (QEMU invocation,
transcript collection, common failures, control and mutation machinery) and
`scripts/lib/sel4_gate_markers.py` (marker chains and ordering). Each
`scripts/check/check-sel4-*-plane.py` owns only its concrete expectations for
boot, lifecycle, fabric, IO, storage, and similar domains.

Move repeated QEMU or transcript handling into those libraries rather than
copying it into a new plane script. Extract only observed repetition; do not
build a generic class-heavy test framework, and keep existing public gates.

## Independent judges

An independent judge — a host reference decoder, a capture reader, a receipt
comparator, a composition judge — must be at least as strict as the code it
judges on every boundary it claims:

- An input the Rust side refuses (non-canonical LEB128, an overflowing
  length, an unknown extension), the judge also refuses. A judge looser than
  the decoder accepts malformed wire evidence as proof.
- A frame, record, or ordering the exam says is excluded is checked by
  content, not by length, by protocol number alone, or by its first element.
  "No other address" means every ARP sender and target is parsed; "in the
  order sent" means every sample's position is checked, not sample 0's.
- A counted observation is counted from transcript or output evidence, not
  assigned from a literal or a configuration value the fixture already
  knows.
- Every positive assertion a product judge makes has a negative control
  that makes it fail: a missing marker, a reordered chain, an explicit
  failure marker, a wrong count, absent bytes, a wrong holder. An assertion
  with no control is unproven. A product judge asserts something about
  Slime OS behavior or a format, wire, or boundary it owns or reads; the
  gate-control suite that supplies the plane gates' controls counts as one.
  An assertion about verification or process tooling itself (the
  `scripts/spec/` judge, evidence recording, closeout and publication
  automation, CI selection, any test of a checker) needs no control. Adding one is a new
  exam and a human decision; see
  `docs/decisions/negative-controls-for-product-judges.md`.
- A gate that runs a subset of an exam (a `--slice`, an `--arm`) still runs
  the pinned corpus judge and the controls that protect what the subset
  relies on; an implementation must not be able to alter a pinned refusal
  on a path the narrower gate never looks at.
- A repository-owned record a judge consumes from outside (a listener's
  receipt) is read only through its Zutai contract's decoder. An externally
  specified capture (a PCAP, an Ethernet frame) has no Slime contract and is
  parsed directly by its standard's layout, as `scripts/lib/zenoh_capture.py`
  reads PCAP. Either way, its presence is recorded from the event that
  produced it, not from a poll that may miss a short-lived peer.

## Pinned external artifacts

A pinned external artifact (wheel, crate, image, toolchain) is verified by
hash on every run: `pip install --require-hashes --no-deps`, a checked
`sha256` on the file, a pinned revision in the lockfile. A cached environment
(`build/<exam>/venv`, a scratch directory) is rebuilt, never trusted from a
version string, a metadata file, or the directory's existence; the cost of a
rebuild is seconds, the cost of a forged cache is a false pass.

## Closures and recipes

A recipe under `just/` or `Justfile` is not a closure input, so adding or
editing one changes no derivation id. A closure source records paths only;
regenerate the sources
(`python3 scripts/generate/generate-system-image-closures.py`) only when a
closure's input set changes, in the same PR, in a derived commit. Test-run records and negative build cases name their
closure, so they do not change with it; re-freeze test-run records with
`just system_test_run_bless` only when a plane gate's execution inputs
change. `scripts/check/` and
`scripts/lib/` are not closure inputs except the files `RELEASE_INPUTS` in
`scripts/generate/generate-system-image-closures.py` names by path (today
`scripts/lib/elf_delivery.py` and the builders under `scripts/build/`); a
change confined to other checker or library files leaves the closures
current. Confirm either way with
`python3 scripts/generate/generate-system-image-closures.py --check`.

A checker, recipe, pin, or fixture in a target's closure changes that
target's closure digest, so the evidence recorded at the old digest no
longer counts. `just spec_closure --explain` lists what each bound target's
closure covers. Where the change lands depends on its `scripts/spec/check`
class:

- A grader file of a bound target (a script in its grader set, or a recipe
  in its closure) is a planning change. A generator that a bound recipe runs,
  such as `scripts/generate/generate-system-image-closures.py --check`, is in
  the grader set like a `scripts/check/` or `scripts/lib/` file.
  It needs a V4 approval, and an implementation PR may not touch it (V3). A
  grader that grades a promise changes only from a new item.
- A product pin or fixture such as `sel4/pins.toml` or
  `verification/zenoh-xcheck/Cargo.lock` is an implementation path. It
  ships under the `owns` of an item that is on `main` and `#active`.
- A `scripts/check/` or `scripts/lib/` file outside every grader set is a
  process path and needs no item.
