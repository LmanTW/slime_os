# Add a gate

The previous pages taught you to change behavior and to add a component. This
page teaches you to *prove* either: how a QEMU plane gate is built, when you
are allowed to add one, and the exact files a new gate touches. It is the
missing half of every change here — code without an observing gate is a claim,
not a behavior.

The `verification-checkers` skill
([`.agents/skills/verification-checkers/SKILL.md`](../../.agents/skills/verification-checkers/SKILL.md))
is the rule, summarized under "Verification code discipline" in `AGENTS.md`; this page is
the walk-through. Read the rule first, because most of the time the correct
answer is **extend an existing gate**, not add one.

## What a gate is

Every `just sel4_*_check` and `just io_*_check` is the same four-part machine:

| Part | Owner | What it does |
| --- | --- | --- |
| **Closure** | `contracts/system-image-closure/v3/closures/<name>.zti` (generated) | Names every input the image is built from — the system spec, each component spec, each implementation tree, the root, the kernel prefix — by path. Resolved in the checkout before every build into `build/closure-resolved/<name>.zti`, whose identity is the derivation id. |
| **Image build** | [`scripts/lib/closure_image.py`](../../scripts/lib/closure_image.py) → `scripts/build/build-system-image.py` | Builds `build/closure/<name>/image.elf` (plus `root.elf`, `loader.elf`, `generation/`, `build-result.json`, `build-result.zti`) and reuses it while the derivation id and dirty flag match. |
| **QEMU run** | [`scripts/lib/sel4_plane.py`](../../scripts/lib/sel4_plane.py) `run_plane` | Boots the image on the pinned machine from `sel4/pins.toml`, collects serial until a terminal regex matches, a failure marker matches, QEMU exits, or the timeout fires. Optionally feeds one line of input after a readiness marker. |
| **Marker contract** | [`scripts/lib/sel4_gate_markers.py`](../../scripts/lib/sel4_gate_markers.py) `match_marker_contract` | Rejects any failure marker anywhere in the transcript, then requires each chain's markers in order. |

A plane checker `scripts/check/check-sel4-<domain>-plane.py` owns only what
is specific to its domain: the closure name, the expected fixture facts, the
chains, the failure markers, and the timeout. The smallest current one,
[`check-sel4-io-queue-plane.py`](../../scripts/check/check-sel4-io-queue-plane.py),
is about 150 lines and reads top to bottom as a specification:

```python
CLOSURE = "sel4-io-queue"
FIXTURE = ROOT / "contracts/generation-manifest/v1/compositions/sel4-io-queue.zti"
TIMEOUT = 240

CHAINS = (
    ("shared mapping and round trip", (
        r"SLIME_ROOT generation admitted number=49 executables=3 instances=3 grants=2 ",
        r"SLIME_GRAPH loan created task=\d+ slot=\d+ id=\d+ to=\d+ offset=0 length=4096",
        r"\[io-queue-driver\] round trip drained=4 echoed=4",
        r"\[io-queue-client\] round trip echoes=4 drained=all",
    )),
    # ... more causal chains ...
    ("malformed slice and terminal cleanup", (
        r"\[io-queue-client\] malformed slice refused before submission",
        r"\[io-queue-client\] io queue plane complete",
        r"SLIME_GRAPH loans served=\d+ loans=0 mappings=0 regions=0 orphans=0 quota=0",
        r"SLIME_GRAPH HEALTHY generation=49 required=3 live=0 completed=3 failed=0",
    )),
)

FAILURE_MARKERS = (
    r"SLIME_ROOT FATAL", r"SLIME_GRAPH FAIL",
    r"\[io-queue-client\] fail: ", r"\[io-queue-driver\] fail: ",
    r"Caught cap fault", r"Caught vm fault", r"panicked at ",
)
```

Three properties to notice:

- **Chains, not a flat list.** Each chain is one causal story; markers within
  a chain must appear in order, but chains are independent of each other. Two
  components racing to print completion belong in separate chains (or in
  `EXPECTED_UNORDERED`), never in one chain with a guessed order.
- **The last marker of the last chain is the terminal condition.** The run
  stops there. Cleanup and the final `SLIME_GRAPH HEALTHY` census belong at the
  end so the run cannot pass while tasks are still live.
- **Failure markers include the component's own `fail:` prefix.** A component
  that detects a wrong result prints `[name] fail: <why>` and the gate fails
  on it immediately, before order is checked.

## Decide: extend, add an arm, or add a plane

Answer in this order and stop at the first yes.

1. **Does an existing plane already boot the composition your change lives
   in?** Add markers to its chains (and the emitting code) — that is the common
   case for a behavior change. The gate's pinned counts (admitted executables,
   `HEALTHY required=…`) move with the graph; update them deliberately.
2. **Is it a new scenario over the same mechanism** (a negative case, a reset,
   a second holder)? Add an `--arm` to the owning checker and a new composition
   if the scenario needs one. `check-sel4-io-network-plane.py` is the model:
   six arms, one checker, several `just io_network_*_check` recipes.
3. **Is it a genuinely new mechanism or execution boundary** — a different
   device, a different input/output protocol, a subsystem with several
   independent checks? Only then add `scripts/check/check-sel4-<domain>-plane.py`.

Work items, backlog IDs, and individual regressions never justify a new
top-level checker on their own.

## Adding a plane, file by file

Suppose the mechanism is new and you have decided on a plane named
`sel4-widget`. The files, in dependency order:

### 1. Components and their specs

The probe components live under `components/testkit/<name>/` (verification
workers) or `components/services/` (a real service under test), each with a
`contracts/component-spec/v1/components/<name>.zti`. Their `test` block must
point at the recipe you are about to create and at a literal the checker
will assert:

```
test = {
  testCondition = "the widget_check gate boots the sel4-widget composition";
  expectedResult = "...";
  passFailCriteria = "[widget-probe] widget plane complete";
  requiredTestEnvironment = "widget_check";
};
```

`just component_spec_check` resolves `requiredTestEnvironment` against the
Justfile and `passFailCriteria` against the checker's string literals, so
the spec, recipe, and checker must land together.

### 2. System spec and derived manifest

Author `contracts/system-spec/v1/systems/sel4-widget.zti` (copy the nearest
plane spec — `sel4-io-queue.zti` is a good minimal one: three components, one
endpoint grant, three notifications). The spec file is the registration:
`DERIVED_GENERATION_FIXTURES` in
[`scripts/lib/system_spec.py`](../../scripts/lib/system_spec.py) reads the directory. Then:

```sh
python3 scripts/generate/generate-generation-from-spec.py
just system_spec_check
```

This writes `contracts/generation-manifest/v1/compositions/sel4-widget.zti`.
Pick a `generation` number no other spec uses; the checker will pin it.

### 3. Closure

```sh
python3 scripts/generate/generate-system-image-closures.py
```

emits `contracts/system-image-closure/v3/closures/sel4-widget.zti` from the
derivation map. Commit it. `just system_image_builder_check` refuses drift.

### 4. Checker

Create `scripts/check/check-sel4-widget-plane.py` by copying the io-queue
checker and replacing the constants. Keep `check_fixture()` — it pins the
generation number and the instance and notification names, so a
composition edit that silently drops a participant fails before QEMU
starts. Keep `build_image()` unchanged; it is the closure seam.

### 5. Recipe

Add to the matching `just/planes-*.just` file (mechanism, runtime, fabric,
storage), in its group, depending on `sel4_pin_check`:

```just
[group('planes / mechanism')]
widget_check: sel4_pin_check
    python3 scripts/check/check-sel4-widget-plane.py
```

A doc comment on the line above the attribute becomes the recipe's
description in `just --list` and in the
[recipe reference](../reference/just-targets.md).

### 6. Gate control

Add one row to `GATES` in
[`check-sel4-gate-controls.py`](../../scripts/check/check-sel4-gate-controls.py):

```python
("sel4_widget_plane", "check/check-sel4-widget-plane.py", <marker count>),
```

The count is the total number of markers across your chains, pinned by hand
so that deleting a marker later is a visible diff rather than a silent
weakening. `just sel4_gate_control_check` then synthesizes a transcript from
your chains and proves your checker rejects it when a marker is deleted,
reordered, or poisoned with a failure marker. This is the step people forget;
CI runs it on every change.

### 7. Run it

```sh
just <your new recipe>   # widget_check in this example
just sel4_gate_control_check
just component_spec_check
just docs_check          # the new recipe name is now referenced from docs
```

Then add a row for the recipe to
[`docs/reference/just-targets.md`](../reference/just-targets.md) — every
public recipe has one; a recipe that should not be listed is private
(`_name`) — and add it to the owning `docs/architecture/` page's
"Verification" list if it is a gate other people will be routed to.

## Writing good markers

- Prefix component markers with `[<component>] ` and root markers with
  `SLIME_ROOT ` / `SLIME_GRAPH `; the failure patterns and the walkthrough
  rely on those prefixes.
- Put the *numbers* in the marker (`drained=4 echoed=4`, `leases=2`) and pin
  them in the regex. A marker that only says "done" proves the code reached a
  line, not that it computed the right thing.
- Use `\d+` for task ids and slots the root assigns, and exact values for
  everything the composition declares.
- Each negative case gets its own marker (`... refused`, `... rejected`), and
  the checker must also list the corresponding success-of-the-wrong-thing as
  a failure marker where one exists.
- Never weaken an assertion to recover green: not to an unordered search, not
  to a looser regex, not to an optional marker. If the order genuinely is not
  causal, move the marker to `EXPECTED_UNORDERED`.

## Bind it to a work item

A gate is evidence only when an item or an area requirement binds it. Name the
recipe in an acceptance, `h.observed "widget_check"`, and land the checker,
the recipe and the item together in a planning PR. From that merge the
recipe is a bound target. Its grader set is frozen for implementation PRs
(V3), and a later change to it needs a V4 approval. See
[Carrying a work item](06-work-item-lifecycle.md).

A checker may report counts and flags beside its exit status. It calls
`record(...)` in
[`scripts/lib/devloop_observations.py`](../../scripts/lib/devloop_observations.py),
and `scripts/spec/record` copies the values into the record. An acceptance
reads them through predicates:
`h.observedWhere "widget_check" { h.atLeast "negativeControlsRefused" 3; }`.

## Where CI fits

The PR workflow does not boot the QEMU planes. It runs the pins, host tests,
formatting, clippy, contract and closure drift checks,
`sel4_gate_control_check`, `docs_check`, and the spec judge. That is why the
gate-control row matters: it is the only part of your gate a PR run exercises.

After the planning PR merges and the item is `#active`, the `Evidence`
workflow runs the bound recipe on `main`. It writes a signed record to the
`evidence` branch, keyed by the recipe's closure digest. Locally,
`just spec_record widget_check` runs the recipe the same way and writes
`build/observations/widget_check.zt`. The workflow runs a target on an AArch64
runner, unless `[host]` in `specs/targets.toml` lists it under another host
class. A target listed under `operator` in
`specs/targets.toml` needs hardware CI does not have. An operator runs it with
`scripts/spec/record <target> --signer <principal> --key <key>`.

## Next

- [Debugging](08-debugging.md) — what to do when the gate you just wrote
  fails for a reason you did not expect.
- [Boot walkthrough](03-boot-walkthrough.md) — the root's own marker
  vocabulary, which every chain begins with.
