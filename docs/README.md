# Slime OS documentation

Routing page. Nothing here is canonical on its own; every page below either
narrates or points at a source that is.

## If you are new

Read the root [`README.md`](../README.md) first — what Slime OS is, the five
first-class concepts, current status, and non-goals. Then:

0. [How work flows](getting-started/00-how-work-flows.md) — the whole
   process on one page: why each convention exists, which program enforces
   it, which path a process change, a bug, or a feature takes, and what an agent is
   doing when you hand it a task.
1. [Orientation](getting-started/01-orientation.md) — how to hold the project
   in your head, and where everything lives.
2. [Build and run](getting-started/02-build-and-run.md) — prerequisites,
   first boot under QEMU, and what the common failures mean.
3. [Boot walkthrough](getting-started/03-boot-walkthrough.md) — what actually
   happens between `just run` and the `SLIME_GRAPH HEALTHY` marker, and how
   the verification gates consume that serial record.
4. [Your first change](getting-started/04-first-change.md) — the workflow end
   to end: routing, gates, contracts, evidence, and owning documentation.
5. [Add a component](getting-started/05-add-a-component.md) — create the crate,
   declare it, compose it, grant authority, and prove it under QEMU.
6. [Carrying a work item](getting-started/06-work-item-lifecycle.md) — a
   `task/v2` item field by field: intents, areas and frozen promises, the
   evidence branch, done witnesses, the closeout bot, and the judge's rules.
7. [Add a gate](getting-started/07-add-a-gate.md) — how a QEMU plane gate is
   built from closure, image, run, and marker contract, when to extend versus
   add one, and every file a new plane touches.
8. [Debugging](getting-started/08-debugging.md) — reading a failed gate: which
   layer refused, the root's marker vocabulary, faults and silent panics,
   reproducing outside the checker.
9. [Write a contract](getting-started/09-write-a-contract.md) — `schema.zt` to
   generated bindings to validator to test to drift check.
10. [Component runtime tour](getting-started/10-component-runtime.md) — the
    `slime-rt` API by intent: lifecycle, output, finding capabilities, IPC,
    waiting, time, spawn and supervision, transfer, shared memory, heap.
11. [Recipes](getting-started/11-recipes.md) — "I want to change X": the
    files, the order, and the gate, for the common change kinds.

If you only read one page before editing, read the recipes; if a term stops
you, the [glossary](glossary.md) routes it to its owner.

## Concepts

The five first-class ideas, as mental models. These pages state invariants
only; every number, bit, label, and bound lives in the reference documents
below, which have update discipline these pages do not.

- [Components](concepts/components.md) — the isolation and fault-containment
  unit, and why it is not a process.
- [Capabilities](concepts/capabilities.md) — explicit, unforgeable,
  narrowing-only authority.
- [Channels](concepts/channels.md) — the two IPC paths, and capabilities in
  motion.
- [Contracts](concepts/contracts.md) — Zutai schemas as the only source of
  truth for every boundary-crossing format.
- [Generations](concepts/generations.md) — the atomic, rollbackable unit of
  deployment, including persistent state.

## Architecture

- [Subsystem architecture](architecture/README.md) — current IPC, fabric,
  time/waiting/lifecycle, private memory, component/image boundaries, target
  profiles, userspace I/O, the network service, generation management, and
  the trust model, with owning source and qualification limits.

## Operations

- [`operations/`](operations/README.md) — operator runbooks for evidence that
  automated gates can judge but not produce, starting with the Framework 13
  CPU boot.

## Reference

These two files are load-bearing and have update discipline: each must change
in the same commit as the surface it describes.

- [`capability-matrix.md`](capability-matrix.md) — the object-by-rights
  surface: every capability kind, every rights bit, every gate, every bound.
- [`syscall-abi.md`](syscall-abi.md) — the component ABI: operation labels,
  operand packing, reply convention, error model, CSpace layout.
  Label coverage is machine-checked by `just contracts_check`.

Two lookup pages without update discipline of their own:

- [`glossary.md`](glossary.md) — terms, each routed to its owner.
- [`reference/just-targets.md`](reference/just-targets.md) — every public
  `just` recipe by group, one line each.

## Decisions

- [`decisions/`](decisions/README.md) — important long-lived cross-module
  choices, including the accepted development-record ownership split. Decision
  records are not required per PR and carry no work-item state.

## Plans

- [`plans/`](plans/README.md) — unimplemented designs, delivery requirements,
  and qualification requirements, without work-item state.

## Exploration

- [`directions/`](directions/README.md) — the register of exploratory
  directions that follow from the vision but are not committed work.

## Everything else lives elsewhere

| Looking for | Go to |
| --- | --- |
| Work-item state: what is open, active, blocked, deferred | `just spec_tasks_status` over `.tasks/items/` and the `evidence` branch; promises with `just spec_status` |
| Current subsystem ownership and invariants | [`architecture/`](architecture/README.md); unfinished requirements in [`plans/`](plans/README.md) |
| Known defects and regressions (open ones precede milestone work) | Open `#bug` items in `.tasks/items/` and failing promises in `just spec_status`; `specs/legacy.zt` indexes the earlier store |
| How userspace drivers receive device/MMIO/IRQ/DMA authority, and what IO gates prove | [Userspace I/O substrate](architecture/io-substrate.md); the authority surface is in [`capability-matrix.md`](capability-matrix.md) and operations in [`syscall-abi.md`](syscall-abi.md) |
| How a historical conclusion was reached | [Private history archive](history.md), pinned by full commit and original path; ordinary changes need no investigation |
| Code map | [`AGENTS.md`](../AGENTS.md); the routing table itself is [`task-to-file.md`](task-to-file.md) |
| The schemas every persisted or cross-process format is generated from | `contracts/`; a few carry their own `README.md` (`network-service`, `network-application`, `network-destination`, `system-spec`) when authority semantics need prose |
| Build, test, and gate commands | `Justfile` (`just --list`); one line per recipe in [`reference/just-targets.md`](reference/just-targets.md) |
| Retained physical evidence (Duo, Framework CPU boot) | `evidence/`, each record bound to an exact image identity and judged by its gate; the [runbooks](operations/README.md) say how a record is produced |
| What is trusted and what is not enforced | [Trust model](architecture/trust-model.md) |
