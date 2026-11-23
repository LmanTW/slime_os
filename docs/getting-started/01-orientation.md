# Orientation

One page of bearings before you build anything. The root
[`README.md`](../../README.md) is the canonical statement of vision, status,
and non-goals; this page only tells you how to hold the project in your head.

## What you are looking at

Slime OS is an experimental capability-based operating system: a Rust
`no_std` userspace graph running on the upstream seL4 microkernel. It is not
a Linux distribution, not a Unix clone, and not trying to become either —
POSIX-shaped things (paths, environment, fork, signals, ambient authority)
are deliberately absent from the native model.

The system is built from five first-class concepts, each with a concept page:

| Concept | One line | Page |
| --- | --- | --- |
| Component | isolated, versioned executable; fault containment unit | [components](../concepts/components.md) |
| Capability | unforgeable, explicit, narrowing-only authority | [capabilities](../concepts/capabilities.md) |
| Channel | typed IPC that can carry capabilities | [channels](../concepts/channels.md) |
| State | owned, schema-versioned persistent data | in [generations](../concepts/generations.md) |
| Generation | the whole bootable graph as one atomic, rollbackable artifact | [generations](../concepts/generations.md) |

One cross-cutting rule binds them: every format that crosses a process,
persistence, or boot boundary is a versioned Zutai schema under `contracts/`,
with all bindings generated from it — see
[contracts](../concepts/contracts.md) before you write any wire code.

## How to orient in the tree

Three files answer most "where is..." questions:

- [`AGENTS.md`](../../AGENTS.md) — the code map: execution path, generated-code
  rule, and navigation traps — and [`docs/task-to-file.md`](../task-to-file.md),
  the index routing every kind of change to its owning module.
- `Justfile` — every build, run, check, and regeneration command
  (`just --list`).
- `just spec_tasks_status` — each work item's state, derived from the
  `evidence` branch, and `just spec_status` — each area promise's state. Items
  live in `.tasks/items/`, promises in `specs/<area>.zt`. Open backlog bugs
  come before milestone work. `scripts/spec/check` enforces it (V7).
- [`docs/plans/`](../plans/README.md) — unimplemented designs and requirements.
  A plan records no state and owns no problem statement. Each item owns its own.

## The house epistemology

Two habits distinguish this repository; adopting them early saves friction:

- **Evidence over intention.** A behavior exists when the owning gate observes
  it on the required surface, not when code for it lands. Gates fail closed:
  missing hardware evidence is a failing check, never a skip. The PR records
  the claim, exact verification, evidence class, identity, and limits; the work
  item records the exit conditions actually observed. Historical investigations
  are supporting records, not the live state store.
- **Refusal over accommodation.** Malformed data, wrong-target binaries,
  superseded formats, unknown operations, unbudgeted requests — all are
  refused at the boundary rather than tolerated, migrated, or guessed at.
  When you meet a check that seems obstinate, it is usually load-bearing.

## Suggested path

1. [Build and run](02-build-and-run.md) — get a boot on your machine.
2. [Boot walkthrough](03-boot-walkthrough.md) — understand what you saw.
3. The five concept pages, in table order above.
4. [Your first change](04-first-change.md) — the workflow, end to end.
5. [Add a component](05-add-a-component.md) — take new code through
   declaration, composition, authority, and QEMU evidence.
6. [Carrying a work item](06-work-item-lifecycle.md), then the proving half:
   [add a gate](07-add-a-gate.md) and [debugging](08-debugging.md).
7. When you know what you want to change, go straight to
   [recipes](11-recipes.md); the [component runtime tour](10-component-runtime.md)
   and [write a contract](09-write-a-contract.md) are the two reference walks
   most changes need.
