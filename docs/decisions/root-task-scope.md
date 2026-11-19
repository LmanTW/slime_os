# The root task keeps mechanism only, and its source has a target

**Status:** Accepted
**Decided by:** the project's human owner, 2026-11-17
**Amended:** 2026-11-18, by the owner: the fixture role leaves in two steps,
and a ceiling follows its implementation
**Related work item:** `root-size-budget`, UUID
`01a1e925-f21f-7c7b-8c45-b6b46bcefd1e`

## Context

`slime-root` holds every capability the kernel hands out at boot. A defect in
any root line can break every isolation claim the system makes.

`just root_size_check` gives each Rust file under `slime-root/` one role and
counts its code lines. A role is the group of files the gate budgets together.
On `main` at `41db01a`, the nine series roles hold 34294 code lines.

Three facts conflict with the rule that mechanism belongs in the root and
policy in components:

- The `policy` role holds 2077 lines.
- `slime-root/src/ipc.rs` names three product components: `entropy-service`,
  `zenoh-service` and `virtio-blk-driver`.
- `slime-root/src/graph_runtime.rs` and `slime-root/src/graph_runtime/` hold
  7427 code lines. Only the binary compiles them, so `just test_sel4_root`
  does not reach them.

## Decision

1. The root keeps a role only if one of two conditions holds. The role needs
   an authority no component may hold: untyped memory, the root CNode, or
   another task's TCB, VSpace or CSpace. Or the role runs before the first
   component exists.
2. A choice among outcomes that the generation allows is policy. A component
   makes that choice.
3. The root names no product component. It reads composition from generation
   rows.
4. The library compiles every root module, so host tests reach it.
5. The work continues in the existing repository. There is no rewrite.
6. The nine series roles reach 23000 code lines or fewer in two stages, as
   `root_size_check` counts them.

| Role | Lines | Decision | What stays in the root |
|---|---|---|---|
| core | 15037 | stays | all of it |
| boot | 5865 | stays | all of it |
| dispatch | 2538 | stays, without the readers that name product components | operation decoding and the service loop |
| policy | 2077 | leaves, to a supervisor component | the operations that policy invokes |
| timer | 1345 | leaves, to a timer component | the handover of the timer device and its IRQ |
| console | 427 | splits | the root's own diagnostic writer |
| fixture | 950 | leaves in two steps, see below | nothing |
| ioResource | 3029 | leaves in stage two | not decided |
| sharedBuffer | 3026 | leaves in stage two | not decided |

### Stage one: 28850 lines

The fixture, policy, timer and console roles leave. The dispatch role loses
its product-name readers. Test-only helpers that sit inside product items move
into `#[cfg(test)]` modules, where the gate counts them as test lines.

| Step | Lines |
|---|---|
| The series today | 34294 |
| fixture, policy, timer and console | −4799 |
| The readers in `ipc.rs`, lines 1036 to 1690 | −409 |
| Test-only helpers inside product items, about | −426 |
| The series with nothing left behind | 28660 |

The target of 28850 allows about 190 lines of what stays from the leaving
roles. The count of 426 comes from a one-off script and is approximate.

### How the fixture role leaves

The fixture role holds two parts, and they leave at different times.

| Part | Lines | What it is | When it leaves |
|---|---|---|---|
| `slime-root/child/` | 390 | the program of the fixture's child task. It is a crate of its own and runs without the root's authority. | first: the crate moved to `components/root-child/` in PR 1053 |
| `slime-root/src/fixture_runtime.rs` | 560 | the root side of the fixture. It runs with the root's authority. | after decision 4 holds |

The child crate cannot move to `components/testkit/`. `just
component_crate_split_check` holds every crate there to the shape of a
component, and the child is not one.

The root side shares the first part of `main` with the product: both run one
boot sequence and diverge after it. The fixture can become a root binary of its
own only when the library holds that sequence. Until then every root image,
the product included, links the fixture's root side and embeds the child image.

Three recipes boot the fixture through `scripts/check/check-sel4-root-boot.py`:

| Recipe | Platform |
|---|---|
| `just sel4_root_boot_check` | `qemu-arm-virt` |
| `just x86_64_sel4_root_boot_check` | `qemu-pc99` |
| `just riscv64_qemu_check` | `qemu-riscv-virt` |

The fixture stays the subject of all three. Only its place in the source
changes.

### Stage two: 23000 lines

The ioResource and sharedBuffer roles leave. Both map memory into another
task's VSpace, so a design under `docs/plans/` must be accepted first. Stage
two does not start before that.

28660 minus the 6055 lines of the two roles is 22605. The target of 23000
allows about 395 lines of what stays from every leaving role.

## Alternatives

- **Restructure without moving anything.** The trusted source stays the same
  size.
- **Stop after stage one.** The series ends near 28850 lines. This is the
  outcome if the stage-two design is rejected.
- **A target below 23000.** The `object_allocator` module and its tree hold
  8164 code lines. A lower target needs a simpler adaptive-memory model, which
  is a separate design decision.
- **A rewrite.** It would discard the QEMU evidence of every plane.

## Consequences

- Each leaving role gets its own work item. The item's acceptance bounds the
  role's count. A planning pull request lowers the role's ceiling in
  `scripts/check/check-root-size.py` after the implementation lands: CI runs
  the gate on every pull request, so a ceiling below the count on `main` would
  fail every one of them.
- A component that receives a role holds only the authority that role needs.
- Code that leaves the root stays in the trusted base of every component that
  depends on it. The line count measures the root's own source, not the
  system's trusted base.
- The count excludes the five crates the root links. The gate pins their
  names, so a sixth crate is a grader change.
- A timer wake no longer passes through the root once the timer role leaves.

## Revisit when

- What stays from the leaving roles exceeds the allowance of a stage. The
  owner then restates that stage's target.
- The stage-two design is rejected. The target then stays at 28850.
- A sixth crate enters the root's dependencies.
