# The root task keeps mechanism only, and a gate bounds its source

**Status:** Accepted
**Decided by:** the project's human owner, 2026-11-17
**Amended:** 2026-11-18, by the owner: the fixture role leaves in two steps,
and a ceiling follows its implementation
**Amended:** 2026-11-22, by the owner: the policy role and the timer role
stay, the console dispatcher stays until a design moves it, and both targets
are withdrawn until the owner restates them from a measured count
**Amended:** 2026-11-23: the ioResource and sharedBuffer roles stay, stage two
is withdrawn, and the gate's ceilings replace the target in lines. The owner
accepted the ceilings in conversation. The other points are agent defaults
under the owner's standing instruction of 2026-11-19, and the owner's merge
accepts them
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

The amendment of 2026-11-22 withdraws the numbers of point 6. It also replaces
three rows of the table below: policy, timer and console. The amendment of
2026-11-23 replaces point 6 and the rows of ioResource and sharedBuffer.

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

The amendment of 2026-11-22 withdraws this target. This section states the
plan as the owner decided it on 2026-11-17.

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

### What stage one has reached

The series holds 32899 code lines on `main` after PR 1145. The gate's ceiling
is 32950.

| Step | State |
|---|---|
| fixture | Out of the series since PR 1107. |
| The root names no product component | Done in PR 1117. `just root_size_check` counts 0 string literals that name a product component; it counted 6. |
| The readers in `ipc.rs` | They stay. The builder states who reads a table, and the root answers from the generation's reader table. The dispatch role holds 2514 lines. |
| policy and timer | They stay, by the amendment of 2026-11-22. The timer role grew to 1435 lines in PR 1118, which added the backend for the BCM2835 system timer. |
| The sort of the policy role | Done in PR 1145. The gate names the role `enforcement`, and it holds 1706 lines. The clock requests count as timer, which holds 1612. The reclaim of a dead task counts as core, which holds 14925. The sort added 6 lines to the series. |
| console | It stays, by the amendment of 2026-11-22, until a design moves the dispatcher. |
| Test-only helpers inside product items | Done in PR 1138. 37 functions with 301 code lines stand in `#[cfg(test)]` blocks. 125 lines of fields and statements stay inside product items. |

The row of 409 lines in the table above assumes that the readers leave the
root. PR 1117 removed the names and kept the readers. A later design decides
how a component reads its own rows without a reader in the root. If the
allowance of stage one does not cover the difference, the owner restates the
target.

### Amendment of 2026-11-22: the policy and timer roles stay

A survey read the three roles that stage one has leave the root. Most of their
lines meet condition 1 of the decision, and the rest decide nothing that a
component could decide in their place. The owner decides:

1. The policy role and the timer role stay in the root.
2. The dispatcher of the console role stays until the owner accepts a design
   under `docs/plans/` that moves it. This amendment plans no such design.
   The root's own diagnostic writer stays in every case.
3. The targets of 28850 and 23000 lines are withdrawn. The owner restates
   both from a measured count, after the step of the test-only helpers.
4. The gate sorts the files of the policy role again, so that the name of a
   role states what it holds. That moves lines between roles and takes none
   out of the root.

The counts below are code lines, as `just root_size_check` counts them, on
`main` at `7e93cf4e`.

| Part of the policy role | Lines | Finding |
|---|---|---|
| `notification.rs`, `wait_set.rs` | 337 | They allocate Notification objects from untyped memory, mint badged capabilities in the root CNode, and copy one into a child's CNode. Condition 1 keeps them. |
| `scheduling.rs` | 179 | A promotion calls `tcb_set_priority` on another task's TCB, with the root's TCB as the authority. Condition 1 keeps it. |
| `lifecycle.rs`, and its requests in `services/policy.rs` | 709 | The root records why an instance ended and refuses a restart that the generation does not admit. It decides no restart. |
| `directory.rs` | 337 | The console thread serves two of its three operations. The design of the console dispatcher decides where they go. |
| Reclaim and memory census in `services/policy.rs` | 165 | Task teardown. It is core mechanism. |
| Clock requests in `services/policy.rs` | 187 | They serve the timer role. |
| Supervision and scheduling requests in `services/policy.rs` | 155 | Request decoding for the parts above. |

PR 1145 took the sort of decision 4, and the table above states the parts as
they stood before it. The sort moved 176 lines of clock requests and 187 lines
of reclaim: `record_termination` went with the reclaim, and
`signal_declared_death` stayed with the wait sets. The gate now names the role
`enforcement`.

The policy role held 2069 lines. Decision point 2 already holds for it: a
component with supervision authority decides a restart, waits and spawns.
`robot-supervisor` and `lifecycle-restart-probe` do so today.

`lifecycle.rs` does not move for one reason. `SPAWN` reads the attempt count
and the backoff instant of an instance in the same step that creates the task.
The module states the rule: a supervisor that skips its wait is refused, not
trusted. A component that held those counts would have to be trusted.

The timer role held 1435 lines before the sort. It does not move, for four
reasons:

- The root proves its timer in the boot sequence, before a component exists.
- The root uses the timer queue itself. One slot is reserved for its cleanup
  retries, and restart admission and the spawn backoff read the clock.
- The timer's Notification is bound to the root's service thread, so requests
  and timer delivery share one blocking point and no wake is lost. A component
  runs at priority 254 or below, and the root above it. A timer component
  would not preempt the other components.
- On RISC-V, on x86-64 and in a Raspberry Pi 5 system-timer image, the root
  answers `CLOCK MONOTONIC READ` for every task.

A timer component would therefore add a second clock and remove none.

The console role holds 443 lines:

| Part of the console role | Lines | Decision |
|---|---|---|
| `console.rs`, `graph_runtime/console_runtime.rs` | 300 | The dispatcher: a second root thread that serves debug writes, terminal input and two directory operations. It stays until a design moves it. |
| `diagnostic.rs`, `graph_runtime/services/diagnostic_once.rs` | 143 | The root's own writer and its once-per-key filter. They stay. |

The dispatcher does not move now, for four reasons:

- A record is whole on the wire because its producer holds a FIFO ticket,
  and `diagnostic.rs` states that the ticket's waiting rule needs every
  producer to be a root thread at one priority: a waiter yields, and a yield
  never schedules an owner of lower priority. A component cannot be a
  producer under that rule.
- The root owns its console UART on one target profile,
  `aarch64-sel4-qemu-virt`. On every other profile its writer calls the
  kernel's debug console. No component drives the console UART. A component
  for a 16550 UART exists, `uart16550-driver`, and this tree gives it a line
  on no platform.
- The dispatcher maps a caller's frame into the root's VSpace to copy a
  payload, and it reads the root's authority tables for terminal input and
  for the two directory operations. No component can do either.
- `just console_record_check` compiles the dispatcher's write path on the
  host and pins the bytes of the component runtime's transport. Its own text
  says that a change of those pins needs a new exam. The plane checkers read
  component lines and root lines in one transcript and rely on their order.

A move is therefore a design of its own, for about 300 lines. The owner
weighs it when one exists.

Stage one therefore had one step left: the test-only helpers inside product
items. PR 1138 took it. `main` held 426 code lines behind a `#[cfg(test)]`
inside a product item. 301 of them were whole functions, and the step moved
those. The other 125 are fields and statements, which cannot leave their item.
The series held 32893 lines after the step, and holds 32899 after the sort of
decision 4.

The lines that a later decision can still move are in stage two, and in
the 7929 lines of `object_allocator` that the alternatives below name.

One consequence below no longer holds: a timer wake keeps passing through the
root.

### How the fixture role leaves

The fixture role holds two parts, and they leave at different times.

| Part | Lines | What it is | When it leaves |
|---|---|---|---|
| `slime-root/child/` | 390 | the program of the fixture's child task. It is a crate of its own and runs without the root's authority. | first: the crate moved to `components/root-child/` in PR 1053 |
| `slime-root/src/fixture_runtime.rs` | 560 before PR 1107, 1007 after | the root side of the fixture. It runs with the root's authority. PR 1107 moved 440 lines of `main` into it. | second: PR 1107 put its module behind `cfg(slime_root_fixture)` |

The child crate cannot move to `components/testkit/`. `just
component_crate_split_check` holds every crate there to the shape of a
component, and the child is not one.

The root side shares the first part of `main` with the product: both run one
boot sequence and diverge after it. The fixture can become a root binary of its
own only when the library holds that sequence. Until then every root image,
the product included, links the fixture's root side and embeds the child image.

PR 1068 moved that sequence and the graph runtime into the library, as
`slime_root::boot::run` and `slime_root::graph_runtime`. The binary alone now
compiles `slime-root/src/main.rs` and `slime-root/src/fixture_runtime.rs`, 1119
code lines.

PR 1107 made the fixture a root build of its own. `slime-root/src/main.rs`
declares `fixture_runtime` behind `cfg(slime_root_fixture)`, and
`slime-root/build.rs` sets that cfg for the fixture root alone. A product root
compiles 124 code lines of the binary and embeds no child image. The package
keeps one binary target, because both console audits hold the one install call
to `slime-root/src/main.rs`. `just root_size_check` leaves the 1007 lines that
only the fixture root compiles out of the series, which holds 33073.

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

The amendment of 2026-11-22 withdraws this target. The arithmetic above
starts from 28660, which stage one no longer reaches. From 32899, the two
roles leave about 26844, which is above 23000. The owner restates this target
with that of stage one.

The amendment of 2026-11-23 withdraws stage two: both roles stay.

### Amendment of 2026-11-23: the ioResource and sharedBuffer roles stay

A survey read the two roles that stage two has leave the root. No part of
them can move unless the root trusts a component with another task's VSpace.
Condition 1 names that authority as one no component may hold. The amendment
decides four points. The owner accepted point 3 on 2026-11-23:

1. The ioResource role and the sharedBuffer role stay in the root.
2. Stage two is withdrawn. No design under `docs/plans/` is written for it.
3. The series has no target in lines. The ceilings of
   `scripts/check/check-root-size.py` hold what the series has reached: 32950
   for the series, and one ceiling for each role. A ceiling goes down when
   lines leave. It goes up only in a planning pull request whose item states
   why.
4. Functions of the two roles that no product code calls leave the root, or
   move into test items. They hold about 90 lines, and they have no item yet.

One ceiling does not yet hold what its role has reached. The ceiling of the
role `enforcement` is 2100, and the role holds 1706 lines since PR 1145. A
planning pull request lowers it. Until then that role may grow by 394 lines
within the ceiling of the series.

The counts below are code lines, as `just root_size_check` counts them, on
`main` at `4408d49b`.

| File of the ioResource role | Lines | Finding |
|---|---|---|
| `io_resource.rs` | 1534 | The table of device grants, mappings, DMA accounts and requests. It calls no kernel operation and names no other root module. It decides each effect, and the trait `IoResourceAdapter` carries the effect out. |
| `graph_runtime/services/io_resource.rs` | 808 | The adapter and the request handlers. The adapter maps a device frame and its page tables into the caller's VSpace, retypes contiguous memory for a queue, and creates an IRQ handler. Condition 1 keeps it. |
| `device.rs` | 658 | It retypes device untyped memory, maps a frame into a child's VSpace, and binds an IRQ handler to a Notification. The boot sequence uses it for the console, the timer and the device scan, before the first component. Both conditions keep it. |
| `irq_control.rs` | 29 | It invokes the IRQ control capability. Condition 1 keeps it. |

| File of the sharedBuffer role | Lines | Finding |
|---|---|---|
| `shared_buffer.rs` | 1668 | The table of regions, mappings, loans and charges. It calls no kernel operation. It decides each effect, and the trait `SharedBufferAdapter` carries the effect out. |
| `buffer_adapter.rs` | 551 | The adapter. It retypes frames, maps and unmaps them in another task's VSpace, and copies, revokes and deletes capabilities in the root CNode. Condition 1 keeps it. |
| `graph_runtime/services/capability.rs` | 807 | The request handlers. An export mints an Endpoint capability in the root CNode and copies it into the sender's CNode. The buffer requests drive the adapter with the caller's VSpace capability. Condition 1 keeps it. |

The two tables hold 3202 of the 6055 lines, and neither calls the kernel.
They do not move for one reason. A table decides which frame enters which
VSpace, for which holder, and within which declared bound. The adapter then
does what the table decided. A component that held a table would direct how
the root uses another task's VSpace. The root would have to trust that
component, or keep a table of its own to check it. The amendment of
2026-11-22 kept `lifecycle.rs` for the same reason.

Two more facts tie the tables to the root:

- A change is one transaction. The table plans it, the adapter acts, and the
  table commits it or rolls it back. A table in a component would split that
  transaction across two tasks.
- The retirement of a dead task runs in the root's service loop. Its phases
  call `reclaim_driver` and `reclaim_dead_task`, and each phase waits for the
  one before it.

One model would let these lines leave: a component holds its own VSpace and
its frames as kernel capabilities, and maps a shared frame itself. The kernel
then checks the rights, and the root mediates no mapping. The receiver of a
large sample makes four root calls today, and would make none. That model
changes condition 1, the runtime of every component and the accounting of
every quota. It is a direction, and this decision does not take it.

## Alternatives

- **Restructure without moving anything.** The trusted source stays the same
  size.
- **Stop after stage one.** The series ends near 28850 lines. This is the
  outcome if the stage-two design is rejected. Since the amendment of
  2026-11-22 the series ends at 32899.
- **A target below 23000.** The `object_allocator` module and its tree hold
  7929 code lines after PR 1138, without `qualification.rs`, which the gate
  counts in the harness role. They held 8164 before. A lower target needs a
  simpler adaptive-memory model, which is a separate design decision.
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
  owner then restates that stage's target. This happened for stage one on
  2026-11-22.
- The verified kernel profile lands. The kernel then exports no generic timer
  to EL0, and the owner weighs a timer component again.
- A design under `docs/plans/` moves the console dispatcher. The owner then
  decides whether it leaves.
- The stage-two design is rejected. The series then stays where stage one
  ends. The amendment of 2026-11-23 withdraws stage two before a design is
  written.
- A direction is accepted in which a component holds its own VSpace and its
  frames. The owner then weighs the ioResource and sharedBuffer roles again.
- A sixth crate enters the root's dependencies.
