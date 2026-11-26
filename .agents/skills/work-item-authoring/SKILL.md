---
name: work-item-authoring
description: Pre-flight procedure for writing a task/v2 work item and its planning PR — bind every requirement clause to a judge line, prove each acceptance fails today and can pass, make each negative control reach the assertion it names, derive `owns` by probe, supersede the promises the change makes false, keep restated counts equal to the grader, and state the path to `#active`. Use before opening or revising a planning PR, when writing or editing `.tasks/items/*.zt`, when adding an exam for a new item, or when planning a repair item for a landed exam. For the audit of an implementation PR against a landed item, use `spec-review`.
---

# Work-item authoring

An exam freezes when its planning PR merges. V3 bars the implementation PR
from the grader set. A gap found after the merge costs a new item and a new
planning PR. Run every check on this page before the planning PR opens, and
again before each push.

Other texts own the neighboring rules. This skill does not restate them.

| Text | Owns |
|---|---|
| [`06-work-item-lifecycle.md`](../../../docs/getting-started/06-work-item-lifecycle.md) | The item fields, the intents, and V1 to V11 |
| [`verification-checkers`](../verification-checkers/SKILL.md) | When a checker is justified and how strict a judge must be |
| [`writing-style`](../writing-style/SKILL.md) | How the sentences of an item and a PR body are written |
| [`spec-review`](../spec-review/SKILL.md) | The audit of an implementation PR against a landed item |
| [`pr-review`](../pr-review/SKILL.md) | What a finding is and how an author answers one |

## Order of work

1. Draft the implementation, or a probe of it, outside the planning PR.
2. Write each requirement from what the exam can observe.
3. Write the exam and its negative controls.
4. Derive `owns` from the draft.
5. Find the promises and the neighbor targets the change touches.
6. State the path to `#active`.
7. Run the pre-flight, then open the PR.

## 1. Draft before the exam freezes

- Write a draft of the implementation, or at least one probe test, before
  the planning PR opens. Run the exam against it.
- Do not commit the draft. V1 refuses product code in a planning PR.
- Run the checker's launch path and read path against the real tool or
  artifact: QEMU output, a stock peer, a `ros2` command. A synthetic
  transcript does not prove the reader.
- Derive each pinned number and each bound from arithmetic or from a measured
  run. Confirm that the thing the acceptance bounds controls the number.
- Confirm that no two scenarios of the exam contradict each other, and that
  each pinned refusal is reachable.
- State in the PR body what the draft did not run.

## 2. Every clause has a judge line

Build this table before writing the exam, and keep it in the PR body.
`spec-review` builds the same table after the implementation, when the exam
can no longer change.

| requirement | clause in the statement | judge file:line that fails when the clause is false |
|---|---|---|

- List every quantifier (`each`, `every`, `all six`), every order word
  (`before`, `after`, `once`), and every negative (`no`, `nothing`,
  `unchanged`, `stays`) as its own clause.
- A clause with no judge line has three legal outcomes: the judge gains the
  line, the statement loses the clause, or a `nonGoals` entry names the
  clause as unobserved.
- The judge must read an independent record. A line the subject prints about
  itself is not evidence of the claim.
- If the statement claims an order or a count of repeats, the judge must
  check the order and the repeats. A set of facts is not enough.
- The product test must receive the exam's input. A test that never sees the
  input can print constants and pass.
- The exam must refuse no transcript that the requirements accept. An exam
  stricter than its item cannot pass as landed.
- Use the item's operation names as the judge's labels.
- A decision that binds a requirement follows the same rule as a statement.

## 3. Each acceptance fails today and can pass

- Run every bound target on `main`. A target that a requirement for new
  behavior binds must fail, and fail on the behavior that requirement names.
- A requirement that existing behavior stays unchanged may bind a passing
  target. Give it its own requirement.
- An item whose mandatory targets all pass today lets activation alone
  produce a done witness. Add an `h.observedWhere` predicate or a marker
  that the work must produce.
- For a bug whose targets pass with the defect in place, ask the human. One
  accepted answer is a mandatory `h.human` acceptance, bound by its own
  requirement, with the decision recorded as `h.fromHuman`.
- Bind the narrowest recipe that asserts the claim. An aggregate recipe can
  be red for a reason the item does not own.
- Confirm with `just spec_closure --explain` that each bound target runs the
  checker its requirement names.
- Confirm that the `Evidence` runner can run the target. The default runner
  is AArch64. `specs/targets.toml` lists the other host classes under
  `[host]` and the operator targets under `operator`.
- If the runner cannot build a mandatory target, ask the human. One accepted
  answer is `h.advisory` on that acceptance.
- Declare a regression target that is red on `main` between the planning
  merge and the implementation. A declared window is a limit, not a defect.

## 4. Each control reaches the assertion it names

These rules bind a product judge. Verification and process tooling needs no
negative control, by
[decision](../../../docs/decisions/negative-controls-for-product-judges.md).

- Delete each assertion of the judge in turn. At least one control must stop
  being refused each time.
- Print the refusal reason of every control. The reason must name the rule
  that the control's label names.
- Make the control builder refuse a mutation equal to the honest transcript,
  and one equal to another control.
- Do not pin a fact of the tree that another PR will change.
- Fix a control gap inside the planning PR. The exam freezes at the merge.
- Move the pinned `negativeControlsRefused` count in the same push as the
  controls.

## 5. Derive `owns` by probe

- In the draft, add the new variant, field, or module. Compile every crate
  and test that names the changed type. List each file that fails.
- Add each regenerated binding, each by-path dependent, and each test or
  comment that restates a moved constant or path.
- Exclude every file in a grader set. `just spec_closure --explain` lists
  them. V3 refuses such a file in an implementation PR.
- Exclude `docs/`. The judge classes it as process, so it rides its own PR.
- A regenerated file that is also a grader cannot ride the implementation
  PR. Plan the PR that lands it, and state the merge order.
- Keep `owns` no wider than the draft needs. A glob over every composition
  lets V2 accept work that nobody planned.
- Read `owns` against `nonGoals`. An item must not own a path that its
  non-goals exclude.
- If another open item owns the same paths, declare `depends` or state the
  order.
- `owns` must not be empty. An item whose whole change lands in graders owns
  one product path and declares in the PR body that it changes nothing there.

## 6. Promises and neighbor targets

- Search `specs/` and `.tasks/terminal/` for every requirement bound to a
  target the item changes, and for every count or behavior the item makes
  false.
- Add each one to `supersedes`, and restate in a requirement what the item
  retires. The `supersedes` row of the
  [lifecycle page](../../../docs/getting-started/06-work-item-lifecycle.md#anatomy-of-an-item)
  lists the three forms an entry takes. The other legal answer is to keep a
  gate on the old promise.
- A terminal item is immutable. Correct it with a new superseding item.
- A grader that grades a promise changes only from a new item. The judge
  refuses the change in a PR that adds no item.
- List every recipe that reaches a judge the PR changes, and every item
  bound to those recipes. State which targets turn red and the merge order.
- After a rebase that touched a shared checker, run every slice next to the
  new one again.

## 7. Paths a planning PR cannot carry

| Path | Class | Plan |
|---|---|---|
| `docs/`, a row of `docs/reference/just-targets.md` | process | A process PR. List it in the PR body as planned. |
| `specs/targets.toml` | process | A process PR that merges before the item goes `#active`. |
| A recipe no bound target reaches | implementation | Bind it in this PR, or put it under `owns`. |
| A change to an existing `contracts/**/schema.zt` | implementation | Under `owns`. An added schema is planning. |

- Do not add a `docs/` row to a planning PR to answer a finding. V1 refuses
  the PR.
- Do not write a recipe comment that says a target is listed in
  `specs/targets.toml` before the process PR lands.
- Run `just spec_check --base origin/main` before every push.

## 8. The path to `#active` and to close

- State in the PR body which PR sets `intent = #active`, and every PR that
  must merge before it.
- Set `#active` in the implementation PR. The `Evidence` workflow claims the
  targets of an `#active` item, so an earlier activation records a failure
  on `main`.
- An item whose whole fix lands in graders has no implementation PR. Plan
  the PR that changes only `intent`.
- Declare `depends` on each item whose landed work the exam reads.
- Settle the item text before activation. A PR that corrects the text merges
  before the PR that activates the item.
- Rewording a statement or an acceptance changes the requirements digest. It
  asks every `h.human` question again.

## 9. Restated numbers and facts

- Derive every count in the item, the recipe comment, the docstring, the
  pass line, and the PR body from the grader. After a grader change, search
  for every copy and update all of them in the same push.
- Recompute each worked example from the rule the requirement states.
- Check each factual sentence against the landed source: a protocol reading,
  a universal such as `every decoder`, a statement of what CI runs.
- Record an observation from a single run in a decision, and say that one
  run produced it.
- Write a step that has not landed in the future tense.
- Read each `nonGoals` entry against every requirement and every pinned
  frame. A non-goal must not exclude a change that a requirement needs.

## 10. Provenance

- A choice of scope, an exit condition, and a trade between two designs
  belong to the human. Ask, and record the answer as `h.fromHuman` with the
  quote.
- Record the author's own choice as `h.agentDefault`, and name the
  alternative in the PR body. Never record it as the human's.
- State the limits of the exam in the problem text or in `nonGoals`.
  `knownLimits` records an accepted R4 ratchet regression only, and adding
  one needs a V4 approval (V8).

## Pre-flight

Run these on the head of the planning PR. Report in the PR body only what was
run and observed.

1. `just spec_tasks_check` passes.
2. `just spec_check --base origin/main` passes, or names only the approvals
   the PR still needs.
3. `just spec_closure --explain` shows each bound target and its checker,
   and lists no file under `owns` as a grader.
4. Each target bound for new behavior fails on `main` for the reason its
   requirement names.
5. The draft passes each bound target.
6. Each deleted assertion turns at least one control.
7. Every restated count equals the grader's count.
8. The PR body holds the clause table, the limits, each decision with its
   provenance, and each planned follow-up PR.

## What is not a defect

- An empty `knownLimits` list.
- A limit that the item declares. A reviewer weighs it once.
- A process gate with no negative control.
- An approved statement longer than 25 words. Rewording it changes the
  requirements digest.
