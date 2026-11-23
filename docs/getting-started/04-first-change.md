# Your first change

The workflow, walked once. The exercise below touches nothing permanent —
it exists to make you collide with the two things that most shape work here:
gates that pin behavior, and the routing discipline that tells you where a
change belongs.

## Before anything: the standing order

1. **Backlog first.** An open backlog bug is a `bug` item in
   `.tasks/items/` with intent `#planned` or `#active`. While one exists, or
   while an area promise fails, no milestone work may enter `#active`.
   `scripts/spec/check` enforces it (V7). `just spec_tasks_status` lists every
   item's state.
2. **Route, don't search.** Find your change's row in the
   [task-to-file index](../task-to-file.md) and read the named module root first. Broad
   symbol-grepping across the tree is how you end up editing a generated
   file or a check script instead of the source.
3. **Know your gate.** Every change area has a narrowest QEMU or host gate;
   identify it before editing so you know what "done" will look like.

## Exercise: watch a gate catch you

This demonstrates the marker contract from the
[boot walkthrough](03-boot-walkthrough.md) with a throwaway edit.

1. Run the product plane gate once, green:

   ```sh
   just sel4_component_graph_check
   ```

2. Open `components/services/spawn-service/src/main.rs`, find the
   `[spawn-service] ready` debug line, and change the text — even one
   character.

3. Run the gate again. Every seL4 gate first resolves a system-image closure:
   it reads the closure source under `contracts/system-image-closure/v3/closures/`,
   which names each input tree by path, and computes each tree's digest from your
   checkout. Your edit changes that digest, so the gate builds a new image and logs
   `[closure build] sel4 <derivation id> (dirty)`. The build result records
   `dirty = true` because a closure input holds an uncommitted change. Such a
   build runs, but no evidence may name it.

4. The gate boots and fails on the marker:
   `missing unordered marker: \[spawn-service\] ready`, with the transcript
   tail and exactly which expectation broke
   (`scripts/check/check-sel4-component-graph.py` holds the table; the
   component's own spec in
   `contracts/component-spec/v1/components/spawn-service.zti` names that
   literal as its pass/fail criterion).

5. Revert your edit and run the gate green. The resolution returns to the
   committed derivation id and reports the build clean.

What you just observed: component output is contract surface, and a build
records the identity of the source that produced it. A real change to a marker
updates the emitting code and the gate's marker table in the same commit; the
gate diff is the evidence the change was intended — never a reason to loosen
the assertion.

## The real workflow, by change kind

**Behavior in the root or a component** — edit the owning module (per the
index), run the narrowest `sel4_*` plane gate that
exercises the path, and for root logic also `just test_sel4_root` (it counts
the `#[test]` attributes in the source and fails when the run misses one, so a
new test changes no recipe). Commit the
change and rerun the gate on the clean tree, so its build result records
`dirty = false`.

**Anything with a wire format** — schema first, always:
edit `contracts/<name>/vN/schema.zt`, regenerate with the matching
`just *_gen`, commit schema and generated output together, and run
`just contracts_check`. Never edit a file whose first line says
`@generated`. See [contracts](../concepts/contracts.md).

**Authority: grants, slots, budgets** — these live in the system spec
(`contracts/system-spec/v1/systems/<name>.zti`), not in component code and not
in the manifests under `contracts/generation-manifest/v1/`, which are derived
outputs. Edit the spec, run
`python3 scripts/generate/generate-generation-from-spec.py`, commit both, and
run `just system_spec_check`. Expect `just sel4_boot_layout_check` to show the
layout diff; bless it only when the diff is the change you meant. New rights
or operations update [`../capability-matrix.md`](../capability-matrix.md) /
[`../syscall-abi.md`](../syscall-abi.md) in the same change — the latter is
machine-enforced.

**Docs only** — state that no runtime tests were run; `just typos` applies.
Run `just docs_check` when editing Markdown documentation, PR templates, or
documentation links. This checks current local documentation
without requiring a history checkout or archive-network access.

## Before you finish

For permanent Rust changes:

```sh
just fmt_check_all
just lint_all
```

Then leave the records that make the claim reviewable:

- **Commit and PR**: state the change, claim, risks/invariants, review surface,
  exact commands and observed results, evidence class, target or image identity
  when relevant, and known limits. Ordinary changes do not need a devlog.
- **Owning knowledge**: update the owning docs or contract when current behavior,
  operation, or limitations change. Long-lived cross-module choices belong in
  `docs/decisions/`; unfinished designs in `docs/plans/`; exploration stays in
  `docs/directions/`. Expensive reusable investigations or unusual verification
  campaigns belong with their owning knowledge and immutable evidence; consult
  [the history guide](../history.md) for archived records.
- **Work-item state**: change nothing after the implementation PR merges.
  The Evidence workflow records the item's targets on the `evidence` branch,
  and the closeout bot moves the item to `.tasks/terminal/` once a done
  witness exists. Never allocate an id by hand.
  `python3 scripts/spec/tasks new` assigns a UUIDv7. Run
  `just spec_check --base origin/main` before you push.

`AGENTS.md` carries the full statement of these rules; this page is the
tour, that file is the law.

## Next

This page changes existing behavior. To add a new component end to end — crate,
declaration, composition, authority, launch policy, and observed QEMU behavior —
continue with [Add a component](05-add-a-component.md).
