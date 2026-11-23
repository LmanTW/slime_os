# Recipes

"I want to change X — which files, in what order, and which gate?" Each
recipe is a checklist. They assume you have read [Your first
change](04-first-change.md) once; they do not repeat the why. Where a recipe
says *regenerate closures*, it means:

```sh
python3 scripts/generate/generate-system-image-closures.py
```

and where it says *the owning plane gate*, find the composition your component
is in (`grep -l '"<component>"' contracts/system-spec/v1/systems/*.zti`) and
run the `just` recipe whose checker names that closure.

The standing rules apply to every recipe: an item on `main` first for
non-trivial work ([work-item lifecycle](06-work-item-lifecycle.md)), backlog
before milestones, never edit a generated file, never weaken a gate to go
green.

---

## Change what a component prints or does

1. Edit `components/<lifecycle>/<name>/src/main.rs` (shared code:
   `components/lib/src/`).
2. If a marker text changed: update the chain in the owning
   `scripts/check/check-sel4-*-plane.py`, and `passFailCriteria` in
   `contracts/component-spec/v1/components/<name>.zti` if it was that line.
3. Regenerate closures.
4. Run the owning plane gate; if a chain changed, also
   `just sel4_gate_control_check`.
5. `just fmt_check_all && just lint_all`.

## Give a component a new capability (grant, notification, budget)

1. Edit `contracts/system-spec/v1/systems/<plane>.zti` — never the manifest
   under `generation-manifest/`. Add the grant (source, target, kind, rights,
   transferable) and a `slotPins` entry only if the component's ABI fixes the
   slot; otherwise resolve it by name at runtime.
2. `python3 scripts/generate/generate-generation-from-spec.py`, then
   `just system_spec_check`.
3. Add the kind to `provides`/`requires` in the component spec if it is new
   for that component; `just component_spec_check`.
4. Use it in code via `slime_rt::resolve_binding(b"<grant name>")`.
5. Regenerate closures. `just sel4_boot_layout_check` will show the slot
   diff for that plane — bless with `just sel4_boot_layout_bless` only if the
   diff is exactly what you meant.
6. Owning plane gate.

Missing this and calling anyway shows as `SLIME_GRAPH request rejected …`
or `binding unresolved` — see [Debugging](08-debugging.md).

## Add a component

Follow [Add a component](05-add-a-component.md) end to end. Short form:
crate → `Cargo.toml` release stanza → component spec → system spec →
regenerate manifest → regenerate closures → owning gate →
`just component_crate_split_check component_spec_check system_spec_check`.

## Add or change a wire format

Follow [Write a contract](09-write-a-contract.md). Short form: `schema.zt` →
`gen_rust.zt` → `just <name>_gen` → validator in `components/proto/src/lib.rs`
→ test in `components/proto/tests/` → register in `check-contracts.py` →
`just contracts_check test_host` → regenerate closures.

## Add a root syscall

1. Declare the label in `contracts/syscall-abi/v1/schema.zt` under the
   owning service; labels are frozen and additive, so take the next unused
   number. `just syscall_abi_gen`.
2. Implement in `slime-root/src/ipc.rs` (argument validation and the rights
   gate) dispatching to the owning mechanism module
   (`slime-root/src/<mechanism>.rs`). A new right means a new bit in
   `contracts/generation/v5/schema.zt` and `just boot_gen`, plus a row in
   [`capability-matrix.md`](../capability-matrix.md).
3. Wrapper in `components/runtime/src/syscall.rs` (and the transport in
   `syscall/sel4_transport.rs` only if operand packing is new).
4. Document the operation in [`syscall-abi.md`](../syscall-abi.md) — the
   label table is machine-checked by `just contracts_check`.
5. Host tests in the mechanism module. `just test_sel4_root` counts them from
   the source, so the recipe does not change.
6. A plane that exercises it, including a refusal case (`request rejected`
   for a holder without the right). Regenerate closures.
7. `just contracts_check test_sel4_root lint_all` plus the plane.

## Add a marker gate or a scenario arm

[Add a gate](07-add-a-gate.md). Decide extend / arm / new plane in that
order. A new plane touches: components + specs, system spec,
closure, checker, recipe in `just/planes-*.just`,
`GATES` row in `check-sel4-gate-controls.py`.

## Change a component's stack, threads, or memory budget

1. System spec placement: `stackBytes`, `extraThreads`, the shared-buffer
   ceilings (`bufferBytePages`, `bufferCount`, `mappingCount`, `loanCount`),
   and `privatePageQuota` (or a spec-level `privateMemoryPolicy`). Component
   spec `resources` must agree.
2. Regenerate manifest and closures; `just system_spec_check`.
3. For private memory, the target envelope in
   `contracts/private-memory-budget/v1` bounds what a plane may declare; the
   [private-memory page](../architecture/private-memory.md) lists the
   qualified ceilings.
4. Owning plane; for private memory, `just private_memory_check`.

## Change the default product (`just run`)

The product composition is `contracts/system-spec/v1/systems/sel4.zti`, not
`reference.zti`. Edit it, regenerate manifest and closures, then
`just sel4_component_graph_check` (which is what `just test` runs) and
`just sel4_boot_layout_check`.

## Add a Rust dependency

1. Add it to the crate's `Cargo.toml`; `Cargo.lock` is part of every
   closure, so regenerate closures.
2. `just deny` (advisories, licenses, source pinning — unknown git sources
   are refused) and `just machete`.
3. Components are `no_std`; a crate needing `alloc` forces the `heap`
   feature and the allocator-group split (`just component_crate_split_check`).

## Bump the seL4 kernel, rust-sel4, or a toolchain

1. `sel4/pins.toml` is the source: submodule commits, release, toolchains,
   target-spec bytes, observed kernel hashes. Update the submodule and the
   pin together.
2. `just sel4_pin_check` must pass before anything boots; it refuses, never
   fixes. Do not bless observed hashes to silence it unless the kernel change
   is the change.
3. `deps/rust-sel4` is part of every closure: regenerate closures.
4. `just x86_64_sel4_image_check` for the pc99 rebuild proof, then
   `just test` and the planes you can afford. A kernel bump unbinds the
   Framework CPU-boot observation ([runbook](../operations/framework-cpu-boot-runbook.md)).

## Change a checker or a script under `scripts/`

1. `scripts/lib/` is shared mechanism; `scripts/check/` is per-gate
   expectations. Prefer extending the library over copying into a checker.
2. `just ruff`. If the file is in the grader set of a bound target, the
   change is a planning change: `just spec_check --base origin/main` prints a
   `V3` finding for it in an implementation PR, and it needs a V4 approval.
   `just spec_closure --explain` shows which targets a file grades.
3. If a marker table changed: `just sel4_gate_control_check`.
4. A new rule in a contract checker is behavioral. It needs a landed work
   item first, like any other non-trivial change. A change to `scripts/spec/`
   changes the judge and needs a V4 approval.

## Change documentation

- Architecture, operating procedure, or limitation changed → the owning
  `docs/architecture/` page, in the same PR as the code.
- A durable cross-module choice → `docs/decisions/` with status and revisit
  conditions.
- An unimplemented design → `docs/plans/`.
- `just docs_check` (links, fragments, UUIDs, and every `just <name>` literal
  must be a real recipe) and `just typos`. State that no runtime tests ran.

## Add a `just` recipe

1. Put it in the `just/*.just` file whose group fits; keep the `[group(...)]`
   attribute; add a `# comment` line above the attribute as its description.
2. Reference it from the page that owns the surface it checks, or from the
   [recipe reference](../reference/just-targets.md); `just docs_check` verifies
   that every literal in docs resolves, and the reference page lists every
   public recipe.
3. If a component spec's `requiredTestEnvironment` should name it, do that
   and run `just component_spec_check`.

## Record hardware evidence

Only the [Framework runbook](../operations/framework-cpu-boot-runbook.md) and
the Duo/RPi5 targets in `just/hardware.just` have an evidence path; each binds
the exact image, machine, and firmware, and a QEMU result never substitutes.
A CPU boot qualifies no device.

## Close a work item

Nobody closes an item by hand ([work-item lifecycle](06-work-item-lifecycle.md#closeout-prs)).
After the implementation PR merges, the `Evidence` workflow records the
item's targets and signs a done witness once every mandatory acceptance is
enforced. Answer each `h.human` acceptance with `scripts/spec/human`. The
closeout bot then opens the PR that moves the item to `.tasks/terminal/`.
`just spec_tasks_status` shows what is still missing.
