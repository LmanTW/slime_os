# Slime OS Agent Guide

## Scope

These instructions apply to the entire repository.

## Project state

Slime OS is a Rust `no_std` userspace graph on upstream seL4, with `slime-root`
owning dynamic mechanism and generated Zutai contracts owning every persisted
or cross-process format. It is QEMU-verified across every plane, and since
2026-09-13 one named physical machine boots it from removable media: a
Framework 13 (AMD Ryzen AI 300, x86-64, P6), without writing internal storage.
That is a CPU and product boot path only: treat physical NVMe qualification,
device support of every kind, rollbackable production generations, and
daily-driver hardware support as unfinished unless code and tests prove
otherwise. A CPU boot qualifies no device.

## Code map: start here, do not broad-search

Route work by ownership before searching for a symbol. Read the named module root first; use LSP symbols/references from there when available, and only then grep the exact symbol. Do not scan `deps/`, `target/`, or `.tasks/` for implementation symbols unless the task specifically concerns them.

For current subsystem rationale, start at [`docs/architecture/`](docs/architecture/README.md), then the owning code or contract below. Unimplemented design and qualification boundaries live in [`docs/plans/`](docs/plans/README.md). Historical source lives in the [archive](docs/history.md); do not reconstruct extracted architecture from milestone chronology.

### Execution path

1. `scripts/build/build-sel4.py` pins and builds seL4, the root task, its child fixture, and the loader image.
2. `slime-root/src/main.rs` initializes the bounded kernel-object allocator, installs the root's console, and calls `slime_root::boot::run`. `slime-root/src/boot.rs` proves the root's foundations and admits the embedded generation. `slime-root/src/graph_runtime.rs` creates the initial capability graph and launches components. `slime-root/src/graph_runtime/services.rs` serves their requests and supervises faults.
3. Components enter through `components/<lifecycle>/<component>/src/main.rs` — one crate per component (CP3), grouped under `system/`, `services/`, `applications/`, or `testkit/` — with shared helpers in `components/lib` and build-time support in `components/build-support`; their syscall surface is `components/runtime/src/syscall.rs`, with the native transport in `components/runtime/src/syscall/sel4_transport.rs` and authoritative operations in `slime-root/src/ipc.rs` plus the owning mechanism module.

### Task-to-file index

The routing table lives in [`docs/task-to-file.md`](docs/task-to-file.md): one
row per kind of change, naming the canonical starting file and the follow-on
files, closures, and gates. Read the row before searching; the most common
rows are expanded into checklists in
[`docs/getting-started/11-recipes.md`](docs/getting-started/11-recipes.md).

### Generated-code rule

Files beginning with `@generated`, files under `boot-contracts/src/generated/`, every manifest that a system spec in `contracts/system-spec/v1/systems/` derives (`DERIVED_GENERATION_FIXTURES` in `scripts/lib/system_spec.py` reads that directory), the system specs named in `COMPUTED_SYSTEM_SOURCES` (`scripts/lib/system_spec.py`),
and every closure source under `contracts/system-image-closure/v3/closures/` plus every negative case under `contracts/system-image-closure/v2/negative/` are outputs, not sources. Change the matching `contracts/.../schema.zt`, `gen_rust.zt`, or system-spec authoring source (`sources/*.zt` for mapped outputs, otherwise
`systems/*.zti`), then run the matching `scripts/generate/generate-bindings.py <name>` (a row of `scripts/lib/zutai_bindings.py`), remaining `scripts/generate/generate-*-bindings.py` / `just *_gen` / `generate-generation-from-spec.py` / `generate-system-image-closures.py`. `components/build-support` generates nothing from a manifest: B70 replaced build-time command tables and the per-plane fabric profile with root-served runtime queries, so a component reads its composition, ceilings, and graph rows from the authenticated generation it is running inside.

A closure source names its inputs by path and records no digest; every build resolves it in the checkout, so an edit to an input tree changes no committed file. A closure's release inputs are listed in `scripts/generate/generate-system-image-closures.py`; they do not include `just/` or `Justfile`. `scripts/check/` and `scripts/lib/` are not inputs except the files `RELEASE_INPUTS` names by path (today `scripts/lib/elf_delivery.py` and the two builders under `scripts/build/`). Regenerate the closure sources (`python3 scripts/generate/generate-system-image-closures.py`) only when a closure's input set changes — a new composition, component, scenario, root role, or release input — in its own derived commit within the same PR; `python3 scripts/generate/generate-system-image-closures.py --check` refuses a stale source set. Test-run records and negative build cases name their closure, so a closure change leaves them unchanged; re-freeze test-run records with `just system_test_run_bless` only when a plane gate's execution inputs change.

### Navigation traps

- `slime-root/src/lib.rs` exposes the mechanism modules host tests compile, the boot sequence and the graph runtime among them; the product binary in `slime-root/src/main.rs` links those same modules. The binary alone compiles `main.rs`. A root built with `SLIME_ROOT_FIXTURE=1` also compiles `fixture_runtime.rs`, behind `cfg(slime_root_fixture)`; a product root does not.
- A component's capability slot layout is established by grants in the matching `contracts/system-spec/v1/systems/<plane>.zti`, the manifest derived from it under `contracts/generation-manifest/v1/compositions/`, and the generated boot-layout fixture, not by the component binary alone. Inspect all three before changing slot numbers or authority; edit only the system spec.
- `scripts/check/` contains end-to-end QEMU assertions and expected serial markers; it is verification code, not the implementation of the behavior it checks.

## Commands

Use the Justfile targets from the repository root. The full list, one row per target with what it proves, is [`docs/reference/just-targets.md`](docs/reference/just-targets.md); these are the ones every task touches:

- `just run` — boot the current seL4 QEMU product image.
- `just test` — run the root/product behavioral aggregate.
- `just generation_check` — build and validate the deterministic seL4 generation.
- `just contracts_check` — validate generation manifest contracts and generated bindings.
- `just spec_check` — the devloop v1.5 judge (`scripts/spec/check`): the store alone, or with `--base origin/main` your branch under V1 to V11, as CI judges it.
- `just spec_tasks_check` — task/v2 items and area files: format, links, schema copies; offline.
- `just spec_tasks_status` / `just spec_status` — each item's state and each area requirement's state, read from the `evidence` branch.
- `just spec_record <target>` / `just spec_closure` — run one target under the record wrapper, and print the closure digest an evidence record is keyed by.
- `just docs_check` — maintained links, fragments, canonical UUID references, and command references, without network.
- `just fmt_check_all` / `just lint_all` / `just ruff` / `just typos` — formatting, clippy with warnings denied, Python lint, spell-check.

Explicit hardware and physical-boot targets (`rpi5_ros2_zenoh_check`, `framework_cpu_boot_check`, the `x86_64_*` and `framework_media_*` recipes) are in no aggregate; `framework_cpu_boot_check` cannot manufacture an observation and QEMU cannot close it.

## Work items, backlog, and roadmap

A work item is one task/v2 Zutai file, `.tasks/items/<slug>.zt`; identity is its UUID, and the slug is a display alias. Start one with `python3 scripts/spec/tasks new <task|bug|milestone> <slug> --area <area>`. It names an area under `specs/`, `owns` globs, requirements bound to `just` targets, and acceptances. Area files under `specs/` hold frozen promises; an item's `supersedes` replaces one. Closed items live in `.tasks/terminal/`. `specs/legacy.zt` indexes the 448 V1 items, whose full text is in Git at the commit it names.

`scripts/spec/check` is the only judge, and it blocks. A feature takes several PRs: a planning PR lands the item and its exam, then an implementation PR changes only paths the item's `owns` covers. The judge refuses product code in a planning PR (V1) and an implementation PR that touches its own grader set (V3). Every PR but a closeout needs one independent review of its head: an approval from a person in `HUMAN_OWNERS` or from an account in `REVIEW_AGENTS`, other than the author (V11). A PR comment that starts with `@claude review` asks the review agent for its verdict. The same review satisfies V4 for a grader, area, schema, or judge change. Backlog bugs come first: a milestone cannot go `#active` while a backlog bug is `#planned` or `#active` (V7). After a push to `main`, the Evidence workflow records every claimed target on the `evidence` branch and signs a done witness for each finished `#active` item. Its closeout bot then opens one PR that moves the item to `.tasks/terminal/`. Nobody runs a completion command.

The rules V1 to V11 and their reasons are [`docs/decisions/work-item-devloop.md`](docs/decisions/work-item-devloop.md) and [`docs/decisions/independent-review.md`](docs/decisions/independent-review.md). The walkthrough is [`docs/getting-started/06-work-item-lifecycle.md`](docs/getting-started/06-work-item-lifecycle.md). Read both before opening a PR that touches `.tasks/`, `specs/`, `scripts/spec/`, or a checker. [`CONTRIBUTING.md`](CONTRIBUTING.md) owns the human-facing PR workflow and the PR class table.

## Code review

These rules bind every reviewer of a PR — a person, a review bot, or an agent asked to review — and the author answering the review. A review's job is to find where the diff, the checker it binds, and the landed work item disagree, and to say so with a file and line.

- **The item bounds the review.** Read the work item, the PR description, and the existing threads before the diff. A process PR has no item; there the rules in this file the PR claims to follow, and the claims its description makes, are what a finding is checked against. A finding names what it breaks — an item requirement or acceptance, a stated invariant, or a rule in this file — the file and line, and the input that produces the wrong result. A case no requirement statement claims is a follow-up proposal in one comment, not a finding; a declared known limit is a decision to weigh, not a gap.
- **Severity states a consequence.** Blocking only when a gate can pass while its claim is false, a refused input is accepted, an authority, lifetime, or determinism rule is broken, a boundary-crossing format has no Zutai contract, the recipe cannot pass as landed, or the PR adds a workflow or job that could report the PR's own verdict. A local defect is non-blocking. Style, alternatives, and hardening the item does not require are suggestions, labelled, never blocking, never re-raised. What the PR cannot carry goes to the planning process in one comment.
- **One review per head.** A later head gets the delta and the threads it answers, not a fresh pass over the whole diff. More than ten findings means a structural problem: name it, give the strongest, stop. Never duplicate a finding another tool posted.
- **Consistency.** A finding that restates an open thread is a reply there; one that contradicts an earlier round names it and the evidence that changed. A thread answered with a question or a declared decision waits for the human.
- **Answering.** Reproduce before fixing; what does not reproduce stays open with what was tried. Declining with a reason is legitimate. Answer a whole round in one push. Revise the item once, in one planning PR, never for a suggestion. Nothing blocking means ready. Threads hold the history; the description describes the head.
- **Triage before fixing.** The author's reply to a round opens with one line per finding: the input that breaks it, whether it changes product behavior or only tooling, documentation or process, and the size of the fix. Fixes follow in the same push.
- **When the author stops and asks.** The author fixes nothing in a round and asks the human in one PR comment, linking [`HUMAN.md`](HUMAN.md), when either holds:
  - a third consecutive round raises a new finding on the same subject. The comment names the subject, the design choice that keeps producing findings, and the decision that would close the whole class (for example: require storage to equal the declared configuration instead of bounding it from below);
  - a non-blocking finding lands on process or verification text or code: `scripts/`, `.tasks/`, `specs/`, `.agents/`, this file, or `docs/` outside `docs/architecture/`. These are collected into one follow-up comment for the human to accept or drop, not fixed in the PR.

  The human's answer is a declared decision under **Consistency**; a finding that follows from it is not re-raised.

[`.agents/skills/pr-review/SKILL.md`](.agents/skills/pr-review/SKILL.md) is the full text; [`.agents/skills/spec-review/SKILL.md`](.agents/skills/spec-review/SKILL.md) is the procedure for an implementation PR against its work item.

## Change records and documentation

The commit and PR record the change, claim, risk, exact verification, and known limits; the work item records scope, state, and observed exit conditions; ordinary changes need no devlog. A behavior change at a contract, wire, or operating boundary updates the owning `docs/architecture/` page in the same PR. Durable cross-module choices go to [`docs/decisions/`](docs/decisions/README.md), unimplemented designs to [`docs/plans/`](docs/plans/README.md), historical investigations to the [`slime_os-history` archive](docs/history.md).

A comment should state what must remain true, not argue that the author was right: invariants, ordering, ABI, capability boundaries, and why the simpler local form would break a current invariant — never investigation history, reviewer findings, or verification results. [`.agents/skills/change-records/SKILL.md`](.agents/skills/change-records/SKILL.md) holds the record ownership table, the decision-record template, and the comment rules in full.

## Writing style

Every PR body, reply to a human, `docs/` page, work-item body, and multi-line comment follows [`.agents/skills/writing-style/SKILL.md`](.agents/skills/writing-style/SKILL.md). Read it before writing any of these. The short form:

- Conclusion first.
- One statement per sentence, at most 25 words. Active voice with a named actor.
- One glossary term per concept. No synonym rotation. No evaluative adjectives about the work.
- Analogies only in `docs/concepts/`, `docs/getting-started/`, and replies. Never in a PR body.
- A table or Mermaid block when the information has that shape. No raw HTML diagrams in the repository.
- Repository text is English. A reply uses the human's language, with identifiers and glossary terms untranslated.

## Development rules

- **Zutai is the only schema language.** Every serialized format that crosses a persistence, process, or boot boundary — on-disk formats, IPC/protocol messages, manifests, and boot records — must be defined as a versioned Zutai schema under `contracts/` (`schema.zt`), with Rust/Python bindings generated from it (`scripts/generate/generate-bindings.py` and the remaining `generate-*-bindings.py`, `just *_gen`). Do not introduce hand-written field offsets, ad-hoc `#[repr(C)]` wire structs, `struct.pack` layouts, or any other schema language (JSON Schema, protobuf, etc.) as the source of truth for a format. Purely in-memory types are exempt, as are readers and writers of externally specified formats (ELF, GPT, Ethernet/IP, MAVLink, SSH signatures) that Slime OS does not own; those may use `struct` with the standard's offsets.
- Prefer small, direct changes over new abstractions.
- Keep mechanism in `slime-root`; component policy belongs in userspace components.
- Preserve the capability/component/generation model. Do not add ambient authority, global executable paths, or implicit environment assumptions.
- Do not treat framebuffer output alone as milestone completion.
- Do not claim physical-machine support without an observed removable-media Framework boot that does not write internal NVMe.
- Keep generation data deterministic, versioned, bounded, and explicitly validated.

## Verification code discipline

Extend the checker that owns an invariant; add a top-level `scripts/check/check-*.py` only for a genuinely new mechanism or reusable boundary, never for a roadmap item, composition, or single plane. seL4 plane mechanism lives in `scripts/lib/sel4_plane.py` and `scripts/lib/sel4_gate_markers.py`; a plane script owns only its expectations. An independent judge is at least as strict as the code it judges on every boundary it claims, every positive assertion a product judge makes has a negative control (verification and process tooling needs none; adding one is a human decision, see [`docs/decisions/negative-controls-for-product-judges.md`](docs/decisions/negative-controls-for-product-judges.md)), and a pinned external artifact is re-verified by hash on every run. [`.agents/skills/verification-checkers/SKILL.md`](.agents/skills/verification-checkers/SKILL.md) is the full rule set; read it before touching `scripts/check/`, `scripts/lib/sel4_*`, an exam judge, or a `just` recipe.

## Verification

- For root or userspace behavior changes, run the narrowest seL4 QEMU path that exercises the changed behavior; the gate resolves its closure in the checkout. A build whose inputs hold uncommitted, untracked or ignored files records `dirty = true` in its build result, and no evidence may name it.
- For generation-format or builder changes, run `just contracts_check` and `just generation_check`.
- For permanent Rust changes, run `just fmt_check_all` and `just lint_all` before finishing.
- For a behavior change at a contract, wire, or operating boundary, update the owning `docs/architecture/` page in the same PR; a diff that reverses what that page states is incomplete.
- Verify on a clean tree or a dedicated worktree. If the working tree holds changes the PR does not carry, say so in the PR description; a check that passed with foreign edits present proves nothing about the PR alone.
- Report only observed commands and results as verification. A review by an agent or bot is review, not evidence: it does not belong in the verification table.
- For documentation-only changes, state that no runtime tests were run.
