# Contributing to Slime OS

## The short version

Slime OS uses GitHub for collaboration, but canonical project state lives in
task/v2 work items under `.tasks/` and area files under `specs/`. GitHub
Issues are intake for bugs and proposals. Work items are not projected into
Issues or milestones; see
[the decision](docs/decisions/no-github-issue-projection.md).

**For a product change, first land a planning PR that adds or edits the work
item. Only after the item is on `main` may you open an implementation PR.**
`scripts/spec/check` refuses a pull request that carries more than one class,
so a new item and its implementation cannot share a pull request. A pull
request confined to process paths — `.github/`, `docs/`, `.agents/`, this
file, `AGENTS.md` — needs no work item; see
[Pull request scope](#pull-request-scope).

**PR merged != work item done.** After each push to `main`, the Evidence
workflow records every claimed target and signs a done witness for each
`#active` item whose mandatory acceptances are enforced. Its closeout bot then
opens one pull request per witnessed item that moves the item to
`.tasks/terminal/`. Nobody runs a completion command.

If those rules read as ceremony, start with
[How work flows](docs/getting-started/00-how-work-flows.md): the same process
as a timeline, with the reason and the enforcing check beside each step. This
file owns the exact rules; that page explains them.
[`docs/decisions/work-item-devloop.md`](docs/decisions/work-item-devloop.md)
and
[`docs/decisions/independent-review.md`](docs/decisions/independent-review.md)
own the rules V1 to V11 and their reasons.

## Where work lives

### Human Issues are intake

Open a [GitHub Issue](https://github.com/iceice666/slime_os/issues) for a bug,
proposal, question, or discussion. For bugs, include the target, revision,
reproduction steps, expected result, and observed output when available.
Ordinary reporters do **not** edit `.tasks`.
Accepted work later becomes a task/v2 item. The Issue does not track that
item; the item's file under `.tasks/` is its only state.

### Bot Issues are retired projections

Issues created by `github-actions[bot]` whose body begins with
`<!-- myque:id=<UUID> -->` came from the retired projection. They are closed
and no longer track their item. Look the UUID up in
[`specs/legacy.zt`](specs/legacy.zt), which indexes every V1 item and names
the commit that holds its full text.

### Work-item hierarchy

An item has one `kind`: `#task`, `#bug`, or `#milestone`. Its `parent` names
a milestone or other item by UUID, and `depends` lists the items it waits
for. Create a child only for independently trackable work with observable
acceptances. Do not change kinds or parents to populate a progress bar.

### The store is canonical

| Surface | Owns |
|---|---|
| `.tasks/items/<slug>.zt` | Open work: problem, area, intent, `owns`, requirements, acceptances, hierarchy, dependencies |
| `.tasks/terminal/<slug>.zt` | Closed work, moved there unchanged by a closeout PR |
| `specs/<area>.zt` | Frozen promises: area requirements and invariants (V10) |
| `specs/legacy.zt` | Index of the 448 V1 items and the commit that holds their text |
| `evidence` branch | Signed observation records and done witnesses |
| GitHub | Intake, collaboration, reviews |
| PR | Reviewable change, claim, risk, verification, limits, and related work item |
| Owning docs/contracts | Current architecture, behavior, procedures, and limitations |
| [History archive](docs/history.md) | Historical investigations and raw evidence; never a product build dependency |

UUIDs are canonical identities. A slug is the file name. Human keys such as
`C9.4` in older text are display aliases that no checker resolves. Generated
lists and `docs/plans/` are not state stores.

## Proposing work

Discuss bugs and ideas in Issues first when useful. Start an item from the
skeleton, which carries a fresh UUIDv7:

```sh
python3 scripts/spec/tasks new task <slug> --area <area> > .tasks/items/<slug>.zt
```

The kind is `task`, `bug`, or `milestone`. `<area>` names a file under
`specs/`, whose invariants bind the item. Never invent a UUID. Fill in the
problem, `owns`, `nonGoals`, requirements, and acceptances, then run
`just spec_tasks_check`.

A new item enters as `#planned`. Submit it in a **planning PR**, and merge
that PR before opening an implementation PR. A landed item covers every
implementation PR within its `owns`; a new item is not required per PR.

### Requirements, acceptances, and the exam

An item carries its requirements as Zutai data, so `scripts/spec/check`
enforces completion instead of trusting a claim.
[Carrying a work item](docs/getting-started/06-work-item-lifecycle.md) walks
the lifecycle command by command; the rules that bind a pull request are
here. [`.tasks/items/ci-cache-budget.zt`](.tasks/items/ci-cache-budget.zt) is
a complete item.

| Field | Meaning |
|---|---|
| `owns` | Path globs an implementation PR of this item may change (V2) |
| `requirements` | `h.req <id> <statement> { <target or acceptance id>; ... }`: one observable statement, bound to `just` targets or human acceptances |
| `acceptance` | `h.observed "<target>"`, `h.observedWhere` with predicates, or `h.human <id> <question>` |
| `intent` | `#planned`, `#active`, `#blocked`, `#deferred`, or `#cancelled` |
| `supersedes` | A terminal item, an item requirement, or an area requirement this item replaces |

The **exam** is the set of targets the acceptances bind, plus every grader
file in their closure. `just spec_closure --explain` lists that composition:
recipe definitions, grader files, declared inputs, image derivations, and
toolchain files. An evidence record is keyed by the closure digest, so a
change to any grader file makes a new record necessary.

**The exam lands before the implementation.** The planning PR adds the
item and any new target or checker it binds. The implementation PR may not
touch the grader set of any bound target (V3). A checker that must change is
a planning change, and so is a generator that a bound recipe runs. A grader
change needs a V4 approval.

When a requirement is a number — attempts refused, controls exercised, bytes
delivered — the recipe's checker reports it through
`scripts/lib/devloop_observations.py`, and `h.observedWhere` states the
predicate:

```python
from devloop_observations import record
record(staleHandlesRejected=refusals, negativeControlsRefused=len(controls))
```

`passed` comes from the recipe's exit status, never from the report, so a
checker cannot vouch for itself. Run one target locally under the record
wrapper with `just spec_record <target>`. It writes
`build/observations/<target>.zt`. A record taken from a dirty tree cannot be
published.

A `#human` acceptance stays open until a person listed in
`specs/allowed_signers` answers it with `scripts/spec/human`. The answer is
signed and bound to the item's requirements digest, so a reworded statement
asks again. Automation never infers an answer. The `Evidence` workflow records
a target on an AArch64 runner, unless `[host]` in `specs/targets.toml` lists it
under another host class, as it does the x86-64 recipes that build a pc99
image. Targets CI cannot run, such as
board and physical-machine boots, are listed under `operator` in
`specs/targets.toml`, and an operator signs their records with
`scripts/spec/record <target> --signer <principal>`.

### Intent and backlog first

| From | To |
|---|---|
| new | `#planned` |
| `#planned` | `#active`, `#deferred`, `#cancelled` |
| `#active` | `#blocked`, `#deferred`, `#cancelled` |
| `#blocked` | `#active`, `#cancelled` |
| `#deferred` | `#planned`, `#cancelled` |

The judge refuses any other intent change (V5). Entering `#deferred` or
`#cancelled` needs a V4 approval. A PR that changes only an item's `intent`
counts as an implementation PR, so `#planned` to `#active` normally ships
with the first implementation change. The Evidence workflow claims an item's
targets only while it is `#active`.

Backlog bugs come first (V7). A milestone, or an item under one, cannot enter
`#active` while a `#bug` item is `#planned` or `#active`, or while an area
promise fails.

## Development setup

Start with [Orientation](docs/getting-started/01-orientation.md), then
[Build and run](docs/getting-started/02-build-and-run.md) for submodules,
`nix develop`, toolchain pins, and QEMU. Continue with
[Your first change](docs/getting-started/04-first-change.md) or
[Add a component](docs/getting-started/05-add-a-component.md).
These guides own the tutorials; this document owns the contribution workflow.

## Making a change

- Read [AGENTS.md](AGENTS.md), the detailed repository engineering rules.
- Route through the [task-to-file index](docs/task-to-file.md) before searching. Change the owning
  implementation, not a checker that merely observes it.
- Identify the narrowest owning gate before editing; preserve capability,
  component, generation, and hardware-safety invariants.
- Use versioned Zutai schemas for cross-process, persistence, and boot formats.
  Change the canonical schema/generator and regenerate outputs together;
  never hand-edit generated bindings.
- Keep comments for current invariants beside the implementation and stable
  rationale in owning docs.
  Put long-lived cross-module choices in `docs/decisions/`, unfinished designs
  and qualification requirements in `docs/plans/`, and exploration in
  `docs/directions/`. Expensive reusable investigations or unusual verification
  campaigns belong in the private [history repository](docs/history.md).

## Pull requests

### Pull request scope

`scripts/spec/check` gives every changed path one class, and a pull request
may carry one class only (V1). The `Spec judge` workflow runs the base
commit's copy of the judge on every pull request and after each review, so a
pull request cannot rewrite the judge that judges it. Run the same judgement
locally with `just spec_check --base origin/main`.

| Class | Paths | Rule |
|---|---|---|
| **planning** | an added or edited `.tasks/items/*.zt`, `specs/*.zt` area files, an **added** `contracts/**/schema.zt`, a script in the grader set of a bound target (a `scripts/check/` or `scripts/lib/` file, or a generator that a bound recipe runs), and `Justfile` or `just/` recipes in the closure of a bound target | lands the item and its exam before any implementation |
| **implementation** | `components/`, `slime-root/`, `boot-contracts/`, other `contracts/` paths including a modified `schema.zt`, `scripts/build/`, `scripts/generate/` and `scripts/tools/` files outside every grader set, `sdk/`, `tools/`, `sel4/`, `deps/`, `nix/`, `evidence/`, `verification/`, `assets/`, build and toolchain files, other recipes, and an intent-only item edit | every path under the `owns` of an item that is on base and `#active` on head (V2); touches no bound grader set (V3) |
| **process** | `.github/`, `docs/`, `.agents/`, `.claude/`, `scripts/spec/`, `roadmap/`, `contracts/task/`, `contracts/observation/`, the task schema copies in `.tasks/`, root `*.md`, `HUMAN_OWNERS`, `AGENT_ACCOUNTS`, `REVIEW_AGENTS`, `specs/allowed_signers`, `specs/targets.toml`, `specs/schema.zt`, `specs/helpers.zt`, `specs/legacy.zt`, and `scripts/check/` or `scripts/lib/` files outside every grader set | needs no work item |
| **closeout** | an unchanged move of `.tasks/items/<slug>.zt` to `.tasks/terminal/` | needs a signed done witness, unless the item is `#cancelled` (V6) |
| **derived** | regenerated closure sources under `contracts/system-image-closure/v3/closures/`, negative cases under `contracts/system-image-closure/v2/negative/`, and `contracts/system-test-run/v1/runs/` and `v2/runs/` | accompanies any class; never decides |

The judge refuses a path the table does not list. A process PR adds it to the
table first. Every `contracts/**/schema.zt` is compiled by
`just contracts_check` whether or not a generator or checker names it yet, so
a schema landed ahead of its implementation is still checked. See
[docs/decisions/planning-pr-schema-contracts.md](docs/decisions/planning-pr-schema-contracts.md).

### Reviews and approvals

Every pull request but a closeout needs one independent review of its current
head (V11). Two things count, and neither counts from the author:

- an approving review from a person in `HUMAN_OWNERS`;
- an approving review from an account in `REVIEW_AGENTS`, which is the review
  agent's verdict.

A comment on the pull request that starts with `@claude review` asks the
review agent for its verdict on the current head. The `Agent review` workflow
runs from `main`, posts the findings, and submits an approval when no finding
is blocking. [`docs/decisions/independent-review.md`](docs/decisions/independent-review.md)
holds the reasons.

The same review is required by name for each of these (V4):

- a change to the grader set of a bound target, or to a recipe in its closure;
- a change to an area invariant;
- a change to an existing contract `schema.zt`;
- a change to `scripts/spec/`, `contracts/task/`, `contracts/observation/`,
  `HUMAN_OWNERS`, `AGENT_ACCOUNTS`, `REVIEW_AGENTS`, or `specs/allowed_signers`;
- an item entering `#deferred` or `#cancelled` (V5).

A grader file or recipe that grades a promise, meaning an area requirement or
a terminal item nobody superseded, changes only from a new item. The judge
reads approvals from the current head, so a new push needs a new review.
An account in `AGENT_ACCOUNTS` never counts as an approval.

### Work-item requirement

Every implementation PR changes only paths under the `owns` of an item that
is **already on `main`** and is `#active` on the PR's head. This covers
features, bug fixes, architecture changes, behavioral refactors, protocols
and schemas, drivers, hardware bring-up, and authority or security changes.

Use the existing [change](.github/PULL_REQUEST_TEMPLATE/change.md) or
[system-change](.github/PULL_REQUEST_TEMPLATE/system-change.md) template. State
what changed, the claim, risks/invariants, review surface, exact verification,
evidence class, target or image identity when relevant, known limits, and
the related work item. Link existing evidence instead of duplicating it.
Name the item by its slug or UUID in the PR description.

### No GitHub auto-close

Do not use `Closes #123`, `Fixes #123`, or `Resolves #123` to complete work.
GitHub does not own work-item completion. A signed done witness on the
`evidence` branch and the closeout PR it allows do.

### Verification

Run the narrowest gate covering the changed behavior and the checks required
by [AGENTS.md](AGENTS.md). Record exact commands, observed results, evidence
class, scope, target or image identity when relevant, and limits; separate
direct observations from inherited evidence and label unobserved conclusions
as inference. Documentation-only PRs state that no runtime tests were run.
Ordinary changes do not require a devlog entry. Run `just docs_check` for
maintained documentation, policy, links, or command-reference changes. Archived
records retain their original checker at their immutable revision; no archive
checkout or network access is required for current docs checks. Run
`just spec_check --base origin/main` before opening a pull request,
`just spec_tasks_check` when it touches `.tasks/` or `specs/`, and
`just typos` for documentation.

## Review and completion

Review conduct — what a reviewer may post, how severity is assigned, and how an
author answers or declines a finding — is set in [AGENTS.md](AGENTS.md) under
"Code review"; it binds people, review bots, and agents alike. When an author
stops and asks, [HUMAN.md](HUMAN.md) says how to answer.

**Merge means implementation landed, not that work is complete.** An item is
done when every mandatory acceptance is enforced on the `evidence` branch at
the current closure digest. QEMU output does not prove hardware support, and a
green unrelated gate does not satisfy an acceptance. `just spec_tasks_status`
prints each item's state, and `just spec_status` prints each area
requirement's state.

### Evidence and closeout

The Evidence workflow (`.github/workflows/evidence.yml`) runs after each push
to `main`:

1. It runs every claimed target: those of `#active` items and of terminal
   items nobody superseded. `#planned` items are never claimed.
2. It publishes each record, keyed by closure digest and signed by `ci`, to
   the `evidence` branch.
3. It signs a done witness for each `#active` item whose mandatory
   acceptances are all enforced.
4. Its closeout bot runs `scripts/spec/closeout`. The bot opens one pull
   request per witnessed or `#cancelled` item that moves the file to
   `.tasks/terminal/` byte for byte.

The judge accepts that move only with a signed witness for the item's current
digest, or for a `#cancelled` item (V6). A terminal item never changes again.
The bot authenticates with a GitHub App token minted per run from the
repository variable `CLOSEOUT_APP_ID` and the secret
`CLOSEOUT_APP_PRIVATE_KEY`. A pull request opened with the workflow's built-in
token triggers no checks, so V6 would never run. Without `CLOSEOUT_APP_ID`,
the job skips closeout and succeeds. Preview locally with
`python3 scripts/spec/closeout --forge local --dry-run`.

## Trivial-change exception

The judge admits no exception. A typo fix in an implementation path still
needs an item on `main` that is `#active` and whose `owns` covers the path. A
change confined to process paths needs no item, and no judgement call is
needed.

## Continuous integration

General CI lives in `.github/workflows/ci.yml`. Pushes to `main` and `develop`,
and pull requests targeting any branch, run it; a newer run cancels the
superseded one for the same ref. The workflow's aggregate `CI` job fails unless
every gate job succeeded. The `Spec judge` workflow
(`.github/workflows/spec-judge.yml`) is separate from `CI`. The `main`
ruleset requires the `Devloop v1.5 judge` and `CI` checks and allows no bypass
of the judge check. It does not require Code Owner review. A pull request
could edit the judge's workflow or add one with the same check name. No
mechanism stops that: the review rules make it a blocking finding, and V11
requires a review of every head
([decision](docs/decisions/independent-review.md)).

Host checks, Kani, and the aggregates run on `ubuntu-latest`; the seL4 image,
root tests, rollback runtime, contract sources, and the four generation shards
run on `ubuntu-24.04-arm`, which is the product's native architecture and free
for public repositories. seL4 jobs enter the repository's pinned Nix dev shell
through the local `.github/actions/slime-env` composite action, which restores
the Nix store, `~/.rustup`, `~/.cargo`, and the persistent Cargo build outputs,
then fetches both pinned toolchains' locked dependencies before the deliberately
offline product build. Jobs that need neither the seL4 prefix nor Nix use a
plain pinned toolchain and `Swatinem/rust-cache`.

CI's `work_items` job runs `just spec_tasks_check` and `just spec_e2e` in
the `nix develop .#spec` shell. The Evidence workflow's closeout job uses
the same shell. `work_items` and the `Spec judge` workflow share one
`spec-v1-*` Nix cache key, computed from `flake.lock`, `flake.nix`, and
`nix/zutai.nix`. `work_items` roots the shell closure under `RUNNER_TEMP`, so
the cache action's post-job GC keeps it.

Every submodule resolves from GitHub over anonymous HTTPS: `deps/zutai`, the
seL4 fork, and the three rust-sel4 checkouts, whose exact origins are pinned in
`sel4/pins.toml` and enforced by `sel4_pin_check`. QEMU runs without
hardware-device access.

SDK publication (`publish-sdk.yml`, on the dedicated signing runner) stays
separate from ordinary CI: it relies on GitHub-specific permissions, events,
and secrets. SDK publication and signing keys retain their separate owners.
The evidence signing key lives in the `evidence` environment, which only
pushes to `main` reach.

## Further reading

- [README](README.md): what Slime OS is.
- [Getting started](docs/getting-started/01-orientation.md): how to learn,
  build, run, and change it.
- [AGENTS.md](AGENTS.md): routing, invariants, schemas, gates, work items, and change-record rules.
- [Architecture](docs/architecture/README.md) and [plans](docs/plans/README.md): current subsystem rationale versus unimplemented requirements.
- [History](docs/history.md): immutable archive lookup, privacy, evidence boundaries, and restoration.
