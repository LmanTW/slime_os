# Slime OS

Slime OS is an experimental atomic personal operating system: a Rust `no_std` userspace graph on upstream seL4, not a Linux distribution. Its purpose is to explore capability-based isolation, component-oriented system services, explicit resource authority, and generation-based deployment.

The current product is a QEMU-verified `aarch64-sel4-qemu-virt` image: upstream seL4 16.0.0 owns scheduling, address spaces, memory objects, capability enforcement, IPC, interrupts, and timers, while `slime-root` owns the dynamic mechanism above them — generation admission, task construction and reclamation, bounded object allocation, shared buffers, native Endpoint IPC, and fault supervision. The custom microkernel that preceded it was retired with P5; there is no Slime kernel and no Slime trap vector.

The Milk-V Duo (`riscv64-sel4-milkv-duo`) has observed upstream-seL4 product-boot evidence. The named Framework 13 has a recorded removable-media CPU/product boot, not device qualification. Raspberry Pi 5 boot, physical NVMe, and daily-driver hardware remain unclaimed. See [target profiles and evidence limits](docs/architecture/targets-and-portability.md).

[Subsystem architecture](docs/architecture/README.md) names current owners and limits; [component/system/image boundaries](docs/architecture/component-system-image.md) explains the spec-derived build path.

## Vision

Slime OS is designed around five first-class concepts:

- **Component:** an isolated, versioned executable unit with an address space and explicit dependencies.
- **Capability:** unforgeable authority to use a kernel object or service endpoint.
- **Channel:** IPC that can carry messages and transfer capabilities.
- **State:** persistent data with an owner, schema, and upgrade/rollback policy.
- **Generation:** a complete bootable graph of components, capability grants, state bindings, and immutable objects.

A generation is built and verified before it becomes bootable. Activation must not overwrite the running system in place. The previous known-good generation remains available, and a pending generation becomes known-good only after userspace health confirmation.

Atomicity therefore covers more than package files: it includes the boot selection, component graph, service endpoints, and declared persistent-state transitions.

Slime OS is not intended to become a small Unix clone with a different kernel implementation. Its native model is capability-based and component-oriented.

The [target-profile reference](docs/architecture/targets-and-portability.md) distinguishes current seL4 identities, retained artifact identities, the Raspberry Pi 5 build boundary, and physical evidence.

## Language responsibilities

Slime OS does not need new configuration or shell languages. Two sibling projects already define those surfaces.

Both projects are pinned as Git submodules under `deps/`. Clone the complete source tree with:

```sh
git clone --recurse-submodules https://github.com/iceice666/slime_os.git
```

For an existing checkout, run `git submodule update --init --recursive`.

### Zutai: system configuration

[Zutai](deps/zutai) is the configuration evaluation language:

- `.zti` provides inert deterministic data;
- `.zt` provides pure, lazy, typed transformation and validation;
- records, unions, optionals, overlays, packages, and serialization provide the configuration vocabulary.

The configuration path is intentionally separated from activation:

```text
Zutai source and hardware data
    -> pure evaluation and normalization
    -> versioned Slime build request
    -> component/object resolution
    -> immutable generation manifest
    -> staged activation
```

Production system evaluation must not receive authority to modify the boot partition, switch generations, format storage, or grant capabilities. Zutai describes intent; the Slime builder validates and executes it transactionally.

Zutai host capabilities are language-level declarations and are currently advisory. They are not seL4 capabilities. A Zutai runtime on Slime may hold opaque handles backed by real service capabilities, but only seL4 and trusted services enforce and transfer authority.

The build pipeline runs Zutai on the development host. Porting the compiler/runtime into Slime userspace is deferred behind the demo path.

### Slisp: native interactive language

Slisp is the resident native shell and application language. Its syntax is only
S-expressions: integers, symbols, lists, lexical functions, `let`, `if`, `do`,
`quote`, and persistent top-level `define`. The freestanding C implementation
proves component development is not tied to Rust; it is built as an external
AArch64 ELF, hash-admitted through the ordinary component specification path,
and launched with only its generation-declared input and service endpoints.

Shell operations will be ordinary capability-bearing functions. Process spawn,
streams, filesystem access, diagnostics, and termination remain explicit Slime
service contracts rather than reader punctuation or ambient POSIX state.

### Native application compilation

The [native-development plan](docs/plans/native-development.md) extends Slisp from its bounded interpreter to a
compiler that emits the exact target-qualified Slime component-image format.
Zutai remains the only schema/configuration language; Slisp may consume generated
bindings but cannot define a second cross-boundary format or grant authority.

See [component and image boundaries](docs/architecture/component-system-image.md).

## Agentic direction

The five first-class concepts are also the natural primitives for running autonomous agents safely, and no new authority model is required for it.

- **Agent = Component.** An agent is an isolated component with an address space and explicit dependencies. Agent fault containment is component fault containment: a crashing agent does not terminate its peers, the services it uses, or the system.
- **Tool call = Channel.** A tool invocation is a typed IPC message to a service endpoint, not an arbitrary function call. The endpoint's schema defines the message; capability transfer along the channel is the only way authority crosses the boundary.
- **Agent authority = Capability grant.** Spawn supplies no implicit environment, working directory, streams, or other authority. An agent receives only the grants declared by the generation, and unforgeable capabilities mean authority cannot be ambient, guessed, or widened at runtime.
- **Agent memory = State binding.** Long-term agent state is a `StateBinding` with an owner, schema version, and policy. `snapshotBeforeUpgrade` and `discardOnRollback` give agent memory the same upgrade and rollback discipline as the rest of the system.
- **Agent update = Generation.** Changing an agent's model, prompt, or tool set produces a new generation. Health checking applies to agent behavior as well as to boot: a pending generation becomes known-good only after userspace confirmation, and a regressing agent rolls back with the same mechanism as a regressing system component.

Privileged mechanism does not treat agents or language models as special. A language model is a userspace service component that agents address over endpoints; the scheduler, context, and memory concerns of agent runtimes live in userspace services. This keeps mechanism policy-free for agents as it is for every other subsystem, and lets model choice, provider, and placement change as a generation without touching the component ABI.

External agent protocols such as MCP may be bridged by a dedicated component that exposes protocol servers as Slime capability endpoints. The bridge cannot grant authority the agent does not already hold, so prompt injection success at the model layer is still bounded by the generation's declared grants.

Because no component holds ambient authority, every capability can be transparently interposed by a user-chosen proxy component (a membrane). This enables agent dry-runs: an agent can be executed against virtualized capabilities to preview the effects it *would* have, before any real authority is granted. Capability transfers can also record provenance, so the system can answer "why is this component allowed to do X" as an explicit grant chain rooted in the generation manifest.

Atomicity and agentic operation reinforce each other: agent memory and authority are versioned, verified, and rollbackable by the same mechanisms as the boot graph, and the boot graph can include agent components without a separate agent deployment track.

## Differentiating directions

Exploratory directions are registered in [`docs/directions/`](docs/directions/README.md). They are not committed work: promotion requires a canonical work item with an observable exit condition and design context in the owning [`docs/plans/`](docs/plans/README.md) page.

## Plan and work items

See [CONTRIBUTING.md](CONTRIBUTING.md) for GitHub intake, planning-before-implementation,
naming the implemented item, and evidence-based completion. See [HUMAN.md](HUMAN.md) for the
decisions the people on the project own and how to read an agent-written PR.

Work-item identity, intent, hierarchy, dependencies, and acceptances live in `.tasks/items/`, one task/v2 Zutai file per open item, named by its slug and identified by a canonical UUID. Closed items move unchanged to `.tasks/terminal/`. Area files under `specs/` hold the frozen promises, and [`specs/legacy.zt`](specs/legacy.zt) indexes the 448 V1 items by UUID and names the commit that holds their full text. Human keys such as `C9.4`, `IO4`, and `B92` in older text are display aliases that no checker resolves. Signed observation records live on the `evidence` branch.

```sh
just spec_tasks_status   # each item's state from the evidence branch
just spec_status         # each area requirement's state from the evidence branch
just spec_tasks_check    # validate items, area files, and schema copies
just spec_check          # the judge; add --base origin/main to judge a branch
```

Current ownership, invariants, and limitations live in
[`docs/architecture/`](docs/architecture/README.md). Unimplemented designs and
qualification requirements live in [`docs/plans/`](docs/plans/README.md);
long-lived choices in [`docs/decisions/`](docs/decisions/README.md) retain their
accepted or proposed status. [`docs/`](docs/README.md) is the entry point.

Historical
chronology and devlogs are preserved in the [private archive](docs/history.md). Open backlog
bugs precede milestone work under rule V7 of `scripts/spec/check`; this page does not carry
a second priority or completion table.

## Current repository layout

```text
Cargo.toml       Root Rust workspace and shared build profiles
sel4/            Upstream seL4 pins (`pins.toml`) and per-platform CMake configuration
slime-root/      The seL4 root task: generation admission, tasks, allocation, shared buffers, IPC, supervision
components/      Rust no_std userspace components, one crate per component under system/, services/, applications/, and testkit/, plus the syscall runtime (`runtime`), shared helpers (`lib`), and generated protocols (`proto`)
boot-contracts/  Shared Rust boot, generation, storage, recovery, and admission contract decoders
contracts/       Versioned Zutai schemas for every persisted, IPC, and boot format, plus generation fixtures
scripts/         Host tooling grouped as build/, check/, generate/, lib/, and spec/ (the work-item judge)
tools/           Developer-facing helpers such as LLDB attachment
docs/            Current architecture, operation, references, decisions, plans, and exploration
docs/history.md  Immutable private archive locator and evidence/restoration boundary
assets/          Boot/runtime assets
deps/            Pinned seL4, rust-sel4, and Zutai submodules
.tasks/          Canonical work-item store (`items/` open, `terminal/` closed)
specs/           Area files holding frozen promises, the V1 item index, and evidence signers
Justfile         Build, run, test, format, lint, generation, contract, and debug commands
```

Common development commands (see `just --list` for the full gate set):

```sh
just run                    # boot the seL4 product image on the pinned QEMU machine
just test                   # product behavioral aggregate
just test_sel4_root         # slime-root's host unit tests, count asserted
just contracts_check        # validate every Zutai contract and generated binding
just fmt_check_all
just lint_all
```

## Non-goals for the initial system

- supporting arbitrary PCs;
- reproducing Linux, FHS, systemd, UID/GID, `fork`, signals, or ambient path authority as native primitives;
- writing a desktop environment before isolation and service recovery work;
- running existing Linux binaries directly;
- inventing another configuration language or shell;
- embedding a language model, agent runtime, or agent scheduler in privileged mechanism;
- granting agents authority to switch generations, format storage, or grant capabilities;
- running agents outside the capability and generation model;
- treating a framebuffer demo as completion of an OS architecture milestone.

Linux remains useful as the development host and may later run as an isolated guest for compatibility. It does not define Slime OS's kernel, native ABI, authority model, or deployment architecture.
