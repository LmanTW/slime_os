# Boot walkthrough

What happens between `just run` and the system coming to rest, told in the
order the serial output shows it. Read this with a real transcript beside it:
every stage below prints markers, and the markers are the system's only
self-description — the verification gates assert on nothing else.

Code pointers name where each stage lives; the modules' own doc comments are
the authoritative detail.

## What is in the image

`build/slime-sel4-graph.elf` is one ELF containing three things:

1. the **kernel loader** (from the pinned rust-sel4 fork) — sets up EL2/EL1,
   hands control to the kernel;
2. the pinned **seL4 kernel** — from `just run` onward, the only privileged
   code in the system;
3. **`slime-root`**, the initial task, with the **generation** compiled in
   (the deterministic manifest declaring every executable, instance, grant,
   and budget — built by `scripts/build/build-generation.py` from
   `contracts/generation-manifest/v1/fixtures/`). The fixture root, which the
   verification boot `just sel4_root_boot_check` uses, also embeds a small
   native child; a product root does not.

There is no disk and no loader search path: every byte the system will ever
execute is in this image, named by the generation, hash-verified at admission.

## Stage by stage

### 1. Loader and kernel

The elfloader prints its banner, seL4 boots, and hands `slime-root` the
`BootInfo`: the capability table it starts with and the untyped memory
regions everything else will be built from. From here on the kernel is
invisible except as the mechanism every later step invokes.

### 2. Root self-checks — `SLIME_ROOT allocator`, `SLIME_TIMER`, `SLIME_FOUNDATION`

`slime-root` starts single-threaded and proves its own foundations before
touching the generation. `slime-root/src/main.rs` brings up the allocator and
the console, and `run` in `slime-root/src/boot.rs` does the rest, in one order
for every root image:

- **Allocator** (`object_allocator.rs`): takes deterministic ownership of
  BootInfo's CSlots and untypeds, and reports the budget it will allocate
  every later object from.
- **Timer proof** (`platform_timer.rs`): acquires the platform timer IRQ,
  schedules a short deadline, and waits — bounded by the hardware clock — for
  the interrupt to actually arrive. A broken IRQ path fails the boot here,
  loudly, rather than hanging some later component.
- **Foundation probe**: allocates two frames and proves they are independent
  (no aliasing), with the allocation accounting checked to the byte.
- **Device probe** (`device.rs`): reports what virtio-mmio transports the
  machine actually declares. `just run` attaches no disk, so this reports
  absence — the storage gates attach one and assert the opposite.

A step that cannot go on prints `SLIME_ROOT FATAL <reason>`, and the root
parks. `main` does both with `fatal!`. A phase of `run` prints the record with
`stop!` and returns a `Stop`, and `main` parks the root. Nothing panics; every
failure is a typed, printed refusal.

### 3. Generation admission — `SLIME_ROOT generation admitted`

The embedded generation bytes are decoded
(`boot-contracts/src/generation.rs`) and admitted
(`slime-root/src/generation.rs`) against the target profile this root was
built for. Admission is where the system's core promise is enforced, before
any component exists:

- every executable payload is hash-verified and must be qualified for exactly
  this target profile — an image built for another target is refused before a
  byte of it is mapped;
- the declared fabric graph, if any, is checked against the root's own
  ceilings;
- the **whole plan is costed up front** (`SLIME_ROOT plan slots`): the root
  computes the total CSpace cost of every declared instance and refuses a
  graph that does not fit *before* activation, never partway through with
  children already running.

The markers state the counts — executables, instances, grants, how many
payloads are native ELF — and the authority manifest identity. The gates
pin these numbers per fixture; the shape is what to read.

### 4. Staging — `SLIME_GRAPH staged`, `SLIME_GRAPH endpoint`

For each root-autostart instance (in the product generation: only `init`),
the root builds the complete task — CSpace, VSpace with the ELF mapped,
TCB, IPC buffer, badged root and console endpoints, fault handler — without
running it (`task.rs`, `child_vspace.rs`). Generation-declared native
Endpoint edges between instances are created and installed at each side's
declared slots (`peer_endpoint.rs`).

The badge on each task's service endpoint is its identity: the root
authenticates every later request from the badge, so no component can speak
as another.

### 5. Activation and the declared graph — `SLIME_GRAPH activated`, `[init]`

Only after every allocation has succeeded does anything run. The root
activates `init`, and from here **policy leaves the root**: `init`
(`components/system/init/src/main.rs`) reads its own declared bindings, and
launches the graph the generation declares by asking the root to `SPAWN`
each child from a granted executable capability.

Watch the division of labor in the markers: `[init]`-prefixed lines are a
userspace component narrating its policy; `SLIME_GRAPH spawn authorized` /
`spawned` lines are the root recording the mechanism — which executable
slot, how many grants, endpoints, and supervision handles crossed. A spawned
child receives exactly the capabilities its grants declare, at the slots its
own logical numbering names, and nothing else: no environment, no paths, no
ambient anything.

### 6. Service and supervision — the graph runs

The root's dispatcher loop serves the two badged endpoints (`ipc.rs`, plus
the console thread — see `docs/syscall-abi.md` for the full operation
surface). Components talk to each other directly over their declared native
Endpoints; the root neither sees nor mediates that traffic.

When a component exits or faults, the root records it
(`supervision.rs`, `fault.rs`), reports it
(`SLIME_GRAPH component exit task=N status=S`), and reclaims the task's
entire per-task arena — TCBs, CNode, VSpace, frames — rather than leaking it
(`SLIME_GRAPH tasks reclaimed`). A parent that holds the child's supervision
handle observes the termination as a typed status, never as a signal or a
shared global.

### 7. Rest — `SLIME_GRAPH HEALTHY`

When every required instance has reached a terminal state cleanly, the
supervisor certifies the graph:

```
SLIME_GRAPH HEALTHY generation=N required=R live=0 completed=C failed=0
```

plus a final census proving nothing leaked: zero live tasks, zero
task-owned native capabilities, zero outstanding export tickets. The system
then comes to rest; QEMU keeps running until you quit (`Ctrl-A x`).

## How the gates read this

Every `just sel4_*_check` boots a real image and asserts an **ordered** list
of these markers — order matters, and a set of failure patterns
(`SLIME_ROOT FATAL`, `SLIME_GRAPH FAIL`, nonzero exit statuses, seL4's own
complaints) fails the run immediately. The tables live in
`scripts/check/check-sel4-*.py`, one per plane.

Two consequences worth internalizing:

- **Markers are contract surface.** Changing a marker's text or order breaks
  the gate that pins it; that is the design, not an accident. Change both in
  the same commit, and treat the gate diff as the evidence the change was
  intended.
- **The assertions themselves are tested.** `just sel4_gate_control_check`
  proves every gate fails on a deleted, reordered, or explicitly failing
  marker — so a green gate means the evidence was really there.

`just run` boots the same product image `just sel4_component_graph_check`
asserts, so if your interactive boot looked wrong, that gate will say
precisely which expectation broke and print the transcript.

## Next

The [concept pages](../concepts/components.md) give the mental models behind
what you just watched, and [your first change](04-first-change.md) walks the
workflow. [`AGENTS.md`](../../AGENTS.md) routes any change to its owning
module and its narrowest gate. The two reference documents —
[`capability-matrix.md`](../capability-matrix.md) and
[`syscall-abi.md`](../syscall-abi.md) — carry the exact authority and ABI
surfaces this walkthrough only gestures at.
