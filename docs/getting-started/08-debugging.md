# Debugging

What to do when a gate fails for a reason you did not expect, or an
interactive boot does something you did not intend. The system has no
debugger-friendly surface by design; its self-description is the serial
transcript, and this page is a field guide to reading it.

Start from the *first* deviation in the transcript, not the last line. A root
that prints `SLIME_GRAPH FAIL` at activation will print nothing useful after,
and a gate that times out is usually reporting a consequence three stages
removed from its cause.

## 1. Which layer refused?

A `just <plane>_check` can fail in four distinct places. The error text tells
you which; do not diagnose a QEMU problem when the build never ran.

| You see | Layer | Meaning |
| --- | --- | --- |
| `closure does not resolve: implementations[<name>].artifact: identity mismatch for <path>` | Closure resolution, before any build | A tree the closure digests changed (your edit, a submodule bump, an untracked file). Run `python3 scripts/generate/generate-system-image-closures.py`. If you did not edit that path, `git status` — the generator refuses a tree holding ignored files, and the resolver walks the raw filesystem. |
| `stale closure(s): … run python3 scripts/generate/…` | `just system_image_builder_check` | Same cause, caught by the drift gate rather than a plane. |
| `<name>: closure build failed:` followed by 20 lines of cargo/CMake | Image build | Ordinary compile error. The full log is in `build/closure/<name>/`; rerun the plane after fixing. |
| `fixture is missing '<declaration>'` | Checker preflight | The derived composition manifest no longer declares something the checker pins (generation number, an instance, a notification). Either regenerate from the system spec or update the checker's pin deliberately. |
| `QEMU timed out after Ns before terminal condition` + last 80 lines | Run | The terminal marker never appeared. Read the tail: usually a component is waiting for something, or the root printed a `FAIL` the terminal regex does not include. |
| `QEMU exited with status N before terminal condition` | Run | The guest halted or QEMU died. A seL4 kernel panic or a `SLIME_ROOT FATAL` that parks the root ends up here on some planes. |
| `failure marker in serial transcript: '…'` | Marker contract | An explicit failure was printed; the marker names who. |
| `<chain>: missing marker: <regex>` | Marker contract | The transcript never matched the pattern. Check the emitting code's exact text against the regex — a changed number or a stray space is the usual cause. |
| `<chain>: marker out of order: <regex>` | Marker contract | The pattern matched somewhere, but before an earlier marker in the same chain. Either the causal story changed or two independent events were put in one chain. |

The checker only reports the first marker problem; after fixing it, expect
the next.

## 2. Reading the root's vocabulary

Every root line is `SLIME_ROOT …` (before the graph exists) or
`SLIME_GRAPH …` (once instances exist). The families you will meet while
debugging:

**Fatal, before the graph.** `SLIME_ROOT FATAL <reason>` — allocator,
timer proof, generation decode, or admission failed; the root parks. The
reason is a typed refusal (`stop!` or `fatal!`, in
`slime-root/src/graph_runtime.rs`), never a panic. An image built for the
wrong target profile, a hash mismatch, or a superseded generation format
shows up here.

**Refusal at admission or activation.** `SLIME_GRAPH FAIL <what> rejected …`
— the generation decoded but the root will not build the plan: CSpace plan
over budget, a binding whose authority does not exist, an instance mapping
that does not fit, a dependency the graph cannot satisfy. The `what` names
the owning module (`slime-root/src/graph_runtime/services/`). Fix the system
spec, regenerate, and re-check `just sel4_boot_layout_check`.

**A component asked for something it may not have.**
`SLIME_GRAPH request rejected task=N label=L error=E` — a root syscall was
refused. `label` is the operation label from
[`syscall-abi.md`](../syscall-abi.md); `error` is the typed reason (missing
right, unknown slot, budget exhausted, bad operand). This is the most
common outcome when you add a call to a component without adding the grant
to the system spec. `SLIME_GRAPH service refused task=N label=L
class=undeclared` is the stricter cousin: the composition did not declare
that service class for this task at all. `SLIME_GRAPH binding unresolved
task=N …` means a name the component resolved was never bound in its spec.

**Per-operation lines appear once.** The root prints `SLIME_CLOCK served`,
`SLIME_CLOCK refused` and `SLIME_IO payload dma` only the first time each key
occurs. To see how often an operation repeated, read the
`SLIME_ROOT diagnostic repeats …` line just before `SLIME_GRAPH served`; a
missing second line is not a missing operation.

**A component died.**

- `SLIME_GRAPH component exit task=N status=S` — a clean `exit(S)`.
  `status=1` with nothing printed before it is what a **Rust panic** looks
  like: the component runtime's panic handler calls `exit(1)` without
  printing (`components/runtime/src/lib.rs`). Wrap the suspicious step in a
  `debug_write` before and after; you will not get a panic message.
- `SLIME_GRAPH component fault task=N kind=<Kind> address=Some(0x…)` — a
  hardware fault the root supervised: a VM fault (unmapped access — a bad
  pointer into a shared buffer window, a stack overflow, a private-memory
  region not yet grown), a cap fault (invoking a slot that holds nothing —
  usually a slot number that disagrees with the system spec), or an unknown
  syscall. `address` is the task-virtual address; compare it with the
  component's linked layout and its declared windows.
- `Caught cap fault` / `Caught vm fault` printed by **the kernel itself** —
  the faulting thread had no fault handler. On a plane that is the root
  thread, and it means the root's own code faulted; every plane lists it as
  a failure marker.
- `panicked at …` — a Rust panic message in the transcript comes from the
  root or the loader (`panic = "abort"`), never from a component.

**Cleanup did not balance.** `SLIME_GRAPH loans served=… loans=0 mappings=0
regions=0 orphans=0 quota=0` and the final `HEALTHY … live=0` census are
the leak detectors. A nonzero `orphans` or `live` after every component
exited means something still holds a capability or mapping; the task id in
the preceding `holder reclaim incomplete task=N` line says who.

**Health census mismatch.** `SLIME_GRAPH HEALTHY generation=G required=R
live=L completed=C failed=F` — gates pin every number. If your change added
an instance and the gate fails here, you changed the graph: update the pins
in the checker and the `generation admitted … executables= instances=
grants=` line together.

## 3. Reading component markers

Components narrate with `[<name>] …`. Three conventions matter:

- `[<name>] fail: <why>` is the component's own assertion failure. Every
  plane lists its participants' `fail: ` prefix as a failure marker, so it
  ends the run at once with the reason attached. Use it in probes instead of
  panicking.
- A probe that reaches its end prints a terminal marker such as
  `[io-queue-client] io queue plane complete`; the component spec's
  `passFailCriteria` names it and the checker's last chain ends near it.
- Silence is data. A component that printed its `ready` line and nothing
  more is blocked on a wait (an endpoint `recv`, a wait set with no signal
  arriving). Check that the *other* side's notification or endpoint grant is
  declared and that both sides agree on the slot the system spec pins.

## 4. Reproducing outside the checker

Every plane leaves its image in `build/closure/<name>/image.elf` beside
`root.elf`, `loader.elf`, the built `generation/`, and `build-result.json`
(which records the closure identity the image was built from). Boot it by
hand with the same machine profile the checkers read from
`sel4/pins.toml [qemu_arm_virt]`:

```sh
qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 -smp 1 \
    -m size=2048M -nographic -serial mon:stdio \
    -kernel build/closure/sel4-io-queue/image.elf
```

Quit with `Ctrl-A x`. This gives you the full transcript without the
checker's 80-line tail, and lets you type at an interactive plane. Planes
that attach a disk or a network backend add arguments; copy them from the
checker's `additional_arguments` (or its printed `[boot]` line on the
component-graph checker). If the plane feeds input after a readiness marker
(`input_trigger` / `input_text` in the checker), type it yourself.

Passing `--no-build` to a checker reuses the last image, which is useful
when you are iterating on the marker table rather than the code.

`gdb` through QEMU's `-s -S` works mechanically but is unsupported here:
the root is built with the size-optimized `root-image` profile and every
component crate sets `debug = false`, so you get addresses without symbols.
Markers are the supported instrument; add one where you would have set a
breakpoint.

## 5. Host-side checks that fail before QEMU

- **`just test_sel4_root` asserts its test count** (`just/quality.just`).
  It counts the `#[test]` attributes in the library files the run compiles
  and compares that with the tests that ran. "ran N tests, expected M" means
  the source holds a test the run did not execute, or the reverse. Look for a
  `cfg` on a single test or on an inline module, which the count does not
  read, or for a test that a macro generates. A file that no module declares
  is in neither number; `just root_size_check` refuses it.
- **`just sel4_gate_control_check` fails after you edited a chain** — its
  `GATES` table pins each checker's marker count. Update the count in the
  same change.
- **`just component_spec_check` rejects `passFailCriteria`** — the literal
  is not a string in the named recipe's check script. Copy it from the
  checker, including brackets.
- **`just sel4_boot_layout_check` shows a diff** — a grant, slot pin, or
  budget moved. Read the diff; bless with `just sel4_boot_layout_bless`
  only when the moved slot is the change you meant.
- **`just docs_check` names an absent recipe** — a `just <name>` literal in
  documentation, a task requirement, a script, or CI does not exist. Recipe
  names are contract surface for docs; rename both.
- **`just spec_check --base origin/main` prints a `V2` finding** — an
  implementation path sits under no `owns` glob of an item that is on base and
  `#active` on head. Set the owning item to `#active`, or land a planning PR
  that adds the glob first.
- **The same command prints a `V3` finding** — the implementation PR touches
  a checker or recipe that grades a bound target. Move that change to a
  planning PR.

## 6. When you have found it

Fix the cause, not the observation. Then:

1. regenerate closures if any digested tree changed;
2. rerun the narrowest plane gate green;
3. if the marker table changed, rerun `just sel4_gate_control_check`;
4. write the *first* deviation and the fix in the PR's verification section.

If the investigation was expensive and the conclusion is reusable, keep the
conclusion beside the owning code as an invariant comment or in the owning
`docs/architecture/` page — not the transcript, and not a narrative in a
code comment. The [history guide](../history.md) says where raw evidence goes
if it must be preserved.

## Next

- [Write a contract](09-write-a-contract.md) — when the thing you are
  debugging is a wire format.
- [Component runtime tour](10-component-runtime.md) — the runtime API a
  component is written against, and which refusals each call can produce.
