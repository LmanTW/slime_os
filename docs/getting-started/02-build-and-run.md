# Build and run

Goal: from a fresh clone to a booted Slime OS image under QEMU, plus the
verification aggregate that proves the boot you saw is the boot the repository
promises.

Everything below runs on the automated product target
`aarch64-sel4-qemu-virt`. No physical hardware is required.

## Prerequisites

### 1. Clone with submodules

The seL4 kernel, rust-sel4 crates, and Zutai are pinned Git submodules under
`deps/`. The Slisp product component is built directly from the in-tree
freestanding C sources.

```sh
git clone --recurse-submodules https://github.com/iceice666/slime_os.git
# or, for an existing checkout:
git submodule update --init --recursive
```

### 2. Enter the dev shell

The supported environment is the Nix dev shell:

```sh
nix develop
```

It provides everything the build needs — `just`, QEMU, CMake, Ninja, `dtc`,
the exact GNU AArch64 cross compiler the pinned kernel hashes were observed
with (exported as `CROSS_COMPILER_PREFIX`), a Python with the seL4 kernel
generators' modules, and `rustup`. On first entry its hook installs the two
pinned Rust toolchains:

- the workspace toolchain (declared in `flake.nix`), used by host crates and
  components;
- the rust-sel4 toolchain (declared in `sel4/pins.toml [rust_sel4]`), used to
  build the root task, its child, and the kernel loader.

Working outside the shell is possible but unsupported: you would have to
reproduce each of those pins by hand, and the pin check will still hold you
to them.

Supported host systems are the ones `flake.nix` declares: `x86_64-linux`,
`aarch64-linux`, and `aarch64-darwin`.

## First boot

```sh
just run
```

This chains three steps:

1. **`just sel4_pin_check`** — verifies every pin the product depends on:
   submodule commits and origins, the seL4 release, both Rust toolchains, the
   root target spec bytes, and the kernel configuration against
   `sel4/pins.toml`. It fetches and installs nothing; it only refuses.
2. **`scripts/build/build-sel4.py`** — configures, builds, and installs the
   pinned seL4 kernel into `build/sel4-prefix/`, builds the root task with the
   product generation embedded, builds the kernel loader, and packages
   `build/slime-sel4-graph.elf`. It also writes
   `build/slime-sel4.identity.json` recording source, config, ELF, and image
   digests. The first build compiles the kernel and every component crate, so
   it takes a while; later builds are incremental.
3. **QEMU** — boots the image on the pinned machine
   (`virt,virtualization=on`, cortex-a53, 1 CPU, 2048 MiB) with serial on
   stdio.

You will see the elfloader, then seL4's boot output, then the root task's
ordered `SLIME_ROOT` / `SLIME_GRAPH` markers as it admits the generation and
launches the component graph — see the
[boot walkthrough](03-boot-walkthrough.md) for what each stage means. The
graph remains resident with Slisp waiting for input; QEMU does not exit on its
own. Quit with `Ctrl-A x`.

## Verify

```sh
just test
```

The product behavioral aggregate: it boots the root-fixture image and the
component-graph image and asserts their ordered serial markers, then proves
the marker assertions themselves fail on missing, reordered, or
explicitly-failing evidence (`sel4_gate_control_check`).

Beyond the aggregate, each subsystem has its own narrow QEMU gate
(`just --list` shows all of them; `AGENTS.md` names the canonical one per
change area). The ones you will meet first:

```sh
just test_sel4_root      # slime-root's host unit tests (needs the built seL4 prefix)
just test_host           # contracts, protocol, helpers and production TCP engine
just contracts_check     # every Zutai contract and generated binding
just fmt_check_all       # formatting, all workspace crates
just lint_all            # clippy, warnings denied
```

## Common failures

**`missing pin manifest` / `unresolved import` / empty `deps/sel4`** —
submodules are not initialized. Run
`git submodule update --init --recursive`.

**`required tool is not on PATH: ...gcc`** — you are outside `nix develop`,
or entered it before the shell finished its hook. The build takes the cross
compiler from `CROSS_COMPILER_PREFIX`, which the shell exports as an absolute
store path.

**`the seL4 build's host Python generators are missing modules ...`** — the
kernel's own build drives Python generators through a bare `python3`; only
the dev shell's Python carries their dependencies. Enter `nix develop`.

**`sel4_pin_check` reports toolchain drift** — the built kernel's hashes no
longer match `sel4/pins.toml [observed_prefix]`. If you did not intentionally
change the kernel, config, or toolchain, suspect a moved `flake.nix` input
(the pins file's comments explain exactly what the hashes bind). Do not bless
new hashes to make the error go away; the mismatch is the finding.

**`test_sel4_root` / `lint_sel4_root` refuses to run** — both need the
installed seL4 prefix (`build/sel4-prefix/`), because the `sel4` crate reads
libsel4's generated config at build time. Run `just run` or
`just sel4_qemu_image_check` once first. Refusal is deliberate: silently
linting or testing a different configuration would be worse than failing.

### A boot appears to hang

First distinguish a resident guest from a failed automated gate. `just run`
starts QEMU directly and does not wait for a success marker or impose a boot
deadline; quit it with `Ctrl-A x`. Remaining alive is not itself a failure.

For an automated failure:

1. Identify the failing recipe's owning `scripts/check/check-sel4-*.py` and
   the image/platform it actually boots. The component-graph checker prints
   its QEMU command as `[boot] ...`; compare that command with the intended
   build rather than diagnosing a different image or target.
2. Read the printed serial transcript tail and compare it with that checker's
   required markers, failure markers, and terminal condition. Distinguish
   explicit failure, missing evidence, and out-of-order evidence. A deadline
   says the required observation did not complete; it does not identify the
   guest's root cause or establish that rerunning will fix it.
3. For `just sel4_component_graph_check`, inspect
   [`check-sel4-component-graph.py`](../../scripts/check/check-sel4-component-graph.py):
   its 120-second boot session waits for `[slisp] resident input wait`, feeds
   `(+ 1 1)` and `sysinfo`, then requires both `=> spawned sysinfo` and the
   root's supervision-collection record. A resident-input marker alone is
   not a completed check. Its full marker assertions still run after capture.
4. Inspect the owning runner if capture or shutdown is the issue. This graph
   checker uses [`sel4_boot.run`](../../scripts/lib/sel4_boot.py), which bounds
   QEMU with a watchdog, captures combined stdout/stderr, and terminates the
   process after the marker/input session. It does **not** require the guest
   to exit. Other checkers may own their own loop and deadline; do not assume
   this graph checker's terminal condition applies to every gate.

## Where things land

| Path | Contents |
| --- | --- |
| `build/sel4-prefix/` | the installed seL4 kernel, libsel4, and platform info |
| `build/sel4-cargo/` | cargo target directories for the seL4-target crates |
| `build/slime-sel4-graph.elf` | the packaged product image `just run` boots |
| `build/slime-sel4.identity.json` | digests tying the image to its sources |

`build/` is disposable; deleting it costs you one full rebuild.

## Next

- [Boot walkthrough](03-boot-walkthrough.md) — what happens between `just run`
  and the terminal `SLIME_GRAPH HEALTHY` marker.
- `AGENTS.md` and [`task-to-file.md`](../task-to-file.md) — the code map and the routing index for making a change.
- `just spec_tasks_status` — each work item's state from the `evidence`
  branch: what is open and what is enforced.
- [Architecture](../architecture/README.md) — current subsystem ownership and
  invariants; [plans](../plans/README.md) — unfinished requirements.
