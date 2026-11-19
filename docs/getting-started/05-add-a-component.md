# Add a component

A buildable crate is not a running component. A component reaches QEMU only
when all five layers agree:

1. **Implementation** — one buildable component crate.
2. **Declaration** — one component specification describing what that component
   is and what it requires.
3. **Composition** — one generation includes an executable and an instance.
4. **Authority and launch policy** — the actual spawner can launch it, and the
   instance receives only its declared grants and bindings.
5. **Observed behavior** — the owning QEMU gate sees admission, launch, the
   component's marker, its intended terminal or healthy-idle state, and the
   final health census.

A crate or catalogue entry never launches itself. Keep that invariant in view
through every step below.

For the smallest current in-tree crate shape, read the
[`sysinfo` crate](../../components/system/sysinfo/) beside its
[component specification](../../contracts/component-spec/v1/components/sysinfo.zti).
`sysinfo` is an authority-free system utility whose component-spec type remains
`application`; source lifecycle ownership and contract type are separate axes.
The `hello` snippets below copy that crate shape but place the new leaf workload
under `applications/`; they do not copy `sysinfo`'s product role or add its
launch-context behavior.

## Choose the layer you are changing

| You are adding | Source to change | What it means |
| --- | --- | --- |
| Buildable in-tree code | `components/{system,services,applications,testkit}/<name>/` | Cargo can produce a component ELF. The selected root records lifecycle responsibility; nothing runs yet. |
| A component declaration | `contracts/component-spec/v1/components/<name>.zti` | The repository can validate the component's identity, requirements, compatibility, and evidence. Nothing runs yet. |
| A system composition | [`contracts/system-spec/v1/systems/*.zti`](../../contracts/system-spec/v1/systems/) | A system spec selects components, placement, authority, budgets, and graph records from which a generation manifest is derived. |

All manifests under `contracts/generation-manifest/v1/compositions/` are
generated outputs, not editable composition sources. The derivation map,
`DERIVED_GENERATION_FIXTURES` in
[`scripts/lib/system_spec.py`](../../scripts/lib/system_spec.py), is built from the
spec files in `contracts/system-spec/v1/systems/`. The generator and the system-spec
gate share it:

- `contracts/system-spec/v1/systems/reference.zti` derives
  `contracts/generation-manifest/v1/fixtures/valid.zti`.
- `contracts/system-spec/v1/systems/sel4.zti` derives the default product's
  `contracts/generation-manifest/v1/compositions/sel4.zti`.
- Every other system spec `<name>.zti` derives `<name>.zti` under `compositions/`.

Editing `reference.zti` alone does **not** change `just run`. To change the
default product, edit `contracts/system-spec/v1/systems/sel4.zti` and regenerate
its manifest. Never hand-edit a generated manifest.

## 1. Add the implementation crate

First choose exactly one lifecycle root:

- `system/` for boot-critical platform policy and system utilities;
- `services/` for resident service components;
- `applications/` for shipped user workloads; or
- `testkit/` for probes, fixtures, fault injectors, and verification workers.

Do not choose a root from the protocol the component happens to use or the
composition that first launches it. A component has one lifecycle owner even
when it participates in several protocols and generations. The `hello` example
is a shipped leaf workload, so create this minimum layout:

```text
components/applications/hello/
├── Cargo.toml
├── build.rs
└── src/
    └── main.rs
```

`components/applications/*` is already a workspace-member glob, as are the
other three lifecycle roots, so no new entry is needed in
`[workspace].members`.

### `components/applications/hello/Cargo.toml`

```toml
[package]
name = "slime-component-hello"
version = "0.1.0"
edition = "2024"
publish = false
rust-version = "1.96"
build = "build.rs"

[[bin]]
name = "hello"
path = "src/main.rs"
test = false

[dependencies]
slime-rt = { path = "../../runtime" }

[build-dependencies]
slime-build-support = { path = "../../build-support" }

[lints]
workspace = true
```

### `components/applications/hello/build.rs`

```rust
fn main() {
    slime_build_support::configure();
}
```

The build script configures the shared component build environment. It must not
parse a generation, copy private per-plane data, or derive capability slots.

### `components/applications/hello/src/main.rs`

```rust
#![no_std]
#![no_main]

slime_rt::entry!(main);

fn main(_startup_arg: u32) {
    slime_rt::debug_write(b"[hello] running\n");
}
```

The marker is behavioral contract surface once a QEMU gate asserts it. Change
the emitting code and that gate's ordered marker table together.

### Add the release profile

Cargo has no package glob that applies these settings to workspace members.
A real component addition must add this exact root `Cargo.toml` stanza:

```toml
[profile.release.package.slime-component-hello]
opt-level = "s"
codegen-units = 1
debug = false
```

The size settings are load-bearing because `slime-root` maps a component image
whole.

`just component_crate_split_check` enforces the crate boundary:

- lifecycle root, directory `hello`, package `slime-component-hello`, and
  binary `hello` agree;
- the crate declares exactly one binary and `build = "build.rs"`;
- `build.rs` does nothing except call `slime_build_support::configure()`;
- allocator features remain scoped to the component groups that require them;
- the root release-profile stanza exists with the exact settings above;
- lifecycle category roots contain no `Cargo.toml` or `src/` of their own; and
- reusable source shared by multiple crates lives in `components/lib`.

Do not enable an allocator for an authority-free leaf component. Private
modules may remain inside the leaf crate. If two components need the same
source, move that source to `components/lib` instead of creating a second
category-level or cross-crate shared-code location.

## 2. Declare the component

Add `contracts/component-spec/v1/components/hello.zti`, but do not invent the
record from an empty template. Copy the nearest **admitted** component spec and
replace every semantic field. For this leaf shape,
[`sysinfo.zti`](../../contracts/component-spec/v1/components/sysinfo.zti) is the
starting point.

A component spec describes the component independently of any one composition.
Its field groups require deliberate choices:

- **Identity and implementation:** choose `name`, `componentType`, version,
  purpose, and owner; for this crate use `implementation.provider =
  "workspace"`, `implementation.binary = "hello"`, and an empty
  `contentHash`.
- **Capability kinds:** `provides` and `requires` summarize the authority the
  reference generation actually gives the component. Start empty for this leaf
  example. Add a kind only when the composition contains the corresponding
  grant; never use these lists as a wish list.
- **Interfaces and communication:** leave interfaces and QoS empty when the
  component has no IPC or fabric role. A real interface is a versioned Zutai
  schema under `contracts/`, followed by generated bindings and matching
  composition records — not a Rust-only wire struct or a second schema language.
- **Lifecycle:** select the admitted states in canonical order. A simple leaf
  follows the nearest comparable component; service readiness, degradation, or
  stop behavior must be reflected rather than assumed.
- **Resources:** declare the stack and every bounded resource. Spawn budget,
  extra threads, shared-buffer pages/count/mappings/loans, and private-page
  quota stay zero unless observed behavior requires them.
- **Health:** choose `required` or `optional` consistently with the composed
  instance and health census. A component is not required merely because it is
  useful.
- **Compatibility:** keep the platform equal to the execution environment and
  select modes derived from the component's real dependencies, resources,
  runtime, interfaces, and QoS.
- **Evidence:** `test.requiredTestEnvironment` must name a real Justfile target,
  and `test.passFailCriteria` must be an exact string literal asserted by that
  gate's check script.

Do **not** copy a fictitious `hello.zti` with a made-up gate. First choose and
extend the real QEMU gate that owns the new behavior; then make the spec point
to that target and one of its actual evidence markers. `just
component_spec_check` validates both the record and this evidence link.

## 3. Compose an executable and an instance

The declaration says what `hello` is. A composition says that one instance of
it exists in one generation, who owns it, how it starts, what it may access,
and how the graph accounts for it.

### Edit the system spec and regenerate

Use the matching source under
[`contracts/system-spec/v1/systems/`](../../contracts/system-spec/v1/systems/).
For the default product, use
[`sel4.zti`](../../contracts/system-spec/v1/systems/sel4.zti).
After editing the source, regenerate the declared manifests:

```sh
python3 scripts/generate/generate-generation-from-spec.py
```

The generator uses the shared derivation map to produce all composition
manifests and the reference fixture. It derives executable, instance, object,
binding, budget, and health records from the system spec plus the component-spec
corpus. Review the generated manifest; correct its sources and regenerate
instead of patching the output.

### Facts every composition must cover

Declare these facts in the system spec and component specs, then verify them
in the generated manifest:

1. **Executable and object:** the executable names the `hello` artifact, role,
   command profile if any, spawn budget, and generation-module object.
2. **Instance placement:** the instance names that executable, its owner,
   autostart policy, dependencies, health classification, and any scheduling or
   thread facts.
3. **Spawner authority:** the actual userspace spawner receives an executable
   grant targeting `hello` with both `exec` and `spawn` rights. A catalogue
   executable without this edge remains inert.
4. **Holder binding:** the executable grant is bound into the spawner's
   capability table. Omit a slot pin when deterministic assignment is enough.
5. **Health membership:** required instances appear in the applicable required
   set; optional instances do not silently inflate the terminal census.
6. **Budgets:** stack, spawn, shared-buffer, mapping, loan, private-memory, and
   other ceilings agree with the component spec and intended behavior.
7. **Optional state:** declare persisted state, schema version, owner, and
   rollback policy only when the component genuinely owns state.
8. **Interfaces and fabric:** add interface schemas, route participants,
   interposition, notifications, QoS, and fabric budgets only for a component
   that participates in those mechanisms.

### Launch policy: ownership is active

The root stages and activates only root-owned autostart instances. Every
owner-spawned instance needs both:

- an executable capability held by its declared owner; and
- an explicit `slime_rt::spawn` call in that owning policy component.

The product graph demonstrates the distinction. Its catalogue contains
`console` and `spawn-service`, but `init` explicitly resolves their executable
bindings and calls `slime_rt::spawn`. Their catalogue and instance records do
not launch themselves. If `hello` is owned by `init`, extend `init`'s owning
boot action and supervision path; if another policy component owns it, that
component must perform the spawn.

Autostart on an owner-spawned instance states composition policy; it does not
turn root into the spawner.

## 4. Add only required authority

Start with no grants. The `hello` example needs none for its own behavior; the
only new authority edge is the executable capability its owner needs to launch
it.

For every additional grant, answer all five questions in the composition and
code review:

1. **Source:** which instance owns or creates the object?
2. **Holder or target:** which instance receives authority, and is that the
   same instance the grant's target names?
3. **Rights:** which exact root-checked operations does the behavior require?
4. **Transferability:** may the holder pass a narrowed copy onward, or must the
   grant remain local?
5. **Binding:** under which declared name does the holder resolve it, and does
   an existing ABI require a particular slot?

Default to the narrowest rights and `transferable = false`. Do not add ambient
authority, broad service access, or an executable grant to a convenient holder
that is not the actual spawner.

Bindings may omit `slot`; the generation builder assigns deterministic slots by
grant name within each holder's namespace. Pin a slot only when preserving an
existing ABI or byte-frozen boot layout. A new component does not justify fixed
numbers by itself. If a frozen layout must move, review and bless the deliberate
boot-layout diff rather than weakening the gate.

See [Components](../concepts/components.md) for the isolation model and
[Capabilities](../concepts/capabilities.md) for grant, spawn-grant, and transfer
semantics.

## 5. Prove behavior under QEMU

A component is complete only when the narrowest owning QEMU gate observes the
whole vertical slice in order:

1. generation admission includes the intended executable, instance, grants,
   objects, and budgets;
2. the root stages it if root-owned, or the owner receives an executable
   binding and the spawn is authorized;
3. the expected instance is staged and activated;
4. the gate observes the exact component marker, such as `[hello] running`;
5. the component exits cleanly, or reaches its intended healthy-idle service
   state;
6. terminal components are reclaimed, including task-owned capabilities; and
7. the final `SLIME_GRAPH HEALTHY` census has the intended required, live,
   completed, and failed counts.

Treat the gate as a contract, not a smoke-print search. Existing checks pin
hard-coded executable, instance, required, and completed counts, plus ordered
markers. Update those values and ordering deliberately when the graph changes.
Never replace an exact assertion with a weaker count, unordered search, or
optional marker merely to recover green output.

## Validation order for a real component addition

These commands describe the **future component implementation workflow**. They
are not evidence required for this documentation-only page.

1. Crate shape and release profile:

   ```sh
   just component_crate_split_check
   ```

2. Component declaration and evidence link:

   ```sh
   just component_spec_check
   ```

3. System-spec derivation and generated-manifest consistency:

   ```sh
   just system_spec_check
   ```

4. The narrowest owning QEMU gate, for example:

   ```sh
   just sel4_component_graph_check
   ```

   Use the actual owning `just sel4_*_check`, not this example by default.

5. For the permanent Rust addition:

   ```sh
   just fmt_check_all
   just lint_all
   ```

Run `just contracts_check` when a contract surface changed. Run `just
generation_check` when the generation builder or its governed generation
construction surface changed. Do not add either as ritual for an unrelated
crate-only edit.

The finished path is always the same: **crate → component spec → composition →
authority and launch policy → observed QEMU evidence**.

## Next

The component's code is written against the runtime in the
[component runtime tour](10-component-runtime.md); the gate that observes it is
built as in [Add a gate](07-add-a-gate.md).
