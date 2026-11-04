#!/usr/bin/env python3

"""Emit one `contracts/system-image-closure/v3` closure source per derived composition.

A source names the system spec, the implementation of each component, the target and its prefix, the
root and loader roles, the release inputs, the build parameters and the expected outputs, each input by
its path and kind. It records no identity. A v2 closure recorded the SHA-256 identity of every input,
including the repository's own trees, so every change to an input tree rewrote the corpus.

`--resolve NAME --output PATH --report REPORT` resolves one committed source in this checkout through
`scripts/lib/system_image_closure.py`: every input gains the identity of the files git lists, the
system and component specs their compiled identities, and the resulting v2 `SystemImageClosure` is
written to PATH. REPORT receives a `contracts/closure-resolution/v1` record of its name, its identity
(the derivation id) and whether an input was dirty.

`--check` fails on a source that differs from what this script writes, or on any file left in the
retired `contracts/system-image-closure/v2/closures/`, the same discipline
`generate-generation-from-spec.py` applies to the composition corpus.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import json
import tempfile
from pathlib import Path

import closure_resolution_contract as REPORT_CONTRACT
import system_image_closure_contract as CONTRACT
import system_image_closure_source_contract as SOURCE_CONTRACT
from component_sdk import PROFILE_PLATFORMS, pins
from component_spec import admit_specs, interface_catalogue
from harness import ROOT
from system_image_closure import resolve_source, source_names
from system_spec import (
    DERIVED_GENERATION_FIXTURES,
    SYSTEM_ROOT,
    compile_system,
    prefetch_systems,
)

CLOSURE_ROOT = ROOT / "contracts" / "system-image-closure" / "v3" / "closures"
# Resolved v2 closures used to be committed here. Nothing is; a file left behind is an orphan.
LEGACY_ROOT = ROOT / "contracts" / "system-image-closure" / "v2" / "closures"
NEGATIVE_ROOT = ROOT / "contracts" / "system-image-closure" / "v2" / "negative"
INPUT_ROOT = ROOT / "contracts" / "system-image-closure" / "v2" / "inputs"
PREFIXES = {
    "qemu-arm-virt": INPUT_ROOT / "sel4-prefix",
    "qemu-riscv-virt": INPUT_ROOT / "sel4-riscv64-prefix",
}

# The shared workspace inputs `resolve_closure` requires of every closure, as
# `(name, repository-relative path, kind)`. The target specification is added
# from `component_sdk.PROFILE_PLATFORMS` below because it varies by profile.
RELEASE_INPUTS: tuple[tuple[str, str, str], ...] = (
    ("boot-contracts", "boot-contracts", "tree"),
    ("cargo-lock", "Cargo.lock", "file"),
    ("component-build-support", "components/build-support", "tree"),
    ("component-cargo-config", "components/.cargo/config.toml", "file"),
    ("component-library", "components/lib", "tree"),
    ("component-proto", "components/proto", "tree"),
    ("component-runtime", "components/runtime", "tree"),
    ("component-spec-contract", "contracts/component-spec/v1", "tree"),
    ("generation-builder", "scripts/build/build-generation.py", "file"),
    ("image-builder", "scripts/build/build-sel4.py", "file"),
    ("elf-delivery", "scripts/lib/elf_delivery.py", "file"),
    ("interface-schema-contract", "contracts/interface-schema/v1", "tree"),
    ("root-child", "slime-root/child", "tree"),
    ("workspace-manifest", "Cargo.toml", "file"),
    ("zenoh-grants-table-contract", "contracts/zenoh-service-grants-table/v1", "tree"),
    ("zenoh-grants-table-encoder", "scripts/lib/zenoh_grants_table.py", "file"),
    ("zenoh-limits-contract", "contracts/zenoh-service-limits/v1", "tree"),
    ("zenoh-limits-encoder", "scripts/lib/zenoh_limits.py", "file"),
    ("generation-resources", "scripts/build/generation_resources.py", "file"),
)

ROOT_IMPLEMENTATION = ("slime-root", "tree")
# Which `deps/rust-sel4*` submodule a closure's loader role names, keyed by
# the platform bound by `component_sdk.PROFILE_PLATFORMS`. A platform with no
# loader patch shares the base checkout; a patched platform names its own
# independent submodule (`sel4/pins.toml`'s `[rust_sel4_<platform>]` tables),
# so an NDA'd board's fork never appears in another platform's closure identity.
LOADER_IMPLEMENTATIONS: dict[str, tuple[str, str]] = {
    "qemu-arm-virt": ("deps/rust-sel4", "tree"),
    "qemu-riscv-virt": ("deps/rust-sel4", "tree"),
    "bcm2712-rpi5": ("deps/rust-sel4-bcm2712-rpi5", "tree"),
    "cv1800b-duo": ("deps/rust-sel4-cv1800b-duo", "tree"),
}

# Which compositions get a closure. Every derived composition except the
# reference generation, which targets `x86_64-qemu-virtio` and has no seL4
# platform asset to name.
EXCLUDED = {"reference"}


# CP14: scenario closures. A scenario is one base composition plus declared
# build parameters that change generation bytes — the three deltas that used to
# reach the generation builder as ambient `SLIME_*` variables set from
# `build-sel4.py`'s `VARIANT_GENERATION_DELTAS`. Each becomes its own closure
# with its own identity, so "the saturation image" is a build key rather than
# an environment an operator remembered to set.
#
# The numbers are the ones that table declares, so each scenario's generation
# identity is unchanged by becoming closure data. `matrix-unsatisfiable` has no
# Each entry is `(base composition, build parameters, {component: profile})`.
# The profiles are the executable-changing scenarios: `build-sel4.py` set the
# same knobs per variant from `FAULT_VARIANT`/`STREAM_DEATH_VARIANTS`, so the
# ELF bytes are unchanged by the selection becoming closure data.
SCENARIOS: dict[str, tuple[str, dict[str, str], dict[str, str]]] = {
    "sel4-io-driver-reset-in-flight": (
        "sel4-io-driver-reset",
        {},
        {"network-service": "networkDriverResetInFlight"},
    ),
    "sel4-io-service-fault-in-flight": (
        "sel4-io-service-fault",
        {},
        {"network-service": "networkFaultInFlight"},
    ),
    "sel4-saturation": (
        "sel4-traffic",
        {"generationNumber": "39", "fabricLimitOverride": "inFlightOperations=2"},
        {},
    ),
    # C8.14's degradation envelope: the interposition hop dies mid-route *and*
    # a publisher ends its stream early, which is why one closure carries two
    # distinct scenario profiles.
    "sel4-fault": (
        "sel4-traffic",
        {"generationNumber": "40"},
        {"fabric-proxy": "proxyEarlyExit", "fabric-publisher": "streamEarlyExit"},
    ),
    # C8.4's mid-stream publisher death, without the fault plane's proxy death:
    # the two must stay distinguishable, which they cannot be if one image
    # carries both.
    "sel4-stream-death": (
        "sel4-stream",
        {},
        {"fabric-publisher": "streamEarlyExit"},
    ),
    # C8.5's QoS plane retires a departed publisher through the peer-dead path,
    # so it needs the same mid-stream publisher death the stream plane does.
    # `build-sel4.py` gave it that by listing the qos variant in
    # `STREAM_DEATH_VARIANTS`; as closure data it is a scenario over its own
    # composition rather than a property of the base graph, because the base
    # `sel4-qos` closure must stay the plane without a dying publisher.
    # C8.12's negative control: one participant's reliability flipped so the
    # pair becomes incompatible and admission must refuse the graph. That one
    # field is the whole test, which is why it is a declared parameter rather
    # than a second copy of the matrix composition.
    "sel4-matrix-unsatisfiable": (
        "sel4-matrix",
        {
            "generationNumber": "35",
            "fabricQosOverride": "telemetry-alt:fabric-publisher-b:reliability:bestEffort",
        },
        {},
    ),
    "sel4-qos-death": (
        "sel4-qos",
        {},
        {"fabric-publisher": "streamEarlyExit"},
    ),
}

# CP14 root roles. A root role is a distinct root *build* over the same
# composition: the selector carries no embedded generation and reads one from
# disk, the fixture root reports its capability layout, the unwind root forces
# B38's construction unwind, and the private-memory roles inject one allocator
# failure each. Every role is its own closure identity.
#
# `(base composition, root role, root parameters)`. The base is the graph the
# role's own gate boots, and the role changes only the root or embedded fixture.
ROOT_ROLE_CLOSURES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "sel4-private-memory-stress-injected": (
        "sel4-private-memory-stress", "private-memory-stress", (),
    ),
    "sel4-private-memory-stress-rv64-injected": (
        "sel4-private-memory-stress-rv64", "private-memory-stress", (),
    ),
    # The RV64 rows reuse the heap-stress composition: it is the only RV64
    # private-memory graph whose probes need no injected root, so a role image
    # over it exercises the same workload with only its own compile-time
    # difference. The stress composition cannot serve, because its probe is
    # written against the injected allocator pressure of its own role.
    "sel4-private-memory-cspace": (
        "sel4-private-memory", "cspace-expanded", (),
    ),
    "sel4-private-memory-cspace-rv64": (
        "sel4-private-memory-heap-stress-rv64", "cspace-expanded", (),
    ),
    "sel4-private-memory-metadata": (
        "sel4-private-memory", "metadata-lifecycle", (),
    ),
    "sel4-private-memory-metadata-rv64": (
        "sel4-private-memory-heap-stress-rv64", "metadata-lifecycle", (),
    ),
    "sel4-private-memory-bootstrap": (
        "sel4-private-memory", "bootstrap-boundaries", (),
    ),
    "sel4-private-memory-bootstrap-rv64": (
        "sel4-private-memory-heap-stress-rv64", "bootstrap-boundaries", (),
    ),
    # The four demand-backed roles run their holders in windows of the root's
    # own address space before any component is published, so they need only a
    # composition that boots; each reference architecture carries all four.
    "sel4-private-memory-elastic": (
        "sel4-private-memory", "private-memory-elastic", (),
    ),
    "sel4-private-memory-elastic-rv64": (
        "sel4-private-memory-heap-stress-rv64", "private-memory-elastic", (),
    ),
    "sel4-private-memory-fragmentation": (
        "sel4-private-memory", "private-memory-fragmentation", (),
    ),
    "sel4-private-memory-fragmentation-rv64": (
        "sel4-private-memory-heap-stress-rv64", "private-memory-fragmentation", (),
    ),
    "sel4-private-memory-rollback": (
        "sel4-private-memory", "private-memory-rollback", (),
    ),
    "sel4-private-memory-rollback-rv64": (
        "sel4-private-memory-heap-stress-rv64", "private-memory-rollback", (),
    ),
    "sel4-private-memory-conservation": (
        "sel4-private-memory", "private-memory-conservation", (),
    ),
    "sel4-private-memory-conservation-rv64": (
        "sel4-private-memory-heap-stress-rv64", "private-memory-conservation", (),
    ),
    # The adaptive plane under the conservation role, whose one compiled-in
    # revoke failure lands on the first adaptive holder that dies. It is the
    # only way to observe a real incarnation being quarantined and then
    # returned by exactly one retry.
    "sel4-private-memory-adaptive-lifecycle": (
        "sel4-private-memory-adaptive",
        "private-memory-conservation",
        (),
    ),
    "sel4-reclamation-unwind": ("sel4-reclamation", "reclamation-unwind", ()),
    "sel4-channel-fixture": ("sel4-channel", "root-fixture", ()),
    # The two private-memory roles compile bounded, one-shot allocator failures.
    "sel4-private-memory-fail-second-allocation": (
        "sel4-private-memory",
        "private-memory-fail-second-allocation",
        (),
    ),
    "sel4-private-memory-fail-large-map": (
        "sel4-private-memory",
        "private-memory-fail-large-map",
        (),
    ),
    # CP14 declared the `boot-selector` role but no closure carried it. A
    # selector root embeds no generation and reads one from disk, so its base
    # composition supplies only the build inputs, never an embedded payload —
    # which is why it can be a derived composition even though the legacy
    # boot-selection variant named the undrivable `sel4` graph.
    "sel4-boot-selector": ("sel4-channel", "boot-selector", ()),
}

# Ordinary compositions whose default `embedded-generation` root still needs a
# declared root parameter. `sel4` is the one interactive plane: its console
# component `requires: input`, and only the emulated QEMU keyboard feed
# supplies that capability's bytes, which the legacy `GRAPH_VARIANT` build set
# unconditionally rather than as a composition-scoped parameter.
ROOT_PARAMETERS: dict[str, tuple[str, ...]] = {
    "sel4": ("qemuKeyboard",),
    "sel4-http": ("qemuKeyboard",),
    "sel4-http-public": ("qemuKeyboard",),
    "sel4-net": ("qemuKeyboard",),
    # IO8: the product graph plus the pwm driver is the same interactive
    # plane, typed at over the same emulated keyboard.
    "sel4-pwm": ("qemuKeyboard",),
    # IO9: the product graph plus the serial driver and the heartbeat producer.
    "sel4-mavlink": ("qemuKeyboard",),
}


# The closure every negative build case perturbs.
NEGATIVE_BASE = "sel4-boot"


def fail(message: str) -> None:
    raise SystemExit(f"system image closure generation: {message}")


def artifact(relative: str, kind: str) -> dict:
    """A locator: a source names a path and its kind. Each checkout computes the identity."""
    path = ROOT / relative
    if not (path.is_dir() if kind == "tree" else path.is_file()):
        fail(f"missing {kind} input: {relative}")
    return {"path": relative, "kind": kind}


def implementation_path(spec: dict) -> tuple[str, str]:
    """Where a component's implementation lives, and how it is identified.

    A `workspace` provider is identified by its crate tree, which is what a
    rebuild reads. An `external` provider is identified by the committed ELF
    the component spec pins by content hash. An `undeclared` provider has no
    implementation to name, so a composition admitting one gets no closure.
    """
    from component_paths import crate_path

    provider = spec["implementation"]["provider"]
    if provider == CONTRACT.PROVIDER_WORKSPACE:
        crate = crate_path(spec["implementation"]["binary"])
        return str(crate.relative_to(ROOT)), "tree"
    if provider == CONTRACT.PROVIDER_EXTERNAL:
        binary = spec["implementation"]["binary"]
        artifacts = {
            "slisp-external": "slisp.elf",
            "c-runtime-probe-external": "c-runtime-probe.elf",
        }
        name = artifacts.get(binary)
        if name is None:
            raise LookupError(provider)
        return f"contracts/system-image-closure/v2/inputs/components/{name}", "file"
    raise LookupError(provider)


def render(value: object, indent: int = 0) -> str:
    padding = " " * indent
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list):
        if not value:
            return "[]"
        rows = "".join(f"{padding}  {render(item, indent + 2)};\n" for item in value)
        return "[\n" + rows + padding + "]"
    if isinstance(value, dict):
        rows = "".join(
            f"{padding}  {key} = {render(item, indent + 2)};\n" for key, item in value.items()
        )
        return "{\n" + rows + padding + "}"
    raise TypeError(type(value))


# One compile, and so one computed-source render, per system spec per run; the
# same once-per-run reading of the repository the resolver's cache gives a corpus.
_SYSTEMS: dict[str, object] = {}


def compiled_system(source: str, components: dict):
    found = _SYSTEMS.get(source)
    if found is None:
        found = _SYSTEMS[source] = compile_system(
            SYSTEM_ROOT / f"{source}.zti", components=components
        )
    return found


def closure_for(
    name: str,
    specs: dict,
    components: dict,
    *,
    base: str | None = None,
    parameters: dict[str, str] | None = None,
    profiles: dict[str, str] | None = None,
    root_role: str | None = None,
    root_parameters: tuple[str, ...] = (),
) -> dict | None:
    """One closure, or `None` when the composition cannot have a reproducible one.

    `base` and `parameters` build a *scenario* closure: the same composition
    with declared build parameters that change generation bytes. The closure's
    own `name` is the scenario's, so two scenarios over one composition are two
    build keys rather than one identity an environment variable disambiguated.
    """
    source = base or name
    system = compiled_system(source, components)
    profile_name = system.spec["targetRequirement"]
    if not profile_name.startswith(("aarch64-sel4", "riscv64-sel4")):
        return None

    implementations = []
    for component in system.spec["components"]:
        spec = specs[component]
        try:
            relative, kind = implementation_path(spec.spec)
        except LookupError as error:
            # `undeclared` and `external` providers: the former has no
            # implementation to name at all, and the latter's ELF is not a
            # committed artifact in this repository, so neither can be a
            # closure input without inventing a path.
            print(
                f"  {name}: no closure — {component} has a {error.args[0]!r} implementation",
                flush=True,
            )
            return None
        implementations.append(
            {
                "component": component,
                "provider": spec.spec["implementation"]["provider"],
                "artifact": artifact(relative, kind),
                "buildProfile": (profiles or {}).get(component, "default"),
            }
        )
    implementations.sort(key=lambda entry: entry["component"])

    binding = PROFILE_PLATFORMS.get(profile_name)
    if binding is None:
        fail(f"no component SDK binding for target profile {profile_name!r}")
    platform = str(binding["platform"])
    loader_implementation = LOADER_IMPLEMENTATIONS.get(platform)
    if loader_implementation is None:
        fail(f"no loader submodule declared for platform {platform!r}")
    pin_table = pins(ROOT)
    rust_sel4 = pin_table["rust_sel4"]
    prefix = PREFIXES.get(platform)
    if prefix is None:
        fail(f"no committed seL4 prefix snapshot for platform {platform!r}")
    root_target = str(rust_sel4[
        "riscv64_root_target" if profile_name.startswith("riscv64-") else "root_target"
    ])
    target_spec = (
        Path("deps") / "rust-sel4" / "support" / "targets" / Path(str(binding["cargo_target"])).name
    ).as_posix()
    return {
        "formatVersion": SOURCE_CONTRACT.FORMAT_VERSION,
        "name": name,
        "systemSpec": artifact(str((SYSTEM_ROOT / f"{source}.zti").relative_to(ROOT)), "file"),
        "implementations": implementations,
        "target": {
            "profile": profile_name,
            "platform": platform,
            "prefix": artifact(str(prefix.relative_to(ROOT)), "tree"),
            "toolchain": rust_sel4["toolchain"],
            "rustSel4Commit": rust_sel4["commit"],
        },
        "root": {
            "role": root_role or CONTRACT.ROOT_ROLE_EMBEDDED_GENERATION,
            "implementation": artifact(*ROOT_IMPLEMENTATION),
            "parameters": sorted(root_parameters),
        },
        "loader": {
            "role": CONTRACT.LOADER_ROLE_KERNEL_LOADER,
            "implementation": artifact(*loader_implementation),
            "parameters": [],
        },
        "releaseInputs": sorted(
            [
                {"name": input_name, "artifact": artifact(relative, kind)}
                for input_name, relative, kind in RELEASE_INPUTS
            ]
            + [
                {"name": "target-spec", "artifact": artifact(target_spec, "file")},
                {"name": "root-target", "artifact": artifact(root_target, "file")},
            ],
            key=lambda entry: entry["name"],
        ),
        "buildParameters": [
            {"name": key, "value": parameters[key]} for key in sorted(parameters or {})
        ],
        "expectedOutputs": list(CONTRACT.OUTPUT_CLASSES),
    }


def outputs() -> dict[Path, str]:
    catalogue = interface_catalogue()
    compiled = admit_specs(catalogue=catalogue)
    specs = {entry.name: entry for entry in compiled}
    components = {entry.name: entry.spec for entry in compiled}
    prefetch_systems(
        [
            SYSTEM_ROOT / f"{name}.zti"
            for name in sorted(DERIVED_GENERATION_FIXTURES)
            if name not in EXCLUDED
        ]
    )
    emitted: dict[Path, str] = {}
    for name in sorted(DERIVED_GENERATION_FIXTURES):
        if name in EXCLUDED:
            continue
        closure = closure_for(
            name, specs, components, root_parameters=ROOT_PARAMETERS.get(name, ())
        )
        if closure is None:
            continue
        emitted[CLOSURE_ROOT / f"{name}.zti"] = render(closure) + "\n"
    for name, (base, parameters, profiles) in sorted(SCENARIOS.items()):
        if base not in DERIVED_GENERATION_FIXTURES:
            fail(f"scenario {name} names composition {base!r}, which is not derived")
        if not parameters and not profiles:
            fail(f"scenario {name} declares no parameters and no profiles, so it is its base")
        closure = closure_for(
            name, specs, components, base=base, parameters=parameters, profiles=profiles
        )
        if closure is None:
            fail(f"scenario {name} produced no closure, but its base composition has one")
        emitted[CLOSURE_ROOT / f"{name}.zti"] = render(closure) + "\n"
    for name, (base, role, parameters) in sorted(ROOT_ROLE_CLOSURES.items()):
        if base not in DERIVED_GENERATION_FIXTURES:
            fail(f"root-role closure {name} names composition {base!r}, which is not derived")
        if role == CONTRACT.ROOT_ROLE_EMBEDDED_GENERATION:
            fail(f"root-role closure {name} declares the ordinary role, so it is its base")
        closure = closure_for(
            name, specs, components, base=base, root_role=role, root_parameters=parameters
        )
        if closure is None:
            fail(f"root-role closure {name} produced none, but its base composition has one")
        emitted[CLOSURE_ROOT / f"{name}.zti"] = render(closure) + "\n"
    if not emitted:
        fail("no composition produced a closure")
    # Negative cases name their base closure, so a change to one of its inputs
    # leaves every case unchanged.
    if CLOSURE_ROOT / f"{NEGATIVE_BASE}.zti" not in emitted:
        fail(f"negative cases name base closure {NEGATIVE_BASE}, which no composition produced")
    for mutation in CONTRACT.MUTATIONS:
        name = f"sel4-b40-{mutation.replace('_', '-')}"
        case = {
            "formatVersion": CONTRACT.NEGATIVE_FORMAT_VERSION,
            "name": name,
            "baseClosure": NEGATIVE_BASE,
            "mutation": mutation,
            "expectedRefusal": "CSpaceMismatch",
        }
        emitted[NEGATIVE_ROOT / f"{name}.zti"] = render(case) + "\n"
    return emitted


def resolve_one(name: str, output: Path, report: Path) -> None:
    """Resolve one committed source in this checkout; write the v2 closure and the report."""
    if name not in source_names():
        fail(f"no closure source named {name!r} under {CLOSURE_ROOT.relative_to(ROOT)}")
    materialized = resolve_source(name)
    if output.name != f"{name}.zti":
        fail(f"--output must be named {name}.zti, because a closure's name is its file name")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(materialized.path.read_bytes())
    value = {
        "formatVersion": REPORT_CONTRACT.FORMAT_VERSION,
        "name": name,
        "derivationId": materialized.compiled.identity.hex(),
        "dirty": materialized.dirty,
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(render(value) + "\n", encoding="utf-8")
    print(f"resolved {name} to {value['derivationId']}{' (dirty)' if materialized.dirty else ''}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if a closure source is stale")
    parser.add_argument("--resolve", metavar="NAME", help="resolve one source in this checkout")
    parser.add_argument("--output", type=Path, help="with --resolve: where to write the resolved closure")
    parser.add_argument("--report", type=Path, help="with --resolve: where to write the resolution report")
    arguments = parser.parse_args()
    if arguments.resolve is not None:
        if arguments.output is None or arguments.report is None or arguments.check:
            parser.error("--resolve needs --output and --report, and excludes --check")
        resolve_one(arguments.resolve, arguments.output, arguments.report)
        return
    emitted = outputs()
    if arguments.check:
        stale = [
            path
            for path, contents in emitted.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != contents
        ]
        orphaned = sorted(
            str(path.relative_to(ROOT))
            for directory in (CLOSURE_ROOT, LEGACY_ROOT, NEGATIVE_ROOT)
            for path in directory.glob("*.zti")
            if path not in emitted
        )
        if stale or orphaned:
            raise SystemExit(
                "stale closure(s): "
                + ", ".join(sorted(path.name for path in stale))
                + ("; orphaned: " + ", ".join(orphaned) if orphaned else "")
                + "; run python3 scripts/generate/generate-system-image-closures.py"
            )
        print(f"{len(emitted)} system-image closure sources are current")
        return
    for directory in (CLOSURE_ROOT, LEGACY_ROOT, NEGATIVE_ROOT):
        if directory == LEGACY_ROOT and not directory.is_dir():
            continue
        directory.mkdir(parents=True, exist_ok=True)
        for path in directory.glob("*.zti"):
            if path not in emitted:
                path.unlink()
                print(f"Removed {path.relative_to(ROOT)}")
    if LEGACY_ROOT.is_dir() and not any(LEGACY_ROOT.iterdir()):
        LEGACY_ROOT.rmdir()
    for path, contents in emitted.items():
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
        )
        temporary = Path(handle.name)
        try:
            with handle:
                handle.write(contents)
            temporary.replace(path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        print(f"Generated {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
