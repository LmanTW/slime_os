"""One pipeline for every binding a contract's Zutai renderer writes.

A binding runs its contract's `.zt` renderer with `zutai run` into a private
staging root, refuses a run that fails, writes nothing, or emits the schema's
`INVALID_*_SCHEMA` sentinel, formats Rust output with rustfmt, and then either
compares the result with the committed file (`check`) or replaces the file
atomically (`write`). The committed outputs are the reference: this module
decides how a binding is produced, never what it contains.

Generators whose rendering is not a single `zutai run` per contract keep their
own scripts under `scripts/generate/` (boot, interface-schema, the two ABI
generators that also check documentation, the Zenoh stock corpus, and the two
bindings rendered in Python from `zutai json`).
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from harness import ROOT
from zutai_cli import STDLIB, binary


@dataclass(frozen=True)
class Output:
    path: str  # repository-relative destination
    staged: str  # where the renderer writes it, relative to the staging root


@dataclass(frozen=True)
class Run:
    schema: str  # repository-relative `.zt` the renderer runs
    roots: tuple[str, ...]  # environment variables that name the staging root
    outputs: tuple[Output, ...]
    invalid: str | None  # sentinel the renderer emits for an invalid schema


def same(path: str) -> Output:
    return Output(path, path)


def flat(path: str) -> Output:
    return Output(path, Path(path).name)


def run(schema: str, root: str, *outputs: Output, invalid: str | None = None, roots: tuple[str, ...] = ()) -> Run:
    return Run(schema, (root, *roots), outputs, invalid)


PROTO = "components/proto/src"
HEADERS = "components/runtime/include/slime"
LIB = "scripts/lib"


def _rust(contract: str, version: str, module: str, sentinel: str, *extra: Output) -> Run:
    """The common shape: one contract, one Rust module, staged at its own path."""
    root = f"SLIME_{sentinel}_BINDINGS_ROOT"
    return run(
        f"contracts/{contract}/{version}/schema.zt",
        root,
        same(f"{PROTO}/{module}.rs"),
        *extra,
        invalid=f"INVALID_{sentinel}_SCHEMA",
    )


def _python(contract: str, version: str, renderer: str, module: str, variable: str) -> Run:
    """A host-only binding: the contract's renderer writes one flat Python module."""
    return run(f"contracts/{contract}/{version}/{renderer}", variable, flat(f"{LIB}/{module}.py"))


BINDINGS: dict[str, tuple[Run, ...]] = {
    "block": (_rust("block", "v1", "block", "BLOCK"),),
    "block-v2": (_rust("block", "v2", "block_v2", "BLOCK_V2"),),
    "capability-transfer": (_rust("capability-transfer", "v1", "capability_transfer", "CAPABILITY_TRANSFER"),),
    "component": (
        run(
            "contracts/component/v2/schema.zt",
            "SLIME_COMPONENT_BINDINGS_ROOT",
            same(f"{PROTO}/component.rs"),
            invalid="INVALID_COMPONENT_SCHEMA",
            roots=("SLIME_BOOT_BINDINGS_ROOT",),
        ),
    ),
    "entropy": (
        run(
            "contracts/entropy-source/v1/schema.zt",
            "SLIME_ENTROPY_BINDINGS_ROOT",
            same(f"{PROTO}/entropy_source.rs"),
            invalid="INVALID_ENTROPY_SOURCE_SCHEMA",
        ),
        run(
            "contracts/entropy-service/v1/schema.zt",
            "SLIME_ENTROPY_BINDINGS_ROOT",
            same(f"{PROTO}/entropy_service.rs"),
            invalid="INVALID_ENTROPY_SERVICE_SCHEMA",
        ),
    ),
    "fabric-call": (_rust("fabric-call", "v1", "fabric_call", "FABRIC_CALL"),),
    "fabric-operation": (_rust("fabric-operation", "v1", "fabric_operation", "FABRIC_OPERATION"),),
    "fabric-qos": (_rust("fabric-qos", "v1", "fabric_qos", "FABRIC_QOS"),),
    "fabric-ring": (
        run(
            "contracts/fabric-stream/v2/schema.zt",
            "SLIME_FABRIC_STREAM_V2_BINDINGS_ROOT",
            same(f"{PROTO}/fabric_ring.rs"),
            invalid="INVALID_FABRIC_RING_SCHEMA",
        ),
    ),
    "fabric-stream": (_rust("fabric-stream", "v1", "fabric_stream", "FABRIC_STREAM"),),
    "fabric-time": (_rust("fabric-time", "v1", "fabric_time", "FABRIC_TIME"),),
    "fabric-trace": (_rust("fabric-trace", "v1", "fabric_trace", "FABRIC_TRACE", same(f"{LIB}/fabric_trace_contract.py")),),
    "fabric-visibility": (
        _rust("fabric-visibility", "v1", "fabric_visibility", "FABRIC_VISIBILITY", same(f"{LIB}/fabric_visibility_contract.py")),
    ),
    "frame-store": (_rust("frame-store", "v1", "frame_store", "FRAME_STORE", same(f"{LIB}/frame_store_contract.py")),),
    "fs": (_rust("fs", "v1", "fs", "FS", flat(f"{LIB}/fs_contracts.py")),),
    "generation-management": (
        run(
            "contracts/generation-management/v1/schema.zt",
            "SLIME_GENERATION_MANAGEMENT_BINDINGS_ROOT",
            same(f"{PROTO}/generation.rs"),
            invalid="INVALID_GENERATION_MANAGEMENT_SCHEMA",
        ),
    ),
    "io-queue": (_rust("io-queue", "v1", "io_queue", "IO_QUEUE"),),
    "link-device": (_rust("link-device", "v1", "link_device", "LINK_DEVICE"),),
    "mavlink-heartbeat": (
        _rust("mavlink-heartbeat", "v1", "mavlink_heartbeat", "MAVLINK_HEARTBEAT", same(f"{LIB}/mavlink_heartbeat_contract.py")),
    ),
    "network-service": (_rust("network-service", "v1", "network_service", "NETWORK_SERVICE", flat(f"{LIB}/network_launch.py")),),
    "powerbox": (_rust("powerbox", "v1", "powerbox", "POWERBOX"),),
    "private-memory-probe": (_rust("private-memory-probe", "v1", "private_memory_probe", "PRIVATE_MEMORY_PROBE"),),
    "pwm-servo": (_rust("pwm-servo", "v1", "pwm_servo", "PWM_SERVO", same(f"{HEADERS}/pwm_servo.h")),),
    "sample-descriptor": (_rust("sample-descriptor", "v1", "sample_descriptor", "SAMPLE_DESCRIPTOR"),),
    "serial-device": (_rust("serial-device", "v1", "serial_device", "SERIAL_DEVICE"),),
    "spawn": (_rust("spawn", "v2", "spawn", "SPAWN", same(f"{HEADERS}/spawn.h")),),
    "store": (_rust("store", "v1", "store", "STORE"),),
    "zenoh-profile": (_rust("zenoh-profile", "v1", "zenoh_profile", "ZENOH_PROFILE"),),
    "boot-media": (
        _python("boot-media", "v1", "schema.zt", "boot_media_contract", "SLIME_BOOT_MEDIA_BINDINGS_ROOT"),
    ),
    "component-sdk-release": (
        _python(
            "component-sdk-release",
            "v1",
            "gen_python.zt",
            "component_sdk_release_contract",
            "SLIME_COMPONENT_SDK_RELEASE_BINDINGS_ROOT",
        ),
    ),
    "component-spec": (
        _python("component-spec", "v1", "gen_python.zt", "component_spec_contract", "SLIME_COMPONENT_SPEC_BINDINGS_ROOT"),
    ),
    "closure-resolution": (
        _python(
            "closure-resolution", "v1", "gen_python.zt", "closure_resolution_contract", "SLIME_CLOSURE_RESOLUTION_BINDINGS_ROOT"
        ),
    ),
    "image-attestation": (
        _python(
            "image-attestation", "v1", "gen_python.zt", "image_attestation_contract", "SLIME_IMAGE_ATTESTATION_BINDINGS_ROOT"
        ),
    ),
    "composition-inventory": (
        _python(
            "composition-inventory",
            "v1",
            "gen_python.zt",
            "composition_inventory_contract",
            "SLIME_COMPOSITION_INVENTORY_BINDINGS_ROOT",
        ),
    ),
    "cpu-boot-observation": (
        _python(
            "cpu-boot-observation", "v1", "schema.zt", "cpu_boot_observation_contract", "SLIME_CPU_BOOT_OBSERVATION_BINDINGS_ROOT"
        ),
    ),
    "system-image-closure": (
        _python(
            "system-image-closure", "v2", "gen_python.zt", "system_image_closure_contract", "SLIME_SYSTEM_IMAGE_CLOSURE_BINDINGS_ROOT"
        ),
    ),
    "system-image-closure-source": (
        _python(
            "system-image-closure",
            "v3",
            "gen_python.zt",
            "system_image_closure_source_contract",
            "SLIME_SYSTEM_IMAGE_CLOSURE_SOURCE_BINDINGS_ROOT",
        ),
    ),
    "system-spec": (
        _python("system-spec", "v1", "gen_python.zt", "system_spec_contract", "SLIME_SYSTEM_SPEC_BINDINGS_ROOT"),
    ),
    "system-test-run": (
        _python("system-test-run", "v2", "gen_python.zt", "system_test_run_contract", "SLIME_SYSTEM_TEST_RUN_BINDINGS_ROOT"),
    ),
}


class BindingError(SystemExit):
    pass


def _render_run(name: str, spec: Run, renderer: list[str] | None = None) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix=f"slime-{name}-bindings-") as temporary:
        staging = Path(temporary)
        for output in spec.outputs:
            (staging / output.staged).parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ | {"ZUTAI_STDLIB_ROOT": str(STDLIB)}
        environment |= {variable: str(staging) for variable in spec.roots}
        process = subprocess.run(
            renderer or [str(binary()), "run", str(ROOT / spec.schema)],
            cwd=ROOT,
            env=environment,
            check=False,
            text=True,
            capture_output=True,
        )
        if process.returncode != 0:
            raise BindingError(
                f"{name}: {spec.schema} failed (exit {process.returncode}):\n{process.stdout}{process.stderr}"
            )
        rendered: dict[str, str] = {}
        for output in spec.outputs:
            staged = staging / output.staged
            if not staged.is_file():
                raise BindingError(f"{name}: {spec.schema} wrote no {output.staged}")
            text = staged.read_text(encoding="utf-8")
            if spec.invalid is not None and spec.invalid in text:
                raise BindingError(f"{name}: {spec.schema} reported {spec.invalid} in {output.staged}")
            rendered[output.path] = _format_rust(name, text) if output.path.endswith(".rs") else text
        return rendered


def _format_rust(name: str, source: str) -> str:
    process = subprocess.run(
        ["rustfmt", "--edition", "2024", "--emit", "stdout"],
        cwd=ROOT,
        input=source,
        check=False,
        text=True,
        capture_output=True,
    )
    if process.returncode != 0:
        raise BindingError(f"{name}: rustfmt refused the rendered Rust:\n{process.stderr}")
    return process.stdout


def render(name: str) -> dict[str, str]:
    """Every output of binding `name`, rendered and formatted, keyed by repository path."""
    if name not in BINDINGS:
        raise BindingError(f"unknown binding {name!r}; known: {', '.join(sorted(BINDINGS))}")
    rendered: dict[str, str] = {}
    for spec in BINDINGS[name]:
        rendered |= _render_run(name, spec)
    return rendered


@contextmanager
def _output_lock(name: str):
    """Serialize concurrent writers and checkers of the same binding."""
    with (Path(tempfile.gettempdir()) / f"slime-{name}-bindings.lock").open("w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def _write_atomic(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp")
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(contents)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _differing(rendered: dict[str, str], root: Path) -> list[str]:
    return [
        path
        for path, text in rendered.items()
        if not (root / path).is_file() or (root / path).read_text(encoding="utf-8") != text
    ]


def stale(name: str) -> list[str]:
    """Repository paths whose committed bytes differ from what `name` renders."""
    rendered = render(name)
    with _output_lock(name):
        return _differing(rendered, ROOT)


# Negative controls. A stand-in renderer (a Python one-liner given the staging
# root in CONTROL_ROOT) drives the same `_render_run` and `_differing` paths the
# real bindings use; each refusal case must be refused and the clean case must
# render and compare equal, so a pass of `--check` is evidence of refusal rather
# than of renderers that happen to succeed today.
CONTROL_ROOT = "SLIME_CONTROL_BINDINGS_ROOT"
CONTROL_SENTINEL = "INVALID_CONTROL_SCHEMA"
CONTROL_RUN = Run("control.zt", (CONTROL_ROOT,), (same("out/control.rs"), flat("lib/control.py")), CONTROL_SENTINEL)
_WRITE = (
    "import os, pathlib; root = pathlib.Path(os.environ['{root}']); "
    "(root / 'out/control.rs').write_text({rust!r}); (root / 'control.py').write_text({python!r})"
)
CLEAN_RUST = "pub const CONTROL: u8 = 1;\n"
CLEAN_PYTHON = "CONTROL = 1\n"
RENDER_REFUSALS = {
    "renderer exits non-zero": "raise SystemExit(3)",
    "declared output not written": "pass",
    "sentinel in the Rust output": _WRITE.format(
        root=CONTROL_ROOT, rust=f"// {CONTROL_SENTINEL}\n" + CLEAN_RUST, python=CLEAN_PYTHON
    ),
    "sentinel in the Python output": _WRITE.format(
        root=CONTROL_ROOT, rust=CLEAN_RUST, python=f"# {CONTROL_SENTINEL}\n" + CLEAN_PYTHON
    ),
    "Rust rustfmt refuses": _WRITE.format(root=CONTROL_ROOT, rust="pub const CONTROL: u8 = ;\n", python=CLEAN_PYTHON),
}
CLEAN = _WRITE.format(root=CONTROL_ROOT, rust=CLEAN_RUST, python=CLEAN_PYTHON)


def check_controls() -> int:
    """Run every control; raise BindingError if one is not refused. Returns the count refused."""
    refused = 0
    for label, body in RENDER_REFUSALS.items():
        try:
            _render_run("control", CONTROL_RUN, [sys.executable, "-c", body])
        except SystemExit:
            refused += 1
            continue
        raise BindingError(f"binding control accepted: {label}")
    rendered = _render_run("control", CONTROL_RUN, [sys.executable, "-c", CLEAN])
    with tempfile.TemporaryDirectory(prefix="slime-control-bindings-committed-") as temporary:
        committed = Path(temporary)
        if sorted(_differing(rendered, committed)) != sorted(rendered):
            raise BindingError("binding control accepted: committed outputs missing")
        refused += 1
        for path, text in rendered.items():
            (committed / path).parent.mkdir(parents=True, exist_ok=True)
            (committed / path).write_text(text, encoding="utf-8")
        if _differing(rendered, committed):
            raise BindingError("binding control refused identical committed outputs")
        (committed / "out/control.rs").write_text(CLEAN_RUST + "// drift\n", encoding="utf-8")
        if _differing(rendered, committed) != ["out/control.rs"]:
            raise BindingError("binding control accepted: a drifted committed output")
        refused += 1
    return refused


def write(name: str) -> list[str]:
    """Render `name` and replace every output atomically; returns the paths written."""
    rendered = render(name)
    with _output_lock(name):
        for path, text in rendered.items():
            _write_atomic(ROOT / path, text)
    return list(rendered)
