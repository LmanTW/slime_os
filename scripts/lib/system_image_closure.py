"""Canonical CP11 system-image closure and test-run resolution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import dataclasses
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import system_image_closure_contract as image_contract
import system_image_closure_source_contract as source_contract
import system_test_run_contract as test_contract
from component_spec import CompiledSpec, admit_specs, interface_catalogue
from component_sdk import PROFILE_PLATFORMS, TREE_DOMAIN, pins, tree_digest, zti
from harness import ROOT
from system_spec import CompiledSystem, compile_system, derive_manifest
from zutai_cli import ZutaiError, evaluate

IMAGE_CONTRACT_ROOT = ROOT / "contracts" / "system-image-closure" / "v2"
TEST_CONTRACT_ROOT = ROOT / "contracts" / "system-test-run" / "v2"
IMAGE_CHECKER = IMAGE_CONTRACT_ROOT / "check.zt"
SOURCE_CONTRACT_ROOT = ROOT / "contracts" / "system-image-closure" / "v3"
SOURCE_ROOT = SOURCE_CONTRACT_ROOT / "closures"
SOURCE_CHECKER = SOURCE_CONTRACT_ROOT / "check.zt"
# Where a checkout's resolved closures are written. Ignored by git and named by no closure input.
RESOLVED_ROOT = ROOT / "build" / "closure-resolved"
NEGATIVE_CHECKER = IMAGE_CONTRACT_ROOT / "check-negative.zt"
NEGATIVE_ROOT = IMAGE_CONTRACT_ROOT / "negative"
TEST_CHECKER = TEST_CONTRACT_ROOT / "check.zt"
SYSTEM_ROOT = ROOT / "contracts" / "system-spec" / "v1" / "systems"
_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Mirrors `generate-system-image-closures.py`'s `LOADER_IMPLEMENTATIONS`: which
# `deps/rust-sel4*` submodule a platform's kernel-loader role must name. A
# platform with no loader patch shares the base checkout; a patched platform
# names its own independent submodule, so this checker -- an authority
# independent of the generator -- refuses a closure naming the wrong one.
_LOADER_PATHS = {
    "qemu-arm-virt": Path("deps") / "rust-sel4",
    "qemu-riscv-virt": Path("deps") / "rust-sel4",
    "bcm2712-rpi5": Path("deps") / "rust-sel4-bcm2712-rpi5",
    "cv1800b-duo": Path("deps") / "rust-sel4-cv1800b-duo",
}

_IMAGE_FIELDS = {
    "formatVersion",
    "name",
    "systemSpec",
    "systemIdentity",
    "implementations",
    "target",
    "root",
    "loader",
    "releaseInputs",
    "buildParameters",
    "expectedOutputs",
}
_ARTIFACT_FIELDS = {"path", "kind", "identity"}
_IMPLEMENTATION_FIELDS = {"component", "provider", "artifact", "identity", "buildProfile"}
_TARGET_FIELDS = {
    "profile",
    "platform",
    "prefix",
    "toolchain",
    "rustSel4Commit",
}
_ROLE_FIELDS = {"role", "implementation", "parameters"}
_NAMED_INPUT_FIELDS = {"name", "artifact"}
_PARAMETER_FIELDS = {"name", "value"}
_NEGATIVE_FIELDS = {
    "formatVersion",
    "name",
    "baseClosure",
    "mutation",
    "expectedRefusal",
}
_TEST_FIELDS = {
    "formatVersion",
    "name",
    "imageClosure",
    "executionKind",
    "executionProfile",
    "disks",
    "networks",
    "devices",
    "faultControls",
    "timeoutSeconds",
    "markerContractIdentity",
    "forbiddenOutcomes",
}
_FIXTURE_FIELDS = {"name", "path", "identity", "writable"}
_FAULT_FIELDS = {"kind", "target", "value"}


class SystemImageClosureError(ValueError):
    pass


@dataclass(frozen=True)
class CompiledClosure:
    path: Path
    value: dict
    normalized: bytes
    identity: bytes


@dataclass(frozen=True)
class CompiledTestRun:
    path: Path
    value: dict
    normalized: bytes
    identity: bytes


@dataclass(frozen=True)
class CompiledTestRunDeclaration:
    """A frozen checker declaration, not permission to execute unbound inputs."""

    path: Path
    value: dict
    normalized: bytes
    identity: bytes


@dataclass(frozen=True)
class CompiledNegativeCase:
    path: Path
    value: dict
    normalized: bytes
    identity: bytes


@dataclass(frozen=True)
class ResolvedClosure:
    compiled: CompiledClosure
    system: CompiledSystem
    manifest: dict
    artifacts: dict[str, Path]
    external_components: dict[str, Path]
    build_parameters: dict[str, str]
    # Per-component build profile, keyed by component. `default` for every
    # ordinary implementation; a scenario profile changes that component's ELF
    # bytes, so it belongs to the identity that selected it.
    build_profiles: dict[str, str]
    # What the root task is built to be, and the closed platform-qualified
    # parameters that vary it. `embedded-generation` with no parameters is the
    # ordinary case; the rest were `build-sel4.py` variant branches.
    root_role: str
    root_parameters: tuple[str, ...]


def _fail(message: str) -> None:
    raise SystemImageClosureError(message)


@dataclass
class ResolutionCache:
    """Repository reads shared across many resolutions in one process.

    A closure corpus names the same trees -- the loader submodule, the root
    crate, the prefix snapshot, every release input -- a hundred times over,
    the component-spec corpus once per closure, and each system spec once per
    closure built over it, re-rendering a computed one's source each time.
    Sharing one cache turns those into one read or render each. It is valid
    only while the paths it has read stay unchanged: a caller that mutates an
    artifact or a system source between resolutions, as the negative controls
    do, must not carry a cache across the mutation.
    """

    identities: dict[tuple[Path, str], str] = dataclasses.field(default_factory=dict)
    specs: dict[str, CompiledSpec] | None = None
    systems: dict[Path, CompiledSystem] = dataclasses.field(default_factory=dict)

    def identity(self, path: Path, kind: str) -> str:
        key = (path, kind)
        found = self.identities.get(key)
        if found is None:
            found = self.identities[key] = artifact_identity(path, kind)
        return found

    def compiled_specs(self) -> dict[str, CompiledSpec]:
        if self.specs is None:
            self.specs = {
                entry.name: entry for entry in admit_specs(catalogue=interface_catalogue())
            }
        return self.specs

    def compiled_system(self, path: Path) -> CompiledSystem:
        """`compile_system` with its computed-source drift check, once per path."""
        key = path.resolve()
        found = self.systems.get(key)
        if found is None:
            components = {entry.name: entry.spec for entry in self.compiled_specs().values()}
            found = self.systems[key] = compile_system(key, components=components)
        return found


def normalize(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


# Repository metadata a tree input may carry without being part of its
# identity. A submodule checkout holds a `.git` gitlink file whose content
# names the superproject's object store, so it differs between the primary
# checkout and every `git worktree` while the tree's own bytes are identical.
REPOSITORY_METADATA: tuple[str, ...] = (".git",)


def _git(path: Path, *arguments: str) -> subprocess.CompletedProcess[str] | None:
    """`git -C path ...`, or None when git is not installed."""
    try:
        return subprocess.run(["git", "-C", str(path), *arguments], capture_output=True, text=True)
    except FileNotFoundError:
        return None


def _toplevel(path: Path) -> Path | None:
    """The working tree of the innermost git repository holding `path`, or None outside git."""
    directory = path if path.is_dir() else path.parent
    result = _git(directory, "rev-parse", "--show-toplevel")
    if result is None or result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def _listed_files(repository: Path, sub: str) -> list[str]:
    """Files git lists under `sub` of `repository` (tracked and present, plus untracked not
    ignored), relative to `repository`, recursing into submodules."""
    staged = _git(repository, "ls-files", "-z", "--stage", "--", sub or ".")
    listed = _git(repository, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", sub or ".")
    if staged is None or listed is None or staged.returncode != 0 or listed.returncode != 0:
        _fail(f"cannot list the files git sees under {repository / sub}")
    gitlinks = {entry.split("\t", 1)[1] for entry in staged.stdout.split("\0") if entry.startswith("160000 ")}
    found: list[str] = []
    for raw in sorted({item for item in listed.stdout.split("\0") if item}):
        full = repository / raw
        if raw in gitlinks:
            found.extend(f"{raw}/{inner}" for inner in _listed_files(full, ""))
        elif full.is_symlink():
            _fail(f"tree contains a symlink: {full}")
        elif full.is_file():
            found.append(raw)
    return found


def _visible_tree_digest(path: Path) -> str | None:
    """`tree_digest`'s encoding over the files git lists under `path`, or None when git cannot say.

    The file set is git's rather than the directory's, so an ignored file -- a build output, a cache
    -- is not part of a tree's identity. It marks the resolution dirty instead. Outside a git
    checkout, or for a tree git itself ignores, the caller falls back to the directory walk.
    """
    top = _toplevel(path)
    if top is None:
        return None
    resolved = path.resolve()
    relative = "" if resolved == top else resolved.relative_to(top).as_posix()
    if relative:
        ignored = _git(top, "check-ignore", "--quiet", "--", relative)
        if ignored is None or ignored.returncode == 0:
            return None
    prefix = f"{relative}/" if relative else ""
    files = sorted(entry[len(prefix):] for entry in _listed_files(top, relative) if entry.startswith(prefix))
    files = [entry for entry in files if entry not in REPOSITORY_METADATA and not entry.startswith(".git/")]
    digest = hashlib.sha256()
    digest.update(TREE_DOMAIN)
    digest.update(len(files).to_bytes(8, "little"))
    for entry in files:
        full = resolved / entry
        encoded = entry.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
        digest.update(b"\1" if os.access(full, os.X_OK) else b"\0")
        inner = hashlib.sha256(full.read_bytes()).digest()
        digest.update(len(inner).to_bytes(8, "little"))
        digest.update(inner)
    return digest.hexdigest()


def tree_identity(path: Path) -> str:
    """A tree input's identity: the bytes a clone reproduces, never how it was checked out.

    Inside a git checkout that is the files git lists; elsewhere, as in an exported SDK, the walk.
    The two agree on a tree that holds no ignored file.
    """
    if not path.is_dir():
        _fail(f"missing tree artifact: {path}")
    visible = _visible_tree_digest(path)
    return visible if visible is not None else tree_digest(path, exclude=REPOSITORY_METADATA)


def inputs_dirty(paths: list[Path]) -> bool:
    """Whether any input path holds a modified tracked file or an untracked or ignored file.

    Each path is asked of its own repository, and a submodule's root is asked of the superproject as
    well, so a submodule checked out away from its pin is dirty too. Outside git nothing is dirty.
    """
    groups: dict[Path, set[str]] = {}
    for path in paths:
        top = _toplevel(path)
        if top is None:
            continue
        resolved = path.resolve()
        groups.setdefault(top, set()).add("." if resolved == top else resolved.relative_to(top).as_posix())
        if resolved == top:
            outer = _toplevel(top.parent)
            if outer is not None:
                groups.setdefault(outer, set()).add(top.relative_to(outer).as_posix())
    for top, specs in groups.items():
        status = _git(
            top, "status", "-z", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--", *sorted(specs)
        )
        if status is None or status.returncode != 0:
            _fail(f"cannot read git status under {top}")
        for entry in status.stdout.split("\0"):
            if not entry:
                continue
            # Git names an ignored directory once, even when it holds no file. An empty directory adds
            # no byte to any tree digest, so only an ignored directory that holds an entry is dirty.
            if entry.startswith("!! ") and entry.endswith("/") and not _holds_entry(top / entry[3:]):
                continue
            return True
    return False


def _holds_entry(directory: Path) -> bool:
    """Whether `directory` holds anything other than real directories, at any depth."""
    for root, directories, files in os.walk(directory):
        if files or any(os.path.islink(os.path.join(root, name)) for name in directories):
            return True
    return False


def artifact_identity(path: Path, kind: str) -> str:
    if kind == "file":
        if not path.is_file():
            _fail(f"missing file artifact: {path}")
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if kind == "tree":
        return tree_identity(path)
    _fail(f"unknown artifact kind {kind!r}")


def _exact(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        _fail(f"{label}: expected a record")
    actual = set(value)
    if actual != fields:
        _fail(f"{label}: fields are {sorted(actual)}, expected {sorted(fields)}")
    return value


def _bounded_text(value: object, bound: int, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        _fail(f"{label}: expected {'possibly empty ' if empty else ''}text")
    if len(value.encode("utf-8")) > bound:
        _fail(f"{label}: text exceeds bound")
    return value


def _digest(value: object, label: str, contract: ModuleType = image_contract) -> str:
    text = _bounded_text(value, contract.MAX_DIGEST_BYTES, label)
    if _SHA256.fullmatch(text) is None:
        _fail(f"{label}: expected lowercase SHA-256")
    return text


def _closure_name(value: object, label: str, contract: ModuleType) -> str:
    """A closure named by its file name without `.zti`, never by a digest of it."""
    text = _bounded_text(value, contract.MAX_NAME_BYTES, label)
    if _NAME.fullmatch(text) is None:
        _fail(f"{label}: expected a closure name in canonical spelling, got {text!r}")
    if _SHA256.fullmatch(text) is not None:
        _fail(f"{label}: expected a closure name, got a digest")
    return text


def _list(value: object, bound: int, label: str) -> list:
    if not isinstance(value, list):
        _fail(f"{label}: expected a list")
    if len(value) > bound:
        _fail(f"{label}: count exceeds bound")
    return value


def _run_zutai(path: Path, checker: Path, variable: str, source_bound: int) -> dict:
    if not path.is_file():
        _fail(f"record not found: {path}")
    if path.stat().st_size > source_bound:
        _fail(f"{path}: source exceeds bound")
    try:
        decoded = evaluate(command="run", target=checker, input_path=path, env_var=variable)
    except ZutaiError as error:
        _fail(f"{path}: malformed Zutai input: {error}")
    if not decoded.startswith("#valid"):
        _fail(f"{path}: malformed Zutai input: {decoded.strip()}")
    try:
        raw = evaluate(command="json", target=path, input_path=path, env_var=variable)
    except ZutaiError as error:
        _fail(f"{path}: invalid Zutai JSON projection: {error}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        _fail(f"{path}: invalid Zutai JSON projection: {error}")
    return value


def _artifact(
    raw: object,
    label: str,
    *,
    base: Path | None = None,
    cache: ResolutionCache | None = None,
) -> tuple[dict, Path | None]:
    value = _exact(raw, _ARTIFACT_FIELDS, label)
    path_text = _bounded_text(value["path"], image_contract.MAX_PATH_BYTES, f"{label}.path")
    kind = _bounded_text(value["kind"], image_contract.MAX_NAME_BYTES, f"{label}.kind")
    if kind not in image_contract.ARTIFACT_KINDS:
        _fail(f"{label}.kind: unknown artifact kind {kind!r}")
    _digest(value["identity"], f"{label}.identity")
    if base is None:
        return value, None
    relative = Path(path_text)
    if relative.is_absolute() or ".." in relative.parts:
        _fail(f"{label}.path: path must be normalized and closure-relative")
    resolved = (base / relative).resolve()
    if not resolved.is_relative_to(base.resolve()):
        _fail(f"{label}.path: path escapes closure root")
    observed = (
        artifact_identity(resolved, kind) if cache is None else cache.identity(resolved, kind)
    )
    if observed != value["identity"]:
        _fail(f"{label}: identity mismatch for {path_text}")
    return value, resolved


def compile_closure(path: Path, contract: ModuleType = image_contract) -> CompiledClosure:
    value = _exact(
        _run_zutai(
            path.resolve(),
            IMAGE_CHECKER,
            "SLIME_SYSTEM_IMAGE_CLOSURE_PATH",
            contract.MAX_SOURCE_BYTES,
        ),
        _IMAGE_FIELDS,
        str(path),
    )
    if value["formatVersion"] != contract.FORMAT_VERSION:
        _fail(f"unsupported image closure version {value['formatVersion']}")
    name = _bounded_text(value["name"], contract.MAX_NAME_BYTES, "name")
    if _NAME.fullmatch(name) is None or name != path.stem:
        _fail("closure name must match its file name and use canonical spelling")
    _digest(value["systemIdentity"], "systemIdentity")
    _artifact(value["systemSpec"], "systemSpec")
    implementations = _list(
        value["implementations"], contract.MAX_IMPLEMENTATIONS, "implementations"
    )
    component_names: list[str] = []
    for index, raw in enumerate(implementations):
        entry = _exact(raw, _IMPLEMENTATION_FIELDS, f"implementations[{index}]")
        component_names.append(
            _bounded_text(entry["component"], contract.MAX_NAME_BYTES, "component")
        )
        provider = _bounded_text(entry["provider"], contract.MAX_NAME_BYTES, "provider")
        if provider not in contract.PROVIDERS:
            _fail(f"implementations[{index}].provider: unknown provider {provider!r}")
        _artifact(entry["artifact"], f"implementations[{index}].artifact")
        _digest(entry["identity"], f"implementations[{index}].identity")
        profile = _bounded_text(
            entry["buildProfile"], contract.MAX_NAME_BYTES, "buildProfile", empty=True
        )
        if profile not in contract.BUILD_PROFILES:
            _fail(
                f"implementations[{index}].buildProfile: unknown profile {profile!r}; "
                f"expected one of {sorted(contract.BUILD_PROFILES)}"
            )
    if component_names != sorted(component_names) or len(set(component_names)) != len(
        component_names
    ):
        _fail("implementations must be uniquely keyed and sorted by component")
    target = _exact(value["target"], _TARGET_FIELDS, "target")
    _bounded_text(target["profile"], contract.MAX_NAME_BYTES, "target.profile")
    _bounded_text(target["platform"], contract.MAX_NAME_BYTES, "target.platform")
    _artifact(target["prefix"], "target.prefix")
    _bounded_text(target["toolchain"], contract.MAX_TEXT_BYTES, "target.toolchain")
    _bounded_text(target["rustSel4Commit"], contract.MAX_TEXT_BYTES, "target.rustSel4Commit")
    for role_name, allowed in (("root", contract.ROOT_ROLES), ("loader", contract.LOADER_ROLES)):
        role = _exact(value[role_name], _ROLE_FIELDS, role_name)
        if role["role"] not in allowed:
            _fail(f"{role_name}.role: unknown role {role['role']!r}")
        _artifact(role["implementation"], f"{role_name}.implementation")
        role_parameters = _list(
            role["parameters"], contract.MAX_ROLE_PARAMETERS, f"{role_name}.parameters"
        )
        for index, parameter in enumerate(role_parameters):
            _bounded_text(parameter, contract.MAX_TEXT_BYTES, f"{role_name}.parameters[{index}]")
    release_inputs = _list(value["releaseInputs"], contract.MAX_RELEASE_INPUTS, "releaseInputs")
    release_names = []
    for index, raw in enumerate(release_inputs):
        entry = _exact(raw, _NAMED_INPUT_FIELDS, f"releaseInputs[{index}]")
        release_names.append(
            _bounded_text(entry["name"], contract.MAX_NAME_BYTES, "release input name")
        )
        _artifact(entry["artifact"], f"releaseInputs[{index}].artifact")
    if release_names != sorted(release_names) or len(set(release_names)) != len(release_names):
        _fail("releaseInputs must be uniquely keyed and sorted by name")
    parameters = _list(value["buildParameters"], contract.MAX_BUILD_PARAMETERS, "buildParameters")
    parameter_names = []
    for index, raw in enumerate(parameters):
        entry = _exact(raw, _PARAMETER_FIELDS, f"buildParameters[{index}]")
        parameter_names.append(
            _bounded_text(entry["name"], contract.MAX_NAME_BYTES, "parameter name")
        )
        _bounded_text(entry["value"], contract.MAX_TEXT_BYTES, "parameter value", empty=True)
    if parameter_names != sorted(parameter_names) or len(set(parameter_names)) != len(
        parameter_names
    ):
        _fail("buildParameters must be uniquely keyed and sorted by name")
    if parameter_names:
        unknown = sorted(set(parameter_names) - set(contract.BUILD_PARAMETERS))
        if unknown:
            _fail(
                f"buildParameters names {unknown}, which this closure version does not admit; "
                f"expected a subset of {sorted(contract.BUILD_PARAMETERS)}"
            )
    outputs = _list(value["expectedOutputs"], contract.MAX_OUTPUTS, "expectedOutputs")
    if outputs != list(contract.OUTPUT_CLASSES):
        _fail("expectedOutputs must name the complete canonical output set in contract order")
    normalized = normalize(value)
    if len(normalized) > contract.MAX_NORMALIZED_BYTES:
        _fail("normalized closure exceeds bound")
    return CompiledClosure(
        path.resolve(),
        value,
        normalized,
        hashlib.sha256(contract.IDENTITY_DOMAIN + normalized).digest(),
    )


def compile_test_run(path: Path, contract: ModuleType = test_contract) -> CompiledTestRun:
    """Require fully bound fields; declaration placeholders are never executable."""
    return _compile_test_run(path, contract, declaration=False)


def compile_test_run_declaration(
    path: Path, contract: ModuleType = test_contract,
) -> CompiledTestRunDeclaration:
    """Validate frozen checker inputs, allowing explicitly paired unbound fields."""
    return _compile_test_run(path, contract, declaration=True)


def _compile_test_run(
    path: Path, contract: ModuleType, *, declaration: bool,
) -> CompiledTestRun | CompiledTestRunDeclaration:
    value = _exact(
        _run_zutai(
            path.resolve(), TEST_CHECKER, "SLIME_SYSTEM_TEST_RUN_PATH", contract.MAX_SOURCE_BYTES
        ),
        _TEST_FIELDS,
        str(path),
    )
    if value["formatVersion"] != contract.FORMAT_VERSION:
        _fail(f"unsupported test-run version {value['formatVersion']}")
    name = _bounded_text(value["name"], contract.MAX_NAME_BYTES, "name")
    if _NAME.fullmatch(name) is None or name != path.stem:
        _fail("test-run name must match its file name and use canonical spelling")
    if not (declaration and value["imageClosure"] == ""):
        _closure_name(value["imageClosure"], "imageClosure", contract)
    if value["executionKind"] not in contract.EXECUTION_KINDS:
        _fail(f"unknown execution kind {value['executionKind']!r}")
    _bounded_text(value["executionProfile"], contract.MAX_NAME_BYTES, "executionProfile")
    for field in ("disks", "networks", "devices"):
        fixtures = _list(value[field], contract.MAX_FIXTURES, field)
        names = []
        for index, raw in enumerate(fixtures):
            entry = _exact(raw, _FIXTURE_FIELDS, f"{field}[{index}]")
            names.append(_bounded_text(entry["name"], contract.MAX_NAME_BYTES, "fixture name"))
            unbound = declaration and entry["path"] == "" and entry["identity"] == ""
            if not unbound:
                _bounded_text(entry["path"], contract.MAX_PATH_BYTES, "fixture path")
                _digest(entry["identity"], "fixture identity", contract)
            if not isinstance(entry["writable"], bool):
                _fail("fixture writable must be boolean")
        if names != sorted(names) or len(set(names)) != len(names):
            _fail(f"{field} must be uniquely keyed and sorted by name")
    faults = _list(value["faultControls"], contract.MAX_FAULT_CONTROLS, "faultControls")
    for index, raw in enumerate(faults):
        entry = _exact(raw, _FAULT_FIELDS, f"faultControls[{index}]")
        if entry["kind"] not in contract.FAULT_KINDS:
            _fail(f"faultControls[{index}]: unknown kind {entry['kind']!r}")
        unbound = declaration and entry["target"] == "" and entry["value"] == ""
        if not unbound:
            _bounded_text(entry["target"], contract.MAX_TEXT_BYTES, "fault target")
            _bounded_text(entry["value"], contract.MAX_TEXT_BYTES, "fault value")
    timeout = value["timeoutSeconds"]
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 0 < timeout <= contract.MAX_TIMEOUT_SECONDS
    ):
        _fail("timeoutSeconds is outside the declared bound")
    _digest(value["markerContractIdentity"], "markerContractIdentity", contract)
    forbidden = _list(
        value["forbiddenOutcomes"], contract.MAX_FORBIDDEN_OUTCOMES, "forbiddenOutcomes"
    )
    for index, outcome in enumerate(forbidden):
        _bounded_text(outcome, contract.MAX_TEXT_BYTES, f"forbiddenOutcomes[{index}]")
    normalized = normalize(value)
    if len(normalized) > contract.MAX_NORMALIZED_BYTES:
        _fail("normalized test run exceeds bound")
    result = CompiledTestRunDeclaration if declaration else CompiledTestRun
    return result(
        path.resolve(),
        value,
        normalized,
        hashlib.sha256(contract.IDENTITY_DOMAIN + normalized).digest(),
    )


_LOCATOR_FIELDS = {"path", "kind"}
_SOURCE_FIELDS = _IMAGE_FIELDS - {"systemIdentity"}
_SOURCE_IMPLEMENTATION_FIELDS = _IMPLEMENTATION_FIELDS - {"identity"}


@dataclass(frozen=True)
class MaterializedClosure:
    """A source resolved in this checkout: the v2 closure written to `path`, and whether it is dirty."""

    path: Path
    compiled: CompiledClosure
    dirty: bool


def source_path(name: str, root: Path = ROOT) -> Path:
    return root / SOURCE_ROOT.relative_to(ROOT) / f"{name}.zti"


def source_names(root: Path = ROOT) -> list[str]:
    return sorted(path.stem for path in (root / SOURCE_ROOT.relative_to(ROOT)).glob("*.zti"))


def _locator(raw: object, label: str) -> dict:
    value = _exact(raw, _LOCATOR_FIELDS, label)
    path_text = _bounded_text(value["path"], image_contract.MAX_PATH_BYTES, f"{label}.path")
    relative = Path(path_text)
    if relative.is_absolute() or ".." in relative.parts:
        _fail(f"{label}.path: path must be normalized and closure-relative")
    if value["kind"] not in image_contract.ARTIFACT_KINDS:
        _fail(f"{label}.kind: unknown artifact kind {value['kind']!r}")
    return value


def compile_source(path: Path) -> dict:
    """One closure source: the v2 shape with every identity left out. The rest is checked on its
    resolution by `compile_closure` and `resolve_closure`."""
    value = _exact(
        _run_zutai(path.resolve(), SOURCE_CHECKER, "SLIME_SYSTEM_IMAGE_CLOSURE_SOURCE_PATH", source_contract.MAX_SOURCE_BYTES),
        _SOURCE_FIELDS,
        str(path),
    )
    if value["formatVersion"] != source_contract.FORMAT_VERSION:
        _fail(f"unsupported closure source version {value['formatVersion']}")
    name = _bounded_text(value["name"], image_contract.MAX_NAME_BYTES, "name")
    if _NAME.fullmatch(name) is None or name != path.stem:
        _fail("closure source name must match its file name and use canonical spelling")
    _locator(value["systemSpec"], "systemSpec")
    for index, raw in enumerate(_list(value["implementations"], image_contract.MAX_IMPLEMENTATIONS, "implementations")):
        _locator(_exact(raw, _SOURCE_IMPLEMENTATION_FIELDS, f"implementations[{index}]")["artifact"], f"implementations[{index}].artifact")
    _locator(_exact(value["target"], _TARGET_FIELDS, "target")["prefix"], "target.prefix")
    for role in ("root", "loader"):
        _locator(_exact(value[role], _ROLE_FIELDS, role)["implementation"], f"{role}.implementation")
    for index, raw in enumerate(_list(value["releaseInputs"], image_contract.MAX_RELEASE_INPUTS, "releaseInputs")):
        _locator(_exact(raw, _NAMED_INPUT_FIELDS, f"releaseInputs[{index}]")["artifact"], f"releaseInputs[{index}].artifact")
    return value


def resolve_source(
    name: str,
    *,
    source_root: Path = ROOT,
    output_root: Path | None = None,
    cache: ResolutionCache | None = None,
) -> MaterializedClosure:
    """Resolve one closure source in the checkout at `source_root` and write the v2 closure.

    Each locator gains the identity of its bytes, the system spec and each component spec their
    compiled identities. The written closure's identity is the build's derivation id.
    """
    base = source_root.resolve()
    value = compile_source(source_path(name, base))
    reads = ResolutionCache() if cache is None else cache
    inputs: list[Path] = []

    def reference(locator: dict) -> dict:
        path = base / locator["path"]
        inputs.append(path)
        return {"path": locator["path"], "kind": locator["kind"], "identity": reads.identity(path, locator["kind"])}

    specs = reads.compiled_specs()
    system = reads.compiled_system(base / value["systemSpec"]["path"])
    implementations = []
    for entry in value["implementations"]:
        spec = specs.get(entry["component"])
        if spec is None:
            _fail(f"implementations[{entry['component']}]: no admitted component spec")
        implementations.append({
            "component": entry["component"],
            "provider": entry["provider"],
            "artifact": reference(entry["artifact"]),
            "identity": spec.identity.hex(),
            "buildProfile": entry["buildProfile"],
        })
    resolved = {
        "formatVersion": image_contract.FORMAT_VERSION,
        "name": name,
        "systemSpec": reference(value["systemSpec"]),
        "systemIdentity": system.identity.hex(),
        "implementations": implementations,
        "target": {**value["target"], "prefix": reference(value["target"]["prefix"])},
        "root": {**value["root"], "implementation": reference(value["root"]["implementation"])},
        "loader": {**value["loader"], "implementation": reference(value["loader"]["implementation"])},
        "releaseInputs": [{"name": entry["name"], "artifact": reference(entry["artifact"])} for entry in value["releaseInputs"]],
        "buildParameters": value["buildParameters"],
        "expectedOutputs": value["expectedOutputs"],
    }
    directory = (base / RESOLVED_ROOT.relative_to(ROOT)) if output_root is None else output_root
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{name}.zti"
    staged = directory / f".{name}.{os.getpid()}.zti"
    staged.write_text(zti(resolved) + "\n", encoding="utf-8")
    os.replace(staged, target)
    return MaterializedClosure(target, compile_closure(target), inputs_dirty(inputs))


def resolve_closure(
    path: Path,
    *,
    source_root: Path = ROOT,
    cache: ResolutionCache | None = None,
) -> ResolvedClosure:
    """Re-read every path a closure names and refuse any identity that disagrees.

    `cache` shares those reads across a corpus; see `ResolutionCache` for when
    that is sound.
    """
    compiled = compile_closure(path)
    value = compiled.value
    base = source_root.resolve()
    reads = ResolutionCache() if cache is None else cache
    _, system_path = _artifact(value["systemSpec"], "systemSpec", base=base, cache=reads)
    assert system_path is not None
    specs = reads.compiled_specs()
    system = reads.compiled_system(system_path)
    if system.identity.hex() != value["systemIdentity"]:
        _fail("systemIdentity does not match the compiled system")
    if system.spec["targetRequirement"] != value["target"]["profile"]:
        _fail("system target requirement does not match the closure target profile")
    artifacts: dict[str, Path] = {"systemSpec": system_path}
    _, prefix = _artifact(value["target"]["prefix"], "target.prefix", base=base, cache=reads)
    assert prefix is not None
    artifacts["prefix"] = prefix
    profile_name = value["target"]["profile"]
    binding = PROFILE_PLATFORMS.get(profile_name)
    if binding is None:
        _fail(f"unknown component SDK target profile {profile_name!r}")
    if binding["platform"] != value["target"]["platform"]:
        _fail("target profile and platform binding do not pair")
    pin_table = pins(base)
    rust_sel4 = pin_table["rust_sel4"]
    if rust_sel4["toolchain"] != value["target"]["toolchain"]:
        _fail("closure toolchain does not match the source pin")
    if rust_sel4["commit"] != value["target"]["rustSel4Commit"]:
        _fail("closure rust-sel4 commit does not match the source pin")
    observed_prefix = pin_table[binding["pins"]]
    for relative, key in (
        ("bin/kernel.elf", "kernel_sha256"),
        ("libsel4/include/kernel/gen_config.json", "kernel_config_sha256"),
        ("libsel4/include/sel4/gen_config.json", "libsel4_config_sha256"),
        ("support/kernel.dtb", "dtb_sha256"),
        ("support/platform_gen.yaml", "platform_info_sha256"),
    ):
        artifact = prefix / relative
        if not artifact.is_file():
            _fail(f"target.prefix is missing pinned artifact {relative}")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if digest != observed_prefix[key]:
            _fail(f"target.prefix {relative} does not match the source pin")
    selections = {entry["component"]: entry for entry in value["implementations"]}
    if set(selections) != set(system.spec["components"]):
        _fail("implementation selections do not exactly cover the system components")
    external: dict[str, Path] = {}
    for component in system.spec["components"]:
        spec = specs[component]
        selection = selections[component]
        implementation = spec.spec["implementation"]
        if selection["provider"] != implementation["provider"]:
            _fail(f"{component}: closure provider disagrees with the component spec")
        if selection["identity"] != spec.identity.hex():
            _fail(f"{component}: component-spec identity mismatch")
        _, implementation_artifact = _artifact(
            selection["artifact"],
            f"implementations[{component}].artifact",
            base=base,
            cache=reads,
        )
        assert implementation_artifact is not None
        artifacts[f"component:{component}"] = implementation_artifact
        if implementation["provider"] == image_contract.PROVIDER_EXTERNAL:
            if implementation_artifact.is_dir():
                _fail(f"{component}: external implementation artifact must be a file")
            if (
                hashlib.sha256(implementation_artifact.read_bytes()).hexdigest()
                != implementation["contentHash"]
            ):
                _fail(f"{component}: external ELF hash disagrees with component spec")
            external[implementation["binary"]] = implementation_artifact
    for name in ("root", "loader"):
        _, artifact = _artifact(
            value[name]["implementation"], f"{name}.implementation", base=base, cache=reads
        )
        assert artifact is not None
        artifacts[name] = artifact
    for entry in value["releaseInputs"]:
        _, artifact = _artifact(
            entry["artifact"], f"releaseInputs[{entry['name']}].artifact", base=base, cache=reads
        )
        assert artifact is not None
        artifacts[f"release:{entry['name']}"] = artifact
    release_names = [entry["name"] for entry in value["releaseInputs"]]
    required_release_inputs = {
        "boot-contracts",
        "generation-builder",
        "image-builder",
        "elf-delivery",
        "cargo-lock",
        "component-build-support",
        "component-cargo-config",
        "component-library",
        "component-proto",
        "component-runtime",
        "component-spec-contract",
        "interface-schema-contract",
        "root-child",
        "root-target",
        "target-spec",
        "workspace-manifest",
        "zenoh-grants-table-contract",
        "zenoh-grants-table-encoder",
        "zenoh-limits-contract",
        "zenoh-limits-encoder",
        "generation-resources",
    }
    if set(release_names) != required_release_inputs:
        _fail(
            "releaseInputs must exactly cover the canonical workspace build inputs; "
            f"missing={sorted(required_release_inputs - set(release_names))} "
            f"extra={sorted(set(release_names) - required_release_inputs)}"
        )
    root_role = value["root"]["role"]
    if root_role not in image_contract.ROOT_ROLES:
        _fail(f"unknown root role {root_role!r}")
    root_parameters = value["root"]["parameters"]
    unknown_root = sorted(set(root_parameters) - set(image_contract.ROOT_PARAMETERS))
    if unknown_root:
        _fail(
            f"root.parameters names {unknown_root}, which this closure version does not "
            f"admit; expected a subset of {sorted(image_contract.ROOT_PARAMETERS)}"
        )
    if len(set(root_parameters)) != len(root_parameters):
        _fail("root.parameters must be unique")
    if root_parameters != sorted(root_parameters):
        _fail("root.parameters must be sorted")
    # Both parameters compile a platform-specific address or marker into the
    # root task, so the wrong platform is refused before Cargo runs rather than
    # producing a root that reads a device it does not have.
    platform_name = value["target"]["platform"]
    for parameter, required_platform in (
        (image_contract.ROOT_PARAMETER_QEMU_KEYBOARD, "qemu-arm-virt"),
        (image_contract.ROOT_PARAMETER_DUO_TEST_TERMINATOR, "cv1800b-duo"),
    ):
        if parameter in root_parameters and platform_name != required_platform:
            _fail(
                f"root.parameters: {parameter!r} requires platform {required_platform!r}, "
                f"not {platform_name!r}"
            )
    if artifacts["root"] != (base / "slime-root").resolve():
        _fail("every root role's implementation must be the declared slime-root tree")
    if value["loader"]["role"] != image_contract.LOADER_ROLE_KERNEL_LOADER:
        _fail("this closure requires the kernel-loader role")
    if value["loader"]["parameters"]:
        _fail("kernel-loader accepts no role parameters in closure version 1")
    expected_loader_path = _LOADER_PATHS.get(platform_name)
    if expected_loader_path is None:
        _fail(f"no loader submodule declared for platform {platform_name!r}")
    if artifacts["loader"] != (base / expected_loader_path).resolve():
        _fail(f"kernel-loader implementation must be the declared {expected_loader_path} tree")
    cargo_target = str(binding["cargo_target"])
    if not binding["cargo_target_is_spec"]:
        _fail("system-image closures require a file-backed target specification")
    expected_target_spec = (
        base / "deps" / "rust-sel4" / "support" / "targets" / Path(cargo_target).name
    ).resolve()
    if artifacts["release:target-spec"] != expected_target_spec:
        _fail("target-spec release input does not match the selected target profile")
    expected_root_target = (
        "aarch64-sel4-roottask-minimal.json"
        if value["target"]["profile"].startswith("aarch64-")
        else "riscv64imac-sel4-roottask-minimal.json"
    )
    if artifacts["release:root-target"].name != expected_root_target:
        _fail("root target specification does not match the selected target profile")
    parameters = {entry["name"]: entry["value"] for entry in value["buildParameters"]}
    profiles = {entry["component"]: entry["buildProfile"] for entry in value["implementations"]}
    manifest = derive_manifest(system)
    return ResolvedClosure(
        compiled,
        system,
        manifest,
        artifacts,
        external,
        parameters,
        profiles,
        root_role,
        tuple(root_parameters),
    )


def make_build_result(
    resolved: ResolvedClosure,
    *,
    dirty: bool,
    output_root: Path,
    generation: Path,
    root: Path,
    loader: Path,
    image: Path,
    identity_manifest: Path,
) -> tuple[dict, bytes, str]:
    def record(path: Path) -> dict:
        payload = path.read_bytes()
        return {
            "path": path.relative_to(output_root).as_posix(),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    value = {
        "formatVersion": image_contract.BUILD_RESULT_FORMAT_VERSION,
        "closureIdentity": resolved.compiled.identity.hex(),
        "systemIdentity": resolved.system.identity.hex(),
        "platform": resolved.compiled.value["target"]["platform"],
        "rootRole": resolved.compiled.value["root"]["role"],
        "loaderRole": resolved.compiled.value["loader"]["role"],
        "targetProfile": resolved.compiled.value["target"]["profile"],
        "generation": record(generation),
        "root": record(root),
        "loader": record(loader),
        "image": record(image),
        "identityManifest": record(identity_manifest),
        "dirty": dirty,
    }
    normalized = normalize(value)
    return (
        value,
        normalized,
        hashlib.sha256(image_contract.BUILD_RESULT_IDENTITY_DOMAIN + normalized).hexdigest(),
    )


def compile_negative_case(
    path: Path, contract: ModuleType = image_contract
) -> CompiledNegativeCase:
    """One negative build case: a valid base closure plus one closed mutation.

    Compiled rather than resolved, and the distinction is the point: a negative
    case names no artifacts of its own, so there is nothing to re-read and
    verify. What is checked is that it is well-formed, that its mutation is one
    the contract admits, and that the base closure it perturbs exists and
    resolves — because a mutation against a base nobody can build is evidence
    of nothing.
    """
    value = _exact(
        _run_zutai(
            path.resolve(),
            NEGATIVE_CHECKER,
            "SLIME_NEGATIVE_BUILD_CASE_PATH",
            contract.MAX_SOURCE_BYTES,
        ),
        _NEGATIVE_FIELDS,
        str(path),
    )
    if value["formatVersion"] != contract.NEGATIVE_FORMAT_VERSION:
        _fail(f"unsupported negative build case version {value['formatVersion']}")
    name = _bounded_text(value["name"], contract.MAX_NAME_BYTES, "name")
    if _NAME.fullmatch(name) is None or name != path.stem:
        _fail("negative case name must match its file name and use canonical spelling")
    _closure_name(value["baseClosure"], "baseClosure", contract)
    mutation = _bounded_text(value["mutation"], contract.MAX_NAME_BYTES, "mutation")
    if mutation not in contract.MUTATIONS:
        _fail(
            f"mutation: {mutation!r} is not one this contract admits; expected one of "
            f"{sorted(contract.MUTATIONS)}"
        )
    _bounded_text(value["expectedRefusal"], contract.MAX_TEXT_BYTES, "expectedRefusal")
    normalized = normalize(value)
    if len(normalized) > contract.MAX_NORMALIZED_BYTES:
        _fail("normalized negative case exceeds bound")
    return CompiledNegativeCase(
        path.resolve(),
        value,
        normalized,
        hashlib.sha256(contract.NEGATIVE_IDENTITY_DOMAIN + normalized).digest(),
    )


def negative_case_paths(root: Path = NEGATIVE_ROOT) -> list[Path]:
    return sorted(root.glob("*.zti"))
