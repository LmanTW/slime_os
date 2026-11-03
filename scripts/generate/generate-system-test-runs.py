#!/usr/bin/env python3

"""Generate `contracts/system-test-run/v2` records from each plane gate's execution inputs.

CP11 declared that QEMU arguments, disk fixtures, injected device behavior,
timeouts, and marker contracts belong to a versioned test-run contract rather
than to the image closure, so a marker oracle or a timeout cannot alter the
image it exercises. CP14's fifth deliverable is moving the real values there.

The records are *frozen declarations*, extracted once and then held fixed —
the same convention `sel4_boot_layout_check` uses for its per-plane layout
fixtures, with `--check` refusing drift and `--bless` re-freezing after an
intended change. That direction matters: after the first freeze the record is
the authority and a checker that quietly grows a disk or doubles a timeout is a
refusal, not a silent update.

What this does *not* do is make the checkers read these records. That is CP15's
migration, and claiming it here would be false: the values below are still
executed from each checker's own constants. What the freeze buys today is that
an execution input cannot change without a reviewed record change.

A record names the closure its plane builds rather than copying the closure's
identity, so a change to a closure input leaves every record unchanged.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import ast
import re
from collections.abc import Iterable

import work_items

from harness import ROOT

CHECK_ROOT = ROOT / "scripts" / "check"
RUN_ROOT = ROOT / "contracts" / "system-test-run" / "v2" / "runs"
CLOSURE_ROOT = ROOT / "contracts" / "system-image-closure" / "v3" / "closures"

# The marker contract each plane's expectations are stated against. One
# identity for the seL4 serial marker vocabulary: the planes assert different
# chains *within* it, and those chains stay in their owning checker.
MARKER_CONTRACT = "f03ce9b40628dcb82e3ec97154b2f5ec549a41bfbb9cfcf13a632e40113fd42e"

# Multi-platform checker invocations whose non-default arm is not closure
# reachable, so the record names a literal image instead of resolving one.
# `just riscv64_qemu_check` is the recipe that invokes these, and every target
# it names with `--platform qemu-riscv-virt` and can execute belongs here: a
# real invocation without a record leaves its execution profile and image
# provenance unfrozen. The tuple is `(run name, execution profile, image
# name)`, and a checker may name more than one: MEM-64M's reuse arm boots its
# own RV64 image beside the ceiling arm's, and a single-tuple table would leave
# the second one unrecorded.
EXTRA_RUNS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "sel4-generation": (
        (
            "sel4-generation-qemu-riscv-virt",
            "qemu-riscv-virt",
            "slime-sel4-generation-qemu-riscv-virt.elf",
        ),
    ),
    "sel4-private-memory": (
        (
            "sel4-private-memory-qemu-riscv-virt",
            "qemu-riscv-virt",
            "slime-sel4-private-memory-qemu-riscv-virt.elf",
        ),
        (
            "sel4-private-memory-cycles-qemu-riscv-virt",
            "qemu-riscv-virt",
            "slime-sel4-private-memory-cycles-qemu-riscv-virt.elf",
        ),
    ),
    "sel4-rollback": (
        (
            "sel4-rollback-qemu-riscv-virt",
            "qemu-riscv-virt",
            "slime-sel4-rollback-qemu-riscv-virt.elf",
        ),
    ),
}

# Additional invocations that ARE closure-reachable, unlike the arms above.
# Every separately booted image needs its own frozen record, because
# `check-system-test-run.py` can only freeze and validate an image's execution
# inputs through a record naming it. The tuple is `(run name, closure name,
# execution profile)`; the image resolves through the closure, so there is no
# literal path to name.
EXTRA_CLOSURE_RUNS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "sel4-reclamation": (("sel4-large-image", "sel4-large-image", "qemu-arm-virt"),),
    # IO8 and IO9: the product-graph checker's other arms boot the product
    # graph plus the pwm driver (`just sel4_pwm_graph_check`) and plus the
    # serial driver and heartbeat producer (`just sel4_mavlink_graph_check`).
    # The serial arm (`just sel4_serial_graph_check`) boots it plus a driver on
    # QEMU virt's second serial port and a testkit probe.
    "sel4-component-graph": (
        ("sel4-pwm", "sel4-pwm", "qemu-arm-virt"),
        ("sel4-mavlink", "sel4-mavlink", "qemu-arm-virt"),
        ("sel4-serial", "sel4-serial", "qemu-arm-virt"),
    ),
    "sel4-private-memory": (
        (
            "sel4-private-memory-fail-large-map",
            "sel4-private-memory-fail-large-map",
            "qemu-arm-virt",
        ),
        (
            "sel4-private-memory-fail-second-allocation",
            "sel4-private-memory-fail-second-allocation",
            "qemu-arm-virt",
        ),
        (
            "sel4-private-memory-cycles",
            "sel4-private-memory-cycles",
            "qemu-arm-virt",
        ),
    ),
    # The network checker boots one image per arm. Its default arm is `sel4-io-network`, and the other
    # fourteen are named here, each by the closure it builds. The socket-buffer arm is planned until its composition lands.
    "sel4-io-network": tuple(
        (name, name, "qemu-arm-virt")
        for name in (
            "sel4-io-tcp",
            "sel4-io-tcp-impairment",
            "sel4-io-tcp-listener",
            "sel4-io-tcp-options",
            "sel4-io-tcp-buffers",
            "sel4-io-driver-reset-in-flight",
            "sel4-io-service-fault-in-flight",
            "sel4-io-lifetime",
            "sel4-io-local",
            "sel4-net",
            "sel4-zenoh",
            "sel4-zenoh-external",
            "sel4-zenoh-service",
            "sel4-http",
            "sel4-http-public",
        )
    ),
}

# A checker that boots several images passes QEMU arguments in a few functions, and its arms share the checker's
# timeout and failure markers. Three tables describe such a checker, and a person edits them:
#
#   ARM_ENTRY_FUNCTIONS  the functions that boot each arm. An arm that runs inline in `main()` has none.
#   QEMU_SITES           the functions that pass QEMU arguments, and the devices each one attaches.
#   ARM_DEVICES          the devices each arm attaches. A record states exactly this.
#
# Extraction does not infer a device from the code. It checks that the code agrees with the tables, and a
# disagreement in either direction is a refusal. A QEMU token may sit only in a site. Each site passes exactly
# the devices it declares. The sites that an arm can reach must attach exactly the devices the arm declares. The
# reach counts every name that the arm's functions read, in nested definitions and in both branches of a
# conditional, so it can over-state a device and cannot hide one that a name reaches.
ARM_ENTRY_FUNCTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "check-sel4-io-network-plane.py": {
        "sel4-io-network": ("run_authority_arm",),
        "sel4-io-tcp": ("run_tcp_arm",),
        "sel4-io-tcp-impairment": ("run_impairment_arm",),
        "sel4-io-tcp-listener": ("run_listener_arm",),
        "sel4-io-tcp-options": ("run_options_arm",),
        "sel4-io-tcp-buffers": ("run_buffers_arm",),
        "sel4-io-driver-reset-in-flight": ("run_tcp_arm",),
        "sel4-io-service-fault-in-flight": (),
        "sel4-io-lifetime": (),
        "sel4-io-local": (),
        "sel4-net": ("run_net_arm",),
        "sel4-zenoh": ("run_zenoh_arm",),
        "sel4-zenoh-external": ("run_zenoh_external_arm",),
        "sel4-zenoh-service": ("run_zenoh_service_arm",),
        "sel4-http": ("run_http_arm",),
        "sel4-http-public": ("run_http_public_arm",),
    },
}

QEMU_SITES: dict[str, dict[str, tuple[str, ...]]] = {
    "check-sel4-io-network-plane.py": {
        "run_with_peer": ("virtio-net-device",),
        "run_net_arm": ("virtio-net-device",),
        "run_zenoh_external_arm": ("virtio-net-device",),
        "run_http_request": ("virtio-net-device",),
    },
}

# The `--arm` choice of `main()` that runs each arm. The generator reads the branches of `main()` that test
# each choice, to find what the arm runs there and the closure it builds. A missing entry is a refusal.
ARM_CHOICES: dict[str, dict[str, str]] = {
    "check-sel4-io-network-plane.py": {
        "sel4-io-network": "authority",
        "sel4-io-tcp": "tcp",
        "sel4-io-tcp-impairment": "tcp-impairment",
        "sel4-io-tcp-listener": "tcp-listener",
        "sel4-io-tcp-options": "tcp-options",
        "sel4-io-tcp-buffers": "tcp-buffers",
        "sel4-io-driver-reset-in-flight": "driver-reset",
        "sel4-io-service-fault-in-flight": "service-fault",
        "sel4-io-lifetime": "lifetime",
        "sel4-io-local": "local",
        "sel4-net": "net",
        "sel4-zenoh": "zenoh",
        "sel4-zenoh-external": "zenoh-external",
        "sel4-zenoh-service": "zenoh-service",
        "sel4-http": "http",
        "sel4-http-public": "http-public",
    },
}

# The name of the parsed-arguments variable and the attribute that selects an arm, as in `arguments.arm`.
ARM_SELECTOR = ("arguments", "arm")

ARM_DEVICES: dict[str, dict[str, tuple[str, ...]]] = {
    "check-sel4-io-network-plane.py": {
        "sel4-io-network": (),
        "sel4-io-tcp": ("virtio-net-device",),
        "sel4-io-tcp-impairment": ("virtio-net-device",),
        "sel4-io-tcp-listener": ("virtio-net-device",),
        "sel4-io-tcp-options": ("virtio-net-device",),
        "sel4-io-tcp-buffers": ("virtio-net-device",),
        "sel4-io-driver-reset-in-flight": ("virtio-net-device",),
        "sel4-io-service-fault-in-flight": (),
        "sel4-io-lifetime": (),
        "sel4-io-local": (),
        "sel4-net": ("virtio-net-device",),
        "sel4-zenoh": (),
        "sel4-zenoh-external": ("virtio-net-device",),
        "sel4-zenoh-service": (),
        "sel4-http": ("virtio-net-device",),
        "sel4-http-public": ("virtio-net-device",),
    },
}

# A planning exclusion belongs to one invocation, never to its whole checker.
# Any implementation artifact appearing requires removing the exclusion first.
# Rows are (canonical item UUID, checker filename, closure name, artifact paths).
PLANNED_RUNS: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
    "sel4-serial": (
        "01a10778-adf1-7d64-a4e8-851e425c03e9",
        "check-sel4-component-graph.py",
        "sel4-serial",
        (
            "contracts/system-spec/v1/systems/sel4-serial.zti",
            "contracts/generation-manifest/v1/compositions/sel4-serial.zti",
            "contracts/system-image-closure/v3/closures/sel4-serial.zti",
            "contracts/system-test-run/v2/runs/sel4-serial.zti",
            "components/services/pl011-driver",
            "components/testkit/serial-probe",
        ),
    ),
}

# Checkers that boot no seL4 QEMU plane of their own, so they own no test run:
# board gates, host-only contract gates, aggregate composers that delegate to
# the planes they compose, and the bless/derivation helpers.
NOT_A_PLANE = {
    "check-sel4-boot-layout.py",  # composes every plane; owns no single run
    "check-sel4-fabric-aggregate.py",  # composes the fault and traffic planes
    "check-sel4-capability-layout.py",  # audits the boot plane's root, no run of its own
    "check-sel4-gate-control.py",  # mutates other gates' transcripts
    "check-sel4-plane.py",  # shared runner
    "check-sel4-root-boot.py",  # root-only aggregate over the boot plane
    "check-sel4-gate-controls.py",  # asserts other gates reject bad input; boots nothing
    "check-sel4-pins.py",  # host-side pin assertion; boots nothing
    "check-sel4-x86-64-image.py",  # validates artifact identity; boots nothing
    "check-sel4-trace-plane.py",  # analyses a transcript; boots nothing
}


def fail(message: str) -> None:
    raise SystemExit(f"system test run generation: {message}")


def plane_checkers() -> list[_Path]:
    validate_planned_runs()
    return [
        path
        for path in sorted(CHECK_ROOT.glob("check-sel4-*.py"))
        if path.name not in NOT_A_PLANE
    ]


def run_name(path: _Path) -> str:
    """`check-sel4-io-block-plane.py` -> `sel4-io-block`."""
    stem = path.stem[len("check-") :]
    if stem.endswith("-plane"):
        stem = stem[: -len("-plane")]
    return stem

def declared_variants(path: _Path) -> list[tuple[str, str, str, str]]:
    """Invocation names before planning exclusions or artifact resolution."""
    name = run_name(path)
    variants = [(name, closure_name_for(path, name), "qemu-arm-virt", "")]
    for run, profile, image in EXTRA_RUNS.get(name, ()):
        variants.append((run, "", profile, image))
    for run, closure, profile in EXTRA_CLOSURE_RUNS.get(name, ()):
        variants.append((run, closure, profile, ""))
    return variants


def validate_planned_runs() -> None:
    """Refuse stale or ambiguous exclusions, including rows no checker visits."""
    for run, row in PLANNED_RUNS.items():
        if not isinstance(row, tuple) or len(row) != 4:
            fail(f"{run}: malformed planning registration")
        identity, checker, closure, artifacts = row
        if not isinstance(identity, str) or not work_items.UUID.fullmatch(identity):
            fail(f"{run}: planning identity is not a canonical UUID")
        # The shared reader is deliberately shallow. An exclusion additionally
        # needs identity and state in the item's envelope, never its body.
        try:
            item_text = (work_items.ITEMS / f"{identity}.md").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail(f"{run}: cannot read planning item envelope: {error}")
        opening, separator, remainder = item_text.partition("---\n")
        frontmatter, closing, _body = remainder.partition("\n---\n")
        if opening or not separator or not closing:
            fail(f"{run}: planning item lacks a delimited frontmatter envelope")
        fields = {
            key: re.findall(rf"^{key}:[ \t]*(.*)$", frontmatter, re.MULTILINE)
            for key in ("schema", "id", "state")
        }
        if (any(len(values) != 1 for values in fields.values())
                or fields["schema"][0] not in {"work-item/v1", "work-item/v2"}
                or fields["id"][0] != identity
                or fields["state"][0] not in {"open", "active", "blocked", "deferred"}):
            fail(f"{run}: planning item envelope has invalid identity, schema or state")
        matches = [item for item in work_items.items() if item["id"] == identity]
        if (identity not in work_items.identities() or len(matches) != 1
                or matches[0]["state"] not in {"open", "active", "blocked", "deferred"}
                or matches[0]["retired"]):
            fail(f"{run}: planning identity must name one nonterminal work item")
        if (not isinstance(checker, str) or _Path(checker).name != checker
                or checker in NOT_A_PLANE
                or not checker.startswith("check-sel4-") or not checker.endswith(".py")
                or not (CHECK_ROOT / checker).is_file()):
            fail(f"{run}: planning checker is absent or conflicts with inventory")
        variants = declared_variants(CHECK_ROOT / checker)
        if sum(name == run and expected == closure for name, expected, _, _ in variants) != 1:
            fail(f"{run}: planning registration names no matching invocation/closure")
        if not isinstance(artifacts, tuple) or not artifacts:
            fail(f"{run}: planning registration requires implementation artifacts")
        for artifact in artifacts:
            if (not isinstance(artifact, str) or not artifact
                    or _Path(artifact).is_absolute() or ".." in _Path(artifact).parts
                    or not (ROOT / artifact).resolve().is_relative_to(ROOT.resolve())):
                fail(f"{run}: artifact must be a nonescaping root-relative path")
            if (ROOT / artifact).exists() or (ROOT / artifact).is_symlink():
                fail(f"{run}: stale planning registration: artifact {artifact} is present")
        mandatory = {
            str((CLOSURE_ROOT / f"{closure}.zti").relative_to(ROOT)),
            str((RUN_ROOT / f"{run}.zti").relative_to(ROOT)),
        }
        if not mandatory <= set(artifacts):
            fail(f"{run}: planning artifacts must include closure and run declaration")


def run_variants(path: _Path) -> list[tuple[str, str, str, str]]:
    """Every active invocation; absent closures need an independent exemption."""
    validate_planned_runs()
    variants = []
    for name, closure, profile, image in declared_variants(path):
        if name in PLANNED_RUNS:
            if PLANNED_RUNS[name][1] != path.name:
                fail(f"{name}: planning registration conflicts with another checker")
            continue
        if closure and not (CLOSURE_ROOT / f"{closure}.zti").is_file():
            # Only legacy default arms may resolve to a literal image. The
            # aggregate owns the exemption, not a missing closure or item state.
            if name != run_name(path):
                fail(f"{name}: missing active closure {closure}")
            image = booted_image(path)
            aggregate = CHECK_ROOT / "check-system-image-aggregate.py"
            text = aggregate.read_text(encoding="utf-8") if aggregate.is_file() else ""
            block = re.search(r"IMAGES_WITHOUT_CLOSURE = \{(.*?)\n\}", text, re.DOTALL)
            exempt = set(re.findall(r'"(slime-[a-z0-9.-]+\.elf)":', block.group(1))) if block else set()
            if image not in exempt:
                fail(f"{name}: missing active closure {closure} without a literal-image exemption")
        variants.append((name, closure, profile, image))
    return variants


def booted_image(path: _Path) -> str:
    """The `build/slime-*.elf` this checker boots.

    Derived from the checker rather than from the run name, because the two
    differ: `check-sel4-component-graph.py` boots `slime-sel4-graph.elf`. Using
    the name would attribute a plane to the wrong image, which is exactly the
    mapping error the aggregate gate exists to catch.
    """
    text = path.read_text(encoding="utf-8")
    found = sorted(
        set(re.findall(r'"build"\s*/\s*"(slime-[a-z0-9.-]+\.elf)"', text))
        | set(re.findall(r"build/(slime-[a-z0-9.-]+\.elf)", text))
    )
    if not found:
        fail(f"{path.name}: boots no build/slime-*.elf image")
    # A checker touching several images (a plane plus a control arm) is keyed by
    # the one its own name implies, falling back to the single image it names.
    stem = run_name(path)
    preferred = f"slime-{stem}.elf"
    if preferred in found:
        return preferred
    return found[0]


def closure_name_for(path: _Path, name: str) -> str:
    """The closure this checker's own source declares, or its run name.

    Most checkers' closure matches their run name (`sel4-channel` builds the
    `sel4-channel` closure). A checker whose plane image predates the closure
    naming convention — `check-sel4-component-graph.py` and
    `check-sel4-device-plane.py` both build the `sel4` closure — declares a
    `CLOSURE = "..."` constant that names it explicitly; reading that instead
    of guessing from the run name is what keeps this generic rather than a
    second hand-maintained mapping beside the aggregate gate's.
    """
    match = re.search(r'^CLOSURE = "([a-z0-9-]+)"', path.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match is not None else name


def closure_reference_for(name: str) -> str:
    """The name of the closure this run exercises, or the empty string when none exists.

    An empty name is a truthful statement that the plane's image is not yet
    closure-reachable rather than a fabricated reference. `check-system-test-run.py`
    requires a non-empty name to be the closure the run's plane builds and an empty
    one to name an image the aggregate gate agrees is exempt.
    """
    return name if (CLOSURE_ROOT / f"{name}.zti").is_file() else ""


DEVICE_NAME = re.compile(r"virtio-[a-z]+-device")

# The flags a site may pass. A site is a function that builds the QEMU arguments after the base command, and
# the real checker passes only these three. Any other flag is refused, so a disk or a serial port cannot be
# added without a person extending this list.
SITE_FLAGS = ("-netdev", "-device", "-object")
# The first element of a tuple that holds QEMU arguments. A function that passes a tuple starting like this
# but is not a site is refused.
QEMU_FLAGS = ("-netdev", "-device", "-drive", "-object", "-usb", "-serial", "-display", "-chardev", "-global")


def literal_text(node: ast.AST) -> str | None:
    """The text of a string literal, or of an f-string whose pieces are all literal text, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def leading_text(node: ast.AST) -> str | None:
    """The literal text a string value starts with: a literal, or the first piece of an f-string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def qemu_tokens(node: ast.AST) -> set[str]:
    """Every QEMU token written anywhere under `node`, as the strings they hold.

    A token is a string that equals a QEMU flag, a string that starts with a `virtio-<kind>-device` name, the
    string `usb-kbd`, or the name `additional_arguments` as a variable or a keyword. The strings come from the
    syntax tree, so the quote style does not matter. The whole tree is read, including nested definitions.
    """
    found: set[str] = set()
    for inner in ast.walk(node):
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            value = inner.value
            if value in QEMU_FLAGS or value == "usb-kbd" or DEVICE_NAME.match(value):
                found.add(value[:40])
        elif isinstance(inner, ast.JoinedStr):
            first = leading_text(inner)
            if first and DEVICE_NAME.match(first):
                found.add(first[:40])
        elif isinstance(inner, ast.Name) and inner.id == "additional_arguments":
            found.add("additional_arguments")
        elif isinstance(inner, ast.keyword) and inner.arg == "additional_arguments":
            found.add("additional_arguments")
    return found


# The module that defines the launcher. It is imported only for `run_plane`, by name and without an alias.
LAUNCHER_MODULE = "sel4_plane"


def check_launcher_uses(path: _Path, body: list[ast.stmt]) -> None:
    """`run_plane` is the only launcher, and every use of its name is a direct call that hides no keyword.

    `run_plane` appends `additional_arguments` to the QEMU command. A direct call that names its keywords shows
    what it passes. A call that spreads a mapping or a sequence, a use of the name that is not a call, an
    attribute named `run_plane`, and a string equal to the launcher or to the keyword could pass arguments that
    the reading of a site does not see, so each is refused anywhere in the checker.
    """
    tree = ast.Module(body=body, type_ignores=[])
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "run_plane" and alias.asname not in (None, "run_plane"):
                    fail(f"{path.name}: run_plane is imported as {alias.asname!r} at line {node.lineno}, so a call through that name could not be read")
                if alias.name == "run_plane" and (node.module != LAUNCHER_MODULE or node.level != 0):
                    fail(f"{path.name}: run_plane is imported at line {node.lineno} from {'.' * node.level}{node.module or ''}, not from {LAUNCHER_MODULE}")
                if alias.name == "*":
                    fail(f"{path.name}: a star import at line {node.lineno} could bind the launcher under a name that was not read")
            if node.module == LAUNCHER_MODULE and any(alias.name != "run_plane" for alias in node.names):
                fail(f"{path.name}: line {node.lineno} imports something other than run_plane from {LAUNCHER_MODULE}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == LAUNCHER_MODULE:
                    fail(f"{path.name}: {LAUNCHER_MODULE} is imported as a module at line {node.lineno}, which would reach run_plane as an attribute")
        if isinstance(node, ast.Name) and node.id == "run_plane":
            parent = parents.get(node)
            if not (isinstance(parent, ast.Call) and parent.func is node):
                fail(f"{path.name}: run_plane is used at line {node.lineno} other than as a direct call, so what it passes cannot be read")
        elif isinstance(node, ast.Attribute) and node.attr == "run_plane":
            fail(f"{path.name}: run_plane is reached as an attribute at line {node.lineno}, so what it passes cannot be read")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "run_plane":
            if any(keyword.arg is None for keyword in node.keywords) or any(isinstance(argument, ast.Starred) for argument in node.args):
                fail(f"{path.name}: the run_plane call at line {node.lineno} spreads a mapping or a sequence, so what it passes cannot be read")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in ("run_plane", "additional_arguments"):
            fail(f"{path.name}: the string {node.value!r} at line {node.lineno} could name the launcher or its keyword at run time")


def site_arguments(path: _Path, name: str, function: ast.FunctionDef) -> list[str]:
    """The devices a site passes, in order, with one entry for each `-device` argument.

    The arguments of a site are the elements of the tuple or list literals that the keyword `additional_arguments`
    receives from a call to `run_plane`. Another call that carries the keyword is refused, because only
    `run_plane` adds the arguments to QEMU. A literal must hold flag and value pairs. Each flag is a string
    literal from `SITE_FLAGS`, so a computed flag, a variable flag, an odd count and a starred element are refused.
    A `-device` value must be a string literal or an f-string that starts with a `virtio-<kind>-device` name, and
    that name is the device. A `-netdev` or `-object` value must be a name, a string literal or an f-string. A
    definition nested in the function may hold no QEMU token, and no QEMU token may sit outside those literals.
    """
    where = f"{path.name}: {name}"
    for inner in ast.walk(function):
        if inner is not function and isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            held = qemu_tokens(inner)
            if held:
                fail(f"{where} holds QEMU token(s) {sorted(held)} in a nested {type(inner).__name__.lower()}, so its arguments cannot be read where they are written")
    carriers: list[ast.expr] = []
    for call in ast.walk(function):
        if not isinstance(call, ast.Call):
            continue
        launches = isinstance(call.func, ast.Name) and call.func.id == "run_plane"
        given = [keyword.value for keyword in call.keywords if keyword.arg == "additional_arguments"]
        if given and not launches:
            fail(f"{where} passes additional_arguments to a call that is not run_plane, which is the only call that adds them to QEMU")
        if launches:
            if len(given) != 1:
                fail(f"{where} calls run_plane at line {call.lineno} without additional_arguments, so that launch path attaches no declared device")
            carriers.append(given[0])
    if not carriers:
        fail(f"{where} is declared as a site but passes no additional_arguments to run_plane")
    devices: list[str] = []
    inside: set[int] = set()
    per_launch: list[list[str]] = []
    for carrier in carriers:
        if not isinstance(carrier, (ast.Tuple, ast.List)):
            fail(f"{where} passes additional_arguments that is not a tuple or list literal, so its arguments cannot be read")
        inside.update(id(node) for node in ast.walk(carrier))
        launch_devices: list[str] = []
        per_launch.append(launch_devices)
        elements = carrier.elts
        if len(elements) % 2:
            fail(f"{where} passes an odd number of additional_arguments elements, so they are not flag and value pairs")
        for flag_node, value_node in zip(elements[0::2], elements[1::2], strict=True):
            if isinstance(flag_node, ast.Starred) or isinstance(value_node, ast.Starred):
                fail(f"{where} passes a starred element in additional_arguments, so its arguments cannot be read")
            flag = literal_text(flag_node)
            if flag is None:
                fail(f"{where} passes a flag in additional_arguments that is not a string literal, so what it names cannot be read")
            if flag not in SITE_FLAGS:
                fail(f"{where} passes the flag {flag!r}, which this generator does not record")
            if flag == "-device":
                value = leading_text(value_node)
                found = DEVICE_NAME.match(value) if value else None
                if found is None:
                    fail(f"{where} passes a -device whose value is not a literal that starts with a virtio-<kind>-device name")
                launch_devices.append(found.group(0))
            else:
                if not isinstance(value_node, (ast.Name, ast.Constant, ast.JoinedStr)) or (
                    isinstance(value_node, ast.Constant) and not isinstance(value_node.value, str)
                ):
                    fail(f"{where} passes a {flag} value that is not a name, a string literal or an f-string")
                text = leading_text(value_node)
                if text is not None and text.startswith("-"):
                    fail(f"{where} passes a {flag} value that looks like a flag")
    # Every launch path must attach the same devices. A site is declared once, so a path that attaches fewer
    # devices than another would make the record claim a device that the path does not attach.
    if any(sorted(launch) != sorted(per_launch[0]) for launch in per_launch):
        fail(f"{where} has launch paths that attach different devices, {[sorted(launch) for launch in per_launch]}")
    devices = per_launch[0]
    # Every QEMU token in the function must sit inside one of those literals. A token anywhere else is a
    # second route to QEMU that the reading did not cover.
    for inner in ast.walk(function):
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            value = inner.value
            if (value in QEMU_FLAGS or value == "usb-kbd" or DEVICE_NAME.match(value)) and id(inner) not in inside:
                fail(f"{where} holds the QEMU token {value[:40]!r} outside additional_arguments")
        elif isinstance(inner, ast.Name) and inner.id == "additional_arguments":
            fail(f"{where} uses additional_arguments as a name, so its arguments cannot be read")
    return devices


def device_facts(nodes: Iterable[ast.AST]) -> tuple[int, list[str]]:
    """The number of `-drive` strings and the sorted device names among `nodes`, for a checker with no tables."""
    drives = 0
    devices: set[str] = set()
    for inner in nodes:
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            if inner.value == "-drive":
                drives += 1
            elif inner.value == "usb-kbd":
                devices.add("usb-kbd")
            else:
                found = DEVICE_NAME.match(inner.value)
                if found:
                    devices.add(found.group(0))
    return drives, sorted(devices)


def top_level_units(body: list[ast.stmt]) -> dict[str, list[ast.stmt]]:
    """Each name that a top-level statement binds, with the statements that bind it.

    A unit is a function, a class or an assignment. Reaching a name reaches every statement that binds it.
    """
    units: dict[str, list[ast.stmt]] = {}
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            units.setdefault(node.name, []).append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for inner in ast.walk(target):
                    if isinstance(inner, ast.Name):
                        units.setdefault(inner.id, []).append(node)
    return units


def reachable_units(units: dict[str, list[ast.stmt]], entries: tuple[str, ...]) -> set[str]:
    """`entries` and every top-level name that they read, directly or through another, in any scope.

    Every name counts, whether it is called, passed, aliased or read in a nested definition or in one branch
    of a conditional. The reach can therefore name more units than the arm runs. It cannot miss one that a
    name reaches.
    """
    seen: set[str] = set()
    pending = list(entries)
    while pending:
        name = pending.pop()
        if name in seen or name not in units:
            continue
        seen.add(name)
        for node in units[name]:
            for inner in ast.walk(node):
                if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load) and inner.id in units:
                    pending.append(inner.id)
    return seen


def arm_branches(path: _Path, main: ast.FunctionDef) -> list[tuple[ast.If, frozenset[str], bool]]:
    """Each `if` in `main` whose test compares the `--arm` choice, with the choices it names and whether it is exact.

    The choice is read as `arguments.arm`. Every use of it must be one comparison against string literals, with
    `==`, `!=`, `in` or `not in`, and that comparison must sit in the test of an `if`, alone or in an `and` chain.
    A comparison anywhere else, such as an assignment, a loop test, a conditional expression, a `match`, a call or
    an alias of `arguments`, is refused, because the branch it guards could not be found.

    A branch is exact when its test is such a comparison, or an `and` of them, and all of them are positive. Then
    the branch runs only for the choices it names. A branch with a `!=`, a `not in`, an `or` or a `not` can run for
    other choices, so it is not exact, and the checks treat it as running for every arm.
    """
    holder, attribute = ARM_SELECTOR
    parents = {child: parent for parent in ast.walk(main) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(main):
        if isinstance(node, ast.Name) and node.id == holder and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            if not (isinstance(parent, ast.Attribute) and parent.value is node):
                fail(f"{path.name}: main() uses {holder} other than by attribute at line {node.lineno}, so the --arm branches cannot be found")
    entries: dict[int, tuple[ast.If, set[str], bool]] = {}
    for node in ast.walk(main):
        if not (isinstance(node, ast.Attribute) and node.attr == attribute and isinstance(node.value, ast.Name) and node.value.id == holder):
            continue
        where = f"{path.name}: {holder}.{attribute} at line {node.lineno}"
        compare = parents.get(node)
        if not isinstance(compare, ast.Compare) or len(compare.ops) != 1:
            fail(f"{where} is not one comparison, so the branch it guards cannot be found")
        operator = compare.ops[0]
        if not isinstance(operator, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)):
            fail(f"{where} is compared with an operator other than ==, !=, in or not in")
        if compare.left is node:
            other = compare.comparators[0]
        elif compare.comparators[0] is node and isinstance(operator, (ast.Eq, ast.NotEq)):
            other = compare.left
        else:
            fail(f"{where} is on the wrong side of its comparison")
        if isinstance(other, ast.Constant) and isinstance(other.value, str):
            names = {other.value}
        elif (
            isinstance(other, (ast.Tuple, ast.Set, ast.List))
            and other.elts
            and all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in other.elts)
        ):
            names = {item.value for item in other.elts}
        else:
            fail(f"{where} is compared with something other than string literals, so the choices it names cannot be read")
        exact = not isinstance(operator, (ast.NotEq, ast.NotIn))
        child, ancestor = compare, parents.get(compare)
        while not (isinstance(ancestor, ast.If) and ancestor.test is child):
            if isinstance(ancestor, ast.BoolOp):
                exact = exact and isinstance(ancestor.op, ast.And)
            elif isinstance(ancestor, ast.UnaryOp) and isinstance(ancestor.op, ast.Not):
                exact = False
            else:
                fail(f"{where} is not in the test of an if, so the branch it guards cannot be found")
            child, ancestor = ancestor, parents.get(ancestor)
        known = entries.setdefault(id(ancestor), (ancestor, set(), True))
        if exact:
            known[1].update(names)
        entries[id(ancestor)] = (ancestor, known[1], known[2] and exact)
    return [(branch, frozenset(names), exact) for branch, names, exact in entries.values()]


# Names whose use lets code reach a binding without writing its name, or rebind one. The checker uses none of
# them, so each is refused anywhere in it, and no lookup can send a call to a function that the reading missed.
BANNED_NAMES = frozenset(
    {"globals", "locals", "vars", "exec", "eval", "compile", "setattr", "getattr", "delattr", "__import__", "__builtins__", "importlib", "breakpoint"}
)


def imported_modules(tree: ast.Module) -> set[str]:
    """The names that `import` statements bind anywhere in the tree."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.asname or alias.name.split(".")[0] for alias in node.names}
    return names


def build_image_calls(path: _Path, tree: ast.Module) -> tuple[dict[int, str], set[str]]:
    """Each direct call to `build_image`, by the id of its node, with the closure it names, and the value names.

    The value names are the module-level constants and the imported modules that supply a closure. A caller must
    keep each of them bound once, because a local of the same name would change what the call builds.

    `build_image` must be called by name with the closure as its one positional argument. A call with a keyword, a
    starred argument or no argument, and any other use of the name, such as an alias, a default argument or a
    value passed on, is refused, so a closure cannot be built without being counted. The closure is a string
    literal, a module-level string constant, or `module.CLOSURE` of an imported module.
    """
    imports = imported_modules(tree)

    def library_closure(module: str) -> str:
        source = ROOT / "scripts" / "lib" / f"{module}.py"
        found = re.search(r'^CLOSURE = "([a-z0-9-]+)"', source.read_text(encoding="utf-8"), re.MULTILINE) if source.is_file() else None
        if found is None:
            fail(f"{path.name}: {module}.py declares no CLOSURE constant")
        return found.group(1)

    constants: dict[str, str] = {}
    used: set[str] = set()

    def resolve(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in constants:
            used.add(node.id)
            used.update(via_module.get(node.id, ()))
            return constants[node.id]
        if isinstance(node, ast.Attribute) and node.attr == "CLOSURE" and isinstance(node.value, ast.Name) and node.value.id in imports:
            used.add(node.value.id)
            return library_closure(node.value.id)
        fail(f"{path.name}: cannot resolve the closure named by {ast.dump(node)[:80]}")

    via_module: dict[str, set[str]] = {}

    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constants[node.targets[0].id] = value.value
            elif isinstance(value, ast.Attribute) and value.attr == "CLOSURE" and isinstance(value.value, ast.Name) and value.value.id in imports:
                constants[node.targets[0].id] = library_closure(value.value.id)
                via_module[node.targets[0].id] = {value.value.id}
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    calls: dict[int, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Name) and node.id == "build_image" and isinstance(node.ctx, ast.Load)):
            continue
        call = parents.get(node)
        if not (isinstance(call, ast.Call) and call.func is node):
            fail(f"{path.name}: build_image is used at line {node.lineno} other than as a direct call")
        if len(call.args) != 1 or call.keywords or isinstance(call.args[0], ast.Starred):
            fail(f"{path.name}: build_image at line {node.lineno} is not called with exactly one positional closure")
        calls[id(call)] = resolve(call.args[0])
    return calls, used


def built_closures(path: _Path) -> set[str]:
    """Every closure that the checker builds, for the gate that compares them with the declared runs."""
    return set(build_image_calls(path, ast.parse(path.read_text(encoding="utf-8")))[0].values())


def check_name_bindings(path: _Path, tree: ast.Module, protected: set[str], values: set[str]) -> None:
    """No name that an arm reaches is rebound, and no builtin that looks a name up is used.

    The reach follows names, so a function that is rebound locally, passed in as a parameter, declared global,
    defined again or imported under the same name would send a call somewhere the reach did not look. Each
    protected function is therefore defined once, at the top level and without a decorator. `run_plane` is
    imported once, at the top level. Any other binding of a protected name, in any scope, is refused. So is a
    string equal to one, and a name or attribute that looks a binding up by text or replaces it.

    `values` are the module-level constants and the imported modules that supply a closure to `build_image`.
    Each is bound exactly once at the top level, by a plain assignment or a plain `import`, and nowhere else, so a
    local of the same name cannot change the closure a call builds. No attribute of an imported module is stored.
    An attribute named like a protected function and a call whose callee is neither a name nor an attribute are
    refused, so `build_image` cannot be reached through a module, a table or a subscript.
    """
    direct = {id(node) for node in tree.body}
    allowed_stores: set[int] = set()
    top_bindings: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in values:
            allowed_stores.add(id(node.targets[0]))
            top_bindings[node.targets[0].id] = top_bindings.get(node.targets[0].id, 0) + 1
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if bound in values:
                    top_bindings[bound] = top_bindings.get(bound, 0) + 1
    for name in sorted(values):
        if top_bindings.get(name) != 1:
            fail(f"{path.name}: {name} supplies a closure to build_image, so it must be bound exactly once at the top level, and it is bound {top_bindings.get(name, 0)} times")
    imported = imported_modules(tree)
    guarded = protected | values
    defined: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in protected:
            defined[node.name] = defined.get(node.name, 0) + 1
            if node.decorator_list:
                fail(f"{path.name}: {node.name} has a decorator at line {node.lineno}, so what it names cannot be read")
    for name in sorted(protected - {"run_plane"}):
        if defined.get(name) != 1:
            fail(f"{path.name}: {name} must be defined exactly once at the top level, and it is defined {defined.get(name, 0)} times")
    allowed_import = [
        node for node in tree.body if isinstance(node, ast.ImportFrom) and any((alias.asname or alias.name) == "run_plane" for alias in node.names)
    ]
    if len(allowed_import) != 1:
        fail(f"{path.name}: run_plane must be imported exactly once at the top level")
    strings = protected - {"main"}
    for node in ast.walk(tree):
        where = f"{path.name}: line {getattr(node, 'lineno', 0)}"
        if isinstance(node, ast.Name):
            if node.id in BANNED_NAMES:
                fail(f"{where} uses {node.id}, which looks a binding up by text or replaces it")
            if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in guarded and id(node) not in allowed_stores:
                fail(f"{where} rebinds {node.id}, which an arm reaches")
        elif isinstance(node, ast.arg) and node.arg in guarded:
            fail(f"{where} names a parameter {node.arg}, which hides the {node.arg} that an arm reaches")
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and set(node.names) & guarded:
            fail(f"{where} declares {sorted(set(node.names) & guarded)} global or nonlocal")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in protected and id(node) not in direct:
            fail(f"{where} defines {node.name} again inside another scope")
        elif isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef)) and node.name in protected:
            fail(f"{where} defines {node.name} as something other than a function")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            bound = {(alias.asname or alias.name.split(".")[0]) if isinstance(node, ast.Import) else (alias.asname or alias.name) for alias in node.names}
            if bound & protected and node not in allowed_import:
                fail(f"{where} imports {sorted(bound & protected)}, which an arm reaches")
            if bound & values and id(node) not in direct:
                fail(f"{where} imports {sorted(bound & values)} again below the top level")
        elif isinstance(node, ast.Call) and not isinstance(node.func, (ast.Name, ast.Attribute)):
            fail(f"{where} calls something that is neither a name nor an attribute, so what it calls cannot be read")
        elif isinstance(node, ast.ExceptHandler) and node.name in protected:
            fail(f"{where} binds {node.name} in an except clause")
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in protected:
            fail(f"{where} binds {node.name} in a match pattern")
        elif isinstance(node, ast.MatchMapping) and node.rest in protected:
            fail(f"{where} binds {node.rest} in a match pattern")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
            fail(f"{where} uses the attribute {node.attr}, which reaches a binding without writing its name")
        elif isinstance(node, ast.Attribute) and node.attr in protected:
            fail(f"{where} reaches {node.attr} as an attribute, which hides the call from the reading of the reach")
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name) and node.value.id in imported:
            fail(f"{where} stores an attribute of the imported module {node.value.id}, which could change a closure")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in strings:
            fail(f"{where} holds the string {node.value!r}, which could look up a function that an arm reaches")


def names_read(statements: Iterable[ast.AST], singles: Iterable[ast.AST] = ()) -> set[str]:
    """The names read in `statements`, each walked in full, and in `singles`, each taken as it is."""
    names = {inner.id for statement in statements for inner in ast.walk(statement) if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load)}
    return names | {node.id for node in singles if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}


def main_statements(path: _Path, main: ast.FunctionDef) -> tuple[dict[str, list[ast.stmt]], list[ast.stmt], list[ast.AST], set[str]]:
    """What `main` runs for each `--arm` choice, for every arm, and the choices that have an exact branch.

    The first value maps a choice to the statements of the exact branches that name it. The second holds the
    statements that run for every arm: the body of a branch that is not exact, and the `else` of any branch. The
    third holds the nodes of `main` outside every branch, which run for every arm. These are single nodes and
    are not walked into, because a branch node among them would pull in its body. The fourth is the set of
    choices that an exact branch names.
    """
    by_choice: dict[str, list[ast.stmt]] = {}
    every: list[ast.stmt] = []
    exact_choices: set[str] = set()
    covered: set[int] = set()
    for branch, names, exact in arm_branches(path, main):
        for statement in (*branch.body, *branch.orelse):
            covered.update(id(inner) for inner in ast.walk(statement))
        if exact:
            exact_choices |= names
            for name in names:
                by_choice.setdefault(name, []).extend(branch.body)
        else:
            every.extend(branch.body)
        every.extend(branch.orelse)
    outside = [node for node in ast.walk(main) if node is not main and id(node) not in covered]
    return by_choice, every, outside, exact_choices


def check_qemu_sites(path: _Path, body: list[ast.stmt], sites: dict[str, tuple[str, ...]]) -> None:
    """Every QEMU token sits in a declared site, and each site passes exactly the devices it declares."""
    functions = {node.name: node for node in body if isinstance(node, ast.FunctionDef)}
    check_launcher_uses(path, body)
    for name, declared in sites.items():
        if name not in functions:
            fail(f"{path.name}: QEMU_SITES names {name}, which the checker does not define")
        read = site_arguments(path, name, functions[name])
        if sorted(read) != sorted(declared):
            fail(f"{path.name}: {name} declares devices {sorted(declared)}, but its additional_arguments pass {sorted(read)}")
    for node in body:
        if isinstance(node, ast.FunctionDef) and node.name in sites:
            continue
        tokens = qemu_tokens(node)
        if tokens:
            where = f"function {node.name}" if isinstance(node, ast.FunctionDef) else f"the statement at line {node.lineno}"
            fail(f"{path.name}: {where} is not in QEMU_SITES and holds QEMU token(s) {sorted(tokens)}")


def arm_source(path: _Path, run: str, text: str) -> tuple[str, int, list[str]]:
    """The source an arm's faults are read from, and the drives and devices the arm attaches.

    A checker with no tables is read whole. For a checker with them, the devices are the arm's entry in
    `ARM_DEVICES`, after the code is checked against the tables.

    An arm reaches the units that its entry functions read, the units that the exact branches of `main` naming
    its `--arm` choice read, and the units that every arm reads: the branches that are not exact, every `else`,
    and the statements of `main` outside the branches. The devices of the sites it reaches must equal its
    declaration, counted with repeats. The closures built in what it reaches must be exactly its own closure, so
    two call sites that swap their closures are refused. No unit an arm reaches may be rebound.
    """
    arms = ARM_ENTRY_FUNCTIONS.get(path.name)
    if arms is None:
        return (text, *device_facts(ast.walk(ast.parse(text))))
    if run not in arms:
        fail(f"{path.name}: {run} has no entry in ARM_ENTRY_FUNCTIONS")
    declared_by_arm = ARM_DEVICES.get(path.name, {})
    if set(declared_by_arm) != set(arms):
        fail(f"{path.name}: ARM_DEVICES and ARM_ENTRY_FUNCTIONS disagree on the arms {sorted(set(declared_by_arm) ^ set(arms))}")
    sites = QEMU_SITES.get(path.name, {})
    tree = ast.parse(text)
    body = tree.body
    functions = {node.name: node for node in body if isinstance(node, ast.FunctionDef)}
    missing = [name for name in arms[run] if name not in functions]
    if missing:
        fail(f"{path.name}: {run} names entry function(s) {missing} that the checker does not define")
    check_qemu_sites(path, body, sites)
    main = functions.get("main")
    if main is None:
        fail(f"{path.name}: the checker defines no main(), so its --arm branches cannot be read")
    choices = ARM_CHOICES.get(path.name, {})
    absent = sorted(name for name in arms if name not in choices)
    if absent:
        fail(f"{path.name}: the arm(s) {absent} have no entry in ARM_CHOICES, so their branch of main() cannot be found")
    by_choice, every, outside, exact_choices = main_statements(path, main)
    unbranched = sorted(name for name in arms if choices[name] not in exact_choices)
    if unbranched:
        fail(f"{path.name}: main() has no branch for the arm(s) {unbranched}")
    units = top_level_units(body)
    build_calls, value_names = build_image_calls(path, tree)

    def reach(name: str) -> tuple[set[str], list[ast.AST]]:
        statements = [*by_choice.get(choices[name], []), *every]
        read_by_main = names_read(statements, outside)
        unread = [entry for entry in arms[name] if entry not in read_by_main]
        if unread:
            fail(f"{path.name}: {name} declares the entry function(s) {unread}, but the branch of main() for {choices[name]!r} never reads them")
        reached = reachable_units(units, (*arms[name], *sorted(read_by_main)))
        nodes: list[ast.AST] = [inner for unit in reached for statement in units[unit] for inner in ast.walk(statement)]
        nodes += [inner for statement in statements for inner in ast.walk(statement)]
        return reached, [*nodes, *outside]

    reaches = {name: reach(name) for name in arms}
    protected = {"main", "build_image", "run_plane", *sites, *(entry for entries in arms.values() for entry in entries)}
    protected |= {unit for reached, _nodes in reaches.values() for unit in reached if unit in functions}
    check_name_bindings(path, tree, protected, value_names)
    reached, nodes = reaches[run]
    attached = sorted(device for name in reached if name in sites for device in sites[name])
    declared = sorted(declared_by_arm[run])
    if attached != declared:
        fail(f"{path.name}: {run} declares devices {declared}, but the sites it can reach, {sorted(reached & set(sites))}, attach {attached}")
    own = next((closure for name, closure, _profile, _image in declared_variants(path) if name == run), "")
    built = {build_calls[id(node)] for node in nodes if id(node) in build_calls}
    if built != {own}:
        fail(f"{path.name}: {run} is declared to boot {own!r}, but the code it reaches builds {sorted(built)}")
    lines = text.splitlines()
    pieces = ["\n".join(lines[node.lineno - 1 : node.end_lineno]) for name in sorted(reached) for node in units[name]]
    # The statements of main() that run for this arm are part of what it runs, so the fault patterns read them
    # too: the exact branches for its choice, every branch that is not exact, every else, and the statements
    # outside the branches.
    selected = [*by_choice.get(choices[run], []), *every]
    pieces += ["\n".join(lines[node.lineno - 1 : node.end_lineno]) for node in selected]
    inside_branches = {
        number
        for branch, _names, _exact in arm_branches(path, main)
        for statement in (*branch.body, *branch.orelse)
        for number in range(statement.lineno, statement.end_lineno + 1)
    }
    pieces += [lines[number - 1] for number in range(main.lineno, main.end_lineno + 1) if number not in inside_branches]
    return "\n".join(pieces), 0, declared


def extract(path: _Path, run: str | None = None) -> dict:
    """Read one invocation's execution-only inputs from its checker constants."""
    run = run_name(path) if run is None else run
    if run not in {name for name, _, _, _ in declared_variants(path)}:
        fail(f"{path.name}: unsupported extraction invocation {run}")
    text = path.read_text(encoding="utf-8")
    if path.name == "check-sel4-reclamation-plane.py":
        # Both arms share boot transport, but not timeout or transcript policy.
        # Host fixture/refusal controls are not QEMU execution declarations.
        selected = ({"TIMEOUT", "boot", "run_unwind_arm"}
                    if run == "sel4-reclamation" else
                    {"LARGE_TIMEOUT", "LARGE_FAILURES", "boot", "judge_large_image"})
        segments = {}
        for node in ast.parse(text).body:
            if isinstance(node, ast.FunctionDef):
                names = {node.name}
            else:
                targets = ([node.target] if isinstance(node, ast.AnnAssign)
                           else node.targets if isinstance(node, ast.Assign) else [])
                names = {target.id for target in targets if isinstance(target, ast.Name)}
            for name in names & selected:
                if name in segments:
                    fail(f"{path.name}: duplicate execution declaration {name}")
                segments[name] = ast.get_source_segment(text, node)
        if set(segments) != selected:
            fail(f"{path.name}: missing execution declarations for {run}")
        text = "\n".join(segments.values())
        if run == "sel4-large-image":
            text = text.replace("LARGE_TIMEOUT =", "TIMEOUT =")
    if path.name == "check-sel4-private-memory-plane.py":
        # The frozen variants above are fixed-capacity arms. This transport
        # belongs only to the separately selected adaptive/matrix arms.
        lines = text.splitlines(keepends=True)
        declarations = []
        for node in ast.parse(text).body:
            targets = ([node.target] if isinstance(node, ast.AnnAssign)
                       else node.targets if isinstance(node, ast.Assign) else [])
            if any(isinstance(target, ast.Name) and target.id == "ADAPTIVE_DEVICE_ARGUMENTS"
                   for target in targets):
                declarations.append(node)
        if len(declarations) != 1:
            fail(f"{path.name}: expected one top-level adaptive-only transport declaration")
        node = declarations[0]
        lines[node.lineno - 1:node.end_lineno] = ["\n"] * (
            node.end_lineno - node.lineno + 1
        )
        text = "".join(lines)

    timeouts = re.findall(
        r"^(?:BOOT_TIMEOUT_SECONDS|TIMEOUT|BOOT_TIMEOUT|SESSION_TIMEOUT_SECONDS)\s*=\s*(\d+)",
        text,
        re.MULTILINE,
    )
    # Some planes state their bound as an argument default rather than a module
    # constant. That is the same declaration — the value a plain `just` run
    # executes with — so it counts.
    timeouts += re.findall(r'"--timeout",\s*type=int,\s*default=(\d+)', text)
    if not timeouts:
        fail(f"{path.name}: declares no boot timeout, so its run would be unbounded")
    # The largest declared bound: a plane with a session or recovery timeout
    # beyond its boot timeout may legitimately run that long.
    timeout = max(int(value) for value in timeouts)

    # One `-drive` argument is one attached disk. Counting distinct occurrences
    # rather than parsing QEMU argv keeps this honest about what the checker
    # actually attaches; a checker that attaches two disks in two code paths
    # declares two.
    scoped, drive_sites, devices = arm_source(path, run, text)

    # A forbidden outcome is written either as a bare literal or as a regex with
    # a trailing matcher (`r"SLIME_ROOT FATAL .*"`). Matching only the literal
    # form silently reported "forbids nothing" for every plane using the regex
    # form, which is the more common one.
    forbidden = sorted(
        {
            marker
            for marker in re.findall(
                r'r?"(SLIME_ROOT FATAL|SLIME_GRAPH FAIL|SLIME_ROOT PANIC)(?: \.\*)?"', text
            )
        }
    )

    # Runtime fault injection, by the specific mechanism each kind uses. These
    # are deliberately narrow: a generic `inject` would match ordinary helper
    # names and declare a fault the plane does not exercise, and an over-broad
    # declaration is worse than none because it is what a reader trusts.
    faults = []
    for kind, pattern in (
        # The checker rewrites persisted bytes before or between boots.
        ("corruption", r"\bcorrupt(?:ed|ion|_[a-z]+)?\b|CORRUPT"),
        # A participant is compiled or driven to die mid-exchange.
        ("peer-death", r"EARLY_EXIT|peer[_ -]death|PEER_DEATH"),
        # A device is made to fail or to report a fault, rather than merely
        # being attached.
        ("device", r"device[_ -]fault|DEVICE_FAULT|fault[_ -]inject"),
    ):
        if re.search(pattern, scoped):
            faults.append(kind)

    return {
        "timeoutSeconds": timeout,
        "drives": drive_sites,
        "devices": devices,
        "forbiddenOutcomes": forbidden,
        "faults": faults,
    }


def render(name: str, closure: str, profile: str, facts: dict) -> str:
    """Render one target-qualified record in canonical field order."""

    def text_list(values: list[str], indent: str = "    ") -> str:
        if not values:
            return "[]"
        rows = "".join(f'{indent}  "{value}";\n' for value in values)
        return "[\n" + rows + indent + "]"

    disks = ""
    if facts["drives"]:
        rows = []
        for index in range(facts["drives"]):
            rows.append(
                "    {\n"
                f'      name = "disk-{index}";\n'
                f'      path = "";\n'
                f'      identity = "";\n'
                "      writable = true;\n"
                "    };"
            )
        disks = "[\n" + "\n".join(rows) + "\n  ]"
    else:
        disks = "[]"

    devices = ""
    if facts["devices"]:
        rows = []
        for device in facts["devices"]:
            rows.append(
                "    {\n"
                f'      name = "{device}";\n'
                f'      path = "";\n'
                f'      identity = "";\n'
                "      writable = false;\n"
                "    };"
            )
        devices = "[\n" + "\n".join(rows) + "\n  ]"
    else:
        devices = "[]"

    faults = ""
    if facts["faults"]:
        rows = []
        for kind in facts["faults"]:
            rows.append(
                "    {\n"
                f'      kind = "{kind}";\n'
                f'      target = "";\n'
                f'      value = "";\n'
                "    };"
            )
        faults = "[\n" + "\n".join(rows) + "\n  ]"
    else:
        faults = "[]"

    return (
        "{\n"
        "  formatVersion = 2;\n"
        f'  name = "{name}";\n'
        f'  imageClosure = "{closure}";\n'
        '  executionKind = "emulator";\n'
        f'  executionProfile = "{profile}";\n'
        f"  disks = {disks};\n"
        "  networks = [];\n"
        f"  devices = {devices};\n"
        f"  faultControls = {faults};\n"
        f'  timeoutSeconds = {facts["timeoutSeconds"]};\n'
        f'  markerContractIdentity = "{MARKER_CONTRACT}";\n'
        f'  forbiddenOutcomes = {text_list(facts["forbiddenOutcomes"], "  ")};\n'
        "}\n"
    )


def outputs() -> dict[_Path, str]:
    emitted: dict[_Path, str] = {}
    for path in plane_checkers():
        for name, closure_name, profile, _image in run_variants(path):
            emitted[RUN_ROOT / f"{name}.zti"] = render(
                name,
                closure_reference_for(closure_name) if closure_name else "",
                profile,
                extract(path, name),
            )
    return emitted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check", action="store_true", help="refuse any record that drifted from its checker"
    )
    mode.add_argument(
        "--bless", action="store_true", help="re-freeze records after an intended change"
    )
    arguments = parser.parse_args()

    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    emitted = outputs()

    if arguments.check:
        stale = [
            path.name
            for path, content in emitted.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != content
        ]
        if stale:
            fail(
                f"record(s) disagreeing with their checker: {sorted(stale)}; "
                "re-freeze with `just system_test_run_bless` if the change is intended"
            )
        print(f"{len(emitted)} system test-run records are current")
        return 0

    for path, content in sorted(emitted.items()):
        path.write_text(content, encoding="utf-8")
        print(f"Blessed {path.relative_to(ROOT)}")
    print(f"{len(emitted)} system test-run records frozen")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
