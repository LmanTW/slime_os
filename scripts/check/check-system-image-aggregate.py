#!/usr/bin/env python3

"""CP15 aggregate inventory gate.

CP12 proved every composition is derived, CP13 that every derived composition
has a resolvable closure, CP14 that every remaining build-time distinction is
closure data. What none of them proves is the *correspondence*: that the images
this repository actually boots and the closures it declares are the same set,
each reachable from exactly one of the other.

Without that, both drifts are silent. A closure nobody exercises is an untested
build key that will rot; an image no closure describes is a build nobody can
reproduce. This gate closes both directions:

1. every plane image a checker boots is reachable from exactly one canonical
   closure, or is listed with a declared reason it is not;
2. every closure is exercised by at least one owning build or boot gate;
3. every plane build flag is owned by exactly one `just` target, so no image is
   produced by a path no gate runs;
4. the closure corpus, the scenario set, the root-role set, and the negative
   case set are pairwise disjoint — a name cannot be two kinds of thing;
5. every exemption in this file names a real image and a real reason, so the
   list cannot silently absorb a regression.

This is a source-and-contract gate, not a boot gate: it runs in seconds and
asserts the mapping. `just system_image_builder_check` and
`just system_image_scenario_check` own the expensive byte-level arms, and each
plane gate owns its own markers. The division is deliberate — this gate must be
cheap enough to run on every change, because a mapping that is only checked
before a release is a mapping that drifts between releases.
"""

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import copy
import importlib.util
import re

from harness import ROOT
from just_metadata import recipes, targets as just_targets
from sel4_boot import DEFAULT_PLATFORM, PLATFORMS
from system_image_closure import negative_case_paths
from system_spec import DERIVED_GENERATION_FIXTURES

CHECK_ROOT = ROOT / "scripts" / "check"
CLOSURE_ROOT = ROOT / "contracts" / "system-image-closure" / "v3" / "closures"
GENERATOR = ROOT / "scripts" / "generate" / "generate-system-image-closures.py"
SEL4_BUILDER = ROOT / "scripts" / "build" / "build-sel4.py"

# Images a checker boots that no closure describes, and why. Each is a build
# CP12–CP14 could not bring under a closure, and each reason names the specific
# blocker rather than "not yet".
#
# Keeping this explicit rather than pattern-matched is the point: an image that
# stops being reachable from a closure has to be added here by hand, which is a
# reviewed edit, instead of quietly matching a wildcard.
IMAGES_WITHOUT_CLOSURE = {
    # Root roles and platform images CP14 declared but whose host composition
    # still builds through the legacy path.
    "slime-sel4-boot-selection.elf": "the boot-selector root role is declared and gated but its host composition builds legacy",
    # Physical-board and non-QEMU platform images. These are not seL4 QEMU
    # planes and their platform assets are board-qualified rather than
    # closure-resolvable.
    "slime-sel4-bcm2712-rpi5.elf": "a physical Raspberry Pi 5 image, outside the QEMU closure corpus",
    "slime-sel4-graph-cv1800b-duo-test-terminator.elf": "a Milk-V Duo board image, outside the QEMU closure corpus",
    "slime-sel4-graph.elf": "check-sel4-component-graph.py's --no-build reads this fixed legacy path only for check-external-component-admission.py's mixed-source generation",
    "slime-sel4-generation-qemu-riscv-virt.elf": "the RV64 arm of the generation plane; its closure names qemu-arm-virt, so the RV64 build keeps its platform flag until CP15 migrates it",
    "slime-sel4-private-memory-qemu-riscv-virt.elf": "MEM-LARGE adds the RV64 execution arm before CP15 migrates its image build to closure identity",
    "slime-sel4-private-memory-cycles-qemu-riscv-virt.elf": "the RV64 arm of MEM-64M's reuse cycles; its closure names qemu-arm-virt, so the RV64 build keeps its platform flag until CP15 migrates it",
    "slime-sel4-rollback-qemu-riscv-virt.elf": "the RV64 arm of the rollback plane; its closure names qemu-arm-virt, so the RV64 build keeps its platform flag until CP15 migrates it",
    "slime-sel4-qemu-riscv-virt.elf": "the RV64 arm of the product root-boot aggregate; its closure names qemu-arm-virt, so the RV64 build keeps its platform flag until CP15 migrates it",
    # P6's pc99 arms. pc99's Multiboot2 media has no loader image, so both
    # stay on the legacy builder until closure packaging supports that route.
    "slime-sel4-qemu-pc99.elf": "the pc99 arm of the product root-boot aggregate; pc99's Multiboot2 media has no loader image, so it builds legacy until closure packaging supports that boot route",
    "slime-sel4-graph-qemu-pc99.elf": "the pc99 arm of the component-graph gate; the same legacy Multiboot2 route as slime-sel4-qemu-pc99.elf",
    "slime-sel4-sample-qemu-pc99.elf": "the pc99 arm of the sample plane; the same legacy Multiboot2 route as slime-sel4-qemu-pc99.elf",
    "slime-sel4-wait-set-qemu-pc99.elf": "the pc99 arm of the wait-set plane; the same legacy Multiboot2 route as slime-sel4-qemu-pc99.elf",
}


def fail(message: str) -> None:
    raise SystemExit(f"system image aggregate check: {message}")


def load_generator():
    spec = importlib.util.spec_from_file_location("aggregate_closure_generator", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR_MODULE = load_generator()


def booted_images() -> dict[str, set[str]]:
    """Every `build/slime-*.elf` a check script names, and which scripts do.

    A multi-platform plane composes its non-default image name rather than
    writing it out — `f"slime-sel4-rollback{suffix}.elf"` with `suffix` taken
    from the selected platform — so the literal scan alone would report that no
    checker boots it and reject its exemption. Those names are expanded here
    from the platform vocabulary the same checker declares, because an image a
    recipe really boots must be visible to this gate whether or not its name is
    spelled in one piece.

    A checker that resolves its image through `sel4_boot.artifact_paths` names
    only the stem — `artifact_paths("slime-sel4", platform)` — and the suffix
    is composed in the library, so neither scan above sees it. Its stem is
    expanded here with the default platform and with every other platform of
    `sel4_boot.PLATFORMS` the checker spells out, which is the vocabulary its
    `--platform` arms admit.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(CHECK_ROOT.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in (
            r'"build"\s*/\s*"(slime-[a-z0-9.-]+\.elf)"',
            r'build/(slime-[a-z0-9.-]+\.elf)',
        ):
            for match in re.finditer(pattern, text):
                found.setdefault(match.group(1), set()).add(path.name)
        for stem in re.findall(r'f"(slime-[a-z0-9-]+)\{suffix\}\.elf"', text):
            for platform in re.findall(r'^\s+"(qemu-[a-z0-9-]+)":', text, re.MULTILINE):
                if platform == DEFAULT_PLATFORM:
                    continue
                found.setdefault(f"{stem}-{platform}.elf", set()).add(path.name)
        for stem in re.findall(r'artifact_paths\(\s*"(slime-[a-z0-9-]+)"', text):
            found.setdefault(f"{stem}.elf", set()).add(path.name)
            for platform in PLATFORMS:
                if platform != DEFAULT_PLATFORM and f'"{platform}"' in text:
                    found.setdefault(f"{stem}-{platform}.elf", set()).add(path.name)
    if not found:
        fail("no check script names a plane image, so this gate asserts nothing")
    return found


def script_owners() -> dict[str, list[str]]:
    """Which `just` target invokes each check script."""
    owners: dict[str, list[str]] = {}
    for name, recipe in recipes().items():
        text = "\n".join(
            "".join(part if isinstance(part, str) else "" for part in line)
            for line in recipe["body"]
        )
        for script in re.findall(r"scripts/check/([\w.-]+\.py)", text):
            owners.setdefault(script, []).append(name)
    return owners


def closure_name_for(image: str) -> str | None:
    """The closure whose name matches this image, by the shared stem.

    `build/slime-<name>.elf` is produced from composition `<name>`, which is the
    convention every plane image already follows, so the mapping needs no second
    table to drift against.
    """
    match = re.fullmatch(r"slime-(.+)\.elf", image)
    if match is None:
        return None
    return match.group(1)


def check_image_closure_correspondence(images: dict[str, set[str]]) -> tuple[int, int]:
    """Every booted image maps to one closure, or is exempt for a stated reason."""
    closures = {path.stem for path in CLOSURE_ROOT.glob("*.zti")}
    mapped, exempt = 0, 0
    for image in sorted(images):
        name = closure_name_for(image)
        if name is None:
            fail(f"{image}: does not follow the slime-<name>.elf convention")
        if name in closures:
            if image in IMAGES_WITHOUT_CLOSURE:
                fail(
                    f"{image}: listed as having no closure, but closure {name!r} exists; "
                    "remove the exemption"
                )
            mapped += 1
            continue
        reason = IMAGES_WITHOUT_CLOSURE.get(image)
        if reason is None:
            fail(
                f"{image}: booted by {sorted(images[image])} but no closure named {name!r} "
                "exists and no reason is declared"
            )
        if len(reason) < 20:
            fail(f"{image}: its exemption reason is too short to be a reason")
        exempt += 1
    stale = sorted(set(IMAGES_WITHOUT_CLOSURE) - set(images))
    if stale:
        fail(f"exemption(s) naming an image no checker boots: {stale}")
    return mapped, exempt


def check_every_closure_is_exercised(images: dict[str, set[str]]) -> int:
    """Every closure is exercised by an owning build or boot gate.

    A closure is exercised when some `just` target either boots the image its
    name implies or builds it through the closure gates. The second half
    matters: the scenario and root-role closures have no image of their own
    yet, and `just system_image_builder_check` plus
    `just system_image_scenario_check` are what build them, so they are
    exercised by those rather than unexercised.
    """
    owners = script_owners()
    recipe_names = just_targets()
    for gate in ("system_image_builder_check", "system_image_scenario_check"):
        if gate not in recipe_names:
            fail(f"{gate} is not a Justfile recipe, so it cannot exercise a closure")

    unexercised = []
    for path in sorted(CLOSURE_ROOT.glob("*.zti")):
        image = f"slime-{path.stem}.elf"
        if image in images:
            gates = sorted({gate for script in images[image] for gate in owners.get(script, [])})
            if not gates:
                unexercised.append(f"{path.stem} (image booted by no just target)")
            continue
        # No image of its own: it must be a scenario, a root-role closure, or a
        # composition whose closure the builder/scenario gates build.
        if (
            path.stem in GENERATOR_MODULE.SCENARIOS
            or path.stem in GENERATOR_MODULE.ROOT_ROLE_CLOSURES
            or path.stem in DERIVED_GENERATION_FIXTURES
        ):
            continue
        unexercised.append(f"{path.stem} (no image, no scenario, no root role, no composition)")
    if unexercised:
        fail(f"closure(s) exercised by nothing: {unexercised}")
    return len(list(CLOSURE_ROOT.glob("*.zti")))


def composed_plane_flags(text: str) -> set[str]:
    """The plane flags `text` builds through `f"--{name}-plane"`.

    Only string literals bound to `name` in the same file are admitted, so a
    flag composed from a runtime value stays invisible here and is reported as
    an orphan rather than silently excused.
    """
    composed: set[str] = set()
    for name in re.findall(r'f"--\{([A-Za-z_][A-Za-z0-9_]*)\}-plane"', text):
        for binding in re.findall(rf'^\s*{name}\s*=\s*(.+)$', text, re.MULTILINE):
            composed.update(f"--{value}-plane" for value in re.findall(r'"([a-z0-9-]+)"', binding))
    return composed


def check_plane_flags_are_owned() -> int:
    """Every plane build flag is reachable from exactly one owning gate.

    An image produced by a flag no gate runs is an image nobody verifies, which
    is the same drift class as a closure nobody exercises seen from the build
    side rather than the closure side.

    A checker may compose its flag rather than spell it: the capacity arm
    builds `f"--{variant}-plane"` from a variant bound in the same file, so a
    literal scan sees neither flag it reaches. That idiom is expanded from the
    string literals the file binds to that name, which is the vocabulary the
    arm can actually select.
    """
    builder = SEL4_BUILDER.read_text(encoding="utf-8")
    declared = sorted(set(re.findall(r'"(--[a-z0-9-]+)"', builder)))
    plane_flags = [flag for flag in declared if flag.endswith("-plane")]
    if not plane_flags:
        fail("build-sel4.py declares no plane flag, so this assertion is vacuous")

    owners = script_owners()
    used: dict[str, set[str]] = {}
    # A flag is reached either by a recipe invoking the builder directly or by a
    # check script the recipe runs. Both are ownership; scanning only one half
    # reports a false orphan for every gate that builds in its own recipe body.
    for name, recipe in recipes().items():
        body = "\n".join(
            "".join(part if isinstance(part, str) else "" for part in line)
            for line in recipe["body"]
        )
        for flag in plane_flags:
            if flag in body:
                used.setdefault(flag, set()).add(name)
    for path in sorted(CHECK_ROOT.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        reached = {flag for flag in plane_flags if f'"{flag}"' in text}
        reached |= composed_plane_flags(text) & set(plane_flags)
        for flag in reached:
            for gate in owners.get(path.name, []):
                used.setdefault(flag, set()).add(gate)
    orphaned = sorted(flag for flag in plane_flags if flag not in used)
    if orphaned:
        fail(f"plane flag(s) no just target reaches: {orphaned}")
    return len(plane_flags)


def check_record_kinds_are_disjoint() -> None:
    """A name is one kind of thing: composition, scenario, root role, or negative case."""
    compositions = set(DERIVED_GENERATION_FIXTURES) - {"reference"}
    scenarios = set(GENERATOR_MODULE.SCENARIOS)
    root_roles = set(GENERATOR_MODULE.ROOT_ROLE_CLOSURES)
    negatives = {path.stem for path in negative_case_paths()}
    named = (
        ("composition", compositions),
        ("scenario", scenarios),
        ("root role", root_roles),
        ("negative case", negatives),
    )
    for index, (left_label, left) in enumerate(named):
        for right_label, right in named[index + 1 :]:
            overlap = sorted(left & right)
            if overlap:
                fail(
                    f"{overlap} are both a {left_label} and a {right_label}; "
                    "a record name is one kind of thing"
                )
    # And every closure file is exactly one of the three closure kinds.
    closures = {path.stem for path in CLOSURE_ROOT.glob("*.zti")}
    unclassified = sorted(closures - compositions - scenarios - root_roles)
    if unclassified:
        fail(f"closure(s) that are neither composition, scenario, nor root role: {unclassified}")


def check_negative_cases_have_no_image() -> int:
    """A negative case produces no bootable plane image.

    The type exists so a deliberately invalid build cannot be presented as a
    product image; an `build/slime-<case>.elf` would be exactly that
    presentation, so its absence is asserted rather than assumed.
    """
    cases = [path.stem for path in negative_case_paths()]
    if not cases:
        fail("no negative build case is declared")
    for case in cases:
        stray = ROOT / "build" / f"slime-{case}.elf"
        if stray.exists():
            fail(f"{case}: a negative build case has a plane image at {stray}")
    return len(cases)


def check_no_undeclared_build_knobs(
    extra_source: str | None = None, also_non_keying: str | None = None
) -> tuple[int, int, int]:
    """Every `SLIME_*` build knob is closure-declared, non-keying, or a named legacy knob.

    An ambient environment variable that changes image bytes is exactly what
    CP14 converted into closure data, and a new one reintroduces the drift
    silently because nothing in a build's output records that it was read.

    The classification is three-way and deliberately not two-way. CP15 has not
    yet deleted the legacy build path, so knobs only that path reads are a real
    and expected present state; calling them a failure would make this gate red
    for the whole migration and so get it disabled. Calling them fine would let
    a *new* ambient knob hide among them. Enumerating them by name does
    neither: the set can only shrink as CP15 migrates each gate, and anything
    outside all three classes is refused.
    """
    # Read by the closure builder, which sets exactly the knobs its closure
    # declares after clearing every `SLIME_*` from the environment.
    CLOSURE_DECLARED = {
        "SLIME_FABRIC_PROXY_EARLY_EXIT",
        "SLIME_FABRIC_STREAM_EARLY_EXIT",
        "SLIME_NETWORK_DRIVER_RESET_IN_FLIGHT",
        "SLIME_NETWORK_FAULT_IN_FLIGHT",
        "SLIME_GENERATION_CMD_SCENARIO",
        "SLIME_BOOT_SELECTION_FAIL",
        "SLIME_RECOVERY_IMAGE",
        "SLIME_B40_MUTATION",
        "SLIME_GENERATION",
        "SLIME_SEL4_MANIFEST",
    }
    # The three build parameters. These reach a build by *rewriting the resolved
    # manifest* rather than through the environment, which is the stronger form:
    # the value lands in the manifest the closure identity covers, so it cannot
    # be set for one build and forgotten for the next. The legacy path still
    # reads them as ambient overrides, which is why they appear here at all.
    CLOSURE_PARAMETERS = {
        "SLIME_GENERATION_NUMBER": "generationNumber",
        "SLIME_FABRIC_LIMIT_OVERRIDE": "fabricLimitOverride",
        "SLIME_FABRIC_QOS_OVERRIDE": "fabricQosOverride",
    }
    # Select where a build happens or what it reports, never what bytes it
    # produces, so they are not part of an image key.
    NON_KEYING = {
        "SLIME_TARGET_PROFILE": "selects the platform asset, already a closure platform field",
        "SLIME_COMPONENT_LINKER_DIR": "locates linker scripts for out-of-tree builds",
        "SLIME_GENERATION_CANDIDATE": "names a candidate generation path, not image bytes",
        "SLIME_COMPONENT_CC": "names the host C compiler for the C-runtime helper",
        "SLIME_ATTESTATION_RUNNER": "names the build machine an attestation note records, after the build",
        "SLIME_UNUSED": "names the unused input variable of a Zutai evaluation of an attestation note",
    }
    # Read only by the legacy build path CP15 deletes. Each is an ambient switch
    # whose closure equivalent either exists already or is named in CP14's
    # not-delivered set; none is reachable from `build-system-image.py`.
    LEGACY_PENDING_DELETION = {
        "SLIME_ACCEPTED_RELEASE_SEQUENCE",
        "SLIME_BOOT_BUNDLE_IDENTITY",
        "SLIME_BOOT_SELECTOR",
        "SLIME_DUO_EARLY_FAULT",
        "SLIME_DUO_TEST_TERMINATOR",
        "SLIME_DUO_TIMEBASE_HZ",
        "SLIME_GENERATION_CMD_CHECK",
        "SLIME_KNOWN_GOOD_FIRST",
        "SLIME_PC99_COM1_PORT",
        "SLIME_PENDING_ATTEMPTS",
        "SLIME_PENDING_GENERATION",
        "SLIME_PENDING_RELEASE_SEQUENCE",
        "SLIME_PRODUCT_SLISP_SHA256",
        "SLIME_PRODUCT_TEST_TERMINATOR",
        "SLIME_PRODUCT_UART_PADDR",
        "SLIME_QEMU_KEYBOARD",
        "SLIME_ROOT_FIXTURE",
        "SLIME_TRANSFER_ACTIVATE",
        "SLIME_TRANSFER_RECEIVER",
        "SLIME_WRONG_TARGET_EXECUTABLE",
    }

    if also_non_keying is not None:
        NON_KEYING[also_non_keying] = "a negative control's second classification"
    classes = {
        "closure-declared": set(CLOSURE_DECLARED),
        "closure parameter": set(CLOSURE_PARAMETERS),
        "non-keying": set(NON_KEYING),
        "legacy pending deletion": set(LEGACY_PENDING_DELETION),
    }
    for knob in sorted(set().union(*classes.values())):
        owners = [name for name, members in classes.items() if knob in members]
        if len(owners) > 1:
            fail(f"build knob {knob} is in more than one class: {owners}")

    closure_builder = ROOT / "scripts" / "build" / "build-system-image.py"
    found: dict[str, set[str]] = {}
    for path in sorted((ROOT / "scripts" / "build").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if extra_source is not None and path.name == "build-sel4.py":
            text += extra_source
        for knob in re.findall(r'"(SLIME_[A-Z0-9_]+)"', text):
            # `SLIME_FABRIC_` and `SLIME_SEL4_` appear as prefix fragments in
            # environment-scrubbing loops rather than as knob names.
            if knob.endswith("_"):
                continue
            found.setdefault(knob, set()).add(path.name)
    if not found:
        fail("no SLIME_* build knob was found, so this assertion is vacuous")

    classified = (
        CLOSURE_DECLARED
        | set(CLOSURE_PARAMETERS)
        | set(NON_KEYING)
        | LEGACY_PENDING_DELETION
    )
    undeclared = sorted(set(found) - classified)
    if undeclared:
        fail(
            "build knob(s) in none of the three classes: "
            f"{[(knob, sorted(found[knob])) for knob in undeclared]}; "
            "a knob that changes image bytes belongs in a closure"
        )
    stale = sorted(classified - set(found))
    if stale:
        fail(f"classified knob(s) no build script reads: {stale}")
    # The legacy set may only shrink: a knob named legacy must not be reachable
    # from the closure builder, or it is closure data misfiled as legacy.
    closure_text = closure_builder.read_text(encoding="utf-8")
    misfiled = sorted(
        knob for knob in LEGACY_PENDING_DELETION if f'"{knob}"' in closure_text
    )
    if misfiled:
        fail(f"legacy-classified knob(s) the closure builder reads: {misfiled}")
    # And every closure-declared knob must actually be reachable from it.
    unreachable = sorted(
        knob for knob in CLOSURE_DECLARED if f'"{knob}"' not in closure_text
    )
    if unreachable:
        fail(f"closure-declared knob(s) the closure builder never sets: {unreachable}")
    # Each build parameter must be a name the closure contract admits, so this
    # class cannot become a place to park an ambient knob.
    # The schema is the vocabulary's authority; reading it here rather than
    # restating the three names means adding a fourth parameter cannot leave
    # this gate checking a stale set.
    schema = (
        ROOT / "contracts" / "system-image-closure" / "v2" / "schema.zt"
    ).read_text(encoding="utf-8")
    admitted = set(re.findall(r'^parameter[A-Za-z]+ :: Text = "([a-zA-Z]+)";', schema, re.MULTILINE))
    if not admitted:
        fail("the closure schema declares no build parameter, so this assertion is vacuous")
    for knob, parameter in CLOSURE_PARAMETERS.items():
        if parameter not in admitted:
            fail(f"{knob} maps to {parameter!r}, which the closure contract does not admit")
    return (
        len(CLOSURE_DECLARED) + len(CLOSURE_PARAMETERS),
        len(NON_KEYING),
        len(LEGACY_PENDING_DELETION),
    )


def check_migration_is_monotone() -> tuple[int, int]:
    """Migrated checkers do not regress, and unmigrated ones are named.

    CP15 moves each plane gate from a `--<name>-plane` flag to a closure
    identity. Mid-migration both shapes exist, so the useful invariant is not
    "no checker uses a flag" — that is false until the last one moves — but
    that a checker which has moved cannot move back, and that the remaining set
    is enumerated rather than open.

    A checker that builds through `closure_image` must not also invoke
    `build-sel4.py`: holding both is how a gate silently keeps booting the
    legacy artifact while appearing migrated.
    """
    # Gates that legitimately hold both paths, and why. A composer over every
    # plane must, while some planes have closures and some do not; a gate whose
    # negative arm needs an input a closure build scrubs must, until that input
    # is closure data. Each is named so the exception cannot spread silently,
    # and each must still route its *closure-covered* planes through the
    # closure path.
    DUAL_PATH = {
        "check-sel4-demo-plane.py": "its boot-selection arm has no closure and its wrong-target arm needs a scrubbed input",
        "check-sel4-generation-plane.py": "its riscv64 arm has no closure; the closure names platform qemu-arm-virt",
        "check-sel4-rollback-plane.py": "its riscv64 arm has no closure; the closure names platform qemu-arm-virt",
        "check-sel4-private-memory-plane.py": "MEM-LARGE adds an RV64 arm before CP15 migrates that target's image to closure identity",
        # P6's pc99 arms: pc99's Multiboot2 media has no loader image, so each
        # builds legacy on that platform until closure packaging supports it.
        "check-sel4-boot-layout.py": "its pc99 arm has no closure; the Multiboot2 route stays on the legacy builder",
        "check-sel4-component-graph.py": "its pc99 arm has no closure; the Multiboot2 route stays on the legacy builder",
        "check-sel4-sample-plane.py": "its pc99 arm has no closure; the Multiboot2 route stays on the legacy builder",
        "check-sel4-wait-set-plane.py": "its pc99 arm has no closure; the Multiboot2 route stays on the legacy builder",
    }
    migrated, legacy, dual = [], [], []
    for path in sorted(CHECK_ROOT.glob("check-sel4-*.py")):
        text = path.read_text(encoding="utf-8")
        uses_closure = "closure_image" in text
        uses_flag = bool(re.search(r'"--[a-z0-9-]+-plane"', text)) or "build-sel4.py" in text
        if uses_closure and uses_flag and path.name in DUAL_PATH:
            dual.append(path.name)
            continue
        if uses_closure and uses_flag:
            fail(
                f"{path.name}: builds through closure_image *and* invokes the legacy builder; "
                "a half-migrated gate can boot the legacy artifact while appearing migrated"
            )
        if uses_closure:
            migrated.append(path.name)
        elif uses_flag:
            legacy.append(path.name)
    if not migrated:
        fail("no plane gate builds by closure identity, so CP15 has not started")
    stale = sorted(set(DUAL_PATH) - set(dual))
    if stale:
        fail(f"gate(s) listed as dual-path that no longer hold both: {stale}")
    return len(migrated), len(legacy), len(dual)


def check_gate_controls(images: dict[str, set[str]]) -> int:
    """This gate refuses each drift it claims to catch.

    A mapping assertion that cannot fail is decoration. Each control perturbs
    one input in a scratch copy and requires the specific refusal, so the gate's
    own claims are observed rather than asserted. The perturbations are applied
    to copies of the in-memory inputs, never to repository files.
    """
    controls: list[tuple[str, object, str]] = [
        (
            "an image booted by a checker with neither a closure nor a reason",
            lambda: check_image_closure_correspondence(
                {**copy.deepcopy(images), "slime-sel4-invented.elf": {"check-invented.py"}}
            ),
            "no reason is declared",
        ),
        (
            "an image not following the naming convention",
            lambda: check_image_closure_correspondence(
                {**copy.deepcopy(images), "slime-sel4-broken.bin": {"check-broken.py"}}
            ),
            "does not follow",
        ),
        (
            "an exemption naming an image no checker boots",
            lambda: _with_exemption(
                {**IMAGES_WITHOUT_CLOSURE, "slime-sel4-ghost.elf": "a reason long enough to pass"},
                lambda: check_image_closure_correspondence(copy.deepcopy(images)),
            ),
            "naming an image no checker boots",
        ),
        (
            "an exemption whose reason is not a reason",
            lambda: _with_exemption(
                {
                    key: ("x" if key == "slime-sel4-boot-selection.elf" else value)
                    for key, value in IMAGES_WITHOUT_CLOSURE.items()
                },
                lambda: check_image_closure_correspondence(copy.deepcopy(images)),
            ),
            "too short to be a reason",
        ),
        (
            "a newly introduced ambient build knob",
            lambda: check_no_undeclared_build_knobs('\n"SLIME_INVENTED_SCENARIO"\n'),
            "in none of the three classes",
        ),
        (
            "a closure-declared knob also classified non-keying",
            lambda: check_no_undeclared_build_knobs(
                also_non_keying="SLIME_NETWORK_FAULT_IN_FLIGHT"
            ),
            "is in more than one class",
        ),
        (
            "a name that is both a scenario and a root-role closure",
            lambda: _with_generator_scenarios(
                {**GENERATOR_MODULE.SCENARIOS, next(iter(GENERATOR_MODULE.ROOT_ROLE_CLOSURES)): ()},
                check_record_kinds_are_disjoint,
            ),
            "is one kind of thing",
        ),
    ]
    for label, action, needle in controls:
        try:
            action()
        except SystemExit as error:
            if needle not in str(error):
                fail(f"control {label!r} failed for the wrong reason: {error}")
        else:
            fail(f"control {label!r} was accepted, so this gate does not catch it")
    return len(controls)


def _with_exemption(replacement: dict[str, str], action) -> None:
    global IMAGES_WITHOUT_CLOSURE
    saved = IMAGES_WITHOUT_CLOSURE
    IMAGES_WITHOUT_CLOSURE = replacement
    try:
        action()
    finally:
        IMAGES_WITHOUT_CLOSURE = saved


def _with_generator_scenarios(replacement: dict, action) -> None:
    saved = GENERATOR_MODULE.SCENARIOS
    GENERATOR_MODULE.SCENARIOS = replacement
    try:
        action()
    finally:
        GENERATOR_MODULE.SCENARIOS = saved


images = booted_images()
mapped, exempt = check_image_closure_correspondence(images)
closure_count = check_every_closure_is_exercised(images)
flag_count = check_plane_flags_are_owned()
check_record_kinds_are_disjoint()
negative_count = check_negative_cases_have_no_image()
closure_knobs, non_keying_knobs, legacy_knobs = check_no_undeclared_build_knobs()
migrated_gates, legacy_gates, dual_gates = check_migration_is_monotone()
control_count = check_gate_controls(images)

print(
    f"system image aggregate check: {len(images)} booted plane image(s) — {mapped} reachable "
    f"from exactly one canonical closure, {exempt} exempt with a declared reason; all "
    f"{closure_count} closures exercised by an owning build or boot gate; {flag_count} plane "
    f"build flag(s) each reachable from a just target; composition, scenario, root-role, and "
    f"negative-case names pairwise disjoint; {negative_count} negative case(s) carry no plane image; "
    f"SLIME_* build knobs classified {closure_knobs} closure-declared / {non_keying_knobs} "
    f"non-keying / {legacy_knobs} legacy pending CP15 deletion, with none unclassified, none "
    f"misfiled, and every closure-declared knob reachable from the closure builder; "
    f"{migrated_gates} plane gate(s) build by closure identity, {legacy_gates} still on the legacy "
    f"flag, and {dual_gates} declared dual-path with none holding both undeclared; "
    f"and {control_count} named drift control(s) refused"
)
