#!/usr/bin/env python3

"""No EL0 program of a Raspberry Pi 5 system-timer image names a generic-timer register.

The image builder takes `--system-timer` for `bcm2712-rpi5`. The root of that
image counts the SoC's system timer, and its components ask the root for the
clock. This gate builds two such images and reads every EL0 program in each:

* the root ELF and the root child ELF that the image identity names, each
  held to the SHA-256 the identity records;
* the component image of every executable of the generation the image
  embeds, found by the SHA-256 the identity records for it.

The first image is the product, `--component-graph`. Its generation holds no
component that reads the clock. The second is `--clock-authority-plane`,
whose `clock-authority-probe` reads the counter and its rate. The gate sets no
variable itself: the flag is the only thing that differs between a build and
its control, so a builder that does not carry the switch to its component
builds leaves the probe's reads in place.

Every program must hold no access (`scripts/lib/el0_timer_audit.py`).

The controls come from the same two images built without the flag. Each root
must then write `CNTP_CTL_EL0` and read `CNTPCT_EL0`, and
`clock-authority-probe` must read `CNTPCT_EL0`. An audit that finds nothing in
those builds either cannot tell the two apart. The synthetic controls of the
reader run first.

The switch has one source. The builder must refuse `--system-timer` for
another platform and refuse the variable in its own environment, and the two
images must have identities of their own: an image that counts the system
timer under the default image's name would reach the board unnoticed.

The gate reads code and boots nothing. The kernel and the loader run above
EL0 and use these registers, so the gate does not read them. Whether the
system timer works on the board is an operator's observation; no gate here
makes it.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import hashlib
import json
import os
import re
import subprocess
import sys
from typing import NoReturn

import devloop_observations
import el0_timer_audit
from harness import ROOT

PLATFORM = "bcm2712-rpi5"
TARGET_PROFILE = "aarch64-rpi5"
SWITCH = "SLIME_SYSTEM_TIMER"
# The images the gate builds, as `(label, builder flag)`.
IMAGES = (("product", "--component-graph"), ("clock", "--clock-authority-plane"))
CLOCK_READER = "clock component clock-authority-probe"
WROTE = re.compile(r"^seL4 image build: wrote \S+ and (\S+\.identity\.json)$", re.MULTILINE)
# The EL0 programs among the ELFs an image identity names.
EL0_ELFS = ("root", "child")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"EL0 generic-timer check: {message}")


def run(command: list[str], environment: dict[str, str], what: str) -> str:
    process = subprocess.run(command, cwd=ROOT, env=environment, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if process.returncode != 0:
        sys.stderr.write(process.stdout[-4000:])
        fail(f"{what} failed with exit status {process.returncode}")
    return process.stdout


def held(path: _Path, digest: str, what: str) -> bytes:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        fail(f"{what} at {path.relative_to(ROOT)} does not match the SHA-256 its image identity records")
    return data


def read(what: str, function, data: bytes) -> list[str]:
    try:
        return el0_timer_audit.program_accesses(function(data))
    except el0_timer_audit.AuditError as error:
        fail(f"{what}: {error}")


def components(generation: bytes, what: str) -> dict[str, list[str]]:
    try:
        images = el0_timer_audit.generation_images(generation)
    except el0_timer_audit.AuditError as error:
        fail(f"{what}: {error}")
    return {f"component {name}": read(f"{what}, component {name}", el0_timer_audit.image_code, image) for name, image in images}


def refused(command: list[str], environment: dict[str, str], what: str) -> None:
    """The builder must stop, and name the flag, before it builds anything."""
    process = subprocess.run(command, cwd=ROOT, env=environment, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if process.returncode == 0 or "--system-timer" not in process.stdout or WROTE.search(process.stdout):
        sys.stderr.write(process.stdout[-2000:])
        fail(f"the builder did not refuse {what}")


def image_programs(label: str, variant: str, system_timer: bool) -> tuple[str, dict[str, list[str]]]:
    """Build one image; return its identity path and every EL0 program it holds."""
    environment = {name: value for name, value in os.environ.items() if name != SWITCH}
    command = [sys.executable, str(ROOT / "scripts" / "build" / "build-sel4.py"), "--platform", PLATFORM, variant, "--skip-pin-check"]
    what = f"the {PLATFORM} {label} image{' with --system-timer' if system_timer else ''}"
    output = run(command + (["--system-timer"] if system_timer else []), environment, f"the build of {what}")
    wrote = WROTE.findall(output)
    if len(wrote) != 1:
        fail(f"the build of {what} named {len(wrote)} image identities, expected one")
    identity = json.loads((ROOT / wrote[0]).read_text(encoding="utf-8"))
    if identity.get("platform") != PLATFORM or identity.get("target_profile") != TARGET_PROFILE:
        fail(f"{wrote[0]} is not an identity of {PLATFORM} for {TARGET_PROFILE}")
    if identity.get("system_timer", False) is not system_timer:
        fail(f"{wrote[0]} records system_timer={identity.get('system_timer')!r} for {what}")
    programs = {}
    for role in EL0_ELFS:
        record = identity["elf"][role]
        programs[f"{label} {role}"] = read(f"{what}, {role} ELF", el0_timer_audit.elf_code, held(ROOT / record["path"], record["sha256"], f"the {role} ELF"))
    digest = identity["generation"]["sha256"]
    generations = [path for path in sorted((ROOT / "build" / PLATFORM).glob("*/generation.bin")) if hashlib.sha256(path.read_bytes()).hexdigest() == digest]
    if not generations:
        fail(f"no generation under build/{PLATFORM}/ has the SHA-256 that {wrote[0]} records")
    programs.update({f"{label} {name}": found for name, found in components(generations[0].read_bytes(), what).items()})
    return wrote[0], programs


def build_all(system_timer: bool) -> tuple[list[str], dict[str, list[str]]]:
    identities, programs = [], {}
    for label, variant in IMAGES:
        identity, found = image_programs(label, variant, system_timer)
        identities.append(identity)
        programs |= found
    return identities, programs


def main() -> int:
    if sys.argv[1:] not in ([], ["--controls-only"]):
        fail(f"unknown arguments {sys.argv[1:]}; the script takes --controls-only or nothing")
    try:
        synthetic = el0_timer_audit.controls()
    except el0_timer_audit.AuditError as error:
        fail(str(error))
    print(f"EL0 generic-timer check: {synthetic} synthetic controls refused or found what they must")
    if sys.argv[1:]:
        return 0

    builder = [sys.executable, str(ROOT / "scripts" / "build" / "build-sel4.py"), "--component-graph", "--skip-pin-check"]
    clean = {name: value for name, value in os.environ.items() if name != SWITCH}
    refused(builder + ["--system-timer"], clean, "--system-timer for the default platform")
    refused(builder + ["--platform", PLATFORM], clean | {SWITCH: "1"}, f"{SWITCH} in its environment")

    generic_identities, generic = build_all(False)
    system_identities, system = build_all(True)
    identities = generic_identities + system_identities
    if len(set(identities)) != len(identities):
        fail(f"two builds wrote one image identity: {sorted(identities)}")

    # Controls on real builds: without the flag the reader finds the accesses the sources hold.
    controls = [(f"{label} root", access) for label, _ in IMAGES for access in ("msr CNTP_CTL_EL0", "mrs CNTPCT_EL0")] + [(CLOCK_READER, "mrs CNTPCT_EL0")]
    for program, access in controls:
        if access not in generic.get(program, []):
            fail(f"control: {program} of the build without the flag holds no '{access}', so the audit cannot tell the two builds apart")
    if set(system) != set(generic):
        fail(f"the two builds hold different programs: {sorted(set(system) ^ set(generic))}")

    problems = [f"{program}: {len(found)} access(es), {sorted(set(found))}" for program, found in sorted(system.items()) if found]
    for program, found in sorted(system.items()):
        print(f"[el0-timer] {program:<52} generic={len(generic[program]):>3} system={len(found):>3}")
    if problems:
        fail("the system-timer image names a generic-timer register from EL0:\n  " + "\n  ".join(problems))
    devloop_observations.record(
        el0ProgramsAudited=len(system),
        el0TimerAccesses=sum(len(found) for found in system.values()),
        el0TimerAccessesWithoutSwitch=sum(len(found) for found in generic.values()),
        el0TimerSyntheticControls=synthetic,
    )
    print(f"EL0 generic-timer check: {len(system)} EL0 programs of the {PLATFORM} system-timer builds hold no generic-timer access")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
