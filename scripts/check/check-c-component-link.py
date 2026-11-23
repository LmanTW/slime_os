#!/usr/bin/env python3
"""A freestanding C component build runs no host compiler driver.

`scripts/build/build-c-component.py` compiles a C component with the pinned
Clang and links it with the pinned LLD. For a target that Clang's bare-metal
toolchain does not handle, the Clang driver hands the link to a program named
`gcc` and adds `-m64`. That program is whatever the host provides: an AArch64
`gcc` refuses `-m64`, and an x86-64 one adds its own link arguments. A product
ELF must not depend on either.

The gate builds the platform's image first, so the installed seL4 headers
exist. It then builds the product Slisp component again with a closed `PATH`:
one directory that holds `ld.lld` and a trap under every name in `TRAPS`. The
trap records its own name and arguments and exits with `TRAP_EXIT`. The build
must succeed, no trap may have run, and the output must be a static
executable for the architecture.

Two controls show that the trap catches the route this gate forbids. The first
runs `gcc` by name with the closed `PATH`. The second links one object through
the Clang driver with the closed `PATH`, in the form the builder used before
it named the linker. Each must fail, and the trap must have recorded `gcc`.
If a later Clang links this target with LLD itself, the second control stops
failing. That is the signal that the builder no longer needs its own link
step, and the control then changes with the builder.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import devloop_observations  # noqa: E402
from harness import BUILD_SCRIPTS, ROOT, load_script  # noqa: E402

IMAGE_BUILDER = BUILD_SCRIPTS / "build-sel4.py"
COMPONENT_BUILDER = BUILD_SCRIPTS / "build-c-component.py"
SLISP_SOURCES = (
    ROOT / "components" / "slisp" / "slisp.c",
    ROOT / "components" / "slisp" / "main.c",
)
# One row per architecture a recipe runs this gate for: the platform whose
# image build installs the seL4 headers, the Clang target, and the ELF
# machine number the output must carry.
ARCHITECTURES = {
    "x86_64": {"platform": "qemu-pc99", "target": "x86_64-none-elf", "machine": 62},
}
# Every name a compiler driver, a linker other than LLD, or an assembler has
# on a host. The closed `PATH` holds nothing else but `ld.lld`, so a program
# under a name this list lacks is not found and the build fails as well.
TRAPS = ("gcc", "cc", "g++", "c++", "cpp", "collect2", "ld", "ld.bfd", "ld.gold", "as")
TRAP_EXIT = 97
ET_EXEC = 2
PT_DYNAMIC = 2
PT_INTERP = 3
# What this run observed, counted where each case concludes.
ACCEPTED: list[str] = []
REFUSED: list[str] = []


def fail(message: str) -> NoReturn:
    raise SystemExit(f"C component link check: {message}")


def record(message: str) -> None:
    print(f"C component link check: {message}", flush=True)


def build_image(platform: str) -> None:
    command = [sys.executable, str(IMAGE_BUILDER), "--platform", platform, "--skip-pin-check"]
    record(f"build {' '.join(command[1:])}")
    try:
        process = subprocess.run(command, cwd=ROOT, check=False)
    except OSError as error:
        fail(f"cannot run the seL4 image build: {error}")
    if process.returncode != 0:
        fail(f"seL4 image build failed with exit status {process.returncode}")


def closed_path(directory: Path, log: Path) -> dict[str, str]:
    """An environment whose `PATH` holds `ld.lld` and the traps, and nothing else."""
    linker = shutil.which("ld.lld")
    if linker is None:
        fail("ld.lld is not on PATH; enter `nix develop`")
    directory.mkdir()
    (directory / "ld.lld").symlink_to(Path(linker).resolve())
    trap = directory / TRAPS[0]
    trap.write_text(
        f"#!/bin/sh\nprintf '%s %s\\n' \"${{0##*/}}\" \"$*\" >> '{log}'\nexit {TRAP_EXIT}\n",
        encoding="utf-8",
    )
    trap.chmod(0o755)
    for name in TRAPS[1:]:
        (directory / name).symlink_to(trap)
    environment = os.environ.copy()
    environment["PATH"] = str(directory)
    return environment


def trapped(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


def check_static_executable(path: Path, machine: int) -> None:
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        fail(f"{path.name} is not a little-endian ELF64 file")
    kind, found = struct.unpack_from("<HH", data, 16)
    if kind != ET_EXEC or found != machine:
        fail(
            f"{path.name} has ELF type {kind} and machine {found}; expected {ET_EXEC} and {machine}"
        )
    (offset,) = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    for index in range(count):
        (segment,) = struct.unpack_from("<I", data, offset + index * size)
        if segment in (PT_DYNAMIC, PT_INTERP):
            fail(
                f"{path.name} carries program header type {segment}; a component is a static executable"
            )


def check_build(architecture: str, compiler: str, staging: Path) -> None:
    profile = ARCHITECTURES[architecture]
    log = staging / "build-traps.log"
    output = staging / f"slisp-{architecture}.elf"
    command = [
        sys.executable,
        str(COMPONENT_BUILDER),
        "--architecture",
        architecture,
        "--cc",
        compiler,
        *[str(source) for source in SLISP_SOURCES],
        str(output),
    ]
    process = subprocess.run(
        command,
        cwd=ROOT,
        env=closed_path(staging / "build-path", log),
        check=False,
        text=True,
        capture_output=True,
    )
    calls = trapped(log)
    if calls:
        fail(f"the {architecture} component build ran a host tool: {calls[0]}")
    if process.returncode != 0:
        fail(
            f"the {architecture} component build failed with exit status "
            f"{process.returncode} on a PATH that holds only ld.lld:\n{process.stderr[-2000:]}"
        )
    if not output.is_file():
        fail(f"the {architecture} component build wrote no {output.name}")
    check_static_executable(output, profile["machine"])
    ACCEPTED.append(f"{architecture} build")
    record(f"the {architecture} Slisp component links with ld.lld alone")


def control_trap_is_on_path(staging: Path) -> None:
    log = staging / "control-name-traps.log"
    environment = closed_path(staging / "control-name-path", log)
    program = shutil.which("gcc", path=environment["PATH"])
    if program is None:
        fail("control: the closed PATH resolves no gcc")
    process = subprocess.run(
        [program, "--version"], env=environment, check=False, capture_output=True
    )
    if process.returncode != TRAP_EXIT or trapped(log) != ["gcc --version"]:
        fail("control: `gcc` on the closed PATH did not reach the trap")
    REFUSED.append("gcc by name")
    record("control refused: gcc by name reaches the trap")


def control_driver_link(architecture: str, compiler: str, staging: Path) -> None:
    profile = ARCHITECTURES[architecture]
    log = staging / "control-driver-traps.log"
    environment = closed_path(staging / "control-driver-path", log)
    source = staging / "control.c"
    source.write_text("void _start(void) {}\n", encoding="utf-8")
    target = f"--target={profile['target']}"
    flags = [target, "-ffreestanding", "-fno-stack-protector", "-fno-builtin", "-nostdlib"]
    compiled = subprocess.run(
        [compiler, *flags, "-c", str(source), "-o", str(staging / "control.o")],
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )
    if compiled.returncode != 0 or trapped(log):
        fail(
            f"control: Clang could not compile one object on the closed PATH:\n{compiled.stderr[-2000:]}"
        )
    linked = subprocess.run(
        [
            compiler,
            *flags,
            "-fuse-ld=lld",
            "-Wl,--no-pie",
            "-Wl,--build-id=none",
            str(staging / "control.o"),
            "-o",
            str(staging / "control.elf"),
        ],
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )
    calls = trapped(log)
    if linked.returncode == 0 or not calls or not calls[0].startswith("gcc "):
        fail(
            f"control: a {profile['target']} link through the Clang driver did not reach `gcc` "
            f"(exit status {linked.returncode}, traps {calls}). If this Clang links the target "
            "with LLD itself, the builder's own link step and this control change together"
        )
    REFUSED.append("driver link")
    record(
        f"control refused: the Clang driver links {profile['target']} through `{calls[0].split()[0]}`"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--architecture", choices=sorted(ARCHITECTURES), required=True)
    arguments = parser.parse_args()
    profile = ARCHITECTURES[arguments.architecture]
    build_image(profile["platform"])
    builder = load_script("build_c_component", "build/build-c-component.py")
    compiler = builder.compiler_for_target(
        os.environ.get("SLIME_COMPONENT_CC", "clang"), arguments.architecture
    )
    resolved = shutil.which(compiler)
    if resolved is None:
        fail(f"the component compiler {compiler!r} is not on PATH; enter `nix develop`")
    with tempfile.TemporaryDirectory(prefix="slime-c-component-link-") as temporary:
        staging = Path(temporary)
        check_build(arguments.architecture, resolved, staging)
        control_trap_is_on_path(staging)
        control_driver_link(arguments.architecture, resolved, staging)
    devloop_observations.record(
        casesObserved=len(ACCEPTED) + len(REFUSED), negativeControlsRefused=len(REFUSED)
    )
    record(f"{len(ACCEPTED)} build accepted and {len(REFUSED)} controls refused")


if __name__ == "__main__":
    main()
