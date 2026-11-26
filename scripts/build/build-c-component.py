#!/usr/bin/env python3

from __future__ import annotations
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from harness import ROOT

RUNTIME = ROOT / "components" / "runtime"
INCLUDE = RUNTIME / "include"
ARCHITECTURES = {
    "aarch64": {
        "target": "aarch64-none-elf",
        "prefix": ROOT / "build" / "sel4-prefix",
        "start": RUNTIME / "c" / "start-aarch64.S",
        "linker": RUNTIME / "c" / "component-aarch64.ld",
        "machine_flags": (),
    },
    "riscv64": {
        "target": "riscv64-none-elf",
        "prefix": ROOT / "build" / "sel4-riscv64-prefix",
        "start": RUNTIME / "c" / "start-riscv64.S",
        "linker": RUNTIME / "c" / "component-riscv64.ld",
        "machine_flags": ("-march=rv64imac", "-mabi=lp64"),
    },
    "x86_64": {
        "target": "x86_64-none-elf",
        "prefix": ROOT / "build" / "sel4-pc99-prefix",
        "start": RUNTIME / "c" / "start-x86_64.S",
        "linker": RUNTIME / "c" / "component-x86_64.ld",
        # No `-mno-sse`: seL4 pc99 saves and restores x87/SSE state per thread
        # (`KERNEL_X86_FPU = "XSAVE"`), so a component may use those registers,
        # and the Rust side of this profile relies on the same fact
        # (`sel4/targets/README.md`). `-mno-red-zone` matches what the Rust
        # target specifications set with `disable-redzone`: a signal-free
        # freestanding component gains nothing from the red zone, and the
        # kernel's own entry paths do not preserve it.
        #
        # `-fno-pic` with the small code model is what makes the fixed 0x400000
        # link base in `component-x86_64.ld` usable. Clang defaults to PIC on
        # this target, which emits 32-bit absolute relocations against local
        # symbols that `ld.lld` then refuses ("cannot be used against local
        # symbol; recompile with -fPIC"). The component is loaded at exactly
        # the address it links to, so position independence buys nothing and
        # the absolute addressing the model permits is correct.
        "machine_flags": ("-mno-red-zone", "-fno-pic", "-mcmodel=small"),
        # The builder runs `ld.lld` itself for this target. Clang's bare-metal
        # toolchain does not handle `x86_64-none-elf`, so the driver hands the
        # link to a host program named `gcc`. No component pin names that
        # program. `scripts/check/check-c-component-link.py` refuses a build
        # that runs it.
        #
        # `--no-pie` keeps the output `ET_EXEC`. A component is loaded at the
        # exact address it links to, and its 32-bit absolute relocations do
        # not fit a position-independent image.
        "direct_link_flags": ("--no-pie",),
    },
}
COMMON_FLAGS = ("-ffreestanding", "-fno-stack-protector", "-fno-builtin", "-nostdlib")


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, env=os.environ.copy(), check=True)


def compiler_for_target(compiler: str, architecture: str) -> str:
    """Use Nix's underlying Clang for a foreign LLVM target.

    The wrapper injects host-only flags around the command line and routes the
    link through the host `gcc`. Neither survives a target it was not built
    for: RISC-V rejects one of the injected hardening flags before compiling,
    and an `x86_64-none-elf` link reaches a `gcc` that does not recognize the
    wrapper's own Clang-specific options. Its `orig-cc` record is the wrapper's
    authoritative route to the same pinned Clang without either.

    AArch64 keeps the wrapper: it is the host toolchain's own target family
    on this project's Darwin and Linux hosts, and the wrapper's flags are
    accepted there.
    """
    if architecture == "aarch64":
        return compiler
    path = Path(compiler)
    origin = path.parent.parent / "nix-support" / "orig-cc"
    if not origin.is_file():
        return compiler
    candidate = Path(origin.read_text(encoding="utf-8").strip()) / "bin" / path.name
    if not candidate.is_file():
        raise SystemExit(f"Nix compiler origin is missing: {candidate}")
    return str(candidate)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build one freestanding C Slime component")
    parser.add_argument("source", type=Path, nargs="+")
    parser.add_argument("output", type=Path)
    parser.add_argument("--architecture", choices=ARCHITECTURES, default="aarch64")
    parser.add_argument(
        "--cc",
        default=os.environ.get("SLIME_COMPONENT_CC", "clang"),
        help="Clang-compatible compiler for the selected freestanding target",
    )
    arguments = parser.parse_args()
    compiler = compiler_for_target(arguments.cc, arguments.architecture)
    architecture = ARCHITECTURES[arguments.architecture]
    target_flag = f"--target={architecture['target']}"
    common_flags = (target_flag, *architecture["machine_flags"], *COMMON_FLAGS)
    sel4_include = architecture["prefix"] / "libsel4" / "include"
    sources = [source.resolve() for source in arguments.source]
    output = arguments.output.resolve()
    for source in sources:
        if not source.is_file():
            raise SystemExit(f"missing component source: {source}")
    if not sel4_include.is_dir():
        raise SystemExit(
            f"missing {architecture['prefix'].relative_to(ROOT)}; build the selected seL4 platform first"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="slime-c-component-") as temporary:
        staging = Path(temporary)
        include_flags = ["-isystem", str(sel4_include), "-I", str(INCLUDE)]
        runtime_object = staging / "runtime.o"
        start_object = staging / "start.o"
        component_objects = [staging / f"component-{index}.o" for index in range(len(sources))]
        run(
            [
                compiler,
                *common_flags,
                *include_flags,
                "-c",
                str(RUNTIME / "c" / "component_runtime.c"),
                "-o",
                str(runtime_object),
            ]
        )
        run(
            [
                compiler,
                *common_flags,
                "-c",
                str(architecture["start"]),
                "-o",
                str(start_object),
            ]
        )
        for source, component_object in zip(sources, component_objects, strict=True):
            run(
                [
                    compiler,
                    *common_flags,
                    *include_flags,
                    "-Os",
                    "-c",
                    str(source),
                    "-o",
                    str(component_object),
                ]
            )
        objects = [
            str(start_object),
            str(runtime_object),
            *[str(component_object) for component_object in component_objects],
        ]
        if "direct_link_flags" in architecture:
            run(
                [
                    "ld.lld",
                    *architecture["direct_link_flags"],
                    "-T",
                    str(architecture["linker"]),
                    "--build-id=none",
                    *objects,
                    "-o",
                    str(output),
                ]
            )
        else:
            run(
                [
                    compiler,
                    *common_flags,
                    "-fuse-ld=lld",
                    f"-Wl,-T,{architecture['linker']}",
                    "-Wl,--build-id=none",
                    *objects,
                    "-o",
                    str(output),
                ]
            )
    print(output)


if __name__ == "__main__":
    main()
