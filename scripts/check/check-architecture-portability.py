#!/usr/bin/env python3
"""Reject privileged x86 mechanism in surviving neutral Rust trees.

P1 extracted the retired custom kernel's x86 mechanism behind an explicit
boundary and this gate keeps it there. What it forbids is *privileged
mechanism*: raw general-purpose and control registers, ring-0 instructions,
relocation and ELF-magic constants, and the emulator binary. The
architecture-neutral trees below reach hardware only through seL4
invocations, so none of those may appear in them.

The architecture *name* is not itself forbidden, for the same reason
`aarch64` and `riscv64` are not: these trees already select per-architecture
arms with `#[cfg(target_arch = ...)]`, and P6.1 makes `x86_64` an admitted
seL4 architecture alongside them. A `cfg` arm is the boundary working, not a
breach of it. What would be a breach — an inline `mov %cr4`, a `wrmsr`, a
hard-coded `R_X86_64_*` relocation — is still refused, and P6's own source
boundary (archived `roadmap/07-architecture-portability.md`, located through
`docs/history.md`) keeps privileged x86 mechanism outside these trees.
"""

from __future__ import annotations

import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from component_paths import COMPONENT_CRATE_ROOTS  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
NEUTRAL_ROOTS = (
    *COMPONENT_CRATE_ROOTS,
    ROOT / "components" / "lib" / "src",
    ROOT / "components" / "runtime" / "src",
    ROOT / "slime-root" / "src",
)
# Privileged x86 mechanism, by vocabulary rather than by architecture name.
#
# Three groups, each enumerated rather than approximated, because this gate is
# only as strong as the list:
#
#  * ring-0 and I/O instructions: anything that changes privileged machine
#    state or touches a port directly;
#  * privileged registers: control, debug, and segment-descriptor-table
#    registers, plus the general-purpose register names that only appear in
#    hand-written x86 assembly;
#  * artifact-level x86 assumptions: relocation types, the ELF machine
#    constant, and the emulator binary.
#
# Deliberately absent is the bare token `x86_64`. `#[cfg(target_arch = ...)]`
# arms for the admitted architectures are the boundary working as designed —
# these trees already carry `aarch64` and `riscv64` arms — and P6.1 makes
# x86-64 an admitted seL4 architecture alongside them.
PRIVILEGED_INSTRUCTIONS = (
    "cli",
    "clts",
    "hlt",
    "invd",
    "invlpg",
    "invpcid",
    "iret",
    "iretq",
    "lgdt",
    "lidt",
    "lldt",
    "lmsw",
    "ltr",
    "monitor",
    "mwait",
    "rdmsr",
    "wrmsr",
    "xsetbv",
    "rdpmc",
    "rsm",
    "sgdt",
    "sidt",
    "sldt",
    "smsw",
    "sti",
    "swapgs",
    "sysexit",
    "sysret",
    "sysretq",
    "vmcall",
    "vmlaunch",
    "vmresume",
    "vmxoff",
    "vmxon",
    "wbinvd",
    # Port I/O. `in`/`out` are also English words and Rust keywords, so they
    # are matched only in their width-suffixed assembly spellings.
    "inb",
    "inw",
    "inl",
    "outb",
    "outw",
    "outl",
)
PRIVILEGED_REGISTERS = (
    # Control, debug, and test registers.
    *(f"cr{index}" for index in range(9)),
    *(f"dr{index}" for index in range(8)),
    "efer",
    "gdtr",
    "idtr",
    "ldtr",
    # `tr` and `str` are deliberately absent: as bare tokens they collide with
    # Rust's `&str` and with ordinary identifiers, and `ltr`/`sldt`/`sgdt`
    # above already cover every instruction that reads or writes them.
    # 64-bit general-purpose register names. These appear only in hand-written
    # assembly: Rust's `asm!` operands are named placeholders, and the
    # architecture arms in these trees use `in(reg)`/`out(reg)` rather than
    # explicit registers.
    *(f"r{name}" for name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip")),
    *(f"r{index}" for index in range(8, 16)),
)
ARTIFACT_ASSUMPTIONS = (
    r"\bR_X86_64\w*\b",
    r"qemu-system-x86_64",
    # `EM_X86_64` as a bare number: an ELF machine check belongs in
    # `boot-contracts`, driven by the target-profile contract's `elf_machine`.
    r"\b0x8664\b",
)
FORBIDDEN = re.compile(
    "(?i)(?:"
    + "|".join(
        [
            r"\b(?:" + "|".join(PRIVILEGED_INSTRUCTIONS) + r")\b",
            r"\b(?:" + "|".join(PRIVILEGED_REGISTERS) + r")\b",
            *ARTIFACT_ASSUMPTIONS,
        ]
    )
    + ")"
)


def fail(message: str) -> None:
    raise SystemExit(f"architecture portability check: {message}")


# Rust line and block comments. The rule is about what the code *does*, so a
# comment naming `CR4.FSGSBASE` to explain why a kernel configuration permits a
# userspace instruction is documentation, not mechanism — and forbidding it
# would push exactly the invariants this boundary depends on out of the source.
COMMENT = re.compile(r"//.*|/\*.*?\*/", re.DOTALL)


def main() -> None:
    checked = 0
    violations: list[str] = []
    for root in NEUTRAL_ROOTS:
        if not root.is_dir():
            fail(f"missing neutral source tree {root.relative_to(ROOT)}")
        for path in sorted(root.rglob("*.rs")):
            checked += 1
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if FORBIDDEN.search(COMMENT.sub("", line)):
                    violations.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}")
    if checked == 0:
        fail("neutral source set is empty")
    if violations:
        fail("privileged x86 mechanism in neutral source:\n" + "\n".join(violations))
    print(
        f"architecture portability check: {checked} neutral Rust files contain no "
        "privileged x86 mechanism"
    )


if __name__ == "__main__":
    main()
