"""Judge the product side of the Zenoh grants path: the read label, the schema fields, the root reader and the wrapper.

The grants table has an encoder, a decoder and a builder step. This module judges the code that carries the table from
the generation to the Zenoh service: the label that reads it, the manifest and system spec fields that declare it, the
`slime-root` reader that serves it to one instance, and the runtime wrapper that calls it.

Two kinds of evidence. Each declaration the files must hold is a fact: a pattern that has to match the named file. The
reader's behaviour is graded by the two `slime-root` tests, run alone under the pinned AArch64 recipe, and the count of
tests that ran and were filtered out has to add up to the number `just test_sel4_root` pins.

This module imports no system spec module. The implementation changes those, so a judge that imported them would be
graded by the files the implementation rewrites.
"""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from collections.abc import Callable

import zenoh_facts as facts
from harness import ROOT

FILTER = "zenoh_grants"
TESTS = (
    "ipc::tests::zenoh_grants_rows_are_served_only_to_the_zenoh_service",
    "ipc::tests::zenoh_grants_pages_by_row_cursor_within_the_staged_bound",
)
PINNED_TESTS = 365
QUALITY = "just/quality.just"


class ReaderExamError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ReaderExamError(message)


# (id, path, pattern, an example line the pattern must match). Patterns are searched with re.MULTILINE.
FACTS: tuple[tuple[str, str, str, str], ...] = (
    ("label-contract", "contracts/syscall-abi/v1/schema.zt", r'^\s*operation "capabilityTable" "ZENOH_GRANTS_READ" 75;$',
     '  operation "capabilityTable" "ZENOH_GRANTS_READ" 75;'),
    ("label-rust", "components/proto/src/syscall_abi.rs", r"^\s*pub const ZENOH_GRANTS_READ: u64 = 75;$",
     "    pub const ZENOH_GRANTS_READ: u64 = 75;"),
    ("label-c", "components/runtime/include/slime/syscall_abi.h", r"^#define SLIME_CAPABILITYTABLE_ZENOH_GRANTS_READ 75U$",
     "#define SLIME_CAPABILITYTABLE_ZENOH_GRANTS_READ 75U"),
    ("label-doc", "docs/syscall-abi.md", r"^\| 75 \| `CAPABILITY ZENOH GRANTS READ` \|",
     "| 75 | `CAPABILITY ZENOH GRANTS READ` | `MR0=cursor` |"),
    ("manifest-holder", "contracts/generation-manifest/v1/schema.zt", r"^ZenohGrantEntry :: type \{[^}]*\bholder : Text;[^}]*\bkey : Text;[^}]*\bpublish : Bool;[^}]*\bsubscribe : Bool;[^}]*\};",
     "ZenohGrantEntry :: type {\n  holder : Text;\n  key : Text;\n  publish : Bool;\n  subscribe : Bool;\n};"),
    ("manifest-field", "contracts/generation-manifest/v1/schema.zt", r"^\s*zenohGrants\? : List ZenohGrantEntry;$",
     "  zenohGrants? : List ZenohGrantEntry;"),
    ("manifest-derive", "contracts/generation-manifest/v1/schema.zt", r"^FromData @ZenohGrantEntry :: derive", "FromData @ZenohGrantEntry :: derive"),
    ("manifest-export", "contracts/generation-manifest/v1/schema.zt", r"^\s*ZenohGrantEntry =;$", "  ZenohGrantEntry =;"),
    ("spec-record", "contracts/system-spec/v1/schema.zt", r"^SystemZenohGrant :: type \{[^}]*\bholder : Text;[^}]*\bkey : Text;[^}]*\bpublish : Bool;[^}]*\bsubscribe : Bool;[^}]*\};",
     "SystemZenohGrant :: type {\n  holder : Text;\n  key : Text;\n  publish : Bool;\n  subscribe : Bool;\n};"),
    ("spec-field", "contracts/system-spec/v1/schema.zt", r"^\s*zenohGrants\? : List SystemZenohGrant;$", "  zenohGrants? : List SystemZenohGrant;"),
    ("spec-object", "contracts/system-spec/v1/schema.zt", r"^\s*zenohGrantsObject\? : Bool;$", "  zenohGrantsObject? : Bool;"),
    ("spec-derive", "contracts/system-spec/v1/schema.zt", r"^FromData @SystemZenohGrant :: derive", "FromData @SystemZenohGrant :: derive"),
    ("spec-bound", "contracts/system-spec/v1/schema.zt", r"^maxZenohGrants :: Int = 64;$", "maxZenohGrants :: Int = 64;"),
    ("spec-export-record", "contracts/system-spec/v1/schema.zt", r"^\s*SystemZenohGrant =;$", "  SystemZenohGrant =;"),
    ("spec-export-bound", "contracts/system-spec/v1/schema.zt", r"^\s*maxZenohGrants =;$", "  maxZenohGrants =;"),
    ("python-line", "contracts/system-spec/v1/gen_python.zt", r'^\s*line "MAX_ZENOH_GRANTS" schema\.maxZenohGrants;$',
     '  line "MAX_ZENOH_GRANTS" schema.maxZenohGrants;'),
    ("python-constant", "scripts/lib/system_spec_contract.py", r"^MAX_ZENOH_GRANTS = 64$", "MAX_ZENOH_GRANTS = 64"),
    ("python-ceiling", "scripts/lib/system_spec.py", r'^\s*\("zenohGrants", contract\.MAX_ZENOH_GRANTS\),$',
     '        ("zenohGrants", contract.MAX_ZENOH_GRANTS),'),
    ("root-instance", "slime-root/src/ipc.rs", r'^pub const ZENOH_GRANTS_READER_INSTANCE: &str = "zenoh-service";$',
     'pub const ZENOH_GRANTS_READER_INSTANCE: &str = "zenoh-service";'),
    ("root-rows-per-call", "slime-root/src/ipc.rs",
     r"^pub const ZENOH_GRANTS_ROWS_PER_CALL: usize =\s*crate::transfer_window::MAX_STAGED_ARRAY_BYTES / ZENOH_GRANTS_ROW_BYTES;$",
     "pub const ZENOH_GRANTS_ROWS_PER_CALL: usize =\n    crate::transfer_window::MAX_STAGED_ARRAY_BYTES / ZENOH_GRANTS_ROW_BYTES;"),
    ("root-row-bytes", "slime-root/src/ipc.rs", r"^pub const ZENOH_GRANTS_ROW_BYTES: usize =\s*slime_proto::zenoh_service_grants_table_wire::ENTRY_BYTES;$",
     "pub const ZENOH_GRANTS_ROW_BYTES: usize =\n    slime_proto::zenoh_service_grants_table_wire::ENTRY_BYTES;"),
    ("root-reader", "slime-root/src/ipc.rs", r"^pub fn read_zenoh_grants\($", "pub fn read_zenoh_grants("),
    ("root-copier", "slime-root/src/ipc.rs", r"^pub fn copy_zenoh_grants_rows\($", "pub fn copy_zenoh_grants_rows("),
    ("root-gate", "slime-root/src/ipc.rs", r"if caller != ZENOH_GRANTS_READER_INSTANCE \{", "    if caller != ZENOH_GRANTS_READER_INSTANCE {"),
    ("root-routed", "slime-root/src/ipc.rs", r"^\s*\| capability_table_labels::ZENOH_GRANTS_READ$", "        | capability_table_labels::ZENOH_GRANTS_READ"),
    ("root-route-test", "slime-root/src/ipc.rs", r"capability_table_labels::ZENOH_GRANTS_READ,\s*SERVICE_CAPABILITY_TRANSFER,",
     "                capability_table_labels::ZENOH_GRANTS_READ,\n                SERVICE_CAPABILITY_TRANSFER,"),
    ("root-locator", "slime-root/src/generation.rs", r"^pub\(crate\) fn zenoh_grants_object<", "pub(crate) fn zenoh_grants_object<'a>("),
    ("root-magic", "slime-root/src/generation.rs", r"starts_with\(&slime_proto::zenoh_service_grants_table_wire::TABLE_MAGIC\)",
     "if object.kind == KIND_RESOURCE && object.bytes.starts_with(&slime_proto::zenoh_service_grants_table_wire::TABLE_MAGIC) {"),
    ("root-dispatch", "slime-root/src/graph_runtime/services.rs", r"^\s*capability_table_labels::ZENOH_GRANTS_READ => \{$",
     "            capability_table_labels::ZENOH_GRANTS_READ => {"),
    ("root-dispatch-reader", "slime-root/src/graph_runtime/services.rs", r"ipc::read_zenoh_grants\(generation, instance, cursor, &mut rows\)",
     "match ipc::read_zenoh_grants(generation, instance, cursor, &mut rows) {"),
    ("wrapper-transport", "components/runtime/src/syscall/sel4_transport.rs", r"^pub fn zenoh_grants_read\(cursor: usize, out: &mut \[u8\]\) -> i64 \{$",
     "pub fn zenoh_grants_read(cursor: usize, out: &mut [u8]) -> i64 {"),
    ("wrapper-label", "components/runtime/src/syscall/sel4_transport.rs", r"^\s*capability_table_labels::ZENOH_GRANTS_READ,$",
     "        capability_table_labels::ZENOH_GRANTS_READ,"),
    ("wrapper-public", "components/runtime/src/syscall.rs", r"^pub fn zenoh_grants_read\(cursor: usize, out: &mut \[u8\]\) -> Result<usize, i64> \{$",
     "pub fn zenoh_grants_read(cursor: usize, out: &mut [u8]) -> Result<usize, i64> {"),
    ("wrapper-export", "components/runtime/src/lib.rs", r"\bzenoh_grants_read\b", "    debug_write, zenoh_grants_read,"),
    ("test-pin", QUALITY, rf"^\s*expected={PINNED_TESTS}$", f"    expected={PINNED_TESTS}"),
)
PINNED_FACTS = len(FACTS)


def check_facts(read: Callable[[str], str]) -> int:
    """Every fact holds in the text `read` returns for its path. Returns how many facts held."""
    try:
        return facts.check(FACTS, read)
    except facts.FactsError as error:
        raise ReaderExamError(str(error)) from error


def fact_controls() -> int:
    try:
        return facts.controls(FACTS)
    except facts.FactsError as error:
        raise ReaderExamError(str(error)) from error


def judge_run(output: str) -> int:
    """The filtered `slime-root` run: exactly the two reader tests ran and passed, and every other pinned test was
    filtered out. Returns the number of tests that ran."""
    ran = re.findall(r"^running (\d+) tests?$", output, re.MULTILINE)
    _need(ran == ["2"], f"the run reported {ran or 'no test count'}, not one run of 2 tests")
    results = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", output, re.MULTILINE)
    _need(results == [("ok", "2", "0", "0", "0", str(PINNED_TESTS - 2))],
          f"the run did not pass 2 tests and filter out {PINNED_TESTS - 2}: {results}")
    passed = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))
    _need(passed == set(TESTS), f"the tests that passed are {sorted(passed)}, not {sorted(TESTS)}")
    return len(passed)


def honest_run() -> str:
    lines = ["running 2 tests", *(f"test {name} ... ok" for name in TESTS), "",
             f"test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; {PINNED_TESTS - 2} filtered out; finished in 0.01s"]
    return "\n".join(lines) + "\n"


def run_controls() -> int:
    honest = honest_run()
    _need(judge_run(honest) == 2, "the honest run was not read as two tests")
    first, second = TESTS
    mutations = (
        ("no test ran", "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 365 filtered out; finished in 0.00s\n"),
        ("a third test", honest.replace("running 2 tests", "running 3 tests").replace("2 passed", "3 passed").replace(f"{PINNED_TESTS - 2} filtered out", f"{PINNED_TESTS - 3} filtered out")),
        ("a failed test", honest.replace(f"test {second} ... ok", f"test {second} ... FAILED").replace("2 passed; 0 failed", "1 passed; 1 failed")),
        ("a test of another name", honest.replace(first, "ipc::tests::another_test")),
        ("a pin that does not add up", honest.replace(f"{PINNED_TESTS - 2} filtered out", f"{PINNED_TESTS - 3} filtered out")),
        ("two runs in one output", honest + honest),
    )
    refused = 0
    for label, text in mutations:
        _need(text != honest, f"the {label} control changed nothing")
        try:
            judge_run(text)
        except ReaderExamError:
            refused += 1
        else:
            raise ReaderExamError(f"the judge accepted {label}")
    return refused


RUN_CONTROLS = 6
PINNED_CONTROLS = PINNED_FACTS + RUN_CONTROLS
PINNED_CASES = PINNED_FACTS + 1


def controls() -> tuple[int, int]:
    """Returns (honest checks passed, refusals) on synthetic input. Needs no source file and no toolchain."""
    _need(judge_run(honest_run()) == 2, "the honest run was not read as two tests")
    return PINNED_FACTS + 1, fact_controls() + run_controls()


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise ReaderExamError(f"{path} cannot be read: {error}") from error


def run_reader_tests() -> str:
    """`cargo test -p slime-root --lib -- zenoh_grants`, the way `just test_sel4_root` runs the suite: the pinned
    toolchain, the AArch64 target, the cross linker and `qemu-aarch64` as the runner."""
    prefix = ROOT / "build" / "sel4-prefix"
    _need((prefix / "libsel4" / "include" / "kernel" / "gen_config.json").is_file(), f"no installed seL4 prefix at {prefix}")
    pins = tomllib.loads((ROOT / "sel4" / "pins.toml").read_text(encoding="utf-8"))
    toolchain = pins["rust_sel4"]["toolchain"]
    cross = os.environ.get("CROSS_COMPILER_PREFIX")
    _need(bool(cross), "CROSS_COMPILER_PREFIX is not set")
    libc = subprocess.run([f"{cross}gcc", "-print-file-name=libc.so"], capture_output=True, text=True, check=True).stdout.strip()
    sysroot = os.path.dirname(os.path.dirname(libc))
    environment = {
        **os.environ,
        "SEL4_PREFIX": str(prefix),
        "RUSTUP_TOOLCHAIN": toolchain,
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": f"{cross}gcc",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER": f"qemu-aarch64 -L {sysroot}",
        "CC_aarch64_unknown_linux_gnu": f"{cross}gcc",
    }
    command = ["cargo", "test", "-p", "slime-root", "--target", "aarch64-unknown-linux-gnu", "--lib", "--", FILTER]
    finished = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True)
    _need(finished.returncode == 0, f"{' '.join(command)} exited {finished.returncode}: {(finished.stdout + finished.stderr)[-1500:]}")
    return finished.stdout
