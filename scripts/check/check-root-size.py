#!/usr/bin/env python3

"""Budget the source of `slime-root` by role.

Every Rust file under `slime-root/` has exactly one role. The script counts the
code lines of each role and refuses a role, or the series total, that exceeds
its ceiling. It also refuses a file with no role, a file with two roles, and a
dependency of `slime-root` that `DEPENDENCIES` does not name.

A code line is a line that holds at least one character outside whitespace and
comments. The lexer below reads Rust's comments, string literals, raw strings
and character literals, so a brace or `//` inside a literal is text.

A top-level item behind the exact attribute `#[cfg(test)]` is a test item. Its
lines are test lines, from the attribute to the `;` or the closing `}` that
ends the item. A file named `tests.rs` or `*_tests.rs`, and a file under a
`tests/` directory, is a test file. Test lines belong to no role. Any other
`cfg`, and a `#[cfg(test)]` inside an item, leaves the lines as code.

`ROLES` holds the ceilings. This script is the grader set of
`just root_size_check`, so a ceiling or a role assignment changes only through
a planning pull request with an approval (V4). `SERIES` names the roles the
series total covers. The `harness` role holds the build script and the two
`qualification.rs` files. Cargo runs the build script on the host, and a
`slime_*` cfg compiles each qualification scenario into its own root role
image. The role has its own ceiling and is outside the series total.

The series total is what a product root compiles, so it leaves out a file that
only the fixture root compiles. `slime-root/build.rs` sets the cfg
`slime_root_fixture` for the fixture root alone. A module that `src/main.rs`
declares behind exactly `#[cfg(slime_root_fixture)]`, and every module below
it, is such a file. Its role must be `fixture`, and the ceiling of that role
still bounds it. The script reports the lines of those files as
`fixtureOnlyCodeLines`.

The script also walks the module tree from each crate root. A walk reads every
`mod name;` declaration of a file and follows it into the file that holds the
module. It reads the file with comments and literals blanked, so text inside
them declares nothing.

The walk from `src/main.rs` finds what only the binary compiles. Host tests
build the library, so they cannot name those lines. The count is reported as
`binaryOnlyCodeLines`, with the count of those files as `binaryOnlyFiles`, and
`BINARY_ONLY_CEILING` bounds the lines. The part of it that a product root
compiles is reported as `productBinaryCodeLines`: the same files without those
that only the fixture root compiles. `PRODUCT_BINARY_CEILING` bounds it.

The walk from `src/lib.rs` finds what the library compiles under a condition.
A file is conditional when a `#[cfg(...)]` attribute stands on its declaration
or on the declaration of a module above it, or when the file holds an inner
`#![cfg(...)]` attribute. A build that does not meet the condition skips the
file, so the host build may not compile it. The count is reported as
`libraryConditionalCodeLines`, with `libraryConditionalFiles`, and
`LIBRARY_CONDITIONAL_CEILING` bounds the lines. Test files are in neither
count.

The script measures every function outside test items, in code lines from the
line of its `fn` to the line of its closing brace. `FUNCTION_LIMIT` bounds a
function. `LONG_FUNCTIONS` names the functions that were longer when the limit
landed, each with a ceiling of its own. A function above the limit that the
table does not name is refused, and so is a named function above its ceiling.
An entry stays after its function is split, as a role's file entry does; a
planning pull request removes it. The script reports the number of functions
above the limit as `functionsOverLimit`, and the longest function of
`LAUNCH_PATH` as `launchPathLongestFunctionCodeLines`.

The script counts the `fatal!` invocations in the files of the library's tree,
outside test items. A function that reaches one stops the root and does not
return, so no host test can call it past that point. The count is reported as
`libraryFatalSites`, and `LIBRARY_FATAL_CEILING` bounds it.

The script counts the string literals that name a product component. A product
component is a crate under one of the four lifecycle directories of
`components/`, and its name is the name of its directory. A literal names one
when its whole text is that name. The script reads `slime-root/` and the two
crates of this repository that the root links, outside test items and test
files. The count is reported as `productComponentNames`, and
`COMPONENT_NAME_CEILING` bounds it. Before it reads a file, the script checks
the reader on synthetic sources: it must count a literal in a function and a
raw literal, and it must not count a literal in a test item, a comment, or a
longer text.

A walk refuses what it cannot follow: a `path` attribute on a declaration, a
declaration inside an inline module, and a declaration that no file or two
files hold. The script also refuses a file that neither walk reaches, other
than the build script and test files, because no build compiles it.

A role may name a file that does not exist. A planning pull request assigns a
file before the implementation creates it, and an entry stays after its file
is deleted.

Known limits. The script counts `slime-root/` only. Code that moves into a
crate the root links leaves the count. `DEPENDENCIES` pins which crates those
are, so a new one is a grader change. The script reads which modules stand
behind `slime_root_fixture`. It does not read which builds set that cfg:
`scripts/build/build-sel4.py` does, for two root roles and for the fixture
variant on every platform but `cv1800b-duo`.
A walk reads the `cfg` on a module
declaration and on a whole file. It does not read a `cfg` on an item inside a
file, so an item that the host build skips still counts as compiled. A walk
does not expand macros, so a module that a macro declares is not followed.
The count of component names holds a literal only: a name inside a longer
literal, a name that code assembles, and an instance name that differs from
every crate's name are not counted. A
role holds whole files:
`src/object_allocator/qualification.rs` also holds two methods that the
product image calls, and the `harness` role counts them.
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import devloop_observations  # noqa: E402
from harness import ROOT  # noqa: E402
from rust_source import MODULE_DECLARATION, SourceError, is_test_file, lex, modules, sources, test_items  # noqa: E402

CRATE = "slime-root"
MANIFEST = ROOT / CRATE / "Cargo.toml"
BINARY_ROOT = "src/main.rs"
LIBRARY_ROOT = "src/lib.rs"
BUILD_SCRIPT = "build.rs"
FUNCTION = re.compile(r"(?<![A-Za-z0-9_])fn\s+([A-Za-z_][A-Za-z0-9_]*)")
FATAL_SITE = re.compile(r"(?<![A-Za-z0-9_])fatal!\s*[(\[{]")
# The one attribute that puts a module of the binary into the fixture root alone.
FIXTURE_ATTRIBUTE = re.compile(r"#\[\s*cfg\s*\(\s*slime_root_fixture\s*\)\s*\]")
FIXTURE_ROLE = "fixture"


@dataclass(frozen=True)
class Role:
    """`ceiling` bounds the role's code lines. `files` are paths relative to
    `slime-root/`. `trees` are directory prefixes, each ending in `/`. A tree
    gives its role to a file that no role names."""

    ceiling: int
    files: tuple[str, ...] = ()
    trees: tuple[str, ...] = ()


# Each role ceiling is the role's count on the commit that landed this script,
# rounded up to a multiple of 50. Four are newer. `boot` is 5650: the role
# holds 5600 lines since `src/boot.rs` carries the boot sequence and the 440
# lines that build and settle the fixture tasks left `main`. `fixture` is 1050
# with those lines. `core` is 14950 and `timer` is 1650: each is the count the
# role holds with its part of `services/policy.rs`, 14925 and 1612, rounded up
# to a multiple of 50.
ROLES: dict[str, Role] = {
    # Kernel-object allocation, address spaces, tasks, faults and the graph.
    "core": Role(
        ceiling=14950,
        files=(
            "src/lib.rs",
            "src/object_allocator.rs",
            "src/private_memory.rs",
            "src/task.rs",
            "src/child_vspace.rs",
            "src/graph.rs",
            "src/transfer_window.rs",
            "src/fault.rs",
            "src/supervision.rs",
            "src/cspace.rs",
            "src/root_cspace.rs",
            "src/launched.rs",
            "src/thread_abi.rs",
            "src/vm_attributes.rs",
            "src/event.rs",
            "src/graph_runtime/adaptive.rs",
            "src/graph_runtime/state.rs",
            "src/graph_runtime/services/spawn.rs",
            "src/graph_runtime/services/reclaim.rs",
        ),
        trees=("src/object_allocator/", "src/private_memory/"),
    ),
    # Runs once, before the first component: admission, launch, boot media.
    "boot": Role(
        ceiling=5650,
        files=(
            "src/main.rs",
            "src/boot.rs",
            "src/generation.rs",
            "src/graph_runtime.rs",
            "src/graph_runtime/platform.rs",
            "src/peer_endpoint.rs",
            "src/boot_selector.rs",
            "src/boot_selector_block.rs",
            "src/boot_record.rs",
            "src/framebuffer.rs",
            "src/glyph_font.rs",
        ),
        trees=("src/generation/",),
    ),
    # Device regions, IRQ control and IO resource grants.
    "ioResource": Role(
        ceiling=3050,
        files=(
            "src/io_resource.rs",
            "src/device.rs",
            "src/irq_control.rs",
            "src/graph_runtime/services/io_resource.rs",
        ),
    ),
    # Shared buffers and capability transfer between components.
    "sharedBuffer": Role(
        ceiling=3050,
        files=(
            "src/shared_buffer.rs",
            "src/buffer_adapter.rs",
            "src/graph_runtime/services/capability.rs",
        ),
    ),
    # Operation decoding and the service loop.
    "dispatch": Role(
        ceiling=2550,
        files=("src/ipc.rs", "src/graph_runtime/services.rs"),
    ),
    # What the root enforces on a request and decides for no one: restart
    # admission, scheduling class, directory scope, notifications and wait sets.
    "enforcement": Role(
        ceiling=2100,
        files=(
            "src/lifecycle.rs",
            "src/scheduling.rs",
            "src/directory.rs",
            "src/notification.rs",
            "src/wait_set.rs",
            "src/graph_runtime/services/policy.rs",
        ),
    ),
    # The platform timer, the timer queue, the clock service and its requests.
    "timer": Role(
        ceiling=1650,
        files=(
            "src/timer.rs",
            "src/platform_timer.rs",
            "src/clock.rs",
            "src/graph_runtime/services/clock_requests.rs",
        ),
    ),
    # The root side of the fixture. Its child program is `components/root-child`.
    "fixture": Role(
        ceiling=1050,
        files=("src/fixture_runtime.rs",),
    ),
    # Root diagnostics and the console endpoint.
    "console": Role(
        ceiling=450,
        files=(
            "src/console.rs",
            "src/diagnostic.rs",
            "src/graph_runtime/console_runtime.rs",
            "src/graph_runtime/services/diagnostic_once.rs",
        ),
    ),
    # The build script and qualification scenarios of root role images.
    "harness": Role(
        ceiling=1750,
        files=(
            "build.rs",
            "src/object_allocator/qualification.rs",
            "src/private_memory/qualification.rs",
        ),
    ),
}

SERIES = ("core", "boot", "ioResource", "sharedBuffer", "dispatch", "enforcement", "timer", "fixture", "console")
# The series held 34294 code lines on the commit that landed this script,
# 33941 after the fixture's child crate left `slime-root/`, and 33073 once a
# product root compiled no fixture. It held 32893 once the test-only functions
# of product types stood in test items.
SERIES_CEILING = 32950
# The binary alone compiled 9301 code lines, in 13 files, on the commit that
# landed this measure, and 1119 lines, in `src/main.rs` and
# `src/fixture_runtime.rs`, once the library held the graph runtime and the
# boot sequence.
BINARY_ONLY_CEILING = 1150
# A product root compiled 124 of those lines, all of `src/main.rs`, once the
# fixture's module stood behind its cfg.
PRODUCT_BINARY_CEILING = 150
# The library compiled 2443 code lines under a `cfg`, in 6 files, on the same
# commit: the boot selector, the boot framebuffer of x86-64 and one
# qualification module.
LIBRARY_CONDITIONAL_CEILING = 2450

# No function may hold more code lines, except those `LONG_FUNCTIONS` names.
FUNCTION_LIMIT = 150
# The functions above the limit on the commit that landed it, as
# `(file, function)`, each with its count then rounded up to a multiple of 50.
# An entry covers every function of that name in that file.
LONG_FUNCTIONS: dict[tuple[str, str], int] = {
    ("src/graph_runtime/services.rs", "serve_instance_graph"): 1500,
    ("src/graph_runtime/services/spawn.rs", "serve_spawn"): 600,
    ("src/task.rs", "create"): 450,
    ("src/graph_runtime/services/spawn.rs", "construct_child"): 400,
    # The body that `main` holds until the fixture's module holds it.
    ("src/fixture_runtime.rs", "run"): 350,
    ("src/graph_runtime/services/io_resource.rs", "serve_io_resource"): 350,
    ("src/private_memory/qualification.rs", "exercise_failure_rollback"): 350,
    ("src/private_memory/elastic.rs", "grow"): 250,
    ("src/graph_runtime/services/spawn.rs", "preflight_spawn_grants"): 200,
    ("src/graph_runtime/services/capability.rs", "serve_capability_export"): 200,
    ("src/private_memory/qualification.rs", "exercise_mixed_fragmentation"): 200,
    ("src/graph_runtime/services/policy.rs", "serve_lifecycle_request"): 200,
}
# The files that run once, from the console install to the first component.
LAUNCH_PATH = ("src/boot.rs", "src/graph_runtime.rs")
# The library's tree held 160 `fatal!` invocations on the commit that landed
# this measure, and 5 once its boot, launch and service loop returned a result.
LIBRARY_FATAL_CEILING = 8

# The directories of `components/` that hold one crate per product component.
COMPONENT_GROUPS = ("system", "services", "applications", "testkit")
# The root, and the crates of this repository that it links.
NAME_SCAN = (CRATE, "boot-contracts", "components/proto")
# The root names no product component. `slime-root/src/ipc.rs` held six such
# literals until the root took its table readers from the generation.
COMPONENT_NAME_CEILING = 0

# Every crate `slime-root/Cargo.toml` names in a dependency table.
DEPENDENCIES = frozenset({"boot-contracts", "sel4", "slime-proto", "sel4-root-task", "object"})


def fail(message: str) -> NoReturn:
    raise SystemExit(f"root size check failed: {message}")


def count(text: str) -> tuple[int, int]:
    """(code lines, test lines) of one source file."""
    lexed = lex(text)
    test = test_items(text, lexed)
    code_lines = sum(1 for held, tested in zip(lexed.code, test, strict=True) if held and not tested)
    test_lines = sum(1 for held, tested in zip(lexed.code, test, strict=True) if held and tested)
    return code_lines, test_lines


def functions(text: str) -> list[tuple[str, int]]:
    """(name, code lines) of every function with a body, outside test items."""
    lexed = lex(text)
    blanked = lexed.text
    test = test_items(text, lexed)
    found: list[tuple[str, int]] = []
    for declared in FUNCTION.finditer(blanked):
        # The body opens at the first `{` outside the parameter list; a `;` first means no body.
        index, nesting, opened = declared.end(), 0, -1
        while index < len(blanked):
            char = blanked[index]
            if char in "([":
                nesting += 1
            elif char in ")]":
                nesting -= 1
            elif nesting == 0 and char in ";{":
                opened = index if char == "{" else -1
                break
            index += 1
        if opened < 0:
            continue
        nesting, closed = 0, opened
        while closed < len(blanked):
            if blanked[closed] == "{":
                nesting += 1
            elif blanked[closed] == "}":
                nesting -= 1
                if nesting == 0:
                    break
            closed += 1
        first, last = blanked.count("\n", 0, declared.start()), blanked.count("\n", 0, closed)
        if test[first]:
            continue
        found.append((declared.group(1), sum(1 for line in range(first, last + 1) if lexed.code[line] and not test[line])))
    return found


def fatal_sites(text: str) -> int:
    """`fatal!` invocations outside test items."""
    lexed = lex(text)
    test = test_items(text, lexed)
    return sum(1 for site in FATAL_SITE.finditer(lexed.text) if not test[lexed.text.count("\n", 0, site.start())])


def component_names() -> frozenset[str]:
    """The directory name of every crate under a lifecycle directory of `components/`."""
    names = frozenset(manifest.parent.name for group in COMPONENT_GROUPS for manifest in (ROOT / "components" / group).glob("*/Cargo.toml"))
    if not names:
        fail("no crate under components/; the count of component names would read nothing")
    return names


def named_components(text: str, names: frozenset[str]) -> list[tuple[int, str]]:
    """(line, name) of every string literal outside test items whose whole text is a component's name."""
    lexed = lex(text)
    test = test_items(text, lexed)
    return [(line + 1, literal) for line, literal in lexed.strings if literal in names and not test[line]]


def name_reader_controls(names: frozenset[str]) -> None:
    """The reader must count a literal in product code and nothing else."""
    name = min(names)
    cases = (
        ("a literal in a function", f'fn f() -> &\'static str {{ "{name}" }}\n', 1),
        ("a raw literal", f'const N: &str = r#"{name}"#;\n', 1),
        ("a byte literal", f'const N: &[u8] = b"{name}";\n', 1),
        ("a literal in a test item", f'#[cfg(test)]\nmod tests {{\n    const N: &str = "{name}";\n}}\n', 0),
        ("a comment", f'// "{name}"\nfn f() {{}} /* "{name}" */\n', 0),
        ("a longer text", f'const N: &str = "[{name}] started";\n', 0),
        ("another text", 'const N: &str = "no-such-component-crate";\n', 0),
    )
    for label, source, expected in cases:
        if len(named_components(source, names)) != expected:
            fail(f"control: the reader of component names does not count {expected} for {label}")


def read_source(relative: str) -> str:
    return (ROOT / CRATE / relative).read_text(encoding="utf-8")


def roles_of(relative: str) -> list[str]:
    """Roles that name the file; when none does, roles whose tree holds it."""
    named = [name for name, role in ROLES.items() if relative in role.files]
    return named or [name for name, role in ROLES.items() if any(relative.startswith(tree) for tree in role.trees)]


def dependencies() -> set[str]:
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    tables = [manifest]
    tables += list(manifest.get("target", {}).values())
    names: set[str] = set()
    for table in tables:
        for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
            names.update(table.get(kind, {}))
    return names


def main() -> int:
    if sys.argv[1:]:
        fail(f"unknown arguments {sys.argv[1:]}; the script takes none")
    for name, role in ROLES.items():
        if any(not tree.endswith("/") for tree in role.trees):
            fail(f"role {name}: a tree must end in '/'")
    if set(SERIES) | {"harness"} != set(ROLES):
        fail("SERIES and harness must name every role once")

    code = dict.fromkeys(ROLES, 0)
    test_lines = 0
    problems: list[str] = []
    files = sources(CRATE)
    if not files:
        fail(f"no Rust file under {CRATE}/")
    for relative in files:
        code_lines, tested = count((ROOT / CRATE / relative).read_text(encoding="utf-8"))
        owners = roles_of(relative)
        if is_test_file(relative):
            test_lines += code_lines + tested
            continue
        if len(owners) != 1:
            problems.append(f"{CRATE}/{relative} has {len(owners)} roles {owners}; a file has exactly one")
            continue
        code[owners[0]] += code_lines
        test_lines += tested

    for root in (BINARY_ROOT, LIBRARY_ROOT):
        if root not in files:
            fail(f"{CRATE}/{root} is missing; a walk starts there")
    try:
        binary_tree = modules(files, BINARY_ROOT, read_source)
        library_tree = modules(files, LIBRARY_ROOT, read_source)
    except SourceError as error:
        fail(f"{CRATE}: {error}")
    for relative in sorted(set(binary_tree) & set(library_tree)):
        problems.append(f"{CRATE}/{relative} is a module of the binary and of the library")
    for relative in files:
        if relative not in binary_tree and relative not in library_tree and relative != BUILD_SCRIPT and not is_test_file(relative):
            problems.append(f"{CRATE}/{relative} is a module of neither the binary nor the library; no build compiles it")

    def code_lines(tree: list[str]) -> int:
        return sum(count((ROOT / CRATE / relative).read_text(encoding="utf-8"))[0] for relative in tree)

    fixture_only: set[str] = set()
    for declared in MODULE_DECLARATION.finditer(lex(read_source(BINARY_ROOT)).text):
        if FIXTURE_ATTRIBUTE.fullmatch(declared.group(1).strip()) is None:
            continue
        module = declared.group(2)
        holder = next(path for path in (f"src/{module}.rs", f"src/{module}/mod.rs") if path in binary_tree)
        fixture_only.update(relative for relative in modules(files, holder, read_source) if not is_test_file(relative))
    for relative in sorted(fixture_only):
        if roles_of(relative) != [FIXTURE_ROLE]:
            problems.append(f"{CRATE}/{relative}: only the fixture root compiles it, and its role is not {FIXTURE_ROLE}")

    binary = sorted(relative for relative in binary_tree if not is_test_file(relative))
    product_binary = [relative for relative in binary if relative not in fixture_only]
    product_binary_lines = code_lines(product_binary)
    fixture_only_lines = code_lines(sorted(fixture_only))
    conditional = sorted(relative for relative, gated in library_tree.items() if gated and not is_test_file(relative))
    binary_lines = code_lines(binary)
    conditional_lines = code_lines(conditional)

    over_limit = 0
    launch_longest = 0
    for relative in files:
        if is_test_file(relative):
            continue
        for name, length in functions(read_source(relative)):
            if relative in LAUNCH_PATH:
                launch_longest = max(launch_longest, length)
            if length <= FUNCTION_LIMIT:
                continue
            over_limit += 1
            ceiling = LONG_FUNCTIONS.get((relative, name))
            if ceiling is None:
                problems.append(f"{CRATE}/{relative}: function {name} holds {length} code lines, above the limit of {FUNCTION_LIMIT}")
            elif length > ceiling:
                problems.append(f"{CRATE}/{relative}: function {name} holds {length} code lines, above its ceiling of {ceiling}")
    library_fatal = sum(fatal_sites(read_source(relative)) for relative in library_tree if not is_test_file(relative))

    names = component_names()
    name_reader_controls(names)
    named: list[str] = []
    for crate in NAME_SCAN:
        scanned = files if crate == CRATE else sources(crate)
        if not scanned:
            fail(f"no Rust file under {crate}/")
        for relative in scanned:
            if is_test_file(relative):
                continue
            found_names = named_components((ROOT / crate / relative).read_text(encoding="utf-8"), names)
            named.extend(f"{crate}/{relative}:{line} names {name}" for line, name in found_names)

    series = sum(code[name] for name in SERIES) - fixture_only_lines
    for name, role in ROLES.items():
        print(f"[root-size] {name:<13} {code[name]:>6} / {role.ceiling}")
        if code[name] > role.ceiling:
            problems.append(f"role {name} holds {code[name]} code lines, above its ceiling of {role.ceiling}")
    print(f"[root-size] {'series':<13} {series:>6} / {SERIES_CEILING} without {fixture_only_lines} line(s) that only the fixture root compiles")
    print(f"[root-size] files={len(files)} testLines={test_lines}")
    print(
        f"[root-size] {'binaryOnly':<13} {binary_lines:>6} / {BINARY_ONLY_CEILING} in {len(binary)} file(s); "
        f"a product root compiles {product_binary_lines} of them, in {len(product_binary)} file(s)"
    )
    if binary_lines > BINARY_ONLY_CEILING:
        problems.append(f"the binary alone compiles {binary_lines} code lines, above its ceiling of {BINARY_ONLY_CEILING}")
    if product_binary_lines > PRODUCT_BINARY_CEILING:
        problems.append(f"a product root compiles {product_binary_lines} code lines of the binary alone, above its ceiling of {PRODUCT_BINARY_CEILING}")
    print(f"[root-size] {'conditional':<13} {conditional_lines:>6} / {LIBRARY_CONDITIONAL_CEILING} in {len(conditional)} file(s)")
    if conditional_lines > LIBRARY_CONDITIONAL_CEILING:
        problems.append(
            f"the library compiles {conditional_lines} code lines under a cfg, above its ceiling of {LIBRARY_CONDITIONAL_CEILING}"
        )
    print(f"[root-size] {'functions':<13} {over_limit:>6} above {FUNCTION_LIMIT} code lines; the longest on the launch path holds {launch_longest}")
    print(f"[root-size] {'fatalSites':<13} {library_fatal:>6} / {LIBRARY_FATAL_CEILING} in the library")
    if library_fatal > LIBRARY_FATAL_CEILING:
        problems.append(f"the library holds {library_fatal} fatal! invocations, above its ceiling of {LIBRARY_FATAL_CEILING}")
    print(f"[root-size] {'componentNames':<13} {len(named):>5} / {COMPONENT_NAME_CEILING} literal(s) that name one of {len(names)} product components")
    if len(named) > COMPONENT_NAME_CEILING:
        problems.append(
            f"the root and the crates it links name a product component {len(named)} time(s), above the ceiling of {COMPONENT_NAME_CEILING}:\n    "
            + "\n    ".join(named)
        )
    if series > SERIES_CEILING:
        problems.append(f"the series holds {series} code lines, above its ceiling of {SERIES_CEILING}")

    found = dependencies()
    for name in sorted(found - DEPENDENCIES):
        problems.append(f"{CRATE}/Cargo.toml names dependency {name}, which DEPENDENCIES does not")
    for name in sorted(DEPENDENCIES - found):
        problems.append(f"DEPENDENCIES names {name}, which {CRATE}/Cargo.toml does not")

    if problems:
        fail("\n  " + "\n  ".join(problems))
    devloop_observations.record(
        seriesCodeLines=series,
        harnessCodeLines=code["harness"],
        filesObserved=len(files),
        binaryOnlyCodeLines=binary_lines,
        binaryOnlyFiles=len(binary),
        productBinaryCodeLines=product_binary_lines,
        fixtureOnlyCodeLines=fixture_only_lines,
        libraryConditionalCodeLines=conditional_lines,
        libraryConditionalFiles=len(conditional),
        functionsOverLimit=over_limit,
        launchPathLongestFunctionCodeLines=launch_longest,
        libraryFatalSites=library_fatal,
        productComponentNames=len(named),
        **{f"{name}CodeLines": code[name] for name in SERIES},
    )
    print("root size check: every file has one role, and every role, the series, both walks, every function, the fatal sites and the component names are within their bounds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
