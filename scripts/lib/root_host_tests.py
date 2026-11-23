"""Count the host tests of `slime-root` in its source.

`count` gives the number of tests that `just test_sel4_root` must run: the `#[test]` attributes in the library files
that the host build of the tests compiles. The walk starts at `src/lib.rs`. A `#[cfg(test)]` on a module declaration
is no condition, and any other `cfg` leaves the file out: the run compiles for AArch64 and without the boot selector.
The recipe compares the number with the tests that ran, so a test that the source holds and the run misses fails the
gate, and a change that adds a test changes no recipe.

`controls` runs the counter on a synthetic crate and on seven changes to it, and refuses a wrong count.

Known limit. The counter does not read a `cfg` on a single test or on an inline module. With one, the count and the
run differ and the recipe fails.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import rust_source
from harness import ROOT

CRATE = "slime-root"
LIBRARY_ROOT = "src/lib.rs"
TEST_FUNCTION_ATTRIBUTE = re.compile(r"#\[\s*test\s*\]")


def host_tests(files: list[str], read: Callable[[str], str]) -> int:
    """`#[test]` attributes in the library files that a host build of the tests compiles."""
    tree = rust_source.modules(files, LIBRARY_ROOT, read, test_is_condition=False)
    return sum(
        len(TEST_FUNCTION_ATTRIBUTE.findall(rust_source.lex(read(relative)).text))
        for relative, conditional in tree.items()
        if not conditional
    )


# A synthetic crate for the controls of `host_tests`: three tests that a host
# build compiles, and one behind a `cfg` that it does not meet.
_HOST_TEST_TREE = {
    "src/lib.rs": 'pub mod a;\n#[cfg(target_arch = "x86_64")]\npub mod gated;\n#[cfg(test)]\nmod a_tests;\n',
    "src/a.rs": "pub fn f() {}\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn one() {}\n    #[test]\n    fn two() {}\n}\n",
    "src/gated.rs": "#[test]\nfn only_on_x86() {}\n",
    "src/a_tests.rs": "#[test]\nfn three() {}\n",
}


def controls() -> int:
    """The counter gives the expected count on the synthetic crate and on each change to it."""

    def counted(changes: dict[str, str]) -> int:
        tree = {**_HOST_TEST_TREE, **changes}
        return host_tests(sorted(tree), tree.__getitem__)

    a, lib = _HOST_TEST_TREE["src/a.rs"], _HOST_TEST_TREE["src/lib.rs"]
    cases = (
        ("the synthetic crate", {}, 3),
        ("a fourth test in a declared module", {"src/a.rs": a + "#[test]\nfn four() {}\n"}, 4),
        ("a second test behind the unmet cfg", {"src/gated.rs": "#[test]\nfn x() {}\n#[test]\nfn y() {}\n"}, 3),
        ("a test attribute in a comment", {"src/a.rs": a + "// #[test]\n/* #[test] */\n"}, 3),
        ("a test attribute in a string literal", {"src/a.rs": a + 'const T: &str = "#[test]";\n'}, 3),
        ("the test module no longer declared", {"src/lib.rs": lib.replace("#[cfg(test)]\nmod a_tests;\n", "")}, 2),
        ("the test module behind a second cfg", {"src/lib.rs": lib.replace("#[cfg(test)]\nmod a_tests;", '#[cfg(test)]\n#[cfg(feature = "x")]\nmod a_tests;')}, 2),
        ("a file that no module declares", {"src/orphan.rs": "#[test]\nfn lost() {}\n"}, 3),
    )
    for label, changes, expected in cases:
        found = counted(changes)
        if found != expected:
            raise rust_source.SourceError(f"host test count control '{label}' counted {found}, not {expected}")
    return len(cases)


def count() -> int:
    """The number of host tests in the checkout."""
    return host_tests(rust_source.sources(CRATE), lambda relative: (ROOT / CRATE / relative).read_text(encoding="utf-8"))
