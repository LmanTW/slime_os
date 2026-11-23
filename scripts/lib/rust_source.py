"""Read Rust source lexically: comments, literals, test items and the module tree of a crate.

`lex` reads Rust's comments, string literals, raw strings and character literals, so a brace or `//` inside a literal
is text. It keeps, for each line, whether the line holds code, and it keeps the file with every comment and literal
replaced by spaces. Text inside them then declares nothing and names nothing. It also keeps the text of every string
literal with the line that opens it, for a reader that asks what a file names.

`modules` walks the module tree from a crate root. It reads every `mod name;` declaration of a file and follows it
into the file that holds the module. A file is conditional when a `#[cfg(...)]` attribute stands on its declaration or
on the declaration of a module above it, or when the file holds an inner `#![cfg(...)]` attribute. The walk refuses
what it cannot follow: a `path` attribute on a declaration, a declaration inside an inline module, and a declaration
that no file or two files hold.

Known limits. The walk reads the `cfg` on a module declaration and on a whole file. It does not read a `cfg` on an
item inside a file. It does not expand macros, so a module that a macro declares is not followed.

`scripts/check/check-root-size.py` and `scripts/lib/root_host_tests.py` read `slime-root` through this module.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from harness import ROOT

TEST_ATTRIBUTE = "#[cfg(test)]"
# `mod name;` with the outer attributes that stand on it, in blanked text.
MODULE_DECLARATION = re.compile(
    r"(?<![A-Za-z0-9_])((?:#\[[^\]]*\]\s*)*)(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
CFG_ATTRIBUTE = re.compile(r"#\[\s*cfg\s*\(")
TEST_CFG_ATTRIBUTE = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
INNER_CFG_ATTRIBUTE = re.compile(r"#!\[\s*cfg\s*\(")
PATH_ATTRIBUTE = re.compile(r"\bpath\b")


class SourceError(Exception):
    """A shape of source that this module does not read."""


@dataclass
class Lexed:
    """What the lexer keeps of one file, per line."""

    code: list[bool]  # the line holds a character outside whitespace and comments
    depth: list[int]  # delimiter depth before the line's first character
    ends: list[bool]  # the line holds a `;` or `}` that leaves the depth at 0
    text: str = ""  # the file with every comment and literal replaced by spaces
    strings: tuple[tuple[int, str], ...] = ()  # (line, text between the quotes) of each string and raw string literal


def lex(text: str) -> Lexed:
    """Read Rust's lexical structure: comments, literals and delimiters."""
    lines = text.count("\n") + 1
    out = Lexed([False] * lines, [0] * lines, [False] * lines)
    line = depth = index = 0
    size = len(text)
    blanked = list(text)
    strings: list[tuple[int, str]] = []

    def span(end: int, held: bool) -> int:
        """Pass a comment or a literal that ends before `end`; a literal's text is code."""
        nonlocal line
        for position in range(index, min(end, size)):
            if text[position] == "\n":
                line += 1
                out.depth[line] = depth
                continue
            blanked[position] = " "
            if held and not text[position].isspace():
                out.code[line] = True
        return min(end, size)

    while index < size:
        char = text[index]
        if char.isspace():
            index = span(index + 1, False)
        elif text.startswith("//", index):
            end = text.find("\n", index)
            end = size if end < 0 else end
            blanked[index:end] = " " * (end - index)
            index = end
        elif text.startswith("/*", index):
            nesting, end = 1, index + 2
            while end < size and nesting:
                if text.startswith("/*", end):
                    nesting, end = nesting + 1, end + 2
                elif text.startswith("*/", end):
                    nesting, end = nesting - 1, end + 2
                else:
                    end += 1
            index = span(end, False)
        elif char == '"':
            end = index + 1
            while end < size and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            strings.append((line, text[index + 1 : end]))
            index = span(end + 1, True)
        elif char == "r" and raw_string(text, index) and not identifier_before(text, index):
            hashes = raw_string(text, index) - 1
            end = text.find('"' + "#" * hashes, index + hashes + 2)
            strings.append((line, text[index + hashes + 2 : size if end < 0 else end]))
            index = span(size if end < 0 else end + hashes + 1, True)
        elif char == "'":
            index = span(character_literal(text, index), True)
        else:
            out.code[line] = True
            if char in "{([":
                depth += 1
            elif char in "})]":
                depth -= 1
            if char in ";}" and depth == 0:
                out.ends[line] = True
            index += 1
    out.text = "".join(blanked)
    out.strings = tuple(strings)
    return out


def raw_string(text: str, index: int) -> int:
    """For `r"`, `r#"`, ... at `index`: one more than the count of `#`. Otherwise 0."""
    end = index + 1
    while end < len(text) and text[end] == "#":
        end += 1
    return end - index if end < len(text) and text[end] == '"' else 0


def identifier_before(text: str, index: int) -> bool:
    """Whether the `r` at `index` continues an identifier other than the `b` of `br"..."`."""
    if index == 0:
        return False
    before = text[index - 1]
    if before == "b":
        return index >= 2 and (text[index - 2].isalnum() or text[index - 2] == "_")
    return before.isalnum() or before == "_"


def character_literal(text: str, index: int) -> int:
    """The end of the character literal at `index`, or `index + 1` for a lifetime."""
    if text.startswith("\\", index + 1):
        end = text.find("'", index + 3)
        return index + 1 if end < 0 else end + 1
    return index + 3 if text.startswith("'", index + 2) else index + 1


def test_items(text: str, lexed: Lexed) -> list[bool]:
    """For each line, whether a top-level `#[cfg(test)]` item holds it."""
    lines = text.split("\n")
    test = [False] * len(lines)
    number = 0
    while number < len(lines):
        if lines[number].strip() == TEST_ATTRIBUTE and lexed.depth[number] == 0:
            # The item ends at its first `;` at depth 0, or at the `}` that returns to depth 0.
            end = next((n for n in range(number + 1, len(lines)) if lexed.ends[n]), len(lines) - 1)
            for covered in range(number, end + 1):
                test[covered] = True
            number = end + 1
        else:
            number += 1
    return test


def is_test_file(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return name == "tests.rs" or name.endswith("_tests.rs") or "/tests/" in f"/{relative}"



def sources(crate: str) -> list[str]:
    """Rust files under `<crate>/` that Git tracks or does not ignore, relative to it."""
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", crate],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.split("\0")
    prefix = f"{crate}/"
    return sorted(path[len(prefix):] for path in listed if path.endswith(".rs") and (ROOT / path).is_file())


def modules(files: list[str], root: str, read: Callable[[str], str], test_is_condition: bool = True) -> dict[str, bool]:
    """Every file that `root` declares, transitively, and whether it is conditional.

    With `test_is_condition` false, a `#[cfg(test)]` on a declaration is no
    condition: the walk then describes a build of the tests."""
    known = set(files)
    found: dict[str, bool] = {}
    pending = [(root, False)]
    while pending:
        relative, conditional = pending.pop()
        if relative in found:
            raise SourceError(f"{relative} holds a module that two declarations name")
        lexed = lex(read(relative))
        conditional = conditional or INNER_CFG_ATTRIBUTE.search(lexed.text) is not None
        found[relative] = conditional
        name = relative.rsplit("/", 1)[-1]
        base = relative.rsplit("/", 1)[0] if name in ("main.rs", "lib.rs", "mod.rs") else relative.removesuffix(".rs")
        for declared in MODULE_DECLARATION.finditer(lexed.text):
            attributes, module = declared.group(1), declared.group(2)
            if PATH_ATTRIBUTE.search(attributes):
                raise SourceError(f"{relative} declares module {module} with a path attribute; a walk finds a module by its name")
            before = lexed.text[: declared.start(2)]
            if sum(before.count(opened) for opened in "{([") != sum(before.count(closed) for closed in "})]"):
                raise SourceError(f"{relative} declares module {module} inside an inline module; a walk does not follow it")
            candidates = [f"{base}/{module}.rs", f"{base}/{module}/mod.rs"]
            holders = [candidate for candidate in candidates if candidate in known]
            if len(holders) != 1:
                raise SourceError(f"{relative} declares module {module}, and {len(holders)} of {candidates} hold it")
            if not test_is_condition:
                attributes = TEST_CFG_ATTRIBUTE.sub("", attributes)
            pending.append((holders[0], conditional or CFG_ATTRIBUTE.search(attributes) is not None))
    return found
