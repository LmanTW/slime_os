"""Audit that every component console write is one whole line.

The root and console thread already print each accepted record whole
(`console_record_controls`); what can still split a serial line is a component
that builds one line from several writes, because a root line may land between
them. This audit is lexical over tracked sources:

* Rust: every `debug_write(...)` call outside the record sinks passes one byte
  string literal that ends in a newline. A record sink (`console_line.rs`) may
  pass a built record. `debug_write` may otherwise appear only in a `use` list
  without `as`; any other mention (a function value, an alias, a second
  definition) is refused. The two transport files that define and forward it
  are byte-pinned by `console_record_controls` and are not audited here.
* C: no component source outside `components/runtime/c` and
  `components/runtime/include` names `slime_debug_write`; C components write
  through the runtime's line-buffered API.

It is not a parser, a macro expander, or a data-flow proof. A refused pattern is
a source fact; the planes this audit runs beside judge the serial output.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping

from console_record_controls import _rust_code

RECORD_SINKS = frozenset(
    {
        "components/lib/src/console_line.rs",
        "components/runtime/src/console_line.rs",
    }
)
DEFINITIONS = frozenset(
    {
        "components/runtime/src/syscall.rs",
        "components/runtime/src/syscall/sel4_transport.rs",
    }
)
C_RUNTIME_ROOTS = ("components/runtime/c/", "components/runtime/include/")
# Under `components/` and no component: the child program of the root fixture.
# It prints through the kernel's debug sink, one byte for each call, and this
# audit claims nothing about it. The caller leaves these paths out.
NOT_COMPONENTS = ("components/root-child/",)
LIFECYCLE_ROOTS = ("components/system/", "components/services/", "components/applications/", "components/testkit/")
REQUIRED_SINK = "components/lib/src/console_line.rs"

WHOLE_LITERAL = re.compile(r'b"(?:[^"\\]|\\.)*\\n"\s*,?')
WHOLE_RAW = re.compile(r'br(#*)"(?:(?!"\1).)*\n"\1\s*,?', re.S)
RUST_TOKEN = re.compile(r"\bdebug_write\b")
C_TOKEN = re.compile(r"\bslime_debug_write\b")


class AuditError(Exception):
    """A tracked source can write part of a console line."""


def _c_code(text: str) -> str:
    """Mask C comments and string/character literals, keeping line positions."""
    output: list[str] = []
    cursor = 0
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'', re.S)
    for match in pattern.finditer(text):
        output.append(text[cursor : match.start()])
        output.append("".join("\n" if char == "\n" else " " for char in match.group(0)))
        cursor = match.end()
    output.append(text[cursor:])
    return "".join(output)


def _statement_start(code: str, position: int) -> int:
    """Index after the last statement or block boundary before `position`."""
    return max(code.rfind(";", 0, position), code.rfind("{", 0, position), code.rfind("}", 0, position)) + 1


def _in_use_list(code: str, position: int) -> bool:
    head = code[_statement_start(code, position) : position]
    # A brace-list import: walk back over the enclosing `{` of `use a::{...}`.
    start = code.rfind("{", 0, position)
    if start >= 0 and code.find("}", start, position) < 0:
        prefix = code[_statement_start(code, start) : start]
        if re.match(r"\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?use\b", prefix):
            return True
    return re.match(r"\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?use\b", head) is not None


def _closing_paren(code: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    raise AuditError("unbalanced debug_write call")


def _line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def rust_violations(path: str, text: str) -> list[str]:
    """Every place in one Rust source that can write part of a line."""
    if path in DEFINITIONS:
        return []
    code = _rust_code(text)
    found: list[str] = []
    for match in RUST_TOKEN.finditer(code):
        start, end = match.span()
        where = f"{path}:{_line_of(text, start)}"
        after = code[end:]
        if re.match(r"\s+as\b", after):
            found.append(f"{where}: debug_write is renamed")
            continue
        if re.search(r"\bfn\s+$", code[max(0, start - 8) : start]):
            found.append(f"{where}: a second debug_write is defined")
            continue
        if _in_use_list(code, start):
            continue
        call = re.match(r"\s*\(", after)
        if call is None:
            found.append(f"{where}: debug_write is used other than as a call")
            continue
        opening = end + call.end() - 1
        closing = _closing_paren(code, opening)
        if path in RECORD_SINKS:
            continue
        argument = text[opening + 1 : closing].strip()
        if not (WHOLE_LITERAL.fullmatch(argument) or WHOLE_RAW.fullmatch(argument)):
            shown = argument if len(argument) <= 60 else argument[:57] + "..."
            found.append(f"{where}: debug_write({shown}) is not one whole-line literal")
    return found


def c_violations(path: str, text: str) -> list[str]:
    if path.startswith(C_RUNTIME_ROOTS):
        return []
    code = _c_code(text)
    return [f"{path}:{_line_of(text, match.start())}: a C component calls slime_debug_write directly" for match in C_TOKEN.finditer(code)]


def audit(sources: Mapping[str, str]) -> dict[str, int]:
    """Refuse any partial-line write; return the counts examined.

    `sources` maps every tracked `components/**/*.rs`, `*.c` and `*.h` path to
    its text.
    """
    outside = sorted(path for path in sources if path.startswith(NOT_COMPONENTS))
    if outside:
        raise AuditError(f"{outside[0]} is no component; the summary counts component sources only")
    rust = {path: text for path, text in sources.items() if path.endswith(".rs")}
    c = {path: text for path, text in sources.items() if path.endswith((".c", ".h"))}
    for root in LIFECYCLE_ROOTS:
        if not any(path.startswith(root) for path in rust):
            raise AuditError(f"no Rust source under {root} was examined")
    if REQUIRED_SINK not in rust:
        raise AuditError(f"{REQUIRED_SINK} was not examined")
    if not any(not path.startswith(C_RUNTIME_ROOTS) for path in c):
        raise AuditError("no C component source was examined")
    found: list[str] = []
    calls = 0
    for path in sorted(rust):
        found.extend(rust_violations(path, rust[path]))
        calls += len(RUST_TOKEN.findall(_rust_code(rust[path])))
    for path in sorted(c):
        found.extend(c_violations(path, c[path]))
    if found:
        shown = "\n  ".join(found[:12])
        more = f"\n  ... and {len(found) - 12} more" if len(found) > 12 else ""
        raise AuditError(f"{len(found)} partial-line console writes:\n  {shown}{more}")
    return {"rust_files": len(rust), "c_files": len(c), "debug_write_mentions": calls}


# --- refusal controls -------------------------------------------------------

_HONEST = {
    "components/system/a/src/main.rs": 'use slime_rt::{debug_write, exit};\nfn main() {\n    // debug_write(b"partial") in a comment\n    let _ = "debug_write(b\\"x\\")";\n    debug_write(b"[a] ready\\n");\n    slime_rt::debug_write(\n        b"[a] two\\nlines\\n",\n    );\n}\n',
    "components/services/b/src/main.rs": 'fn main() { slime_rt::debug_write(br#"[b] raw\n"#); }\n',
    "components/applications/c/src/main.rs": "fn main() { slime_components::console_line::Line::<64>::new().bytes(b\"[c] x\").emit(); }\n",
    "components/testkit/d/src/main.rs": "pub use slime_rt::debug_write;\nfn main() {}\n",
    REQUIRED_SINK: "pub fn emit(record: &[u8]) { slime_rt::debug_write(record); }\n",
    "components/runtime/src/syscall.rs": "pub fn debug_write(bytes: &[u8]) -> i64 { transport::debug_write(bytes) }\n",
    "components/runtime/c/component_runtime.c": "void slime_debug_write(const uint8_t *b, size_t n) { }\n",
    "components/slisp/main.c": '/* slime_debug_write(x) */\nstatic const char *s = "slime_debug_write";\nvoid f(void) { slime_line_write(s, 1); }\n',
}


def _with(path: str, text: str) -> dict[str, str]:
    return {**_HONEST, path: text}


def _without(prefix: str) -> dict[str, str]:
    return {path: text for path, text in _HONEST.items() if not path.startswith(prefix)}


def controls() -> int:
    """Run the honest tree and every refusal control; return the number refused."""
    counts = audit(_HONEST)
    if counts["rust_files"] != 6 or counts["c_files"] != 2:
        raise AuditError(f"the honest control tree examined {counts}")
    probe = "components/testkit/d/src/main.rs"
    cases: list[tuple[str, Callable[[], object]]] = [
        ("partial literal", lambda: audit(_with(probe, 'fn f() { debug_write(b"[d] value="); }\n'))),
        ("literal without newline", lambda: audit(_with(probe, 'fn f() { debug_write(b"[d] done "); }\n'))),
        ("newline not last", lambda: audit(_with(probe, 'fn f() { debug_write(b"[d] a\\nb"); }\n'))),
        ("built buffer", lambda: audit(_with(probe, "fn f(buf: &[u8]) { debug_write(&buf[..4]); }\n"))),
        ("qualified built buffer", lambda: audit(_with(probe, "fn f(d: &[u8]) { slime_rt::debug_write(d); }\n"))),
        ("call split across lines", lambda: audit(_with(probe, 'fn f() {\n    debug_write(\n        b"[d] part",\n    );\n}\n'))),
        ("raw partial", lambda: audit(_with(probe, 'fn f() { debug_write(br"[d] raw"); }\n'))),
        ("literal plus expression", lambda: audit(_with(probe, 'fn f(x: &[u8]) { debug_write(if true { b"[d]\\n" } else { x }); }\n'))),
        ("renamed import", lambda: audit(_with(probe, "use slime_rt::debug_write as write;\nfn f() {}\n"))),
        ("function value", lambda: audit(_with(probe, "fn f() { let w = slime_rt::debug_write; w(b\"x\"); }\n"))),
        ("forwarding macro", lambda: audit(_with(probe, "macro_rules! p { ($x:expr) => { slime_rt::debug_write($x) }; }\n"))),
        ("second definition", lambda: audit(_with(probe, "fn debug_write(b: &[u8]) {}\n"))),
        ("sink outside the declared files", lambda: audit(_with("components/lib/src/console_line2.rs", "pub fn emit(r: &[u8]) { slime_rt::debug_write(r); }\n"))),
        ("C component calls the writer", lambda: audit(_with("components/slisp/main.c", "void f(void) { slime_debug_write(p, n); }\n"))),
        ("C component header calls the writer", lambda: audit({**_HONEST, "components/slisp/out.h": "static inline void w(void) { slime_debug_write(p, n); }\n"})),
        ("a source that is no component", lambda: audit(_with("components/root-child/src/main.rs", "fn main() {}\n"))),
        ("no system source", lambda: audit(_without("components/system/"))),
        ("no testkit source", lambda: audit(_without("components/testkit/"))),
        ("no record sink", lambda: audit({path: text for path, text in _HONEST.items() if path != REQUIRED_SINK})),
        ("no C component", lambda: audit({path: text for path, text in _HONEST.items() if path != "components/slisp/main.c"})),
    ]
    for name, case in cases:
        try:
            case()
        except AuditError:
            continue
        raise AuditError(f"control {name!r} was accepted")
    return len(cases)
