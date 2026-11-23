"""Judge that the Zenoh service keeps reading the control endpoint of a holder that has settled.

A holder settles when it detaches, dies or expires. The service ends a settled holder's session and refuses it every later
request through `Server`, and the host tests of the server half and the roster grade that answer. A request only gets that
answer if the component reads the holder's control endpoint. The component stores the endpoints of a holder in `ends` and
reads only the holders that have an entry, so a component that clears the entry of a settled holder never answers it. The
holder's call on its control endpoint then blocks.

This module reads `components/services/zenoh-service/src/holders.rs` and holds two facts about it. Neither shows what the
code does, only that the two statements that clear an endpoint are gone. The host tests of the server half show what the
answer is, and a boot in which a holder sends after it settled shows that the component sends it. No gate runs that boot
today.

A statement counts wherever it stands in a line of code, so one that shares a line with other code is seen. A `//` comment
is taken out first and is never counted. The judge checks its facts on a synthetic file first. It must accept that file,
refuse each statement put back in several places, and not count a statement inside a comment.
"""

from __future__ import annotations

import re

from harness import ROOT

HOLDERS_FILE = "components/services/zenoh-service/src/holders.rs"
ITEM = ROOT / ".tasks" / "items" / "zenoh-lost-holder-denied.zt"

# The two statements the fix removes. The first clears the entry of a holder after a detach, and the second is inside
# `reclaim`.
FACTS = (
    ("detach-keeps-the-endpoint", "ends[index] = None;", "the detach path clears the holder's endpoint entry"),
    ("reclaim-keeps-the-endpoint", "*end = None;", "`reclaim` clears the holder's endpoint entry"),
)

# The synthetic file the controls start from: the loop reads every named holder, and nothing clears an entry.
HONEST = """\
fn reclaim(server: &mut Server<2>, session: &mut Option<Session>, index: usize) {
    server.lose(index);
}

fn serve(names: &Names) {
    let mut ends: [Option<Endpoints>; 2] = core::array::from_fn(|_| None);
    for index in 0..names.count {
        let Some(end) = ends[index].as_ref() else {
            continue;
        };
        let _ = recv(end.control);
    }
}
"""


class LostHolderError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise LostHolderError(message)


def code_of(text: str) -> str:
    """`text` with each `//` comment taken out and the whitespace of each line collapsed to single spaces."""
    lines = []
    for raw in text.splitlines():
        code = " ".join(raw.split("//", 1)[0].split())
        if code:
            lines.append(code)
    return "\n".join(lines)


def check(text: str) -> int:
    """Every fact holds in `text`: no code in it holds the statement. Returns how many held."""
    code = code_of(text)
    for name, statement, description in FACTS:
        _need(re.search(re.escape(statement), code) is None, f"{name}: {description}")
    return len(FACTS)


def read() -> str:
    try:
        return (ROOT / HOLDERS_FILE).read_text(encoding="utf-8")
    except OSError as error:
        raise LostHolderError(f"{HOLDERS_FILE} cannot be read: {error}") from error


def check_files() -> int:
    return check(read())


def placements(statement: str) -> list[tuple[str, str]]:
    """The honest file with `statement` put back in one way each: the places the real file could hold it."""
    return [
        ("on its own line in the loop", HONEST.replace("let _ = recv", f"{statement}\n        let _ = recv")),
        ("with a tab indent at the end of the file", HONEST + f"\t\t\t{statement}\n"),
        ("after other code on the same line", HONEST.replace("server.lose(index);", f"server.lose(index); {statement}")),
        ("before other code on the same line", HONEST.replace("server.lose(index);", f"{statement} server.lose(index);")),
        ("with spaces inside the statement collapsed to others", HONEST.replace("server.lose(index);", statement.replace(" = ", "  =  "))),
    ]


def controls() -> int:
    """The honest file is accepted and a comment is not counted. Each statement put back is refused at its own fact.
    Returns the refusals."""
    _need(check(HONEST) == len(FACTS), "control: the honest file did not hold every fact")
    for name, statement, _ in FACTS:
        commented = HONEST + f"    // {statement}\n"
        _need(check(commented) == len(FACTS), f"control: a comment holding the {name} statement was counted")
    refused = 0
    seen: dict[str, str] = {}
    for name, statement, _ in FACTS:
        for label, text in placements(statement):
            _need(text != HONEST, f"control: {name} {label} changed nothing")
            _need(text not in seen, f"control: {name} {label} repeats {seen.get(text)}")
            seen[text] = f"{name} {label}"
            try:
                check(text)
            except LostHolderError as error:
                _need(str(error).startswith(f"{name}:"), f"control: {name} {label} was refused at the wrong fact: {error}")
                refused += 1
                continue
            raise LostHolderError(f"control: the judge accepted {name} {label}")
    return refused


PINNED_CASES = 2
PINNED_CONTROLS = 10


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptance fixes, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    refused = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(refused.group(1)) if refused else 0)
