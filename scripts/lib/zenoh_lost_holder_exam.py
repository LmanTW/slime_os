"""Judge that the Zenoh service keeps reading the control endpoint of a holder that has settled.

A holder settles when it detaches, dies or expires. The service ends a settled holder's session and refuses it every later
request through `Server`, and the host tests of the server half and the roster grade that answer. A request only gets that
answer if the component reads the holder's control endpoint. The component stores the endpoints of a holder in `ends` and
reads only the holders that have an entry, so a component that clears the entry of a settled holder never answers it. The
holder's call on its control endpoint then blocks.

This module reads `components/services/zenoh-service/src/holders.rs` and holds two facts about it. Neither shows what the
code does, only that the two places that clear an endpoint are gone. The host tests of the server half show what the answer
is, and a boot in which a holder sends after it settled shows that the component sends it. No gate runs that boot today.

The judge checks its two facts on a synthetic file first. It must accept the synthetic file without the lines and refuse it
with each line added, and it must not count a line in a comment.
"""

from __future__ import annotations

import re

from harness import ROOT

HOLDERS_FILE = "components/services/zenoh-service/src/holders.rs"
ITEM = ROOT / ".tasks" / "items" / "zenoh-lost-holder-denied.zt"

# What the component does today, and the two lines the fix removes. The first clears the entry of a holder after a
# detach, and the second is inside `reclaim`.
CLEARS_ON_DETACH = "ends[index] = None;"
CLEARS_ON_RECLAIM = "*end = None;"

# One line of a file that a pattern must not match, with the text of a comment taken out first.
FACTS = (
    ("detach-keeps-the-endpoint", CLEARS_ON_DETACH, "the detach path clears the holder's endpoint entry"),
    ("reclaim-keeps-the-endpoint", CLEARS_ON_RECLAIM, "`reclaim` clears the holder's endpoint entry"),
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


def code_lines(text: str) -> list[str]:
    """The lines of `text` with each `//` comment taken out, as a stripped line. A comment alone leaves no line."""
    lines = []
    for raw in text.splitlines():
        code = raw.split("//", 1)[0].strip()
        if code:
            lines.append(code)
    return lines


def check(text: str) -> int:
    """Every fact holds in `text`. Returns how many held."""
    lines = code_lines(text)
    for name, line, description in FACTS:
        _need(line not in lines, f"{name}: {description}")
    return len(FACTS)


def read() -> str:
    try:
        return (ROOT / HOLDERS_FILE).read_text(encoding="utf-8")
    except OSError as error:
        raise LostHolderError(f"{HOLDERS_FILE} cannot be read: {error}") from error


def check_files() -> int:
    return check(read())


def controls() -> int:
    """The honest file is accepted, a comment is not counted, and each cleared entry is refused. Returns the refusals."""
    _need(check(HONEST) == len(FACTS), "control: the honest file did not hold every fact")
    for name, line, _ in FACTS:
        commented = HONEST + f"    // {line}\n"
        _need(check(commented) == len(FACTS), f"control: a comment holding the {name} line was counted")
    refused = 0
    for name, line, _ in FACTS:
        for label, text in (
            (f"the {name} line in the loop", HONEST.replace("let _ = recv", f"{line}\n        let _ = recv")),
            (f"the {name} line with another indent", HONEST + f"\t\t\t{line}\n"),
            (f"the {name} line after code on the same line", HONEST + f"    foo(); {line}\n".replace("foo(); ", "")),
        ):
            _need(text != HONEST, f"control: {label} changed nothing")
            try:
                check(text)
            except LostHolderError as error:
                _need(str(error).startswith(f"{name}:"), f"control: {label} was refused at the wrong fact: {error}")
                refused += 1
                continue
            raise LostHolderError(f"control: the judge accepted {label}")
    unreadable = re.sub(r"\n", "", HONEST)
    _need(unreadable != HONEST, "control: the one-line file changed nothing")
    try:
        check(HONEST.replace("fn reclaim", f"{CLEARS_ON_RECLAIM}\nfn reclaim"))
    except LostHolderError:
        refused += 1
    else:
        raise LostHolderError("control: the judge accepted a cleared entry above `reclaim`")
    return refused


PINNED_CASES = 2
PINNED_CONTROLS = 7


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptance fixes, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    refused = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(refused.group(1)) if refused else 0)
