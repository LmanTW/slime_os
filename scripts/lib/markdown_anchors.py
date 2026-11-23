"""The fragment ids a Markdown file's links may name, over a declared subset.

An inbound `…#fragment` link is an address. Rewording a heading changes that
address while leaving the file in place, so the failure has no symptom at the
destination — which is why `check-docs.py` validates fragments rather than
stripping them, and why this computation lives in one tested place.

Scope, stated exactly rather than as "GitHub's rules":

* **Headings** are ATX (`#`–`######`) outside fenced code. A fence's contents
  are literal text and produce no heading, so a documentation example showing
  `## Removed heading` must not manufacture that anchor.
* **Slugs** lowercase the heading, drop its Markdown syntax, delete punctuation
  that is not a word character or hyphen, and join words with hyphens. Inline
  code contributes its *literal* text: `` `release_trust_check` `` keeps its
  underscores, because they are code, not emphasis.
* **Duplicates** take an incrementing suffix in document order — the second
  `## Verification` is `#verification-1`. Slugs repeat in this repository's
  `docs/plans/` pages, so this is load-bearing rather than hypothetical.
* **Explicit anchors** are `<a id="…">` and `<a name="…">`, used to retain an
  address a heading no longer produces.

Deliberately outside scope: Setext headings (`===`/`---` underlines), which this
repository does not use; HTML `<h1>`–`<h6>` elements; and heading text spanning
multiple lines. Each would be silent under-approximation, so `controls()` pins
the supported set as executable cases.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

ATX = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
EXPLICIT = re.compile(r"<a\s+[^>]*?(?:id|name)\s*=\s*\"([^\"]+)\"")

# Inline code spans, whose contents are literal. Captured first and held aside
# so later emphasis and punctuation stripping cannot reach inside them.
CODE_SPAN = re.compile(r"`+([^`]*)`+")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
EMPHASIS = re.compile(r"(\*+|_+)")
DROP = re.compile(r"[^\w\- ]", re.UNICODE)


def slug(heading: str) -> str:
    """A heading's fragment id, before any duplicate suffix."""
    text = IMAGE.sub(r"\1", heading.strip())
    text = LINK.sub(r"\1", text)
    # Split on inline code so emphasis stripping cannot reach inside it:
    # `budget_us` must keep its underscore, which is code rather than markup.
    # Odd positions are the captured code spans. A sentinel would be simpler
    # and wrong — punctuation stripping deletes any character that is not a
    # word character, sentinel included.
    parts = CODE_SPAN.split(text)
    rendered = [
        DROP.sub("", part if index % 2 else EMPHASIS.sub("", part))
        for index, part in enumerate(parts)
    ]
    return "".join(rendered).lower().replace(" ", "-")


def outside_fences(text: str) -> Iterator[str]:
    """Every line that is neither inside a fenced block nor its delimiter.

    A closing fence must use the same character and be at least as long as the
    one that opened it, so a ```` ```` ```` block may contain a ``` ``` ``` line
    without ending — which is exactly how this repository's documentation shows
    fenced examples.
    """
    fence: tuple[str, int] | None = None
    for line in text.splitlines():
        marker = FENCE.match(line)
        if marker is not None:
            token = marker.group(1)
            if fence is None:
                fence = (token[0], len(token))
                continue
            character, length = fence
            if token[0] == character and len(token) >= length:
                fence = None
            continue
        if fence is None:
            yield line


def headings(text: str) -> list[str]:
    """Every ATX heading's text, in document order, fenced code excluded."""
    found: list[str] = []
    for line in outside_fences(text):
        heading = ATX.match(line)
        if heading is not None:
            found.append(heading.group(2))
    return found


def anchors_in(text: str) -> frozenset[str]:
    """Every fragment a link into ``text`` may name."""
    found: set[str] = set()
    counts: dict[str, int] = {}
    for heading in headings(text):
        base = slug(heading)
        seen = counts.get(base, 0)
        counts[base] = seen + 1
        found.add(base if seen == 0 else f"{base}-{seen}")
    for line in outside_fences(text):
        found.update(EXPLICIT.findall(line))
    return frozenset(found)


@lru_cache(maxsize=None)
def anchors(path: Path) -> frozenset[str]:
    """``anchors_in`` for a file, cached per path."""
    return anchors_in(path.read_text())


# Every case the scope above claims, as `(name, document, present, absent)`.
# Executable rather than prose: an anchor rule that is only described drifts
# from the one that runs, and both directions matter — a missed anchor rejects
# a valid link, a phantom anchor accepts a dead one.
CONTROLS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "a fenced example produces no anchor",
        "# Real heading\n\n```markdown\n## Removed heading\n```\n",
        ("real-heading",),
        ("removed-heading",),
    ),
    (
        "a tilde fence also suppresses headings",
        "# Real heading\n\n~~~\n## Removed heading\n~~~\n",
        ("real-heading",),
        ("removed-heading",),
    ),
    (
        "a longer fence does not close on a shorter one",
        "# Real\n\n````\n```\n## Removed heading\n```\n````\n",
        ("real",),
        ("removed-heading",),
    ),
    (
        "duplicate headings take an incrementing suffix",
        "## Verification\n\none\n\n## Verification\n\ntwo\n\n## Verification\n",
        ("verification", "verification-1", "verification-2"),
        ("verification-3",),
    ),
    (
        "inline code keeps its literal underscores",
        "### B30 — `release_trust_check` was red\n",
        ("b30--release_trust_check-was-red",),
        ("b30--releasetrustcheck-was-red",),
    ),
    (
        "emphasis is stripped but its text is kept",
        "## A *bold* claim\n",
        ("a-bold-claim",),
        ("a-claim",),
    ),
    (
        "link text contributes, the target does not",
        "## See [the report](../report.md)\n",
        ("see-the-report",),
        ("see-the-reportreportmd",),
    ),
    (
        "punctuation is dropped, hyphens survive",
        "## P5.4.9 — C8.9 typed full-profile closure\n",
        ("p549--c89-typed-full-profile-closure",),
        (),
    ),
    (
        "explicit anchors are addressable",
        '<a id="retained-address"></a>\n\n## New wording\n',
        ("retained-address", "new-wording"),
        (),
    ),
    (
        "an explicit anchor inside a fence is an example, not an address",
        '# Real\n\n```html\n<a id="example-only"></a>\n```\n',
        ("real",),
        ("example-only",),
    ),
    (
        "closing hashes are not part of the slug",
        "## Balanced ##\n",
        ("balanced",),
        ("balanced-",),
    ),
)


def controls() -> list[str]:
    """Run every control; return the failures, empty when all hold."""
    failures: list[str] = []
    for name, document, present, absent in CONTROLS:
        found = anchors_in(document)
        for fragment in present:
            if fragment not in found:
                failures.append(f"{name}: expected anchor {fragment!r}, got {sorted(found)}")
        for fragment in absent:
            if fragment in found:
                failures.append(f"{name}: anchor {fragment!r} must not exist, got {sorted(found)}")
    return failures
