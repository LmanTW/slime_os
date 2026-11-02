"""Declarations that files must hold, and the controls that show the check refuses a file without them.

A fact is (id, path, pattern, example). The pattern is searched with re.MULTILINE in the file at `path`, and the example
is a line that the pattern must match. A set of facts is judged on a synthetic file set first: it must accept the file set
built from the examples and refuse, by naming the fact, the file set with one example removed. A fact whose example is
also matched by another fact's pattern in the same file would pass that control without being checked, so the control
refuses a set that has one.
"""

from __future__ import annotations

import re
from collections.abc import Callable

Fact = tuple[str, str, str, str]


class FactsError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise FactsError(message)


def check(facts: tuple[Fact, ...], read: Callable[[str], str]) -> int:
    """Every fact holds in the text `read` returns for its path. Returns how many facts held."""
    for name, path, pattern, _example in facts:
        _need(re.search(pattern, read(path), re.MULTILINE) is not None, f"{name}: {path} does not match {pattern}")
    return len(facts)


def honest_corpus(facts: tuple[Fact, ...]) -> dict[str, str]:
    """A synthetic file for each path, holding the example line of every fact."""
    seen: set[str] = set()
    corpus: dict[str, str] = {}
    for name, path, pattern, example in facts:
        _need(name not in seen, f"{name}: two facts have this id")
        seen.add(name)
        _need(re.search(pattern, example, re.MULTILINE) is not None, f"{name}: its example does not match its own pattern")
        corpus[path] = corpus.get(path, "") + example + "\n"
    return corpus


def controls(facts: tuple[Fact, ...]) -> int:
    """Remove each fact's example from the honest corpus. The check has to refuse by naming that fact."""
    corpus = honest_corpus(facts)
    _need(check(facts, corpus.__getitem__) == len(facts), "the honest corpus did not hold every fact")
    refused = 0
    for name, path, _pattern, example in facts:
        altered = dict(corpus)
        altered[path] = corpus[path].replace(example + "\n", "", 1)
        _need(altered[path] != corpus[path], f"{name}: the control removed nothing")
        try:
            check(facts, altered.__getitem__)
        except FactsError as error:
            _need(str(error).startswith(f"{name}:"), f"{name}: refused at the wrong fact: {error}")
        else:
            raise FactsError(f"{name}: the check accepted a file set without it")
        refused += 1
    return refused
