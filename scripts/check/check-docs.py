#!/usr/bin/env python3

"""Validate maintained documentation without fetching or reading a history corpus.

Local links and canonical work-item references are checked in every docs page
and PR template. Literal Just invocations are checked in
current documentation, live task requirements, scripts and CI execution fields;
historical task outcomes do not promise recipe presence.
History URLs pin a full commit but are never opened. Just metadata is local.

`--smoltcp-matrix` checks the network plan's smoltcp support matrix against the
lockfile, the network service's enabled features and the pinned crate archive
(`scripts/lib/smoltcp_matrix.py`). It reads Cargo's registry cache, so it is a
separate mode; the default run exercises only its offline controls.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "lib"))

import argparse
import ast
import re
import shlex
import tempfile
from urllib.parse import unquote

import yaml

from harness import ROOT
from just_metadata import recipes
from markdown_anchors import anchors, controls as anchor_controls
from work_items import FIELD, UUID, identities, items, retired, without_consumer_records
import smoltcp_matrix

REQUIRED_ACTIVE_DOCUMENTS = (
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "HUMAN.md",
    "docs/README.md",
    ".github/PULL_REQUEST_TEMPLATE/change.md",
    ".github/PULL_REQUEST_TEMPLATE/system-change.md",
)
MARKDOWN_LINK = re.compile(r"\]\(([^)\s]+)\)")
EXTERNAL_LINK_PREFIXES = ("http://", "https://", "mailto:")
HISTORY_BASE = "https://git.justaslime.dev/iceice666/slime_os-history/"
HISTORY_URL = re.compile(re.escape(HISTORY_BASE) + r"[^\s<>`\)\]]*")
HISTORY_COMMIT = re.compile(re.escape(HISTORY_BASE) + r"src/commit/[0-9a-f]{40}(?:/|$)")
HISTORY_LINK = re.compile(r"\[[^\]]*\]\(" + re.escape(HISTORY_BASE) + r"[^)\s]+\)")
UUID_REFERENCE = re.compile(
    r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"
)
CODE_SPAN = re.compile(r"(`+)([^`]+)\1")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
RECIPE_NAME = re.compile(r"[a-zA-Z_][a-zA-Z_0-9-]*")


def active_documents(root: _Path = ROOT) -> tuple[_Path, ...]:
    """Discover whole documentation families, including future architecture pages."""
    return tuple(
        dict.fromkeys(
            (
                *(root / relative for relative in REQUIRED_ACTIVE_DOCUMENTS),
                *sorted((root / "docs").rglob("*.md")),
                *sorted((root / "contracts").rglob("*.md")),
                *sorted((root / ".tasks" / "items").glob("*.md")),
                *sorted((root / ".github" / "PULL_REQUEST_TEMPLATE").rglob("*.md")),
                *sorted((root / ".github").glob("pull_request_template.md")),
                *sorted((root / ".github").glob("PULL_REQUEST_TEMPLATE.md")),
            )
        )
    )


def checks_commands(path: _Path, root: _Path = ROOT) -> bool:
    """Current indexes are checked; retained delivery narratives are link-only."""
    relative = path.relative_to(root)
    return (
        relative.parts[:2] != (".tasks", "items")
        and relative.parts[:4] != ("contracts", "generation-manifest", "v1", "compositions")
    )


def document_reference_failures(
    path: _Path,
    text: str,
    *,
    item_root: _Path = ROOT / ".tasks" / "items",
    known_items: frozenset[str] | None = None,
    retired_items: frozenset[str] | None = None,
) -> list[str]:
    """Validate local Markdown destinations, fragments, and work-item links."""
    found: list[str] = []
    known = identities() if known_items is None else known_items
    gone = retired() if retired_items is None else retired_items
    linked_work_items: set[str] = set()
    for target in dict.fromkeys(HISTORY_URL.findall(text)):
        if not HISTORY_COMMIT.match(target):
            found.append(f"{path}: history URL must use src/commit/<full 40-hex commit>: {target}")
    for target in dict.fromkeys(MARKDOWN_LINK.findall(text)):
        if target.startswith(EXTERNAL_LINK_PREFIXES):
            continue
        base, _, fragment = target.partition("#")
        destination = (path.parent / unquote(base)) if base else path
        resolved = destination.resolve()
        is_work_item = resolved.parent == item_root.resolve() and resolved.suffix == ".md"
        reference = resolved.stem
        if is_work_item:
            linked_work_items.add(reference)
            if not UUID.fullmatch(reference):
                found.append(f"{path}: work-item link {target} does not use a canonical UUID")
                continue
            if reference not in known:
                found.append(f"{path}: work-item link {target} names absent UUID {reference}")
                continue
            if reference in gone:
                # A retired item's identity is its terminal record; the
                # Markdown body it used to have lives only in Git history, so
                # the canonical path is a resolvable reference, not a document.
                continue
        if not destination.exists():
            found.append(f"{path}: dead relative link {target}")
        elif fragment and (
            not destination.is_file() or unquote(fragment) not in anchors(destination)
        ):
            found.append(
                f"{path}: link {target} names no heading or explicit anchor in {destination}"
            )

    # An archive URL names historical content, not an item in the current store.
    local_text = HISTORY_URL.sub("", text)
    for reference in dict.fromkeys(UUID_REFERENCE.findall(local_text)):
        if reference not in linked_work_items and reference not in known:
            found.append(f"{path}: references absent work-item UUID {reference}")
    return found


def literal_commands(text: str) -> list[str]:
    """Read inline code and shell/plain fenced examples, not ordinary prose or URLs."""
    literals: list[str] = []
    fence = ""
    shell = False
    outside: list[str] = []
    for line in text.splitlines():
        match = FENCE.match(line)
        if match:
            delimiter, language = match.groups()
            if not fence:
                fence = delimiter
                shell = language.strip() in {"", "sh", "bash", "shell", "console"}
            elif delimiter[0] == fence[0] and len(delimiter) >= len(fence) and not language.strip():
                fence = ""
            continue
        if fence:
            if shell:
                literals.append(line)
        else:
            outside.append(line)
    literals.extend(match.group(2) for match in CODE_SPAN.finditer("\n".join(outside)))
    return literals


def command_reference_failures(path: _Path, text: str, known_recipes: dict[str, dict]) -> list[str]:
    """Check literal recipe names; patterns and Just's own options are not recipes."""
    found: list[str] = []
    for literal in literal_commands(HISTORY_LINK.sub("", text)):
        # Match an invocation, not a historical URL containing a command name.
        for command in re.split(r"&&|\|\||;", literal):
            command = " ".join(command.split()).removeprefix("$ ")
            if not command.startswith("just "):
                continue
            try:
                words = shlex.split(command, comments=True)[1:]
            except ValueError as error:
                found.append(f"{path}: malformed literal Just command {command!r}: {error}")
                continue
            index = 0
            while index < len(words):
                name = words[index]
                # Global flags and variable assignments precede recipes. Options
                # taking a value consume that value, not a recipe reference.
                if name.startswith("-") or "=" in name:
                    index += 1
                    if name in {
                        "--justfile",
                        "-f",
                        "--working-directory",
                        "-d",
                        "--shell",
                        "--shell-arg",
                        "--dump-format",
                    }:
                        index += 1
                    elif name == "--set":
                        index += 2
                    continue
                # Recipe-family globs and example placeholders are not literals.
                if not RECIPE_NAME.fullmatch(name):
                    break
                if name not in known_recipes:
                    found.append(f"{path}: literal just command names absent recipe {name!r}")
                    break
                parameters = known_recipes[name].get("parameters", [])
                index += 1
                for parameter in parameters:
                    if index >= len(words):
                        break
                    if parameter.get("kind", "singular") != "singular":
                        index = len(words)
                        break
                    if parameter.get("default") is not None and words[index] in known_recipes:
                        break
                    index += 1
    return list(dict.fromkeys(found))


def task_requirements(text: str) -> str:
    """Only unfinished items' requirement sections, never Gate/Observed evidence."""
    state = FIELD["state"].search(text.split("---", 2)[1] if text.startswith("---\n") else "")
    if state is None or state.group("value") not in {"open", "active", "blocked", "deferred"}:
        return ""
    selected: list[str] = []
    active = False
    history_level: int | None = None
    for line in text.splitlines():
        heading = re.match(r"^(#{2,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            level = len(heading[1])
            title = heading[2].casefold()
            if level == 2:
                active = title in {"scope", "requirements", "exit conditions", "verification"}
            if history_level is not None and level <= history_level:
                history_level = None
            if re.match(r"(?:gates?|observed|outcomes?|evidence|history)\b", title):
                history_level = level
        if active and history_level is None:
            selected.append(line)
    return "\n".join(selected)


def machine_consumers(root: _Path = ROOT) -> tuple[_Path, ...]:
    return tuple(
        sorted(
            path
            for directory, suffixes in (
                (root / "scripts", {".py", ".sh"}),
                (root / ".github" / "workflows", {".yml", ".yaml"}),
                (root / ".github" / "actions", {".yml", ".yaml"}),
            )
            for path in directory.rglob("*")
            if path.is_file() and path.suffix in suffixes
        )
    )


def shell_commands(text: str) -> list[str]:
    """Repo shell subset: simple commands, chains, timeout/nix and sh -c wrappers.

    Not a shell interpreter: no variable expansion, eval, functions or heredocs.
    Tokenization keeps quoted prose and comments out of executable positions.
    """
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    lexer = shlex.shlex(text.replace("\\\n", ""), posix=True, punctuation_chars=";&|()<>\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    segments: list[list[str]] = [[]]
    comment = False
    for word in lexer:
        if word and all(character in ";&|()<>\n" for character in word):
            comment = comment and "\n" not in word
            segments.append([])
        elif comment:
            continue
        elif word.startswith("#"):
            comment = True
        else:
            segments[-1].append(word)
    commands: list[str] = []
    for words in segments:
        while words and ("=" in words[0] or words[0] in {"then", "do", "exec"}):
            words = words[1:]
        if words[:1] == ["timeout"] and len(words) >= 3:
            words = words[2:]
        if words[:2] == ["nix", "develop"] and "--command" in words:
            words = words[words.index("--command") + 1 :]
        if words[:1] in (["bash"], ["sh"]) and len(words) >= 3:
            if words[1].startswith("-") and "c" in words[1]:
                commands.extend(shell_commands(words[2]))
        elif words[:1] == ["just"]:
            commands.append(shlex.join(words))
    return commands


def python_commands(text: str) -> list[str]:
    """Inspect subprocess calls, not comments, docstrings or command fixtures.

    Literal argv prefixes are enough to check the recipe even with dynamic
    arguments. Computed commands and custom execution wrappers are out of scope.
    """
    tree = ast.parse(text)
    modules = {"subprocess"}
    functions: set[str] = set()
    runners = {"run", "call", "check_call", "check_output", "Popen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(
                alias.asname or alias.name for alias in node.names if alias.name == "subprocess"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            functions.update(
                alias.asname or alias.name for alias in node.names if alias.name in runners
            )
    commands: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if not (
            isinstance(function, ast.Name)
            and function.id in functions
            or isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in modules
            and function.attr in runners
        ):
            continue
        argument = (
            node.args[0]
            if node.args
            else next((keyword.value for keyword in node.keywords if keyword.arg == "args"), None)
        )
        if isinstance(argument, (ast.List, ast.Tuple)):
            words = []
            for element in argument.elts:
                if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                    break
                words.append(element.value)
            if words[:1] == ["just"]:
                commands.append(shlex.join(words))
            elif words[:1] in (["bash"], ["sh"]) and len(words) >= 3:
                if words[1].startswith("-") and "c" in words[1]:
                    commands.extend(shell_commands(words[2]))
        elif isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                commands.extend(shell_commands(argument.value))
    return commands


def ci_commands(value: object) -> list[str]:
    """Parse executable CI fields, including the workflow matrices' recipe names."""
    commands: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "recipe" and isinstance(child, str):
                commands.extend(shell_commands(f"just {child}"))
            elif key == "run" and isinstance(child, str):
                commands.extend(shell_commands(child))
            else:
                commands.extend(ci_commands(child))
    elif isinstance(value, list):
        for child in value:
            commands.extend(ci_commands(child))
    return commands


def machine_reference_failures(path: _Path, text: str, known_recipes: dict[str, dict]) -> list[str]:
    try:
        if path.suffix == ".py":
            commands = python_commands(text)
        elif path.suffix == ".sh":
            commands = shell_commands(text)
        else:
            commands = ci_commands(yaml.safe_load(text))
    except (SyntaxError, ValueError, yaml.YAMLError) as error:
        return [f"{path}: cannot read literal recipe consumers: {error}"]
    return command_reference_failures(
        path, "```sh\n" + "\n".join(commands) + "\n```", known_recipes
    )


def controls() -> list[str]:
    """Prove broken references fail and historical-only commands remain harmless."""
    failures = [f"anchor control: {failure}" for failure in anchor_controls()]
    present = "00000000-0000-0000-0000-000000000001"
    absent = "00000000-0000-0000-0000-000000000002"
    gone = "00000000-0000-0000-0000-000000000003"
    with tempfile.TemporaryDirectory() as temporary:
        root = _Path(temporary)
        for relative in REQUIRED_ACTIVE_DOCUMENTS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# Required\n")
        source = root / "README.md"
        target = root / "target.md"
        target.write_text("# Existing heading\n")
        item_root = root / ".tasks" / "items"
        item_root.mkdir(parents=True)
        (item_root / f"{present}.md").write_text("# Present\n")
        cases = (
            ("valid", f"[doc](target.md#existing-heading) [item](.tasks/items/{present}.md)", ()),
            ("missing path", "[doc](missing.md)", ("dead relative link",)),
            ("missing fragment", "[doc](target.md#missing)", ("names no heading",)),
            ("noncanonical UUID", "[item](.tasks/items/not-an-id.md)", ("canonical UUID",)),
            ("absent UUID", f"[item](.tasks/items/{absent}.md)", ("absent UUID",)),
            ("absent plain UUID", absent, ("absent work-item UUID",)),
            (
                "retired UUID keeps resolving without a document",
                f"[item](.tasks/items/{gone}.md) {gone}",
                (),
            ),
            (
                "immutable history",
                f"[just retired_check]({HISTORY_BASE}src/commit/{'a' * 40}/devlog/missing.md)",
                (),
            ),
            (
                "mutable history",
                f"[history]({HISTORY_BASE}src/branch/main/devlog/missing.md)",
                ("full 40-hex commit",),
            ),
        )
        for name, document, signals in cases:
            found = document_reference_failures(
                source,
                document,
                item_root=item_root,
                known_items=frozenset({present, gone}),
                retired_items=frozenset({gone}),
            )
            if len(found) != len(signals) or any(
                signal not in failure for signal, failure in zip(signals, found, strict=True)
            ):
                failures.append(f"reference control {name}: expected {signals}, got {found}")
        future = root / "docs" / "architecture" / "future.md"
        future.parent.mkdir(parents=True)
        future.write_text("# Future\n")
        future_contract = root / "contracts" / "future" / "README.md"
        future_contract.parent.mkdir(parents=True)
        future_contract.write_text("# Contract\n")
        discovered = active_documents(root)
        if future not in discovered:
            failures.append("discovery control: new architecture page was not discovered")
        if future_contract not in discovered or (item_root / f"{present}.md") not in discovered:
            failures.append(
                "discovery control: contract docs or work-item evidence was not discovered"
            )
        if any(not path.is_file() for path in discovered) or (root / "devlog").exists():
            failures.append("discovery control: docs-only tree requires missing files or devlog")
        command_cases = (
            (source, "`just current_check`", False),
            (source, "`just removed_check`", True),
            (source, "```sh\njust removed_check\n```", True),
            (source, "`just current_check removed_check`", True),
            (source, "`just\nremoved_check`", True),
            (source, "`just --quiet removed_check`", True),
            (source, f"[`just retired_check`]({HISTORY_BASE}src/commit/{'a' * 40}/old.md)", False),
            (
                source,
                f"[`just retired_check`]({HISTORY_BASE}src/commit/{'a' * 40}/old.md) `just removed_check`",
                True,
            ),
            (item_root / f"{present}.md", "`just retired_check`", False),
        )
        for path, document, expected in command_cases:
            found = (
                command_reference_failures(path, document, {"current_check": {}})
                if checks_commands(path, root)
                else []
            )
            if bool(found) != expected:
                failures.append(
                    f"command control {document!r}: expected failure={expected}, got {found}"
                )
        live_item = "---\nstate: open\n---\n## Scope\n`just removed_check`\n"
        history = "## Gate\n`just retired_check`\n## Observed\n`just retired_check`\n"
        for document, expected in (
            (live_item + history, True),
            (live_item.replace("removed_check", "current_check") + history, False),
            (live_item.replace("state: open", "state: done") + history, False),
            ("---\nstate: active\n---\n## Verification\n### Observed\n`just retired_check`", False),
        ):
            found = command_reference_failures(
                item_root / f"{present}.md", task_requirements(document), {"current_check": {}}
            )
            if bool(found) != expected:
                failures.append(f"task consumer control: expected failure={expected}, got {found}")
        machine_cases = (
            (
                "scripts/consumer.py",
                "import subprocess\nsubprocess.run(['just', 'removed_check'])",
                True,
            ),
            (
                "scripts/consumer.py",
                "from subprocess import run\nrun('just removed_check', shell=True)",
                True,
            ),
            (
                "scripts/consumer.py",
                "import subprocess\nsubprocess.run(['just', 'removed_check', dynamic])",
                True,
            ),
            (
                "scripts/consumer.py",
                "# just retired_check\nexample = ['just', 'retired_check']",
                False,
            ),
            (
                "scripts/consumer.py",
                "import subprocess\nsubprocess.run(['just', '--dump', '--dump-format', 'json'])",
                False,
            ),
            (
                "scripts/consumer.sh",
                "# just retired_check\necho 'just retired_check'\njust $RECIPE",
                False,
            ),
            ("scripts/consumer.sh", "just removed_check # active invocation", True),
            (
                "scripts/consumer.sh",
                "nix build .#kani; nix develop .#kani --command just removed_check",
                True,
            ),
            (
                ".github/workflows/consumer.yml",
                "jobs:\n  check:\n    strategy:\n      matrix:\n        include:\n        - recipe: removed_check\n",
                True,
            ),
            (
                ".github/workflows/consumer.yml",
                "jobs:\n  check:\n    steps:\n    - run: |\n        just current_check\n        just removed_check\n",
                True,
            ),
            (
                ".github/workflows/consumer.yml",
                "jobs:\n  check:\n    steps:\n    - run: nix develop --command just removed_check",
                True,
            ),
            (
                ".github/workflows/consumer.yml",
                "# just retired_check\nname: just retired_check\nrun: echo 'just retired_check'",
                False,
            ),
        )
        for relative, text, expected in machine_cases:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            found = machine_reference_failures(path, text, {"current_check": {}})
            absent_recipe = any("absent recipe 'removed_check'" in failure for failure in found)
            if (expected and not absent_recipe) or (not expected and found):
                failures.append(
                    f"machine consumer control {relative}: expected failure={expected}, got {found}"
                )
            if path not in machine_consumers(root):
                failures.append(f"machine discovery control: missed {relative}")
    return failures


def consumer_record_controls() -> list[str]:
    """A consumer record's own identities are not work-item references."""
    failures: list[str] = []
    epoch = "3f2b9c11-4d5e-4a7b-9c2d-8e1f0a6b5c44"
    parent = "00000000-0000-7000-8000-000000000001"
    item = (
        "---\nschema: work-item/v2\nid: 00000000-0000-7000-8000-000000000002\n"
        "kind: task\nstate: open\ncreated: 2026-09-15T10:00:00Z\n"
        f"parent: {parent}\ndevloop:\n  epoch: {epoch}\n  evidence: []\n---\n\n# Control\n"
    )
    scanned = without_consumer_records(item)
    if epoch in scanned:
        failures.append("consumer record control: a devloop identity was read as a reference")
    if parent not in scanned:
        failures.append("consumer record control: a MyQue-owned parent reference was dropped")
    if "# Control" not in scanned:
        failures.append("consumer record control: the item body was dropped")
    return failures


def smoltcp_matrix_main() -> int:
    failures = smoltcp_matrix.controls()
    failures += smoltcp_matrix.check(
        states={str(item["id"]): str(item["state"]) for item in items()},
        recipes=frozenset(recipes()),
    )
    for failure in failures:
        print(f"smoltcp matrix: {failure}")
    if failures:
        print(f"smoltcp matrix check failed with {len(failures)} problem(s)")
        return 1
    print(
        "smoltcp matrix: the pinned release, its advertised features and the network "
        "service's enabled set agree with docs/plans/network-data-plane.md"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--smoltcp-matrix",
        action="store_true",
        help="check the smoltcp support matrix against the pinned release",
    )
    if parser.parse_args().smoltcp_matrix:
        return smoltcp_matrix_main()
    failures = controls() + consumer_record_controls() + smoltcp_matrix.controls()
    known_recipes = recipes()
    known_items = identities()
    documents = active_documents()
    for path in documents:
        if not path.is_file():
            failures.append(f"{path}: maintained document is missing")
            continue
        text = path.read_text()
        is_work_item = path.relative_to(ROOT).parts[:2] == (".tasks", "items")
        # A consumer's frontmatter record carries identities of its own — a
        # devloop run epoch is a UUID, and names no work item — so only
        # MyQue-owned metadata and the body are read as references.
        scanned = without_consumer_records(text) if is_work_item else text
        failures.extend(document_reference_failures(path, scanned, known_items=known_items))
        if checks_commands(path):
            failures.extend(command_reference_failures(path, text, known_recipes))
        elif is_work_item:
            failures.extend(
                command_reference_failures(path, task_requirements(text), known_recipes)
            )
    consumers = machine_consumers()
    for path in consumers:
        failures.extend(machine_reference_failures(path, path.read_text(), known_recipes))
    for recipe in known_recipes.values():
        body = "\n".join(
            "".join(part if isinstance(part, str) else "" for part in line)
            for line in recipe.get("body", [])
        )
        commands = shell_commands(body)
        failures.extend(
            command_reference_failures(
                ROOT / "Justfile", "```sh\n" + "\n".join(commands) + "\n```", known_recipes
            )
        )
    for failure in failures:
        print(f"docs: {failure.replace(f'{ROOT}/', '')}")
    if failures:
        print(f"docs check failed with {len(failures)} problem(s)")
        return 1
    print(
        f"docs: checked {len(documents)} maintained documents and {len(consumers)} script/CI files; "
        "local links, fragments, UUIDs and current Just commands pass"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
