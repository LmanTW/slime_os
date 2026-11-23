"""Judge the TLS dependency of the Zenoh transport before any link uses it.

`docs/decisions/zenoh-link-transports.md` holds the TLS slice until a TLS stack builds `no_std` and passes `cargo deny`
under the policy as it stands. This module owns what the commands must show. Nothing here reads the Rust of the
dependency.

* `slime-components` builds for `aarch64-unknown-none` with and without the `tls` feature.
* `cargo deny check` reports no error in advisories, bans, licenses or sources.
* The parsed `deny.toml` equals the document pinned here, key for key. A key the exam does not name is a change. A graph
  setting, a license exception, a clarification, a severity or a source rule cannot move without a new exam.
* Only `slime-components` declares the TLS crates, as optional dependencies. The `tls` feature is off by default, and no
  workspace member enables it.
* The default graph of the workspace holds none of the TLS crates.
* The `tls` graph holds `rustls` and `getrandom`. It holds no crate that needs a C toolchain or an operating system
  random source.
* Both graphs are resolved for every target, so a crate behind a `cfg` is counted.

The parsers read what `cargo` prints. The controls below run before any command does. A judge is trusted after it
refuses a corrupted observation and a corrupted output.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import tomllib

from harness import ROOT

ITEM = ROOT / ".tasks" / "items" / "zenoh-tls-dependency.zt"
TARGET = "aarch64-unknown-none"
OWNER = "slime-components"
FEATURE = "tls"
CHECKS = ("advisories", "bans", "licenses", "sources")
# Crates the default graph must not hold, and crates the `tls` graph must not hold.
WATCHED = ("rustls", "rustls-webpki", "rustls-rustcrypto", "getrandom", "ring", "aws-lc-rs", "aws-lc-sys")
FORBIDDEN = ("ring", "aws-lc-rs", "aws-lc-sys", "openssl", "openssl-sys", "native-tls")
DECLARED = ("rustls", "getrandom")
# `deny.toml` as it stood when the exam was written. The judge compares the whole parsed file with this document.
POLICY = {'graph': {'all-features': True},
 'advisories': {'version': 2, 'yanked': 'deny'},
 'licenses': {'version': 2,
              'private': {'ignore': True},
              'allow': ['MIT',
                        'Apache-2.0',
                        'ISC',
                        'Apache-2.0 WITH LLVM-exception',
                        'BSD-1-Clause',
                        'BSD-2-Clause',
                        'BSD-3-Clause',
                        'Unicode-3.0',
                        'CC0-1.0',
                        'MPL-2.0',
                        '0BSD'],
              'confidence-threshold': 0.8},
 'bans': {'multiple-versions': 'warn',
          'wildcards': 'deny',
          'allow-wildcard-paths': True,
          'skip-tree': [{'name': 'sel4', 'depth': 20},
                        {'name': 'sel4-root-task', 'depth': 20},
                        {'name': 'sel4-runtime-common', 'depth': 20}]},
 'sources': {'unknown-registry': 'deny',
             'unknown-git': 'deny',
             'allow-git': ['https://github.com/iceice666/zutai.git',
                           'https://github.com/iceice666/dango.git']}}
KEYS = ("build", "deny", "config", "declared", "features", "enablers", "defaultGraph", "tlsGraph")


class TlsError(Exception):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise TlsError(message)


def honest() -> dict:
    """The observation of a tree that has the dependency and passes every check."""
    return {
        "build": {"tls": 0, "plain": 0},
        "deny": {"exit": 0, "advisories": 0, "bans": 0, "licenses": 0, "sources": 0},
        "config": copy.deepcopy(POLICY),
        "declared": {"rustls": [[OWNER, True, False]], "getrandom": [[OWNER, True, False, True]]},
        "features": {"default": ["component-runtime"], "all": ["component-runtime", FEATURE]},
        "enablers": [],
        "defaultGraph": [],
        "tlsGraph": ["getrandom", "rustls", "rustls-rustcrypto", "rustls-webpki"],
    }


def judge(obs: dict) -> int:
    """Returns the number of checks that hold. A check that fails raises, naming it."""
    _need(isinstance(obs, dict) and set(obs) == set(KEYS), f"tls: the observation has the keys {sorted(obs) if isinstance(obs, dict) else obs!r}, the exam requires {sorted(KEYS)}")
    count = 0
    build, deny, config = obs["build"], obs["deny"], obs["config"]
    for name in ("tls", "plain"):
        _need(build.get(name) == 0, f"build {name}: `cargo build --target {TARGET}` exited {build.get(name)}")
        count += 1
    _need(deny.get("exit") == 0, f"deny: `cargo deny check` exited {deny.get('exit')}")
    count += 1
    for name in CHECKS:
        _need(deny.get(name) == 0, f"deny {name}: {deny.get(name)} errors, the exam requires none")
        count += 1
    _need(config == POLICY, f"config: deny.toml differs from the pinned policy at {_difference(config, POLICY)}")
    count += 1
    declared = obs["declared"]
    rustls = declared.get("rustls", [])
    _need(len(rustls) == 1 and rustls[0][0] == OWNER, f"declared: rustls is declared by {[row[0] for row in rustls]}, the exam requires only {OWNER}")
    _need(rustls[0][1] is True and rustls[0][2] is False, f"declared: rustls must be optional with default features off, it is optional={rustls[0][1]} default={rustls[0][2]}")
    count += 2
    random = declared.get("getrandom", [])
    _need(len(random) == 1 and random[0][0] == OWNER, f"declared: getrandom is declared by {[row[0] for row in random]}, the exam requires only {OWNER}")
    _need(random[0][1] is True and random[0][2] is False, f"declared: getrandom must be optional with default features off, it is optional={random[0][1]} default={random[0][2]}")
    _need(random[0][3] is True, "declared: getrandom does not enable `custom`, which a bare-metal target needs for a source of random bytes")
    count += 3
    features = obs["features"]
    _need(FEATURE not in features.get("default", []), f"features: `{FEATURE}` is on by default in {OWNER}")
    _need(FEATURE in features.get("all", []), f"features: {OWNER} has no `{FEATURE}` feature")
    _need(obs["enablers"] == [], f"features: {obs['enablers']} enable `{FEATURE}` of {OWNER}, no component may before one uses it")
    count += 3
    leaked = sorted(set(obs["defaultGraph"]) & set(WATCHED))
    _need(not leaked, f"graph: the default graph holds {leaked}")
    count += 1
    graph = set(obs["tlsGraph"])
    for name in ("rustls", "getrandom"):
        _need(name in graph, f"graph: the `{FEATURE}` graph does not hold {name}")
        count += 1
    bad = sorted(graph & set(FORBIDDEN))
    _need(not bad, f"graph: the `{FEATURE}` graph holds {bad}, which need a C toolchain or an operating system")
    count += 1
    return count


def parse_deny(stderr: str) -> dict:
    """The error count of each check, from the one summary `cargo deny --format json` prints."""
    summaries = []
    for line in stderr.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("type") == "summary":
            summaries.append(value)
    _need(len(summaries) == 1, f"deny: cargo deny printed {len(summaries)} summaries, the exam requires one")
    fields = summaries[0].get("fields")
    _need(isinstance(fields, dict) and set(fields) == set(CHECKS), f"deny: the summary names {sorted(fields) if isinstance(fields, dict) else fields!r}, the exam requires {list(CHECKS)}")
    counts = {}
    for name in CHECKS:
        errors = fields[name].get("errors") if isinstance(fields[name], dict) else None
        _need(isinstance(errors, int) and not isinstance(errors, bool), f"deny: the {name} summary has no error count")
        counts[name] = errors
    return counts


def parse_tree(text: str, first: str | None = None) -> set[str]:
    """The names of the crates `cargo tree --prefix none` printed. With `first`, the first line must name that package."""
    lines = [line for line in text.splitlines() if line.strip()]
    _need(bool(lines), "tree: cargo tree printed nothing")
    _need(not lines[0].startswith(("error", "warning")), f"tree: cargo tree printed {lines[0]!r}")
    names = {line.split()[0] for line in lines}
    if first is not None:
        _need(lines[0].split()[0] == first, f"tree: the first line is {lines[0]!r}, not {first}")
    return names


def parse_metadata(text: str) -> tuple[dict, dict, list]:
    """The declarations of the watched crates, the features of the owner and the members that enable its feature."""
    try:
        document = json.loads(text)
        packages = document["packages"]
    except (ValueError, KeyError, TypeError) as error:
        raise TlsError(f"metadata: cargo metadata printed no package list ({error})") from error
    _need(isinstance(packages, list) and packages, "metadata: cargo metadata listed no package")
    declared: dict = {name: [] for name in DECLARED}
    enablers: list = []
    owner = None
    for package in packages:
        if package.get("name") == OWNER:
            owner = package
        for dependency in package.get("dependencies", []):
            name = dependency.get("name")
            if name in declared:
                row = [package["name"], dependency.get("optional") is True, dependency.get("uses_default_features") is not False]
                if name == "getrandom":
                    row.append("custom" in dependency.get("features", []))
                declared[name].append(row)
            if name == OWNER and FEATURE in dependency.get("features", []):
                enablers.append(package["name"])
    _need(owner is not None, f"metadata: {OWNER} is not a workspace member")
    table = owner.get("features", {})
    features = {"default": sorted(table.get("default", [])), "all": sorted(table)}
    return declared, features, sorted(enablers)


def parse_config(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise TlsError(f"config: deny.toml does not parse ({error})") from error


def _difference(found: object, pinned: object, path: str = "deny.toml") -> str:
    """The first key at which `found` differs from `pinned`, in document order."""
    if isinstance(found, dict) and isinstance(pinned, dict):
        for key in pinned:
            if key not in found:
                return f"{path}.{key} (missing)"
            if found[key] != pinned[key]:
                return _difference(found[key], pinned[key], f"{path}.{key}")
        for key in found:
            if key not in pinned:
                return f"{path}.{key} (not pinned)"
    return path


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)


def observe() -> dict:
    """Run the commands and return what they show. This is the only place that runs a program."""
    build = ["cargo", "build", "--locked", "--target", TARGET, "-p", OWNER, "--no-default-features"]
    plain = _run(build)
    with_tls = _run([*build, "-F", FEATURE])
    deny = _run(["cargo", "deny", "--format", "json", "check"])
    metadata = _run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"])
    _need(metadata.returncode == 0, f"metadata: `cargo metadata` exited {metadata.returncode}")
    default_tree = _run(["cargo", "tree", "--locked", "--workspace", "-e", "normal", "--prefix", "none", "--target", "all"])
    _need(default_tree.returncode == 0, f"tree: `cargo tree --workspace` exited {default_tree.returncode}")
    tls_tree = _run(["cargo", "tree", "--locked", "-p", OWNER, "--no-default-features", "-F", FEATURE, "-e", "normal", "--prefix", "none", "--target", "all"])
    declared, features, enablers = parse_metadata(metadata.stdout)
    config = parse_config((ROOT / "deny.toml").read_text(encoding="utf-8"))
    tls_names = parse_tree(tls_tree.stdout, OWNER) if tls_tree.returncode == 0 else set()
    return {
        "build": {"tls": with_tls.returncode, "plain": plain.returncode},
        "deny": {"exit": deny.returncode, **parse_deny(deny.stderr)},
        "config": config,
        "declared": declared,
        "features": features,
        "enablers": enablers,
        "defaultGraph": sorted(parse_tree(default_tree.stdout) & set(WATCHED)),
        "tlsGraph": sorted(tls_names & set((*WATCHED, *FORBIDDEN))),
    }


def _refused(label: str, obs: object) -> int:
    try:
        judge(obs)  # type: ignore[arg-type]
    except (TlsError, KeyError, TypeError, IndexError, AttributeError):
        return 1
    raise TlsError(f"control: the judge accepted {label}")


def _changed(path: tuple, value: object) -> dict:
    obs = honest()
    node = obs
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = copy.deepcopy(value)
    return obs


def observation_controls() -> int:
    _need(judge(honest()) == CASES, f"control: an honest observation holds {judge(honest())} checks, the exam pins {CASES}")
    refused = 0
    for label, path, value in (
        ("a build with the feature that fails", ("build", "tls"), 101),
        ("a build without the feature that fails", ("build", "plain"), 101),
        ("a cargo deny that exits 1", ("deny", "exit"), 1),
        ("one advisory error", ("deny", "advisories"), 1),
        ("one ban error", ("deny", "bans"), 1),
        ("one license error", ("deny", "licenses"), 1),
        ("one source error", ("deny", "sources"), 1),
        ("rustls declared by two packages", ("declared", "rustls"), [[OWNER, True, False], ["zenoh-service", True, False]]),
        ("rustls declared by another package", ("declared", "rustls"), [["zenoh-service", True, False]]),
        ("rustls not optional", ("declared", "rustls"), [[OWNER, False, False]]),
        ("rustls with default features", ("declared", "rustls"), [[OWNER, True, True]]),
        ("rustls not declared", ("declared", "rustls"), []),
        ("getrandom without custom", ("declared", "getrandom"), [[OWNER, True, False, False]]),
        ("getrandom not declared", ("declared", "getrandom"), []),
        ("getrandom declared by two packages", ("declared", "getrandom"), [[OWNER, True, False, True], ["zenoh-service", True, False, True]]),
        ("getrandom not optional", ("declared", "getrandom"), [[OWNER, False, False, True]]),
        ("the feature on by default", ("features", "default"), ["component-runtime", FEATURE]),
        ("no tls feature", ("features", "all"), ["component-runtime"]),
        ("a component that enables the feature", ("enablers", ), ["zenoh-service"]),
        ("rustls in the default graph", ("defaultGraph",), ["rustls"]),
        ("getrandom in the default graph", ("defaultGraph",), ["getrandom"]),
        ("a tls graph with no rustls", ("tlsGraph",), ["getrandom"]),
        ("a tls graph with no getrandom", ("tlsGraph",), ["rustls"]),
        ("a tls graph with ring", ("tlsGraph",), ["getrandom", "ring", "rustls"]),
        ("a tls graph with aws-lc-sys", ("tlsGraph",), ["aws-lc-sys", "getrandom", "rustls"]),
        ("a tls graph with openssl-sys", ("tlsGraph",), ["getrandom", "openssl-sys", "rustls"]),
    ):
        refused += _refused(label, _changed(path, value))
    for label, edit in (
        ("a license added to the allow list", lambda c: c["licenses"]["allow"].append("Zlib")),
        ("a license removed from the allow list", lambda c: c["licenses"]["allow"].pop(0)),
        ("a license exception for one crate", lambda c: c["licenses"].update(exceptions=[{"allow": ["Zlib"], "crate": "foldhash"}])),
        ("a license clarification", lambda c: c["licenses"].update(clarify=[{"crate": "foldhash", "expression": "MIT", "license-files": []}])),
        ("a lower license confidence", lambda c: c["licenses"].update({"confidence-threshold": 0.5})),
        ("all features off in the graph", lambda c: c["graph"].update({"all-features": False})),
        ("a crate excluded from the graph", lambda c: c["graph"].update(exclude=["rustls"])),
        ("yanked crates only warned about", lambda c: c["advisories"].update(yanked="warn")),
        ("one advisory ignored", lambda c: c["advisories"].update(ignore=["RUSTSEC-2024-0399"])),
        ("a crate added to the skip tree", lambda c: c["bans"]["skip-tree"].append({"name": "rustls", "depth": 20})),
        ("a crate removed from the skip tree", lambda c: c["bans"]["skip-tree"].pop(0)),
        ("one crate skipped in bans", lambda c: c["bans"].update(skip=[{"name": "rustls-webpki"}])),
        ("wildcards only warned about", lambda c: c["bans"].update(wildcards="warn")),
        ("a git source added", lambda c: c["sources"]["allow-git"].append("https://github.com/example/crate.git")),
        ("an unknown git source only warned about", lambda c: c["sources"].update({"unknown-git": "warn"})),
        ("an organisation allowed", lambda c: c["sources"].update({"allow-org": {"github": ["rustls"]}})),
        ("an empty policy", lambda c: c.clear()),
    ):
        obs = honest()
        edit(obs["config"])
        refused += _refused(label, obs)
    for key in KEYS:
        obs = honest()
        del obs[key]
        refused += _refused(f"an observation without {key}", obs)
    obs = honest()
    obs["extra"] = 1
    refused += _refused("an observation with a key the exam does not name", obs)
    return refused


def _deny_text(errors: dict | None = None) -> str:
    counts = {name: 0 for name in CHECKS} if errors is None else errors
    fields = {name: {"errors": counts.get(name, 0), "helps": 0, "notes": 3, "warnings": 1} for name in CHECKS}
    return "\n".join((json.dumps({"type": "diagnostic", "fields": {"severity": "warning"}}), json.dumps({"type": "summary", "fields": fields})))


def _metadata_text() -> str:
    def package(name: str, dependencies: list) -> dict:
        return {"name": name, "dependencies": dependencies, "features": {"default": ["component-runtime"], "component-runtime": [], FEATURE: ["dep:rustls"]} if name == OWNER else {}}

    return json.dumps({"packages": [
        package(OWNER, [
            {"name": "rustls", "optional": True, "uses_default_features": False, "features": []},
            {"name": "getrandom", "optional": True, "uses_default_features": False, "features": ["custom"]},
        ]),
        package("zenoh-service", [{"name": OWNER, "optional": False, "uses_default_features": True, "features": []}]),
    ]})


def parser_controls() -> int:
    _need(parse_deny(_deny_text()) == {name: 0 for name in CHECKS}, "control: an honest cargo deny summary was misread")
    _need(parse_deny(_deny_text({"licenses": 2}))["licenses"] == 2, "control: a summary with two license errors was misread")
    _need(parse_tree(f"{OWNER} v0.1.0\nrustls v0.23.46\n", OWNER) == {OWNER, "rustls"}, "control: an honest cargo tree was misread")
    declared, features, enablers = parse_metadata(_metadata_text())
    _need(declared == {"rustls": [[OWNER, True, False]], "getrandom": [[OWNER, True, False, True]]}, "control: honest cargo metadata declarations were misread")
    _need(features == {"default": ["component-runtime"], "all": sorted(["component-runtime", FEATURE, "default"])}, "control: honest cargo metadata features were misread")
    _need(enablers == [], "control: honest cargo metadata enablers were misread")
    _need(parse_config("[graph]\nall-features = true\n") == {"graph": {"all-features": True}}, "control: an honest deny.toml was misread")
    refused = 0
    for label, call in (
        ("a cargo deny with no summary", lambda: parse_deny("not json\n{}")),
        ("a cargo deny with two summaries", lambda: parse_deny(_deny_text() + "\n" + _deny_text())),
        ("a summary without the bans check", lambda: parse_deny(json.dumps({"type": "summary", "fields": {k: {"errors": 0} for k in CHECKS if k != "bans"}}))),
        ("a summary whose error count is a string", lambda: parse_deny(json.dumps({"type": "summary", "fields": {k: {"errors": "0"} for k in CHECKS}}))),
        ("a summary whose error count is a boolean", lambda: parse_deny(json.dumps({"type": "summary", "fields": {k: {"errors": False} for k in CHECKS}}))),
        ("an empty cargo tree", lambda: parse_tree("\n", OWNER)),
        ("a cargo tree that printed an error", lambda: parse_tree("error: failed to load manifest\n")),
        ("a cargo tree for another package", lambda: parse_tree("rustls v0.23.46\n", OWNER)),
        ("cargo metadata that is not JSON", lambda: parse_metadata("error: no manifest")),
        ("cargo metadata with no package", lambda: parse_metadata('{"packages": []}')),
        ("a deny.toml that does not parse", lambda: parse_config("[graph\nall-features")),
        ("cargo metadata without the owner", lambda: parse_metadata('{"packages": [{"name": "other", "dependencies": []}]}')),
    ):
        try:
            call()
        except TlsError:
            refused += 1
        else:
            raise TlsError(f"control: the parser accepted {label}")
    enabling = json.loads(_metadata_text())
    enabling["packages"][1]["dependencies"][0]["features"] = [FEATURE]
    _need(parse_metadata(json.dumps(enabling))[2] == ["zenoh-service"], "control: a member that enables the feature was not named")
    return refused


CASES = 20
CONTROLS = 64


def all_controls() -> int:
    return observation_controls() + parser_controls()


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptance fixes, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    refused = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(refused.group(1)) if refused else 0)
