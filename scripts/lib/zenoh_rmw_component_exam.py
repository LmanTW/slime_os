"""Judge that the rmw_zenoh node component exists, is registered, and drives the graph link.

The component is a crate under `components/applications/zenoh-rmw-node`. It runs one `GraphLinkOf` over a TCP
connection of the network service, declares its one subscription on the chat key, writes a Put for each string it
publishes and drains the samples the link queued. This module reads the files by pattern, as
`zenoh_service_component_exam` does for the service, and checks each fact first against a synthetic file set. The
crate itself, the generation that boots it and the QEMU exchange are other items.

What the files hold is text, and text shows that code exists. What the code does is graded elsewhere: the link and
its queue by `zenoh_rmw_data_link_exam`, and the booted exchange by the item that boots it.

This module imports no system spec module and no component spec module.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
from harness import ROOT

COMPONENT = "components/applications/zenoh-rmw-node"
PACKAGE = "slime-component-zenoh-rmw-node"
BINARY = "zenoh-rmw-node"
SPEC = f"contracts/component-spec/v1/components/{BINARY}.zti"
ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-component.zt"

COMPONENT_FACTS: tuple[facts.Fact, ...] = (
    ("crate-package", f"{COMPONENT}/Cargo.toml", rf'^name = "{PACKAGE}"$', f'name = "{PACKAGE}"'),
    ("crate-binary", f"{COMPONENT}/Cargo.toml", rf'^name = "{BINARY}"$', f'name = "{BINARY}"'),
    ("crate-library", f"{COMPONENT}/Cargo.toml", r'^slime-components = \{ path = "\.\./\.\./lib" \}$', 'slime-components = { path = "../../lib" }'),
    ("crate-build-dependency", f"{COMPONENT}/Cargo.toml", r'^slime-build-support = \{ path = "\.\./\.\./build-support" \}$', 'slime-build-support = { path = "../../build-support" }'),
    ("crate-build", f"{COMPONENT}/build.rs", r"^    slime_build_support::configure\(\);$", "    slime_build_support::configure();"),
    ("crate-entry", f"{COMPONENT}/src/main.rs", r"^slime_rt::entry!\(main\);$", "slime_rt::entry!(main);"),
    ("crate-no-std", f"{COMPONENT}/src/main.rs", r"^#!\[no_std\]$", "#![no_std]"),
    ("release-profile", "Cargo.toml", rf"^\[profile\.release\.package\.{PACKAGE}\]$", f"[profile.release.package.{PACKAGE}]"),
    ("lockfile-package", "Cargo.lock", rf'^name = "{PACKAGE}"$', f'name = "{PACKAGE}"'),
    ("uses-graph-link", f"{COMPONENT}/src/main.rs", r"\bGraphLinkOf<", "type Link = GraphLinkOf<Wire, FRAMED, SLOTS, SLOTS, KEY, ENTITIES, QUEUE, SLOT_BYTES>;"),
    ("uses-graph-params", f"{COMPONENT}/src/main.rs", r"\bParams::GRAPH\b", "    let params = Params::GRAPH;"),
    ("declares-subscription", f"{COMPONENT}/src/main.rs", r"\.declare_subscriber\(", "    link.declare_subscriber(handle, SUBSCRIPTION_ID, KEY)?;"),
    ("sends-puts", f"{COMPONENT}/src/main.rs", r"\.send_put\(", "    link.send_put(handle, KEY, &attachment, &payload)?;"),
    ("drains-samples", f"{COMPONENT}/src/main.rs", r"\.pop_sample\(\)", "    while let Some(sample) = link.pop_sample() {"),
    ("uses-network", f"{COMPONENT}/src/main.rs", r"\bNetworkIo::attach", "    let io = NetworkIo::attach_with_notifications(control, provision, base, data, notifications)?;"),
    ("spec-name", SPEC, rf'^\s*name = "{BINARY}";$', f'  name = "{BINARY}";'),
    ("spec-binary", SPEC, rf'^\s*binary = "{BINARY}";$', f'    binary = "{BINARY}";'),
    ("spec-recipe", SPEC, r'requiredTestEnvironment = "zenoh_rmw_component_check"', '    requiredTestEnvironment = "zenoh_rmw_component_check";'),
    ("recipe", "just/hardware.just", r"^zenoh_rmw_component_check:$", "zenoh_rmw_component_check:"),
)

# The calls the crate stands on, in the library the graph link lives in.
LIBRARY_FACTS: tuple[facts.Fact, ...] = (
    ("lib-graph-link", "components/lib/src/lib.rs", r"^pub mod zenoh_rmw_link;$", "pub mod zenoh_rmw_link;"),
    ("lib-queue-accessor", "components/lib/src/zenoh_rmw_link.rs", r"^    pub fn pop_sample\(", "    pub fn pop_sample(&mut self) -> Option<LinkSample<S>> {"),
    ("lib-subscribe", "components/lib/src/zenoh_rmw_link.rs", r"^    pub fn declare_subscriber\(", "    pub fn declare_subscriber("),
    ("lib-put", "components/lib/src/zenoh_rmw_link.rs", r"^    pub fn send_put\(", "    pub fn send_put("),
)

ALL_FACTS = COMPONENT_FACTS + LIBRARY_FACTS


class ComponentExamError(Exception):
    pass


def _wrap(call):
    try:
        return call()
    except facts.FactsError as error:
        raise ComponentExamError(str(error)) from error


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise ComponentExamError(f"{path} cannot be read: {error}") from error


def check_component() -> int:
    """Every fact holds in the repository's files. Returns how many held."""
    return _wrap(lambda: facts.check(ALL_FACTS, read_file))


def component_controls() -> int:
    """Each fact removed from a synthetic file set is refused by name. Returns how many were refused."""
    return _wrap(lambda: facts.controls(ALL_FACTS))


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 23
PINNED_CONTROLS = 23


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
