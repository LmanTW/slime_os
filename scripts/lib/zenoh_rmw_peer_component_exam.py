"""Judge that the rmw_zenoh native peer component exists, is registered, and drives a plain link.

The peer is a crate under `components/applications/zenoh-rmw-peer`. It is a plain Profile 0 connector. It dials
the rmw_zenoh node component, waits for the node's subscription on the chatter key, publishes a Put on that key
for each string it sends, and counts what it receives. It is the native side of the booted exchange: the node
runs a graph link, so a peer that is not a graph session needs a plain link whose key and payload bounds fit the
chatter key and a `std_msgs/String`.

This module reads the files by pattern, as `zenoh_rmw_component_exam` does for the node, and checks each fact
first against a synthetic file set. What the crate does when it runs is the booted composition's to judge.

This module imports no system spec module and no component spec module.
"""

from __future__ import annotations

import re

import zenoh_facts as facts
from harness import ROOT

COMPONENT = "components/applications/zenoh-rmw-peer"
PACKAGE = "slime-component-zenoh-rmw-peer"
BINARY = "zenoh-rmw-peer"
SPEC = f"contracts/component-spec/v1/components/{BINARY}.zti"
ITEM = ROOT / ".tasks" / "items" / "zenoh-rmw-peer.zt"

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
    ("uses-plain-link", f"{COMPONENT}/src/main.rs", r"\bLinkOf<", "type Link<'a, 'b> = LinkOf<Stream<Wire<'a, 'b>>, FRAMED, 1, 2, KEY, PAYLOAD, NOTICES>;"),
    ("uses-link-params", f"{COMPONENT}/src/main.rs", r"\bLink::with_params\(", "        let mut link = Link::with_params(Stream::new(wire), &config, params, 1)"),
    ("builds-a-connector", f"{COMPONENT}/src/main.rs", r"\bRole::Connector\b", "            Role::Connector,"),
    ("declares-a-subscription", f"{COMPONENT}/src/main.rs", r"\.declare_subscriber\(", "    link.declare_subscriber(handle, SUBSCRIPTION_ID, CHAT_KEY)?;"),
    ("dials-the-node", f"{COMPONENT}/src/main.rs", r"\.connect_ipv4\(", "    let connection = io.connect_ipv4(node::ENDPOINT, node::PORT)"),
    ("opens-the-session", f"{COMPONENT}/src/main.rs", r"\blink\.open\(", "    link.open(handle, now)?;"),
    ("publishes-puts", f"{COMPONENT}/src/main.rs", r"\.publish\(", "    link.publish(handle, CHAT_KEY, &attachment, &payload)?;"),
    ("reads-samples", f"{COMPONENT}/src/main.rs", r"\bNotice::SampleDelivered\(", "            Notice::SampleDelivered(sample) => {"),
    ("waits-for-the-subscription", f"{COMPONENT}/src/main.rs", r"\bNotice::SubscriberDeclared\b", "            Notice::SubscriberDeclared { .. } => subscribed = true,"),
    ("uses-network", f"{COMPONENT}/src/main.rs", r"\bNetworkIo::attach", "    let io = NetworkIo::attach_with_notifications(control, provision, base, data, notifications)?;"),
    ("spec-name", SPEC, rf'^\s*name = "{BINARY}";$', f'  name = "{BINARY}";'),
    ("spec-binary", SPEC, rf'^\s*binary = "{BINARY}";$', f'    binary = "{BINARY}";'),
    ("spec-recipe", SPEC, r'requiredTestEnvironment = "zenoh_rmw_peer_check"', '    requiredTestEnvironment = "zenoh_rmw_peer_check";'),
    ("recipe", "just/hardware.just", r"^zenoh_rmw_peer_check:$", "zenoh_rmw_peer_check:"),
)

# The calls the crate stands on, in the library the plain link lives in.
LIBRARY_FACTS: tuple[facts.Fact, ...] = (
    ("lib-plain-link", "components/lib/src/lib.rs", r"^pub mod zenoh_link;$", "pub mod zenoh_link;"),
    ("lib-with-params", "components/lib/src/zenoh_link.rs", r"^    pub fn with_params\(", "    pub fn with_params("),
    ("lib-publish", "components/lib/src/zenoh_link.rs", r"^    pub fn publish\(", "    pub fn publish("),
    ("lib-notices", "components/lib/src/zenoh_link.rs", r"^    pub fn next_notice\(", "    pub fn next_notice(&mut self) -> Option<Notice<P>> {"),
)

ALL_FACTS = COMPONENT_FACTS + LIBRARY_FACTS


class PeerExamError(Exception):
    pass


def _wrap(call):
    try:
        return call()
    except facts.FactsError as error:
        raise PeerExamError(str(error)) from error


def read_file(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except OSError as error:
        raise PeerExamError(f"{path} cannot be read: {error}") from error


def check_component() -> int:
    """Every fact holds in the repository's files. Returns how many held."""
    return _wrap(lambda: facts.check(ALL_FACTS, read_file))


def component_controls() -> int:
    """Each fact removed from a synthetic file set is refused by name. Returns how many were refused."""
    return _wrap(lambda: facts.controls(ALL_FACTS))


# What the item fixes, held here as well so the gate stays correct after the item is closed and moved to
# .tasks/terminal. While the item is open its stored predicates are compared with these. Both are exact.
PINNED_CASES = 27
PINNED_CONTROLS = 27


def item_pins() -> tuple[int, int]:
    """The case and control counts the item's acceptances fix, or (0, 0) when the item is not in `.tasks/items`."""
    if not ITEM.is_file():
        return 0, 0
    text = ITEM.read_text(encoding="utf-8")
    cases = re.search(r'h\.count "casesObserved" (\d+)', text)
    controls = re.search(r'h\.count "negativeControlsRefused" (\d+)', text)
    return (int(cases.group(1)) if cases else 0, int(controls.group(1)) if controls else 0)
