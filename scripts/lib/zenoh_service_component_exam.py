"""Judge that the Zenoh service component exists, is registered, and is composed with its holders.

Two sets of facts, each read from the files by pattern and each checked first against a synthetic file set. The component
set covers the crate under `components/services/zenoh-service`, its registration, and the library export the crate
stands on. The composition set covers the system spec, the manifest derived from it, the composition inventory row and the
booted gate's arm in `check-sel4-io-network-plane.py`.

What the files hold is text, and text shows that code exists. What the code does is graded elsewhere: the server half by
`zenoh_server_exam`, the reader by `zenoh_grants_reader_exam`, and the booted exchange by the marker chains of the arm,
which the arm's own checker runs under QEMU. The composition recipe runs that arm after the facts hold.

This module imports no system spec module and no component spec module.
"""

from __future__ import annotations

import zenoh_facts as facts
from harness import ROOT

COMPONENT = "components/services/zenoh-service"
PACKAGE = "slime-component-zenoh-service"
SYSTEM = "sel4-zenoh-service"
PLANE = "scripts/check/check-sel4-io-network-plane.py"

COMPONENT_FACTS: tuple[facts.Fact, ...] = (
    ("crate-package", f"{COMPONENT}/Cargo.toml", rf'^name = "{PACKAGE}"$', f'name = "{PACKAGE}"'),
    ("crate-binary", f"{COMPONENT}/Cargo.toml", r'^name = "zenoh-service"$', 'name = "zenoh-service"'),
    ("crate-build", f"{COMPONENT}/build.rs", r"^fn main\(\) \{ slime_build_support::configure\(\); \}$", "fn main() { slime_build_support::configure(); }"),
    ("crate-entry", f"{COMPONENT}/src/main.rs", r"^slime_rt::entry!\(main\);$", "slime_rt::entry!(main);"),
    ("release-profile", "Cargo.toml", rf"^\[profile\.release\.package\.{PACKAGE}\]$", f"[profile.release.package.{PACKAGE}]"),
    ("reads-grants", f"{COMPONENT}/src/main.rs", r"\bzenoh_grants_read\(", "    let count = zenoh_grants_read(cursor, &mut page)?;"),
    ("decodes-grants", f"{COMPONENT}/src/main.rs", r"\bTable::decode\(", "    let table = Table::decode(&object[..len])?;"),
    ("uses-server", f"{COMPONENT}/src/main.rs", r"\bzenoh_service_server::", "use slime_components::zenoh_service_server::Server;"),
    ("uses-core", f"{COMPONENT}/src/main.rs", r"\bzenoh_service::Core\b", "use slime_components::zenoh_service::Core;"),
    ("uses-link", f"{COMPONENT}/src/main.rs", r"\bLinkOf::with_params\(", "    let link = LinkOf::with_params(io, Role::Connector, &config, params, 0)?;"),
    ("uses-network", f"{COMPONENT}/src/main.rs", r"\bNetworkIo::attach", "    let io = NetworkIo::attach(control, provision, base)?;"),
    ("lib-export", "components/lib/src/lib.rs", r"^pub mod zenoh_service_server;$", "pub mod zenoh_service_server;"),
    ("server-test", "components/lib/src/zenoh_service_server.rs", r"^    fn the_server_exam\(\) \{$", "    fn the_server_exam() {"),
    ("spec-name", "contracts/component-spec/v1/components/zenoh-service.zti", r'^\s*name = "zenoh-service";$', '  name = "zenoh-service";'),
    ("spec-binary", "contracts/component-spec/v1/components/zenoh-service.zti", r'^\s*binary = "zenoh-service";$', '    binary = "zenoh-service";'),
    ("spec-recipe", "contracts/component-spec/v1/components/zenoh-service.zti", r'requiredTestEnvironment = "zenoh_service_booted_check"',
     '      requiredTestEnvironment = "zenoh_service_booted_check";'),
)

COMPOSITION_FACTS: tuple[facts.Fact, ...] = (
    ("spec-name", f"contracts/system-spec/v1/systems/{SYSTEM}.zti", rf'^\s*name = "{SYSTEM}";$', f'  name = "{SYSTEM}";'),
    ("spec-instance", f"contracts/system-spec/v1/systems/{SYSTEM}.zti", r'\{ name = "zenoh-service"; executable = "zenoh-service"',
     '    { name = "zenoh-service"; executable = "zenoh-service"; };'),
    ("spec-grants-object", f"contracts/system-spec/v1/systems/{SYSTEM}.zti", r"^\s*zenohGrantsObject = true;$", "  zenohGrantsObject = true;"),
    ("spec-grants", f"contracts/system-spec/v1/systems/{SYSTEM}.zti", r"^\s*zenohGrants = \[$", "  zenohGrants = ["),
    ("spec-network", f"contracts/system-spec/v1/systems/{SYSTEM}.zti", r"\bnetworkApplications\b[^\n]*\n(?:.*\n)*?.*\bzenoh-service\b",
     "  networkApplications = [\n    { holder = \"zenoh-service\"; };\n  ];"),
    ("manifest-instance", f"contracts/generation-manifest/v1/compositions/{SYSTEM}.zti", r'\bname = "zenoh-service"', '    { name = "zenoh-service"; };'),
    ("manifest-grants", f"contracts/generation-manifest/v1/compositions/{SYSTEM}.zti", r"^\s*zenohGrants = \[$", "  zenohGrants = ["),
    ("inventory-row", "contracts/composition-inventory/v1/inventory.zti", rf'composition = "{SYSTEM}";', f'      composition = "{SYSTEM}";'),
    ("inventory-gate", "contracts/composition-inventory/v1/inventory.zti", r'owningGate = "zenoh_service_booted_check";', '      owningGate = "zenoh_service_booted_check";'),
    ("test-run-record", f"contracts/system-test-run/v2/runs/{SYSTEM}.zti", rf'^\s*closure = "{SYSTEM}";$', f'  closure = "{SYSTEM}";'),
    ("arm-choice", PLANE, r'"zenoh-service"', 'choices=("zenoh", "zenoh-service")'),
    ("arm-function", PLANE, r"^def run_zenoh_service_arm\(", "def run_zenoh_service_arm(transcript_path: Path | None) -> None:"),
    ("arm-chains", PLANE, r"^ZENOH_SERVICE_CHAINS\b", "ZENOH_SERVICE_CHAINS: tuple[tuple[str, tuple[str, ...]], ...] = ("),
    ("arm-grant-refusal", PLANE, r"zenoh-service\\?\] denial class=not-granted refused=1", '        r"\\[zenoh-service\\] denial class=not-granted refused=1",'),
    ("arm-exchange", PLANE, r"zenoh-service\\?\] holder attached", '        r"\\[zenoh-service\\] holder attached",'),
    ("recipe", "just/hardware.just", r"^zenoh_service_booted_check:$", "zenoh_service_booted_check:"),
)


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
    return _wrap(lambda: facts.check(COMPONENT_FACTS, read_file))


def check_composition() -> int:
    return _wrap(lambda: facts.check(COMPOSITION_FACTS, read_file))


def component_controls() -> int:
    return _wrap(lambda: facts.controls(COMPONENT_FACTS))


def composition_controls() -> int:
    return _wrap(lambda: facts.controls(COMPOSITION_FACTS))
