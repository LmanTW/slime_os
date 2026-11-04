"""Judge the generation builder's Zenoh limits record, and the spec admission that runs it.

`zenoh_limits.encode` turns six limits into record bytes. This module judges the two places that call it: the builder
(`build_zenoh_limits`), which adds what only a manifest knows, and the system spec, which runs the builder at admission.

The builder must emit the encoder's bytes and the independent struct writer's bytes. It must hold the rows to what the
record declares: the holders they name, the keys they subscribe to and the longest key. It must refuse each input the
contract and the manifest forbid, at the boundary that owns the refusal. The spec must refuse a composition that runs the
service without declaring its limits, and limits without their object or an object without limits.

The builder does not check the stack against the rows. The service checks the declared stack against the storage it was
built with, and `zenoh-service-grants/v1` is not a generation input, so this module asserts no stack arithmetic.
Like the other judges it is trusted only after it refuses a wrong builder.
"""

from __future__ import annotations

import copy

import zenoh_limits
import zenoh_limits_exam as exam
from component_spec import admit_specs, interface_catalogue
from harness import ROOT, load_script
from system_spec import (
    SystemSpecError,
    _validate_authority_sections as validate_authority_sections,
    compile_system,
    derive_manifest,
)

SYSTEM = ROOT / "contracts" / "system-spec" / "v1" / "systems" / "sel4-zenoh.zti"
BUILDER = load_script("zenoh_limits_builder_exam_builder", "build/build-generation.py")

KEY = "0/slime_service/exchange"
ROWS = [
    {"holder": "alpha", "key": KEY, "publish": True, "subscribe": False},
    {"holder": "beta", "key": KEY, "publish": False, "subscribe": True},
]
# A second key that alpha publishes and nobody subscribes to. It adds no subscription.
PUBLISH_ONLY = [*ROWS, {"holder": "alpha", "key": "0/slime_service/publish_only", "publish": True, "subscribe": False}]
LIMITS = {"holders": 2, "ringSlots": 4, "sampleBytes": 12, "keyBytes": 129, "localSubscriptions": 3, "stackBytes": 32768}
# The record's field names are snake case and the manifest's are camel case.
FIELDS = {"holders": "holders", "ring_slots": "ringSlots", "sample_bytes": "sampleBytes", "key_bytes": "keyBytes",
          "local_subscriptions": "localSubscriptions", "stack_bytes": "stackBytes"}


def fail(message: str) -> None:
    raise SystemExit(f"zenoh limits builder exam: {message}")


def compiled_system():
    return compile_system(SYSTEM, components={entry.name: entry.spec for entry in admit_specs(catalogue=interface_catalogue())})


def _values(limits: dict[str, int]) -> dict[str, int]:
    return {field: limits[key] for field, key in FIELDS.items()}


def _manifest(system, rows=ROWS, limits=LIMITS, holders=("alpha", "beta")) -> dict:
    """A real manifest with the service and its holders added as instances and the rows and limits set."""
    manifest = derive_manifest(system)
    manifest["instances"] = [*manifest["instances"], *({"name": name} for name in (BUILDER.ZENOH_GRANTS_READER_INSTANCE, *holders))]
    manifest["zenohGrants"] = copy.deepcopy(rows)
    if limits is None:
        manifest.pop("zenohLimits", None)
    else:
        manifest["zenohLimits"] = copy.deepcopy(limits)
    return manifest


def _more_holders(count: int) -> tuple[list[dict], tuple[str, ...]]:
    names = tuple(f"holder{index}" for index in range(count))
    return [{"holder": name, "key": KEY, "publish": False, "subscribe": True} for name in names], names


def controls(system=None) -> tuple[int, int]:
    """The Zenoh limits builder emits the declared record, holds the rows to it, and refuses every malformed input.

    Nothing is written to a file. Returns (honest checks passed, refusals)."""
    system = compiled_system() if system is None else system
    positive = 0

    honest = _manifest(system)
    encoded = BUILDER.build_zenoh_limits(honest)
    if encoded != zenoh_limits.encode(_values(LIMITS)):
        fail("the builder changed the encoder's bytes")
    positive += 1
    if encoded != exam.reference(_values(LIMITS)):
        fail("the builder differs from the independent struct writer")
    positive += 1
    if exam.decode(encoded) != _values(LIMITS):
        fail("the builder emitted a record that does not decode to the declared limits")
    positive += 1
    reverse = copy.deepcopy(honest)
    reverse["zenohGrants"].reverse()
    reverse["instances"].reverse()
    if BUILDER.build_zenoh_limits(reverse) != encoded:
        fail("the record depends on authoring order")
    positive += 1

    # The rows fit exactly at each declared limit, so a builder that refuses at the limit is wrong too.
    for label, rows, limits in (
        ("two holders and two declared", ROWS, dict(LIMITS, holders=2)),
        ("a key exactly as long as the declared key bytes", ROWS, dict(LIMITS, keyBytes=len(KEY))),
        ("one subscribe key and one declared subscription", ROWS, dict(LIMITS, localSubscriptions=1)),
        ("a key that is published and not subscribed does not count as a subscription", PUBLISH_ONLY, dict(LIMITS, localSubscriptions=1)),
    ):
        built = BUILDER.build_zenoh_limits(_manifest(system, rows=rows, limits=limits))
        if built != zenoh_limits.encode(_values(limits)):
            fail(f"the builder's bytes for {label} differ from the encoder's")
        positive += 1

    refused = 0
    third, third_names = _more_holders(1)
    two_keys = [*ROWS, {"holder": "beta", "key": "0/other", "publish": False, "subscribe": True}]
    for label, make, reason in (
        ("two holders named and one declared", lambda: _manifest(system, limits=dict(LIMITS, holders=1)), "name 2 holders"),
        ("three holders named and two declared", lambda: _manifest(system, rows=[*ROWS, *third], holders=("alpha", "beta", *third_names)), "name 3 holders"),
        ("a key one byte over the declared key bytes", lambda: _manifest(system, limits=dict(LIMITS, keyBytes=len(KEY) - 1)), "is longer than"),
        ("two subscribe keys and one declared subscription", lambda: _manifest(system, rows=two_keys, limits=dict(LIMITS, localSubscriptions=1)), "subscribe to 2 keys"),
        ("a limit of zero", lambda: _manifest(system, limits=dict(LIMITS, holders=0)), "the contract allows"),
        ("a limit above its bound", lambda: _manifest(system, limits=dict(LIMITS, ringSlots=65536)), "the contract allows"),
        ("a limit missing", lambda: _manifest(system, limits={k: v for k, v in LIMITS.items() if k != "stackBytes"}), "the contract names"),
        ("an extra limit", lambda: _manifest(system, limits=dict(LIMITS, extra=1)), "the contract names"),
        ("no limits", lambda: _manifest(system, limits=None), "has no limits"),
        ("limits that are not a record", lambda: _manifest(system, limits=[1, 2, 3]), "has no limits"),
        ("no zenoh-service instance", lambda: _without_reader(_manifest(system)), "no zenoh-service instance"),
    ):
        altered = make()
        try:
            BUILDER.build_zenoh_limits(altered)
        except SystemExit as error:
            if reason not in str(error):
                fail(f"zenoh limits {label} refused at the wrong boundary: {error}")
        else:
            fail(f"the limits builder accepted {label}")
        refused += 1

    # A valid spec. The service is added to the spec in memory with its limits set, and the manifest the spec derives must
    # hold the spec's limits and encode to the record those limits give. Without this a derivation that dropped the limits
    # would pass, because every case above hands the builder a manifest of its own.
    valid = copy.deepcopy(system)
    valid.spec["instances"] = [*valid.spec["instances"], {"name": BUILDER.ZENOH_GRANTS_READER_INSTANCE, "executable": "init"}]
    valid.spec["zenohGrants"] = [dict(ROWS[0], holder="ros2-demo-publisher"), dict(ROWS[1], holder="ros2-demo-subscriber")]
    valid.spec["zenohGrantsObject"] = True
    valid.spec["zenohLimits"] = copy.deepcopy(LIMITS)
    valid.spec["zenohLimitsObject"] = True
    try:
        validate_authority_sections(valid.spec, _names(valid))
        derived = derive_manifest(valid)
    except SystemSpecError as error:
        fail(f"the system spec refused a valid spec with limits: {error}")
    if derived.get("zenohLimits") != LIMITS:
        fail("a valid spec's limits did not reach the derived manifest as declared")
    positive += 1
    if BUILDER.build_zenoh_limits(derived) != zenoh_limits.encode(_values(LIMITS)):
        fail("the record built from a valid spec's derived manifest differs from the encoder's bytes for its limits")
    positive += 1
    if not any(entry["id"] == "zenoh-limits" for entry in derived["objects"]):
        fail("a valid spec's derived manifest has no zenoh-limits object")
    positive += 1

    # Spec admission: the spec's own checks run first, and then the builder.
    for label, mutate, reason in (
        ("limits without their object", lambda spec: spec.update(zenohLimitsObject=False), "require their resource object"),
        ("the object without limits", lambda spec: spec.pop("zenohLimits"), "needs its limits"),
        ("the service without the object", lambda spec: spec.update(zenohLimitsObject=False, zenohLimits=None), "must declare it"),
        ("rows above the declared holders", lambda spec: spec["zenohLimits"].update(holders=1), "name 2 holders"),
    ):
        altered = copy.deepcopy(valid)
        mutate(altered.spec)
        try:
            validate_authority_sections(altered.spec, _names(altered))
            derive_manifest(altered)
        except SystemSpecError as error:
            if reason not in str(error):
                fail(f"zenoh limits spec {label} refused at the wrong boundary: {error}")
        else:
            fail(f"the system spec admitted {label}")
        refused += 1
    return positive, refused


def _without_reader(manifest: dict) -> dict:
    manifest["instances"] = [entry for entry in manifest["instances"] if entry["name"] != BUILDER.ZENOH_GRANTS_READER_INSTANCE]
    return manifest


def _names(system) -> set[str]:
    from system_spec import instance_names

    return set(instance_names(system.spec))
