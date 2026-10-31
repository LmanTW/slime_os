"""Judge the generation builder's Zenoh grants table, and the spec admission that runs it.

`zenoh_grants_table.encode` turns rows into table bytes. This module judges the two places that call it: the builder
(`build_zenoh_grants_table`), which adds what only a manifest knows, and the system spec, which runs the builder at
admission. No composition has a `zenoh-service` instance yet, so the manifest is a real one with that instance added
and the spec is a real one with grants set in memory.

The builder must emit the encoder's bytes, the independent struct writer's bytes, and bytes that decode to the declared
rows, whatever order the rows and instances come in. It must refuse each input the contract and the manifest forbid, at
the boundary that owns the refusal. Like the other judges it is trusted only after it refuses a mutation of the builder.
"""

from __future__ import annotations

import copy

from component_spec import admit_specs, interface_catalogue
import zenoh_grants_table
import zenoh_grants_table_exam as exam
from harness import ROOT, load_script
from system_spec import (
    SystemSpecError,
    _validate_authority_sections as validate_authority_sections,
    compile_system,
    derive_manifest,
    instance_names,
)

SYSTEM = ROOT / "contracts" / "system-spec" / "v1" / "systems" / "sel4-zenoh.zti"
BUILDER = load_script("zenoh_grants_builder_exam_builder", "build/build-generation.py")


def fail(message: str) -> None:
    raise SystemExit(f"zenoh grants builder exam: {message}")


def compiled_system():
    return compile_system(SYSTEM, components={entry.name: entry.spec for entry in admit_specs(catalogue=interface_catalogue())})


def controls(system=None) -> tuple[int, int]:
    """The Zenoh grants builder emits exactly the declared rows, and it refuses every malformed table and spec.

    No composition has a `zenoh-service` instance yet, so the manifest here is a real one with that instance added and
    the spec is a real one with grants set. Nothing is written to a file. Returns (honest checks passed, refusals)."""
    system = compiled_system() if system is None else system

    rows = [
        {"holder": "ros2-demo-subscriber", "key": "0/slime_demo/extra/second", "publish": False, "subscribe": True},
        {"holder": "ros2-demo-publisher", "key": "0/slime_demo/extra/second", "publish": True, "subscribe": False},
        {"holder": "ros2-demo-publisher", "key": "0/slime_demo/extra/first", "publish": True, "subscribe": True},
    ]
    manifest = derive_manifest(system)
    manifest["instances"].append({"name": BUILDER.ZENOH_GRANTS_READER_INSTANCE})
    manifest["zenohGrants"] = copy.deepcopy(rows)
    encoded = BUILDER.build_zenoh_grants_table(manifest)
    positive = 0
    if encoded != zenoh_grants_table.encode(rows):
        fail("zenoh grants builder changed the encoder's bytes")
    positive += 1
    if encoded != exam.reference(rows):
        fail("zenoh grants builder differs from the independent struct writer")
    positive += 1
    if exam.decode(encoded) != zenoh_grants_table.canonical(rows):
        fail("zenoh grants builder emitted a table that does not decode to the declared rows")
    positive += 1
    reverse = copy.deepcopy(manifest)
    reverse["zenohGrants"].reverse()
    reverse["instances"].reverse()
    if BUILDER.build_zenoh_grants_table(reverse) != encoded:
        fail("zenoh grants encoding depends on authoring order")
    positive += 1

    def with_rows(altered: dict, change) -> dict:
        change(altered["zenohGrants"])
        return altered

    refused = 0
    for label, mutate, reason in (
        ("no rows", lambda value: value.update(zenohGrants=[]), "has no rows"),
        ("a missing reader instance", lambda value: value.update(instances=[i for i in value["instances"] if i["name"] != BUILDER.ZENOH_GRANTS_READER_INSTANCE]), "no zenoh-service instance"),
        ("a holder that is not an instance", lambda value: value["zenohGrants"][0].update(holder="nobody"), "is not a declared instance"),
        ("the reader as a holder", lambda value: value["zenohGrants"][0].update(holder=BUILDER.ZENOH_GRANTS_READER_INSTANCE), "may not hold a row"),
        ("a row that grants nothing", lambda value: value["zenohGrants"][0].update(publish=False, subscribe=False), "grants nothing"),
        ("a key with a wildcard", lambda value: value["zenohGrants"][0].update(key="0/slime_demo/*"), "outside the grants alphabet"),
        ("a key past the profile limit", lambda value: value["zenohGrants"][0].update(key="k" * 130), "is not 1 to 129 bytes"),
        ("a repeated pair", lambda value: value["zenohGrants"].append(dict(value["zenohGrants"][0])), "names a key twice"),
        ("a field the grants record does not have", lambda value: value["zenohGrants"][0].update(future_right=True), "closes a row"),
        ("a row without a key", lambda value: value["zenohGrants"][0].pop("key"), "closes a row"),
        ("a rights field that is not a boolean", lambda value: value["zenohGrants"][0].update(publish=1), "not two booleans"),
    ):
        altered = copy.deepcopy(manifest)
        mutate(altered)
        try:
            BUILDER.build_zenoh_grants_table(altered)
        except SystemExit as error:
            if reason not in str(error):
                fail(f"zenoh grants {label} refused at the wrong boundary: {error}")
        else:
            fail(f"zenoh grants builder accepted {label}")
        refused += 1

    # A valid spec. The reader instance is added to the spec in memory, the grants are set, and the manifest the spec
    # derives must hold the spec's rows and encode to the table those rows give. Without this a derivation that dropped
    # every row would pass, because every case below it stops before the builder or hands it an empty list.
    valid = copy.deepcopy(system)
    valid.spec["instances"] = [*valid.spec["instances"], {"name": BUILDER.ZENOH_GRANTS_READER_INSTANCE, "executable": "init"}]
    valid.spec["zenohGrants"] = copy.deepcopy(rows)
    valid.spec["zenohGrantsObject"] = True
    valid_names = set(instance_names(valid.spec))
    try:
        validate_authority_sections(valid.spec, valid_names)
        derived = derive_manifest(valid)
    except SystemSpecError as error:
        fail(f"the system spec refused a valid spec with grants: {error}")
    if derived.get("zenohGrants") != rows:
        fail("a valid spec's grants did not reach the derived manifest as declared")
    positive += 1
    if BUILDER.build_zenoh_grants_table(derived) != zenoh_grants_table.encode(rows):
        fail("the table built from a valid spec's derived manifest differs from the encoder's bytes for its rows")
    positive += 1
    if not any(entry["id"] == "zenoh-grants" for entry in derived["objects"]):
        fail("a valid spec's derived manifest has no zenoh-grants object")
    positive += 1

    # Spec admission: the same builder runs on the spec, and the spec's own checks run first.
    names = set(instance_names(system.spec)) | {BUILDER.ZENOH_GRANTS_READER_INSTANCE}
    for label, mutate, reason in (
        ("grants without their object", lambda spec: spec.update(zenohGrants=copy.deepcopy(rows), zenohGrantsObject=False), "require their resource object"),
        ("a holder the spec does not admit", lambda spec: spec.update(zenohGrants=[dict(rows[0], holder="nobody")], zenohGrantsObject=True), "is not admitted"),
        ("an object with no grants", lambda spec: spec.update(zenohGrants=[], zenohGrantsObject=True), "has no rows"),
    ):
        altered_system = copy.deepcopy(system)
        mutate(altered_system.spec)
        try:
            validate_authority_sections(altered_system.spec, names)
            derive_manifest(altered_system)
        except SystemSpecError as error:
            if reason not in str(error):
                fail(f"zenoh grants spec {label} refused at the wrong boundary: {error}")
        else:
            fail(f"system spec admitted zenoh grants with {label}")
        refused += 1
    return positive, refused
