#!/usr/bin/env python3
"""Regenerate the small v5 admission fixture through the production builder."""
import importlib.util
import sys
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lib"))
spec = importlib.util.spec_from_file_location("generation_builder", ROOT / "scripts/build/build-generation.py")
assert spec is not None and spec.loader is not None
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

profile = builder.TARGET_PROFILES_BY_NAME["aarch64-sel4-qemu-virt"]
manifest = {
    "target": profile.name,
    "bootAction": "product",
    "bootstrapInstance": "init",
    "objects": [{"id": "image", "kind": "bootstrap", "size": 4096}],
    "executables": [{"name": "init", "object": "image", "role": "init", "spawnBudget": 0}],
    "instances": [
        {"name": name, "executable": "init", "owner": "root", "autostart": True,
         "bindings": [], "dependencies": [], "health": "required", "lifetime": "bounded"}
        for name in ("init", "peer-a", "peer-b")
    ],
    "grants": [], "state": [], "mintedBindings": [], "interfaceSchemas": [],
    "privateMemoryBudget": [], "sharedBufferBudget": [],
    "health": {"bootAttempts": 3, "requiredInstances": ["init", "peer-a", "peer-b"]},
}
# ELF is an externally specified format. One executable page plus the main
# thread's IPC/window pair gives each instance a three-frame image footprint.
elf = struct.pack(
    "<4sBBBB8xHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0,
    2, profile.elf_machine, 1, profile.component_base, 64, 0, 0, 64, 56, 1, 64, 0, 0,
) + struct.pack(
    "<IIQQQQQQ", 1, 5, 0, profile.component_base, profile.component_base,
    0, profile.page_bytes, profile.page_bytes,
)
image = builder._admit_sel4_elf("fixture", elf, profile.page_bytes, profile)
encoded = builder.build_generation(manifest, {"image": image}, None, 1, profile)
Path(__file__).with_name("admission-v5.bin").write_bytes(encoded)
manifest["objects"].extend(
    {"id": name, "kind": "resource", "size": 4096} for name in ("padding-a", "padding-b")
)
encoded = builder.build_generation(
    manifest, {"image": image, "padding-a": b"a", "padding-b": b"b"}, None, 1, profile
)
Path(__file__).with_name("admission-bounds-v5.bin").write_bytes(encoded)
# A generation with a reader table. The builder writes a row for the instance
# named `entropy-service` when the generation carries the entropy authority, so
# the fixture declares that instance and asks for that one table's readers.
manifest["instances"].append({**manifest["instances"][0], "name": "entropy-service"})
manifest["health"]["requiredInstances"].append("entropy-service")
readers = builder.build_resource_readers(manifest, {"entropy-authority"})
assert readers is not None
manifest["objects"] = [
    {"id": "image", "kind": "bootstrap", "size": 4096},
    {"id": builder.RESOURCE_READERS_OBJECT, "kind": "resource", "size": 4096},
]
encoded = builder.build_generation(
    manifest, {"image": image, builder.RESOURCE_READERS_OBJECT: readers}, None, 1, profile
)
Path(__file__).with_name("admission-readers-v5.bin").write_bytes(encoded)
