---
schema: work-item/v2
id: 01a19add-bddf-77a3-ab9c-ca12ecb6512f
kind: task
state: open
created: 2026-11-02T14:06:25+08:00
updated: 2026-11-02T14:06:32+08:00
tags:
  - ros2
supersedes:
  - 01a18064-bd3b-790e-8606-762289dbb197
devloop:
  schema: dev-spec/v1
  recordSchema: devloop-consumer/v1
  bodyProfile: fenced-zti/v1
  helper: devloop-helpers/v1:93745c5aa610e8859ed5f5d937e47d55d36ac612cc60b3a22141fa6763fe1c23
  requirementsDigest: b51960c172938f47c2ae6ebb265227ce3ac0a61c18b74cc96b0ed1d3463d7a22
  admission: slime-data-volume-20261102
  epoch: unstarted
  evidence: []
---

# A hash-pinned frame store read from a read-only QEMU disk

```zti
{
  schema = "dev-spec/v1";
  problem = "The LiDAR frame store from 01a18064-a82b-70cb-bb32-527657addf86 is about 99 MB and is converted from a bag that is not committed, so no system-image closure can carry it, and building it into a generation would make every recording a new image. A run can attach it as a disk instead: system-test-run records already declare disks, virtio-blk-driver serves block rings whose rights and sector range the generation declares, and one block request moves 4 KiB. Nothing defines how a payload sits on such a disk, nothing writes that disk from a frame store, and no guest component reads one back. This item replaces 01a18064-bd3b-790e-8606-762289dbb197, which would have built the data into the image.";
  scope = [
    "contracts/data-volume/v1 defines the disk: a GPT disk whose one partition holds a volume header and the payload, with GUIDs derived from the payload's SHA-256 so a payload has one disk image, and a seven-class refusal order. Version 1 carries one payload kind, a contracts/frame-store/v1 store.";
    "Add scripts/build/build-data-volume.py: --kind frame-store --payload FILE --output DISK writes the one disk of a valid frame store, or refuses as kind, output or payload with a final stderr line build-data-volume: refused CLASS and writes nothing.";
    "Add a components/lib reader that validates a data volume in the contract's order through a block ring, streams the payload through SHA-256, and validates the frame store from the disk without holding it whole. Add a testkit component data-volume-probe and a composition sel4-data-volume whose one block ring has read rights only, booted on aarch64 QEMU with the disk attached read-only.";
    "virtio-blk-driver reports the rights its ring authority grants instead of a fixed read,write, and reports each request it refuses for its rights.";
    "Document the data volume in docs/architecture/io-substrate.md and the contract README.";
  ];
  nonGoals = [
    "Writing a data volume from a guest, or more than one payload on a disk.";
    "Reading the 99 MB LiDAR store in one finite plane. Such a plane's root serves 131072 requests before it stops, and a 4 KiB read costs about six, so about 80 MiB is the most one boot reads; the publisher item must lift that bound.";
    "Changing the object store or filesystem formats, or their 32 KiB object bound.";
    "Committing large data or fetching it from the network.";
  ];
  requirements = [
    {
      id = "builds-the-one-disk";
      statement = "build-data-volume.py writes, for the exam's frame store and for components/lib/src/frame_store/fixture.bin, exactly the disk the exam computes from the contract, and refuses an unknown kind as kind, a payload that is not a frame store as payload and an existing output as output, leaving no new file and the existing output unchanged.";
      acceptance = [
        "data-volume-observed";
      ];
    };
    {
      id = "reads-the-volume";
      statement = "sel4-data-volume boots on aarch64 QEMU with the builder's disk of the exam's frame store attached read-only. data-volume-probe prints the payload's byte count and SHA-256, then the frame count, period, first and last log time and the SHA-256 of the payloads in index order, then a refused write, a heap use of at most 65536 bytes, and completion. Before the probe reports the refused write, virtio-blk-driver reports that its one ring has read rights only and that it refused one write on ring 0.";
      acceptance = [
        "data-volume-observed";
      ];
    };
    {
      id = "refuses-broken-volumes";
      statement = "Seven disks, each built to fail one check of the contract first (a GPT header, the partition type, the volume header, the payload length, the padding after the payload, the payload hash, and the frame store), are each refused by the probe with that check's class and nothing printed after it; only the frame-store refusal follows the volume line.";
      acceptance = [
        "data-volume-observed";
      ];
    };
  ];
  predicates = [
    {
      id = "qualified";
      kind = "equal";
      observation = "passed";
      expected = {
        kind = "bool";
        intValue = 0;
        boolValue = true;
        textValue = "";
      };
      lower = 0;
      upper = 0;
      lowerInclusive = false;
      upperInclusive = false;
      members = [];
    };
  ];
  acceptance = [
    {
      id = "data-volume-observed";
      rationale = "data_volume_check compares the builder's disks byte for byte with an independent encoder of the contract, builds the image through build-system-image.py, and boots it with the honest disk and seven disks it corrupted itself. The probe hashes the bytes it read and the driver reports the authority it enforced, so a probe that skipped a check, lost a frame or never wrote prints a line the judge refuses.";
      gate = "just-target";
      mode = "automated";
      mandatory = true;
      predicate = "qualified";
    };
  ];
}
```
