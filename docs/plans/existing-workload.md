# Existing-workload qualification

## Goal

Qualify a selected existing-workload backend without implying cross-architecture
support. Work-item state lives in `.tasks/items/`.

## Release boundary

A selected existing-workload backend must be admitted for that workload's exact
target profile, never inherited from x86-64 or another architecture.

## Kernel prerequisites

The x86-64 guest route (X2) has no kernel to run on yet. The pinned seL4 fork and
upstream master (`0f10829`, 2026-09-22) provide Intel VT-x and VT-d only: there
is no AMD SVM, no AMD IOMMU, and no interrupt remapping. Before any Framework guest
starts, X2 needs an SVM kernel extension outside every verified configuration,
a Slime-written VMM, and H4's containment
([AMD IOMMU ownership](../decisions/amd-iommu-ownership.md)). No physical device
passthrough to a guest is admissible until interrupt remapping exists. The
userspace personality route (X1) needs none of these.

## Owning references

- [`foreign-workloads.md`](foreign-workloads.md)
- [`../architecture/targets-and-portability.md`](../architecture/targets-and-portability.md)
