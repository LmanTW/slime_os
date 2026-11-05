# Operations

Operator procedures: steps a human performs outside the automated gates,
where the gate can only judge the record afterwards. Each runbook names the
exact commands, what must be observed, what the validator refuses, and what
the resulting evidence does and does not claim.

- [Framework 13 CPU boot](framework-cpu-boot-runbook.md) — write the approved
  removable medium, cold-boot the named machine twice without touching
  internal storage, and record the observation `just framework_cpu_boot_check`
  judges.
- [LiDAR point cloud in Foxglove](lidar-foxglove-demo.md) — run the guest's recorded
  cloud through the bridge into Foxglove, and see it update on `/velodyne_points`.

Runbooks describe the current procedure only. Requirements for what is not yet
qualified live in [`../plans/`](../plans/README.md); the claim boundary each
observation supports lives in [`../architecture/`](../architecture/README.md).
