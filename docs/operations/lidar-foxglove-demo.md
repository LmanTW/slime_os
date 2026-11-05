# LiDAR point cloud in Foxglove

This runbook shows a recorded LiDAR point cloud leaving a SlimeOS guest and arriving in Foxglove. The guest
`lidar-publisher` reads the frames from a read-only disk and publishes them over Zenoh. The host
`tools/foxglove-bridge/bridge.py` forwards them to Foxglove over its WebSocket protocol.

`just lidar_foxglove_demo_check` judges the same chain without a person. This runbook is for seeing it, and
for the optional `demo-viewed` observation of work item `01a1a8cb-a7a0-7dc1-bb24-951d0db30d1e`.

## What you need

| Input | Value |
|---|---|
| The bag | `lidar_ros2.mcap`, 98,999,859 bytes, SHA-256 `9ddece1e03367bd7c5cf1b6f9b977be35b97f00a36dfb4d55990429f0e1558ad`. It is never committed. |
| `SLIME_LIDAR_BAG` | The bag's path. The demo refuses any other bytes. |
| Host | macOS on Apple silicon or x86-64 Linux, the hosts the bridge pins wheels for, with the pinned `qemu-system-aarch64`. |
| Network | A registry for the bridge's two wheels, which it reinstalls on every start. Port 17447 free on the host. |
| Foxglove | The Foxglove app, which can open a Foxglove WebSocket connection. |

## Run it

1. Start the demo. It converts the bag, writes the disk, builds the image and starts the bridge:

   ```sh
   SLIME_LIDAR_BAG=/path/to/lidar_ros2.mcap just lidar_foxglove_demo
   ```

2. Wait for `lidar-demo: in Foxglove, open a Foxglove WebSocket connection to ws://127.0.0.1:8765`.
3. In Foxglove, open a connection of kind Foxglove WebSocket to `ws://127.0.0.1:8765`. Add a 3D panel and
   enable the `/velodyne_points` topic.
4. Press Enter in the terminal. The guest boots and prints `[lidar-publisher] store frames=200 …`. It then
   publishes one frame every 500 ms, so the cloud updates for about 100 s.
5. The guest prints its summary and `session closed`, and the graph ends `SLIME_GRAPH HEALTHY`. The bridge
   keeps serving. Press Ctrl-C to stop it.

The bridge forwards live samples only: a connection opened after a frame was sent does not receive that frame.
Connect before you press Enter. `just lidar_foxglove_demo port=9000` serves on another port.

## What it shows and does not show

- It shows the guest's frames reaching Foxglove through network-service, QEMU user networking and the bridge.
- It does not judge them. `just lidar_foxglove_demo_check` compares every frame with the store.
- It is not a rate claim: the guest publishes at 2 Hz, not the bag's 10 Hz.
- It is not physical hardware: the guest runs on aarch64 QEMU.

## Recording the observation

The `demo-viewed` acceptance is recorded only with the owner's explicit confirmation that the cloud updated
on `/velodyne_points` in Foxglove. A passing run of the check is not that confirmation.
