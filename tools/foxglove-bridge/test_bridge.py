"""The bridge's own logic without its servers: the data key, the log time and the store it accepts.

    python3 -m unittest discover -s tools/foxglove-bridge -p 'test_*.py'
"""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bridge  # noqa: E402

FIXTURE = bridge.ROOT / "components" / "lib" / "src" / "frame_store" / "fixture.bin"
GID = bytes(range(0xE0, 0xF0))
LIDAR_HASH = bytes.fromhex("9198cabf7da3796ae6fe19c4cb3bdd3525492988c70522628af5daa124bae2b5")


class DataKey(unittest.TestCase):
    def test_the_lidar_topic_names_the_publishers_key(self) -> None:
        self.assertEqual(
            bridge.data_key("/velodyne_points", "sensor_msgs/msg/PointCloud2", LIDAR_HASH),
            "0/velodyne_points/sensor_msgs::msg::dds_::PointCloud2_/RIHS01_" + LIDAR_HASH.hex(),
        )

    def test_a_type_that_is_not_a_message_is_refused(self) -> None:
        for type_name in ("sensor_msgs/srv/Trigger", "PointCloud2", "/msg/X", "a/msg/", "a/msg/b/c"):
            with self.subTest(type_name=type_name), self.assertRaises(SystemExit):
                bridge.data_key("/t", type_name, LIDAR_HASH)


class LogTime(unittest.TestCase):
    def attachment(self, timestamp: int, gid_length: int = 16) -> bytes:
        return struct.pack("<qqB", 7, timestamp, gid_length) + GID

    def test_the_attachment_timestamp_is_the_log_time(self) -> None:
        self.assertEqual(bridge.log_time_of(self.attachment(1_700_000_000_000_000_000), 5), 1_700_000_000_000_000_000)

    def test_receive_time_without_a_usable_attachment(self) -> None:
        for label, attachment in (
            ("none", None), ("too short", self.attachment(9)[:-1]), ("too long", self.attachment(9) + b"\x00"),
            ("another GID length", self.attachment(9, gid_length=8)), ("a negative timestamp", self.attachment(-1)),
        ):
            with self.subTest(label):
                self.assertEqual(bridge.log_time_of(attachment, 5), 5)


class StoreFacts(unittest.TestCase):
    def test_the_fixture_store_names_its_topic_type_schema_and_key(self) -> None:
        store = bridge.Store(FIXTURE.read_bytes())
        self.assertTrue(store.topic.startswith("/"))
        self.assertIn("/msg/", store.type_name)
        self.assertGreater(len(store.schema), 0)
        self.assertTrue(store.key.startswith("0/" + store.topic.strip("/") + "/"))

    def test_a_corrupted_store_is_refused(self) -> None:
        data = bytearray(FIXTURE.read_bytes())
        data[0] ^= 1
        with self.assertRaises(bridge.frame_store.InvalidStore):
            bridge.Store(bytes(data))


if __name__ == "__main__":
    unittest.main()
