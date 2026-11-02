"""Tests of the frame-store converter library: RIHS01 against published hashes, and each refusal.

    python3 -m unittest discover -s tools/frame-store -p 'test_*.py'

`just frame_store_check` judges the converter end to end against the pinned LiDAR bag. These tests
need no bag.
"""

from __future__ import annotations

import struct
import unittest
import zlib

import frame_store as fs

SEP = "=" * 80
TIME = ("builtin_interfaces/Time", "int32 sec\nuint32 nanosec\n")
HEADER = ("std_msgs/Header", "# Standard metadata\nbuiltin_interfaces/Time stamp\nstring frame_id\n")
QUATERNION = ("geometry_msgs/Quaternion", "float64 x 0\nfloat64 y 0\nfloat64 z 0\nfloat64 w 1\n")
VECTOR3 = ("geometry_msgs/Vector3", "float64 x\nfloat64 y\nfloat64 z\n")
POINT = ("geometry_msgs/Point", "float64 x\nfloat64 y\nfloat64 z\n")
POSE = ("geometry_msgs/Pose", "Point position\nQuaternion orientation\n")
POSE_COVARIANCE = ("geometry_msgs/PoseWithCovariance", "Pose pose\nfloat64[36] covariance\n")
TWIST = ("geometry_msgs/Twist", "Vector3  linear\nVector3  angular\n")
TWIST_COVARIANCE = ("geometry_msgs/TwistWithCovariance", "Twist twist\nfloat64[36] covariance\n")
POINT_FIELD = (
    "sensor_msgs/PointField",
    "uint8 INT8=1\nuint8 UINT8=2\nuint8 INT16=3\nuint8 UINT16=4\nuint8 INT32=5\nuint8 UINT32=6\n"
    "uint8 FLOAT32=7\nuint8 FLOAT64=8\nstring name\nuint32 offset\nuint8 datatype\nuint32 count\n",
)
POINT_CLOUD2 = (
    "std_msgs/Header header\nuint32 height\nuint32 width\nsensor_msgs/PointField[] fields\nbool is_bigendian\n"
    "uint32 point_step\nuint32 row_step\nuint8[] data\nbool is_dense\n"
)


def bundle(main: str, *dependencies: tuple[str, str]) -> str:
    """ros2msg text as rosbag2 records it: the type, then each dependency after a separator line."""
    return main + "".join(f"\n{SEP}\nMSG: {name}\n{text}" for name, text in dependencies)


# Published hashes. String: `ros2 topic info -v` in ros2/ros2cli#877 and ros2/rmw_zenoh#202. Header, Imu
# and Odometry: the golden values in ZettaScaleLabs/hiroz crates/hiroz-codegen/tests/hash_regression.rs.
# PointCloud2: the LiDAR bag's metadata.yaml.
PUBLISHED = {
    "std_msgs/msg/String": (
        "string data\n",
        "df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18",
    ),
    "std_msgs/msg/Header": (
        bundle(HEADER[1], TIME),
        "f49fb3ae2cf070f793645ff749683ac6b06203e41c891e17701b1cb597ce6a01",
    ),
    "sensor_msgs/msg/Imu": (
        bundle(
            "std_msgs/Header header\ngeometry_msgs/Quaternion orientation\nfloat64[9] orientation_covariance # Row major\n"
            "geometry_msgs/Vector3 angular_velocity\nfloat64[9] angular_velocity_covariance\n"
            "geometry_msgs/Vector3 linear_acceleration\nfloat64[9] linear_acceleration_covariance\n",
            HEADER, TIME, QUATERNION, VECTOR3,
        ),
        "7d9a00ff131080897a5ec7e26e315954b8eae3353c3f995c55faf71574000b5b",
    ),
    "nav_msgs/msg/Odometry": (
        bundle(
            "std_msgs/Header header\nstring child_frame_id\ngeometry_msgs/PoseWithCovariance pose\n"
            "geometry_msgs/TwistWithCovariance twist\n",
            HEADER, TIME, POSE_COVARIANCE, POSE, POINT, QUATERNION, TWIST_COVARIANCE, TWIST, VECTOR3,
        ),
        "3cc97dc7fb7502f8714462c526d369e35b603cfc34d946e3f2eda2766dfec6e0",
    ),
    "sensor_msgs/msg/PointCloud2": (
        bundle(POINT_CLOUD2, HEADER, TIME, POINT_FIELD),
        "9198cabf7da3796ae6fe19c4cb3bdd3525492988c70522628af5daa124bae2b5",
    ),
}


def record(opcode: int, body: bytes) -> bytes:
    return struct.pack("<BQ", opcode, len(body)) + body


def text(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<I", len(raw)) + raw


def bag(*messages: tuple[int, int, bytes], compression: str = "", topic: str = "/chatter") -> bytes:
    """A small uncompressed bag of `std_msgs/msg/String` messages, as (channel, log time, data)."""
    inner = record(fs.OP_SCHEMA, struct.pack("<H", 1) + text("std_msgs/msg/String") + text("ros2msg") + text("string data\n"))
    inner += record(fs.OP_CHANNEL, struct.pack("<HH", 1, 1) + text(topic) + text("cdr") + struct.pack("<I", 0))
    for channel, log_time, data in messages:
        inner += record(fs.OP_MESSAGE, struct.pack("<HIQQ", channel, 0, log_time, log_time) + data)
    chunk = struct.pack("<QQQI", 0, 0, len(inner), zlib.crc32(inner)) + text(compression) + struct.pack("<Q", len(inner)) + inner
    body = record(fs.OP_HEADER, text("ros2") + text("test")) + record(fs.OP_CHUNK, chunk)
    body += record(fs.OP_DATA_END, bytes(4)) + record(fs.OP_FOOTER, bytes(20))
    return fs.MAGIC + body + fs.MAGIC


class Rihs01(unittest.TestCase):
    def test_published_hashes(self) -> None:
        for name, (schema, digest) in PUBLISHED.items():
            with self.subTest(name):
                self.assertEqual(fs.rihs01(name, schema).hex(), digest)

    def test_array_and_string_forms(self) -> None:
        fields = fs._fields("string<=8 a\nint32[3] b\nint32[<=4] c\nstring<=5[2] d\nchar e\nbyte f\n", "p/msg/T")
        self.assertEqual(
            [(f["name"], f["type"]["type_id"], f["type"]["capacity"], f["type"]["string_capacity"]) for f in fields],
            [("a", 21, 0, 8), ("b", 54, 3, 0), ("c", 102, 4, 0), ("d", 69, 2, 5), ("e", 3, 0, 0), ("f", 16, 0, 0)],
        )

    def test_empty_message_has_one_member(self) -> None:
        fields = fs._fields("# nothing\nint32 CONSTANT=1\n", "p/msg/Empty")
        self.assertEqual([f["name"] for f in fields], ["structure_needs_at_least_one_member"])

    def test_refusals(self) -> None:
        for schema in ("p/Missing m\n", "float128 x\n", "uint8<=3 x\n", "int32 Bad\n", bundle("int32 x\n", ("p/T", "int32 y\n"), ("p/T", "int32 y\n"))):
            with self.subTest(schema), self.assertRaises(fs.Refused) as caught:
                fs.rihs01("p/msg/T", schema)
            self.assertEqual(caught.exception.kind, "schema")


class Convert(unittest.TestCase):
    def kind(self, data: bytes, topic: str = "/chatter") -> str:
        with self.assertRaises(fs.Refused) as caught:
            fs.encode(fs.store_from_bag(fs.read_bag(data), topic))
        return caught.exception.kind

    def test_orders_by_log_time(self) -> None:
        store = fs.store_from_bag(fs.read_bag(bag((1, 300, b"c"), (1, 100, b"a"), (1, 200, b"b"))), "/chatter")
        self.assertEqual(store.frames, ((100, b"a"), (200, b"b"), (300, b"c")))
        self.assertEqual(store.period_ns, 100)

    def test_refusals(self) -> None:
        self.assertEqual(self.kind(bag((1, 1, b"a"), (1, 2, b"b"), compression="zstd")), "compressed-chunk")
        self.assertEqual(self.kind(bag((1, 1, b"a"), (1, 2, b"b")), "/missing"), "channel")
        self.assertEqual(self.kind(bag((1, 5, b"a"), (1, 5, b"b"))), "period")
        self.assertEqual(self.kind(bag((1, 5, b"a"))), "period")
        long_topic = "/" + "t" * 256
        self.assertEqual(self.kind(bag((1, 1, b"a"), (1, 2, b"b"), topic=long_topic), long_topic), "bound")
        self.assertEqual(self.kind(bag((2, 1, b"a"))), "bag")
        self.assertEqual(self.kind(bag((1, 1, b"a"))[:-1]), "bag")

    def test_payload_bound(self) -> None:
        big = bytes(fs.contract.MAX_PAYLOAD_BYTES + 1)
        with self.assertRaises(fs.Refused) as caught:
            fs.encode(fs.Store("/t", "std_msgs/msg/String", "string data\n", 1, ((1, big),)))
        self.assertEqual(caught.exception.kind, "bound")


class Validate(unittest.TestCase):
    FIXTURE = (fs.ROOT / "components" / "lib" / "src" / "frame_store" / "fixture.bin").read_bytes()

    def refused(self, data: bytes) -> str | None:
        try:
            fs.validate(data)
        except fs.InvalidStore as error:
            return error.kind
        return None

    def test_accepts_the_fixture_and_an_encoded_store(self) -> None:
        self.assertIsNone(self.refused(self.FIXTURE))
        store = fs.Store("/a", "std_msgs/msg/String", "string data\n", 5, ((1, b""), (2, b"x" * 9), (2, b"y")))
        self.assertIsNone(self.refused(fs.encode(store)))

    def test_refuses_by_class(self) -> None:
        def edited(index: int, value: int) -> bytes:
            data = bytearray(self.FIXTURE)
            data[index] = value
            return bytes(data)
        cases = {
            "truncated": self.FIXTURE[:63],
            "magic": edited(0, self.FIXTURE[0] ^ 1),
            "version": edited(4, 2),
            "header": edited(7, 1),
            "frame-count": self.FIXTURE[:8] + bytes(4) + self.FIXTURE[12:],
            "trailing": self.FIXTURE + bytes(8),
            "padding": edited(len(self.FIXTURE) - 1, 1),
        }
        for kind, data in cases.items():
            self.assertEqual(self.refused(data), kind, kind)

    def test_every_truncation_is_refused(self) -> None:
        for length in range(len(self.FIXTURE)):
            self.assertIsNotNone(self.refused(self.FIXTURE[:length]), length)


if __name__ == "__main__":
    unittest.main()
