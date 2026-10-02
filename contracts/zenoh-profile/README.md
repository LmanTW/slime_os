# Zenoh Profile 0 vocabulary, version 1

`v1/schema.zt` declares what Slime OS decides about the Zenoh wire for the
RPi5 ROS 2 demo's static bounded peer link: the admitted message identifiers,
the numeric bounds a decoder enforces before it allocates, the two admitted
extensions, and the closed vocabulary of reasons a decoder refuses input.
Generate the Rust constants with `python3 scripts/generate/generate-zenoh-profile-bindings.py`
(`just zenoh_profile_gen`); the output is `components/proto/src/zenoh_profile.rs`.

## What this contract does not define

The bytes of a Zenoh message belong to the eclipse-zenoh project (wire version
`0x09`), so this contract declares no record layout and no field offsets. It is
the reader of an externally specified format, not its owner. Session state,
timers, leases and the TCP link are not here either.

## Bounds

`maxBatchBytes`, `maxKeyBytes`, `maxAttachmentBytes` and `maxPayloadBytes` equal
the frozen demo contract's `maxTransportMessageBytes`, `maxKeyexprBytes`,
`maxAttachmentBytes` and `maxPayloadBytes` in
[`../rpi5-ros2-demo/v2`](../rpi5-ros2-demo/v2/README.md). `maxCookieBytes` is
this contract's own bound. The 33-byte attachment is 8 + 8 + 1 + 16 bytes: an
`i64` sequence number, an `i64` source timestamp and a LEB128-prefixed 16-byte
GID.

## Refusal classes

`refusalClasses` is a closed, ordered list. Codes run from one in declaration
order and zero is reserved for accepted input. A probe reports the wire `name`;
a trace records the `code`.

## Wire facts that differ from the prose specification

The U_SUBSCRIBER key expression travels in a mandatory `ZBuf` extension (id
`0x0f`). Its payload is `<flags:u8><scope:z16>` followed by the raw suffix bytes
to the end of the buffer, with no `<u8;z16>` length prefix of its own. This
follows the eclipse-zenoh 1.0.0 codec; the prose specification implies a prefix.
