# ROS 2 wire compatibility

## Goal

Qualify bounded ROS 2 wire interoperability without implying support beyond the
admitted profile. Work-item state lives in `.tasks/items/`.

## Release boundary

R0 defines the minimum topic path; R1/R2 broaden it to external `rmw_zenoh`
peers, services, and actions. Transport-level security is not claimed by
R0/R1/R2 unless separately admitted and verified.

## R0: Zenoh Profile 0 transport

**Canonical work items:** epic `01a0f5fa-f2c4-71cf-962b-c62cbea2ef68`, with
slices encoder `01a0f5fa-f704-73e0-b3a1-cd2debc429e9`, session machine
`01a0f5fa-fb06-7cbd-9a39-1539785433b7`, classic-CDR codec
`01a0f5fa-ff13-7667-8c59-6f4c6d312535`, transport runtime
`01a0f5fb-0344-7bb5-9d5b-2b79bc0339a8`, nodes and composition
`01a0f5fb-0780-754f-b2f4-e7513c86b63c`, and QEMU gate
`01a0fc73-3bcd-75c7-9ec5-0e9f84c7505b`. R0 itself,
`01a00b4d-2400-7987-93d6-19201c397dff`, is a pre-cutoff prose item and keeps its
record; the epic owns the remaining work because only a spec-driven item can bind
evidence. R0 closes by hand once the epic's acceptance holds. The design and its
alternatives are in
[the decision record](../decisions/zenoh-profile0-transport.md).

### Present state

The wire codec, session machine, CDR codec, transport runtime, the two node
components and the `sel4-zenoh` composition exist; [the architecture
page](../architecture/zenoh-transport.md) owns how they work. The
[format-2 demo contract](../../contracts/rpi5-ros2-demo/v2/README.md) fixes the
topic, the `Counter` type, the key expression, the 33-byte attachment, the
bounds and the four sample byte strings.

Observed under AArch64 QEMU: generation 168 is admitted with four instances,
four samples cross one session, the batches the nodes report are byte-identical
on both sides and equal the host reference's encoding of their own fields, and
the graph ends `HEALTHY` with four required instances completed. The first exam
landed with this plan ordered the two concurrent nodes against each other and
refused that guest; the corrected exam (a chain per node plus one crossing chain)
accepts it. See [Boundaries](#boundaries) for what is and is not observed.

An earlier boot of the same sources stopped at `attach`: a non-blocking receive
that found nothing was returned as a zero-byte message, and the attach handshake
rejected it as malformed. That was a defect in the runtime's receive path, not in
the Zenoh code, and it is fixed separately; the existing `--arm local` network
plane check, which carries no Zenoh code, failed the same way until then.

### What was built

| Slice | Implementation | Recipe |
| --- | --- | --- |
| Encoder | INIT, OPEN, FRAME, D/U_SUBSCRIBER, PUSH+Put with the 33-byte attachment, CLOSE and the stream length, into fixed storage, in `components/lib/src/zenoh_profile0*` | `zenoh_encoder_check` |
| Session machine | A pure state machine: handshake as connector and listener, lease, frame sequence numbers, declare, deliver, undeclare, close; time injected | `zenoh_session_check` |
| CDR codec | `components/lib/src/ros_cdr*`: classic CDR_LE for `Counter`, encoder and decoder | `zenoh_cdr_check` |
| Transport runtime | `components/lib/src/zenoh_link*`: the session over a byte-stream trait, with reassembly, partial writes, bounded queues and a retry limit | `zenoh_transport_check` |
| Nodes and composition | `ros2-demo-publisher` and `ros2-demo-subscriber` under `components/applications`, and the `sel4-zenoh` system spec (generation 168) with its derived manifest and closures | `zenoh_composition_check` |
| QEMU arm | The `zenoh` arm of `check-sel4-io-network-plane.py` and its 36 markers | `rpi5_ros2_zenoh_check` |

### How each slice is verified

None of these recipes is in CI or an aggregate. The first column is what the
recipe requires; the second is why a wrong implementation cannot pass. The host
recipes and `zenoh_composition_check` pass, and `rpi5_ros2_zenoh_check` passes on a
booted `sel4-zenoh` image.

| Slice | The recipe requires | Why a wrong implementation fails |
| --- | --- | --- |
| Encoder | All 17 accepted corpus batches reproduced byte for byte; 7 named refusals | The batches come from the upstream eclipse-zenoh 1.0.0 encoder. `scripts/lib/zenoh_wire.py` re-derives each from its summary first, so the corpus, the reference and the Rust encoder must all agree |
| Session | 5 named scenarios and 7 named refusals, exactly once each | The names are the checker's; a missing, extra or repeated name fails |
| CDR | 4 samples whose bytes equal the demo fixture's `cdrHex` and bytes the checker packs from the field values; 7 malformed inputs | A fixture edited to match a wrong codec still disagrees with the packed bytes |
| Transport | 6 scenarios and 7 refusals over a scripted byte link, with the Rust filter `zenoh_link::` | No QEMU is needed, and a runtime under another path runs no test and fails |
| Composition | 15 authority facts on the derived manifest, after 15 refused mutations | Another port or address, a missing right, listen or resolver authority, a wildcard listener, an unadmitted peer, a UDP destination and an external backend are each refused |
| QEMU arm | The composition judge, the four host recipes, 36 markers in six chains (a chain per node and one crossing between them), then 4 batches (736 bytes) judged against the reference | Each reported batch must equal the reference's encoding of its own decoded fields, with the demo key, the contract's payload, an attachment sequence rising by one and one GID; 28 transcript mutations are refused first |

Each Rust slice prints one `[zenoh-exam]` line per case it judges.
`scripts/check/check-zenoh-profile0.py` owns the expectation and never the tests:
it requires exactly the names it lists and compares reported bytes with bytes from
an independent source. Before it trusts a judge it refuses corrupted evidence
(8, 6, 8 and 6 mutated transcripts for the encoder, session, CDR and transport,
15 for the composition and 22 for the exchange) and reports the counts to the
`just-observations` gate.

The QEMU arm's 36 markers join the network plane's pinned gate-control count
(193 to 229), so `just sel4_gate_control_check` applies its missing, reordered and
failure-marker mutations to them.

### Traceability to R0's verification list

| R0 verification | Observed by |
| --- | --- |
| Publisher and subscriber create only their declared session, topic and direction | `zenoh_composition_check`'s authority facts and the arm's four named denials, each reported only after the reply was checked to be a denial |
| Alternate domain, key, endpoint, port or direction fails | The composition mutations and the transcript's wrong-key and wildcard-key controls |
| Messages serialize to the pinned CDR bytes and cross the session with deterministic values | `zenoh_cdr_check` and the arm's byte-for-byte comparison |
| Malformed lengths, headers, LEB128, key expressions, attachments and CDR alignment fail before allocation | The decoder corpus (landed with the decoder), `zenoh_encoder_check`'s refusals, `zenoh_cdr_check` and `zenoh_transport_check` |
| A wildcard key, a router endpoint and a scouting attempt are rejected | The session refusals `wildcard-key-declaration` and `router-peer`, and the publisher's real scouting request (a UDP connect to Zenoh's multicast group) which the network service refuses; the arm requires the denial |
| Node restart issues fresh sessions and cannot replay stale samples | `zenoh_transport_check`'s `restart-uses-fresh-session`, which asserts the predecessor's frames are refused by sequence number and deliver nothing, and `stale-session-handle` |
| The same profile passes under AArch64 QEMU | `rpi5_ros2_zenoh_check` |

### Boundaries

- The ROSIDL importer and the RIHS01 type-hash generator are not slices. The demo
  contract's checker derives those values today, and this work consumes them as
  frozen constants.
- The exchange crosses the network service's loopback backend, so there is no
  packet capture. The arm judges the batches the nodes report handing to `send`
  and receiving from `recv`; it observes the node codecs and session, not the
  stack's own bytes.
- Nothing here is `rmw_zenoh` interoperability, liveliness, queryables, a router,
  scouting or transport security, and nothing here is a Raspberry Pi 5 claim.
- **The first exam was wrong, and booting the guest showed it.** Its marker chains
  ordered one node's lines against the other's, and its judge required the
  publisher's denials to follow its close, while the nodes run concurrently and
  report their denied requests during setup. No real transcript satisfied both
  halves. The corrected exam checks causal order only and landed as its own
  planning change; the bytes, values, teardown order and health census were never
  in question.
- **Keep-alive is host-tested, not exercised under QEMU.** The decoder takes message
  id 4 and an open session sends one every quarter of the lease it announced when it
  has sent nothing else ([`../decisions/zenoh-stock-peer.md`](../decisions/zenoh-stock-peer.md));
  a link quiet for longer than the peer's lease is closed. The demo is well inside
  the 2 s lease, so the behaviour is tested on the host and against a stock peer,
  and not exercised on a quiet link under QEMU.
- The nodes' reported batches are judged against an independent reference, but
  the guest chooses what it prints, and the loopback backend gives no packet
  capture.

## R0–R3 requirements

The sections from [Compatibility layers](#compatibility-layers) to
[Conformance references](#conformance-references) are requirements.
[Present state](#present-state) says which R0 parts exist. No R1, R2, or R3 exit
condition is met. A planned recipe named below does not exist yet.

## Compatibility layers

Passing one layer never implies support for the others:

1. **R0 minimal Zenoh topic profile:** enough ROS 2 node identity, topic, type, QoS, CDR serialization, and bounded Zenoh session/declaration/put behavior for two local nodes on Raspberry Pi 5.
2. **R1 broader topic wire profile:** interoperability with pinned external ROS 2 peers running `rmw_zenoh`, whose data key expression, type hash, and message attachment R0 already emits.
3. **R2 service and action profile:** ROS service/action mapping, state machines, QoS, and bounded restart behavior.
4. **R3 existing workload route:** unmodified or mostly unmodified ROS packages through an admitted native RMW, Linux-personality, or VM route.

## Admitted interface subset

R0 and R1 accept only normalized types whose maximum CDR serialized size is known before activation:

- booleans, integers, floating-point values, bytes, characters, and admitted time/duration structures;
- nested admitted messages;
- fixed-size arrays;
- bounded strings and bounded sequences;
- deterministic field order, alignment, encapsulation, endianness, and type identity.

They reject before staging:

- unbounded strings or sequences;
- recursive layouts without a finite declared bound;
- unsupported unions, annotations, representations, or extensibility modes;
- duplicate type names with different normalized layouts;
- any message whose declared maximum exceeds the route, heap, queue, fragment, datagram, or shared-buffer quota.

The importer produces the same C8 `InterfaceSchema` identity used by native components, plus the deterministic ROS type identity (RIHS01) and DDS-mangled type name the selected transport's key expression embeds. It does not create an unchecked second type system.

## R0: Minimal Raspberry Pi 5 Zenoh ROS 2 topic profile

**Depends on:** RP5 from [RPi5 ROS 2 demo](rpi5-ros2-demo.md#rp5--node-and-transport-runtime-envelope), C8 stream/fabric mechanisms used behind the gateway/runtime, [IO4](network-data-plane.md) for the selected bounded stream/network transport and exact destination grant, and target-qualified AArch64/RPi5 artifacts.

### Deliverables

- define a versioned ROS 2 Profile 0 containing ROS distribution baseline, RMW boundary, transport family, wire protocol version, session mode, link protocol, admitted session and declaration messages, key-expression format, admitted type, topic name, direction, QoS subset, serialized-size bounds, attachment layout, discovery mode, resource ceilings, and trace records;
- implement a deterministic bounded ROSIDL/IDL importer into C8 `InterfaceSchema`, plus generated or validated Rust bindings, the RIHS01 type hash, the DDS-mangled on-wire type name, and golden CDR fixtures for the admitted message type;
- implement the minimal classic-CDR serializer/deserializer needed by the demo, including explicit encapsulation, endianness, alignment, string termination, sequence, nesting, and maximum-size checks before allocation;
- implement the minimal Zenoh subset needed for one static bounded peer link: the `INIT`/`OPEN` handshake, `FRAME` batching against the 2-byte little-endian stream length, `DECLARE_SUBSCRIBER`/`UNDECLARE_SUBSCRIBER`, `PUSH` with a `Put` body, `CLOSE`, LEB128 primitive decoding that bound-checks before allocating, and teardown;
- emit the per-message attachment `rmw_zenoh` expects — sequence number, source timestamp, and source GID through Zenoh's own value serialization, whose fixed-size arrays still carry a length prefix — so R1 is reachable without changing the payload path;
- implement or port the minimal ROS 2 node API needed for the publisher/subscriber demo: initialization, node identity, publisher/subscriber creation, executor/spin or wait-set behavior, publish, receive callback, logging, and shutdown;
- map publishers/subscribers to C8 `Stream<T>` endpoints without exposing graph mutation, ambient discovery, raw network sockets, filesystem/package lookup, or undeclared parameters;
- package the publisher and subscriber as target-qualified components with deterministic startup data and explicit route, session, stream/network, clock, log, and trace grants;
- provide host/AArch64 QEMU fixtures for CDR bytes, key expressions, attachment bytes, session and declaration framing, message identity, field values, ordering, QoS compatibility, denial, malformed-payload, and malformed-framing cases;
- record unsupported ROS and transport features as stable structured denials or build-time rejections rather than silent omissions.

### Required checks

- the publisher creates only its declared session/publisher/topic/type and cannot subscribe, inspect hidden graph state, open an undeclared endpoint, or delegate route authority unless explicitly granted;
- the subscriber creates only its declared session/subscriber/topic/type and cannot publish or observe unrelated routes;
- alternate domain, key expression, endpoint, port, topic name, type identity, type hash, QoS profile, node identity, graph operation, or direction fails without leaking protected metadata;
- bounded messages serialize to the pinned CDR bytes and traverse the Zenoh/C8 route with deterministic identity and values;
- malformed batch lengths, message headers, LEB128 lengths, key expressions, attachments, declaration bodies, and CDR alignment fail before allocation, mapping, or out-of-bounds access;
- a wildcard key expression, a router or gossip endpoint, and a multicast scouting attempt are all rejected rather than tolerated;
- node restart issues fresh sessions, endpoints, timers, heap state, and parameters and cannot replay stale samples;
- the same profile passes under AArch64 QEMU before being promoted to the physical RP7 demo.

### Planned verification target

```sh
just rpi5_ros2_zenoh_check
```

### Exit condition

Two target-qualified local ROS 2 node components exchange the declared bounded topic through a minimal bounded Zenoh profile with classic CDR payloads under AArch64 QEMU, with exact generation-declared graph and stream authority, no router or discovery authority anywhere in the graph, explicit denial for unsupported ROS and transport features, and finite resource bounds.

## R1: Broader ROS 2 topic wire profile

R1 expands R0 into external topic interoperability with pinned ROS 2 peers running `rmw_zenoh`, which REP-2000 lists Tier 1 for Kilted Kaiju and Rolling. It is not allowed to weaken R0's bounds or authority model.

R0 already emits the three things such a peer matches on — the `<domainId>/<topic>/<typeNameOnWire>/<typeHash>` key expression, the RIHS01 type hash, and the per-message attachment — so R1 adds discovery and peer behavior rather than a second wire format.

### Deliverables

- extend the versioned ROS 2 wire profile to cover the pinned host peer image, fixed probes, packet/result capture, and one command that selects the peer's RMW without changing the fixture image;
- implement the liveliness-token declarations `rmw_zenoh` builds its node graph from, under the `@ros2_lv` admin-space grammar, including the QoS substring encoding and the name mangling that keeps a `/` out of a key-expression field;
- decide and record how the peer reaches the Slime node without granting ambient discovery: either an explicitly granted router endpoint, or direct static peer endpoints on both sides. Upstream documents router gossip as the supported discovery path and ships multicast scouting disabled, and whether two directly connected peers populate the graph cache without gossip is unverified — R1 must establish this by observation before claiming interoperability;
- broaden duplicate/reorder handling, peer restart, retry exhaustion, and teardown within declared resource limits;
- keep native C8 Stream endpoints mapped to publishers/subscribers without exposing raw sockets or arbitrary graph creation;
- preserve the same ROSIDL/IDL importer, RIHS01 derivation, and CDR layout rules as R0.

### Required checks

- a pinned `rmw_zenoh` publisher sends an admitted topic to a native Slime subscriber and a native publisher sends the same type to a pinned `rmw_zenoh` subscriber;
- reliable and best-effort routes pass independently with declared finite resource behavior;
- name mapping, type identity, RIHS01 type hash, CDR bytes, attachment fields, and requested/offered matching agree with pinned peer fixtures;
- alternate domain, key expression, peer address, port, topic, type, direction, and QoS attempts fail closed;
- a denied local route emits no corresponding Zenoh `Put`, and an undeclared remote publisher cannot inject a native sample;
- malformed batch lengths, headers, key expressions, attachments, declaration bodies, and CDR alignment fail before out-of-bounds access or unbounded allocation;
- any router or discovery authority R1 admits is an exact generation-declared endpoint grant, and its absence is a named denial rather than a fallback to scouting.

### Planned verification target

The planned recipe is `ros2_topic_check`.

### Exit condition

The content-addressed pinned ROS 2 peer container exchanges admitted bounded topics bidirectionally with native Slime components over the admitted Zenoh profile through exact graph and network grants; reliable and best-effort behavior matches the profile, denied routes emit no data message, and malformed or exhausted transport state cannot escape declared resource bounds.

## R2: ROS 2 services and actions profile

### Deliverables

- implement standard ROS service request/reply topic mapping, request identity, client routing, response correlation, timeout, cancellation, duplicate handling, and bounded server concurrency;
- map a ROS service onto a C8 `Call<Request, Reply>` route while preserving native peer-death, timeout, cancellation, and authorization errors;
- implement ROS actions as the standard three services and two topics: send goal, cancel goal, get result, feedback, and status;
- implement the accepted/executing/canceling/succeeded/aborted/canceled goal state machine with UUID validation, explicit transition checks, bounded active-goal count, and bounded result retention;
- extend the pinned `rmw_zenoh` conformance corpus with service, action, restart, duplicate, timeout, and cancellation fixtures.

### Required checks

- native and pinned upstream peers call an admitted service in both directions and preserve request/response identity under concurrent clients;
- duplicate or stale requests never execute a declared non-idempotent operation twice;
- action accept, reject, feedback, status, success, abort, cancel, and result retrieval agree with the pinned upstream peer;
- an unauthorized client cannot send a goal, cancel another goal, retrieve a result, observe feedback/status, mutate parameters, or change lifecycle state;
- malformed UUIDs, illegal goal transitions, cancellation races, duplicate results, expired results, and transient-local replay fail deterministically without leaking active-goal state.

### Planned verification target

The planned recipe is `ros2_service_action_check`.

### Exit condition

The content-addressed pinned ROS 2 peer container and native Slime components call services and execute, observe, cancel, and retrieve actions bidirectionally under admitted RMW selections through declared graph and network authority, with exact correlation and finite resource bounds.

## Embedded companion boundary

MCU-class ROS devices without the admitted 64-bit MMU isolation baseline are external peers, not local R3 workloads and not reduced-security Slime ports. A future companion profile may admit micro-ROS/XRCE-DDS or a smaller Zutai protocol only through an exact serial, CAN, USB, or `NetworkDestination` capability.

The generation must bound peer identity, admitted types, route direction, payload size, frequency, queue depth, timeout, reconnect/reset behavior, and actuator authority. Malformed traffic, resource exhaustion, disconnect, and MCU reboot become structured C8/C9 events. The companion receives no ambient discovery domain, graph creation, raw network, storage, or device authority.

### MCU-class systems

Cortex-M, RV32 microcontrollers, and other systems without the admitted MMU and user/supervisor isolation baseline do not run a weakened form of this kernel. They are external devices reached through bounded userspace services.

A later companion profile may admit micro-ROS/XRCE-DDS, `zenoh-pico`, or a smaller Zutai protocol over an exact serial, CAN, USB, or network capability. `zenoh-pico` is a candidate *here* and not as a Slime component: its C toolchain, `z_malloc`/`z_realloc`/`z_free` requirement, and BSD-socket-shaped port API are properties of the microcontroller it runs on rather than obligations on Slime, and the demo's Zenoh transport is what it would peer with. That profile must declare peer identity, types, directions, payload size, frequency, queue depth, timeout, reset behavior, and actuator authority. Disconnect, malformed traffic, reboot, and resource exhaustion become structured C8/C9 events; the companion never receives ambient graph, network, storage, or device authority.

## R3: Existing ROS workload route

R3 runs existing ROS client-library workloads locally. It is not required for R0 if the first demo uses minimal Slime-native ROS 2 nodes over the R0 transport profile.

### Supported routes

- a native RMW/client-library surface that speaks the R0/R1 transport profile through Slime services;
- X1 personality: run a Linux userspace ROS process with filesystem, network, clock, randomness, and process behavior translated to explicit Slime services; or
- a separately admitted VM or target-specific backend, never inherited from an x86-only AMD-V claim.

The selected route is generation data. Moving a workload between routes cannot widen its grants. The selected route is also architecture-qualified: a package proven on x86-64 is not admitted on AArch64/RPi5 until its executable closure and route pass the corresponding target checks.

### Deliverables

- pin exact upstream distribution packages, build artifacts, route, supported client-library surface, and rejected operating-system assumptions;
- package every executable, shared object, interface, configuration, and resource as content-addressed generation objects or explicitly granted state;
- map ROS domain, remapping rules, parameters, logs, clocks, files, network peers, devices, process creation, and scheduling class to explicit generation data and capabilities;
- deny unsupported syscalls, package discovery, plugin loading, dynamic types, transports, or middleware options with stable structured/errno behavior;
- run pinned demo topic/service/parameter workloads through the selected route and expose the workload's complete possible authority to manifest graph and authority-diff tooling.

### Required checks

- pinned packages run without adding native global paths, package indexes, environment inheritance, raw sockets, or unrestricted middleware discovery;
- child processes, composed nodes, plugins, and dynamically created ROS entities cannot exceed the parent workload's declared grants or quotas;
- missing filesystem, network, clock, randomness, device, or scheduling authority fails through the selected compatibility boundary rather than being fabricated;
- workload restart, generation rollback, and route change retain only declared persistent state and cannot retain stale endpoints, secrets, buffers, or network sessions.

### Planned verification target

The planned recipe is `ros2_workload_check`.

### Exit condition

Pinned ROS workloads run locally through one declared compatibility route, interoperate with native C8 components, and remain confined to generation-declared filesystem, network, clock, randomness, scheduling, graph, and device authority with stable rejection for everything else.

## Conformance references

- [ROS 2 middleware/RMW boundary](https://docs.ros.org/en/kilted/Concepts/Intermediate/About-Different-Middleware-Vendors.html)
- [ROS 2 QoS policies and compatibility](https://docs.ros.org/en/kilted/Concepts/Intermediate/About-Quality-of-Service-Settings.html)
- [ROS topic and service name mapping](https://design.ros2.org/articles/topic_and_service_names.html)
- [ROS 2 action protocol](https://design.ros2.org/articles/actions.html)
- [REP-2000 distribution and middleware support tiers](https://www.ros.org/reps/rep-2000.html)
- [Zenoh protocol specification 1.0.0](https://spec.zenoh.io/spec/1.0.0/)
- [`ros2/rmw_zenoh`](https://github.com/ros2/rmw_zenoh)

These references define targets to test against; they do not waive Slime's deterministic bounds or authority invariants.

## Owning references

- [`../plans/rpi5-ros2-demo.md`](../plans/rpi5-ros2-demo.md)
- `contracts/zenoh-profile/` (lands with the decoder)
