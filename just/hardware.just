[group('hardware')]
rpi5_ros2_demo_contract_v2_check:
    python3 scripts/check/check-rpi5-ros2-demo-contract-v2.py

# Zenoh Profile 0 encoder: every batch the upstream eclipse-zenoh 1.0.0 encoder
# produced in the decoder corpus, reproduced byte for byte, with each encoder
# refusal observed. Fails until the encoder lands.
[group('hardware')]
zenoh_encoder_check:
    python3 scripts/check/check-zenoh-profile0.py --slice encoder

# Zenoh Profile 0 session machine: handshake, declaration, delivery, teardown and
# lease expiry as pure state transitions, with each refusal observed. Fails until
# the session machine lands.
[group('hardware')]
zenoh_session_check:
    python3 scripts/check/check-zenoh-profile0.py --slice session

# Classic-CDR codec for slime_demo_msgs/msg/Counter against the frozen demo
# contract's four sample byte strings, with each malformed input refused. Fails
# until the codec lands.
[group('hardware')]
zenoh_cdr_check:
    python3 scripts/check/check-zenoh-profile0.py --slice cdr

# Transport runtime over a scripted byte link: split and coalesced batches,
# backpressure, peer close and restart, with each refusal observed. Fails until
# the runtime lands.
[group('hardware')]
zenoh_transport_check:
    python3 scripts/check/check-zenoh-profile0.py --slice transport

# The derived sel4-zenoh composition grants the two nodes exactly the demo's
# authority and nothing more, judged against 15 mutations. Fails until the
# composition lands.
[group('hardware')]
zenoh_composition_check:
    python3 scripts/check/check-zenoh-profile0.py --slice composition

# The codec and session against the real eclipse-zenoh 1.0.0 crates: the corpus as
# upstream's encoder produces it, a 6000-case sweep in both directions, one full
# session and the Zenoh ID edge cases, each counted and judged here. Needs the
# crates from a registry, so it is explicit and not in CI. Fails until the harness
# lands.
[group('hardware')]
zenoh_xcheck_check:
    python3 scripts/check/check-zenoh-profile0.py --slice xcheck

# The Profile 0 session against batches a stock eclipse-zenoh 1.0.0 peer put on a TCP
# link, replayed from scripts/lib/zenoh_stock_peer.py: its connect, subscribe, publish,
# keep-alive and close, and the things a bounded profile must still refuse. The live peer
# is an explicit local experiment; nothing here needs a registry. Fails until the session
# accepts a stock peer.
[group('hardware')]
zenoh_stock_check:
    python3 scripts/check/check-zenoh-profile0.py --slice stock

# A Zenoh Profile 0 link declared by a named configuration, in a fixed mode with no heap or a
# heap mode where the component supplies the storage a fragmented message is reassembled into.
# Judged against the fragments a stock eclipse-zenoh 1.0.0 peer wrote, reproduced byte for byte by
# scripts/lib/zenoh_fragment.py, and against contracts/zenoh-link-limits/v1. The live peer is an
# explicit local experiment; nothing here needs a registry. Fails until the link takes fragments.
[group('hardware')]
zenoh_links_check:
    python3 scripts/check/check-zenoh-profile0.py --slice links

# A stock Zenoh peer ending its subscription: an UndeclareSubscriber that names the subscriber by id
# alone, inside a DECLARE carrying the network QoS extension. The eight batches the peer sent are
# replayed into a connector session and the host reference reproduces the undeclaration byte for
# byte (scripts/lib/zenoh_undeclare_exam.py, contracts/zenoh-stock-undeclare/v1). Nothing here needs
# a registry. Fails until the session takes the bare undeclaration.
[group('hardware')]
zenoh_undeclare_check:
    python3 scripts/check/check-zenoh-profile0.py --slice undeclare

# Judges a Zenoh Profile 0 session that holds several subscriptions of its own. The session refused
# a second one as subscriber-limit, whatever its parameters said. Params.local now says how many it
# holds. The links exam and the stock-peer exam run beside it, because both pin the subscriber limit.
# The expectation is scripts/lib/zenoh_subscribers_exam.py. Nothing here needs a registry. The recipe
# fails until the session takes the parameter.
[group('hardware')]
zenoh_subscribers_check:
    python3 scripts/check/check-zenoh-profile0.py --slice subscribers

# Judges what the Zenoh service may do for each holder. The decoder of
# contracts/zenoh-service-grants/v1 takes the declarations it must take and refuses the ones it must
# refuse. Each limit is held on both sides of its bound. Each check is removed in turn, and the
# weakened contract must then take the record that the check refuses. The expectation is
# scripts/lib/zenoh_grants_exam.py. The exam renders the schema's constants as Rust and requires
# components/proto/src/zenoh_service_grants.rs to equal that text. Nothing here needs a registry.
# The recipe fails until that file lands.
[group('hardware')]
zenoh_grants_check:
    python3 scripts/check/check-zenoh-profile0.py --slice grants

# Judges the Zenoh service core, which serves one session to local holders by their grants. The
# judge reads what the Rust tests print. The expectation is scripts/lib/zenoh_service_exam.py. The
# subscribers, links and stock-peer exams run beside it. Nothing here needs a registry. The recipe
# fails until the core lands.
[group('hardware')]
zenoh_service_check:
    python3 scripts/check/check-zenoh-profile0.py --slice service

# Judges the Zenoh service client protocol, the constants and layouts that a local holder and the service
# share. The judge reads the schema as text and checks it against the IO0 and grants contracts. The expectation
# is scripts/lib/zenoh_client_exam.py. Nothing here needs a registry. The recipe fails until the generated
# constants file lands.
[group('hardware')]
zenoh_service_client_check:
    python3 scripts/check/check-zenoh-profile0.py --slice client

# Judges the wire records of the Zenoh service client protocol, the encoders and decoders a holder and the service
# share. The judge renders them from the schema's layouts, requires the committed Rust file to equal that text, and
# compares the bytes the Rust test prints with what Python's struct writes from the same layouts. The expectation is
# scripts/lib/zenoh_client_wire_exam.py. Nothing here needs a registry. The recipe fails until the generated file
# lands.
[group('hardware')]
zenoh_service_client_wire_check:
    python3 scripts/check/check-zenoh-profile0.py --slice client-wire

# Judges the generation builder's Zenoh grants table and the system spec admission that runs it. The judge builds the
# table from a manifest and from a spec, requires the encoder's bytes, the independent struct writer's bytes and a decode
# back to the declared rows, and refuses each input the contract and the manifest forbid. The expectation is
# scripts/lib/zenoh_grants_builder_exam.py. Nothing here needs a Zenoh service instance to exist.
[group('hardware')]
zenoh_service_grants_builder_check:
    python3 scripts/check/check-zenoh-grants-builder.py

# Judges the path that carries the Zenoh grants table from the generation to the Zenoh service. The judge requires the
# read label in the contract and its generated outputs, the manifest and system spec fields, the `slime-root` reader
# that serves the table to the instance named `zenoh-service`, and the runtime wrapper. It runs the reader's two tests
# alone under the AArch64 recipe `test_sel4_root` uses. The expectation is scripts/lib/zenoh_grants_reader_exam.py. The
# recipe fails until the implementation lands.
[group('hardware')]
zenoh_service_grants_reader_check:
    python3 scripts/check/check-zenoh-profile0.py --slice grants-reader

# Judges the server half of the Zenoh service client protocol. The Rust test sends the client's requests to the server
# half and prints each answer. The judge writes every request and completion again with Python's struct from the
# schema's layout, requires the same bytes, and requires that no completion is one the client refuses. The expectation
# is scripts/lib/zenoh_server_exam.py. The recipe fails until the server half lands.
[group('hardware')]
zenoh_service_server_check:
    python3 scripts/check/check-zenoh-profile0.py --slice server

# Judges that the Zenoh service component exists and is registered. The judge requires the crate and its manifest, the
# release profile, the component spec, the library export of the server half, and the calls that read the grants,
# decode them, own the link and use the server half. The expectation is scripts/lib/zenoh_service_component_exam.py.
# The recipe fails until the component lands.
[group('hardware')]
zenoh_service_component_check:
    python3 scripts/check/check-zenoh-profile0.py --slice service-component

# Judges the composition that runs the Zenoh service with two holders, and boots it. The judge requires the system
# spec, the manifest derived from it, the composition inventory row and the arm of the network plane checker, and then
# runs that arm under QEMU. The arm requires the holders to exchange through the service and requires the service to
# refuse a key that a holder lacks. The expectation is scripts/lib/zenoh_service_component_exam.py and the marker
# chains in scripts/check/check-sel4-io-network-plane.py. The recipe is in no aggregate. It fails until the
# composition lands.
[group('hardware')]
zenoh_service_booted_check:
    python3 scripts/check/check-zenoh-profile0.py --slice service-booted

# Judges the Zenoh service grants table, the form of the grants that the generation carries and the root serves. The
# judge writes each table again with Python's struct from the schema's layout, requires the encoder, the generated wire
# records and the Rust decoder to agree with it, and refuses each corruption of a table. The expectation is
# scripts/lib/zenoh_grants_table_exam.py. The recipe fails until the generated file, the decoder and the test land.
[group('hardware')]
zenoh_service_grants_table_check:
    python3 scripts/check/check-zenoh-profile0.py --slice grants-table

# Judges the Zenoh service client adapter, which speaks the client protocol over one IO0 ring. The judge reads what
# the Rust test prints from a scripted service and requires every request, every refusal and every returned loan to
# be the ones it lists. The expectation is scripts/lib/zenoh_client_io_exam.py. The wire records run beside it. The
# recipe fails until the adapter lands.
[group('hardware')]
zenoh_service_client_io_check:
    python3 scripts/check/check-zenoh-profile0.py --slice client-io

# Judges what the Zenoh service client adapter does when an attach fails after both loans arrived. The judge reads
# what the Rust test prints from a scripted service and requires the loans back before the abort, the attach answer
# read before the abort is sent, and no abort where the service holds no session. The expectation is
# scripts/lib/zenoh_client_abort_exam.py. The recipe fails until the adapter's test prints these lines.
[group('hardware')]
zenoh_service_client_abort_check:
    python3 scripts/check/check-zenoh-profile0.py --slice client-abort

# Judges the Zenoh service core over a link. The core queues a declaration or a publication through the
# link's single send slot and delivers to its rings after the slot flushed. The judge reads what the Rust
# test prints. The expectation is scripts/lib/zenoh_service_link_exam.py. The subscribers, links and
# stock-peer exams run beside it. Nothing here needs a registry. The recipe fails until the link-facing
# core lands.
[group('hardware')]
zenoh_service_link_check:
    python3 scripts/check/check-zenoh-profile0.py --slice service-link

# Judges contracts/frame-store/v1, its Rust reader and its MCAP converter. Converts the LiDAR bag named by
# SLIME_LIDAR_BAG (refused unless its SHA-256 is the pinned value) twice and compares every payload with the
# exam's own MCAP reading. The Rust reader must read 70 stores exactly as the exam's decoder does. The
# expectation is scripts/lib/frame_store_exam.py and scripts/lib/mcap_format.py. Needs the bag, which is
# never committed, so it is explicit and in no aggregate.
[group('hardware')]
frame_store_check:
    python3 scripts/check/check-frame-store.py

# Judges contracts/data-volume/v1: scripts/build/build-data-volume.py must write exactly the exam's disk for a
# frame store and refuse three bad inputs; the sel4-data-volume image must boot on aarch64 QEMU with that disk
# attached read-only and report what data-volume-probe read, then refuse fifty disks the exam corrupted, one
# per check of its decoder, each with its check's class. The expectation is scripts/lib/data_volume_exam.py. Explicit, in no aggregate.
[group('hardware')]
data_volume_check:
    python3 scripts/check/check-data-volume.py

# The converter library without the bag: RIHS01 against five published type hashes, the ros2msg field
# forms, and each refusal class. Also proves the committed reader fixture is the one the library writes.
[group('hardware')]
frame_store_tools_check:
    python3 -m unittest discover -s tools/frame-store -p 'test_*.py'
    python3 tools/frame-store/write-fixture.py --check

# R0's end-to-end claim: two node components exchange the declared topic over
# Zenoh Profile 0 under AArch64 QEMU, judged byte for byte against the host wire
# reference. Explicit, never part of `all`; fails until the composition lands.
[group('hardware')]
rpi5_ros2_zenoh_check: sel4_pin_check zenoh_composition_check zenoh_encoder_check zenoh_session_check zenoh_cdr_check zenoh_transport_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm zenoh

# The demo's guest connects out over a NIC to a stock eclipse-zenoh 1.0.0 listener on the
# host, built from a hash-pinned wheel into build/zenoh-external. The listener's own record,
# a packet capture holding exactly one TCP connection to 10.0.2.2:17447 and no DNS or UDP,
# and the guest's report are judged against one another and the host wire reference.
# Needs the wheel from a registry, so it is explicit and not in CI or any aggregate. Fails
# until the sel4-zenoh-external composition (generation 169) lands.
[group('hardware')]
zenoh_external_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm zenoh-external

[group('hardware')]
rpi5_artifact_check: architecture_contract_check rpi5_ros2_demo_contract_v2_check
    python3 scripts/check/check-rpi5-artifacts.py

# Retirement of the RPi5 ROS 2 demo format-1 contract: the artifact gate still
# passes on format 2 alone, and the format-1 contract directory is gone.
[group('hardware')]
rpi5_ros2_demo_v1_retired_check: rpi5_artifact_check
    @if test -e contracts/rpi5-ros2-demo/v1; then echo 'contracts/rpi5-ros2-demo/v1 still exists' >&2; exit 1; fi

# Uses the board-specific bcm2712 prefix, target directory, generation, image,
# and pinned hashes; it is not interchangeable with the qemu-arm-virt build.
[group('hardware')]
sel4_rpi5_image_check: sel4_pin_check
    python3 scripts/build/build-sel4.py --platform bcm2712-rpi5 --skip-pin-check

[group('hardware')]
sel4_duo_image_check: sel4_pin_check
    python3 scripts/build/build-sel4.py --platform cv1800b-duo --skip-pin-check

# Flatten via the media builder: objcopy drops the sectionless loader payload.
# This recipe writes no block device.
[group('hardware')]
rpi5_media_check: sel4_rpi5_image_check
    python3 scripts/build/build-rpi5-media.py

# Physical gate: require ordered boot evidence from the pinned build on UART10.
# Missing board, adapter, media, or serial evidence is a failure, never a skip.
# Copy build/rpi5-media/* to FAT32, reset, then pass the serial device.
[group('hardware')]
rpi5_boot_check serial="": sel4_pin_check rpi5_artifact_check
    python3 scripts/check/check-rpi5-boot.py {{ if serial == "" { "" } else { "--serial " + serial } }}

# Bring-up aid only: monitor debug UART without qualifying the board.
# Exits after 10 seconds of quiet or the requested timeout.
[group('hardware')]
rpi5_serial_monitor serial timeout="120":
    python3 scripts/check/check-rpi5-boot.py --monitor --serial {{ serial }} --timeout {{ timeout }}

# P3.D: build the Milk-V Duo bring-up payload and wrap it in the FIT the board's
# firmware accepts, writing `build/duo-payload/identity.json`. Deploys nothing
# and touches no board, so it is safe to run anywhere `nix` is available.
#
# The payload is a flat binary, not an ELF: this board's vendor U-Boot has no
# `bootelf`, and FIT `/incbin/` does not parse program headers.
[group('hardware')]
duo_payload_check:
    python3 scripts/build/build-duo-payload.py

# P3.D: boot the pinned payload on the named Milk-V Duo and require ordered
# S-mode evidence on UART0 at the baud `sel4/pins.toml [cv1800b_duo]` pins.
# Physical: it proves the FIT is this build's, deploys it to the board's own FAT
# boot partition over USB-NCM, drives U-Boot over serial, and reads a real
# serial device. A QEMU pass cannot complete this milestone (roadmap invariant
# 8), so a missing board, link, adapter, or marker is a failure and never a skip.
#
# Unlike the Pi 5 path there is no removable-media step: the operator's laptop
# has no SD reader, so the board's card never leaves it. Stock `/boot/boot.sd`
# is never modified, so letting autoboot run returns the board to vendor Linux.
#
# Requires a key the board's dropbear already accepts, bootstrapped once over
# the serial console:
#   just duo_boot_check /dev/ttyUSB0
[group('hardware')]
duo_boot_check serial="": duo_payload_check
    python3 scripts/check/check-duo-boot.py {{ if serial == "" { "" } else { "--serial " + serial } }}

# P3.E: build and digest-deploy the Duo sample-plane and bounded early-fault
# FITs, drive four autonomous physical boots, and require identical normalized
# semantics across three successful runs. Each image cold-resets through the
# observed RTC block and the gate waits for vendor Linux before continuing.
[group('hardware')]
duo_sel4_check serial="": riscv64_qemu_check
    python3 scripts/check/check-duo-sel4.py {{ if serial == "" { "" } else { "--serial " + serial } }}

# P3.F: build the target-qualified resident graph with Duo UART0 input, deploy
# its distinct product FIT, drive one bounded Slisp session, and cold-reset only
# through the gate-only terminator after every assertion has passed.
[group('hardware')]
duo_slisp_check serial="": slisp_core_check sel4_component_graph_check
    python3 scripts/check/check-duo-slisp.py {{ if serial == "" { "" } else { "--serial " + serial } }}

# Bring-up aid, not a gate: print whatever the Duo's UART0 emits and assert
# nothing. Builds no artifacts and qualifies no board, so it answers the one
# question `duo_boot_check` cannot when the wire is silent — whether any byte
# reaches this host. Exits on its own after 10s of quiet or the timeout.
#
# just duo_serial_monitor /dev/ttyUSB0
[group('hardware')]
duo_serial_monitor serial timeout="120":
    python3 scripts/check/check-duo-boot.py --monitor --serial {{ serial }} --timeout {{ timeout }}

# P3.D: prove `duo_boot_check`'s marker chain has teeth. Mutates the observed
# board transcript committed under evidence/duo/ — deleting each
# required marker, reordering the terminal one, appending each failure marker —
# and requires every mutation to fail the checker. Touches no hardware, so it
# guards the checker rather than the board.
[group('hardware')]
duo_gate_control_check:
    python3 scripts/check/check-duo-gate-control.py
