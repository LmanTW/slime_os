[group('hardware')]
rpi5_ros2_demo_contract_check:
    python3 scripts/check/check-rpi5-ros2-demo-contract.py

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

# R0's end-to-end claim: two node components exchange the declared topic over
# Zenoh Profile 0 under AArch64 QEMU, judged byte for byte against the host wire
# reference. Explicit, never part of `all`; fails until the composition lands.
[group('hardware')]
rpi5_ros2_zenoh_check: sel4_pin_check zenoh_composition_check zenoh_encoder_check zenoh_session_check zenoh_cdr_check zenoh_transport_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm zenoh

[group('hardware')]
rpi5_artifact_check: architecture_contract_check rpi5_ros2_demo_contract_check rpi5_ros2_demo_contract_v2_check
    python3 scripts/check/check-rpi5-artifacts.py

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
