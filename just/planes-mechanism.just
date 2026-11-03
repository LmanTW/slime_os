[group('planes / mechanism')]
io_link_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-link-plane.py

[group('planes / mechanism')]
io_driver_authority_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-driver-authority-plane.py

[group('planes / mechanism')]
io_network_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-network-plane.py

[group('planes / mechanism')]
io_tcp_check: sel4_pin_check io_tcp_host_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm tcp

# Scripted reordering, loss, silence and zero windows held to the declared TCP
# bounds; the peer's host controls run first. Explicit, never part of `all`.
[group('planes / mechanism')]
io_tcp_impairment_check: sel4_pin_check link_peer_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm tcp-impairment

# One exact external listener, its refusals, half-close, simultaneous close and
# close with unread or unsent data, judged from the wire after the peer's host
# controls. Explicit, never part of `all`.
[group('planes / mechanism')]
io_tcp_listener_check: sel4_pin_check link_peer_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm tcp-listener

# Per-binding TCP options (Nagle, keep-alive, hop limit, idle timeout) declared
# in generation data and judged from the wire, with Reno selected and stated.
# Explicit, never part of `all`.
[group('planes / mechanism')]
io_tcp_options_check: sel4_pin_check link_peer_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm tcp-options

# Per-holder TCP receive and transmit buffers declared in generation data:
# builder bounds, the transmit in-flight limit, SYN window scale, zero-window
# point and socket reuse judged from the wire, throughput recorded. The 2048-byte
# impairment and options exams run first as the regression. Explicit, never
# part of `all`.
[group('planes / mechanism')]
io_tcp_buffers_check: sel4_pin_check link_peer_check io_tcp_impairment_check io_tcp_options_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm tcp-buffers

# The root prints each per-operation clock and payload DMA diagnostic once per
# key and counts the repeats, judged against the frames on the wire, with every
# gate that reads those lines run first. Explicit, never part of `all`.
[group('planes / mechanism')]
root_diagnostic_volume_check: sel4_pin_check io_tcp_buffers_check clock_authority_check sel4_storage_check sel4_store_check sel4_rollback_check sel4_recovery_plane_check sel4_generation_check sel4_transfer_check sel4_filesystem_check replay_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm root-diagnostics

# network-service wakes on the virtio-net driver's completions: one declared
# device wait-set source in every composition that has both, judged from the
# derived manifests and from rx-window acknowledgment latency on the wire, with
# each changed composition's own gate run first. Explicit, never part of `all`.
[group('planes / mechanism')]
link_wake_check: sel4_pin_check io_tcp_buffers_check io_tcp_listener_check zenoh_external_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm link-wake

# The product shell beside the network stack: seven Slisp lines typed one at a
# time into the resident shell, a spawned numeric fetch judged against the
# controlled peer, and refusals that leave no forbidden packet on the wire, with
# the spawn, product-graph, Slisp and host regressions the spawn/v2 migration
# touches. Explicit, never part of `all`.
[group('planes / mechanism')]
sel4_net_check: sel4_pin_check sel4_spawn_check sel4_component_graph_check slisp_core_check test_host
    python3 scripts/check/check-sel4-io-network-plane.py --arm net

# Entropy authority: a userspace entropy service over virtio-rng, booted twice
# with the device and once without, with seeded draws judged against the
# host's HMAC-DRBG and the contract and host regressions its tables add.
# Explicit, never part of `all`.
[group('planes / mechanism')]
sel4_entropy_check: sel4_pin_check contracts_check system_spec_check test_host
    python3 scripts/check/check-sel4-entropy-plane.py

[group('planes / mechanism')]
io_tcp_host_check:
    cargo test -p slime-network-tcp-tests --locked

[group('planes / mechanism')]
io_local_check: sel4_pin_check io_tcp_host_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm local

# Actual root/console record contention, then twenty local QEMU boots with raw captures.
[group('planes / mechanism')]
console_record_check: sel4_pin_check io_tcp_host_check
    python3 scripts/check/check-sel4-gate-controls.py --console-record
    python3 scripts/check/check-sel4-io-network-plane.py --arm local --local-runs 20 --raw-directory "build/console-record-$(date -u +%Y%m%dT%H%M%S)-$$"

# Every component console write is one whole line, judged lexically over the
# tracked sources, after the planes whose markers were observed split pass.
# Explicit, never part of `all`.
[group('planes / mechanism')]
console_lines_check: sel4_pin_check console_record_check io_network_check io_tcp_listener_check io_tcp_options_check io_network_driver_reset_check sel4_net_check robot_runtime_check
    python3 scripts/check/check-sel4-gate-controls.py --console-lines

# Console exam sensitivity only; not product qualification or work-item evidence.
[group('planes / mechanism')]
console_record_controls:
    python3 scripts/check/check-sel4-gate-controls.py --console-record-controls

# The allowed Zenoh grants read in the frozen console transport: the pins hold with the wrapper and without it, and
# refuse every other change. The controls are scripts/lib/console_record_controls.py `_addition_controls`. Boots nothing.
[group('planes / mechanism')]
console_pin_additions_check:
    python3 scripts/check/check-sel4-gate-controls.py --console-record-controls

[group('planes / mechanism')]
io_network_lifetime_check: sel4_pin_check io_tcp_host_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm lifetime

[group('planes / mechanism')]
io_network_service_fault_check: sel4_pin_check io_tcp_host_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm service-fault

[group('planes / mechanism')]
io_network_driver_reset_check: sel4_pin_check io_tcp_host_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm driver-reset

[group('planes / mechanism')]
io_network_qualification_check: contracts_check system_spec_check system_image_builder_check io_tcp_host_check test_host test_sel4_root io_network_check io_link_check link_peer_check sel4_gate_control_check fmt_check_all lint_all
    just docs_check
    just ruff
    just typos

# Reproducible host-stack HTTP/DNS cases; no Internet access is needed.
[group('planes / mechanism')]
io_http_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm http

# Explicit opt-in: DNS and HTTP are performed by the guest, not a host proxy.
[group('planes / mechanism')]
io_http_public_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-network-plane.py --arm http-public --allow-public

# Completion gate includes a fresh live observation rather than cached evidence.
[group('planes / mechanism')]
io_http_qualification_check: io_network_qualification_check io_http_check
    just io_http_public_check

[group('planes / mechanism')]
io_queue_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-queue-plane.py

[group('planes / mechanism')]
io_block_check: sel4_pin_check
    python3 scripts/check/check-sel4-io-block-plane.py

[group('planes / mechanism')]
sel4_channel_check: sel4_pin_check
    python3 scripts/check/check-sel4-channel-plane.py

[group('planes / mechanism')]
sel4_loan_check: sel4_pin_check
    python3 scripts/check/check-sel4-loan-plane.py

[group('planes / mechanism')]
sel4_spawn_check: sel4_pin_check
    python3 scripts/check/check-sel4-spawn-plane.py

[group('planes / mechanism')]
sel4_sample_check: sel4_pin_check
    python3 scripts/check/check-sel4-sample-plane.py

[group('planes / mechanism')]
sel4_supervision_check: sel4_pin_check
    python3 scripts/check/check-sel4-supervision-plane.py

[group('planes / mechanism')]
sel4_reclamation_check: sel4_pin_check
    python3 scripts/check/check-sel4-reclamation-plane.py

# Large component images on aarch64 QEMU: a probe past every former image and
# generation bound is launched four times, verifies its own pages, faults once
# on its read-only data and is reclaimed to the same watermarks, while the
# builder, checker and root refuse every ceiling. The arm also runs
# `test_sel4_root` for the root's named refusal tests. Explicit, never part of
# `all`; fails until the `sel4-large-image` composition lands.
[group('planes / mechanism')]
sel4_large_image_check: sel4_pin_check test_host generation_check sel4_boot_layout_check sel4_c_runtime_check sel4_reclamation_check
    python3 scripts/check/check-sel4-reclamation-plane.py --arm large-image

[group('planes / mechanism')]
sel4_crossing_check: sel4_pin_check
    python3 scripts/check/check-sel4-crossing-plane.py
