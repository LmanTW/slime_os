# `just` recipe reference

Every public recipe, grouped as the `just/*.just` files group them. This page
exists so that a recipe name you meet in a checker, a work item, or a PR has
one place to be looked up; `just --list` prints the same names, and
`just docs_check` refuses any `just <name>` literal in documentation that no
longer resolves. Private recipes (`_*`) are omitted.

Descriptions are one line each. The authoritative statement of what a gate
proves is its checker's docstring (`scripts/check/check-*.py`) and the
architecture page that lists it under "Verification". Where a recipe's
comment in its `.just` file was the source, improving that comment improves
this table.

Conventions:

- `*_check` boots or verifies and fails closed; `*_gen` regenerates an
  output from its schema; `*_bless` rewrites a frozen fixture from an
  observed run and must be reviewed as a diff; `*_image` builds only.
- Every `sel4_*`, `io_*`, `private_memory_*`, and plane recipe depends on
  `sel4_pin_check` and resolves a system-image closure before building.
- The `compatibility` group is aliases kept for external callers; new
  references use the canonical recipe.

For how the planes work and how to add one, read
[Add a gate](../getting-started/07-add-a-gate.md).

## product

| Recipe | Does |
| --- | --- |
| `just framework_cpu_boot_check` | P6.6 judges a physical Framework CPU boot. |
| `just framework_cpu_boot_prepare device protect` | P6.6: the Framework's removable-media CPU boot, and its evidence. |
| `just framework_cpu_boot_verify *ARGS` | P6.6: re-hash the protected internal region and judge the operator's record; arguments pass through to `check-framework-cpu-boot.py verify`. |
| `just framework_media_check` | P6.5 builds one Framework-target-qualified raw GPT/FAT32 image, validates the identity and removable-writer safety boundary, then boots those exact bytes under the pinned q35/OVMF reference to the resident product graph. |
| `just framework_media_image` | Build P6.5's Framework-qualified deterministic GPT/FAT32 image. |
| `just generation_check` | Build the product seL4 generation twice and verify identical admitted bytes. |
| `just riscv64_qemu_check` | The marker chain this platform's transcript must satisfy. |
| `just riscv64_qemu_image_check` | P3 replays the architecture-neutral corpus on the pinned RV64 reference. |
| `just run` | Build the product image (`sel4_product_image`) and boot it under the pinned QEMU AArch64 machine with serial on stdio; quit with `Ctrl-A x`. |
| `just run_release` | Same as `run`. |
| `just sel4_boot_check` | P5.4.9/C8.10 gate: the full C8 graph in one seL4 generation. |
| `just sel4_boot_layout_bless` | Rewrite the frozen boot-layout fixtures from an observed boot; read the diff first. |
| `just sel4_boot_layout_check` | B10 on seL4: init's resolved capability layout, per plane, against fixtures. |
| `just sel4_capability_layout_check` | Six builds and boots proving each injected CSpace mutation fails its boot; deliberately outside `just test`. |
| `just sel4_component_graph_check` | P5.2 gate: a generation of native ELF component images boots its declared graph on seL4. |
| `just sel4_demo_check` | Use fresh QEMU boots for rollback and wrong-target negative controls. |
| `just sel4_mavlink_graph_check` | IO9: the product graph plus a serial driver and a MAVLink heartbeat producer, on QEMU where no port exists: the driver binds nothing and stays resident, the producer holds its one-second grid and reports each refusal, and the graph stays healthy. |
| `just sel4_pin_check` | Refuse unless every pinned submodule, toolchain, target spec, and kernel config matches `sel4/pins.toml`; installs nothing. |
| `just sel4_product_image` | Build the product component-graph image `build/slime-sel4-graph.elf`. |
| `just sel4_pwm_graph_check` | IO8: the product graph plus the pwm driver, on QEMU where no PWM block exists: the driver binds nothing, stays resident, and answers Slisp's `(pwm 0 1600)` with no-device while the graph stays healthy. |
| `just sel4_qemu_image_check` | Build the pinned seL4 kernel, root, child fixture, and loader image, writing `build/slime-sel4.identity.json`. |
| `just sel4_root_boot_check` | Root admission, allocator, timer proof, fault isolation, cleanup, and ready markers on the root-fixture image. |
| `just sel4_serial_graph_check` | The product graph plus a driver granted QEMU virt's second serial port and a testkit probe: the gate is the host end of that port, reading the probe's bytes and sending a burst it reads back whole, while a driver bound to no port and malformed requests are refused as the serial protocol names and the console still answers the shell. |
| `just sel4_stress_check` | Boot the stress composition and require the graph to return to zero live tasks under repeated spawn/exit churn. |
| `just x86_64_qemu_check` | P6.4 replays the architecture-neutral corpus on the pinned x86-64 reference, in the same shape as `riscv64_qemu_check`. |
| `just x86_64_sel4_image_check` | P6.1 builds the admitted x86-64 seL4 kernel, root task, child fixture, and generation for the pinned QEMU pc99 profile, and P6.2 assembles the GRUB Multiboot2 EFI tree that supplies the two ELFs as modules. |
| `just x86_64_sel4_root_boot_check` | P6.2's boot contract and P6.3's native execution slice. |

## quality

| Recipe | Does |
| --- | --- |
| `just ci_critical_path_check` | Every recipe the CI contract-source, Miri and host-test jobs run, with closure freshness asserted here directly: restructuring those jobs or removing a duplicated check must not drop an assertion unnoticed. |
| `just deny` | cargo-deny: advisories, bans, licenses, and source pinning. |
| `just devloop ARGS` | Run the pinned devloop against this repository's Zutai toolchain and gate policy: `just devloop validate <UUID>`, `just devloop admit <spec.zti> …`. |
| `just docs_check` | Local links, fragments, canonical UUIDs, and every `just` literal in docs, task requirements, scripts, and CI. |
| `just fmt` | `cargo fmt --all`. |
| `just fmt_boot_contracts` | `cd boot-contracts && cargo fmt` |
| `just fmt_check` | `cargo fmt --all --check`. |
| `just fmt_check_all` | Check formatting of every surviving workspace crate. |
| `just fmt_check_boot_contracts` | `cd boot-contracts && cargo fmt -- --check` |
| `just fmt_check_components` | `cd components && cargo fmt $(just _component_packages) --check` |
| `just fmt_check_sel4_root` | `cargo fmt -p slime-root -- --check` |
| `just fmt_components` | `cd components && cargo fmt $(just _component_packages)` |
| `just fmt_sel4_root` | `cargo fmt -p slime-root` |
| `just framework_safety_check` | Enforce the surviving seL4 storage-write authority allowlist. |
| `just kani_io_proofs` | Kani proofs over the IO0 ring arithmetic for every declared queue size. |
| `just kani_virtio_proofs` | Kani proofs over the virtio device-boundary decoders. |
| `just link_peer_check` | The frame-level peer the network planes talk to, exercised without QEMU. |
| `just lint` | Aggregate: `lint_all`. |
| `just lint_all` | Aggregate: `lint_boot_contracts`, `lint_components_host`, `lint_sel4_root`, `lint_sel4_root_x86_64`. |
| `just lint_boot_contracts` | `cd boot-contracts && cargo clippy --all-features -- -D warnings` |
| `just lint_components` | Clippy for component crates (needs the seL4 prefix). |
| `just lint_components_host` | Host-target lint excludes crates that require the built seL4 prefix. |
| `just lint_fix_components` | Clippy `--fix` for component crates. |
| `just lint_pedantic` | Root clippy with pedantic warnings enabled. |
| `just lint_sel4_root clippy_flags` | Product-target lint requires the installed seL4 prefix, pinned toolchain, custom targets, and embedded child ELF; missing prerequisites fail closed. |
| `just lint_sel4_root_x86_64 clippy_flags` | P6.1's x86-64 arms. |
| `just machete` | Unused-dependency scan of workspace crates. |
| `just miri` | Aggregate: `miri_boot_contracts`, `miri_proto`. |
| `just miri_boot_contracts` | Miri over `boot-contracts`. |
| `just miri_proto` | Miri over `slime-proto`'s decoders. |
| `just private_memory_phase2_check` | One recipe covering every phase-2 acceptance, so a single execution input binds the expandable-CSpace, metadata-lifecycle, bootstrap-boundary and fixed-capacity evidence to the same code closure and images. |
| `just private_memory_phase2_regression_check` | Preserve the fixed-capacity regression surface on both reference architectures. |
| `just private_memory_phase3_check` | One recipe covering every phase-3 acceptance. |
| `just private_memory_phase4_check` | One recipe covering the phase-4 surface: the adaptive planes on both reference architectures, their over-guaranteed negative control, and the whole fixed and demand-backed surface underneath them. |
| `just private_memory_phase5_check` | MEM-ADAPTIVE's qualification: the inventory matrix on both reference architectures over the whole phase-4 surface. |
| `just pr_scope_check` | The pull-request scope classes and their refusals on synthetic diffs, then a compile of every `contracts/**/schema.zt`; CI judges a real base..head with the same classes. |
| `just private_memory_policy_check` | Formatting, lint, and host tests plus the private-memory policy planes. |
| `just ruff` | `ruff check scripts/` |
| `just ruff_fix` | `ruff check scripts/ --fix` |
| `just sel4_gate_control_check` | Prove seL4 gates fail closed when evidence or shared execution breaks. |
| `just smoltcp_matrix_check` | The smoltcp support matrix in the network data-plane plan against the locked release, its checksum-verified crate archive, and the network service's enabled features; needs `cargo fetch --locked`. |
| `just tasks_check` | `myque check` plus backlog-first policy, spec-driven mandate, terminal records, devloop validation, and `codePaths` coverage. |
| `just issue_projection_retired_check` | Work items are not projected into GitHub Issues: refuses while `myque-project.yml` exists, policy names it, a workflow or script runs `myque-gh apply`, or contributor guidance asks for `myque-gh pr link`; fails until the projection retirement lands. |
| `just closeout_checkout_check` | The tree the closeout script runs devloop in covers every `.devloop/policy.json` `codePaths` entry, and a checkout without submodules is refused; clones canonical main, so it needs the network and is not in CI. |
| `just devloop_diagnostics_check` | Explicit end-to-end failed-gate diagnostics qualification through the pinned CLI: retained receipt/output, attribution, failure-cache reuse, truncation and capture refusals; runs `tasks_check` first. |
| `just devloop_diagnostics_controls` | The diagnostics judge's corrupted-result and actual-CLI transport controls; passing controls do not qualify the repair. |
| `just devloop_observation_capacity_check` | Explicit Linux real-CLI raw stderr capacity, replay, filesystem mutation and measured-memory qualification, using strace from locked nixpkgs; runs `tasks_check` first. |
| `just devloop_observation_capacity_controls` | Receipt, filesystem monitor and bounded/unbounded collector controls; never qualifies the implementation. |
| `just tasks_graph` | `myque graph`. |
| `just tasks_list` | `myque list` — generated view, never authoritative. |
| `just tasks_next` | `myque next` — actionable items. |
| `just test` | Aggregate: `sel4_root_boot_check`, `sel4_component_graph_check`, `sel4_gate_control_check`. |
| `just test_host` | Override the components bare-metal default with the actual host target; host-only build-support tests need no target override. |
| `just test_sel4_root` | Run shipped root mechanism modules on the host. |
| `just typos` | Spell-check sources and docs. |
| `just x86_portability_check` | Reject privileged x86 mechanism in surviving neutral Rust trees. |

## contracts

| Recipe | Does |
| --- | --- |
| `just architecture_contract_check` | Section metadata may move; executable bytes and source admission may not. |
| `just bootstate_model_check` | Model-check `contracts/bootstate/model/bootstate.zt`. |
| `just bootstate_trace_check` | M5.6c BootState model-implementation conformance check. |
| `just capability_rights_model_check` | Model-check the capability-rights model. |
| `just component_spec_check` | Aggregate: `contracts_check`, `component_spec_validation_check`. |
| `just component_spec_validation_check` | CP0 component-specification model gate. |
| `just contracts_check` | Aggregate: `contracts_source_check`, `generation_corpus_check`. |
| `just contracts_source_check` | Type-check every contract schema and renderer and refuse stale generated bindings (`check-contracts.py`). |
| `just data_fabric_profile_check` | C8.9 typed full-profile and resource-bound closure gate. |
| `just data_fabric_trace_check` | Refuse stale fabric-trace bindings. |
| `just fabric_manifest_check` | C8.2 fabric-graph generation admission gate. |
| `just generation_corpus_check shard_index shard_count` | Every seL4 manifest the generation builder declares still builds, optionally one round-robin shard of the corpus. |
| `just generation_v5_retired_check` | Retirement of the generation v5 guard: the corpus still builds, and the guard's checker, recipe, codePaths entry, reference row and CI steps are gone. |
| `just generation_v5_check shard_index shard_count` | Every generation this repository builds is v5, and nothing still writes v4. |
| `just interface_schema_check` | Validate `contracts/interface-schema/v1` and its normalized outputs. |
| `just io_model_check` | Aggregate: `io_queue_model_check`, `io_resource_model_check`. |
| `just io_queue_model_check` | Model-check `contracts/io-queue/model/io-queue.zt`. |
| `just io_resource_model_check` | Model-check the io-resource model. |
| `just release_trust_check` | Aggregate: `contracts_check`, `release_trust_runtime_check`. |
| `just release_trust_runtime_check` | M5.8 signed-release authorization and replay scenarios. |
| `just sample_descriptor_check` | Aggregate: `contracts_check`, `sel4_sample_check`. |
| `just system_composition_closure_check` | Render `contracts/composition-inventory/v1`'s host constants. |
| `just system_image_builder_check` | Resolution checks each closure's committed prefix against `sel4/pins.toml`; no installed platform build or published SDK record is needed for that check. |
| `just system_image_closure_aggregate_check` | Every shipped or tested image traces to exactly one closure, and every closure is exercised by an owning gate. |
| `just system_image_closure_gates_check` | Every gate that consumes the committed closure corpus, on one tree: freshness, resolution and its controls, the frozen test-run records and their inventory controls, the scenario and root-role arms, and image/closure ownership. |
| `just system_image_closure_check` | Render `contracts/system-image-closure/v2` host constants. |
| `just system_image_scenario_check` | CP14 scenario-identity gate. |
| `just system_spec_check` | Validate every system spec and refuse a derived composition manifest that drifted from it. |
| `just system_test_run_baseline_check` | One execution identity covers the declaration/closure boundary and its quality gates. |
| `just system_test_run_bless` | Generate `contracts/system-test-run/v2` records from each plane gate's execution inputs. |
| `just closure_input_host_paths_check` | Committed closure inputs carry no host path. No file under `contracts/system-image-closure/v2/inputs/` names a home directory or this checkout. Each committed seL4 prefix names its libsel4 generator inputs under `/slime/sel4`. The two riscv64 prefix headers hold their pinned canonicalized bytes. Explicit. |
| `just closure_derivation_check` | Closure sources carry no in-tree digest, and each checkout derives their identities. It requires a source for each of 103 pinned closures and no committed resolved closure. In a scratch checkout of `HEAD`, six sampled closures resolve twice to one derivation id, each report decodes through `contracts/closure-resolution/v1`, and each resolved closure's identity and artifact digests match values computed independently over the files git lists. A tracked edit, an untracked file, an ignored file and a recipe comment each move exactly the expected derivation ids and `dirty` flags, and the generator rewrites no committed file. `sel4-channel` then builds clean and dirty, and each `build-result.zti` decodes through `decodeSystemImageBuildResult` with the matching `dirty` flag. |
| `just image_attestation_check` | Image attestations (`contracts/image-attestation/v1`). In a scratch clone of `HEAD` with a bare remote, `scripts/build/attest-system-images.py` attests `sel4-channel` while a concurrent writer moves the notes ref, and its note matches the host class, derivation id and output digests the judge computes. It reproduces the same digests at a later commit with the same derivation id, ignores another host class, and refuses an attested commit, an unknown or repeated closure, a dirty input, and a mismatched note before or during its push. `--check` refuses a conflicting pair and a malformed note. The nightly workflow at `.github/workflows/image-attestations.yml` runs the writer as declared. |
| `just system_test_run_reference_check` | Test-run records name their image closure (`contracts/system-test-run/v2`). The exam pins which closure each of 70 runs boots. In a scratch checkout of `HEAD`, it appends one line to `components/lib/src/lib.rs` and regenerates the closures. No test-run record and no negative build case may change, and `check-system-test-run.py` must refuse three wrong closure references. |
| `just system_test_run_inventory_check` | Run discovery and per-arm extraction controls, then the complete frozen-record gate. |
| `just system_test_run_check` | Execution-only inputs — disks, devices, injected faults, timeouts, marker contracts — are declared per plane and frozen, so a timeout or a disk cannot change without a reviewed record change. |

## generate

| Recipe | Does |
| --- | --- |
| `just block_gen` | `python3 scripts/generate/generate-bindings.py block` |
| `just boot_gen` | Regenerate `boot-contracts/src/generated/` and `scripts/lib/boot_contracts.py` from every boot-family schema. |
| `just boot_media_gen` | Render `contracts/boot-media/v1`'s host constants. |
| `just bootstate_gen` | Aggregate: `boot_gen`. |
| `just capability_transfer_gen` | `python3 scripts/generate/generate-bindings.py capability-transfer` |
| `just component_gen` | `python3 scripts/generate/generate-bindings.py component` |
| `just component_runtime_abi_gen` | The `label -> operation` pairs the contract declared, from its own output. |
| `just component_sdk_release_gen` | Render `contracts/component-sdk-release/v1`'s host constants. |
| `just cpu_boot_observation_gen` | Render `contracts/cpu-boot-observation/v1`'s host constants. |
| `just fabric_graph_gen` | Aggregate: `boot_gen`. |
| `just entropy_gen` | `python3 scripts/generate/generate-bindings.py entropy` |
| `just fabric_ring_gen` | `python3 scripts/generate/generate-bindings.py fabric-ring` |
| `just fabric_stream_gen` | `python3 scripts/generate/generate-bindings.py fabric-stream` |
| `just fabric_trace_gen` | `python3 scripts/generate/generate-bindings.py fabric-trace` |
| `just fabric_visibility_gen` | `python3 scripts/generate/generate-bindings.py fabric-visibility` |
| `just frame_store_gen` | `python3 scripts/generate/generate-bindings.py frame-store` |
| `just generation_gen` | Aggregate: `boot_gen`. |
| `just generation_management_gen` | `python3 scripts/generate/generate-bindings.py generation-management` |
| `just interface_schema_gen` | `python3 scripts/generate/generate-interface-schema-bindings.py` |
| `just io_queue_gen` | `python3 scripts/generate/generate-bindings.py io-queue` |
| `just kernel_image_gen` | Aggregate: `boot_gen`. |
| `just link_device_gen` | `python3 scripts/generate/generate-bindings.py link-device` |
| `just mavlink_heartbeat_gen` | `python3 scripts/generate/generate-bindings.py mavlink-heartbeat` |
| `just network_service_gen` | `python3 scripts/generate/generate-bindings.py network-service` |
| `just powerbox_gen` | `python3 scripts/generate/generate-bindings.py powerbox` |
| `just private_memory_probe_gen` | `python3 scripts/generate/generate-bindings.py private-memory-probe` |
| `just pwm_servo_gen` | `python3 scripts/generate/generate-bindings.py pwm-servo` |
| `just sample_descriptor_gen` | `python3 scripts/generate/generate-bindings.py sample-descriptor` |
| `just serial_device_gen` | `python3 scripts/generate/generate-bindings.py serial-device` |
| `just spawn_gen` | `python3 scripts/generate/generate-bindings.py spawn` |
| `just store_gen` | `python3 scripts/generate/generate-bindings.py store` |
| `just syscall_abi_gen` | The `label -> operation` pairs the contract declared, from its own table. |
| `just zenoh_profile_gen` | `python3 scripts/generate/generate-bindings.py zenoh-profile` |
| `just zenoh_service_grants_gen` | Render the constants of `contracts/zenoh-service-grants/v1` as `components/proto/src/zenoh_service_grants.rs`. The grants exam requires that file to equal this output byte for byte. |
| `just zenoh_service_client_gen` | Render the constants of `contracts/zenoh-service-client/v1` as `components/proto/src/zenoh_service_client.rs`. The client exam requires that file to equal this output byte for byte. |
| `just zenoh_service_limits_gen` | Render the wire record of `contracts/zenoh-service-limits/v1` as `components/proto/src/zenoh_service_limits_wire.rs`. The limits exam requires the committed file to equal this output byte for byte. |
| `just zenoh_service_grants_table_gen` | Render the wire records of `contracts/zenoh-service-grants-table/v1` as `components/proto/src/zenoh_service_grants_table_wire.rs`. The grants table exam requires that file to equal this output byte for byte. |
| `just zenoh_service_client_wire_gen` | Render the wire records of `contracts/zenoh-service-client/v1` as `components/proto/src/zenoh_service_client_wire.rs`. The wire exam requires that file to equal this output byte for byte. |
| `just zenoh_undeclare_gen` | Render the stock peer's undeclaration session as the Rust constants `zenoh_undeclare::` reads, from `contracts/zenoh-stock-undeclare/v1`. |
| `just zenoh_stock_gen` | Render the captured stock-peer batches as the Rust constants `zenoh_stock::` reads, from `contracts/zenoh-stock-fixtures/v1`. |

## planes / mechanism

| Recipe | Does |
| --- | --- |
| `just io_block_check` | IO2 gate: computed virtio-blk operations, refusals, and async settlement. |
| `just io_driver_authority_check` | IO1 gate: generation-scoped userspace hardware authority under seL4. |
| `just io_http_check` | Reproducible host-stack HTTP/DNS cases; no Internet access is needed. |
| `just io_http_public_check` | Explicit opt-in: DNS and HTTP are performed by the guest, not a host proxy. |
| `just io_http_qualification_check` | Completion gate includes a fresh live observation rather than cached evidence. |
| `just io_link_check` | IO3 gate: a supervised userspace virtio-net driver serves LinkDevice over IO0/IO1. |
| `just io_local_check` | The loopback listen/accept arm: duplex bytes, EOF, readiness draining, authority refusals. |
| `just console_record_check` | Actual-source root/console contention and whole local producer operations, then twenty consecutive local QEMU boots with exclusive raw captures; [qualification boundary](../plans/console-record-qualification.md). |
| `just console_lines_check` | Every component console write is one whole line: a lexical audit of tracked Rust and C component sources, after the planes whose markers were observed split; fails until the implementation lands. |
| `just console_record_controls` | Console exam sensitivity controls only; not product qualification or task evidence. |
| `just console_pin_additions_check` | Judges the allowed Zenoh grants read in the frozen console transport. The pins hold with the wrapper and without it, and refuse a changed byte, a second copy, a reworded doc comment, another function, a change beside the block and a block in the other file. The script records 4 accepted fixtures and 14 refused. It boots nothing. The expectation is `scripts/lib/console_record_controls.py`. |
| `just io_network_check` | All six network arms: authority, external TCP, local TCP, client lifetime, service fault, driver reset. |
| `just io_network_driver_reset_check` | External link reset with pending payload work, epoch advance, and restart. |
| `just io_network_lifetime_check` | Client death, socket/session reclamation, and supervised restart. |
| `just io_network_qualification_check` | Aggregate network qualification: every network arm, link, host engine tests, contracts, closure and docs gates. |
| `just io_network_service_fault_check` | Service VM fault with in-flight work, mapping revocation, fresh-incarnation restart. |
| `just io_queue_check` | IO0 gate: two supervised components exchange work through the shared queue. |
| `just io_tcp_check` | The external TCP stream arm plus the host TCP engine tests. |
| `just io_tcp_impairment_check` | Scripted reordering, loss, a silent peer and zero windows held to the declared TCP bounds, judged from the wire. |
| `just io_tcp_listener_check` | One exact external listener: admitted accept, silent and reset refusals, half-close, simultaneous close and unread/unsent close judged from the wire. |
| `just io_tcp_options_check` | Per-binding Nagle, keep-alive, hop limit and idle timeout declared in generation data and judged from the wire, with Reno selected; fails until the `sel4-io-tcp-options` composition lands. |
| `just io_tcp_buffers_check` | Per-holder TCP receive and transmit buffers declared in generation data: builder bounds, the transmit in-flight limit, SYN window scale, zero-window point and socket reuse judged from the wire, throughput recorded; fails until the `sel4-io-tcp-buffers` composition lands. |
| `just root_diagnostic_volume_check` | The root prints each per-operation clock and payload DMA diagnostic once per key and counts the repeats, reconciled with the frames on the wire, after every gate that reads those lines; fails until the implementation lands. |
| `just link_wake_check` | network-service wakes on the virtio-net driver's completions: one declared device wait-set source per composition, and rx-window acknowledgments faster than the idle timer on the wire; fails until the implementation lands. |
| `just sel4_net_check` | The resident Slisp shell spawns http-get with a string argument on `sel4-net`; the body is judged against the controlled peer and refusals against the wire, with the spawn, product-graph, Slisp and host regressions. |
| `just sel4_entropy_check` | Entropy authority on `sel4-entropy`: seeded draws judged against the host HMAC-DRBG, hardware draws distinct and fail-closed without virtio-rng, budgets and request sizes refused. |
| `just io_tcp_host_check` | Host tests of the production TCP engine against real host smoltcp peers. |
| `just sel4_channel_check` | P5.3.1 gate: two components rendezvous over a generation-declared native seL4 Endpoint. |
| `just sel4_crossing_check` | B22 gate: a graph outlives `MAX_CHANNELS` and still sends on every live one. |
| `just sel4_loan_check` | P5.3.2 gate: a loan crosses between components on seL4, against quotas the generation declared. |
| `just sel4_reclamation_check` | B38 gate: exceed old task CSlot/untyped lifetime watermarks with bounded live use. |
| `just sel4_large_image_check` | Large component images on `sel4-large-image`: a probe past every former image and generation bound verifies its own pages across four launches, faults once on read-only data and is reclaimed to the same watermarks, while builder, checker and root refuse every ceiling, with the host, generation, boot-layout, C runtime and reclamation regressions; fails until the composition lands. |
| `just sel4_sample_check` | P5.3.4 gate: the C7 sample plane, composed on seL4. |
| `just sel4_spawn_check` | P5.3.3 gate: a component constructs children on seL4 and supervises them. |
| `just sel4_supervision_check` | B16 gate: a graph outlives `MAX_RECORDS` and still answers every live handle. |

## planes / runtime

| Recipe | Does |
| --- | --- |
| `just clock_authority_check` | C9.1 gate: timer and simulated-time authority is independent, bounded, and deny-by-default; monotonic reads are ambient and never reach the root. |
| `just clock_direct_read_check` | No source, binding or builder table declares a monotonic read right, after the clock, replay, robot-runtime and TCP-buffer planes pass; fails until the implementation lands. |
| `just lifecycle_restart_check` | C9.4 gate: a userspace supervisor restarts under declared policy, and the bound is terminal. |
| `just sel4_lifetime_check` | Declared instance lifetime enforced by the root on `sel4-lifetime` and `sel4-lifetime-exit`: a resident instance stays live under certification, a bounded one completes, a resident optional exit is recorded unhealthy and a resident required exit fails the graph, with the host, root, lifecycle and product-graph regressions; fails until those compositions land. |
| `just private_memory_adaptive_check` | MEM-ADAPTIVE's declared-policy plane. |
| `just private_memory_bootstrap_check` | Prove bootstrap reserve bounds and independent refusal before publication. |
| `just private_memory_check` | C10.2 gate: the generation's declared private-memory budget is the live ceiling. |
| `just private_memory_conservation_check` | Prove one holder's returned capacity becomes another's, zeroed and reconciled. |
| `just private_memory_cspace_check` | Prove kernel capability operations execute beyond the initial CNode. |
| `just private_memory_cycles_check` | MEM-64M requires both QEMU architectures to carry this workload, so an architecture-specific reclamation path cannot regress behind the other's evidence. |
| `just private_memory_elastic_check` | Prove an idle maximum reserves nothing and a guarantee survives exhaustion. |
| `just private_memory_fragmentation_check` | Prove page-granular growth from backing no aligned span fits. |
| `just private_memory_isolation_check` | MEM-1G's authority and permission boundary, kept separate from the capacity arm so a 1 GiB working set is never the reason an isolation denial is missed. |
| `just private_memory_matrix_check` | MEM-ADAPTIVE's inventory matrix: one root and component set, one pool-relative policy, packaged with each pinned kernel-visible RAM row's own kernel, device tree and loader. |
| `just private_memory_metadata_check` | Prove metadata growth, charged reuse and quarantine retry reconcile. |
| `just private_memory_rollback_check` | Prove every acquisition and mapping stage rolls back without a second charge. |
| `just private_memory_stress_check` | C10.2 gate: the generation's declared private-memory budget is the live ceiling. |
| `just replay_check` | C9.5 gate: a recorded run, a deterministic replay of it, and both refusals. |
| `just robot_runtime_check` | C9.6 gate: a robot workload composed of every C9 slice, under contention. |
| `just robot_withdrawn_controls` | The withdrawn arm's controls without booting: one honest withdrawal accepted, 12 broken orderings and counts refused. |
| `just robot_withdrawn_check` | After `robot_withdrawn_controls` and `robot_runtime_check`, four boots in which the actuator holds the withdrawn command and settles it only on the forwarded cancellation; fails until the implementation lands. |
| `just scheduling_class_check` | C9.3 gate: a declared class orders the CPU, and no component widens itself. |
| `just sel4_c_runtime_check` | Build and boot one external C component against the generated runtime ABI. |
| `just slisp_core_check` | Exercise the bounded Slisp core on the host and as an external seL4 component. |
| `just wait_set_check` | C9.2 gate: one wake per ready set, recovered from one badge word, in order. |

## planes / fabric

| Recipe | Does |
| --- | --- |
| `just sel4_call_check` | B25/C8.6 gate: parent-vouched native calls on the seL4 call plane. |
| `just sel4_fabric_aggregate_check` | C8.15 gate: full-graph determinism and the C8 parent close. |
| `just sel4_fault_check` | C8.14 gate: degradation and fault isolation on seL4. |
| `just sel4_matrix_check` | C8.12 gate: the integrated matching, visibility, and denial matrix on seL4. |
| `just sel4_operation_check` | P5.4.7/C8.7 gate: bounded native operations on the seL4 operation plane. |
| `just sel4_qos_check` | Keep QoS separate: the stream generation has no time capability. |
| `just sel4_saturation_check` | C8.13 gate: declared resource ceilings driven to their exact bound on seL4. |
| `just sel4_stream_check` | P5.5.2 gate: the full C8.4 stream plane, unmodified, on seL4. |
| `just sel4_trace_check` | C8.11: the bounded, deterministic semantic trace, on every timed fabric worker. |
| `just sel4_traffic_check` | C8.13 gate: concurrent cross-plane traffic and resource ceilings on seL4. |
| `just sel4_visibility_bless` | Blessing rewrites the frozen view fixture from the observed boot. |
| `just sel4_visibility_check` | P5.4.8/C8.8 gate: filtered introspection and declared interposition on seL4. |

## planes / storage

| Recipe | Does |
| --- | --- |
| `just sel4_boot_selection_check` | Fresh QEMU boots share one retained raw disk; do not split this checker. |
| `just sel4_device_check` | B83 gate: the product root does not reclaim the userspace block path. |
| `just sel4_directory_check` | P5.4.3 gate: M6.3's directory capability mechanism (M6.3). |
| `just sel4_filesystem_check` | P5.4.3 gate: M6.3's filesystem service (M6.3). |
| `just sel4_generation_check` | P5.4.3 gate: M6.5's generation commands, in userspace (M6.5). |
| `just sel4_input_check` | P5.4.3 gate: `InputRead` mediation. |
| `just sel4_powerbox_check` | P5.4.3 gate: M6.6's powerbox file dialog (M6.6). |
| `just sel4_recovery_plane_check` | P5.4.2c gate: M5.9's recovery reconstruction, in userspace (M5.9). |
| `just sel4_rollback_check` | P5.4.2c gate: M5.6's rollback contract, in userspace (M5.6). |
| `just sel4_storage_check` | P5.4.2c gate: a userspace component reaches a real disk (M5.2, M5.3). |
| `just sel4_store_check` | P5.4.2c gate: M5.4's object store, in userspace (M5.4). |
| `just sel4_transfer_check` | P5.4.3 gate: M6.7's generation transfer (M6.7). |

## component sdk

| Recipe | Does |
| --- | --- |
| `just component_crate_split_check` | Keep allocator groups in separate Cargo invocations: feature unification would enable mutually exclusive global allocators. |
| `just component_sdk_compatibility_check` | CP9: version policy and an evidence-backed compatibility matrix. |
| `just component_sdk_export_check` | CP6: the SDK export is deterministic, self-describing, and boundary-clean. |
| `just component_sdk_out_of_tree_check` | CP5: pinned SDK consumption from a distinct component repository. |
| `just component_sdk_prefix_check` | Keep SDK artifacts platform-qualified; QEMU must reject the RPi ELF. |
| `just component_sdk_preflight ARGS` | Read-only and credential-free: it gates a publication before the release job. |
| `just component_sdk_release_check` | CP7: permanent SDK publication, idempotence, and reverse drift. |
| `just component_sdk_system_image_check` | CP15: immutable SDK releases build, boot, and roll back one closure. |
| `just component_sdk_upgrade_check` | CP10: a consumer pins, upgrades, rebuilds, boots, and rolls back. |
| `just external_component_admission_check` | CP4: external ELF admission, rejection, signing, and mixed-source generation. |
| `just runtime_binding_resolution_check` | Records that named-binding resolution is proved by the plane gates; prints the statement. |

## hardware

| Recipe | Does |
| --- | --- |
| `just duo_boot_check serial` | P3.D: boot the pinned payload on the named Milk-V Duo and require ordered S-mode evidence on UART0 at the baud `sel4/pins.toml [cv1800b_duo]` pins. |
| `just duo_gate_control_check` | P3.D: prove `duo_boot_check`'s marker chain has teeth. |
| `just duo_payload_check` | P3.D: build the Milk-V Duo bring-up payload and wrap it in the FIT the board's firmware accepts, writing `build/duo-payload/identity.json`. |
| `just duo_sel4_check serial` | P3.E: build and digest-deploy the Duo sample-plane and bounded early-fault FITs, drive four autonomous physical boots, and require identical normalized semantics across three successful runs. |
| `just duo_serial_monitor serial timeout` | Bring-up aid, not a gate: print whatever the Duo's UART0 emits and assert nothing. |
| `just duo_slisp_check serial` | P3.F: build the target-qualified resident graph with Duo UART0 input, deploy its distinct product FIT, drive one bounded Slisp session, and cold-reset only through the gate-only terminator after every assertion has passed. |
| `just rpi5_artifact_check` | RP1 exact-profile executable closure and deterministic artifact gate. |
| `just rpi5_ros2_demo_v1_retired_check` | Retirement of the RPi5 ROS 2 demo format-1 contract: the artifact gate passes on format 2 alone, and the format-1 contract directory is gone. |
| `just rpi5_boot_check serial` | Physical gate: require ordered boot evidence from the pinned build on UART10. |
| `just rpi5_media_check` | Flatten via the media builder: objcopy drops the sectionless loader payload. |
| `just rpi5_ros2_demo_contract_v2_check` | RP0 format-2 Raspberry Pi 5 ROS 2 demo contract gate. |
| `just zenoh_encoder_check` | Zenoh Profile 0 encoder reproduces every upstream-encoded batch in the decoder corpus byte for byte, after the host wire reference proves itself against the same corpus, and refuses seven named bad inputs; fails until the encoder lands. |
| `just zenoh_session_check` | Zenoh Profile 0 session machine completes five named scenarios and refuses seven named inputs, as pure state transitions with injected time; fails until the session machine lands. |
| `just zenoh_cdr_check` | Classic-CDR codec reproduces the demo fixture's four Counter samples, recomputed from their field values, and refuses seven malformed inputs; fails until the codec lands. |
| `just zenoh_transport_check` | Zenoh transport runtime over a scripted byte link: six scenarios (split and coalesced batches, backpressure, peer close, restart) and seven refusals; fails until the runtime lands. |
| `just zenoh_stock_check` | A stock eclipse-zenoh 1.0.0 peer's captured batches taken by the Profile 0 session on the plain demo topic, with the refusal corpus pinned by name and digest and the retained decoder, session, encoder and link tests required by name; explicit, in no aggregate, and fails until the session accepts a stock peer. |
| `just zenoh_xcheck_check` | The codec and session against the real eclipse-zenoh 1.0.0 crates: the corpus as upstream's encoder produces it, a 6000-case sweep in both directions, one full session and the Zenoh ID edge cases. Needs the crates from a registry, so it is explicit and not in CI. |
| `just zenoh_links_check` | A Zenoh Profile 0 link declared by a named configuration in a fixed mode or a heap mode, judged against the fragments a stock eclipse-zenoh 1.0.0 peer wrote (reproduced byte for byte by `scripts/lib/zenoh_fragment.py`), `contracts/zenoh-link-limits/v1`, the edge between a whole message and a fragmented one, and each refusal, with the stock-peer exam's retained tests required by name. Explicit; fails until the link takes fragments. |
| `just zenoh_grants_check` | Judges `contracts/zenoh-service-grants/v1` through its own decoder. It takes 17 declarations and refuses 42, and it holds each limit on both sides of its bound. It removes each of the contract's ten checks in turn. The weakened contract must then take the record that the check refuses. It makes each of four upper bounds exclusive, and the weakened contract must then refuse the record at that bound. It renders the nine schema constants as Rust and requires `components/proto/src/zenoh_service_grants.rs` to equal that text byte for byte. Explicit. It fails until that file lands. |
| `just zenoh_service_check` | Judges the Zenoh service core, which serves one session to local holders by their grants. The core declares the keys to the peer once the session is open. It delivers a publication to every subscribed holder and sends it to the peer only if the peer declared the key. A slow holder loses its oldest samples and is told once. The exam has twelve refusals by name and class. `scripts/lib/zenoh_wire.py` reproduces the frames byte for byte. The test prints the `size_of` of a slot, a row, a holder and the core, and the judge refuses a size above the grants contract's overhead. The test also prints the nine constants it reads from `slime_proto::zenoh_service_grants`, and the judge compares each with the schema. The subscribers, links and stock-peer exams run beside it, with their controls. Explicit. It fails until the core lands. |
| `just zenoh_service_client_check` | Judges the Zenoh service client protocol. Each layout adds up to its declared size, fits the IO0 payloads and lists its record's fields in order. No field names a key, holder, session or peer. The sample header and the largest payload fill the data page. Operations, statuses, items and loan roles are distinct. The exam compares the committed Rust constants file with the generator's output byte for byte. Explicit. It fails until the generated file lands. |
| `just zenoh_service_client_wire_check` | Judges the wire records of the Zenoh service client protocol. The judge renders a struct, an encoder and a decoder for each of the four records from the schema's layouts, and requires the committed Rust file to equal that text. The Rust test encodes each record and the judge compares the bytes with what Python's `struct` writes from the same layouts. A short buffer is refused. Explicit. It fails until the generated file lands. |
| `just zenoh_service_client_io_check` | Judges the Zenoh service client adapter. The Rust tests play a scripted service and print each request the adapter wrote, each refusal and each loan returned. The judge requires the request bytes from the schema's layout, a refusal for every request outside the protocol, and both loans returned after an answer outside the protocol. The wire records run beside it. Explicit. It fails until the adapter lands. |
| `just zenoh_service_grants_builder_check` | Judges the generation builder's Zenoh grants table and the system spec admission that runs it. The judge builds the table from a manifest and from a spec, and requires the encoder's bytes, the independent struct writer's bytes and a decode back to the declared rows. It refuses each input the contract and the manifest forbid. The expectation is `scripts/lib/zenoh_grants_builder_exam.py`. |
| `just zenoh_service_grants_reader_check` | Judges the path that carries the Zenoh grants table from the generation to the Zenoh service. The judge requires the read label, the manifest and system spec fields, the `slime-root` reader for the instance named `zenoh-service` and the runtime wrapper. It runs the reader's two tests alone under the AArch64 recipe that `test_sel4_root` uses. The expectation is `scripts/lib/zenoh_grants_reader_exam.py`. The recipe fails until the implementation lands. |
| `just zenoh_service_server_check` | Judges the server half of the Zenoh service client protocol. The Rust test sends the client's requests to the server half and prints each answer. The judge writes every request and completion again with Python's `struct` from the schema's layout and requires the same bytes. It requires that no completion is one the client refuses. The expectation is `scripts/lib/zenoh_server_exam.py`. The recipe fails until the server half lands. |
| `just zenoh_service_limits_check` | Judges the Zenoh service limits record, the six limits of the grants record that the generation carries and the root serves, and the places that must carry them. The judge writes each record again with Python's struct from the schema's layout, refuses each corruption of a record, requires the generated binding to equal the renderer's output. It also requires declarations the files must hold: the system spec and manifest fields and their derivation, the closure release inputs, the builder's dispatch, the root's locate and dispatch, and the service's read. A declaration shows that code exists and not what it does. The expectation is `scripts/lib/zenoh_limits_exam.py`. The recipe fails until the implementation lands. |
| `just zenoh_service_component_check` | Judges that the Zenoh service component exists and is registered. The judge requires the crate and its manifest, the release profile, the component spec, the library export of the server half, and the calls that read the grants, decode them, own the link and use the server half. The expectation is `scripts/lib/zenoh_service_component_exam.py`. The recipe fails until the component lands. |
| `just zenoh_service_booted_check` | Judges the composition that runs the Zenoh service with two holders, and boots it under QEMU. The judge requires the system spec, the derived manifest, the inventory row and the arm of the network plane checker, and then runs that arm. The arm requires the holders to exchange through the service and requires the service to refuse a key that a holder lacks. The recipe is in no aggregate. It fails until the composition lands. |
| `just zenoh_service_grants_table_check` | Judges the Zenoh service grants table. The judge writes each table again with Python's `struct` from the schema's layout, and requires the encoder, the generated wire records and the Rust decoder to agree with it. It refuses each corruption of a table. The expectation is `scripts/lib/zenoh_grants_table_exam.py`. |
| `just zenoh_service_client_abort_check` | Judges what the Zenoh service client adapter does when an attach fails after both loans arrived. The Rust test plays a scripted service and prints each request sent, the loans back and the answers unread at each send. The judge requires the loans back before the abort, the attach answer read before it is sent and no abort where the service holds no session. The expectation is `scripts/lib/zenoh_client_abort_exam.py`. |
| `just zenoh_service_link_check` | Judges the Zenoh service core over a link. The core queues a declaration or a publication through the link's single send slot and refuses a second call as busy. It delivers a publication to the local rings only after the slot flushed. A peer's sample reaches the holders by the subscription that matched. A burst that the service does not drain is counted as loss. A stream that takes a frame and then resets leaves no copy in a ring. `scripts/lib/zenoh_wire.py` reproduces the frames byte for byte. The subscribers, links and stock-peer exams run beside it, with their controls. Explicit. It fails until the link-facing core lands. |
| `just frame_store_check` | Judges `contracts/frame-store/v1`, its Rust reader and its MCAP converter. It requires the LiDAR bag named by `SLIME_LIDAR_BAG` to have the pinned size and SHA-256. It converts the bag's `/velodyne_points` channel twice and requires both stores to equal the store the exam encodes from its own MCAP reading. It converts a two-channel bag built from the bag's messages and refuses six bags by class: a wrong digest, a compressed chunk and a missing channel. The Rust reader must read 70 stores exactly as the exam's decoder does. These are the committed fixture, the converted store and 68 corpus stores, 61 of them refused by class. Fourteen corpus stores hold two faults, so a reader must also check in the contract's order. Explicit, because the bag is never committed. |
| `just data_volume_check` | Judges `contracts/data-volume/v1`. `scripts/build/build-data-volume.py` must write exactly the exam's disk for its frame store and for the committed frame-store fixture, and refuse an unknown kind, a payload that is not a frame store and an existing output. The `sel4-data-volume` image boots on aarch64 QEMU with the honest disk attached read-only: `data-volume-probe` reports the payload's length and SHA-256, the frames and their digest, a write the driver refused, and its heap. Fifty disks the exam corrupted, one per check of its decoder, are each refused with their check's class; each boot is read five seconds past its terminal line. |
| `just frame_store_tools_check` | The converter library without the bag. RIHS01 matches five published type hashes. The ros2msg field forms map to their rosidl type ids. Each refusal class is produced. The committed reader fixture equals the one the library writes. Explicit. |
| `just zenoh_subscribers_check` | Judges a Zenoh Profile 0 session that holds as many subscriptions of its own as `Params.local` says. It declares three and delivers to each key. It undeclares one and reuses its slot. Two subscriptions on one key deliver once, and close releases all of them. The exam has thirteen refusals by name and class. `scripts/lib/zenoh_wire.py` reproduces the three declaration frames and the undeclaration frame byte for byte. The links and stock-peer exams run beside it. Explicit. It fails until the session takes the parameter. |
| `just zenoh_undeclare_check` | A Zenoh Profile 0 connector session taking the whole session a stock eclipse-zenoh 1.0.0 peer sent, including its UndeclareSubscriber that names the subscriber by id alone inside a DECLARE carrying the network QoS extension (reproduced byte for byte by `scripts/lib/zenoh_wire.py`), with ten variants of it refused by name and class, and the stock corpus and the stock-peer exam required beside it. Explicit; fails until the session takes the bare undeclaration. |
| `just zenoh_composition_check` | The derived `sel4-zenoh` composition grants the two nodes exactly the demo's authority, judged against 15 mutations of an honest composition; fails until the composition lands. |
| `just lidar_publish_check` | `sel4-lidar-external` boots on aarch64 QEMU with the LiDAR frame store on a read-only disk and publishes every frame to a stock `eclipse-zenoh==1.0.0` peer on the host, built from the wheel pinned for the host. The exam encodes the store from the bag `SLIME_LIDAR_BAG` names and requires the builder's disk to equal the data-volume contract's image of it. It judges the transcript, a packet capture holding exactly one TCP connection to `10.0.2.2:17447`, and the peer's `contracts/zenoh-digest-receipt/v1` record against the store: every frame in order, byte for byte, in batches of at most 4096 bytes, each Put at least 495 ms after the one before. Needs the bag and a registry, so explicit and in no aggregate; fails until the `sel4-lidar-external` composition lands. |
| `just zenoh_external_check` | The demo's guest connects out over a virtio NIC to a stock `eclipse-zenoh==1.0.0` listener on the host, built from a hash-pinned wheel: the listener's own record of the four samples, a packet capture holding exactly one TCP connection to `10.0.2.2:17447` and no DNS, UDP or ICMP, and the guest's report are judged against one another and the host wire reference; needs the wheel from a registry, so explicit and in no aggregate; fails until the `sel4-zenoh-external` composition lands. |
| `just rpi5_ros2_zenoh_check` | R0's end-to-end claim: the composition and the four host recipes, then two node components exchange the declared topic over Zenoh Profile 0 under AArch64 QEMU, each reported batch judged byte for byte against the host wire reference; explicit, never part of `all`; fails until every slice lands. |
| `just rpi5_serial_monitor serial timeout` | Bring-up aid only: monitor debug UART without qualifying the board. |
| `just sel4_duo_image_check` | One seL4 build platform: the board or machine an image targets. |
| `just sel4_rpi5_image_check` | Uses the board-specific bcm2712 prefix, target directory, generation, image, and pinned hashes; it is not interchangeable with the qemu-arm-virt build. |

## runtime

| Recipe | Does |
| --- | --- |
| `just private_memory_adaptive_lifecycle_check` | The same composition under one compiled-in revoke failure: a live incarnation is quarantined, refunds nothing, and is returned by exactly one retry. |

## compatibility

| Recipe | Does |
| --- | --- |
| `just aarch64_boot_check` | alias → `sel4_root_boot_check` |
| `just aarch64_trap_check` | alias → `sel4_root_boot_check` |
| `just boot_layout_check` | alias → `sel4_boot_layout_check` |
| `just dango_check` | alias → `slisp_core_check` |
| `just data_fabric_boot_check` | alias → `sel4_boot_check` |
| `just data_fabric_check` | alias → `sel4_fabric_aggregate_check` |
| `just data_fabric_fault_check` | alias → `sel4_fault_check` |
| `just data_fabric_matrix_check` | alias → `sel4_matrix_check` |
| `just data_fabric_saturation_check` | alias → `sel4_saturation_check` |
| `just data_fabric_traffic_check` | alias → `sel4_traffic_check` |
| `just directory_check` | alias → `sel4_filesystem_check` |
| `just fabric_authority_check` | alias → `sel4_stream_check` |
| `just fabric_call_check` | alias → `sel4_call_check` |
| `just fabric_operation_check` | alias → `sel4_operation_check` |
| `just fabric_qos_check` | alias → `sel4_qos_check` |
| `just fabric_stream_check` | alias → `sel4_stream_check` |
| `just fabric_visibility_check` | alias → `sel4_visibility_check` |
| `just framework_inventory_check` | Retired: prints that H1 hardware inventory awaits a seL4 Framework device path. |
| `just generation_cmd_check` | alias → `sel4_generation_check` |
| `just powerbox_check` | alias → `sel4_powerbox_check` |
| `just product_boot_check` | alias → `sel4_component_graph_check` |
| `just recovery_check` | alias → `sel4_recovery_plane_check` |
| `just rollback_check` | alias → `sel4_rollback_check` |
| `just rpi5_arm_slice_check` | alias → `sel4_demo_check` |
| `just sample_plane_check` | alias → `sel4_sample_check` |
| `just sample_plane_live_check` | alias → `sel4_sample_check` |
| `just sel4_dango_check` | alias → `slisp_core_check` |
| `just shared_buffer_accounting_check` | alias → `sel4_loan_check` |
| `just shared_buffer_factory_check` | alias → `sel4_loan_check` |
| `just shared_buffer_loan_check` | alias → `sel4_loan_check` |
| `just shared_buffer_mapping_check` | alias → `sel4_loan_check` |
| `just spawn_prereq_check` | alias → `sel4_spawn_check` |
| `just spawn_service_check` | alias → `sel4_spawn_check` |
| `just storage_cap_check` | alias → `sel4_storage_check` |
| `just storage_fault_check` | alias → `sel4_storage_check` |
| `just storage_nvme_read_check` | Fails closed: physical NVMe evidence is not available. |
| `just storage_read_check` | alias → `sel4_storage_check` |
| `just storage_store_check` | alias → `sel4_store_check` |
| `just storage_write_check` | alias → `sel4_storage_check` |
| `just transfer_check` | alias → `sel4_transfer_check` |
