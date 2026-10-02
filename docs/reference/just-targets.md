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
| `just private_memory_policy_check` | Formatting, lint, and host tests plus the private-memory policy planes. |
| `just ruff` | `ruff check scripts/` |
| `just ruff_fix` | `ruff check scripts/ --fix` |
| `just sel4_gate_control_check` | Prove seL4 gates fail closed when evidence or shared execution breaks. |
| `just smoltcp_matrix_check` | The smoltcp support matrix in the network data-plane plan against the locked release, its checksum-verified crate archive, and the network service's enabled features; needs `cargo fetch --locked`. |
| `just tasks_check` | `myque check` plus backlog-first policy, spec-driven mandate, terminal records, devloop validation, and `codePaths` coverage. |
| `just closeout_checkout_check` | The tree the closeout script runs devloop in covers every `.devloop/policy.json` `codePaths` entry, and a checkout without submodules is refused; clones canonical main, so it needs the network and is not in CI. |
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
| `just contracts_check` | Aggregate: `contracts_source_check`, `generation_v5_check`. |
| `just contracts_source_check` | Type-check every contract schema and renderer and refuse stale generated bindings (`check-contracts.py`). |
| `just data_fabric_profile_check` | C8.9 typed full-profile and resource-bound closure gate. |
| `just data_fabric_trace_check` | Refuse stale fabric-trace bindings. |
| `just fabric_manifest_check` | C8.2 fabric-graph generation admission gate. |
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
| `just system_image_closure_check` | Render `contracts/system-image-closure/v2` host constants. |
| `just system_image_scenario_check` | CP14 scenario-identity gate. |
| `just system_spec_check` | Validate every system spec and refuse a derived composition manifest that drifted from it. |
| `just system_test_run_baseline_check` | One execution identity covers the declaration/closure boundary and its quality gates. |
| `just system_test_run_bless` | Generate `contracts/system-test-run/v1` records from each plane gate's execution inputs. |
| `just system_test_run_check` | Execution-only inputs — disks, devices, injected faults, timeouts, marker contracts — are declared per plane and frozen, so a timeout or a disk cannot change without a reviewed record change. |

## generate

| Recipe | Does |
| --- | --- |
| `just block_gen` | `python3 scripts/generate/generate-block-bindings.py` |
| `just boot_gen` | Regenerate `boot-contracts/src/generated/` and `scripts/lib/boot_contracts.py` from every boot-family schema. |
| `just boot_media_gen` | Render `contracts/boot-media/v1`'s host constants. |
| `just bootstate_gen` | Aggregate: `boot_gen`. |
| `just capability_transfer_gen` | `python3 scripts/generate/generate-capability-transfer-bindings.py` |
| `just component_gen` | `python3 scripts/generate/generate-component-bindings.py` |
| `just component_runtime_abi_gen` | The `label -> operation` pairs the contract declared, from its own output. |
| `just component_sdk_release_gen` | Render `contracts/component-sdk-release/v1`'s host constants. |
| `just cpu_boot_observation_gen` | Render `contracts/cpu-boot-observation/v1`'s host constants. |
| `just fabric_graph_gen` | Aggregate: `boot_gen`. |
| `just fabric_ring_gen` | `python3 scripts/generate/generate-fabric-ring-bindings.py` |
| `just fabric_stream_gen` | `python3 scripts/generate/generate-fabric-stream-bindings.py` |
| `just fabric_trace_gen` | `python3 scripts/generate/generate-fabric-trace-bindings.py` |
| `just fabric_visibility_gen` | `python3 scripts/generate/generate-fabric-visibility-bindings.py` |
| `just generation_gen` | Aggregate: `boot_gen`. |
| `just generation_management_gen` | `python3 scripts/generate/generate-generation-management-bindings.py` |
| `just interface_schema_gen` | `python3 scripts/generate/generate-interface-schema-bindings.py` |
| `just io_queue_gen` | `python3 scripts/generate/generate-io-queue-bindings.py` |
| `just kernel_image_gen` | Aggregate: `boot_gen`. |
| `just link_device_gen` | `python3 scripts/generate/generate-link-device-bindings.py` |
| `just mavlink_heartbeat_gen` | `python3 scripts/generate/generate-mavlink-heartbeat-bindings.py` |
| `just network_service_gen` | `python3 scripts/generate/generate-network-service-bindings.py` |
| `just powerbox_gen` | `python3 scripts/generate/generate-powerbox-bindings.py` |
| `just private_memory_probe_gen` | `python3 scripts/generate/generate-private-memory-probe-bindings.py` |
| `just pwm_servo_gen` | `python3 scripts/generate/generate-pwm-servo-bindings.py` |
| `just sample_descriptor_gen` | `python3 scripts/generate/generate-sample-descriptor-bindings.py` |
| `just serial_device_gen` | `python3 scripts/generate/generate-serial-device-bindings.py` |
| `just spawn_gen` | `python3 scripts/generate/generate-spawn-bindings.py` |
| `just store_gen` | `python3 scripts/generate/generate-store-bindings.py` |
| `just syscall_abi_gen` | The `label -> operation` pairs the contract declared, from its own table. |

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
| `just sel4_net_check` | The resident Slisp shell spawns http-get with a string argument on `sel4-net`; the body is judged against the controlled peer and refusals against the wire, with the spawn, product-graph, Slisp and host regressions. |
| `just sel4_entropy_check` | Entropy authority on `sel4-entropy`: seeded draws judged against the host HMAC-DRBG, hardware draws distinct and fail-closed without virtio-rng, budgets and request sizes refused; fails until the composition lands. |
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
| `just clock_authority_check` | C9.1 gate: declared clock authority is independent, bounded, and deny-by-default. |
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
| `just rpi5_boot_check serial` | Physical gate: require ordered boot evidence from the pinned build on UART10. |
| `just rpi5_media_check` | Flatten via the media builder: objcopy drops the sectionless loader payload. |
| `just rpi5_ros2_demo_contract_check` | RP0 target-qualified Raspberry Pi 5 ROS 2 demo contract gate. |
| `just rpi5_ros2_demo_contract_v2_check` | RP0 format-2 Raspberry Pi 5 ROS 2 demo contract gate. |
| `just zenoh_encoder_check` | Zenoh Profile 0 encoder reproduces every upstream-encoded batch in the decoder corpus byte for byte, after the host wire reference proves itself against the same corpus, and refuses seven named bad inputs; fails until the encoder lands. |
| `just zenoh_session_check` | Zenoh Profile 0 session machine completes five named scenarios and refuses seven named inputs, as pure state transitions with injected time; fails until the session machine lands. |
| `just zenoh_cdr_check` | Classic-CDR codec reproduces the demo fixture's four Counter samples, recomputed from their field values, and refuses seven malformed inputs; fails until the codec lands. |
| `just zenoh_transport_check` | Zenoh transport runtime over a scripted byte link: six scenarios (split and coalesced batches, backpressure, peer close, restart) and seven refusals; fails until the runtime lands. |
| `just zenoh_composition_check` | The derived `sel4-zenoh` composition grants the two nodes exactly the demo's authority, judged against 15 mutations of an honest composition; fails until the composition lands. |
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
