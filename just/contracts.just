[private]
_zutai_model path:
    cargo build --release --manifest-path deps/zutai/Cargo.toml -q -p zutai-cli
    ZUTAI_STDLIB_ROOT=deps/zutai/stdlib deps/zutai/target/release/zutai-cli model-check {{path}}

[group('contracts')]
bootstate_model_check: (_zutai_model "contracts/bootstate/model/bootstate.zt")

[group('contracts')]
capability_rights_model_check: (_zutai_model "contracts/capability-rights/model/capability-rights.zt")

[group('contracts')]
io_queue_model_check: (_zutai_model "contracts/io-queue/model/io-queue.zt")

[group('contracts')]
io_resource_model_check: (_zutai_model "contracts/io-resource/model/io-resource.zt")

[group('contracts')]
io_model_check: io_queue_model_check io_resource_model_check

[group('contracts')]
bootstate_trace_check: bootstate_model_check sel4_rollback_check
    python3 scripts/check/check-bootstate-trace.py

[group('contracts')]
release_trust_runtime_check: sel4_rollback_check
    python3 scripts/check/check-release-trust.py

[group('contracts')]
release_trust_check: contracts_check release_trust_runtime_check

[group('contracts')]
contracts_source_check: bootstate_model_check capability_rights_model_check io_queue_model_check io_resource_model_check
    python3 scripts/check/check-contracts.py
    python3 scripts/generate/generate-spawn-bindings.py --check
    python3 scripts/generate/generate-pwm-servo-bindings.py --check
    python3 scripts/generate/generate-serial-device-bindings.py --check
    python3 scripts/generate/generate-mavlink-heartbeat-bindings.py --check
    python3 scripts/generate/generate-link-device-bindings.py --check
    python3 scripts/generate/generate-network-service-bindings.py --check
    python3 scripts/generate/generate-zenoh-profile-bindings.py --check
    python3 scripts/check/check-boot-layout-resource.py
    python3 scripts/check/check-lifecycle-identity.py
    python3 scripts/generate/generate-fabric-ring-bindings.py --check
    python3 scripts/generate/generate-syscall-abi-bindings.py --check
    python3 scripts/generate/generate-component-runtime-abi-bindings.py --check

[group('contracts')]
generation_v5_check shard_index="0" shard_count="1":
    python3 scripts/check/check-generation-v5.py --shard-index {{ shard_index }} --shard-count {{ shard_count }}

[group('contracts')]
contracts_check: contracts_source_check generation_v5_check

[group('contracts')]
architecture_contract_check: contracts_check
    python3 scripts/check/check-architecture-contract.py

[group('contracts')]
interface_schema_check: contracts_check
    python3 scripts/check/check-interface-schema.py

[group('contracts')]
component_spec_validation_check:
    python3 scripts/check/check-component-spec.py

[group('contracts')]
component_spec_check: contracts_check component_spec_validation_check

# Depends on component-record validation alone, not on `contracts_check`. What
# this recipe proves — specs parse, and every derived composition manifest still
# matches the spec it came from — cannot change because the 42-manifest
# generation corpus was or was not rebuilt first, and rebuilding it here costs
# 15 minutes. `contracts_check` remains its own gate; CI runs it sharded.
[group('contracts')]
system_spec_check: component_spec_validation_check
    python3 scripts/check/check-system-spec.py
    python3 scripts/generate/generate-generation-from-spec.py --check

[group('contracts')]
system_composition_closure_check: system_spec_check
    python3 scripts/generate/generate-composition-inventory-bindings.py --check
    python3 scripts/check/check-composition-inventory.py

# Resolution checks each closure's committed prefix against `sel4/pins.toml`;
# no installed platform build or published SDK record is needed for that check.
# The checker runs the closure freshness check itself, before anything else.
[group('contracts')]
system_image_builder_check: system_composition_closure_check
    python3 scripts/check/check-system-image-builder.py

# Execution-only inputs — disks, devices, injected faults, timeouts, marker
# contracts — are declared per plane and frozen, so a timeout or a disk cannot
# change without a reviewed record change. Bless with `just system_test_run_bless`.
[group('contracts')]
system_test_run_check:
    python3 scripts/check/check-system-test-run.py

# One execution identity covers the declaration/closure boundary and its quality gates.
[group('contracts')]
system_test_run_baseline_check: system_image_closure_check system_test_run_check
    just tasks_check
    just docs_check
    just ruff
    just typos

[group('contracts')]
system_test_run_bless:
    python3 scripts/generate/generate-system-test-runs.py --bless

# Every shipped or tested image traces to exactly one closure, and every
# closure is exercised by an owning gate. Cheap by design: a mapping only
# checked before a release is a mapping that drifts between releases.
[group('contracts')]
system_image_closure_aggregate_check:
    python3 scripts/check/check-system-image-aggregate.py

[group('contracts')]
system_image_scenario_check: system_image_builder_check
    python3 scripts/check/check-system-image-scenario.py


[group('contracts')]
system_image_closure_check: system_spec_check
    python3 scripts/generate/generate-system-image-closure-bindings.py --check
    python3 scripts/generate/generate-system-test-run-bindings.py --check
    python3 scripts/check/check-system-image-closure.py

[group('contracts')]
fabric_manifest_check: contracts_check sel4_stream_check
    python3 scripts/check/check-fabric-manifest.py

[group('contracts')]
data_fabric_profile_check: contracts_check
    python3 scripts/check/check-data-fabric-profile.py

[group('contracts')]
data_fabric_trace_check: contracts_check sel4_trace_check
    python3 scripts/generate/generate-fabric-trace-bindings.py --check

[group('contracts')]
sample_descriptor_check: contracts_check sel4_sample_check
