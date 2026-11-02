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
    python3 scripts/generate/generate-zenoh-stock-bindings.py --check
    python3 scripts/generate/generate-zenoh-stock-bindings.py --controls
    python3 scripts/generate/generate-zenoh-undeclare-bindings.py --check
    python3 scripts/generate/generate-zenoh-undeclare-bindings.py --controls
    python3 scripts/check/check-boot-layout-resource.py
    python3 scripts/check/check-lifecycle-identity.py
    python3 scripts/generate/generate-syscall-abi-bindings.py --check
    python3 scripts/generate/generate-component-runtime-abi-bindings.py --check

[group('contracts')]
generation_v5_check shard_index="0" shard_count="1":
    python3 scripts/check/check-generation-v5.py --shard-index {{ shard_index }} --shard-count {{ shard_count }}

[group('contracts')]
generation_corpus_check shard_index="0" shard_count="1":
    python3 scripts/check/check-generation-corpus.py --shard-index {{ shard_index }} --shard-count {{ shard_count }}

[group('contracts')]
contracts_check: contracts_source_check generation_corpus_check

# Retirement of the generation v5 guard: the corpus still builds, and its
# checker, recipe, codePaths entry, reference row and CI steps are gone. The
# bracketed patterns keep this recipe from matching itself.
[group('contracts')]
generation_v5_retired_check: generation_corpus_check
    @if test -e scripts/check/check-generation-v[5].py; then echo 'the v5 guard checker still exists' >&2; exit 1; fi
    @if grep -rnE 'generation_v5[_]check|check-generation-v5[.]py' just Justfile .devloop/policy.json .github docs/reference/just-targets.md; then echo 'the v5 guard is still referenced above' >&2; exit 1; fi

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
    python3 scripts/generate/generate-bindings.py --check composition-inventory
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

# Run discovery and per-arm extraction controls, then the complete frozen-record gate.
[group('contracts')]
system_test_run_inventory_check:
    python3 scripts/check/check-system-test-run.py --inventory-controls
    python3 scripts/check/check-system-test-run.py

# Test-run records name their image closure instead of copying its identity (contracts/system-test-run/v2).
# In a scratch checkout of HEAD, a closure input change must rewrite no test-run record and no negative
# build case, and check-system-test-run.py must refuse a wrong closure name. The expectation is
# scripts/lib/test_run_reference_exam.py.
[group('contracts')]
system_test_run_reference_check:
    python3 scripts/check/check-system-test-run-references.py

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

# Committed closure inputs carry no host path: no file under contracts/system-image-closure/v2/inputs/
# names a home directory or this checkout, each committed seL4 prefix names its libsel4 generator inputs
# under /slime/sel4, and the riscv64 prefix headers hold their pinned canonicalized bytes. Explicit, so it
# can land before the riscv64 snapshot is fixed.
[group('contracts')]
closure_input_host_paths_check:
    python3 scripts/check/check-system-image-closure.py --input-host-paths

# Closure sources carry no in-tree digest, and each checkout derives their identities. In a scratch checkout
# of HEAD, sampled closures resolve to identities computed independently over the files git lists, dirty
# inputs move exactly the expected derivation ids, and the generator rewrites no committed file; then
# sel4-channel builds clean and dirty. The expectation is scripts/lib/closure_derivation_exam.py.
[group('contracts')]
closure_derivation_check:
    python3 scripts/check/check-closure-derivations.py

# Image attestations: in a scratch clone with a bare remote, scripts/build/attest-system-images.py attests
# sel4-channel, survives a concurrent writer, reproduces its digests at a later commit, and refuses an
# attested commit, an unknown closure, a dirty input and a mismatched note; --check judges the notes; the
# nightly workflow runs it as declared. The expectation is scripts/lib/image_attestation_exam.py.
[group('contracts')]
image_attestation_check:
    python3 scripts/check/check-image-attestations.py

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
    python3 scripts/generate/generate-bindings.py --check system-image-closure
    python3 scripts/generate/generate-bindings.py --check system-test-run
    python3 scripts/check/check-system-image-closure.py

# Every gate that consumes the committed closure corpus, on one tree: freshness,
# resolution and its controls, the frozen test-run records and their inventory
# controls, the scenario and root-role arms, and image/closure ownership.
[group('contracts')]
system_image_closure_gates_check: system_image_closure_check system_test_run_inventory_check system_image_scenario_check system_image_closure_aggregate_check
    python3 scripts/generate/generate-system-image-closures.py --check

[group('contracts')]
fabric_manifest_check: contracts_check sel4_stream_check
    python3 scripts/check/check-fabric-manifest.py

[group('contracts')]
data_fabric_profile_check: contracts_check
    python3 scripts/check/check-data-fabric-profile.py

[group('contracts')]
data_fabric_trace_check: contracts_check sel4_trace_check
    python3 scripts/generate/generate-bindings.py --check fabric-trace

[group('contracts')]
sample_descriptor_check: contracts_check sel4_sample_check
