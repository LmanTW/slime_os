[group('generate')]
io_queue_gen:
    python3 scripts/generate/generate-bindings.py io-queue
[group('generate')]
link_device_gen:
    python3 scripts/generate/generate-bindings.py link-device

[group('generate')]
network_service_gen:
    python3 scripts/generate/generate-bindings.py network-service

[group('generate')]
zenoh_profile_gen:
    python3 scripts/generate/generate-bindings.py zenoh-profile

[group('generate')]
zenoh_stock_gen:
    python3 scripts/generate/generate-zenoh-stock-bindings.py

[group('generate')]
zenoh_undeclare_gen:
    python3 scripts/generate/generate-zenoh-undeclare-bindings.py

# Renders the constants of contracts/zenoh-service-grants/v1 as components/proto/src/zenoh_service_grants.rs.
# The grants exam requires the committed file to equal this output byte for byte.
[group('generate')]
zenoh_service_grants_gen:
    python3 scripts/generate/generate-zenoh-service-grants-bindings.py

# Renders the constants of contracts/zenoh-service-client/v1 as components/proto/src/zenoh_service_client.rs.
# The client exam requires the committed file to equal this output byte for byte.
[group('generate')]
zenoh_service_client_gen:
    python3 scripts/generate/generate-zenoh-service-client-bindings.py

# Renders the wire record of contracts/zenoh-service-limits/v1 as components/proto/src/zenoh_service_limits_wire.rs.
# The limits exam requires the committed file to equal this output byte for byte.
[group('generate')]
zenoh_service_limits_gen:
    python3 scripts/generate/generate-zenoh-service-limits.py

# Renders the wire records of contracts/zenoh-service-grants-table/v1 as components/proto/src/zenoh_service_grants_table_wire.rs.
# The grants table exam requires the committed file to equal this output byte for byte.
[group('generate')]
zenoh_service_grants_table_gen:
    python3 scripts/generate/generate-zenoh-service-grants-table.py

# Renders the wire records of contracts/zenoh-service-client/v1 as components/proto/src/zenoh_service_client_wire.rs.
# The wire exam requires the committed file to equal this output byte for byte.
[group('generate')]
zenoh_service_client_wire_gen:
    python3 scripts/generate/generate-zenoh-service-client-wire.py


[group('generate')]
block_gen:
    python3 scripts/generate/generate-bindings.py block

[group('generate')]
component_gen:
    python3 scripts/generate/generate-bindings.py component

[group('generate')]
store_gen:
    python3 scripts/generate/generate-bindings.py store

[group('generate')]
spawn_gen:
    python3 scripts/generate/generate-bindings.py spawn

[group('generate')]
pwm_servo_gen:
    python3 scripts/generate/generate-bindings.py pwm-servo

[group('generate')]
entropy_gen:
    python3 scripts/generate/generate-bindings.py entropy

[group('generate')]
serial_device_gen:
    python3 scripts/generate/generate-bindings.py serial-device

[group('generate')]
frame_store_gen:
    python3 scripts/generate/generate-bindings.py frame-store

[group('generate')]
mavlink_heartbeat_gen:
    python3 scripts/generate/generate-bindings.py mavlink-heartbeat

[group('generate')]
component_runtime_abi_gen:
    python3 scripts/generate/generate-component-runtime-abi-bindings.py

[group('generate')]
syscall_abi_gen:
    python3 scripts/generate/generate-syscall-abi-bindings.py

[group('generate')]
sample_descriptor_gen:
    python3 scripts/generate/generate-bindings.py sample-descriptor

[group('generate')]
interface_schema_gen:
    python3 scripts/generate/generate-interface-schema-bindings.py

[group('generate')]
capability_transfer_gen:
    python3 scripts/generate/generate-bindings.py capability-transfer

[group('generate')]
fabric_stream_gen:
    python3 scripts/generate/generate-bindings.py fabric-stream

[group('generate')]
fabric_ring_gen:
    python3 scripts/generate/generate-bindings.py fabric-ring

[group('generate')]
fabric_trace_gen:
    python3 scripts/generate/generate-bindings.py fabric-trace

[group('generate')]
fabric_visibility_gen:
    python3 scripts/generate/generate-bindings.py fabric-visibility

[group('generate')]
fabric_graph_gen: boot_gen

[group('generate')]
generation_management_gen:
    python3 scripts/generate/generate-bindings.py generation-management

[group('generate')]
powerbox_gen:
    python3 scripts/generate/generate-bindings.py powerbox

[group('generate')]
private_memory_probe_gen:
    python3 scripts/generate/generate-bindings.py private-memory-probe

[group('generate')]
component_sdk_release_gen:
    python3 scripts/generate/generate-bindings.py component-sdk-release


[group('generate')]
boot_media_gen:
    python3 scripts/generate/generate-bindings.py boot-media
[group('generate')]
cpu_boot_observation_gen:
    python3 scripts/generate/generate-bindings.py cpu-boot-observation
[group('generate')]
boot_gen:
    python3 scripts/generate/generate-boot-bindings.py

[group('generate')]
generation_gen: boot_gen

[group('generate')]
kernel_image_gen: boot_gen

[group('generate')]
bootstate_gen: boot_gen
