[group('generate')]
io_queue_gen:
    python3 scripts/generate/generate-io-queue-bindings.py
[group('generate')]
link_device_gen:
    python3 scripts/generate/generate-link-device-bindings.py

[group('generate')]
network_service_gen:
    python3 scripts/generate/generate-network-service-bindings.py

[group('generate')]
zenoh_profile_gen:
    python3 scripts/generate/generate-zenoh-profile-bindings.py


[group('generate')]
block_gen:
    python3 scripts/generate/generate-block-bindings.py

[group('generate')]
component_gen:
    python3 scripts/generate/generate-component-bindings.py

[group('generate')]
store_gen:
    python3 scripts/generate/generate-store-bindings.py

[group('generate')]
spawn_gen:
    python3 scripts/generate/generate-spawn-bindings.py

[group('generate')]
pwm_servo_gen:
    python3 scripts/generate/generate-pwm-servo-bindings.py

[group('generate')]
serial_device_gen:
    python3 scripts/generate/generate-serial-device-bindings.py

[group('generate')]
mavlink_heartbeat_gen:
    python3 scripts/generate/generate-mavlink-heartbeat-bindings.py

[group('generate')]
component_runtime_abi_gen:
    python3 scripts/generate/generate-component-runtime-abi-bindings.py

[group('generate')]
syscall_abi_gen:
    python3 scripts/generate/generate-syscall-abi-bindings.py

[group('generate')]
sample_descriptor_gen:
    python3 scripts/generate/generate-sample-descriptor-bindings.py

[group('generate')]
interface_schema_gen:
    python3 scripts/generate/generate-interface-schema-bindings.py

[group('generate')]
capability_transfer_gen:
    python3 scripts/generate/generate-capability-transfer-bindings.py

[group('generate')]
fabric_stream_gen:
    python3 scripts/generate/generate-fabric-stream-bindings.py

[group('generate')]
fabric_ring_gen:
    python3 scripts/generate/generate-fabric-ring-bindings.py

[group('generate')]
fabric_trace_gen:
    python3 scripts/generate/generate-fabric-trace-bindings.py

[group('generate')]
fabric_visibility_gen:
    python3 scripts/generate/generate-fabric-visibility-bindings.py

[group('generate')]
fabric_graph_gen: boot_gen

[group('generate')]
generation_management_gen:
    python3 scripts/generate/generate-generation-management-bindings.py

[group('generate')]
powerbox_gen:
    python3 scripts/generate/generate-powerbox-bindings.py

[group('generate')]
private_memory_probe_gen:
    python3 scripts/generate/generate-private-memory-probe-bindings.py

[group('generate')]
component_sdk_release_gen:
    python3 scripts/generate/generate-component-sdk-release-bindings.py


[group('generate')]
boot_media_gen:
    python3 scripts/generate/generate-boot-media-bindings.py
[group('generate')]
cpu_boot_observation_gen:
    python3 scripts/generate/generate-cpu-boot-observation-bindings.py
[group('generate')]
boot_gen:
    python3 scripts/generate/generate-boot-bindings.py

[group('generate')]
generation_gen: boot_gen

[group('generate')]
kernel_image_gen: boot_gen

[group('generate')]
bootstate_gen: boot_gen
