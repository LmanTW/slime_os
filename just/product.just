# Pin validation is offline: submodules and the pinned toolchain must already
# be installed.
[group('product')]
sel4_pin_check:
    python3 scripts/check/check-sel4-pins.py

# Produces build/slime-sel4.identity.json for the boot gate.
[group('product')]
sel4_qemu_image_check: sel4_pin_check
    python3 scripts/build/build-sel4.py --skip-pin-check

# Rebuilds before boot so QEMU runs the bytes named by the identity manifest.
[group('product')]
sel4_root_boot_check: sel4_pin_check
    python3 scripts/check/check-sel4-root-boot.py

# P3 replays the architecture-neutral corpus on the pinned RV64 reference.
[group('product')]
riscv64_qemu_image_check: sel4_pin_check
    python3 scripts/build/build-sel4.py --platform qemu-riscv-virt --skip-pin-check

# P6.1 builds the admitted x86-64 seL4 kernel, root task, child fixture, and
# generation for the pinned QEMU pc99 profile, and P6.2 assembles the GRUB
# Multiboot2 EFI tree that supplies the two ELFs as modules. Deliberately no
# boot here: `x86_64_sel4_root_boot_check` owns the boot claim.
[group('product')]
x86_64_sel4_image_check: sel4_pin_check
    python3 scripts/build/build-sel4.py --platform qemu-pc99 --skip-pin-check
    python3 scripts/check/check-sel4-x86-64-image.py

# P6.2's boot contract and P6.3's native execution slice. One gate because they
# are one observation: the ordered marker chain only exists if the shared GRUB
# Multiboot2 layout booted pinned q35/OVMF *and* the root's native x86-64 task,
# fault, timer, thread-pointer, and reclamation arms all behaved.
[group('product')]
x86_64_sel4_root_boot_check: sel4_pin_check
    python3 scripts/check/check-sel4-root-boot.py --platform qemu-pc99

# P6.4 replays the architecture-neutral corpus on the pinned x86-64 reference,
# in the same shape as `riscv64_qemu_check`.
[group('product')]
x86_64_qemu_check: sel4_pin_check
    python3 scripts/check/check-sel4-root-boot.py --platform qemu-pc99
    python3 scripts/check/check-sel4-wait-set-plane.py --platform qemu-pc99
    python3 scripts/check/check-sel4-sample-plane.py --platform qemu-pc99
    python3 scripts/check/check-sel4-component-graph.py --platform qemu-pc99
    python3 scripts/check/check-sel4-boot-layout.py --platform qemu-pc99
    python3 scripts/check/check-architecture-portability.py

# The x86-64 C component link runs no host compiler driver. The gate builds
# the pc99 image for the installed seL4 headers, so it needs an x86-64 host.
# It then builds the product Slisp component on a PATH that holds `ld.lld`
# and traps, and refuses two controls. The inputs name what that build reads;
# without them the closure digest would cover no file under scripts/build/.
[group('product')]
[metadata("inputs", "scripts/build/build-c-component.py", "components/slisp/**", "components/runtime/c/**", "components/runtime/include/**")]
x86_64_component_link_check: sel4_pin_check
    python3 scripts/check/check-c-component-link.py --architecture x86_64

# P6.5 builds one Framework-target-qualified raw GPT/FAT32 image, validates the
# identity and removable-writer safety boundary, then boots those exact bytes
# under the pinned q35/OVMF reference to the resident product graph.
[group('product')]
framework_media_check: sel4_pin_check contracts_check
    python3 scripts/check/check-framework-media.py

[group('product')]
framework_media_image: sel4_pin_check contracts_check
    python3 scripts/build/build-framework-media.py

# P6.6 judges a physical Framework CPU boot. `framework_cpu_boot_check` proves
# the observation validator refuses bad evidence and reports the recorded
# claim; it cannot manufacture one, because only a power cycle from the medium
# can. `framework_cpu_boot_prepare` writes the approved image and hashes the
# protected internal region, and `framework_cpu_boot_verify` re-hashes it and
# judges the operator's record. QEMU cannot close this gate.
[group('product')]
framework_cpu_boot_check: framework_media_check
    python3 scripts/check/check-framework-cpu-boot.py

[group('product')]
framework_cpu_boot_prepare device protect: framework_media_check
    python3 scripts/check/check-framework-cpu-boot.py prepare --device {{device}} --protect {{protect}}

# Arguments pass through unchanged, as positional arguments so a quoted product
# or CPU string stays intact, to `check-framework-cpu-boot.py verify`:
# `--boots <file> --operator <name> --observed-on <date> --machine-vendor ...
# --machine-product ... --machine-cpu ... --firmware-vendor ...
# --firmware-version ... [--secure-boot] [--state <file>] [--output <file>]`.
# P6.6: re-hash the protected internal region and judge the operator's record.
[group('product')]
[positional-arguments]
framework_cpu_boot_verify *ARGS: framework_media_check
    python3 scripts/check/check-framework-cpu-boot.py verify "$@"


# The RISC-V root boot claim alone, in the same shape as
# `x86_64_sel4_root_boot_check`. `riscv64_qemu_check` replays four more plane
# gates and the portability check after the same boot.
[group('product')]
riscv64_sel4_root_boot_check: sel4_pin_check
    python3 scripts/check/check-sel4-root-boot.py --platform qemu-riscv-virt

[group('product')]
riscv64_qemu_check: sel4_pin_check
    python3 scripts/check/check-sel4-root-boot.py --platform qemu-riscv-virt
    python3 scripts/check/check-sel4-wait-set-plane.py --platform qemu-riscv-virt
    python3 scripts/check/check-sel4-sample-plane.py --platform qemu-riscv-virt
    python3 scripts/check/check-sel4-generation-plane.py --platform qemu-riscv-virt
    python3 scripts/check/check-sel4-rollback-plane.py --platform qemu-riscv-virt
    python3 scripts/check/check-architecture-portability.py


# Each gate must boot its own embedded-generation artifact.
[group('product')]
sel4_stress_check: sel4_pin_check
    python3 scripts/check/check-sel4-stress-plane.py

[group('product')]
sel4_component_graph_check: sel4_pin_check
    python3 scripts/check/check-sel4-component-graph.py

# IO8: the product graph plus the pwm driver, on QEMU where no PWM block
# exists: the driver binds nothing, stays resident, and answers Slisp's
# `(pwm 0 1600)` with no-device while the graph stays healthy.
[group('product')]
sel4_pwm_graph_check: sel4_pin_check
    python3 scripts/check/check-sel4-component-graph.py --composition sel4-pwm

# IO9: the product graph plus a serial driver and a MAVLink heartbeat producer,
# on QEMU where no port exists: the driver binds nothing and stays resident,
# the producer holds its one-second grid and reports each refusal, and the
# graph stays healthy.
[group('product')]
sel4_mavlink_graph_check: sel4_pin_check
    python3 scripts/check/check-sel4-component-graph.py --composition sel4-mavlink

# The product graph plus a driver granted QEMU virt's second serial port and a
# testkit probe: the gate is the host end of that port, reading the bytes the
# probe writes and sending a burst the probe reads back whole, while a second
# driver bound to no port and malformed requests are refused as the serial
# protocol names, and the console still answers the shell.
[group('product')]
sel4_serial_graph_check: sel4_pin_check
    python3 scripts/check/check-sel4-component-graph.py --composition sel4-serial

# Use fresh QEMU boots for rollback and wrong-target negative controls.
[group('product')]
sel4_demo_check: sel4_pin_check
    python3 scripts/check/check-sel4-demo-plane.py

[group('product')]
sel4_boot_layout_check: sel4_pin_check
    python3 scripts/check/check-sel4-boot-layout.py

[group('product')]
sel4_boot_layout_bless: sel4_pin_check
    python3 scripts/check/check-sel4-boot-layout.py --bless

# Fail closed: each injected CSpace mutation must make its boot fail.
# This performs six builds and boots, so it is intentionally outside `just test`.
[group('product')]
sel4_capability_layout_check: sel4_pin_check
    python3 scripts/check/check-sel4-capability-layout.py

[group('product')]
sel4_boot_check: sel4_pin_check
    python3 scripts/check/check-sel4-boot-plane.py

# Keep the product component-graph image distinct from fixture variants.
[group('product')]
sel4_product_image: sel4_pin_check
    python3 scripts/build/build-sel4.py --component-graph --skip-pin-check

[group('product')]
run: sel4_product_image
    qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 -smp 1 \
        -m size=2048M -nographic -serial mon:stdio -kernel build/slime-sel4-graph.elf

[group('product')]
run_release: run

[group('product')]
generation_check: contracts_check sel4_component_graph_check
    python3 scripts/check/check-generation-determinism.py
