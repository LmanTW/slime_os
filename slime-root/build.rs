//! Selects whether `slime-root` boots a compile-time fixture or the immutable
//! disk-backed selector path used by the product image.

fn main() {
    println!("cargo:rerun-if-env-changed=SLIME_GENERATION");
    println!("cargo::rustc-check-cfg=cfg(slime_generation_supplied)");
    println!("cargo:rerun-if-env-changed=SLIME_BOOT_SELECTOR");
    println!("cargo:rerun-if-env-changed=SLIME_ROOT_FIXTURE");
    println!("cargo:rerun-if-env-changed=SLIME_BOOT_BUNDLE_IDENTITY");
    println!("cargo:rerun-if-env-changed=SLIME_TARGET_PROFILE");
    println!("cargo:rerun-if-env-changed=SLIME_QEMU_KEYBOARD");
    println!("cargo:rerun-if-env-changed=SLIME_PC99_COM1_PORT");
    println!("cargo:rerun-if-env-changed=SLIME_PRODUCT_UART_PADDR");
    println!("cargo:rerun-if-env-changed=SLIME_PRODUCT_TEST_TERMINATOR");
    println!("cargo:rerun-if-env-changed=SLIME_DUO_EARLY_FAULT");
    println!("cargo:rerun-if-env-changed=SLIME_DUO_TIMEBASE_HZ");
    println!("cargo:rerun-if-env-changed=SLIME_SYSTEM_TIMER");
    println!("cargo::rustc-check-cfg=cfg(slime_boot_selector)");
    println!("cargo::rustc-check-cfg=cfg(slime_b38_force_unwind)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_fail_second_allocation)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_fail_large_map)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_stress)");
    println!("cargo::rustc-check-cfg=cfg(slime_cspace_expanded)");
    println!("cargo::rustc-check-cfg=cfg(slime_metadata_lifecycle)");
    println!("cargo::rustc-check-cfg=cfg(slime_bootstrap_boundaries)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_elastic)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_fragmentation)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_rollback)");
    println!("cargo::rustc-check-cfg=cfg(slime_private_conservation)");
    println!("cargo::rustc-check-cfg=cfg(slime_b40_mutate_missing)");
    println!("cargo::rustc-check-cfg=cfg(slime_b40_mutate_extra)");
    println!("cargo::rustc-check-cfg=cfg(slime_b40_mutate_aliased)");
    println!("cargo::rustc-check-cfg=cfg(slime_b40_mutate_wrong_slot)");
    println!("cargo::rustc-check-cfg=cfg(slime_b40_mutate_wrong_type)");
    println!("cargo::rustc-check-cfg=cfg(slime_b40_mutate_wrong_rights)");
    println!("cargo::rustc-check-cfg=cfg(slime_root_fixture)");
    println!("cargo::rustc-check-cfg=cfg(slime_qemu_keyboard)");
    println!("cargo::rustc-check-cfg=cfg(slime_root_console_pl011)");
    println!("cargo::rustc-check-cfg=cfg(slime_pc99_com1)");
    println!("cargo::rustc-check-cfg=cfg(slime_product_uart)");
    println!("cargo::rustc-check-cfg=cfg(slime_product_test_terminator)");
    println!("cargo::rustc-check-cfg=cfg(slime_cv1800b_duo)");
    println!("cargo::rustc-check-cfg=cfg(slime_framework13_ai300)");
    println!("cargo::rustc-check-cfg=cfg(slime_duo_early_fault)");
    println!("cargo::rustc-check-cfg=cfg(slime_physical_target)");
    println!("cargo::rustc-check-cfg=cfg(slime_arm_generic_timer)");
    println!("cargo::rustc-check-cfg=cfg(slime_bcm2835_system_timer)");
    println!("cargo::rustc-check-cfg=cfg(slime_timer_registers)");
    let target_profile = std::env::var("SLIME_TARGET_PROFILE")
        .unwrap_or_else(|_| "aarch64-sel4-qemu-virt".to_owned());
    println!("cargo:rustc-env=SLIME_TARGET_PROFILE={target_profile}");
    // QEMU `virt` is the one target whose root owns its console UART: the
    // root maps the machine's PL011 and writes its transcript through it.
    if target_profile == "aarch64-sel4-qemu-virt" {
        println!("cargo::rustc-cfg=slime_root_console_pl011");
    }
    // A named physical board, as opposed to a QEMU machine: the root announces
    // its target profile at READY and resets the board through its own
    // registers after an autonomous proof, neither of which a QEMU gate wants.
    let physical_target = target_profile == "riscv64-sel4-milkv-duo";
    if physical_target {
        println!("cargo::rustc-cfg=slime_physical_target");
    }
    if target_profile == "riscv64-sel4-milkv-duo" {
        println!("cargo::rustc-cfg=slime_cv1800b_duo");
        let timebase = std::env::var("SLIME_DUO_TIMEBASE_HZ")
            .expect("Milk-V Duo build requires SLIME_DUO_TIMEBASE_HZ");
        let frequency: u64 = timebase
            .parse()
            .expect("SLIME_DUO_TIMEBASE_HZ must be a positive integer");
        assert!(frequency > 0, "SLIME_DUO_TIMEBASE_HZ must be positive");
        println!("cargo:rustc-env=SLIME_DUO_TIMEBASE_HZ={frequency}");
    }
    // The root's monotonic source. An AArch64 root reads and programs the
    // generic timer from EL0, which the kernel must export. The Raspberry Pi 5
    // root can use the SoC's system timer instead, a device page that needs no
    // export. Every other architecture has a device page already.
    let architecture = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if std::env::var("SLIME_SYSTEM_TIMER").as_deref() == Ok("1") {
        if target_profile != "aarch64-rpi5" {
            panic!("SLIME_SYSTEM_TIMER is valid only for the aarch64-rpi5 profile");
        }
        println!("cargo::rustc-cfg=slime_bcm2835_system_timer");
        println!("cargo::rustc-cfg=slime_timer_registers");
    } else if architecture == "aarch64" {
        println!("cargo::rustc-cfg=slime_arm_generic_timer");
    } else {
        println!("cargo::rustc-cfg=slime_timer_registers");
    }
    if target_profile == "x86_64-sel4-framework13-ai300" {
        println!("cargo::rustc-cfg=slime_framework13_ai300");
    }
    if let Ok(uart_paddr) = std::env::var("SLIME_PRODUCT_UART_PADDR") {
        if !physical_target {
            panic!("SLIME_PRODUCT_UART_PADDR is valid only for physical board profiles");
        }
        let address = uart_paddr
            .strip_prefix("0x")
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .expect("SLIME_PRODUCT_UART_PADDR must be nonzero hexadecimal");
        assert!(address != 0, "SLIME_PRODUCT_UART_PADDR must be nonzero");
        println!("cargo::rustc-cfg=slime_product_uart");
        println!("cargo:rustc-env=SLIME_PRODUCT_UART_PADDR={uart_paddr}");
    }
    if std::env::var("SLIME_PRODUCT_TEST_TERMINATOR").as_deref() == Ok("1") {
        if std::env::var("SLIME_PRODUCT_UART_PADDR").is_err() {
            panic!("SLIME_PRODUCT_TEST_TERMINATOR requires SLIME_PRODUCT_UART_PADDR");
        }
        println!("cargo::rustc-cfg=slime_product_test_terminator");
    }
    if std::env::var("SLIME_DUO_EARLY_FAULT").as_deref() == Ok("1") {
        if target_profile != "riscv64-sel4-milkv-duo" {
            panic!("SLIME_DUO_EARLY_FAULT is valid only for the Milk-V Duo profile");
        }
        println!("cargo::rustc-cfg=slime_duo_early_fault");
    }
    if std::env::var("SLIME_BOOT_SELECTOR").as_deref() == Ok("1") {
        let identity = std::env::var("SLIME_BOOT_BUNDLE_IDENTITY")
            .expect("selector build requires SLIME_BOOT_BUNDLE_IDENTITY");
        if identity.len() != 64 || !identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            panic!("SLIME_BOOT_BUNDLE_IDENTITY must be 32-byte lowercase hex");
        }
        println!("cargo:rustc-cfg=slime_boot_selector");
        println!("cargo:rustc-env=SLIME_BOOT_BUNDLE_IDENTITY={identity}");
    }
    if std::env::var("SLIME_ROOT_FIXTURE").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=slime_root_fixture");
    }
    if std::env::var("SLIME_QEMU_KEYBOARD").as_deref() == Ok("1") {
        println!("cargo:rustc-cfg=slime_qemu_keyboard");
    }
    if let Ok(port) = std::env::var("SLIME_PC99_COM1_PORT") {
        if target_profile != "x86_64-sel4-qemu-pc99" {
            panic!("SLIME_PC99_COM1_PORT is valid only for the pc99 profile");
        }
        let value = port
            .strip_prefix("0x")
            .and_then(|value| u16::from_str_radix(value, 16).ok())
            .expect("SLIME_PC99_COM1_PORT must be nonzero hexadecimal");
        assert!(value != 0, "SLIME_PC99_COM1_PORT must be nonzero");
        println!("cargo::rustc-cfg=slime_pc99_com1");
        println!("cargo:rustc-env=SLIME_PC99_COM1_PORT={port}");
    }
    if std::env::var("SLIME_BOOT_SELECTOR").as_deref() != Ok("1")
        && let Ok(path) = std::env::var("SLIME_GENERATION")
    {
        println!("cargo:rerun-if-changed={path}");
        println!("cargo:rustc-cfg=slime_generation_supplied");
    }
}
