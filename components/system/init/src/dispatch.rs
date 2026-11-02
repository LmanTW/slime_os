use super::*;

/// The authenticated boot action, as the root delivers it in this thread's
/// first C parameter. The numbering is `boot_contracts::generation::BootAction`
/// and is fixed by the generation contract, not by this file.
mod boot_action {
    pub const PRODUCT: u32 = 1;
    pub const BOOT: u32 = 2;
    pub const CALL: u32 = 3;
    pub const CHANNEL: u32 = 4;
    pub const CROSSING: u32 = 5;
    pub const DIRECTORY: u32 = 7;
    pub const FILESYSTEM: u32 = 8;
    pub const GENERATION: u32 = 9;
    pub const INPUT: u32 = 10;
    pub const LOAN: u32 = 11;
    pub const OPERATION: u32 = 12;
    pub const POWERBOX: u32 = 13;
    pub const QOS: u32 = 14;
    pub const RECLAMATION: u32 = 15;
    pub const RECOVERY: u32 = 16;
    pub const ROLLBACK: u32 = 17;
    pub const SAMPLE: u32 = 18;
    pub const SPAWN: u32 = 19;
    pub const STORAGE: u32 = 20;
    pub const STORE: u32 = 21;
    pub const STREAM: u32 = 22;
    pub const SUPERVISION: u32 = 23;
    pub const TRANSFER: u32 = 24;
    pub const VISIBILITY: u32 = 25;
    /// The 48-instance ceiling graph (B49).
    pub const STRESS: u32 = 26;
    /// C8.12's matching, visibility, and denial matrix.
    pub const MATRIX: u32 = 27;
    /// C8.13's concurrent cross-plane traffic and resource ceilings.
    pub const TRAFFIC: u32 = 28;
    /// RP2's demo-scoped AArch64 vertical slice.
    pub const DEMO: u32 = 29;
    /// C10.2's generation-declared private-memory budget.
    pub const PRIVATE_MEMORY: u32 = 30;
    /// C9.1's explicit clock and timer service authority plane.
    pub const CLOCK_AUTHORITY: u32 = 31;
    /// C9.2's bounded userspace wait set over one declared Notification.
    pub const WAIT_SET: u32 = 32;

    /// C9.3's declared scheduling class and its promotion authority.
    pub const SCHEDULING_CLASS: u32 = 33;

    /// C9.4's lifecycle transition graph, supervised restart, health
    /// dependencies, and parameter authority.
    pub const LIFECYCLE_RESTART: u32 = 34;

    /// C9.5's typed recording and deterministic replay.
    pub const REPLAY: u32 = 35;

    /// C9.6's robot workload composition.
    pub const ROBOT_RUNTIME: u32 = 36;

    /// MEM-64M's private-memory reuse clause.
    pub const PRIVATE_MEMORY_CYCLES: u32 = 39;
    pub const LIFETIME: u32 = 40;
    /// A hash-pinned data volume read through a read-only block ring.
    pub const DATA_VOLUME: u32 = 41;
    // The table above is a hand copy of the contract's numbering, and the two
    // are an ABI: the root passes one of these words to this thread and this
    // file matches on it. Renumbering a variant in the contract without
    // updating this table would silently compose a different plane, so the
    // agreement is asserted at compile time rather than left to review.
    use boot_contracts::generation::BootAction;
    const _: () = assert!(PRODUCT == BootAction::Product.id());
    const _: () = assert!(BOOT == BootAction::Boot.id());
    const _: () = assert!(CALL == BootAction::Call.id());
    const _: () = assert!(CHANNEL == BootAction::Channel.id());
    const _: () = assert!(CROSSING == BootAction::Crossing.id());
    const _: () = assert!(DIRECTORY == BootAction::Directory.id());
    const _: () = assert!(FILESYSTEM == BootAction::Filesystem.id());
    const _: () = assert!(GENERATION == BootAction::Generation.id());
    const _: () = assert!(INPUT == BootAction::Input.id());
    const _: () = assert!(LOAN == BootAction::Loan.id());
    const _: () = assert!(OPERATION == BootAction::Operation.id());
    const _: () = assert!(POWERBOX == BootAction::Powerbox.id());
    const _: () = assert!(QOS == BootAction::Qos.id());
    const _: () = assert!(RECLAMATION == BootAction::Reclamation.id());
    const _: () = assert!(RECOVERY == BootAction::Recovery.id());
    const _: () = assert!(ROLLBACK == BootAction::Rollback.id());
    const _: () = assert!(SAMPLE == BootAction::Sample.id());
    const _: () = assert!(SPAWN == BootAction::Spawn.id());
    const _: () = assert!(STORAGE == BootAction::Storage.id());
    const _: () = assert!(STORE == BootAction::Store.id());
    const _: () = assert!(STREAM == BootAction::Stream.id());
    const _: () = assert!(SUPERVISION == BootAction::Supervision.id());
    const _: () = assert!(TRANSFER == BootAction::Transfer.id());
    const _: () = assert!(VISIBILITY == BootAction::Visibility.id());
    const _: () = assert!(STRESS == BootAction::Stress.id());
    const _: () = assert!(MATRIX == BootAction::Matrix.id());
    const _: () = assert!(TRAFFIC == BootAction::Traffic.id());
    const _: () = assert!(DEMO == BootAction::Demo.id());
    const _: () = assert!(PRIVATE_MEMORY == BootAction::PrivateMemory.id());
    const _: () = assert!(CLOCK_AUTHORITY == BootAction::ClockAuthority.id());
    const _: () = assert!(WAIT_SET == BootAction::WaitSet.id());
    const _: () = assert!(SCHEDULING_CLASS == BootAction::SchedulingClass.id());
    const _: () = assert!(LIFECYCLE_RESTART == BootAction::LifecycleRestart.id());
    const _: () = assert!(REPLAY == BootAction::Replay.id());
    const _: () = assert!(ROBOT_RUNTIME == BootAction::RobotRuntime.id());
    const _: () = assert!(PRIVATE_MEMORY_CYCLES == BootAction::PrivateMemoryCycles.id());
    const _: () = assert!(LIFETIME == BootAction::Lifetime.id());
    const _: () = assert!(DATA_VOLUME == BootAction::DataVolume.id());
}

/// Compose the graph the generation selected.
///
/// The selector is authenticated generation data delivered at activation, so
/// two builds of this image cannot disagree about which graph they boot: the
/// image is byte-identical across every manifest and only the admitted
/// `bootAction` differs.
///
/// Returns for `PRODUCT`, whose graph the caller launches, and for `DEMO`, which
/// runs RP2's data path and then lets that same product graph launch over the
/// one generation carrying both. Every other action runs its plane to
/// completion and exits.
pub(super) fn compose_declared_graph(startup_arg: u32) {
    use boot_action as action;
    match startup_arg {
        action::BOOT => drive_boot_plane(),
        action::CHANNEL => {
            drive_channel_plane();
            slime_rt::debug_write(b"[init] channel plane complete\n");
            slime_rt::exit(0)
        }
        action::LOAN => {
            drive_loan_plane();
            slime_rt::debug_write(b"[init] loan plane complete\n");
            slime_rt::exit(0)
        }
        action::SPAWN => {
            drive_spawn_plane();
            slime_rt::debug_write(b"[init] spawn plane complete\n");
            slime_rt::exit(0)
        }
        action::SAMPLE => {
            drive_sample_plane();
            slime_rt::debug_write(b"[init] sample plane complete\n");
            slime_rt::exit(0)
        }
        // RP2: the one action that does *both* halves in a single generation.
        // The bounded data path runs first and must complete, then this returns
        // so `main` launches the ordinary component graph over the same
        // admitted generation — which is the milestone's whole point. Every
        // other plane asserts one half and exits; asserting them across two
        // fixtures is exactly what RP2 says is not evidence for the demo.
        action::DEMO => {
            drive_demo_plane();
            slime_rt::debug_write(b"[init] demo data path complete\n");
        }
        action::STREAM | action::QOS => {
            drive_stream_plane(startup_arg == boot_action::QOS);
            slime_rt::debug_write(b"[init] fabric stream complete\n");
            slime_rt::exit(0)
        }
        action::SUPERVISION => {
            drive_supervision_plane();
            slime_rt::debug_write(b"[init] supervision plane complete\n");
            slime_rt::exit(0)
        }
        action::RECLAMATION => {
            drive_reclamation_plane();
            slime_rt::debug_write(b"[init] reclamation plane complete\n");
            slime_rt::exit(0)
        }
        action::PRIVATE_MEMORY => {
            drive_private_memory_plane();
            slime_rt::debug_write(b"[init] private memory plane complete\n");
            slime_rt::exit(0)
        }
        action::PRIVATE_MEMORY_CYCLES => {
            drive_private_memory_cycles_plane();
            slime_rt::debug_write(b"[init] private memory cycles plane complete\n");
            slime_rt::exit(0)
        }
        action::CLOCK_AUTHORITY => {
            slime_rt::debug_write(b"[init] clock authority plane is root-launched\n");
            slime_rt::exit(0)
        }
        // Every lifetime probe is root-autostart, and the owner spawns the one
        // it supervises itself, so init has nothing to launch.
        action::LIFETIME => {
            slime_rt::debug_write(b"[init] lifetime plane is root-launched\n");
            slime_rt::exit(0)
        }
        // C9.2's waiter, signaller, and denied instances are all root-autostart,
        // and the waiter spawns the peer it supervises itself — a supervision
        // source must name a handle its own holder obtained, so init handing one
        // over would prove the wrong thing.
        action::WAIT_SET => {
            slime_rt::debug_write(b"[init] wait set plane is root-launched\n");
            slime_rt::exit(0)
        }
        // C9.3's four probe instances are all root-autostart, and the controller
        // spawns the subject it promotes itself — promotion authority must ride
        // on a handle its own holder obtained, so init handing one over would
        // prove the wrong thing. The same rule as the wait-set plane above.
        action::SCHEDULING_CLASS => {
            slime_rt::debug_write(b"[init] scheduling class plane is root-launched\n");
            slime_rt::exit(0)
        }
        // C9.4's probe instances are root-autostart, and the supervisor spawns
        // and restarts the worker itself — restart authority must ride on a
        // handle its own holder obtained, so init handing one over would prove
        // the wrong thing. The same rule as the two planes above.
        action::LIFECYCLE_RESTART => {
            slime_rt::debug_write(b"[init] lifecycle restart plane is root-launched\n");
            slime_rt::exit(0)
        }
        // C9.5's five probe instances are all root-autostart, and the recorder
        // and replayer hold their declared endpoint and buffer factory directly.
        // The same rule as the three planes above: authority a plane asserts
        // about must ride on the handle its own holder was granted, so init
        // handing one over would prove the wrong thing.
        action::REPLAY => {
            slime_rt::debug_write(b"[init] replay plane is root-launched\n");
            slime_rt::exit(0)
        }
        // `fabric-service` and `fabric-call-worker` must hold supervision
        // handles over their own dependents (`drive_robot_runtime_plane`'s
        // header explains why root-autostart cannot supply one), so init
        // spawns them and their subjects itself; `robot-supervisor` and
        // `robot-burner` need no capability from init and are root-autostart.
        action::ROBOT_RUNTIME => {
            drive_robot_runtime_plane();
            slime_rt::debug_write(b"[init] robot runtime plane complete\n");
            slime_rt::exit(0)
        }
        action::CROSSING => {
            drive_crossing_plane();
            slime_rt::debug_write(b"[init] crossing plane complete\n");
            slime_rt::exit(0)
        }
        action::CALL => {
            drive_call_plane();
            slime_rt::debug_write(b"[init] call plane complete\n");
            slime_rt::exit(0)
        }
        action::OPERATION => {
            drive_operation_plane();
            slime_rt::debug_write(b"[init] operation plane complete\n");
            slime_rt::exit(0)
        }
        action::VISIBILITY => {
            drive_visibility_plane();
            slime_rt::debug_write(b"[init] visibility plane complete\n");
            slime_rt::exit(0)
        }
        action::MATRIX => {
            drive_matrix_plane();
            slime_rt::debug_write(b"[init] matrix plane complete\n");
            slime_rt::exit(0)
        }
        action::TRAFFIC => drive_traffic_plane(),
        action::STORAGE => {
            drive_storage_plane();
            slime_rt::debug_write(b"[init] storage plane complete\n");
            slime_rt::exit(0)
        }
        action::STORE => {
            drive_store_plane();
            slime_rt::debug_write(b"[init] store plane complete\n");
            slime_rt::exit(0)
        }
        action::DATA_VOLUME => {
            drive_data_volume_plane();
            slime_rt::debug_write(b"[init] data volume plane complete\n");
            slime_rt::exit(0)
        }
        action::POWERBOX => {
            drive_powerbox_plane();
            slime_rt::debug_write(b"[init] powerbox plane complete\n");
            slime_rt::exit(0)
        }
        action::FILESYSTEM => {
            drive_filesystem_plane();
            slime_rt::debug_write(b"[init] filesystem plane complete\n");
            slime_rt::exit(0)
        }
        action::GENERATION => {
            drive_generation_plane();
            slime_rt::debug_write(b"[init] generation plane complete\n");
            slime_rt::exit(0)
        }
        action::TRANSFER => {
            drive_probe_plane_with_token(
                resolve_executable(b"executable:sel4-transfer-probe"),
                b"[init] transfer probe spawned\n",
                b"transfer",
                Some(2),
                &crossing_factory(b"transfer-init-buffer-factory"),
            );
            slime_rt::debug_write(b"[init] transfer plane complete\n");
            slime_rt::exit(0)
        }
        action::INPUT => {
            drive_probe_plane_with_token(
                resolve_executable(b"executable:sel4-input-probe"),
                b"[init] input probe spawned\n",
                b"input",
                // Init's own end of `sel4-input-probe-run-token`. The idle
                // instance holds no such edge, which is what tells the two
                // instances of this executable apart.
                Some(2),
                &[],
            );
            slime_rt::debug_write(b"[init] input plane complete\n");
            slime_rt::exit(0)
        }
        action::DIRECTORY => {
            drive_probe_plane_with_token(
                resolve_executable(b"executable:sel4-directory-probe"),
                b"[init] directory probe spawned\n",
                b"directory",
                // Init's own end of `sel4-directory-probe-run-token`; the idle
                // instance holds a loopback nobody sends on.
                Some(2),
                &[],
            );
            slime_rt::debug_write(b"[init] directory plane complete\n");
            slime_rt::exit(0)
        }
        action::RECOVERY => {
            drive_probe_plane_with_token(
                resolve_executable(b"executable:sel4-recovery-probe"),
                b"[init] recovery probe spawned\n",
                b"recovery",
                Some(2),
                &crossing_factory(b"recovery-init-buffer-factory"),
            );
            slime_rt::debug_write(b"[init] recovery plane complete\n");
            slime_rt::exit(0)
        }
        action::ROLLBACK => {
            drive_probe_plane_with_token(
                resolve_executable(b"executable:sel4-rollback-probe"),
                b"[init] rollback probe spawned\n",
                b"rollback",
                Some(2),
                &crossing_factory(b"rollback-init-buffer-factory"),
            );
            slime_rt::debug_write(b"[init] rollback plane complete\n");
            slime_rt::exit(0)
        }
        // The stress plane declares the largest graph the root's CSpace
        // admits and nothing else: what it proves is that every instance is
        // constructed and stays bounded, which the root reports itself. init
        // has no scenario to drive (B49).
        action::STRESS => {
            slime_rt::debug_write(b"[init] stress plane complete\n");
            slime_rt::exit(0)
        }
        action::PRODUCT => {}
        // An action this image does not implement is a generation the graph
        // cannot compose, which is a boot failure rather than a silent
        // fallthrough to some other graph.
        _ => {
            slime_rt::debug_write(b"[init] unknown boot action\n");
            slime_rt::exit(1)
        }
    }
}
