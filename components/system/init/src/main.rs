#![no_std]
#![no_main]

slime_rt::entry!(main);

#[path = "../../../lib/src/loan_plane.rs"]
mod loan_plane;
use loan_plane::{PEER_PARK_YIELDS, drive_loan_plane};
#[path = "../../../lib/src/spawn_plane.rs"]
mod spawn_plane;
use spawn_plane::drive_spawn_plane;
#[path = "../../../lib/src/crossing_plane.rs"]
mod crossing_plane;
use crossing_plane::drive_crossing_plane;
#[path = "../../../lib/src/supervision_plane.rs"]
mod supervision_plane;
use supervision_plane::drive_supervision_plane;
mod fabric_planes;
use fabric_planes::{
    drive_boot_plane, drive_call_plane, drive_matrix_plane, drive_operation_plane,
    drive_robot_runtime_plane, drive_stream_plane, drive_traffic_plane, drive_visibility_plane,
    launch_fabric_graph, push_i64,
};

mod dispatch;
use dispatch::compose_declared_graph;

use slime_rt::console_line::Line;
use slime_rt::{Rights, SpawnGrant};
// B59: the capability-rights vocabulary is generated from
// `contracts/generation/v5/schema.zt`; these were local copies of the same
// bit numbering.
use boot_contracts::generation::{
    RIGHT_BUFFER_CREATE, RIGHT_DIRECTORY_READ, RIGHT_DIRECTORY_WRITE, RIGHT_EXEC, RIGHT_SEND,
    RIGHT_SPAWN, RIGHT_SUPERVISE, RIGHT_TRANSFER,
};

/// Whether the child this instance owns declares a minted binding called
/// `name` -- the handle init must create and supply at spawn.
///
/// The generated `FABRIC_MINTED_GRANTS` table stated this as a *count* per
/// holder, and init compared that count against a vector length. A count is a
/// lossy summary of the composition: two planes reach the same total through
/// different sets, so it answers "how many" when what init needs is "which".
/// Asking the root by name answers the real question and has no order to be
/// sensitive to, which is what let the generated table go.
///
/// The child is not named because the handle already identifies it: this owner
/// declares each minted name at most once, and two children declaring the same
/// one is an ambiguity `owned-minted:` refuses rather than resolving to
/// whichever the builder emitted first.
fn declares_minted(name: &[u8]) -> bool {
    let mut query = [0u8; 64];
    let prefix = b"owned-minted:";
    let end = prefix.len() + name.len();
    if end > query.len() {
        return false;
    }
    query[..prefix.len()].copy_from_slice(prefix);
    query[prefix.len()..end].copy_from_slice(name);
    slime_rt::resolve_binding(&query[..end]).is_ok()
}

// Manifest-derived bootstrap slot order is emitted by the host builder.
const CONSOLE_CAPS: [SpawnGrant; 0] = [];

fn spawn_service_caps() -> ([SpawnGrant; 4], usize) {
    // Ascending child binding slot is the root's grant-installation order.
    // The optional command follows the fixed executable and factory prefix.
    let mut grants = [
        grant(
            resolve_executable(b"executable:sysinfo"),
            RIGHT_EXEC | RIGHT_SPAWN,
        ),
        grant(
            resolve_executable(b"executable:echo-agent"),
            RIGHT_EXEC | RIGHT_SPAWN,
        ),
        grant(
            slime_rt::resolve_binding(b"spawn-service-shared-buffer-factory")
                .unwrap_or_else(|_| slime_rt::exit(1)),
            RIGHT_BUFFER_CREATE,
        ),
        grant(0, 0),
    ];
    let mut count = 3;
    if let Ok(slot) = slime_rt::resolve_binding(b"executable:http-get") {
        grants[count] = grant(slot, RIGHT_EXEC | RIGHT_SPAWN);
        count += 1;
    }
    (grants, count)
}

// The generated boot-layout slot table was `include!`d here (B10) and is gone
// (CP2/B70). Init asked the root for every slot it needs instead: by grant name,
// by `executable:` layout role, or by `kind:` capability role. Nothing in this
// binary now knows any generation's numbering, which is what lets it be built
// outside this crate -- and what B71 had to make true of the resource those
// queries read before any of it was safe.

const fn grant(slot: u32, rights: Rights) -> SpawnGrant {
    SpawnGrant { slot, rights }
}

// The x86 storage-probe selection cascade and the generation-command caps tables
// were deleted here (B70). Every executable they named -- `storage-writer`,
// `storage-fault-probe`, `storage-store-probe`, `storage-probe`,
// `filesystem-service`, and the five `generation-*` commands -- is declared by
// none of the 28 seL4 manifests, so each constant resolved `SLOT_ABSENT` and
// every branch testing it was unreachable on this kernel. The seL4 planes reach
// the same behavior through their own `bootAction`: `drive_storage_plane`,
// `drive_store_plane`, `drive_filesystem_plane`, and `drive_generation_plane`
// name `sel4-storage-probe`, `sel4-store-probe`, `sel4-filesystem-service`, and
// `sel4-generation-client`/`-manager`, which the fixtures do declare.

fn main(startup_arg: u32) {
    if option_env!("SLIME_BOOT_SELECTION_FAIL") == Some("1") {
        slime_rt::debug_write(b"[init] reporting unhealthy boot\n");
        slime_rt::unhealthy();
    }
    // The authenticated manifest action selects every non-product composition.
    // `PRODUCT` and `DEMO` return so the ordinary component graph below can
    // launch; every other action has already exited.
    compose_declared_graph(startup_arg);
    slime_rt::debug_write(b"[init] launching component graph\n");

    let console_executable =
        slime_rt::resolve_binding(b"executable:console").unwrap_or_else(|_| slime_rt::exit(1));
    let component_console = slime_rt::spawn(console_executable, &CONSOLE_CAPS)
        .unwrap_or_else(|_| slime_rt::exit(1))
        .supervision_slot;
    let spawn_service_executable = slime_rt::resolve_binding(b"executable:spawn-service")
        .unwrap_or_else(|_| slime_rt::exit(1));
    let (spawn_caps, spawn_cap_count) = spawn_service_caps();
    let component_spawn_service =
        slime_rt::spawn(spawn_service_executable, &spawn_caps[..spawn_cap_count])
            .unwrap_or_else(|_| slime_rt::exit(1))
            .supervision_slot;

    if startup_arg == boot_contracts::generation::BootAction::Product.id() {
        // A product generation may declare resident drivers and producers
        // beside the shell (`sel4-pwm`, `sel4-mavlink`); each is launched,
        // servers before their clients, before Slisp. The plain product graph
        // declares none of them and launches none.
        let component_pwm = spawn_declared(b"executable:pwm-servo-driver");
        let component_uart = spawn_declared(b"executable:uart16550-driver");
        let component_heartbeat = spawn_declared(b"executable:mavlink-heartbeat");
        let slisp_executable =
            slime_rt::resolve_binding(b"executable:slisp").unwrap_or_else(|_| slime_rt::exit(1));
        let component_slisp = slime_rt::spawn(slisp_executable, &[])
            .unwrap_or_else(|_| slime_rt::exit(1))
            .supervision_slot;
        slime_rt::debug_write(b"[init] product services resident\n");
        supervise_resident(&[
            Some(component_console),
            Some(component_spawn_service),
            component_pwm,
            component_uart,
            component_heartbeat,
            Some(component_slisp),
        ]);
    }

    let shutdown = slime_proto::spawn::WireSpawnRequest {
        magic: slime_proto::spawn::SPAWN_MAGIC,
        version: slime_proto::spawn::FORMAT_VERSION,
        flags: slime_proto::spawn::REQUEST_FLAG_SHUTDOWN,
        command_len: 0,
        argument_count: 0,
        environment_count: 0,
        capability_roles: 0,
        client_budget: 0,
        command: [0; 16],
        argument_len0: 0,
        argument_len1: 0,
        argument_len2: 0,
        argument_len3: 0,
        argument_bytes: 0,
        supervision_handle: 0,
        environment: [0; 8],
        grant_rights: 0,
        reserved: [0; 4],
    };
    if slime_rt::send(resolve_spawn_service_rpc(), &shutdown.encode(), &[]) != slime_rt::ERR_SUCCESS
    {
        slime_rt::exit(1);
    }
    wait_clean(&[component_spawn_service]);
    if slime_rt::send(console_send_slot(), b"SLIME.CONSOLE.CLOSE", &[]) != slime_rt::ERR_SUCCESS {
        slime_rt::exit(1);
    }
    wait_clean(&[component_console]);
    slime_rt::debug_write(b"[init] component services completed\n");
    slime_rt::debug_write(b"[init] spawn graph launched\n");
    slime_rt::exit(0);
}

/// Launch the executable the generation declares under `name`, or nothing when
/// it declares none; a declared executable that fails to spawn is fatal.
fn spawn_declared(name: &[u8]) -> Option<u32> {
    slime_rt::resolve_binding(name).ok().map(|executable| {
        slime_rt::spawn(executable, &[])
            .unwrap_or_else(|_| slime_rt::exit(1))
            .supervision_slot
    })
}

fn supervise_resident(handles: &[Option<u32>]) -> ! {
    loop {
        for handle in handles.iter().flatten() {
            if slime_rt::supervision_status(*handle)
                .unwrap_or_else(|_| slime_rt::exit(1))
                .is_some()
            {
                slime_rt::debug_write(b"[init] resident service terminated\n");
                slime_rt::exit(1);
            }
        }
        slime_rt::yield_now();
    }
}

/// One boot-layout executable slot, resolved through the root by name.
///
/// CP2/B70: the slot number is a fact about the active generation, so this image
/// asks for it rather than compiling it in. A generation whose layout declares no
/// such executable is a real answer — the caller asked to launch a component this
/// composition does not have — so it exits rather than falling back to a guess.
fn resolve_executable(name: &[u8]) -> u32 {
    slime_rt::resolve_binding(name).unwrap_or_else(|_| slime_rt::exit(1))
}

/// Init's request endpoint to `spawn-service`, resolved by grant name.
///
/// A plain grant lookup: `spawn-service-rpc` is an ordinary endpoint binding in
/// init's own list, so no prefix is needed and the root answers only from that
/// list. This replaces `SPAWN_SERVICE_RPC_SLOT`, the last compiled slot in the
/// product graph's shutdown path (CP2/B70).
fn resolve_spawn_service_rpc() -> u32 {
    slime_rt::resolve_binding(b"spawn-service-rpc").unwrap_or_else(|_| slime_rt::exit(1))
}

/// Init's shared-buffer factory slot, resolved through the root by capability
/// role rather than compiled in.
///
/// `kind:sharedBufferFactory+bufferCreate` asks by what the capability *is*, and
/// the root refuses an ambiguous answer, so this is only usable where the
/// generation binds init exactly one factory. The compositions that bind more
/// use [`resolve_own_buffer_factory`] or a grant name instead: the full-graph
/// `boot` and `traffic` generations bind two, and RP2's `sel4-demo` binds three.
///
/// Deliberately not "the factory granted to me": that spelling looked like the
/// general rule and is not. Under the product graph init holds one factory whose
/// grant target is `spawn-service`, not itself, so a target test resolves nothing
/// exactly where this is needed most.
fn resolve_buffer_factory() -> u32 {
    slime_rt::resolve_binding(b"kind:sharedBufferFactory+bufferCreate")
        .unwrap_or_else(|_| slime_rt::exit(1))
}

/// Init's *own* shared-buffer factory, by grant name, for every composition
/// where the role query above is ambiguous or answers the wrong question.
///
/// The full-graph `boot` and `traffic` generations bind both
/// `init-shared-buffer-factory` and `fabric-service-shared-buffer-factory` to
/// init, and `sel4-demo` binds a third, so `resolve_buffer_factory`'s role query
/// refuses there. A grant name is unambiguous, and this one is declared by every
/// generation reaching the callers below: `sel4-stream`, `sel4-qos`,
/// `sel4-visibility`, `sel4-boot`, `sel4-demo`, and the one manifest `traffic`,
/// `fault`, and `saturation` share, differing only in generation number.
///
/// Which factory is delegated does not change what the receiver may do — a
/// shared-buffer quota binds to the receiving task, not to the factory capability
/// handed over, verified by delegating the other one and observing the boot plane
/// stay green. So this names init's own for the same reason the source reads
/// better for it, not because the authority differs.
fn resolve_own_buffer_factory() -> u32 {
    slime_rt::resolve_binding(b"init-shared-buffer-factory").unwrap_or_else(|_| slime_rt::exit(1))
}

/// Spawn one boot participant that its manifest grants nothing, returning the
/// supervision handle init keeps.
fn spawn_boot(executable: &[u8]) -> u32 {
    spawn_boot_with(executable, &[])
}

/// Spawn one boot participant with the exact grant vector its manifest declares.
///
/// The count must equal what `preflight_spawn_grants` derives from the
/// generation — the child's minted bindings plus its spawn-crossing grant
/// bindings — or the root refuses the spawn with nothing constructed. Both
/// numbers come from the same manifest, so a disagreement is a fixture defect
/// rather than something to reconcile here.
///
/// `executable` is the component's name, not a slot: the root resolves it from
/// the boot layout it placed these capabilities from (CP2/B70), so this image
/// carries no plane's slot numbering. `executable:` names the layout's component
/// identity domain, which is what keeps a channel of the same name from
/// answering.
fn spawn_boot_with(executable: &[u8], grants: &[SpawnGrant]) -> u32 {
    let executable_slot = match slime_rt::resolve_binding(executable) {
        Ok(slot) => slot,
        Err(error) => {
            push_i64(
                Line::<128>::new().bytes(b"[init] fabric boot unresolved executable error="),
                error,
            )
            .bytes(b"\n")
            .emit();
            fail_boot(b"resolve participant executable")
        }
    };
    match slime_rt::spawn(executable_slot, grants) {
        Ok(spawned) => spawned.supervision_slot,
        Err(error) => {
            push_i64(
                Line::<128>::new()
                    .bytes(b"[init] fabric boot spawn failed slot=")
                    .decimal(u64::from(executable_slot))
                    .bytes(b" grants=")
                    .decimal(u64::from(grants.len() as u32))
                    .bytes(b" error="),
                error,
            )
            .bytes(b"\n")
            .emit();
            fail_boot(b"spawn participant")
        }
    }
}

fn fail_boot(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] fabric boot fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// Require one spawned task to still be healthy-idle, never having exited.
///
/// The complement of [`wait_clean`], for a structural role a plane declares but
/// drives no traffic through: its correct outcome is blocked idle, so an exit of
/// any status is the failure.
fn expect_parked(handle: u32) {
    match slime_rt::supervision_status(handle) {
        Ok(None) => {}
        _ => fail_boot(b"parked participant left healthy idle"),
    }
}
fn wait_clean(handles: &[u32]) {
    for handle in handles {
        loop {
            match slime_rt::supervision_status(*handle) {
                Ok(None) => slime_rt::yield_now(),
                Ok(Some(slime_rt::Termination::Exit(0))) => break,
                other => {
                    let kind: u32 = match other {
                        Ok(Some(slime_rt::Termination::Exit(_))) => 1,
                        Ok(Some(slime_rt::Termination::Fault(_))) => 2,
                        Ok(Some(slime_rt::Termination::Timeout)) => 3,
                        Ok(Some(slime_rt::Termination::PeerLoss)) => 4,
                        Ok(Some(slime_rt::Termination::Unhealthy)) => 5,
                        _ => 9,
                    };
                    Line::<64>::new()
                        .bytes(b"[init] unclean handle=")
                        .decimal(u64::from(*handle))
                        .bytes(b" kind=")
                        .decimal(u64::from(kind))
                        .bytes(b"\n")
                        .emit();
                    slime_rt::exit(1)
                }
            }
        }
    }
}

/// Prove native endpoint rendezvous and unrelated progress while the sender is
/// blocked in the kernel rather than filling a root-mediated queue.
fn drive_channel_plane() {
    const LINE: &[u8] = b"[console] channel plane carried this line\n";
    const CLOSE: &[u8] = b"SLIME.CONSOLE.CLOSE";
    // `console` is an *executable* slot the boot layout declares and no grant
    // binds, so resolving it exercises the layout half of the query — the half
    // `CONSOLE_SLOT` was the compiled stand-in for. The `executable:` prefix names
    // which of the layout's two identity domains is meant; without it the root
    // treats the name as a grant and refuses, which is what keeps a layout entry
    // from ever shadowing a grant.
    let console_executable = slime_rt::resolve_binding(b"executable:console")
        .unwrap_or_else(|_| fail(b"no console executable in this generation's layout"));
    let console =
        slime_rt::spawn(console_executable, &[]).unwrap_or_else(|_| fail(b"spawn console"));
    for _ in 0..PEER_PARK_YIELDS {
        slime_rt::yield_now();
    }
    slime_rt::debug_write(b"[init] rendezvous send entering\n");
    if slime_rt::send(console_send_slot(), LINE, &[]) != slime_rt::ERR_SUCCESS {
        fail(b"native rendezvous send");
    }
    slime_rt::debug_write(b"[init] rendezvous send completed\n");
    if slime_rt::send(console_send_slot(), CLOSE, &[]) != slime_rt::ERR_SUCCESS {
        fail(b"console close");
    }
    wait_clean(&[console.supervision_slot]);
    slime_rt::debug_write(b"[init] channel receiver completed\n");
}

/// The channel init uses for console output in the active generation.
///
/// Product generations name the edge `console-output`; the standalone channel
/// and loan planes retain the historical `dango-output` label. CP2 resolves the
/// active generation's binding instead of compiling either slot number into
/// this component.
fn console_send_slot() -> u32 {
    // No generation reaching this function binds both names, so this is a
    // disjoint lookup rather than a precedence rule. The root answers only from
    // init's own binding list, preventing another plane's edge from leaking in.
    for name in [b"console-output".as_slice(), b"dango-output".as_slice()] {
        if let Ok(slot) = slime_rt::resolve_binding(name) {
            return slot;
        }
    }
    fail(b"no console output binding in this generation")
}

fn fail(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] channel plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// Run the sample composition over generation-declared endpoint and factory
/// bindings, with one supervision handle handed over at spawn.
///
/// The split is the same one `launch_fabric_calls` makes: the channel and the
/// lender's buffer factory are edges the generation fixes before either task
/// runs, so they are ordinary grants; the receiver's supervision handle cannot
/// exist until the receiver does, so it is the one capability init still passes.
/// That also fixes the spawn order — the receiver first, because a handle
/// naming it cannot precede it.
fn drive_sample_plane() {
    let receiver = slime_rt::spawn(resolve_executable(b"executable:sample-receiver"), &[])
        .unwrap_or_else(|_| fail_sample(b"spawn receiver"));
    // Matched positionally against ascending declared slot, exactly as
    // `launch_fabric_calls` matches: the lender's factory at 1, then the
    // receiver's supervision handle at 2. The channel is a declared endpoint the
    // root installs on both sides, so it is not in this list.
    let lender = slime_rt::spawn(
        resolve_executable(b"executable:sample-lender"),
        &[
            grant(resolve_buffer_factory(), RIGHT_BUFFER_CREATE),
            grant(receiver.supervision_slot, RIGHT_SUPERVISE),
        ],
    )
    .unwrap_or_else(|_| fail_sample(b"spawn lender"));
    if slime_rt::spawn(resolve_executable(b"executable:sample-receiver"), &[])
        != Err(slime_rt::ERR_BAD_CAP)
    {
        fail_sample(b"a live instance was spawned twice");
    }
    slime_rt::debug_write(b"[init] spawn budget refused\n");
    for handle in [receiver.supervision_slot, lender.supervision_slot] {
        loop {
            match slime_rt::supervision_status(handle) {
                Ok(None) => slime_rt::yield_now(),
                Ok(Some(slime_rt::Termination::Exit(0))) => break,
                _ => fail_sample(b"a sample component did not exit cleanly"),
            }
        }
    }
    let reaped = slime_rt::spawn(resolve_executable(b"executable:sample-receiver"), &[])
        .unwrap_or_else(|_| fail_sample(b"budget did not recover after a child exited"));
    slime_rt::debug_write(b"[init] spawn budget recovered\n");
    if slime_rt::cap_drop(reaped.supervision_slot) != slime_rt::ERR_SUCCESS {
        fail_sample(b"dropping the reaped handle");
    }
}

fn fail_sample(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] sample plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// Drive RP2's demo-scoped vertical slice: the bounded C7 sample exchange *and*
/// the C8 route provisioning/data path RP4/RP6 need, run under the *same*
/// generation that then launches the product component graph.
///
/// Both halves are deliberately the existing compositions rather than new ones.
/// RP2 asks for the C7 exchange and the C8 route path "under one demo-scoped
/// generation rather than across separate plane fixtures" — so what has to be
/// new is the *generation*, not the scenarios. Reusing them means the demo's
/// data path is the composition `just sel4_sample_check` and
/// `just sel4_stream_check` already exercise, rather than a third scenario no
/// gate has observed.
///
/// Not the identical *run*, and the difference is worth naming: those planes
/// script a mid-stream publisher death through `SLIME_FABRIC_STREAM_EARLY_EXIT`,
/// which `build-sel4.py` sets for `stream`, `qos`, and `fault` only. The demo
/// plane runs the same graph to its ordinary `FLAG_LAST` completion, so it
/// inherits the provisioning, denial, and loan evidence and makes no claim about
/// the scripted-death arm.
///
/// The C7 half moves a payload larger than the control-message bound through
/// real `SYS_SHARED_BUFFER_*` frames against generation-declared quotas, which
/// is RP2's "two components exchange and return a payload larger than the
/// control-message bound with the declared quota and reclamation semantics"
/// required check. Reclamation is asserted per handle, the instant it is
/// collected: a collected supervision handle must refuse a second status call.
///
/// Unlike every plane action, this one **returns**: the demo generation is a
/// product generation too, so `main` goes on to launch `console` and
/// `spawn-service` over the same admitted graph. That single-generation
/// property is the milestone, and it is observable precisely because all three
/// parts emit their markers in one transcript.
fn drive_demo_plane() {
    let receiver = slime_rt::spawn(resolve_executable(b"executable:sample-receiver"), &[])
        .unwrap_or_else(|_| fail_demo(b"spawn receiver"));
    // Positional against ascending declared slot, the same match
    // `drive_sample_plane` makes: the lender's factory at 1, then the
    // receiver's supervision handle at 2. The exchange channel is a declared
    // endpoint the root installs on both sides, so it is not passed here.
    let lender = slime_rt::spawn(
        resolve_executable(b"executable:sample-lender"),
        &[
            grant(resolve_own_buffer_factory(), RIGHT_BUFFER_CREATE),
            grant(receiver.supervision_slot, RIGHT_SUPERVISE),
        ],
    )
    .unwrap_or_else(|_| fail_demo(b"spawn lender"));
    slime_rt::debug_write(b"[init] demo data path spawned\n");
    // Collecting a termination *is* the reclamation: `serve_supervision_status`
    // drops the caller's slot as it hands the outcome over, so an explicit
    // `cap_drop` afterwards is a double free. Established by a real boot rather
    // than by reading — the first revision dropped them and died on
    // `init exit status=1` after the whole data path had succeeded.
    //
    // So the assertion is the inverse: a *second* status call on a collected
    // handle must be refused, which is what proves the slot was released rather
    // than merely reported. A leaked handle would answer again.
    //
    // It is made immediately, inside this loop, rather than in a second pass —
    // and that placement is load-bearing, not tidiness. `free_slot_from(1)`
    // returns the *lowest* free slot, so the next spawn reuses a number this
    // loop just released; `launch_fabric_graph` below spawns six. A re-query
    // after any of them would read some other task's live handle and pass for
    // the wrong reason, which is a gate that cannot fail.
    for handle in [receiver.supervision_slot, lender.supervision_slot] {
        loop {
            match slime_rt::supervision_status(handle) {
                Ok(None) => slime_rt::yield_now(),
                Ok(Some(slime_rt::Termination::Exit(0))) => break,
                _ => fail_demo(b"a demo data-path component did not exit cleanly"),
            }
        }
        if slime_rt::supervision_status(handle).is_ok() {
            fail_demo(b"a collected data-path handle answered twice");
        }
    }
    slime_rt::debug_write(b"[init] demo sample exchange complete\n");
    // The C8 half, in the *same* generation. RP2 asks for the C7 sample-plane
    // exchange and "the C8 route provisioning/data path required by RP4/RP6
    // under one demo-scoped generation rather than across separate plane
    // fixtures", so both run here over one admitted manifest: the fabric graph
    // this generation declares is the stream graph, two routes over two
    // publishers and two subscribers.
    //
    // It interposes nothing: `sel4-demo` declares `interpositions = []` and no
    // `fabric-intruder-supervision` minted binding, so `launch_fabric_graph`
    // takes its `without_proxy` arm and `fabric-intruder` runs as the
    // undeclared-edge denial control rather than as a hop. That mirrors
    // `sel4-stream`, which is the composition this reuses; `sel4-visibility` is
    // the plane that declares a real hop.
    //
    // `launch_fabric_graph` is reused rather than reimplemented for the reason
    // the C7 half reuses the sample exchange: the composition is the evidence
    // `just sel4_stream_check` already froze, and what RP2 makes new is the
    // generation carrying both halves plus the product graph, not a third
    // scenario. `fabric-service` reaches its stream composition because `demo`
    // matches none of its named boot actions and falls through to exactly that
    // path, so no fabric component needed a new branch.
    launch_fabric_graph(b"demo fabric", b" service spawned\n");
}

fn fail_demo(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] demo plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// Drive the P5.4.3 powerbox plane (M6.6): a chooser holding directory
/// authority the requester lacks, handing over one narrowed view on selection.
///
/// The probe's single grant is the RPC endpoint. It holds no directory
/// capability at all, which is the milestone's point: the only way it can name
/// an object is for the chooser to mint one and transfer it, and the chooser
/// mints only what the user's selection gesture named.
fn drive_powerbox_plane() {
    let chooser = slime_rt::spawn(resolve_executable(b"executable:powerbox-chooser"), &[])
        .unwrap_or_else(|_| fail_plane(b"powerbox", b"spawn chooser"));
    slime_rt::debug_write(b"[init] powerbox chooser spawned\n");
    let probe = slime_rt::spawn(resolve_executable(b"executable:powerbox-probe"), &[])
        .unwrap_or_else(|_| fail_plane(b"powerbox", b"spawn probe"));
    slime_rt::debug_write(b"[init] powerbox probe spawned\n");
    wait_clean(&[probe.supervision_slot, chooser.supervision_slot]);
}

/// Drive the P5.4.3 filesystem plane (M6.3's other half): a service that
/// resolves names in a snapshot tree, and a client that must ask it.
///
/// The same shape as the generation plane — mint one channel, spawn the service
/// first so it is listening, then the client — and for the same reason: the
/// authority each holds is placed by the generation, and init composes only the
/// channel between them.
fn drive_filesystem_plane() {
    let service = slime_rt::spawn(
        resolve_executable(b"executable:sel4-filesystem-service"),
        // B83: the service reaches its device through IO0 rings served by the
        // userspace driver, and a ring is a shared buffer it allocates, so its
        // factory is authority it cannot hold in its own right -- `init` is the
        // declared source and the grant crosses the spawn.
        &crossing_factory(b"filesystem-init-buffer-factory"),
    )
    .unwrap_or_else(|_| fail_plane(b"filesystem", b"spawn service"));
    slime_rt::debug_write(b"[init] filesystem service spawned\n");
    // The service announces its store is open on a declared edge, and the
    // client is not spawned until it does. Opening the store is hundreds of
    // block round trips; a client that sent its first request into that window
    // got no reply and failed its own arm.
    let mut ready = [0u8; slime_rt::MAX_MSG];
    let mut caps = [0u64; slime_rt::MAX_CAPS_PER_MSG];
    if slime_rt::recv_blocking(3, &mut ready, &mut caps) < 0 {
        fail_plane(b"filesystem", b"await service readiness");
    }
    // `directory-probe`, not `sel4-directory-probe`: this plane and the
    // directory plane declare different executables, and only the fixtures say
    // which. Verified against `sel4-filesystem.layout`.
    let client = slime_rt::spawn(resolve_executable(b"executable:directory-probe"), &[])
        .unwrap_or_else(|_| fail_plane(b"filesystem", b"spawn client"));
    slime_rt::debug_write(b"[init] filesystem client spawned\n");
    // The client's exit is init's to observe, through the handle its spawn
    // returned. The service cannot: a native Endpoint reports no peer death, so
    // init closes it on the same declared edge the readiness announcement came
    // over.
    wait_clean(&[client.supervision_slot]);
    if slime_rt::send(3, b"SLIME.FILESYSTEM.CLOSE", &[]) != slime_rt::ERR_SUCCESS {
        fail_plane(b"filesystem", b"close the service");
    }
    wait_clean(&[service.supervision_slot]);
}

/// Drive the P5.4.3 generation plane (M6.5): a management service holding the
/// only block capability, and a client that must ask it.
///
/// Two components and one channel, so unlike the storage planes init composes
/// rather than merely spawns. What it does *not* do is hand the client any
/// device authority — that is the plane's whole claim, and init could not do it
/// anyway: the block capability is granted to the manager by the generation, so
/// init never holds it.
fn drive_generation_plane() {
    // The client precedes the manager: the manager is granted a supervision
    // handle naming it, and a handle cannot exist before its task. A native
    // Endpoint reports no peer death, so that handle is the only way the
    // manager can learn its client is gone rather than merely quiet.
    let client = slime_rt::spawn(
        resolve_executable(b"executable:sel4-generation-client"),
        &[],
    )
    .unwrap_or_else(|_| fail_plane(b"generation", b"spawn client"));
    slime_rt::debug_write(b"[init] generation client spawned\n");
    // Two crossing grants, matched positionally against the manager's ascending
    // declared slot: its supervision handle for the client, and B83's
    // shared-buffer factory. The factory is authority the manager cannot hold in
    // its own right -- a ring is a shared buffer it allocates and `init` is the
    // declared source -- so it crosses the spawn like the handle does.
    //
    // Order follows declared slot, not argument convenience: whichever of the
    // two the composition binds at the lower slot must come first here.
    let manager = slime_rt::spawn(
        resolve_executable(b"executable:sel4-generation-manager"),
        &[
            grant(client.supervision_slot, RIGHT_SUPERVISE),
            crossing_factory(b"generation-init-buffer-factory")[0],
        ],
    )
    .unwrap_or_else(|_| fail_plane(b"generation", b"spawn manager"));
    slime_rt::debug_write(b"[init] generation manager spawned\n");
    // The run token, on init's own end of each declared edge. Both instances of
    // each executable hold a real endpoint at that slot -- the idle ones a
    // loopback nobody sends on -- so arrival is what tells them apart. The root
    // delivers a nonzero boot action only to the bootstrap instance, so
    // `startup_arg` cannot.
    if slime_rt::send(3, b"run", &[]) != slime_rt::ERR_SUCCESS {
        fail_plane(b"generation", b"deliver the manager run token");
    }
    if slime_rt::send(4, b"run", &[]) != slime_rt::ERR_SUCCESS {
        fail_plane(b"generation", b"deliver the client run token");
    }
    wait_clean(&[client.supervision_slot, manager.supervision_slot]);
}

/// Drive the P5.4.2c store plane: the same composition as the storage plane,
/// over the probe that runs M5.4 policy in userspace.
///
/// Separate generation and separate probe, one driver: what differs between the
/// two planes is which component is spawned and what it proves, not how init
/// composes it.
fn drive_store_plane() {
    drive_probe_plane_with_token(
        resolve_executable(b"executable:sel4-store-probe"),
        b"[init] store probe spawned\n",
        b"store",
        Some(2),
        &crossing_factory(b"store-init-buffer-factory"),
    );
}

/// Drive the data-volume plane: spawn the probe, which reads the disk the run attached through its
/// read-only block ring, and require a clean exit. A refused volume is a clean exit too; the gate
/// judges what the probe printed. The probe's only crossing grant is its shared-buffer factory.
fn drive_data_volume_plane() {
    drive_probe_plane_with_token(
        resolve_executable(b"executable:data-volume-probe"),
        b"[init] data volume probe spawned\n",
        b"data-volume",
        None,
        &crossing_factory(b"data-volume-init-buffer-factory"),
    );
}

/// Drive the P5.4.2c storage plane: spawn the probe holding its block
/// capability and require a clean exit.
///
/// The probe's crossing grant is its shared-buffer factory. IO2's storage plane
/// reaches its device through the IO0 rings rather than a root-mediated
/// `BlockTransact`, and a ring is a shared buffer the client allocates, so the
/// factory is authority the probe cannot hold in its own right: `init` is the
/// declared source. The driver endpoint is *not* here and must not be --
/// `grant_crosses_spawn` excludes endpoint grants because the root installs
/// both declared ends itself.
fn drive_storage_plane() {
    drive_probe_plane_with_token(
        resolve_executable(b"executable:sel4-storage-probe"),
        b"[init] storage probe spawned\n",
        b"storage",
        Some(2),
        &crossing_factory(b"storage-init-buffer-factory"),
    );
}

/// The one crossing spawn grant a storage-family probe declares: init's own
/// shared-buffer factory, narrowed to exactly `bufferCreate`.
///
/// Resolved by *grant name* rather than by `kind:sharedBufferFactory+bufferCreate`,
/// on the rule [`resolve_own_buffer_factory`] documents: a role query refuses
/// where a generation binds init more than one factory, and which factory a
/// child allocates from is a graph fact the manifest states. The name is init's
/// own binding, so the root answers only from init's list.
///
/// Returned by value rather than as a `const`: the slot is a number this
/// generation chose and the root reports, so nothing here compiles a slot in.
fn crossing_factory(name: &[u8]) -> [SpawnGrant; 1] {
    [grant(
        slime_rt::resolve_binding(name).unwrap_or_else(|_| slime_rt::exit(1)),
        RIGHT_BUFFER_CREATE,
    )]
}

/// Spawn one probe holding its generation-granted device capability and require
/// a clean exit.
///
/// The composition is deliberately the smallest one that proves the authority
/// path: one child, one grant list, no channels. Everything the plane asserts
/// happens inside the probe, against a real device, through a capability the
/// generation placed — so init's part is to hand it over and observe the
/// outcome.
/// `grants` is the exact crossing-grant vector this plane's manifest declares
/// for the probe, matched positionally against ascending declared slot. The
/// count must equal what `preflight_spawn_grants` derives from the generation or
/// the root refuses the spawn with nothing constructed; a plane whose probe
/// holds all its authority in its own right passes an empty slice.
///
/// `run_token` names a declared endpoint to the spawned instance, for a plane
/// that declares its probe executable twice: the instance init spawns and a
/// root-owned idle one holding the same authority with no session. Sending on it
/// is how the spawned copy learns it is the one that runs, because the root
/// delivers a nonzero boot action only to the bootstrap instance and every other
/// instance — spawned or autostarted — reads zero.
fn drive_probe_plane_with_token(
    executable: u32,
    spawned_marker: &[u8],
    plane: &'static [u8],
    run_token: Option<u32>,
    grants: &[SpawnGrant],
) {
    let probe =
        slime_rt::spawn(executable, grants).unwrap_or_else(|_| fail_plane(plane, b"spawn probe"));
    Line::<256>::new().bytes(spawned_marker).emit();
    if let Some(slot) = run_token
        && slime_rt::send(slot, b"run", &[]) != slime_rt::ERR_SUCCESS
    {
        fail_plane(plane, b"deliver the run token");
    }
    wait_clean(&[probe.supervision_slot]);
}

fn fail_plane(plane: &[u8], reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] ")
        .bytes(plane)
        .bytes(b" plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// More lifetimes than the old monotonic root allocator could sustain while
/// keeping only one child live at a time.
const RECLAMATION_LOOP_CHILDREN: u32 = 80;

fn drive_reclamation_plane() {
    if slime_rt::spawn(resolve_executable(b"executable:supervision-child"), &[]).is_ok() {
        fail_reclamation(b"forced construction unwind unexpectedly succeeded");
    }
    slime_rt::debug_write(b"[init] reclamation construction unwind returned\n");
    let mut completed = 0u32;
    for _ in 0..RECLAMATION_LOOP_CHILDREN {
        let child = slime_rt::spawn(resolve_executable(b"executable:supervision-child"), &[])
            .unwrap_or_else(|_| fail_reclamation(b"loop child spawn"));
        loop {
            match slime_rt::supervision_status(child.supervision_slot) {
                Ok(None) => slime_rt::yield_now(),
                Ok(Some(slime_rt::Termination::Exit(0))) => break,
                _ => fail_reclamation(b"loop child termination"),
            }
        }
        completed += 1;
    }
    if completed != RECLAMATION_LOOP_CHILDREN {
        fail_reclamation(b"lifetime loop incomplete");
    }
    slime_rt::debug_write(b"[init] reclamation lifetime bound crossed\n");
    let fault = slime_rt::spawn(resolve_executable(b"executable:reclamation-fault"), &[])
        .unwrap_or_else(|_| fail_reclamation(b"fault child spawn"));
    loop {
        match slime_rt::supervision_status(fault.supervision_slot) {
            Ok(None) => slime_rt::yield_now(),
            Ok(Some(slime_rt::Termination::Fault(_))) => break,
            _ => fail_reclamation(b"fault child termination"),
        }
    }
    slime_rt::debug_write(b"[init] reclamation fault path reused\n");
}

fn fail_reclamation(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] reclamation plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// MEM-64M's reuse clause: relaunch one declared 64 MiB holder until the root
/// has reclaimed and re-served that quota this many times.
///
/// Twenty because that is the number the milestone's exit condition states. The
/// count is the workload, not a watchdog: each incarnation reserves its whole
/// declared ceiling before it runs, so a root that failed to return a dead
/// holder's backing, descriptors, or CSlots refuses a later spawn rather than
/// drifting quietly, and the census the root prints after each reclamation is
/// what makes the absence of drift observable.
const PRIVATE_CYCLE_COUNT: u32 = 20;

/// Unlike the reclamation plane's children, this holder carries a declared
/// quota and must be told which incarnation it is: a pattern that did not vary
/// between lives could not distinguish a zeroed page from one re-served to a
/// later task with an earlier task's bytes still in it. The cycle number goes
/// over the composition's declared endpoint, which both sides hold before the
/// child runs.
fn drive_private_memory_cycles_plane() {
    let executable = resolve_executable(b"executable:private-cycle-probe");
    let token = slime_rt::resolve_binding(b"private-cycle-token")
        .unwrap_or_else(|_| fail_private_cycles(b"cycle token endpoint missing"));
    let mut exits = 0u32;
    let mut faults = 0u32;
    for cycle in 0..PRIVATE_CYCLE_COUNT {
        let child = slime_rt::spawn(executable, &[])
            .unwrap_or_else(|_| fail_private_cycles(b"holder spawn refused"));
        // Sent after the spawn returns and before the status poll: the child
        // blocks on this endpoint as its first act, so a send that preceded
        // construction would have no receiver, and one issued after the poll
        // began would deadlock against a child that never reaches its exit.
        if slime_rt::send(token, &[cycle as u8], &[]) != slime_rt::ERR_SUCCESS {
            fail_private_cycles(b"cycle token send failed");
        }
        // Even cycles exit, odd ones fault. Asserting which rather than merely
        // "it ended" is what keeps both reclamation paths covered: a probe that
        // stopped faulting would still terminate cleanly twenty times and leave
        // half the exit condition unobserved.
        loop {
            match slime_rt::supervision_status(child.supervision_slot) {
                Ok(None) => slime_rt::yield_now(),
                Ok(Some(slime_rt::Termination::Exit(0))) if cycle % 2 == 0 => {
                    exits += 1;
                    break;
                }
                Ok(Some(slime_rt::Termination::Fault(_))) if cycle % 2 == 1 => {
                    faults += 1;
                    break;
                }
                _ => fail_private_cycles(b"holder ended by the wrong path"),
            }
        }
    }
    if exits + faults != PRIVATE_CYCLE_COUNT || exits == 0 || faults == 0 {
        fail_private_cycles(b"cycle census incomplete");
    }
    Line::<96>::new()
        .bytes(b"[init] private memory cycles exits=")
        .decimal(u64::from(exits))
        .bytes(b" faults=")
        .decimal(u64::from(faults))
        .bytes(b"\n")
        .emit();
}

fn fail_private_cycles(reason: &[u8]) -> ! {
    Line::<256>::new()
        .bytes(b"[init] private memory cycles plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}

/// C10.2's plane needs nothing from init.
///
/// Both probes are declared **root-autostart** instances, so the root launches
/// them from the generation directly and installs each one's declared quota at
/// construction. That is deliberate rather than incidental: C10.2's subject is
/// whether a quota declared in a generation reaches the component the
/// generation names, and routing the launch through an `init` spawn would add a
/// parent whose own authority could be mistaken for the mechanism under test.
/// It also keeps the plane clear of the boot capability layout, which is at its
/// 64-entry ceiling — an init-spawned probe needs an `executable` row per
/// instance, and this needs none.
///
/// Init itself is the third case: it declares no quota, so a plane that granted
/// authority to its own launcher would show up as a nonzero ceiling on `init`
/// in the root's markers.
fn drive_private_memory_plane() {
    slime_rt::debug_write(b"[init] private memory plane is root-launched\n");
}
