use crate::clock_authority::{self, ClockAuthority};
use crate::lifecycle_policy::{self, LifecyclePolicy, ParameterGrant};
use crate::sha256::Sha256;
use crate::shared_buffer_budget::{self, SharedBufferBudget};

pub const MAGIC_V5: [u8; 8] = *b"SLIMEG5\0";
pub const MAGIC_V4: [u8; 8] = *b"SLIMEG4\0";
pub const MAGIC_V3: [u8; 8] = *b"SLIMEG3\0";
pub const MAGIC_V2: [u8; 8] = *b"SLIMEG2\0";
pub const MAGIC: [u8; 8] = MAGIC_V5;
include!("generated/generation.rs");

const MAX_TASK_CAPS: usize = 128;
const PLAN_NONE: usize = u32::MAX as usize;
const GRANT_POLICY_ONLY: u32 = 1;
/// Grant flags. No bit is defined: `GRANT_MINTED` named a send/recv grant whose
/// object its source created at runtime, which the native cutover made
/// impossible — an endpoint is a generation-owned seL4 Endpoint the root
/// materializes and installs into both declared ends — so B50 deleted the
/// concept rather than leaving a flag nothing can set. An unknown bit is still
/// refused, so a producer that grew one fails admission.
const GRANT_FLAGS_KNOWN: u32 = 0;

/// Kernel-object kind discriminant for a CNode, matching `KERNEL_OBJECT_CNODE`
/// in `scripts/build/build-generation.py`.
const KERNEL_OBJECT_CNODE: u32 = 1;
/// Kernel-object kind discriminant for a TCB.
const KERNEL_OBJECT_TCB: u32 = 3;
/// Kernel-object kind discriminant for an endpoint.
const KERNEL_OBJECT_ENDPOINT: u32 = 5;
/// Kernel-object kind discriminant for a notification.
const KERNEL_OBJECT_NOTIFICATION: u32 = 7;
const ROOT_SERVICE_SLOT: usize = crate::component_runtime_abi::ROOT_SERVICE_SLOT as usize;
const CONSOLE_SERVICE_SLOT: usize = crate::component_runtime_abi::CONSOLE_SERVICE_SLOT as usize;
const SERVICE_SEND_RIGHT: Rights = 1;

fn parameter_transport_holder(grant: ParameterGrant, holder: &[u8; 32]) -> bool {
    grant.holder_identity == *holder
        && grant.authority_flags
            & (lifecycle_policy::PARAMETER_READ | lifecycle_policy::PARAMETER_WRITE)
            != 0
}

fn service_for_capability(kind: CapabilityKind) -> Option<u32> {
    match kind {
        CapabilityKind::SharedBufferFactory
        | CapabilityKind::SharedBuffer
        | CapabilityKind::Loan => Some(SERVICE_SHARED_BUFFER),
        CapabilityKind::Directory => Some(SERVICE_DIRECTORY),
        CapabilityKind::Input => Some(SERVICE_INPUT),
        CapabilityKind::Supervision => Some(SERVICE_SUPERVISION),
        CapabilityKind::Device
        | CapabilityKind::MmioRegion
        | CapabilityKind::InterruptSource
        | CapabilityKind::DmaAccount => Some(SERVICE_IO_RESOURCE),
        CapabilityKind::Endpoint | CapabilityKind::Executable => None,
    }
}

pub const KIND_KERNEL: u32 = 1;
pub const KIND_BOOTSTRAP: u32 = 2;
pub const KIND_COMPONENT: u32 = 3;

/// Declared capability class. Rights remain the operation ceiling; the kind
/// says what object or kernel capability those rights name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CapabilityKind {
    Endpoint = CAPABILITY_ENDPOINT,
    Executable = CAPABILITY_EXECUTABLE,
    SharedBufferFactory = CAPABILITY_SHARED_BUFFER_FACTORY,
    Directory = CAPABILITY_DIRECTORY,
    Input = CAPABILITY_INPUT,
    Supervision = CAPABILITY_SUPERVISION,
    SharedBuffer = CAPABILITY_SHARED_BUFFER,
    Loan = CAPABILITY_LOAN,
    Device = CAPABILITY_DEVICE,
    MmioRegion = CAPABILITY_MMIO_REGION,
    InterruptSource = CAPABILITY_INTERRUPT_SOURCE,
    DmaAccount = CAPABILITY_DMA_ACCOUNT,
}

impl CapabilityKind {
    fn decode(value: u32) -> Result<Self, DecodeError> {
        match value {
            CAPABILITY_ENDPOINT => Ok(Self::Endpoint),
            CAPABILITY_EXECUTABLE => Ok(Self::Executable),
            CAPABILITY_SHARED_BUFFER_FACTORY => Ok(Self::SharedBufferFactory),
            CAPABILITY_DIRECTORY => Ok(Self::Directory),
            CAPABILITY_INPUT => Ok(Self::Input),
            CAPABILITY_SUPERVISION => Ok(Self::Supervision),
            CAPABILITY_SHARED_BUFFER => Ok(Self::SharedBuffer),
            CAPABILITY_LOAN => Ok(Self::Loan),
            CAPABILITY_DEVICE => Ok(Self::Device),
            CAPABILITY_MMIO_REGION => Ok(Self::MmioRegion),
            CAPABILITY_INTERRUPT_SOURCE => Ok(Self::InterruptSource),
            CAPABILITY_DMA_ACCOUNT => Ok(Self::DmaAccount),
            _ => Err(DecodeError::BadBounds),
        }
    }
}

fn capability_rights_valid(kind: CapabilityKind, rights: Rights) -> bool {
    let allowed = match kind {
        CapabilityKind::Endpoint => RIGHT_SEND | RIGHT_RECV | RIGHT_TRANSFER,
        CapabilityKind::Executable => RIGHT_EXEC | RIGHT_SPAWN | RIGHT_TRANSFER,
        CapabilityKind::SharedBufferFactory => RIGHT_BUFFER_CREATE | RIGHT_TRANSFER,
        CapabilityKind::Directory => {
            RIGHT_DIRECTORY_READ
                | RIGHT_DIRECTORY_WRITE
                | RIGHT_DIRECTORY_LIST
                | RIGHT_DIRECTORY_DERIVE
                | RIGHT_TRANSFER
        }
        CapabilityKind::Input => RIGHT_INPUT_READ,
        CapabilityKind::Supervision => RIGHT_SUPERVISE | RIGHT_TRANSFER,
        CapabilityKind::SharedBuffer => {
            RIGHT_BUFFER_WRITE | RIGHT_BUFFER_MAP | RIGHT_BUFFER_LOAN | RIGHT_TRANSFER
        }
        CapabilityKind::Loan => RIGHT_BUFFER_WRITE | RIGHT_BUFFER_MAP | RIGHT_TRANSFER,
        CapabilityKind::Device | CapabilityKind::MmioRegion => RIGHT_MAP_MMIO,
        CapabilityKind::InterruptSource => RIGHT_IRQ_ACK,
        CapabilityKind::DmaAccount => RIGHT_DMA_PIN | RIGHT_DMA_RELEASE,
    };
    let required = match kind {
        CapabilityKind::Endpoint => RIGHT_SEND | RIGHT_RECV,
        CapabilityKind::Executable => RIGHT_EXEC | RIGHT_SPAWN,
        CapabilityKind::SharedBufferFactory => RIGHT_BUFFER_CREATE,
        CapabilityKind::Directory => {
            RIGHT_DIRECTORY_READ
                | RIGHT_DIRECTORY_WRITE
                | RIGHT_DIRECTORY_LIST
                | RIGHT_DIRECTORY_DERIVE
        }
        CapabilityKind::Input => RIGHT_INPUT_READ,
        CapabilityKind::Supervision => RIGHT_SUPERVISE,
        CapabilityKind::SharedBuffer => RIGHT_BUFFER_WRITE | RIGHT_BUFFER_MAP | RIGHT_BUFFER_LOAN,
        CapabilityKind::Loan => RIGHT_BUFFER_MAP,
        CapabilityKind::Device | CapabilityKind::MmioRegion => RIGHT_MAP_MMIO,
        CapabilityKind::InterruptSource => RIGHT_IRQ_ACK,
        CapabilityKind::DmaAccount => RIGHT_DMA_PIN | RIGHT_DMA_RELEASE,
    };
    rights != 0
        && rights & !allowed == 0
        && rights & required != 0
        && (kind != CapabilityKind::Executable
            || rights & (RIGHT_EXEC | RIGHT_SPAWN) == RIGHT_EXEC | RIGHT_SPAWN)
        && (kind != CapabilityKind::Input || rights == RIGHT_INPUT_READ)
}
pub const KIND_RESOURCE: u32 = 4;
pub const ROLE_INIT: u32 = 1;
/// Rights are a bitmask over the vocabulary declared in
/// `contracts/generation/v5/schema.zt` and generated into `generated/generation.rs`,
/// which `include!` brings into this module. `RIGHT_ALL` is the union of those
/// named bits, so an undefined position such as bit 17 is refused rather than
/// admitted by a bit-width mask (B57).
pub type Rights = u64;
pub const MAX_SPAWN_BUDGET: u16 = 32;
pub const POLICY_IMMUTABLE: u32 = 1;
pub const POLICY_EPHEMERAL: u32 = 2;
pub const POLICY_PRESERVE: u32 = 3;
pub const POLICY_SNAPSHOT_BEFORE_UPGRADE: u32 = 4;
pub const POLICY_DISCARD_ON_ROLLBACK: u32 = 5;
/// Authenticated bootstrap composition selector.
///
/// The numeric ABI is passed in the bootstrap thread's first C parameter. It is
/// deliberately independent of the source spelling so component images remain
/// byte-identical across generation manifests.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootAction {
    Product = 1,
    Boot = 2,
    Call = 3,
    Channel = 4,
    Crossing = 5,
    Directory = 7,
    Filesystem = 8,
    Generation = 9,
    Input = 10,
    Loan = 11,
    Operation = 12,
    Powerbox = 13,
    Qos = 14,
    Reclamation = 15,
    Recovery = 16,
    Rollback = 17,
    Sample = 18,
    Spawn = 19,
    Storage = 20,
    Store = 21,
    Stream = 22,
    Supervision = 23,
    Transfer = 24,
    Visibility = 25,
    /// The 48-instance graph at the admitted ceiling (B49).
    Stress = 26,
    /// C8.12's matching, visibility, and denial matrix.
    Matrix = 27,
    /// C8.13's concurrent cross-plane traffic and resource ceilings.
    Traffic = 28,
    /// RP2's demo-scoped AArch64 vertical slice: one generation that launches
    /// the component graph *and* runs the bounded data path, rather than
    /// asserting the two across separate plane fixtures.
    Demo = 29,
    /// C10.2's generation-declared private-memory budget: one executable
    /// declared twice, as a granted holder and an omitted one.
    PrivateMemory = 30,
    /// C9.1's independently grantable monotonic, timer, and simulated clocks.
    ClockAuthority = 31,
    /// C9.2's bounded userspace wait set over one declared Notification.
    WaitSet = 32,
    /// C9.3's declared scheduling class and its promotion authority.
    SchedulingClass = 33,
    /// C9.4's lifecycle transition graph, supervised restart, health
    /// dependencies, and parameter authority.
    LifecycleRestart = 34,
    /// C9.5's typed recording and deterministic replay: a recorded run, a
    /// replay of it, and a component whose unrecorded grant makes a
    /// determinism claim inadmissible.
    Replay = 35,
    /// C9.6's robot workload composition: a sensor -> controller -> actuator
    /// graph over the native fabric, exercised under declared best-effort CPU
    /// contention and an injected controller restart.
    RobotRuntime = 36,
    /// Language-neutral runtime proof: one independently compiled C component
    /// invokes generated console and lifecycle ABI operations.
    CRuntime = 37,
    /// Minimal pure S-expression language core implemented outside Rust.
    Slisp = 38,
    /// MEM-64M's reuse clause: one declared 64 MiB holder relaunched until the
    /// root has reclaimed and re-served that quota twenty times, half of the
    /// incarnations ending by exit and half by a deliberate fault.
    PrivateMemoryCycles = 39,
    /// Declared instance lifetime: a resident instance that stays live, a
    /// bounded one that completes, and resident ones whose exit the root
    /// records as a failure rather than as completion.
    Lifetime = 40,
    /// A hash-pinned data volume read through a read-only block ring: the honest volume and every
    /// broken one the data-volume exam boots.
    DataVolume = 41,
}

impl BootAction {
    pub const fn id(self) -> u32 {
        self as u32
    }

    /// Every declared composition, in declaration order.
    ///
    /// Exported because a consumer that must map a wire id back to a variant
    /// would otherwise restate this list. `slime-root` answers the id over
    /// `BOOT_ACTION` (B70) and components fold it back, and a component-side
    /// copy is a second vocabulary that goes stale silently: a variant added
    /// here but missing there folds to `None` and reads at the call site as
    /// "some older generation" rather than as the new composition.
    ///
    /// This *is* a hand-written array, so it cannot police itself. Two things
    /// keep it from lagging the enum: [`Self::from_id`]'s exhaustive `match`
    /// fails to compile when a variant is added without a case, and
    /// `boot_action_ids_round_trip` fails when a variant reaches that `match`
    /// and the frozen numbering table but not this list.
    pub const ALL: &'static [Self] = &[
        Self::Product,
        Self::Boot,
        Self::Call,
        Self::Channel,
        Self::Crossing,
        Self::Directory,
        Self::Filesystem,
        Self::Generation,
        Self::Input,
        Self::Loan,
        Self::Operation,
        Self::Powerbox,
        Self::Qos,
        Self::Reclamation,
        Self::Recovery,
        Self::Rollback,
        Self::Sample,
        Self::Spawn,
        Self::Storage,
        Self::Store,
        Self::Stream,
        Self::Supervision,
        Self::Transfer,
        Self::Visibility,
        Self::Stress,
        Self::Matrix,
        Self::Traffic,
        Self::Demo,
        Self::PrivateMemory,
        Self::ClockAuthority,
        Self::WaitSet,
        Self::SchedulingClass,
        Self::LifecycleRestart,
        Self::Replay,
        Self::RobotRuntime,
        Self::CRuntime,
        Self::Slisp,
        Self::PrivateMemoryCycles,
        Self::Lifetime,
        Self::DataVolume,
    ];

    /// The composition a wire id names, or `None` for an id this build does not
    /// declare.
    ///
    /// The inverse of [`Self::id`], and the reason [`Self::ALL`] cannot go
    /// stale: the exhaustive `match` refuses to compile when a variant is added
    /// without a case, and `boot_action_ids_round_trip` then fails unless the
    /// same variant reaches `ALL`. Together they make "named" and "listed" one
    /// step rather than two.
    pub fn from_id(id: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|action| {
            let declared = match action {
                Self::Product => Self::Product.id(),
                Self::Boot => Self::Boot.id(),
                Self::Call => Self::Call.id(),
                Self::Channel => Self::Channel.id(),
                Self::Crossing => Self::Crossing.id(),
                Self::Directory => Self::Directory.id(),
                Self::Filesystem => Self::Filesystem.id(),
                Self::Generation => Self::Generation.id(),
                Self::Input => Self::Input.id(),
                Self::Loan => Self::Loan.id(),
                Self::Operation => Self::Operation.id(),
                Self::Powerbox => Self::Powerbox.id(),
                Self::Qos => Self::Qos.id(),
                Self::Reclamation => Self::Reclamation.id(),
                Self::Recovery => Self::Recovery.id(),
                Self::Rollback => Self::Rollback.id(),
                Self::Sample => Self::Sample.id(),
                Self::Spawn => Self::Spawn.id(),
                Self::Storage => Self::Storage.id(),
                Self::Store => Self::Store.id(),
                Self::Stream => Self::Stream.id(),
                Self::Supervision => Self::Supervision.id(),
                Self::Transfer => Self::Transfer.id(),
                Self::Visibility => Self::Visibility.id(),
                Self::Stress => Self::Stress.id(),
                Self::Matrix => Self::Matrix.id(),
                Self::Traffic => Self::Traffic.id(),
                Self::Demo => Self::Demo.id(),
                Self::PrivateMemory => Self::PrivateMemory.id(),
                Self::ClockAuthority => Self::ClockAuthority.id(),
                Self::WaitSet => Self::WaitSet.id(),
                Self::SchedulingClass => Self::SchedulingClass.id(),
                Self::LifecycleRestart => Self::LifecycleRestart.id(),
                Self::Replay => Self::Replay.id(),
                Self::RobotRuntime => Self::RobotRuntime.id(),
                Self::CRuntime => Self::CRuntime.id(),
                Self::Slisp => Self::Slisp.id(),
                Self::PrivateMemoryCycles => Self::PrivateMemoryCycles.id(),
                Self::Lifetime => Self::Lifetime.id(),
                Self::DataVolume => Self::DataVolume.id(),
            };
            declared == id
        })
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "product" => Self::Product,
            "boot" => Self::Boot,
            "call" => Self::Call,
            "channel" => Self::Channel,
            "crossing" => Self::Crossing,
            "directory" => Self::Directory,
            "filesystem" => Self::Filesystem,
            "generation" => Self::Generation,
            "input" => Self::Input,
            "loan" => Self::Loan,
            "operation" => Self::Operation,
            "powerbox" => Self::Powerbox,
            "qos" => Self::Qos,
            "stress" => Self::Stress,
            "reclamation" => Self::Reclamation,
            "recovery" => Self::Recovery,
            "rollback" => Self::Rollback,
            "sample" => Self::Sample,
            "spawn" => Self::Spawn,
            "storage" => Self::Storage,
            "store" => Self::Store,
            "stream" => Self::Stream,
            "supervision" => Self::Supervision,
            "transfer" => Self::Transfer,
            "visibility" => Self::Visibility,
            "matrix" => Self::Matrix,
            "traffic" => Self::Traffic,
            "demo" => Self::Demo,
            "private-memory" => Self::PrivateMemory,
            "private-memory-cycles" => Self::PrivateMemoryCycles,
            "lifetime" => Self::Lifetime,
            "data-volume" => Self::DataVolume,
            "clock-authority" => Self::ClockAuthority,
            "wait-set" => Self::WaitSet,
            "scheduling-class" => Self::SchedulingClass,
            "lifecycle-restart" => Self::LifecycleRestart,
            "replay" => Self::Replay,
            "robot-runtime" => Self::RobotRuntime,
            "c-runtime" => Self::CRuntime,
            "slisp" => Self::Slisp,
            _ => return None,
        })
    }
}

const IDENTITY_OFFSET: usize = 24;
const IDENTITY_END: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnknownRequiredFlags,
    BadHeader,
    BadIdentity,
    BadBounds,
    BadIndex,
    BadUtf8,
    BadOrder,
    DuplicateName,
    BadObjectHash,
    BadKernel,
    BadBootstrap,
    BadDependency,
    BadBinding,
    BadOwner,
    BadState,
    BadHealth,
    UnknownEnum,
    NonZeroReserved,
}

#[derive(Debug, Clone, Copy)]
pub struct Object<'a> {
    pub id: &'a str,
    pub kind: u32,
    pub digest: [u8; 32],
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct Executable<'a> {
    pub name: &'a str,
    pub object: usize,
    pub role: u32,
    pub spawn_budget: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceOwner {
    Root,
    Instance(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceHealth {
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy)]
pub struct Instance<'a> {
    pub name: &'a str,
    pub executable: usize,
    pub owner: InstanceOwner,
    pub autostart: bool,
    pub health: InstanceHealth,
    dependency_start: usize,
    dependency_count: usize,
    binding_start: usize,
    binding_count: usize,
}

impl Instance<'_> {
    pub const fn dependency_count(self) -> usize {
        self.dependency_count
    }
    pub const fn binding_count(self) -> usize {
        self.binding_count
    }
    pub const fn is_root_autostart(self) -> bool {
        matches!(self.owner, InstanceOwner::Root) && self.autostart
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceBinding {
    pub grant: usize,
    pub slot: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantEndpoint {
    Executable(usize),
    Instance(usize),
}

#[derive(Debug, Clone, Copy)]
pub struct Grant<'a> {
    pub name: &'a str,
    pub source: GrantEndpoint,
    pub target: GrantEndpoint,
    pub rights: Rights,
    pub transferable: bool,
    pub capability_kind: CapabilityKind,
}

#[derive(Debug, Clone, Copy)]
pub struct StateBinding<'a> {
    pub name: &'a str,
    pub owner: usize,
    pub schema_version: u32,
    pub policy: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Process<'a> {
    pub name: &'a str,
    pub instance: usize,
    pub cspace_object: usize,
    pub vspace_object: usize,
    pub main_thread: usize,
    pub quota: usize,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Thread<'a> {
    pub name: &'a str,
    pub process: usize,
    pub tcb_object: usize,
    pub schedule: usize,
    pub fault_policy: usize,
    pub ipc_buffer_object: usize,
    pub ipc_buffer_vaddr: u64,
    pub entry: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct KernelObject<'a> {
    pub name: &'a str,
    pub kind: u32,
    pub owner_process: usize,
    pub size_bits: u32,
    pub count: u32,
    pub source_object: usize,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Mapping {
    pub process: usize,
    pub object: usize,
    pub virtual_address: u64,
    pub page_count: u32,
    pub rights: Rights,
    pub attributes: u64,
    pub source_object: usize,
    pub flags: u32,
}

/// The slots a plan declares for a child's own TCB and fault endpoint. Either
/// may be absent; the caller decides whether that is admissible for the path
/// it is constructing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChildSlotPlan {
    pub service: Option<usize>,
    pub console: Option<usize>,
    pub tcb: Option<usize>,
    pub fault: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct CapBinding {
    pub process: usize,
    pub slot: usize,
    pub object: usize,
    pub rights: Rights,
    pub badge: u64,
    pub grant: usize,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ServiceBinding {
    pub process: usize,
    pub service: u32,
    pub slot: usize,
    pub object: usize,
    pub rights: Rights,
    pub badge: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Schedule<'a> {
    pub name: &'a str,
    pub thread: usize,
    pub authority_process: usize,
    pub priority: u32,
    pub max_controlled_priority: u32,
    pub budget_us: u64,
    pub period_us: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct FaultPolicy<'a> {
    pub name: &'a str,
    pub thread: usize,
    pub handler_process: usize,
    pub endpoint_object: usize,
    pub badge: u64,
    pub action: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct SpawnTemplate<'a> {
    pub name: &'a str,
    pub executable: usize,
    pub owner_process: usize,
    pub quota: usize,
    pub schedule: usize,
    pub fault_policy: usize,
    pub max_instances: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ResourceQuota<'a> {
    pub name: &'a str,
    pub owner_process: usize,
    pub cnode_count: u32,
    pub tcb_count: u32,
    pub endpoint_count: u32,
    pub notification_count: u32,
    pub frame_count: u32,
    pub page_table_count: u32,
    pub mapping_count: u32,
    pub irq_count: u32,
    pub cslot_count: u32,
    pub untyped_bytes: u64,
    pub dynamic_reserve_bytes: u64,
    pub flags: u32,
}

/// A capability the generation authorizes one instance to hand another at
/// spawn, whose concrete object the owner mints at runtime.
///
/// A static [`Grant`] names both endpoints and a concrete object; a channel
/// endpoint minted after activation has no object to name, so the plan would
/// otherwise have to either omit it — leaving the child's slot unaccounted —
/// or degrade the grant to a bare rights assertion.
///
/// What this record fixes before activation: the minter, the holder, the
/// destination slot, and an exact rights ceiling. A spawn is refused unless
/// the caller *is* the declared minter, the destination is the declared slot
/// rather than one the caller chose, and the transferred rights fall within
/// both the ceiling and what the caller itself holds.
///
/// What it deliberately does **not** fix is object identity, which does not
/// exist until the minter creates it. A minter can therefore satisfy a minted
/// declaration with a capability of the right kind and rights but a different
/// underlying object — a supervision handle naming another of its children, or
/// a directory capability at a broader scope than intended. The declaration
/// bounds *who may hand what class of authority to whom, and where it lands*;
/// it is not an object binding. A relationship that must pin identity needs a
/// [`Grant`] against a concrete object instead.
///
/// `transferable` is folded into [`Self::rights`] as `RIGHT_TRANSFER` rather
/// than carried as a separate field, so the two cannot disagree — unlike
/// [`Grant`], whose separate flag must be checked for coherence against its
/// rights word.
#[derive(Debug, Clone, Copy)]
pub struct MintedBinding<'a> {
    pub name: &'a str,
    pub owner: usize,
    pub holder: usize,
    pub slot: usize,
    pub rights: Rights,
    pub capability_kind: CapabilityKind,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationGrant<'a> {
    pub name: &'a str,
    pub source: usize,
    pub target: usize,
    pub object: usize,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationRole {
    Signal,
    Wait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationBinding {
    pub grant: usize,
    pub holder: usize,
    pub slot: usize,
    pub role: NotificationRole,
    pub flags: u32,
}

pub struct Generation<'a> {
    bytes: &'a [u8],
    pub version: u32,
    pub identity: [u8; 32],
    pub number: u64,
    pub parent: Option<[u8; 32]>,
    pub target: &'a str,
    pub boot_action: BootAction,
    pub bootstrap_instance: usize,
    pub boot_attempts: u32,
    object_count: usize,
    executable_count: usize,
    instance_count: usize,
    dependency_count: usize,
    binding_count: usize,
    grant_count: usize,
    state_count: usize,
    health_count: usize,
    process_count: usize,
    thread_count: usize,
    kernel_object_count: usize,
    mapping_count: usize,
    cap_binding_count: usize,
    service_binding_count: usize,
    schedule_count: usize,
    fault_policy_count: usize,
    spawn_template_count: usize,
    resource_quota_count: usize,
    minted_binding_count: usize,
    notification_grant_count: usize,
    notification_binding_count: usize,
    object_offset: usize,
    executable_offset: usize,
    instance_offset: usize,
    dependency_offset: usize,
    binding_offset: usize,
    grant_offset: usize,
    state_offset: usize,
    health_offset: usize,
    process_offset: usize,
    thread_offset: usize,
    kernel_object_offset: usize,
    mapping_offset: usize,
    cap_binding_offset: usize,
    service_binding_offset: usize,
    schedule_offset: usize,
    fault_policy_offset: usize,
    spawn_template_offset: usize,
    resource_quota_offset: usize,
    minted_binding_offset: usize,
    notification_grant_offset: usize,
    notification_binding_offset: usize,
    string_offset: usize,
    string_len: usize,
}

impl<'a> Generation<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::Truncated);
        }
        let magic: [u8; 8] = bytes[..8].try_into().unwrap();
        let version = u32_at(bytes, 8)?;
        if magic != MAGIC_V5 {
            return if matches!(magic, MAGIC_V4 | MAGIC_V3 | MAGIC_V2) {
                Err(DecodeError::UnsupportedVersion)
            } else {
                Err(DecodeError::BadMagic)
            };
        }
        if version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion);
        }
        if u32_at(bytes, 12)? as usize != HEADER_LEN {
            return Err(DecodeError::BadHeader);
        }
        if u64_at(bytes, 16)? != 0 {
            return Err(DecodeError::UnknownRequiredFlags);
        }
        // Reserved word after the notification counts and trailing header pad.
        reserved_zero(bytes, 196, 200)?;
        reserved_zero(bytes, 400, HEADER_LEN)?;
        let total_len = u64_at(bytes, 392)? as usize;
        if total_len != bytes.len() || total_len > MAX_GENERATION_BYTES {
            return Err(DecodeError::BadBounds);
        }
        let identity: [u8; 32] = bytes[IDENTITY_OFFSET..IDENTITY_END].try_into().unwrap();
        if generation_identity(bytes) != identity {
            return Err(DecodeError::BadIdentity);
        }
        let parent_bytes: [u8; 32] = bytes[64..96].try_into().unwrap();

        let generation = Self {
            bytes,
            version,
            identity,
            number: u64_at(bytes, 56)?,
            parent: (parent_bytes != [0; 32]).then_some(parent_bytes),
            target: "",
            boot_action: BootAction::Product,
            bootstrap_instance: u32_at(bytes, 104)? as usize,
            boot_attempts: u32_at(bytes, 108)?,
            object_count: bounded_count(u32_at(bytes, 112)? as usize, 1, MAX_OBJECTS)?,
            executable_count: bounded_count(u32_at(bytes, 116)? as usize, 1, MAX_EXECUTABLES)?,
            instance_count: bounded_count(u32_at(bytes, 120)? as usize, 1, MAX_INSTANCES)?,
            dependency_count: bounded_count(u32_at(bytes, 124)? as usize, 0, MAX_DEPENDENCIES)?,
            binding_count: bounded_count(u32_at(bytes, 128)? as usize, 0, MAX_BINDINGS)?,
            grant_count: bounded_count(u32_at(bytes, 132)? as usize, 0, MAX_GRANTS)?,
            state_count: bounded_count(u32_at(bytes, 136)? as usize, 0, MAX_STATES)?,
            health_count: bounded_count(u32_at(bytes, 140)? as usize, 0, MAX_HEALTH_INSTANCES)?,
            process_count: bounded_count(u32_at(bytes, 144)? as usize, 1, MAX_PROCESSES)?,
            thread_count: bounded_count(u32_at(bytes, 148)? as usize, 1, MAX_THREADS)?,
            kernel_object_count: bounded_count(
                u32_at(bytes, 152)? as usize,
                1,
                MAX_KERNEL_OBJECTS,
            )?,
            mapping_count: bounded_count(u32_at(bytes, 156)? as usize, 0, MAX_MAPPINGS)?,
            cap_binding_count: bounded_count(u32_at(bytes, 160)? as usize, 1, MAX_CAP_BINDINGS)?,
            service_binding_count: bounded_count(
                u32_at(bytes, 164)? as usize,
                1,
                MAX_SERVICE_BINDINGS,
            )?,
            schedule_count: bounded_count(u32_at(bytes, 168)? as usize, 1, MAX_SCHEDULES)?,
            fault_policy_count: bounded_count(u32_at(bytes, 172)? as usize, 1, MAX_FAULT_POLICIES)?,
            spawn_template_count: bounded_count(
                u32_at(bytes, 176)? as usize,
                0,
                MAX_SPAWN_TEMPLATES,
            )?,
            resource_quota_count: bounded_count(
                u32_at(bytes, 180)? as usize,
                1,
                MAX_RESOURCE_QUOTAS,
            )?,
            minted_binding_count: bounded_count(
                u32_at(bytes, 184)? as usize,
                0,
                MAX_MINTED_BINDINGS,
            )?,
            notification_grant_count: bounded_count(
                u32_at(bytes, 188)? as usize,
                0,
                MAX_NOTIFICATION_GRANTS,
            )?,
            notification_binding_count: bounded_count(
                u32_at(bytes, 192)? as usize,
                0,
                MAX_NOTIFICATION_BINDINGS,
            )?,
            object_offset: u64_at(bytes, 200)? as usize,
            executable_offset: u64_at(bytes, 208)? as usize,
            instance_offset: u64_at(bytes, 216)? as usize,
            dependency_offset: u64_at(bytes, 224)? as usize,
            binding_offset: u64_at(bytes, 232)? as usize,
            grant_offset: u64_at(bytes, 240)? as usize,
            state_offset: u64_at(bytes, 248)? as usize,
            health_offset: u64_at(bytes, 256)? as usize,
            process_offset: u64_at(bytes, 264)? as usize,
            thread_offset: u64_at(bytes, 272)? as usize,
            kernel_object_offset: u64_at(bytes, 280)? as usize,
            mapping_offset: u64_at(bytes, 288)? as usize,
            cap_binding_offset: u64_at(bytes, 296)? as usize,
            service_binding_offset: u64_at(bytes, 304)? as usize,
            schedule_offset: u64_at(bytes, 312)? as usize,
            fault_policy_offset: u64_at(bytes, 320)? as usize,
            spawn_template_offset: u64_at(bytes, 328)? as usize,
            resource_quota_offset: u64_at(bytes, 336)? as usize,
            minted_binding_offset: u64_at(bytes, 344)? as usize,
            notification_grant_offset: u64_at(bytes, 352)? as usize,
            notification_binding_offset: u64_at(bytes, 360)? as usize,
            string_offset: u64_at(bytes, 368)? as usize,
            string_len: u64_at(bytes, 376)? as usize,
        };
        if generation.string_len > MAX_STRING_TABLE_BYTES {
            return Err(DecodeError::BadBounds);
        }
        generation.validate_sections(u64_at(bytes, 384)? as usize)?;
        let target = generation.string(u32_at(bytes, 96)? as usize)?;
        let boot_action = BootAction::parse(generation.string(u32_at(bytes, 100)? as usize)?)
            .ok_or(DecodeError::UnknownEnum)?;
        let generation = Self {
            target,
            boot_action,
            ..generation
        };
        generation.validate(u64_at(bytes, 384)? as usize)?;
        Ok(generation)
    }

    fn validate_sections(&self, payload_offset: usize) -> Result<(), DecodeError> {
        check_section(
            self.object_offset,
            self.object_count,
            OBJECT_LEN,
            self.executable_offset,
        )?;
        check_section(
            self.executable_offset,
            self.executable_count,
            EXECUTABLE_LEN,
            self.instance_offset,
        )?;
        check_section(
            self.instance_offset,
            self.instance_count,
            INSTANCE_LEN,
            self.dependency_offset,
        )?;
        check_section(
            self.dependency_offset,
            self.dependency_count,
            DEPENDENCY_LEN,
            self.binding_offset,
        )?;
        check_section(
            self.binding_offset,
            self.binding_count,
            BINDING_LEN,
            self.grant_offset,
        )?;
        check_section(
            self.grant_offset,
            self.grant_count,
            GRANT_LEN,
            self.state_offset,
        )?;
        check_section(
            self.state_offset,
            self.state_count,
            STATE_LEN,
            self.health_offset,
        )?;
        check_section(
            self.health_offset,
            self.health_count,
            HEALTH_LEN,
            self.process_offset,
        )?;
        check_section(
            self.process_offset,
            self.process_count,
            PROCESS_LEN,
            self.thread_offset,
        )?;
        check_section(
            self.thread_offset,
            self.thread_count,
            THREAD_LEN,
            self.kernel_object_offset,
        )?;
        check_section(
            self.kernel_object_offset,
            self.kernel_object_count,
            KERNEL_OBJECT_LEN,
            self.mapping_offset,
        )?;
        check_section(
            self.mapping_offset,
            self.mapping_count,
            MAPPING_LEN,
            self.cap_binding_offset,
        )?;
        check_section(
            self.cap_binding_offset,
            self.cap_binding_count,
            CAP_BINDING_LEN,
            self.service_binding_offset,
        )?;
        check_section(
            self.service_binding_offset,
            self.service_binding_count,
            SERVICE_BINDING_LEN,
            self.schedule_offset,
        )?;
        check_section(
            self.schedule_offset,
            self.schedule_count,
            SCHEDULE_LEN,
            self.fault_policy_offset,
        )?;
        check_section(
            self.fault_policy_offset,
            self.fault_policy_count,
            FAULT_POLICY_LEN,
            self.spawn_template_offset,
        )?;
        check_section(
            self.spawn_template_offset,
            self.spawn_template_count,
            SPAWN_TEMPLATE_LEN,
            self.resource_quota_offset,
        )?;
        check_section(
            self.resource_quota_offset,
            self.resource_quota_count,
            RESOURCE_QUOTA_LEN,
            self.minted_binding_offset,
        )?;
        check_section(
            self.minted_binding_offset,
            self.minted_binding_count,
            MINTED_BINDING_LEN,
            self.notification_grant_offset,
        )?;
        check_section(
            self.notification_grant_offset,
            self.notification_grant_count,
            NOTIFICATION_GRANT_LEN,
            self.notification_binding_offset,
        )?;
        check_section(
            self.notification_binding_offset,
            self.notification_binding_count,
            NOTIFICATION_BINDING_LEN,
            self.string_offset,
        )?;
        if self.object_offset != HEADER_LEN
            || self.string_offset.checked_add(self.string_len) != Some(payload_offset)
            || payload_offset > self.bytes.len()
        {
            return Err(DecodeError::BadBounds);
        }
        Ok(())
    }

    pub const fn is_v5(&self) -> bool {
        self.version == FORMAT_VERSION
    }
    pub const fn object_count(&self) -> usize {
        self.object_count
    }
    pub const fn executable_count(&self) -> usize {
        self.executable_count
    }
    pub const fn instance_count(&self) -> usize {
        self.instance_count
    }
    pub const fn grant_count(&self) -> usize {
        self.grant_count
    }
    pub const fn state_count(&self) -> usize {
        self.state_count
    }
    pub const fn health_count(&self) -> usize {
        self.health_count
    }
    pub const fn process_count(&self) -> usize {
        self.process_count
    }
    pub const fn thread_count(&self) -> usize {
        self.thread_count
    }
    pub const fn kernel_object_count(&self) -> usize {
        self.kernel_object_count
    }
    pub const fn mapping_count(&self) -> usize {
        self.mapping_count
    }
    pub const fn cap_binding_count(&self) -> usize {
        self.cap_binding_count
    }
    pub const fn service_binding_count(&self) -> usize {
        self.service_binding_count
    }
    pub const fn schedule_count(&self) -> usize {
        self.schedule_count
    }
    pub const fn fault_policy_count(&self) -> usize {
        self.fault_policy_count
    }
    pub const fn spawn_template_count(&self) -> usize {
        self.spawn_template_count
    }
    pub const fn resource_quota_count(&self) -> usize {
        self.resource_quota_count
    }
    pub const fn notification_grant_count(&self) -> usize {
        self.notification_grant_count
    }
    pub const fn notification_binding_count(&self) -> usize {
        self.notification_binding_count
    }
    pub const fn bootstrap(&self) -> usize {
        self.bootstrap_instance
    }

    pub fn object(&self, index: usize) -> Result<Object<'a>, DecodeError> {
        if index >= self.object_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.object_offset + index * OBJECT_LEN;
        reserved_zero(self.bytes, offset + 56, offset + OBJECT_LEN)?;
        let payload_offset = u64_at(self.bytes, offset + 8)? as usize;
        let payload_len = u64_at(self.bytes, offset + 16)? as usize;
        if payload_len > MAX_OBJECT_PAYLOAD_BYTES {
            return Err(DecodeError::BadBounds);
        }
        let end = payload_offset
            .checked_add(payload_len)
            .ok_or(DecodeError::BadBounds)?;
        Ok(Object {
            id: self.string(u32_at(self.bytes, offset)? as usize)?,
            kind: u32_at(self.bytes, offset + 4)?,
            digest: self.bytes[offset + 24..offset + 56].try_into().unwrap(),
            bytes: self
                .bytes
                .get(payload_offset..end)
                .ok_or(DecodeError::BadBounds)?,
        })
    }

    pub fn executable(&self, index: usize) -> Result<Executable<'a>, DecodeError> {
        if index >= self.executable_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.executable_offset + index * EXECUTABLE_LEN;
        reserved_zero(self.bytes, offset + 16, offset + EXECUTABLE_LEN)?;
        Ok(Executable {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            object: u32_at(self.bytes, offset + 4)? as usize,
            role: u32_at(self.bytes, offset + 8)?,
            spawn_budget: u32_at(self.bytes, offset + 12)?
                .try_into()
                .map_err(|_| DecodeError::BadBounds)?,
        })
    }

    pub fn executable_named(&self, name: &str) -> Option<Executable<'a>> {
        (0..self.executable_count).find_map(|i| self.executable(i).ok().filter(|e| e.name == name))
    }
    pub fn executable_bytes(&self, name: &str) -> Option<&'a [u8]> {
        let executable = self.executable_named(name)?;
        self.object(executable.object)
            .ok()
            .map(|object| object.bytes)
    }

    pub fn instance(&self, index: usize) -> Result<Instance<'a>, DecodeError> {
        if index >= self.instance_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.instance_offset + index * INSTANCE_LEN;
        reserved_zero(self.bytes, offset + 40, offset + INSTANCE_LEN)?;
        let owner = match u32_at(self.bytes, offset + 8)? {
            0 => {
                if u32_at(self.bytes, offset + 12)? != 0 {
                    return Err(DecodeError::BadOwner);
                }
                InstanceOwner::Root
            }
            1 => InstanceOwner::Instance(u32_at(self.bytes, offset + 12)? as usize),
            _ => return Err(DecodeError::UnknownEnum),
        };
        Ok(Instance {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            executable: u32_at(self.bytes, offset + 4)? as usize,
            owner,
            autostart: bool_at(self.bytes, offset + 16)?,
            dependency_start: u32_at(self.bytes, offset + 20)? as usize,
            dependency_count: u32_at(self.bytes, offset + 24)? as usize,
            binding_start: u32_at(self.bytes, offset + 28)? as usize,
            binding_count: u32_at(self.bytes, offset + 32)? as usize,
            health: match u32_at(self.bytes, offset + 36)? {
                0 => InstanceHealth::Optional,
                1 => InstanceHealth::Required,
                _ => return Err(DecodeError::UnknownEnum),
            },
        })
    }
    pub fn instance_named(&self, name: &str) -> Option<Instance<'a>> {
        (0..self.instance_count).find_map(|i| self.instance(i).ok().filter(|v| v.name == name))
    }
    pub fn dependency(
        &self,
        instance: Instance<'a>,
        index: usize,
    ) -> Result<Instance<'a>, DecodeError> {
        if index >= instance.dependency_count {
            return Err(DecodeError::BadIndex);
        }
        let absolute = instance
            .dependency_start
            .checked_add(index)
            .ok_or(DecodeError::BadIndex)?;
        if absolute >= self.dependency_count {
            return Err(DecodeError::BadIndex);
        }
        self.instance(u32_at(
            self.bytes,
            self.dependency_offset + absolute * DEPENDENCY_LEN,
        )? as usize)
    }
    pub fn binding(
        &self,
        instance: Instance<'a>,
        index: usize,
    ) -> Result<InstanceBinding, DecodeError> {
        if index >= instance.binding_count {
            return Err(DecodeError::BadIndex);
        }
        let absolute = instance
            .binding_start
            .checked_add(index)
            .ok_or(DecodeError::BadIndex)?;
        if absolute >= self.binding_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.binding_offset + absolute * BINDING_LEN;
        Ok(InstanceBinding {
            grant: u32_at(self.bytes, offset)? as usize,
            slot: u32_at(self.bytes, offset + 4)? as usize,
        })
    }

    pub const fn component_count(&self) -> usize {
        0
    }

    pub fn grant(&self, index: usize) -> Result<Grant<'a>, DecodeError> {
        if index >= self.grant_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.grant_offset + index * GRANT_LEN;
        let rights = u64_at(self.bytes, offset + 12)?;
        let flags = u32_at(self.bytes, offset + 24)?;
        if flags & !GRANT_FLAGS_KNOWN != 0 {
            return Err(DecodeError::UnknownRequiredFlags);
        }
        let capability_kind = CapabilityKind::decode(u32_at(self.bytes, offset + 28)?)?;
        Ok(Grant {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            source: GrantEndpoint::Instance(u32_at(self.bytes, offset + 4)? as usize),
            target: if capability_kind == CapabilityKind::Executable {
                GrantEndpoint::Executable(u32_at(self.bytes, offset + 8)? as usize)
            } else {
                GrantEndpoint::Instance(u32_at(self.bytes, offset + 8)? as usize)
            },
            rights,
            transferable: bool_at(self.bytes, offset + 20)?,
            capability_kind,
        })
    }
    pub fn grant_named(&self, name: &str) -> Option<Grant<'a>> {
        (0..self.grant_count).find_map(|i| self.grant(i).ok().filter(|g| g.name == name))
    }
    pub fn authority_manifest_identity(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"slime-authority-manifest-v1");
        for index in 0..self.grant_count {
            let grant = self.grant(index).expect("validated grant");
            update_bounded_string(&mut hasher, grant.name);
            let endpoint_name = |endpoint| match endpoint {
                GrantEndpoint::Executable(i) => {
                    self.executable(i).expect("validated executable").name
                }
                GrantEndpoint::Instance(i) => self.instance(i).expect("validated instance").name,
            };
            update_bounded_string(&mut hasher, endpoint_name(grant.source));
            update_bounded_string(&mut hasher, endpoint_name(grant.target));
            hasher.update(&grant.rights.to_le_bytes());
            hasher.update(&u32::from(grant.transferable).to_le_bytes());
        }
        hasher.finalize()
    }

    pub fn state(&self, index: usize) -> Result<StateBinding<'a>, DecodeError> {
        if index >= self.state_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.state_offset + index * STATE_LEN;
        reserved_zero(self.bytes, offset + 16, offset + STATE_LEN)?;
        Ok(StateBinding {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            owner: u32_at(self.bytes, offset + 4)? as usize,
            schema_version: u32_at(self.bytes, offset + 8)?,
            policy: u32_at(self.bytes, offset + 12)?,
        })
    }
    pub fn health_instance(&self, index: usize) -> Result<Instance<'a>, DecodeError> {
        if index >= self.health_count {
            return Err(DecodeError::BadIndex);
        }
        self.instance(u32_at(self.bytes, self.health_offset + index * HEALTH_LEN)? as usize)
    }

    pub fn process(&self, index: usize) -> Result<Process<'a>, DecodeError> {
        if index >= self.process_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.process_offset + index * PROCESS_LEN;
        reserved_zero(self.bytes, offset + 28, offset + PROCESS_LEN)?;
        Ok(Process {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            instance: u32_at(self.bytes, offset + 4)? as usize,
            cspace_object: u32_at(self.bytes, offset + 8)? as usize,
            vspace_object: u32_at(self.bytes, offset + 12)? as usize,
            main_thread: u32_at(self.bytes, offset + 16)? as usize,
            quota: u32_at(self.bytes, offset + 20)? as usize,
            flags: u32_at(self.bytes, offset + 24)?,
        })
    }
    pub fn thread(&self, index: usize) -> Result<Thread<'a>, DecodeError> {
        if index >= self.thread_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.thread_offset + index * THREAD_LEN;
        reserved_zero(self.bytes, offset + 44, offset + THREAD_LEN)?;
        Ok(Thread {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            process: u32_at(self.bytes, offset + 4)? as usize,
            tcb_object: u32_at(self.bytes, offset + 8)? as usize,
            schedule: u32_at(self.bytes, offset + 12)? as usize,
            fault_policy: u32_at(self.bytes, offset + 16)? as usize,
            ipc_buffer_object: u32_at(self.bytes, offset + 20)? as usize,
            ipc_buffer_vaddr: u64_at(self.bytes, offset + 24)?,
            entry: u64_at(self.bytes, offset + 32)?,
            flags: u32_at(self.bytes, offset + 40)?,
        })
    }
    pub fn kernel_object_record(&self, index: usize) -> Result<KernelObject<'a>, DecodeError> {
        if index >= self.kernel_object_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.kernel_object_offset + index * KERNEL_OBJECT_LEN;
        reserved_zero(self.bytes, offset + 28, offset + KERNEL_OBJECT_LEN)?;
        Ok(KernelObject {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            kind: u32_at(self.bytes, offset + 4)?,
            owner_process: u32_at(self.bytes, offset + 8)? as usize,
            size_bits: u32_at(self.bytes, offset + 12)?,
            count: u32_at(self.bytes, offset + 16)?,
            source_object: u32_at(self.bytes, offset + 20)? as usize,
            flags: u32_at(self.bytes, offset + 24)?,
        })
    }

    /// CNode size in bits for the process owning `instance`, from the admitted
    /// plan. This is the authority the generation declared the child's CSpace
    /// must hold, so the root sizes the real CNode from it rather than from a
    /// compiled-in constant.
    ///
    /// `None` when no process claims the instance, which is the fixture paths:
    /// they construct tasks outside the plan and keep the minimum shell.
    pub fn instance_cspace_size_bits(&self, instance: usize) -> Result<Option<u32>, DecodeError> {
        for index in 0..self.process_count {
            let process = self.process(index)?;
            if process.instance != instance {
                continue;
            }
            let object = self.kernel_object_record(process.cspace_object)?;
            if object.kind != KERNEL_OBJECT_CNODE {
                return Err(DecodeError::BadBinding);
            }
            return Ok(Some(object.size_bits));
        }
        Ok(None)
    }

    /// The scheduling priority the plan declares for an instance's initial
    /// thread.
    ///
    /// `None` when no process claims the instance, which is the fixture paths:
    /// they construct tasks outside the plan and take the root's default.
    ///
    /// Resolved through the plan rather than read off the instance, because
    /// priority is a property of a *thread*: the record is already per-thread
    /// so that a process with several can differentiate them, and reading it
    /// from the instance would flatten that the first time one does.
    pub fn instance_priority(&self, instance: usize) -> Result<Option<u32>, DecodeError> {
        for index in 0..self.process_count {
            let process = self.process(index)?;
            if process.instance != instance {
                continue;
            }
            // The process's *main* thread, not whichever thread happens to
            // appear first in the table. They were the same while a process
            // had exactly one thread; with B47's extra threads, scanning the
            // thread table would return a priority belonging to some other
            // thread of the same process, depending on record order.
            let thread = self.thread(process.main_thread)?;
            return Ok(Some(self.schedule(thread.schedule)?.priority));
        }
        Ok(None)
    }

    /// The priority the plan declares for thread `thread_index` of
    /// `instance`, counting from zero for the main thread (B48).
    ///
    /// Per thread, not per instance: the `ScheduleRecord` is already
    /// per-thread, so a process can run its worker below its main thread —
    /// which is what lets one component hold a busy low-priority thread while
    /// its own IPC stays responsive.
    ///
    /// `None` when no process claims the instance or it declares no such
    /// thread.
    pub fn thread_priority(
        &self,
        instance: usize,
        thread_index: usize,
    ) -> Result<Option<u32>, DecodeError> {
        for index in 0..self.process_count {
            let process = self.process(index)?;
            if process.instance != instance {
                continue;
            }
            // The main thread is whichever the process names; the rest follow
            // in table order, which is the order the builder emits them and
            // the order the root constructs them.
            if thread_index == 0 {
                let thread = self.thread(process.main_thread)?;
                return Ok(Some(self.schedule(thread.schedule)?.priority));
            }
            let mut seen = 0;
            for candidate in 0..self.thread_count {
                let thread = self.thread(candidate)?;
                if thread.process != index || candidate == process.main_thread {
                    continue;
                }
                seen += 1;
                if seen == thread_index {
                    return Ok(Some(self.schedule(thread.schedule)?.priority));
                }
            }
            return Ok(None);
        }
        Ok(None)
    }

    /// How many threads the plan declares for `instance` (B47).
    ///
    /// Counted from the thread table rather than read from a field, because
    /// the thread records are what the root must construct: a count that
    /// disagreed with them would build a TCB with no schedule or leave a
    /// declared thread unbuilt.
    ///
    /// `None` when no process claims the instance.
    pub fn instance_threads(&self, instance: usize) -> Result<Option<usize>, DecodeError> {
        let mut found = None;
        for index in 0..self.process_count {
            let process = self.process(index)?;
            if process.instance != instance {
                continue;
            }
            let mut threads = 0;
            for thread_index in 0..self.thread_count {
                if self.thread(thread_index)?.process == index {
                    threads += 1;
                }
            }
            found = Some(threads);
            break;
        }
        Ok(found)
    }

    /// The CSpace slots the plan declares for a child's own TCB and fault
    /// endpoint. Classified by the bound object's kind rather than its name,
    /// so a renamed object still resolves.
    ///
    /// `None` when no process claims the instance.
    pub fn instance_child_slots(
        &self,
        instance: usize,
    ) -> Result<Option<ChildSlotPlan>, DecodeError> {
        let mut found = None;
        for index in 0..self.process_count {
            if self.process(index)?.instance == instance {
                found = Some(index);
                break;
            }
        }
        let Some(process_index) = found else {
            return Ok(None);
        };
        let (mut tcb, mut fault) = (None, None);
        for index in 0..self.cap_binding_count {
            let binding = self.cap_binding(index)?;
            if binding.process != process_index {
                continue;
            }
            // Only the process's own bindings name a slot the root installs.
            // A grant-derived binding carries its grant index and is filled by
            // whoever holds the authority, against a placeholder object whose
            // kind says nothing about what lands there.
            if binding.grant != PLAN_NONE {
                continue;
            }
            let object = self.kernel_object_record(binding.object)?;
            let target = match object.kind {
                KERNEL_OBJECT_TCB => &mut tcb,
                KERNEL_OBJECT_ENDPOINT => &mut fault,
                _ => continue,
            };
            // Two bindings of one kind would leave the installed slot
            // ambiguous, so the plan is refused rather than guessed at.
            if target.is_some() {
                return Err(DecodeError::BadBinding);
            }
            *target = Some(binding.slot);
        }
        // The root service endpoint is declared as a service binding rather
        // than a cap binding, because it is the child's route to the root
        // rather than an object the child owns.
        let mut service = None;
        for index in 0..self.service_binding_count {
            let binding = self.service_binding(index)?;
            if binding.process != process_index || binding.service != SERVICE_LIFECYCLE {
                continue;
            }
            if service.is_some() {
                return Err(DecodeError::BadBinding);
            }
            service = Some(binding.slot);
        }
        let mut console = None;
        for index in 0..self.service_binding_count {
            let binding = self.service_binding(index)?;
            if binding.process != process_index || binding.service != SERVICE_CONSOLE {
                continue;
            }
            if console.is_some() {
                return Err(DecodeError::BadBinding);
            }
            // Write-only, enforced here as well as in the host twin: a console
            // client that could receive would dequeue another process's output
            // before the console dispatcher saw it.
            if binding.rights & 0b10 != 0 {
                return Err(DecodeError::BadBinding);
            }
            console = Some(binding.slot);
        }
        Ok(Some(ChildSlotPlan {
            service,
            console,
            tcb,
            fault,
        }))
    }
    pub fn mapping(&self, index: usize) -> Result<Mapping, DecodeError> {
        if index >= self.mapping_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.mapping_offset + index * MAPPING_LEN;
        reserved_zero(self.bytes, offset + 44, offset + MAPPING_LEN)?;
        Ok(Mapping {
            process: u32_at(self.bytes, offset)? as usize,
            object: u32_at(self.bytes, offset + 4)? as usize,
            virtual_address: u64_at(self.bytes, offset + 8)?,
            page_count: u32_at(self.bytes, offset + 16)?,
            rights: u64_at(self.bytes, offset + 20)?,
            attributes: u64_at(self.bytes, offset + 28)?,
            source_object: u32_at(self.bytes, offset + 36)? as usize,
            flags: u32_at(self.bytes, offset + 40)?,
        })
    }
    pub fn cap_binding(&self, index: usize) -> Result<CapBinding, DecodeError> {
        if index >= self.cap_binding_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.cap_binding_offset + index * CAP_BINDING_LEN;
        reserved_zero(self.bytes, offset + 36, offset + CAP_BINDING_LEN)?;
        Ok(CapBinding {
            process: u32_at(self.bytes, offset)? as usize,
            slot: u32_at(self.bytes, offset + 4)? as usize,
            object: u32_at(self.bytes, offset + 8)? as usize,
            rights: u64_at(self.bytes, offset + 12)?,
            badge: u64_at(self.bytes, offset + 20)?,
            grant: u32_at(self.bytes, offset + 28)? as usize,
            flags: u32_at(self.bytes, offset + 32)?,
        })
    }
    /// Whether `instance` is authorized to invoke one typed root mechanism.
    ///
    /// Service bindings that share child slot 1 are declarations, not extra
    /// CSpace installs. The root uses this lookup after resolving the caller's
    /// badged task, so holding lifecycle transport never grants another
    /// mechanism implicitly.
    pub fn instance_has_service(&self, instance: usize, service: u32) -> Result<bool, DecodeError> {
        let mut process_index = None;
        for index in 0..self.process_count {
            if self.process(index)?.instance == instance {
                if process_index.is_some() {
                    return Err(DecodeError::BadBinding);
                }
                process_index = Some(index);
            }
        }
        let Some(process_index) = process_index else {
            return Ok(false);
        };
        for index in 0..self.service_binding_count {
            let binding = self.service_binding(index)?;
            if binding.process == process_index && binding.service == service {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn service_binding(&self, index: usize) -> Result<ServiceBinding, DecodeError> {
        if index >= self.service_binding_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.service_binding_offset + index * SERVICE_BINDING_LEN;
        reserved_zero(self.bytes, offset + 36, offset + SERVICE_BINDING_LEN)?;
        Ok(ServiceBinding {
            process: u32_at(self.bytes, offset)? as usize,
            service: u32_at(self.bytes, offset + 4)?,
            slot: u32_at(self.bytes, offset + 8)? as usize,
            object: u32_at(self.bytes, offset + 12)? as usize,
            rights: u64_at(self.bytes, offset + 16)?,
            badge: u64_at(self.bytes, offset + 24)?,
            flags: u32_at(self.bytes, offset + 32)?,
        })
    }
    pub fn schedule(&self, index: usize) -> Result<Schedule<'a>, DecodeError> {
        if index >= self.schedule_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.schedule_offset + index * SCHEDULE_LEN;
        reserved_zero(self.bytes, offset + 40, offset + SCHEDULE_LEN)?;
        Ok(Schedule {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            thread: u32_at(self.bytes, offset + 4)? as usize,
            authority_process: u32_at(self.bytes, offset + 8)? as usize,
            priority: u32_at(self.bytes, offset + 12)?,
            max_controlled_priority: u32_at(self.bytes, offset + 16)?,
            budget_us: u64_at(self.bytes, offset + 20)?,
            period_us: u64_at(self.bytes, offset + 28)?,
            flags: u32_at(self.bytes, offset + 36)?,
        })
    }
    pub fn fault_policy(&self, index: usize) -> Result<FaultPolicy<'a>, DecodeError> {
        if index >= self.fault_policy_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.fault_policy_offset + index * FAULT_POLICY_LEN;
        reserved_zero(self.bytes, offset + 28, offset + FAULT_POLICY_LEN)?;
        Ok(FaultPolicy {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            thread: u32_at(self.bytes, offset + 4)? as usize,
            handler_process: u32_at(self.bytes, offset + 8)? as usize,
            endpoint_object: u32_at(self.bytes, offset + 12)? as usize,
            badge: u64_at(self.bytes, offset + 16)?,
            action: u32_at(self.bytes, offset + 24)?,
        })
    }
    pub fn spawn_template(&self, index: usize) -> Result<SpawnTemplate<'a>, DecodeError> {
        if index >= self.spawn_template_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.spawn_template_offset + index * SPAWN_TEMPLATE_LEN;
        Ok(SpawnTemplate {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            executable: u32_at(self.bytes, offset + 4)? as usize,
            owner_process: u32_at(self.bytes, offset + 8)? as usize,
            quota: u32_at(self.bytes, offset + 12)? as usize,
            schedule: u32_at(self.bytes, offset + 16)? as usize,
            fault_policy: u32_at(self.bytes, offset + 20)? as usize,
            max_instances: u32_at(self.bytes, offset + 24)?,
            flags: u32_at(self.bytes, offset + 28)?,
        })
    }
    pub fn resource_quota(&self, index: usize) -> Result<ResourceQuota<'a>, DecodeError> {
        if index >= self.resource_quota_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.resource_quota_offset + index * RESOURCE_QUOTA_LEN;
        Ok(ResourceQuota {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            owner_process: u32_at(self.bytes, offset + 4)? as usize,
            cnode_count: u32_at(self.bytes, offset + 8)?,
            tcb_count: u32_at(self.bytes, offset + 12)?,
            endpoint_count: u32_at(self.bytes, offset + 16)?,
            notification_count: u32_at(self.bytes, offset + 20)?,
            frame_count: u32_at(self.bytes, offset + 24)?,
            page_table_count: u32_at(self.bytes, offset + 28)?,
            mapping_count: u32_at(self.bytes, offset + 32)?,
            irq_count: u32_at(self.bytes, offset + 36)?,
            cslot_count: u32_at(self.bytes, offset + 40)?,
            untyped_bytes: u64_at(self.bytes, offset + 44)?,
            dynamic_reserve_bytes: u64_at(self.bytes, offset + 52)?,
            flags: u32_at(self.bytes, offset + 60)?,
        })
    }
    /// One capability the generation authorizes `holder` to receive at spawn,
    /// minted at runtime by `owner`. The edge is named and the rights ceiling
    /// exact; only the object identity is deferred, because the endpoint does
    /// not exist until its owner mints it.
    pub fn minted_binding(&self, index: usize) -> Result<MintedBinding<'a>, DecodeError> {
        if index >= self.minted_binding_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.minted_binding_offset + index * MINTED_BINDING_LEN;
        Ok(MintedBinding {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            owner: u32_at(self.bytes, offset + 4)? as usize,
            holder: u32_at(self.bytes, offset + 8)? as usize,
            slot: u32_at(self.bytes, offset + 12)? as usize,
            rights: u64_at(self.bytes, offset + 16)?,
            flags: u32_at(self.bytes, offset + 24)?,
            capability_kind: CapabilityKind::decode(u32_at(self.bytes, offset + 28)?)?,
        })
    }

    /// The minted binding authorizing `holder` to receive a capability at
    pub fn minted_binding_for(&self, holder: usize, slot: usize) -> Option<MintedBinding<'a>> {
        (0..self.minted_binding_count).find_map(|index| {
            self.minted_binding(index)
                .ok()
                .filter(|binding| binding.holder == holder && binding.slot == slot)
        })
    }

    pub const fn minted_binding_count(&self) -> usize {
        self.minted_binding_count
    }
    pub fn notification_grant(&self, index: usize) -> Result<NotificationGrant<'a>, DecodeError> {
        if index >= self.notification_grant_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.notification_grant_offset + index * NOTIFICATION_GRANT_LEN;
        reserved_zero(self.bytes, offset + 20, offset + NOTIFICATION_GRANT_LEN)?;
        Ok(NotificationGrant {
            name: self.string(u32_at(self.bytes, offset)? as usize)?,
            source: u32_at(self.bytes, offset + 4)? as usize,
            target: u32_at(self.bytes, offset + 8)? as usize,
            object: u32_at(self.bytes, offset + 12)? as usize,
            flags: u32_at(self.bytes, offset + 16)?,
        })
    }

    pub fn notification_binding(&self, index: usize) -> Result<NotificationBinding, DecodeError> {
        if index >= self.notification_binding_count {
            return Err(DecodeError::BadIndex);
        }
        let offset = self.notification_binding_offset + index * NOTIFICATION_BINDING_LEN;
        reserved_zero(self.bytes, offset + 20, offset + NOTIFICATION_BINDING_LEN)?;
        Ok(NotificationBinding {
            grant: u32_at(self.bytes, offset)? as usize,
            holder: u32_at(self.bytes, offset + 4)? as usize,
            slot: u32_at(self.bytes, offset + 8)? as usize,
            role: match u32_at(self.bytes, offset + 12)? {
                1 => NotificationRole::Signal,
                2 => NotificationRole::Wait,
                _ => return Err(DecodeError::UnknownEnum),
            },
            flags: u32_at(self.bytes, offset + 16)?,
        })
    }

    fn string(&self, offset: usize) -> Result<&'a str, DecodeError> {
        read_string(self.bytes, self.string_offset, self.string_len, offset)
    }

    fn validate(&self, payload_offset: usize) -> Result<(), DecodeError> {
        let mut previous_id = None;
        let mut previous_payload_end = payload_offset;
        for index in 0..self.object_count {
            let object = self.object(index)?;
            if !matches!(
                object.kind,
                KIND_KERNEL | KIND_BOOTSTRAP | KIND_COMPONENT | KIND_RESOURCE
            ) {
                return Err(DecodeError::UnknownEnum);
            }
            if previous_id.is_some_and(|previous| previous >= object.id) {
                return Err(DecodeError::BadOrder);
            }
            let start = u64_at(self.bytes, self.object_offset + index * OBJECT_LEN + 8)? as usize;
            if start != previous_payload_end {
                return Err(DecodeError::BadBounds);
            }
            previous_payload_end = start
                .checked_add(object.bytes.len())
                .ok_or(DecodeError::BadBounds)?;
            let mut hasher = Sha256::new();
            hasher.update(object.bytes);
            if hasher.finalize() != object.digest {
                return Err(DecodeError::BadObjectHash);
            }
            previous_id = Some(object.id);
        }
        if previous_payload_end != self.bytes.len() {
            return Err(DecodeError::BadBounds);
        }
        if self.boot_attempts == 0 {
            return Err(DecodeError::BadHealth);
        }
        self.validate_catalogue()?;
        self.validate_plan()
    }

    fn validate_catalogue(&self) -> Result<(), DecodeError> {
        let mut previous_name = None;
        for index in 0..self.executable_count {
            let executable = self.executable(index)?;
            if executable.object >= self.object_count
                || !matches!(executable.role, 1..=4)
                || executable.spawn_budget > MAX_SPAWN_BUDGET
            {
                return Err(DecodeError::BadIndex);
            }
            if previous_name.is_some_and(|previous| previous >= executable.name) {
                return Err(DecodeError::BadOrder);
            }
            previous_name = Some(executable.name);
        }
        previous_name = None;
        let mut expected_dependency_start = 0;
        let mut expected_binding_start = 0;
        for index in 0..self.instance_count {
            let instance = self.instance(index)?;
            if instance.executable >= self.executable_count {
                return Err(DecodeError::BadIndex);
            }
            if previous_name.is_some_and(|previous| previous >= instance.name) {
                return Err(DecodeError::BadOrder);
            }
            if matches!(instance.owner, InstanceOwner::Instance(owner) if owner >= self.instance_count || owner == index)
            {
                return Err(DecodeError::BadOwner);
            }
            if instance.dependency_start != expected_dependency_start
                || instance.binding_start != expected_binding_start
                || instance
                    .dependency_start
                    .checked_add(instance.dependency_count)
                    .is_none_or(|end| end > self.dependency_count)
                || instance
                    .binding_start
                    .checked_add(instance.binding_count)
                    .is_none_or(|end| end > self.binding_count)
            {
                return Err(DecodeError::BadBounds);
            }
            expected_dependency_start += instance.dependency_count;
            expected_binding_start += instance.binding_count;
            if instance.health == InstanceHealth::Required
                && matches!(instance.owner, InstanceOwner::Instance(owner) if self.instance(owner)?.health != InstanceHealth::Required)
            {
                return Err(DecodeError::BadHealth);
            }
            let mut previous_dependency = None;
            for at in 0..instance.dependency_count {
                let dependency = self.dependency(instance, at)?;
                let dependency_index = self
                    .instance_index(dependency.name)
                    .ok_or(DecodeError::BadDependency)?;
                if dependency_index == index
                    || previous_dependency.is_some_and(|previous| previous >= dependency_index)
                {
                    return Err(DecodeError::BadDependency);
                }
                if instance.is_root_autostart() && !dependency.is_root_autostart() {
                    return Err(DecodeError::BadDependency);
                }
                if instance.health == InstanceHealth::Required
                    && dependency.health != InstanceHealth::Required
                {
                    return Err(DecodeError::BadHealth);
                }
                previous_dependency = Some(dependency_index);
            }
            let mut previous_slot = None;
            for at in 0..instance.binding_count {
                let binding = self.binding(instance, at)?;
                if binding.grant >= self.grant_count
                    || binding.slot >= MAX_TASK_CAPS
                    || previous_slot.is_some_and(|previous| previous >= binding.slot)
                {
                    return Err(DecodeError::BadBinding);
                }
                if !self.grant_applies_to_instance(self.grant(binding.grant)?, index) {
                    return Err(DecodeError::BadBinding);
                }
                previous_slot = Some(binding.slot);
            }
            for grant_index in 0..self.grant_count {
                if self.grant_requires_instance_binding(self.grant(grant_index)?, index) {
                    let mut found = 0;
                    for at in 0..instance.binding_count {
                        found += usize::from(self.binding(instance, at)?.grant == grant_index);
                    }
                    if found != 1 {
                        return Err(DecodeError::BadBinding);
                    }
                }
            }
            previous_name = Some(instance.name);
        }
        validate_acyclic(
            self.instance_count,
            |node, edge| {
                let instance = self.instance(node)?;
                if edge >= instance.dependency_count {
                    return Ok(None);
                }
                let dependency = self.dependency(instance, edge)?;
                self.instance_index(dependency.name)
                    .map(Some)
                    .ok_or(DecodeError::BadDependency)
            },
            DecodeError::BadDependency,
        )?;
        validate_acyclic(
            self.instance_count,
            |node, edge| {
                if edge != 0 {
                    return Ok(None);
                }
                Ok(match self.instance(node)?.owner {
                    InstanceOwner::Root => None,
                    InstanceOwner::Instance(owner) => Some(owner),
                })
            },
            DecodeError::BadOwner,
        )?;
        for index in 0..self.instance_count {
            let instance = self.instance(index)?;
            if instance.autostart
                && let InstanceOwner::Instance(owner) = instance.owner
                && !self.instance(owner)?.autostart
            {
                return Err(DecodeError::BadOwner);
            }
        }
        if expected_dependency_start != self.dependency_count
            || expected_binding_start != self.binding_count
        {
            return Err(DecodeError::BadBounds);
        }
        if self.bootstrap_instance >= self.instance_count {
            return Err(DecodeError::BadBootstrap);
        }
        let bootstrap = self.instance(self.bootstrap_instance)?;
        let executable = self.executable(bootstrap.executable)?;
        if !bootstrap.is_root_autostart()
            || executable.role != ROLE_INIT
            || self.object(executable.object)?.kind != KIND_BOOTSTRAP
        {
            return Err(DecodeError::BadBootstrap);
        }
        self.validate_grants_states_health()
    }

    fn validate_grants_states_health(&self) -> Result<(), DecodeError> {
        let mut previous_grant = None;
        for index in 0..self.grant_count {
            let grant = self.grant(index)?;
            let valid_endpoint = |endpoint| match endpoint {
                GrantEndpoint::Executable(i) => i < self.executable_count,
                GrantEndpoint::Instance(i) => i < self.instance_count,
            };
            if !valid_endpoint(grant.source)
                || !valid_endpoint(grant.target)
                || !matches!(grant.source, GrantEndpoint::Instance(_))
                || grant.rights == 0
                || grant.rights & !RIGHT_ALL != 0
                || (grant.rights & RIGHT_TRANSFER != 0) != grant.transferable
                || !capability_rights_valid(grant.capability_kind, grant.rights)
            {
                return Err(DecodeError::BadIndex);
            }
            let key = (
                grant.name,
                endpoint_key(grant.source),
                endpoint_key(grant.target),
            );
            if previous_grant.is_some_and(|previous| previous >= key) {
                return Err(DecodeError::BadOrder);
            }
            previous_grant = Some(key);
        }
        let mut previous_state = None;
        for index in 0..self.state_count {
            let state = self.state(index)?;
            if state.owner >= self.instance_count
                || state.schema_version == 0
                || !matches!(
                    state.policy,
                    POLICY_IMMUTABLE
                        | POLICY_EPHEMERAL
                        | POLICY_PRESERVE
                        | POLICY_SNAPSHOT_BEFORE_UPGRADE
                        | POLICY_DISCARD_ON_ROLLBACK
                )
            {
                return Err(DecodeError::BadState);
            }
            if previous_state.is_some_and(|previous| previous >= state.name) {
                return Err(DecodeError::BadOrder);
            }
            previous_state = Some(state.name);
        }
        let mut previous_health = None;
        let mut required = 0;
        for index in 0..self.instance_count {
            required += usize::from(self.instance(index)?.health == InstanceHealth::Required);
        }
        if required != self.health_count {
            return Err(DecodeError::BadHealth);
        }
        for index in 0..self.health_count {
            let instance = self.health_instance(index)?;
            let instance_index = self
                .instance_index(instance.name)
                .ok_or(DecodeError::BadHealth)?;
            if instance.health != InstanceHealth::Required
                || previous_health.is_some_and(|previous| previous >= instance_index)
            {
                return Err(DecodeError::BadHealth);
            }
            previous_health = Some(instance_index);
        }
        Ok(())
    }

    fn validate_plan(&self) -> Result<(), DecodeError> {
        // A quota is per *process*; a schedule and a fault policy are per
        // *thread*. Those were the same count while every process had exactly
        // one thread, and requiring them equal is what made the v5 split
        // exist in the format and nowhere else (B47).
        //
        // Threads are still bounded: every process must have at least one, no
        // thread may name a process that does not exist, and each schedule and
        // fault policy is reached through the thread that names it — checked
        // per record below.
        if self.process_count > self.thread_count
            || self.thread_count != self.schedule_count
            || self.thread_count != self.fault_policy_count
            || self.process_count != self.resource_quota_count
        {
            return Err(DecodeError::BadBounds);
        }
        let mut seen_instances = [false; MAX_INSTANCES];
        for index in 0..self.process_count {
            let process = self.process(index)?;
            if process.instance >= self.instance_count
                || process.cspace_object >= self.kernel_object_count
                || process.vspace_object >= self.kernel_object_count
                || process.main_thread >= self.thread_count
                || process.quota >= self.resource_quota_count
                || process.flags != 0
                || seen_instances[process.instance]
            {
                return Err(DecodeError::BadIndex);
            }
            let instance = self.instance(process.instance)?;
            if process.name != instance.name {
                return Err(DecodeError::BadIndex);
            }
            seen_instances[process.instance] = true;
            if self.kernel_object_record(process.cspace_object)?.kind != 1
                || self.kernel_object_record(process.vspace_object)?.kind != 2
            {
                return Err(DecodeError::BadKernel);
            }
        }
        if seen_instances
            .iter()
            .take(self.instance_count)
            .any(|seen| !*seen)
        {
            return Err(DecodeError::BadIndex);
        }
        for index in 0..self.thread_count {
            let thread = self.thread(index)?;
            if thread.process >= self.process_count
                || thread.tcb_object >= self.kernel_object_count
                || thread.schedule >= self.schedule_count
                || thread.fault_policy >= self.fault_policy_count
                || thread.ipc_buffer_object >= self.kernel_object_count
                || thread.flags != 0
            {
                return Err(DecodeError::BadIndex);
            }
            // Its objects are the right kinds, and it belongs to a process
            // that agrees it exists. The check used to be
            // `main_thread != index`, which required *every* thread to be its
            // process's main one — the same one-thread-per-process assumption
            // `validate_plan`'s count equality carried (B47).
            if self.kernel_object_record(thread.tcb_object)?.kind != 3
                || self.kernel_object_record(thread.ipc_buffer_object)?.kind != 4
                || self.kernel_object_record(thread.tcb_object)?.owner_process != thread.process
            {
                return Err(DecodeError::BadKernel);
            }
        }
        // Every process's declared main thread is a real thread of that
        // process. Checked here rather than in the loop above, which walks
        // threads and so cannot see a process whose `main_thread` names one
        // belonging to someone else.
        for index in 0..self.process_count {
            let main = self.process(index)?.main_thread;
            if main >= self.thread_count || self.thread(main)?.process != index {
                return Err(DecodeError::BadKernel);
            }
        }
        for index in 0..self.kernel_object_count {
            let object = self.kernel_object_record(index)?;
            if object.owner_process >= self.process_count
                || !matches!(object.kind, 1..=KERNEL_OBJECT_NOTIFICATION)
                || object.count == 0
                || object.flags != 0
                || (object.source_object != PLAN_NONE && object.source_object >= self.object_count)
            {
                return Err(DecodeError::BadKernel);
            }
        }
        for index in 0..self.mapping_count {
            let mapping = self.mapping(index)?;
            if mapping.process >= self.process_count
                || mapping.object >= self.kernel_object_count
                || mapping.page_count == 0
                || mapping.rights == 0
                || mapping.rights & !RIGHT_ALL != 0
                || mapping.flags != 0
                || (mapping.source_object != PLAN_NONE
                    && mapping.source_object >= self.object_count)
            {
                return Err(DecodeError::BadIndex);
            }
        }
        let mut materialized = [0u8; MAX_GRANTS];
        for index in 0..self.cap_binding_count {
            let binding = self.cap_binding(index)?;
            if binding.process >= self.process_count
                || binding.slot >= MAX_TASK_CAPS
                || binding.object >= self.kernel_object_count
                || binding.rights == 0
                || binding.flags & !GRANT_POLICY_ONLY != 0
                || (binding.grant != PLAN_NONE && binding.grant >= self.grant_count)
            {
                return Err(DecodeError::BadBinding);
            }
            if binding.grant != PLAN_NONE {
                if binding.flags & GRANT_POLICY_ONLY == 0 {
                    materialized[binding.grant] = materialized[binding.grant].saturating_add(1);
                }
                let grant = self.grant(binding.grant)?;
                if binding.rights != grant.rights {
                    return Err(DecodeError::BadBinding);
                }
            }
        }
        for (index, count) in materialized.iter().enumerate().take(self.grant_count) {
            let grant = self.grant(index)?;
            // Every declared grant names a concrete object the plan carries a
            // capability for. A `minted` grant used to be the exception —
            // object identity deferred to a runtime minter — which the native
            // cutover made impossible for the only kind that used it (B50).
            let policy_only = (0..self.cap_binding_count).any(|binding| {
                self.cap_binding(binding).is_ok_and(|binding| {
                    binding.grant == index && binding.flags & GRANT_POLICY_ONLY != 0
                })
            });
            if usize::from(*count) + usize::from(policy_only) != 1 {
                return Err(DecodeError::BadBinding);
            }
            if policy_only
                && matches!(
                    grant.capability_kind,
                    CapabilityKind::Executable | CapabilityKind::Endpoint
                )
            {
                return Err(DecodeError::BadBinding);
            }
        }
        let mut seen_services = [[false; 12]; MAX_PROCESSES];
        for index in 0..self.service_binding_count {
            let binding = self.service_binding(index)?;
            let object_kind = if binding.object < self.kernel_object_count {
                self.kernel_object_record(binding.object)?.kind
            } else {
                0
            };
            let known = matches!(
                binding.service,
                SERVICE_LIFECYCLE
                    | SERVICE_SPAWN
                    | SERVICE_SUPERVISION
                    | SERVICE_CAPABILITY_TRANSFER
                    | SERVICE_SHARED_BUFFER
                    | SERVICE_DIRECTORY
                    | SERVICE_INPUT
                    | SERVICE_CONSOLE
                    | SERVICE_CLOCK
                    | SERVICE_IO_RESOURCE
            );
            let expected_slot = if binding.service == SERVICE_CONSOLE {
                CONSOLE_SERVICE_SLOT
            } else {
                ROOT_SERVICE_SLOT
            };
            if binding.process >= self.process_count
                || binding.slot != expected_slot
                || object_kind != KERNEL_OBJECT_ENDPOINT
                || binding.rights != SERVICE_SEND_RIGHT
                || binding.badge == 0
                || binding.flags != 0
                || !known
                || (known && seen_services[binding.process][binding.service as usize])
            {
                return Err(DecodeError::BadBinding);
            }
            seen_services[binding.process][binding.service as usize] = true;
        }
        for (process_index, seen) in seen_services.iter().enumerate().take(self.process_count) {
            let process = self.process(process_index)?;
            let instance = self.instance(process.instance)?;
            let executable = self.executable(instance.executable)?;
            let mut required = [false; 12];
            required[SERVICE_LIFECYCLE as usize] = true;
            required[SERVICE_CONSOLE as usize] = true;
            let holder_identity = shared_buffer_budget::holder_identity(instance.name);
            let budgeted_for_shared_buffer = (0..self.object_count).any(|object_index| {
                self.object(object_index).is_ok_and(|object| {
                    object.kind == KIND_RESOURCE
                        && object.bytes.starts_with(&shared_buffer_budget::MAGIC)
                        && SharedBufferBudget::decode(object.bytes)
                            .ok()
                            .and_then(|budget| budget.quota_for(&holder_identity))
                            .is_some()
                })
            });
            if budgeted_for_shared_buffer {
                required[SERVICE_SHARED_BUFFER as usize] = true;
            }
            let clock_holder_identity = clock_authority::holder_identity(instance.name);
            let authorized_for_clock = (0..self.object_count).any(|object_index| {
                self.object(object_index).is_ok_and(|object| {
                    object.kind == KIND_RESOURCE
                        && object.bytes.starts_with(&clock_authority::MAGIC)
                        && ClockAuthority::decode(object.bytes)
                            .ok()
                            .and_then(|authority| authority.authority_for(&clock_holder_identity))
                            .is_some()
                })
            });
            if authorized_for_clock {
                required[SERVICE_CLOCK as usize] = true;
            }
            let parameter_holder = lifecycle_policy::instance_identity(instance.name);
            let authorized_for_parameters = (0..self.object_count).any(|object_index| {
                self.object(object_index).is_ok_and(|object| {
                    object.kind == KIND_RESOURCE
                        && object.bytes.starts_with(&lifecycle_policy::MAGIC)
                        && LifecyclePolicy::decode(object.bytes).is_ok_and(|policy| {
                            (0..policy.parameter_count()).any(|index| {
                                policy.parameter(index).is_some_and(|grant| {
                                    parameter_transport_holder(grant, &parameter_holder)
                                })
                            })
                        })
                })
            });
            if authorized_for_parameters {
                // This declares the transport only; root still enforces the
                // exact parameter holder/subject and read/write authority.
                required[SERVICE_SUPERVISION as usize] = true;
            }
            if executable.role == ROLE_INIT || executable.spawn_budget != 0 {
                // Spawn returns a supervision capability, so declaring spawn
                // also declares the narrow table service needed to drop it.
                required[SERVICE_SPAWN as usize] = true;
                required[SERVICE_SUPERVISION as usize] = true;
                required[SERVICE_CAPABILITY_TRANSFER as usize] = true;
            }
            for binding_index in 0..instance.binding_count() {
                let binding = self.binding(instance, binding_index)?;
                let grant = self.grant(binding.grant)?;
                if let Some(service) = service_for_capability(grant.capability_kind) {
                    required[service as usize] = true;
                }
                if grant.capability_kind == CapabilityKind::Executable {
                    required[SERVICE_SPAWN as usize] = true;
                }
                if grant.capability_kind == CapabilityKind::Endpoint || grant.transferable {
                    required[SERVICE_CAPABILITY_TRANSFER as usize] = true;
                }
            }
            for binding_index in 0..self.minted_binding_count {
                let binding = self.minted_binding(binding_index)?;
                if binding.holder != process.instance {
                    continue;
                }
                if let Some(service) = service_for_capability(binding.capability_kind) {
                    required[service as usize] = true;
                }
                if binding.capability_kind == CapabilityKind::Executable {
                    required[SERVICE_SPAWN as usize] = true;
                }
                if binding.capability_kind == CapabilityKind::Endpoint
                    || binding.rights & RIGHT_TRANSFER != 0
                {
                    required[SERVICE_CAPABILITY_TRANSFER as usize] = true;
                }
            }
            if required != *seen {
                return Err(DecodeError::BadBinding);
            }
        }
        for index in 0..self.schedule_count {
            let schedule = self.schedule(index)?;
            if schedule.thread >= self.thread_count
                || (schedule.authority_process != PLAN_NONE
                    && schedule.authority_process >= self.process_count)
                || schedule.priority > schedule.max_controlled_priority
                || schedule.flags != 0
                || self.thread(schedule.thread)?.schedule != index
            {
                return Err(DecodeError::BadIndex);
            }
            // B77: `budget_us`/`period_us` are authenticated wire fields that no
            // mechanism honours while the kernel is built `KernelIsMCS OFF` --
            // nothing here reads them, and non-MCS seL4 has no budget to charge.
            // Refusing a nonzero value keeps the zero an admitted invariant
            // rather than a builder habit, so a generation from another producer
            // cannot declare a budget that boots and is silently ignored. This
            // is a distinct reason from `BadIndex` on purpose: the record is
            // structurally fine, it just claims authority the platform lacks.
            if schedule.budget_us != 0 || schedule.period_us != 0 {
                return Err(DecodeError::NonZeroReserved);
            }
        }
        for index in 0..self.fault_policy_count {
            let fault = self.fault_policy(index)?;
            if fault.thread >= self.thread_count
                || (fault.handler_process != PLAN_NONE
                    && fault.handler_process >= self.process_count)
                || fault.endpoint_object >= self.kernel_object_count
                || fault.action == 0
                || self.thread(fault.thread)?.fault_policy != index
            {
                return Err(DecodeError::BadIndex);
            }
        }
        for index in 0..self.spawn_template_count {
            let template = self.spawn_template(index)?;
            if template.executable >= self.executable_count
                || template.owner_process >= self.process_count
                || template.quota >= self.resource_quota_count
                || template.schedule >= self.schedule_count
                || template.fault_policy >= self.fault_policy_count
                || template.max_instances == 0
                || template.flags != 0
            {
                return Err(DecodeError::BadIndex);
            }
        }
        for index in 0..self.resource_quota_count {
            let quota = self.resource_quota(index)?;
            if quota.owner_process >= self.process_count
                || self.process(quota.owner_process)?.quota != index
                || quota.cnode_count == 0
                || quota.tcb_count == 0
                || quota.cslot_count == 0
                || quota.flags != 0
            {
                return Err(DecodeError::BadIndex);
            }
        }
        // Minted bindings. Each names a real owner/holder pair, a slot inside
        // the holder's CSpace, and a nonzero rights ceiling within the
        // vocabulary. The holder must be an instance the owner actually owns,
        // so a minted capability cannot cross an ownership edge the graph does
        // not declare, and no two may claim the same holder slot.
        let mut previous_name = None;
        for index in 0..self.minted_binding_count {
            let minted = self.minted_binding(index)?;
            // `exec` is admissible here: an owner may hand a child one of the
            // executables it holds, and the child then spawns instances it
            // owns from it. It still travels with `RIGHT_SPAWN`, exactly as a
            // static exec grant does, so a minted executable cannot be
            // launched by a holder the graph did not authorize to spawn.
            if minted.owner >= self.instance_count
                || minted.holder >= self.instance_count
                || minted.slot >= MAX_TASK_CAPS
                || minted.rights == 0
                || minted.rights & !RIGHT_ALL != 0
                || !capability_rights_valid(minted.capability_kind, minted.rights)
                || minted.flags != 0
            {
                return Err(DecodeError::BadBinding);
            }
            if self.instance(minted.holder)?.owner != InstanceOwner::Instance(minted.owner) {
                return Err(DecodeError::BadOwner);
            }
            if previous_name.is_some_and(|previous| previous >= minted.name) {
                return Err(DecodeError::BadOrder);
            }
            // No two declarations may claim one holder slot — neither two
            // minted bindings, nor a minted binding and one of the holder's
            // own grant-backed bindings. A collision would leave the holder's
            // slot naming two different capabilities, and would make the
            // spawn-time ordering by destination slot ambiguous.
            if (0..index).try_fold(false, |seen, earlier| {
                let other = self.minted_binding(earlier)?;
                Ok::<bool, DecodeError>(
                    seen || (other.holder == minted.holder && other.slot == minted.slot),
                )
            })? {
                return Err(DecodeError::BadBinding);
            }
            let holder = self.instance(minted.holder)?;
            for at in 0..holder.binding_count() {
                if self.binding(holder, at)?.slot == minted.slot {
                    return Err(DecodeError::BadBinding);
                }
            }
            previous_name = Some(minted.name);
        }
        // Native notifications are authenticated as named source-to-target
        // relationships, with exactly one signal binding at the source and
        // one wait binding at the target. The grant section is canonical by
        // name; holder slots are unique within the separate native
        // notification namespace.
        let mut previous_notification = None;
        for index in 0..self.notification_grant_count {
            let grant = self.notification_grant(index)?;
            if grant.source >= self.instance_count
                || grant.target >= self.instance_count
                || grant.source == grant.target
                || grant.object >= self.kernel_object_count
                || self.kernel_object_record(grant.object)?.kind != KERNEL_OBJECT_NOTIFICATION
                || grant.flags != 0
            {
                return Err(DecodeError::BadBinding);
            }
            if previous_notification.is_some_and(|previous| previous >= grant.name) {
                return Err(DecodeError::BadOrder);
            }
            // A notification has exactly one waiter and at least one signaller,
            // and the grant's `source` must be among the signallers -- that is
            // the edge the grant names. Additional signallers are the object's
            // reason to exist: a waiter blocked on one notification learns
            // which peer spoke from the badge, which is the only way to wait on
            // a whole peer set at once. Each signaller's declared slot is its
            // badge bit, and the per-holder slot uniqueness checked below keeps
            // those bits distinct.
            let mut source_signals = false;
            let mut signal = 0;
            let mut wait = 0;
            for binding_index in 0..self.notification_binding_count {
                let binding = self.notification_binding(binding_index)?;
                if binding.grant != index {
                    continue;
                }
                match binding.role {
                    NotificationRole::Signal => {
                        source_signals |= binding.holder == grant.source;
                        signal += 1;
                    }
                    NotificationRole::Wait if binding.holder == grant.target => wait += 1,
                    NotificationRole::Wait => return Err(DecodeError::BadBinding),
                }
            }
            if signal == 0 || !source_signals || wait != 1 {
                return Err(DecodeError::BadBinding);
            }
            previous_notification = Some(grant.name);
        }
        for index in 0..self.notification_binding_count {
            let binding = self.notification_binding(index)?;
            if binding.grant >= self.notification_grant_count
                || binding.holder >= self.instance_count
                || binding.slot >= 31
                || binding.flags != 0
            {
                return Err(DecodeError::BadBinding);
            }
            for earlier in 0..index {
                let other = self.notification_binding(earlier)?;
                if other.holder == binding.holder && other.slot == binding.slot {
                    return Err(DecodeError::BadBinding);
                }
            }
        }
        Ok(())
    }

    fn grant_requires_instance_binding(&self, grant: Grant<'_>, instance: usize) -> bool {
        match grant.capability_kind {
            CapabilityKind::Executable => grant.source == GrantEndpoint::Instance(instance),
            CapabilityKind::Endpoint => {
                grant.source == GrantEndpoint::Instance(instance)
                    || grant.target == GrantEndpoint::Instance(instance)
            }
            _ => grant.target == GrantEndpoint::Instance(instance),
        }
    }

    pub fn grant_applies_to_instance(&self, grant: Grant<'_>, instance: usize) -> bool {
        if self.grant_requires_instance_binding(grant, instance) {
            return true;
        }
        let Ok(record) = self.instance(instance) else {
            return false;
        };
        let child_copy = match record.owner {
            InstanceOwner::Root => false,
            InstanceOwner::Instance(owner) => {
                grant.source == GrantEndpoint::Instance(owner)
                    && match grant.capability_kind {
                        CapabilityKind::Executable => (0..self.instance_count).any(|child| {
                            self.instance(child).is_ok_and(|child_record| {
                                child_record.owner == InstanceOwner::Instance(instance)
                                    && grant.target
                                        == GrantEndpoint::Executable(child_record.executable)
                            })
                        }),
                        CapabilityKind::Endpoint => {
                            grant.target == GrantEndpoint::Instance(instance)
                        }
                        _ => {
                            grant.target == GrantEndpoint::Instance(instance)
                                || grant.target == GrantEndpoint::Instance(owner)
                        }
                    }
            }
        };
        child_copy
            || (0..self.instance_count).any(|child| {
                let Ok(child_record) = self.instance(child) else {
                    return false;
                };
                child_record.owner == InstanceOwner::Instance(instance)
                    && grant.source == GrantEndpoint::Instance(instance)
                    && match grant.capability_kind {
                        CapabilityKind::Executable => {
                            grant.target == GrantEndpoint::Executable(child_record.executable)
                        }
                        _ => grant.target == GrantEndpoint::Instance(child),
                    }
            })
    }

    fn instance_index(&self, name: &str) -> Option<usize> {
        (0..self.instance_count).find(|i| self.instance(*i).is_ok_and(|v| v.name == name))
    }
}

fn validate_acyclic<F>(
    node_count: usize,
    mut edge: F,
    cycle_error: DecodeError,
) -> Result<(), DecodeError>
where
    F: FnMut(usize, usize) -> Result<Option<usize>, DecodeError>,
{
    let mut colors = [0u8; MAX_INSTANCES];
    let mut nodes = [0usize; MAX_INSTANCES];
    let mut edges = [0usize; MAX_INSTANCES];
    for root in 0..node_count {
        if colors[root] != 0 {
            continue;
        }
        let mut depth = 1;
        nodes[0] = root;
        colors[root] = 1;
        while depth != 0 {
            let frame = depth - 1;
            let node = nodes[frame];
            match edge(node, edges[frame])? {
                Some(next) => {
                    if next >= node_count {
                        return Err(cycle_error);
                    }
                    edges[frame] += 1;
                    match colors[next] {
                        0 => {
                            if depth >= node_count {
                                return Err(cycle_error);
                            }
                            nodes[depth] = next;
                            colors[next] = 1;
                            depth += 1;
                        }
                        1 => return Err(cycle_error),
                        _ => {}
                    }
                }
                None => {
                    colors[node] = 2;
                    depth -= 1;
                }
            }
        }
    }
    Ok(())
}

fn endpoint_key(endpoint: GrantEndpoint) -> (u8, usize) {
    match endpoint {
        GrantEndpoint::Instance(i) => (0, i),
        GrantEndpoint::Executable(i) => (1, i),
    }
}
fn update_bounded_string(hasher: &mut Sha256, value: &str) {
    hasher.update(&(value.len() as u16).to_le_bytes());
    hasher.update(value.as_bytes());
}
pub fn generation_identity(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if bytes.len() < IDENTITY_END {
        return [0; 32];
    }
    hasher.update(&bytes[..IDENTITY_OFFSET]);
    hasher.update(&[0u8; 32]);
    hasher.update(&bytes[IDENTITY_END..]);
    hasher.finalize()
}
fn bounded_count(value: usize, min: usize, max: usize) -> Result<usize, DecodeError> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(DecodeError::BadBounds)
    }
}
fn check_section(start: usize, count: usize, size: usize, next: usize) -> Result<(), DecodeError> {
    if start.checked_add(count.checked_mul(size).ok_or(DecodeError::BadBounds)?) == Some(next) {
        Ok(())
    } else {
        Err(DecodeError::BadBounds)
    }
}
fn read_string(
    bytes: &[u8],
    base: usize,
    table_len: usize,
    offset: usize,
) -> Result<&str, DecodeError> {
    if offset >= table_len {
        return Err(DecodeError::BadBounds);
    }
    let absolute = base.checked_add(offset).ok_or(DecodeError::BadBounds)?;
    let length = u16_at(bytes, absolute)? as usize;
    if length > MAX_STRING_BYTES
        || offset
            .checked_add(2 + length)
            .is_none_or(|end| end > table_len)
    {
        return Err(DecodeError::BadBounds);
    }
    core::str::from_utf8(
        bytes
            .get(absolute + 2..absolute + 2 + length)
            .ok_or(DecodeError::Truncated)?,
    )
    .map_err(|_| DecodeError::BadUtf8)
}
fn reserved_zero(bytes: &[u8], start: usize, end: usize) -> Result<(), DecodeError> {
    if bytes
        .get(start..end)
        .ok_or(DecodeError::Truncated)?
        .iter()
        .any(|byte| *byte != 0)
    {
        Err(DecodeError::NonZeroReserved)
    } else {
        Ok(())
    }
}
fn bool_at(bytes: &[u8], offset: usize) -> Result<bool, DecodeError> {
    match u32_at(bytes, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::UnknownEnum),
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, DecodeError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(DecodeError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_transport_requires_an_explicit_holder_with_read_or_write_authority() {
        let holder = lifecycle_policy::instance_identity("network-service");
        let other = lifecycle_policy::instance_identity("other");
        let grant = ParameterGrant {
            holder_identity: holder,
            subject_identity: holder,
            authority_flags: lifecycle_policy::PARAMETER_READ | lifecycle_policy::PARAMETER_WRITE,
        };
        for authority_flags in [
            lifecycle_policy::PARAMETER_READ,
            lifecycle_policy::PARAMETER_WRITE,
            grant.authority_flags,
        ] {
            assert!(parameter_transport_holder(
                ParameterGrant {
                    authority_flags,
                    ..grant
                },
                &holder
            ));
        }
        assert!(!parameter_transport_holder(grant, &other));
        assert!(!parameter_transport_holder(
            ParameterGrant {
                holder_identity: other,
                ..grant
            },
            &holder
        ));
        for authority_flags in [0, 4] {
            assert!(!parameter_transport_holder(
                ParameterGrant {
                    authority_flags,
                    ..grant
                },
                &holder
            ));
        }
        let absent: Option<ParameterGrant> = None;
        assert!(!absent.is_some_and(|entry| parameter_transport_holder(entry, &holder)));
        // Subject authority remains a root operation gate, not a transport prerequisite.
        assert!(parameter_transport_holder(
            ParameterGrant {
                subject_identity: other,
                ..grant
            },
            &holder
        ));
    }

    #[test]
    fn rejects_v4_product_generations() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[..8].copy_from_slice(&MAGIC_V4);
        bytes[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert!(matches!(
            Generation::decode(&bytes),
            Err(DecodeError::UnsupportedVersion)
        ));
    }

    #[test]
    fn capability_kinds_reject_rights_from_other_classes() {
        assert!(capability_rights_valid(CapabilityKind::Endpoint, 0b11));
        assert!(!capability_rights_valid(
            CapabilityKind::Endpoint,
            RIGHT_EXEC | RIGHT_SPAWN
        ));
        assert!(capability_rights_valid(
            CapabilityKind::Executable,
            RIGHT_EXEC | RIGHT_SPAWN
        ));
        // Named constants, never bare literals: the old form of this assertion
        // read `1 << 10` for `BLOCK_READ`, and when B90 retired that right the
        // literal silently became a bit outside `RIGHT_ALL` — turning a
        // cross-class refusal into a trivially true one that nothing flagged. A
        // named constant makes the next such retirement a build error here.
        assert!(!capability_rights_valid(
            CapabilityKind::Input,
            RIGHT_BUFFER_MAP
        ));
        assert!(!capability_rights_valid(
            CapabilityKind::Directory,
            RIGHT_INPUT_READ
        ));
    }

    /// B57/B90: `RIGHT_ALL` is the union of the *named* rights, not a bit-width
    /// mask. Bits 10, 11, 17 and 26 are gaps in the numbering — nothing names them
    /// and nothing uses them — so `(1 << 34) - 1` would admit a grant carrying
    /// authority no contract defines. Every validator that masks with
    /// `!RIGHT_ALL` inherits this, so pinning the mask is what keeps the holes
    /// closed. Bits 10 and 11 became gaps when B90 retired
    /// `BLOCK_READ`/`BLOCK_WRITE`, and bit 26 when `clock-authority/v2` retired
    /// `CLOCK_MONOTONIC_READ`; their positions are reserved, never reused.
    #[test]
    fn right_all_is_a_union_of_named_bits_and_excludes_the_reserved_gaps() {
        let named = [
            RIGHT_SEND,
            RIGHT_RECV,
            RIGHT_TRANSFER,
            RIGHT_EXEC,
            RIGHT_MAP_MMIO,
            RIGHT_DMA_PIN,
            RIGHT_DMA_RELEASE,
            RIGHT_IRQ_ACK,
            RIGHT_BUFFER_WRITE,
            RIGHT_BUFFER_MAP,
            RIGHT_STORE_READ,
            RIGHT_STORE_WRITE,
            RIGHT_HEALTH_CONFIRM,
            RIGHT_BOOT_UPDATE,
            RIGHT_SPAWN,
            RIGHT_SUPERVISE,
            RIGHT_DIRECTORY_READ,
            RIGHT_DIRECTORY_WRITE,
            RIGHT_DIRECTORY_LIST,
            RIGHT_DIRECTORY_DERIVE,
            RIGHT_INPUT_READ,
            RIGHT_BUFFER_CREATE,
            RIGHT_BUFFER_LOAN,
            RIGHT_CLOCK_TIMER_USE,
            RIGHT_CLOCK_SIMULATED_READ,
            RIGHT_CLOCK_SIMULATED_ADVANCE,
            RIGHT_SCHEDULING_PROMOTE,
            RIGHT_LIFECYCLE_RESTART,
            RIGHT_PARAMETER_READ,
            RIGHT_PARAMETER_WRITE,
        ];
        let union = named
            .iter()
            .fold(0, |accumulator, right| accumulator | right);
        assert_eq!(union, RIGHT_ALL);
        for gap in [10, 11, 17, 26] {
            assert_eq!(RIGHT_ALL & (1u64 << gap), 0, "bit {gap} is reserved");
        }
        assert_ne!(RIGHT_ALL, (1 << 34) - 1);
        // The mask is what every grant, mapping, and minted-binding check
        // applies, so an undefined bit must survive none of them.
        for gap in [10, 11, 17, 26] {
            assert_ne!(
                (RIGHT_SEND | RIGHT_RECV | 1u64 << gap) & !RIGHT_ALL,
                0,
                "bit {gap} escaped the mask"
            );
        }
        // Every declared kind, so a reserved bit cannot be admitted by one the
        // loop forgot to name.
        for kind in [
            CapabilityKind::Endpoint,
            CapabilityKind::Executable,
            CapabilityKind::SharedBufferFactory,
            CapabilityKind::Directory,
            CapabilityKind::Input,
            CapabilityKind::Supervision,
            CapabilityKind::SharedBuffer,
            CapabilityKind::Loan,
            CapabilityKind::Device,
            CapabilityKind::MmioRegion,
            CapabilityKind::InterruptSource,
            CapabilityKind::DmaAccount,
        ] {
            for gap in [10, 11, 17, 26] {
                assert!(!capability_rights_valid(kind, 1u64 << gap));
            }
        }
    }

    /// The schema's named rights divide between manifest-declarable capability
    /// rights and rights that `capability_rights_valid` deliberately rejects.
    /// The rejected class contains root-minted supervision policy rights, clock
    /// resource-table authorities, and declared-but-ungated legacy rights. A
    /// right moving between classes must move here and in
    /// `docs/capability-matrix.md` in the same change. This test is scoped to
    /// `capability_rights_valid`; other decoder fields have their own masks.
    ///
    /// B90 completed `BASELINES` to all twelve declared kinds. It previously
    /// named nine, omitting IO1's four hardware-resource kinds, so
    /// `NOT_MANIFEST_DECLARABLE` meant "rejected for those nine" while bits 4-7
    /// sat in it and were declared by real manifest grants on kinds the test did
    /// not enumerate. Enumerating every kind is what makes the two classes a
    /// partition of the vocabulary rather than of an arbitrary subset of it.
    #[test]
    fn declared_rights_partition_into_manifest_declarable_and_root_only() {
        const BASELINES: [(CapabilityKind, Rights); 12] = [
            (CapabilityKind::Endpoint, RIGHT_SEND | RIGHT_RECV),
            (CapabilityKind::Executable, RIGHT_EXEC | RIGHT_SPAWN),
            (CapabilityKind::SharedBufferFactory, RIGHT_BUFFER_CREATE),
            (CapabilityKind::Directory, RIGHT_DIRECTORY_READ),
            (CapabilityKind::Input, RIGHT_INPUT_READ),
            (CapabilityKind::Supervision, RIGHT_SUPERVISE),
            (CapabilityKind::SharedBuffer, RIGHT_BUFFER_WRITE),
            (CapabilityKind::Loan, RIGHT_BUFFER_MAP),
            (CapabilityKind::Device, RIGHT_MAP_MMIO),
            (CapabilityKind::MmioRegion, RIGHT_MAP_MMIO),
            (CapabilityKind::InterruptSource, RIGHT_IRQ_ACK),
            (
                CapabilityKind::DmaAccount,
                RIGHT_DMA_PIN | RIGHT_DMA_RELEASE,
            ),
        ];
        const MANIFEST_DECLARABLE: [Rights; 19] = [
            RIGHT_SEND,
            RIGHT_RECV,
            RIGHT_TRANSFER,
            RIGHT_EXEC,
            RIGHT_SPAWN,
            RIGHT_SUPERVISE,
            RIGHT_BUFFER_WRITE,
            RIGHT_BUFFER_MAP,
            RIGHT_BUFFER_CREATE,
            RIGHT_BUFFER_LOAN,
            RIGHT_DIRECTORY_READ,
            RIGHT_DIRECTORY_WRITE,
            RIGHT_DIRECTORY_LIST,
            RIGHT_DIRECTORY_DERIVE,
            RIGHT_INPUT_READ,
            // IO1's four, declarable on the kinds `BASELINES` now names. They
            // sat in the rejected class only because no baseline admitted them.
            RIGHT_MAP_MMIO,
            RIGHT_DMA_PIN,
            RIGHT_DMA_RELEASE,
            RIGHT_IRQ_ACK,
        ];
        const NOT_MANIFEST_DECLARABLE: [Rights; 11] = [
            RIGHT_SCHEDULING_PROMOTE,
            RIGHT_LIFECYCLE_RESTART,
            RIGHT_PARAMETER_READ,
            RIGHT_PARAMETER_WRITE,
            RIGHT_CLOCK_TIMER_USE,
            RIGHT_CLOCK_SIMULATED_READ,
            RIGHT_CLOCK_SIMULATED_ADVANCE,
            RIGHT_STORE_READ,
            RIGHT_STORE_WRITE,
            RIGHT_HEALTH_CONFIRM,
            RIGHT_BOOT_UPDATE,
        ];

        for (kind, baseline) in BASELINES {
            assert!(capability_rights_valid(kind, baseline));
        }
        for right in MANIFEST_DECLARABLE {
            assert!(
                BASELINES
                    .iter()
                    .any(|(kind, baseline)| { capability_rights_valid(*kind, *baseline | right) })
            );
        }
        for right in NOT_MANIFEST_DECLARABLE {
            assert!(
                BASELINES
                    .iter()
                    .all(|(kind, baseline)| { !capability_rights_valid(*kind, *baseline | right) })
            );
        }

        let manifest_union = MANIFEST_DECLARABLE
            .iter()
            .fold(0, |accumulator, right| accumulator | right);
        let rejected_union = NOT_MANIFEST_DECLARABLE
            .iter()
            .fold(0, |accumulator, right| accumulator | right);
        assert_eq!(manifest_union & rejected_union, 0);
        assert_eq!(manifest_union | rejected_union, RIGHT_ALL);
    }
    /// C9.5's two determinism masks partition the rights vocabulary.
    ///
    /// The `determinism` field is required on every right, so the renderer cannot
    /// emit an unclassified one — but a *renderer* bug could still fold a bit into
    /// both masks or neither, and either would silently weaken the refusal:
    /// overlap makes the classification self-contradictory, and a gap makes an
    /// authority nobody classified look harmless. Pinning the partition here means
    /// a regeneration that broke it fails a host test rather than admitting a
    /// deterministic component that reads live state.
    #[test]
    fn the_determinism_masks_partition_every_declared_right() {
        // No right is both recorded and unrecorded.
        assert_eq!(RIGHT_RECORDED & RIGHT_UNRECORDED, 0);
        // Neither mask names a bit outside the vocabulary, including the gap at 17.
        assert_eq!((RIGHT_RECORDED | RIGHT_UNRECORDED) & !RIGHT_ALL, 0);
        // The neutral remainder is exactly what the two masks leave, and it is
        // nonempty: `send`-style outputs exist, so a run where every right had
        // become a source would mean the classification had collapsed.
        let neutral = RIGHT_ALL & !(RIGHT_RECORDED | RIGHT_UNRECORDED);
        assert_ne!(neutral, 0);
        assert_eq!(RIGHT_RECORDED | RIGHT_UNRECORDED | neutral, RIGHT_ALL);
        // The two clock authorities with a C9.5 record family are the only
        // recorded sources. A right joining this mask without a matching record
        // would be certified against nothing. A monotonic read is ambient and is
        // recorded by the component that made it.
        assert_eq!(
            RIGHT_RECORDED,
            RIGHT_CLOCK_TIMER_USE | RIGHT_CLOCK_SIMULATED_READ
        );
        // And every byte-carrying authority is unrecorded, `send` included: it
        // gates `seL4_Call`, whose reply is state the peer chose.
        for right in [
            RIGHT_SEND,
            RIGHT_RECV,
            RIGHT_BUFFER_LOAN,
            RIGHT_STORE_READ,
            RIGHT_DIRECTORY_READ,
            RIGHT_INPUT_READ,
            RIGHT_PARAMETER_READ,
            RIGHT_SUPERVISE,
        ] {
            assert_ne!(right & RIGHT_UNRECORDED, 0, "{right:#x} must be unrecorded");
        }
    }

    #[test]
    fn dependency_cycle_reachable_beyond_probe_is_rejected() {
        let edges = [Some(1usize), Some(2), Some(1)];
        assert_eq!(
            validate_acyclic(
                edges.len(),
                |node, edge| Ok((edge == 0).then_some(edges[node]).flatten()),
                DecodeError::BadDependency
            ),
            Err(DecodeError::BadDependency)
        );
    }

    #[test]
    fn owner_cycle_reachable_beyond_probe_is_rejected() {
        let owners = [Some(1usize), Some(2), Some(1)];
        assert_eq!(
            validate_acyclic(
                owners.len(),
                |node, edge| Ok((edge == 0).then_some(owners[node]).flatten()),
                DecodeError::BadOwner
            ),
            Err(DecodeError::BadOwner)
        );
    }

    /// `BootAction`'s numeric values are an ABI: the root passes one in the
    /// bootstrap thread's first C parameter and answers the same number over
    /// `BOOT_ACTION` (B70), and a component matches on it. Renumbering a
    /// variant would silently select a different graph in an image built
    /// before the change, so the mapping is pinned rather than left to
    /// declaration order.
    ///
    /// Shared with `boot_action_ids_round_trip`, which uses it as the
    /// independent second source proving `BootAction::ALL` is complete.
    const FROZEN_BOOT_ACTIONS: [(BootAction, u32); 40] = [
        (BootAction::Product, 1),
        (BootAction::Boot, 2),
        (BootAction::Call, 3),
        (BootAction::Channel, 4),
        (BootAction::Crossing, 5),
        (BootAction::Directory, 7),
        (BootAction::Filesystem, 8),
        (BootAction::Generation, 9),
        (BootAction::Input, 10),
        (BootAction::Loan, 11),
        (BootAction::Operation, 12),
        (BootAction::Powerbox, 13),
        (BootAction::Qos, 14),
        (BootAction::Stress, 26),
        (BootAction::Reclamation, 15),
        (BootAction::Recovery, 16),
        (BootAction::Rollback, 17),
        (BootAction::Sample, 18),
        (BootAction::Spawn, 19),
        (BootAction::Storage, 20),
        (BootAction::Store, 21),
        (BootAction::Stream, 22),
        (BootAction::Supervision, 23),
        (BootAction::Transfer, 24),
        (BootAction::Visibility, 25),
        (BootAction::Matrix, 27),
        (BootAction::Traffic, 28),
        (BootAction::Demo, 29),
        (BootAction::PrivateMemory, 30),
        (BootAction::ClockAuthority, 31),
        (BootAction::WaitSet, 32),
        (BootAction::SchedulingClass, 33),
        (BootAction::LifecycleRestart, 34),
        (BootAction::Replay, 35),
        (BootAction::RobotRuntime, 36),
        (BootAction::CRuntime, 37),
        (BootAction::Slisp, 38),
        (BootAction::PrivateMemoryCycles, 39),
        (BootAction::Lifetime, 40),
        (BootAction::DataVolume, 41),
    ];

    #[test]
    fn boot_action_numbering_is_frozen() {
        for (action, id) in FROZEN_BOOT_ACTIONS {
            assert_eq!(action.id(), id, "{action:?} changed its ABI number");
        }
    }

    /// `ALL` is complete, and `from_id` inverts `id` over it.
    ///
    /// The completeness half needs a *second* source, because iterating `ALL`
    /// cannot notice a variant `ALL` omits — the loop simply never visits it.
    /// So the count is asserted against `boot_action_numbering_is_frozen`'s
    /// table above, which is maintained for an unrelated reason (the frozen
    /// wire numbering) and would have to be edited in the same change. Between
    /// the two: `from_id`'s exhaustive `match` refuses to compile when a
    /// variant is added without a case, and this fails when the variant is
    /// named there but never reaches `ALL` — the gap that would otherwise let a
    /// new composition fold to `None` and read at a component's call site as
    /// "some older generation" rather than as the composition it is (B70).
    #[test]
    fn boot_action_ids_round_trip() {
        for action in BootAction::ALL {
            assert_eq!(
                BootAction::from_id(action.id()),
                Some(*action),
                "{action:?} does not round-trip through its own id"
            );
        }
        // The completeness check. `FROZEN_BOOT_ACTIONS` is the numbering table
        // above; every entry must be reachable through `ALL`, and the two must
        // agree on length, so a variant added to `from_id` and the frozen table
        // but forgotten in `ALL` fails here.
        for (action, id) in FROZEN_BOOT_ACTIONS {
            assert!(
                BootAction::ALL.contains(&action),
                "{action:?} is frozen at {id} but missing from ALL"
            );
        }
        assert_eq!(
            BootAction::ALL.len(),
            FROZEN_BOOT_ACTIONS.len(),
            "ALL and the frozen numbering table declare different compositions"
        );
        // Ids are unique, so no two variants can answer one wire number.
        for (index, action) in BootAction::ALL.iter().enumerate() {
            for other in &BootAction::ALL[index + 1..] {
                assert_ne!(action.id(), other.id(), "{action:?} and {other:?} collide");
            }
        }
        // Zero is the startup argument every non-bootstrap task receives and
        // the sentinel a component memo uses for "not yet asked", so it must
        // name no composition. `u32::MAX` is the matching "asked and refused".
        assert_eq!(BootAction::from_id(0), None);
        assert_eq!(BootAction::from_id(u32::MAX), None);
    }

    /// Every spelling the source manifest may carry resolves, and nothing else
    /// does. A manifest naming an action this decoder does not know must fail
    /// admission rather than fall back to a default graph.
    #[test]
    fn every_declared_boot_action_spelling_resolves() {
        for (spelling, expected) in [
            ("product", BootAction::Product),
            ("boot", BootAction::Boot),
            ("qos", BootAction::Qos),
            ("stress", BootAction::Stress),
            ("visibility", BootAction::Visibility),
            ("matrix", BootAction::Matrix),
            ("demo", BootAction::Demo),
            ("c-runtime", BootAction::CRuntime),
            ("slisp", BootAction::Slisp),
            ("data-volume", BootAction::DataVolume),
        ] {
            assert_eq!(BootAction::parse(spelling), Some(expected));
        }
        for unknown in ["", "Product", "prod", "unknown", "product "] {
            assert_eq!(BootAction::parse(unknown), None, "{unknown:?} resolved");
        }
    }
}
