use super::*;

/// The key script a generation runs for deterministic input gates.
///
/// A generation with no entry gets an empty source, so `InputRead` answers
/// `WouldBlock`: holding input authority does not invent a session.
pub(super) const fn input_script(generation: u64) -> &'static [u8] {
    match generation {
        // The input plane's own script: two characters, a space, a character,
        // and a newline — enough to prove ordering, the character encoding, the
        // named-key encoding, and exhaustion.
        31 => b"ab c\n",
        // The powerbox plane: the oracle's generation-9 session — a newline to
        // confirm the selection, then escape.
        32 => b"\n\x1b",
        // The Slisp plane: persistent definition, lexical use, structural
        // refusal, then Escape to close the bounded session.
        43 => b"(define answer 40)\n(+ answer 2)\n(+ 1)\n\x1b",
        _ => b"",
    }
}

/// Which in-memory resource a declared capability kind names, and the rights
/// mask that bounds it. The generation decoder has already checked that the
/// rights are valid for the declared kind; dispatch never guesses the object
/// class from overlapping right bits.
/// Construct one typed root-mediated capability from a declared kind.
pub(super) const fn declared_capability(
    kind: CapabilityKind,
    resource: u8,
    rights: u64,
) -> Option<graph::CapabilityEntry> {
    match kind {
        CapabilityKind::Directory => {
            graph::CapabilityEntry::directory(0, directory::ScopeTable::ROOT, rights)
        }
        CapabilityKind::Input => graph::CapabilityEntry::input(rights),
        CapabilityKind::SharedBufferFactory => graph::CapabilityEntry::buffer_factory(rights),
        CapabilityKind::Device => graph::CapabilityEntry::device(resource, rights),
        CapabilityKind::MmioRegion => graph::CapabilityEntry::mmio_region(resource, rights),
        CapabilityKind::InterruptSource => {
            graph::CapabilityEntry::interrupt_source(resource, rights)
        }
        CapabilityKind::DmaAccount => graph::CapabilityEntry::dma_account(resource, rights),
        CapabilityKind::Endpoint
        | CapabilityKind::Executable
        | CapabilityKind::Supervision
        | CapabilityKind::SharedBuffer
        | CapabilityKind::Loan => None,
    }
}

/// Launch every component whose payload this root task can load (P5.2).
///
/// Each component is built from the ELF its own generation object carries — not
/// from one embedded fixture — with its authority derived from the grants the
/// generation declares for it, and its transfer window recorded so its startup
/// bind can be checked against what was actually mapped.
///
/// Construction is staged exactly as the fixture path stages it: every task is
/// built and every window declared before any of them runs, so a failure part
/// way through leaves tasks that never ran rather than a half-started graph.
/// Stage and activate exactly the root-owned autostart instances in a v4
/// generation. Executables are a catalogue: a loadable catalogue entry is not
/// itself a request to construct a task.
/// The console dispatcher's stack and IPC buffer, both root-image pages so
/// they are mapped before the thread runs (B41).
static mut CONSOLE_STACK: console::ConsoleStack = console::ConsoleStack::new();
static mut CONSOLE_IPC_BUFFER: FreePage = FreePage([0; GRANULE_SIZE]);

/// Everything the console loop reads, in a `static` so the thread can hold a
/// pointer to it for as long as it runs.
static mut CONSOLE_CONTEXT: Option<console::ConsoleContext> = None;

/// The scripted key source, owned by the console thread (B41).
static mut CONSOLE_INPUT: Option<console::ScriptedInput> = None;

/// Start the console dispatcher (B41).
///
/// A second root thread, sharing the root's CSpace and VSpace and running at
/// the root's own priority, so it round-robins with the service loop rather
/// than starving behind it or preempting it.
///
/// The thread names its own IPC buffer on every invocation rather than using
/// the crate's ambient slot, so it needs no thread-local state: there is one
/// such slot per address space, and a blocked receive holds it borrowed for as
/// long as it waits.
/// What the second dispatcher serves over, gathered so the launcher's
/// signature names one thing per concern rather than nine positional
/// references.
pub(super) struct ConsoleTables<'a> {
    pub(super) windows: &'a WindowTable<MAX_WINDOW_ENTRIES>,
    pub(super) tasks: &'a TaskTable<MAX_TASKS>,
    pub(super) script: &'static [u8],
    pub(super) input: Option<device::TerminalInput>,
    pub(super) namespaces: &'a mut directory::Namespaces,
    pub(super) scopes: &'a directory::ScopeTable,
}

pub(super) fn start_console_dispatcher(
    bootinfo: &sel4::BootInfo,
    allocator: &mut ObjectAllocator,
    endpoint: sel4::cap::Endpoint,
    tables: ConsoleTables<'_>,
) -> Result<(), Stop> {
    let ConsoleTables {
        windows,
        tasks,
        script,
        input,
        namespaces,
        scopes,
    } = tables;
    let scratch_addr = ptr::addr_of!(CONSOLE_PAGE) as usize;
    let scratch = ScratchPage::claim(bootinfo, scratch_addr)
        .map_err(|error| stop!("console scratch unavailable: {error:?}"))?;
    let input_source = match input {
        Some(terminal) => console::ScriptedInput::new(script).with_terminal(terminal),
        None => console::ScriptedInput::new(script),
    };

    let tcb = allocator
        .allocate_fixed::<sel4::cap_type::Tcb>()
        .map_err(|error| stop!("console TCB unavailable: {error:?}"))?
        .cap();
    let ipc_addr = ptr::addr_of!(CONSOLE_IPC_BUFFER) as usize;
    let ipc_frame = child_vspace::image_frame(bootinfo, ipc_addr);

    // SAFETY: single-threaded until the resume below, and this is the only
    // reference taken to either static.
    let context = unsafe {
        let slot = &mut *ptr::addr_of_mut!(CONSOLE_CONTEXT);
        let input_slot = &mut *ptr::addr_of_mut!(CONSOLE_INPUT);
        *input_slot = Some(input_source);
        let Some(input) = input_slot.as_mut() else {
            return Err(stop!("console input unset"));
        };
        let input = ptr::addr_of_mut!(*input);
        *slot = Some(console::ConsoleContext {
            endpoint,
            scratch,
            windows: windows as *const _,
            buffer: ptr::addr_of_mut!(CONSOLE_IPC_BUFFER) as *mut sel4::IpcBuffer,
            input,
            tasks: tasks as *const _,
            namespaces: ptr::addr_of_mut!(*namespaces),
            scopes: scopes as *const _,
        });
        let Some(context) = slot.as_ref() else {
            return Err(stop!("console context unset"));
        };
        ptr::addr_of!(*context)
    };

    let configured = tcb.tcb_configure(
        // No fault handler: a fault in this thread is a root defect, and a
        // null handler makes the kernel report it rather than deliver it
        // somewhere that would swallow it.
        sel4::CPtr::from_bits(0),
        sel4::init_thread::slot::CNODE.cap(),
        // Every root-sharing thread must use the installed tree's guard.
        child_vspace::root_cspace_guard(bootinfo),
        sel4::init_thread::slot::VSPACE.cap(),
        ipc_addr as sel4::Word,
        ipc_frame,
    );
    configured.map_err(|error| stop!("console thread configure failed: {error:?}"))?;
    // The root's own priority: this thread answers on equal terms with the
    // service loop rather than starving behind it.
    let scheduled = tcb.tcb_set_sched_params(sel4::init_thread::slot::TCB.cap(), 255, 255);
    scheduled.map_err(|error| stop!("console thread priority failed: {error:?}"))?;

    let stack_top = ptr::addr_of!(CONSOLE_STACK) as usize + size_of::<console::ConsoleStack>();
    let mut registers = sel4::UserContext::default();
    // Through a fn pointer rather than casting the item directly, which
    // clippy refuses: the address is the same, the intent is explicit.
    let entry: extern "C" fn(usize) -> ! = console_entry;
    *registers.pc_mut() = entry as usize as sel4::Word;
    // This thread is entered by the kernel rather than by a call, so the ABI's
    // entry alignment is not simply "16-byte aligned"; see `thread_abi`.
    *registers.sp_mut() = thread_abi::initial_stack_pointer(stack_top) as sel4::Word;
    *registers.c_param_mut(0) = context as usize as sel4::Word;
    let started = tcb.tcb_write_all_registers(true, &mut registers);
    started.map_err(|error| stop!("console thread start failed: {error:?}"))?;
    crate::diagnostic_println!("SLIME_ROOT console dispatcher started");
    Ok(())
}

/// The console thread's entry point.
extern "C" fn console_entry(context: usize) -> ! {
    // No `set_ipc_buffer`: this thread names its buffer on every invocation
    // instead, so it touches none of the crate's ambient state.
    //
    // SAFETY: `context` is the `CONSOLE_CONTEXT` pointer written by
    // `start_console_dispatcher`, which lives in a `static`.
    unsafe { console::serve(&*(context as *const console::ConsoleContext)) }
}
