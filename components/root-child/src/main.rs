//! Native seL4 child fixture proving the `slime-root` mechanism cutover.
//!
//! The root task builds this image into its own CSpace/VSpace/TCB and grants it
//! exactly one authority it can invoke: the badged root service endpoint in
//! CSpace slot 1. The fixture sends one root service request, then follows the
//! directive the root returns — exit cleanly, or fault deliberately so the root
//! observes a fault on its supervision path.
//!
//! The clean-exit fixture additionally runs the shared-buffer phase before it
//! exits. That phase is the observable half of `slime-root/src/buffer_adapter.rs`:
//! it reads bytes the root wrote through a real shared frame, writes a reply
//! into the same frame, and then deliberately violates the two protections the
//! root's mapping rights are supposed to enforce by mechanism —
//!
//! 1. storing to a read-only mapping, and
//! 2. executing from a data page mapped `EXECUTE_NEVER`.
//!
//! Both must raise an attributable VM fault. The root supervises each one,
//! moves this thread's PC past it, and resumes, so the fixture still reaches
//! its ordinary clean exit. A probe that does *not* fault is a protection
//! failure, and the fixture says so loudly rather than continuing quietly.
//!
//! Slot numbers and operation labels here mirror `slime-root/src/task.rs` and
//! `slime-root/src/ipc.rs`. Nothing is discovered at runtime: a fixture that
//! could search for authority would not prove the grant is what conveys it.

#![no_std]
#![no_main]

mod runtime;

/// Badged root service endpoint. `slime-root/src/task.rs::CHILD_SLOT_SERVICE`.
const SLOT_SERVICE: sel4::CPtrBits = 1;
/// This task's own TCB, present only when the root supervises it as
/// self-managed. `slime-root/src/task.rs::CHILD_SLOT_TCB`.
const SLOT_TCB: sel4::CPtrBits = 2;
/// Fixture directive label owned by the root behavioral harness.
const OP_FIXTURE_DIRECTIVE: sel4::Word = 5;
/// Lifecycle exit label owned by the root task mechanism.
const OP_EXIT: sel4::Word = 3;
/// Shared-buffer map label, reused as this fixture's shared-buffer report.
const OP_SHARED_BUFFER_REPORT: sel4::Word = 23;
/// Private-memory growth. `contracts/syscall-abi/v1` label 43 (C10.1).
const OP_PRIVATE_MEMORY_GROW: sel4::Word = 43;

/// Fixture request tag, `b"SLIMEREQ"` big-endian, so the root can tell this
/// fixture's request from any other traffic on its endpoint.
const REQUEST_TAG: sel4::Word = 0x534c_494d_4552_4551;

/// Root directive returned in the reply's second message register.
const DIRECTIVE_EXIT: sel4::Word = 0;
const DIRECTIVE_FAULT: sel4::Word = 1;

/// Address deliberately left unmapped by the root loader. `child_vspace`
/// rejects an image whose footprint starts at zero, so a store here is always
/// an unmapped data access and always raises a VM fault.
const UNMAPPED_ADDRESS: usize = 0;

// ---- shared-buffer phase contract ----
//
// Every constant below is duplicated in `slime-root/src/main.rs` under the same
// name. They are compile-time agreements, not runtime discovery: a fixture that
// could find its shared region by searching would not prove that the root's
// mapping is what grants access to it.

/// Where the root maps the read-write shared region.
/// `slime-root/src/main.rs::SHARED_RW_VADDR`.
const SHARED_RW_VADDR: usize = 0x4000_0000;
/// Where the root maps the read-only shared region.
/// `slime-root/src/main.rs::SHARED_RO_VADDR`.
const SHARED_RO_VADDR: usize = 0x4001_0000;

/// Byte offset of the deterministic pattern the root writes into each region.
/// `slime-root/src/main.rs::SHARED_PATTERN_OFFSET`.
const SHARED_PATTERN_OFFSET: usize = 64;

/// The exact value the root writes at `SHARED_PATTERN_OFFSET` of the
/// read-write region. `slime-root/src/main.rs::SHARED_RW_PATTERN`.
const SHARED_RW_PATTERN: u64 = 0x5342_5546_5f52_5721;
/// The value the child writes back into the read-write region.
/// `slime-root/src/main.rs::SHARED_CHILD_REPLY`.
const SHARED_CHILD_REPLY: u64 = 0x4348_494c_445f_4f4b;
/// The value this fixture attempts, and must fail, to store into the read-only
/// region. `slime-root/src/main.rs::SHARED_RO_INTRUSION`.
const SHARED_RO_INTRUSION: u64 = 0xdead_beef_dead_beef;

/// Report flags this fixture sets in the shared-buffer report's third message
/// register. `slime-root/src/main.rs::REPORT_*`.
///
/// `REPORT_EXECUTE_REFUSED` is deliberately absent: only the root can decide
/// that one, from its own fault record.
const REPORT_RW_READBACK_OK: sel4::Word = 1 << 0;
const REPORT_RO_WRITE_REFUSED: sel4::Word = 1 << 1;

// ---- private-memory phase contract (C10.1) ----
//
// As above, every constant here is duplicated in `slime-root/src/main.rs` under
// the same name. The *base* deliberately is not: the root answers it in the
// growth reply, because the root is what chose it, and a fixture that
// recomputed the loader's window arithmetic would be asserting its own copy of
// that arithmetic rather than what the root actually mapped.

/// seL4 granule, the unit the growth operation counts in.
const PAGE_BYTES: usize = 4096;

/// The value this fixture writes into the first private page and re-reads after
/// a further growth. `slime-root/src/main.rs::MEM_PATTERN`.
const MEM_PATTERN: u64 = 0x4d454d5f42415345;

/// Marks the report in MR1 as the private-memory phase's rather than the
/// shared-buffer phase's; both use the same label.
/// `slime-root/src/main.rs::MEM_REPORT_TAG`.
const MEM_REPORT_TAG: sel4::Word = 0x4d454d5f52505449;

/// Report flags for the private-memory phase.
/// `slime-root/src/main.rs::REPORT_MEM_*`.
///
/// The root owns the "every flag is set" constant, not this fixture: a phase
/// that judged its own completeness could pass by reporting fewer observations
/// than it was supposed to make.
const REPORT_MEM_QUERY_OK: sel4::Word = 1 << 0;
const REPORT_MEM_FIRST_GROWTH_OK: sel4::Word = 1 << 1;
const REPORT_MEM_ZEROED: sel4::Word = 1 << 2;
const REPORT_MEM_SECOND_GROWTH_OK: sel4::Word = 1 << 3;
const REPORT_MEM_BASE_STABLE: sel4::Word = 1 << 4;
const REPORT_MEM_QUOTA_REFUSED: sel4::Word = 1 << 5;
const REPORT_MEM_REFUSAL_HAD_NO_EFFECT: sel4::Word = 1 << 6;

pub(crate) fn main() -> ! {
    let service = sel4::cap::Endpoint::from_bits(SLOT_SERVICE);

    sel4::debug_println!("SLIME_CHILD request op={OP_FIXTURE_DIRECTIVE} tag={REQUEST_TAG:#x}");
    let reply = service.call_with_mrs(
        sel4::MessageInfoBuilder::default()
            .label(OP_FIXTURE_DIRECTIVE)
            .length(2)
            .build(),
        [REQUEST_TAG, 0],
    );
    let result = reply.msg[0] as i64;
    let directive = reply.msg[1];
    sel4::debug_println!("SLIME_CHILD reply result={result} directive={directive}");

    match directive {
        DIRECTIVE_FAULT => {
            #[cfg(slime_private_fail_second_allocation)]
            private_memory_zero_page_retry(service);
            sel4::debug_println!("SLIME_CHILD fault requested addr={UNMAPPED_ADDRESS:#x}");
            // SAFETY: this store is intended to fault. The address is unmapped
            // in this task's VSpace by construction, so the kernel raises a VM
            // fault and delivers it to the root's fault endpoint; this thread
            // never resumes.
            unsafe {
                (UNMAPPED_ADDRESS as *mut u64).write_volatile(REQUEST_TAG);
            }
            sel4::debug_println!("SLIME_CHILD fault escaped");
        }
        DIRECTIVE_EXIT => {
            // Both phases run before the exit send, so the root observes every
            // report and every supervised probe while this task is still live
            // and attributable.
            shared_buffer_phase(service);
            private_memory_phase(service);
            sel4::debug_println!("SLIME_CHILD clean exit status=0");
            // The root answers `Exit` by suspending this thread, so this send
            // is the last thing the fixture does on its service endpoint.
            service.send_with_mrs(
                sel4::MessageInfoBuilder::default()
                    .label(OP_EXIT)
                    .length(1)
                    .build(),
                [0],
            );
        }
        other => {
            // An unrecognized directive is treated as exit rather than as a
            // silent default, so a protocol drift shows up in the record
            // instead of being masked by a catch-all match arm.
            sel4::debug_println!("SLIME_CHILD unknown directive={other} treated as exit");
            service.send_with_mrs(
                sel4::MessageInfoBuilder::default()
                    .label(OP_EXIT)
                    .length(1)
                    .build(),
                [0],
            );
        }
    }

    // Reached only if the root neither suspended this thread nor let the fault
    // stand. A self-managed task stops itself; otherwise it parks so it can
    // never be mistaken for a task still doing work.
    let own_tcb = sel4::cap::Tcb::from_bits(SLOT_TCB);
    if own_tcb.tcb_suspend().is_err() {
        sel4::debug_println!("SLIME_CHILD parked");
        loop {
            sel4::r#yield();
        }
    }
    unreachable!()
}

/// Read what the root wrote through the shared frame, answer it, then prove the
/// two protections the root's mapping rights claim to enforce.
///
/// Each probe deliberately performs an access the page tables must refuse. The
/// root supervises the resulting VM fault, steps this thread's PC past the
/// faulting instruction, and resumes it, so control returns to the next line
/// here. A probe that returns *without* having faulted means the protection did
/// not hold; that is reported as a failure flag rather than silently ignored.
fn shared_buffer_phase(service: sel4::cap::Endpoint) {
    let rw_pattern_addr = SHARED_RW_VADDR + SHARED_PATTERN_OFFSET;
    let ro_pattern_addr = SHARED_RO_VADDR + SHARED_PATTERN_OFFSET;
    let mut flags: sel4::Word = 0;

    // Probe 1: the root wrote a deterministic pattern into a frame it then
    // mapped here. Reading it back is what proves the frame is genuinely
    // shared rather than separately zeroed memory.
    //
    // SAFETY: the root maps a read-write frame covering `SHARED_RW_VADDR`
    // before resuming this thread, `SHARED_PATTERN_OFFSET + 8` is inside that
    // one 4 KiB page, and the address is 8-byte aligned. No Rust reference
    // aliases this address.
    let observed = unsafe { (rw_pattern_addr as *const u64).read_volatile() };
    if observed == SHARED_RW_PATTERN {
        flags |= REPORT_RW_READBACK_OK;
    }
    sel4::debug_println!(
        "SLIME_CHILD shared read vaddr={rw_pattern_addr:#x} observed={observed:#x} expected={SHARED_RW_PATTERN:#x}"
    );

    // Write back through the same mapping so the root can confirm the sharing
    // is bidirectional and not a copy.
    //
    // SAFETY: same page and alignment as the read above, and the mapping is
    // read-write, so this store is permitted by the page tables.
    unsafe {
        (rw_pattern_addr as *mut u64).write_volatile(SHARED_CHILD_REPLY);
    }

    // Probe 2: the read-only mapping must refuse a store. This is the
    // rights-are-mechanism proof: the very same frame object is mapped here
    // with `CapRights::read_only()`, so `maskVMRights` produced VMReadOnly and
    // the page-table entry itself rejects the write.
    sel4::debug_println!("SLIME_CHILD ro write probe vaddr={ro_pattern_addr:#x}");
    // SAFETY: the root maps a read-only frame covering `SHARED_RO_VADDR`. The
    // store is *expected* to fault; the root supervises that fault and advances
    // this thread's PC past it. RV64 emits this store with compression disabled
    // so the supervisor's four-byte advance cannot land inside a compressed
    // instruction. If the mapping were wrongly writable the store would simply
    // succeed, which the check below detects and reports.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        (ro_pattern_addr as *mut u64).write_volatile(SHARED_RO_INTRUSION);
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option norvc",
            "sd {value}, 0({address})",
            ".option pop",
            value = in(reg) SHARED_RO_INTRUSION,
            address = in(reg) ro_pattern_addr,
            options(nostack),
        );
    }
    // x86-64 instructions are variable-width, so the encoding is pinned rather
    // than left to the assembler: `mov %rax, (%rcx)` is exactly the three
    // bytes `48 89 01`. The supervisor advances the faulting PC by a fixed
    // width, so an encoding the compiler was free to widen (a REX-prefixed
    // displacement form, say) would resume mid-instruction.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            ".byte 0x48, 0x89, 0x01",
            in("rax") SHARED_RO_INTRUSION,
            in("rcx") ro_pattern_addr,
            options(nostack),
        );
    }
    // SAFETY: as for the read in probe 1; the read-only mapping permits loads.
    let after_write = unsafe { (ro_pattern_addr as *const u64).read_volatile() };
    if after_write != SHARED_RO_INTRUSION {
        flags |= REPORT_RO_WRITE_REFUSED;
    }
    sel4::debug_println!(
        "SLIME_CHILD ro write result observed={after_write:#x} intrusion={SHARED_RO_INTRUSION:#x}"
    );

    // Probe 3: a data page must not be executable. The root maps every shared
    // frame `EXECUTE_NEVER`, so branching into one must raise an instruction
    // abort rather than executing whatever bytes happen to be there. This is a
    // live regression test on `child_vspace::page_attributes`: without the
    // execute-never attribute the branch would run into arbitrary data.
    //
    // This fixture cannot adjudicate its own result. On an instruction abort
    // the faulting PC is the branch *target*, so the root resumes this thread
    // at its link register — which is exactly where a genuinely-executed page
    // would also have returned. The two paths are indistinguishable from here,
    // so the verdict belongs to the root, which either observed an Execute
    // fault at this address or did not.
    #[cfg(not(target_arch = "x86_64"))]
    {
        sel4::debug_println!("SLIME_CHILD wx exec probe vaddr={SHARED_RW_VADDR:#x}");
        branch_to_data_page(SHARED_RW_VADDR);
        // Reached either way: on an instruction fault the root resumes at the
        // architecture's link register, exactly where a successful call returns.
        sel4::debug_println!("SLIME_CHILD wx exec probe returned vaddr={SHARED_RW_VADDR:#x}");
    }
    // Skipped on x86-64: seL4 has no execute-never frame attribute there, so
    // the root maps this page executable and the branch would *succeed*,
    // running whatever data bytes are at the target. That is not a probe, it
    // is undefined execution, so the fixture must not perform it.

    // Hand every observation to the root in one bounded message. The root, not
    // this fixture, decides whether the phase passed, and it supplies the
    // execute-never verdict from its own fault record.
    let reply = service.call_with_mrs(
        sel4::MessageInfoBuilder::default()
            .label(OP_SHARED_BUFFER_REPORT)
            .length(4)
            .build(),
        [REQUEST_TAG, observed as sel4::Word, flags, 0],
    );
    sel4::debug_println!(
        "SLIME_CHILD shared report flags={flags:#x} result={}",
        reply.msg[0] as i64
    );
}

/// Exercise the task-private growable region the root reserved (C10.1).
///
/// Every claim the mechanism makes is checked from inside the task, where it is
/// observable, and the root adjudicates the accounting from its own records:
///
/// 1. a size query (`delta = 0`) answers the current extent without allocating;
/// 2. the first growth answers the previous count and every new page reads as
///    zero;
/// 3. a written pattern survives a *second* growth, which is the base-stability
///    property native pointers depend on;
/// 4. the growth that would pass the declared quota is refused, and the region
///    is intact afterwards — the query still answers the same extent and the
///    pattern is still readable.
///
/// No `.bss` array stands in for the region: every access below is through the
/// base the root reports, so a mapping the root did not install would fault
/// rather than silently read this image's own memory.
#[cfg(not(slime_private_fail_second_allocation))]
fn private_memory_phase(service: sel4::cap::Endpoint) {
    let mut flags: sel4::Word = 0;

    // A size query allocates nothing, so a region that has never grown must
    // answer zero pages — and it still answers the base, which is how an
    // allocator finds its region without a growth.
    let (initial, base) = grow(service, 0);
    if initial == 0 && base != 0 {
        flags |= REPORT_MEM_QUERY_OK;
    }
    sel4::debug_println!("SLIME_CHILD mem query pages={initial} base={base:#x}");

    // Two pages, so a partial mapping would be visible: a growth that mapped
    // the first and not the second would fail the zero read or the readback
    // below rather than passing quietly.
    let (first, first_base) = grow(service, 2);
    if first == 0 && first_base == base {
        flags |= REPORT_MEM_FIRST_GROWTH_OK;
    }
    sel4::debug_println!("SLIME_CHILD mem grew previous={first} delta=2 base={first_base:#x}");
    let base = base as usize;

    // Every new page must read as zero. Frames arrive zeroed from
    // `untyped_retype`, so this is checking that the root mapped fresh frames
    // rather than recycling something with contents.
    //
    // The span actually dereferenced is printed, not just the verdict: without
    // it the transcript records a base the root *reported* and a flag saying
    // reads succeeded, but nothing tying the two together — a root that
    // answered one address and mapped another would look identical. The gate
    // folds this address into the same single-base set as every other record.
    let mut zeros = true;
    for page in 0..2usize {
        for offset in [0usize, 8, PAGE_BYTES - 8] {
            let addr = base + page * PAGE_BYTES + offset;
            // SAFETY: the root mapped `delta` read-write granules starting at
            // `base` before answering the growth above, `addr` is inside that
            // range, and it is 8-byte aligned. No Rust reference aliases it.
            let observed = unsafe { (addr as *const u64).read_volatile() };
            if observed != 0 {
                zeros = false;
                sel4::debug_println!("SLIME_CHILD mem nonzero addr={addr:#x} value={observed:#x}");
            }
        }
    }
    if zeros {
        flags |= REPORT_MEM_ZEROED;
    }
    sel4::debug_println!(
        "SLIME_CHILD mem read base={base:#x} pages=2 bytes={} zeroed={}",
        2 * PAGE_BYTES,
        u8::from(zeros),
    );

    // Write into the first page, then grow again. The base must not move, so
    // the pattern must still be there afterwards — the property that makes the
    // region usable by native code holding real pointers.
    //
    // SAFETY: as above; the mapping is read-write, so this store is permitted.
    unsafe {
        (base as *mut u64).write_volatile(MEM_PATTERN);
    }
    let (second, second_base) = grow(service, 2);
    if second == 2 && second_base as usize == base {
        flags |= REPORT_MEM_SECOND_GROWTH_OK;
    }
    // SAFETY: as above. The address is in the first page, which the second
    // growth must not have moved, remapped, or zeroed.
    let survived = unsafe { (base as *const u64).read_volatile() };
    if survived == MEM_PATTERN {
        flags |= REPORT_MEM_BASE_STABLE;
    }
    sel4::debug_println!(
        "SLIME_CHILD mem grew previous={second} delta=2 base={second_base:#x} survived={survived:#x} expected={MEM_PATTERN:#x}"
    );
    // The address the pattern was written to and read back from, for the same
    // reason the read span above is printed: it is what makes "the base did not
    // move" an assertion about a dereferenced address rather than about a
    // reported number.
    sel4::debug_println!("SLIME_CHILD mem pattern base={base:#x} offset=0");

    // The region is now at its declared ceiling, so one more page must be
    // refused. A refusal is a negative result rather than a fault: the caller
    // stays alive to observe it, which is what lets an allocator report
    // exhaustion instead of dying.
    let (refused, _) = call_grow(service, 1);
    if refused < 0 {
        flags |= REPORT_MEM_QUOTA_REFUSED;
    }
    sel4::debug_println!("SLIME_CHILD mem quota probe delta=1 result={refused}");

    // And the refusal left everything as it was: the same extent, and the same
    // bytes. A partial growth would show up here as a larger count or a lost
    // pattern.
    let (after, _) = grow(service, 0);
    // SAFETY: as above.
    let intact = unsafe { (base as *const u64).read_volatile() };
    if after == 4 && intact == MEM_PATTERN {
        flags |= REPORT_MEM_REFUSAL_HAD_NO_EFFECT;
    }
    sel4::debug_println!(
        "SLIME_CHILD mem intact pages={after} pattern={intact:#x} expected={MEM_PATTERN:#x}"
    );

    // Hand every observation to the root in one bounded message. The root
    // decides whether the phase passed, from these flags and its own page
    // accounting.
    let reply = service.call_with_mrs(
        sel4::MessageInfoBuilder::default()
            .label(OP_SHARED_BUFFER_REPORT)
            .length(4)
            .build(),
        [REQUEST_TAG, MEM_REPORT_TAG, flags, 0],
    );
    sel4::debug_println!(
        "SLIME_CHILD mem report flags={flags:#x} result={}",
        reply.msg[0] as i64
    );
}

#[cfg(slime_private_fail_second_allocation)]
fn private_memory_phase(service: sel4::cap::Endpoint) {
    let (initial, base) = grow(service, 0);
    let (first, first_base) = grow(service, 1);
    let mut flags = 0;
    if initial == 0 && base != 0 {
        flags |= REPORT_MEM_QUERY_OK;
    }
    let base = base as usize;
    if first == 0 && first_base as usize == base {
        flags |= REPORT_MEM_FIRST_GROWTH_OK;
    }
    // The grown page must read as zero before anything writes it: a growth
    // that recycled a frame with contents is otherwise indistinguishable from
    // a fresh one, since the pattern store below would overwrite the evidence.
    let mut zeros = true;
    for offset in [0usize, 8, PAGE_BYTES - 8] {
        let addr = base + offset;
        // SAFETY: the root mapped one read-write granule at `base` before
        // answering the growth above, `addr` is inside it and 8-byte aligned,
        // and no Rust reference aliases it.
        let observed = unsafe { (addr as *const u64).read_volatile() };
        if observed != 0 {
            zeros = false;
            sel4::debug_println!("SLIME_CHILD mem nonzero addr={addr:#x} value={observed:#x}");
        }
    }
    if zeros {
        flags |= REPORT_MEM_ZEROED;
    }
    sel4::debug_println!(
        "SLIME_CHILD mem read base={base:#x} pages=1 bytes={PAGE_BYTES} zeroed={}",
        u8::from(zeros),
    );
    // SAFETY: as above; the mapping is read-write, so this store is permitted.
    unsafe { (base as *mut u64).write_volatile(MEM_PATTERN) };
    let (failed, _) = call_grow(service, 2);
    let (after, after_base) = grow(service, 0);
    let survived = unsafe { (base as *const u64).read_volatile() };
    if failed < 0 && after == 1 && after_base as usize == base && survived == MEM_PATTERN {
        flags |= REPORT_MEM_SECOND_GROWTH_OK
            | REPORT_MEM_BASE_STABLE
            | REPORT_MEM_QUOTA_REFUSED
            | REPORT_MEM_REFUSAL_HAD_NO_EFFECT;
        sel4::debug_println!(
            "SLIME_CHILD mem rollback preserved pages={after} base={base:#x} survived={survived:#x}"
        );
    } else {
        sel4::debug_println!(
            "SLIME_CHILD mem rollback failed result={failed} pages={after} base={after_base:#x} survived={survived:#x}"
        );
    }
    let reply = service.call_with_mrs(
        sel4::MessageInfoBuilder::default()
            .label(OP_SHARED_BUFFER_REPORT)
            .length(4)
            .build(),
        [REQUEST_TAG, MEM_REPORT_TAG, flags, 0],
    );
    sel4::debug_println!(
        "SLIME_CHILD mem report flags={flags:#x} result={}",
        reply.msg[0] as i64
    );
}

#[cfg(slime_private_fail_second_allocation)]
fn private_memory_zero_page_retry(service: sel4::cap::Endpoint) {
    let (initial, base) = grow(service, 0);
    if initial != 0 || base == 0 {
        sel4::debug_println!("SLIME_CHILD mem zero retry failed");
        return;
    }
    let (failed, _) = call_grow(service, 2);
    if failed >= 0 {
        sel4::debug_println!("SLIME_CHILD mem zero retry failed");
        return;
    }
    let (after, after_base) = grow(service, 0);
    if after != 0 || after_base != base {
        sel4::debug_println!("SLIME_CHILD mem zero retry failed");
        return;
    }
    sel4::debug_println!("SLIME_CHILD mem zero rollback result={failed} pages=0 base={base:#x}");
    let (previous, retry_base) = grow(service, 512);
    if previous != 0 || retry_base != base {
        sel4::debug_println!("SLIME_CHILD mem zero retry failed");
        return;
    }
    let base_addr = base as usize;
    for page in 0..512usize {
        let addr = base_addr + page * PAGE_BYTES;
        // SAFETY: the successful whole-window growth mapped every page at this
        // fixed base read-write before returning.
        if unsafe { (addr as *const u64).read_volatile() } != 0 {
            sel4::debug_println!("SLIME_CHILD mem zero retry failed");
            return;
        }
        unsafe { (addr as *mut u64).write_volatile(MEM_PATTERN ^ page as u64) };
    }
    for page in 0..512usize {
        let addr = base_addr + page * PAGE_BYTES;
        // SAFETY: the mapping above remains live and the address is the first
        // aligned word of the selected page.
        if unsafe { (addr as *const u64).read_volatile() } != MEM_PATTERN ^ page as u64 {
            sel4::debug_println!("SLIME_CHILD mem zero retry failed");
            return;
        }
    }
    let (final_pages, final_base) = grow(service, 0);
    if final_pages != 512 || final_base != base {
        sel4::debug_println!("SLIME_CHILD mem zero retry failed");
        return;
    }
    sel4::debug_println!(
        "SLIME_CHILD mem whole retry pages=512 base={base:#x} zeroed=1 preserved=1 survived=0x4d454d5f42415345"
    );
}

/// Grow the private region by `delta` pages, reporting a refusal on serial.
///
/// Answers the pair the operation returns: the page count before the growth,
/// and the window base. The probes that *expect* a refusal call [`call_grow`]
/// directly and inspect the status themselves.
fn grow(service: sel4::cap::Endpoint, delta: sel4::Word) -> (i64, sel4::Word) {
    let (result, base) = call_grow(service, delta);
    if result < 0 {
        sel4::debug_println!("SLIME_CHILD mem grow refused delta={delta} result={result}");
    }
    (result, base)
}

/// The raw operation: primary is the previous page count or a negative status,
/// auxiliary is the window base.
fn call_grow(service: sel4::cap::Endpoint, delta: sel4::Word) -> (i64, sel4::Word) {
    let reply = service.call_with_mrs(
        sel4::MessageInfoBuilder::default()
            .label(OP_PRIVATE_MEMORY_GROW)
            .length(1)
            .build(),
        [delta, 0],
    );
    (reply.msg[0] as i64, reply.msg[1])
}

/// Branch into `addr`, a page the root mapped as non-executable data.
///
/// The indirect call writes the architecture's link register, so the root can
/// resume this thread at the instruction after it records the execute fault.
///
/// Absent on x86-64, which has neither an execute-never frame attribute to
/// probe nor a link register to resume from.
#[cfg(not(target_arch = "x86_64"))]
fn branch_to_data_page(addr: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("blr {target}", target = in(reg) addr, clobber_abi("C"));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("jalr ra, 0({target})", target = in(reg) addr, clobber_abi("C"));
    }
}
