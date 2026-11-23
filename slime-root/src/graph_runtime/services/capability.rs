use super::*;
use crate::io_resource::LeaseId;

pub(super) fn capability_kind(capability: graph::CapabilityEntry) -> u32 {
    use slime_proto::capability_transfer::*;
    match capability {
        graph::CapabilityEntry::SharedBuffer(_) => OBJECT_KIND_SHARED_BUFFER,
        graph::CapabilityEntry::Loan(_) => OBJECT_KIND_SHARED_BUFFER_LOAN,
        graph::CapabilityEntry::Supervision(_) => OBJECT_KIND_SUPERVISION,
        graph::CapabilityEntry::Directory(_) => OBJECT_KIND_DIRECTORY,
        graph::CapabilityEntry::NativeEndpoint(_) => OBJECT_KIND_ENDPOINT,
        _ => 0,
    }
}

pub(super) fn serve_capability_export(
    generation: &Generation<'_>,
    launched: &LaunchedInstances,
    allocator: &mut ObjectAllocator,
    tasks: &mut TaskTable<MAX_TASKS>,
    sender: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let carrier = words[0] as u32;
    let source_slot = (words[0] >> 32) as u32;
    let expected_kind = words[1] as u32;
    let retain = words[1] >> 32 != 0;
    let rights = words[3];
    let Some(sender_instance) = launched.instance_for_task(sender) else {
        return Response::error(IpcError::BadCapability);
    };
    let Some((sender_cnode, sender_cnode_size_bits)) = tasks
        .get(sender)
        .map(|task| (task.cnode, task.cnode_size_bits))
    else {
        return Response::error(IpcError::BadCapability);
    };
    let Some((receiver, _)) = unsafe { &*ptr::addr_of!(PEER_ENDPOINTS) }.receiver_for(
        generation,
        sender_instance,
        carrier,
        launched,
        tasks,
    ) else {
        return Response::error(IpcError::BadCapability);
    };

    let (capability, source_endpoint) = if expected_kind
        == slime_proto::capability_transfer::OBJECT_KIND_ENDPOINT
    {
        let Some((endpoint, side, transferable)) = unsafe { &*ptr::addr_of!(PEER_ENDPOINTS) }
            .endpoint_for(generation, sender_instance, source_slot)
        else {
            return Response::error(IpcError::BadCapability);
        };
        let declared = match side {
            peer_endpoint::Side::Producer => RIGHT_SEND,
            peer_endpoint::Side::Consumer => RIGHT_RECV,
            peer_endpoint::Side::Both => RIGHT_SEND | RIGHT_RECV,
        } | if transferable { RIGHT_TRANSFER } else { 0 };
        if !transferable
            || rights == 0
            || rights & !(RIGHT_SEND | RIGHT_RECV) != 0
            || rights & declared != rights
        {
            crate::diagnostic_println!(
                "SLIME_GRAPH endpoint export rejected task={} source_slot={} carrier={} rights={rights:#x} declared={declared:#x} transferable={}",
                sender.0,
                source_slot,
                carrier,
                u8::from(transferable)
            );
            return Response::error(IpcError::BadCapability);
        }
        let Some(capability) = graph::CapabilityEntry::native_endpoint(rights) else {
            return Response::error(IpcError::BadCapability);
        };
        (capability, Some(endpoint))
    } else {
        let Some(source) = tasks
            .authority(sender)
            .and_then(|table| table.get(source_slot))
        else {
            return Response::error(IpcError::BadCapability);
        };
        let kind = capability_kind(source);
        if kind == 0 || kind != expected_kind || !source.is_transferable() {
            return Response::error(IpcError::BadCapability);
        }
        let Some(capability) = source.narrow(rights) else {
            return Response::error(IpcError::BadCapability);
        };
        (capability, None)
    };

    let exports = unsafe { &mut *ptr::addr_of_mut!(CAPABILITY_EXPORTS) };
    let Some(slot_index) = exports.entries.iter().position(Option::is_none) else {
        return Response::error(IpcError::DestinationSlotsExhausted);
    };
    if tasks.get(receiver).is_none() {
        return Response::error(IpcError::BadCapability);
    }

    let (ticket, sender_ticket_slot) = match source_endpoint {
        Some(endpoint) => {
            let cap_rights = match (rights & RIGHT_SEND != 0, rights & RIGHT_RECV != 0) {
                (true, true) => sel4::CapRights::all(),
                (true, false) => sel4::CapRightsBuilder::none()
                    .write(true)
                    .grant_reply(true)
                    .build(),
                (false, true) => sel4::CapRightsBuilder::none().read(true).build(),
                (false, false) => return Response::error(IpcError::BadCapability),
            };
            let ticket_slot = match allocator.reserve_slot::<sel4::cap_type::Endpoint>() {
                Ok(ticket) => ticket,
                Err(_) => return Response::error(IpcError::DestinationSlotsExhausted),
            };
            let ticket = sel4::init_thread::slot::CNODE
                .cap()
                .absolute_cptr(ticket_slot.cap());
            if ticket
                .mint(
                    &sel4::init_thread::slot::CNODE.cap().absolute_cptr(endpoint),
                    cap_rights.clone(),
                    0,
                )
                .is_err()
            {
                let _ = ticket.delete();
                allocator.release_slot(ticket_slot.cptr().bits() as usize);
                return Response::error(IpcError::BadCapability);
            }
            // Endpoint exports use the same declared-slot mirror the runtime
            // passes to seL4 as the message's source capability. `cap_drop`
            // only removes logical table entries, so it cannot delete this
            // in-flight ticket; cleanup owns the mirror until retirement.
            let sender_ticket_slot =
                task::CHILD_SLOT_AUTHORITY_BASE + source_slot as sel4::CPtrBits;
            if sender_cnode
                .absolute_cptr_from_bits_with_depth(sender_ticket_slot, sender_cnode_size_bits)
                .copy(&ticket, cap_rights)
                .is_err()
            {
                let _ = ticket.delete();
                allocator.release_slot(ticket_slot.cptr().bits() as usize);
                return Response::error(IpcError::BadCapability);
            }
            // C8.13.3: deliberately *not* credited to declared space. The
            // mirror occupies a physical slot in `CHILD_SLOT_AUTHORITY_BASE`'s
            // region, but it mirrors a declared slot the generation already
            // budgeted -- `sender_ticket_slot` is derived from `source_slot`
            // itself -- so crediting it would double-count one declared
            // capability. The physical census sees it, which is the count whose
            // bound it actually consumes.
            (Some(ticket_slot.cptr().bits()), Some(sender_ticket_slot))
        }
        None => (None, None),
    };

    if !retain && source_endpoint.is_none() {
        let Some(table) = tasks.authority_mut(sender) else {
            let staged = CapabilityExport {
                id: 0,
                sender,
                receiver,
                capability,
                ticket,
                sender_ticket_slot,
                retain,
                finalized: false,
            };
            cleanup_export_ticket(allocator, tasks, staged);
            return Response::error(IpcError::BadCapability);
        };
        if !table.drop_slot(source_slot) {
            let staged = CapabilityExport {
                id: 0,
                sender,
                receiver,
                capability,
                ticket,
                sender_ticket_slot,
                retain,
                finalized: false,
            };
            cleanup_export_ticket(allocator, tasks, staged);
            return Response::error(IpcError::BadCapability);
        }
    }

    let id = exports.next_id;
    exports.next_id = exports.next_id.checked_add(1).unwrap_or(1);
    exports.entries[slot_index] = Some(CapabilityExport {
        id,
        sender,
        receiver,
        capability,
        ticket,
        sender_ticket_slot,
        retain,
        finalized: false,
    });
    exports.exported = exports.exported.saturating_add(1);
    crate::diagnostic_println!(
        "SLIME_GRAPH capability exported task={} id={} kind={} rights={rights:#x} retain={}",
        sender.0,
        id,
        capability.kind_name(),
        u8::from(retain)
    );
    Response::success(i64::from(id), 0)
}

pub(super) fn cleanup_export_ticket(
    allocator: &mut ObjectAllocator,
    tasks: &TaskTable<MAX_TASKS>,
    export: CapabilityExport,
) {
    if let Some(slot) = export.sender_ticket_slot
        && let Some(task) = tasks.get(export.sender)
    {
        // Not credited against declared space: the mirror this deletes was
        // never credited to it either (see `serve_capability_export`). The
        // physical census picks the change up on the next query.
        let _ = task
            .cnode
            .absolute_cptr_from_bits_with_depth(slot, task.cnode_size_bits)
            .delete();
    }
    if let Some(bits) = export.ticket {
        let ticket = sel4::init_thread::slot::CNODE
            .cap()
            .absolute_cptr(sel4::cap::Endpoint::from_bits(bits));
        let _ = ticket.revoke();
        let _ = ticket.delete();
        allocator.release_slot(bits as usize);
    }
}

pub(super) fn serve_capability_finalize(
    allocator: &mut ObjectAllocator,
    sender: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let id = words[0] as u32;
    let exports = unsafe { &mut *ptr::addr_of_mut!(CAPABILITY_EXPORTS) };
    let Some(export) = exports.get_mut(id) else {
        return Response::success(0, 0);
    };
    if export.sender != sender {
        return Response::error(IpcError::BadCapability);
    }
    if !export.finalized {
        export.finalized = true;
        // The receiver may already hold a derived endpoint capability after the
        // rendezvous. Keep the root ticket until the export is retired, then
        // revoke descendants before returning its root CSlot to the allocator.
        exports.finalized = exports.finalized.saturating_add(1);
    }
    let _ = allocator;
    Response::success(0, 0)
}

/// Install one finalized export into the receiver's own authority table.
///
/// C9.5 adds the `receiver_instance` gate, and it closes a real hole rather than
/// restating admission. Admission certifies a deterministic instance against the
/// grants and minted bindings the *generation* declares, which is every authority
/// it holds at launch — but not every authority it can come to hold. A
/// transferable capability exported by a peer and imported here would land in the
/// receiver's table without the recording policy ever being consulted, so a
/// component the generation certified deterministic could acquire, say,
/// `directoryRead` at runtime and then read live state no record captures. The
/// determinism claim would still be authenticated and would no longer be true.
///
/// So the same mask admission uses is applied to the arriving capability: an
/// import carrying any right classified `unrecorded` is refused for a receiver
/// the recording resource declares deterministic. The refusal is on the *import*
/// rather than the export, because the export names a receiver but installs
/// nothing, and it is the installation that would widen the claim. A receiver
/// with no determinism claim is unaffected, which is every component in every
/// generation before C9.5.
pub(super) fn serve_capability_import(
    allocator: &mut ObjectAllocator,
    tasks: &mut TaskTable<MAX_TASKS>,
    generation: &Generation<'_>,
    receiver_instance: usize,
    receiver: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let id = words[0] as u32;
    let exports = unsafe { &mut *ptr::addr_of_mut!(CAPABILITY_EXPORTS) };
    let id = if id == 0 {
        let Some(oldest) = exports
            .entries
            .iter()
            .flatten()
            .filter(|entry| entry.receiver == receiver && entry.finalized)
            .map(|entry| entry.id)
            .min()
        else {
            return Response::error(IpcError::BadCapability);
        };
        oldest
    } else {
        id
    };
    let Some(export) = exports
        .entries
        .iter()
        .flatten()
        .find(|entry| entry.id == id)
        .copied()
    else {
        return Response::error(IpcError::BadCapability);
    };
    if export.receiver != receiver || !export.finalized {
        return Response::error(IpcError::BadCapability);
    }
    // The C9.5 gate, before the capability reaches the receiver's table. An
    // import that would widen a deterministic instance's authority past what
    // any recording can capture is refused, so the claim admission certified
    // stays true for the whole life of the task rather than only at launch.
    if generation::recording_declares_deterministic(generation, receiver_instance)
        && export.capability.rights_bits() & boot_contracts::generation::RIGHT_UNRECORDED != 0
    {
        crate::diagnostic_println!(
            "SLIME_RECORD refused import task={} kind={} rights={:#x} class=unrecorded-source",
            receiver.0,
            export.capability.kind_name(),
            export.capability.rights_bits(),
        );
        return Response::error(IpcError::BadCapability);
    }
    let Some(table) = tasks.authority_mut(receiver) else {
        return Response::error(IpcError::BadCapability);
    };
    let Some(destination) = table.free_slot_from(1) else {
        return Response::error(IpcError::DestinationSlotsExhausted);
    };
    if table.install(destination, export.capability).is_err() {
        return Response::error(IpcError::DestinationSlotsExhausted);
    }
    let Some(export) = exports.remove(id) else {
        table.drop_slot(destination);
        return Response::error(IpcError::BadCapability);
    };
    cleanup_export_ticket(allocator, tasks, export);
    exports.imported = exports.imported.saturating_add(1);
    crate::diagnostic_println!(
        "SLIME_GRAPH capability imported task={} id={} kind={} rights={:#x} retain={}",
        receiver.0,
        id,
        export.capability.kind_name(),
        export.capability.rights_bits(),
        u8::from(export.retain)
    );
    Response::success(i64::from(destination), 0)
}

pub(super) fn serve_capability_cancel(
    allocator: &mut ObjectAllocator,
    tasks: &mut TaskTable<MAX_TASKS>,
    sender: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
) -> Response {
    let id = words[0] as u32;
    let exports = unsafe { &mut *ptr::addr_of_mut!(CAPABILITY_EXPORTS) };
    let Some(export) = exports
        .entries
        .iter()
        .flatten()
        .find(|entry| entry.id == id)
        .copied()
    else {
        return Response::error(IpcError::BadCapability);
    };
    if export.sender != sender || export.finalized {
        return Response::error(IpcError::BadCapability);
    }
    if !export.retain {
        let Some(table) = tasks.authority_mut(sender) else {
            return Response::error(IpcError::BadCapability);
        };
        let Some(destination) = table.free_slot_from(1) else {
            return Response::error(IpcError::DestinationSlotsExhausted);
        };
        if table.install(destination, export.capability).is_err() {
            return Response::error(IpcError::DestinationSlotsExhausted);
        }
    }
    let Some(export) = exports.remove(id) else {
        return Response::error(IpcError::BadCapability);
    };
    cleanup_export_ticket(allocator, tasks, export);
    exports.cancelled = exports.cancelled.saturating_add(1);
    Response::success(0, 0)
}

/// Allocate one shared region for `holder` and admit it against the quota the
/// generation declared.
///
/// The page bound is read from the holder's own declared ceiling, not from a
/// constant: a request past it is refused before a frame is allocated, and the
/// table's own `preflight_buffer_charge` refuses it again against live usage.
/// Both are the same generation-declared number, so a holder the budget does
/// not name is refused here at `byte_pages == 0` rather than allocating a frame
/// the admission below would only hand back.
pub(super) fn serve_buffer_create(
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    holder: HolderId,
    pages: usize,
    writable: bool,
) -> Result<BufferHandle, shared_buffer::SharedBufferError> {
    if pages == 0 || pages > buffers.quota(holder).byte_pages as usize {
        // Named as the class it is rather than as a generic bad argument: a
        // request past the holder's declared page ceiling is a quota refusal,
        // and it is one of the four the milestone requires be observable.
        return Err(shared_buffer::SharedBufferError::QuotaExceeded);
    }
    buffers.preflight_create_pages(holder, pages)?;
    // One frame per requested page. Allocating a single frame regardless of
    // `pages` would produce a region whose anchor count disagreed with what the
    // caller asked for, and every later range check reads the anchor count — so
    // a two-page request would create a one-page region and then refuse the
    // caller's own two-page mapping as out of range.
    let mut frames = [shared_buffer::FrameCap(0); shared_buffer::MAX_BUFFER_PAGES];
    let requested = frames
        .get_mut(..pages)
        .ok_or(shared_buffer::SharedBufferError::BadSize)?;
    let mut adapter = BufferAdapter::new(allocator);
    let mut allocated = 0;
    let outcome = (|| {
        let (first, _) = adapter
            .allocator_mut()
            .allocate_shared_granules(pages)
            .map_err(|_| shared_buffer::SharedBufferError::BytesExhausted)?;
        for (index, frame) in requested.iter_mut().enumerate() {
            *frame = shared_buffer::FrameCap(first + index);
            allocated += 1;
        }
        let anchors = shared_buffer::FrameAnchors::from_slice(requested)?;
        buffers.create(holder, anchors, writable)
    })();
    // Failed cleanup stays recorded as an unpublished abort, including the
    // frames whose delete failed. Allocation retries that cleanup first.
    if outcome.is_err() && allocated != 0 {
        let _ = adapter
            .allocator_mut()
            .abort_shared_allocation(requested[0].0);
    }
    outcome
}

/// Mint one loan of a sealed subrange, bound to the receiver the caller named.
///
/// # Naming the receiver
///
/// `receiver_slot` names the receiver through a capability, never through an
/// ambient task id a component supplied — which is the property the exit
/// condition asks for. Two resource kinds satisfy that, and the caller may use
/// either.
///
/// A **supervision handle** names its subject outright. It was minted by the
/// spawn that created that task and names nothing else, ever. This is how the
/// retired kernel does it (`kernel/src/syscall/mod.rs::sys_shared_buffer_loan`),
/// and it is what `sample-lender` — unmodified — passes at its `RECEIVER_SLOT`,
/// so accepting it is what lets a component written against that ABI run here
/// (P5.3.4).
///
/// A **channel end** names its peer. P5.3.2 admitted only this, because no
/// spawn existed to mint a handle; it is kept because it is a real bound in its
/// own right — a component can only loan to a task the generation gave it an
/// edge to — and because a graph without spawn has no handle to name.
///
/// Neither widens the other. A supervision handle is authority over a task the
/// caller *created*, from an executable the generation granted it; a channel end
/// is authority over a task the generation *connected* it to. Both are
/// delegations the manifest made, differing in which one they rest on.
///
/// Note what is *not* read: the x86 grant `sample-plane-receiver-supervision` is
/// `source = init, target = sample-lender` and means "init may hand
/// sample-lender a handle", naming no subject at all. A handle's subject comes
/// from the spawn that minted it, which is the only thing that could know it.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_buffer_loan(
    generation: &Generation<'_>,
    launched: &LaunchedInstances,
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    tasks: &mut TaskTable<MAX_TASKS>,
    id: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
    served: &mut usize,
) -> Response {
    let lender = HolderId(u64::from(id.0));
    let buffer_slot = (words[0] & 0xffff_ffff) as u32;
    let receiver_slot = (words[0] >> 32) as u32;
    let offset = words[1] as usize;
    // Bit 63 of the length word asks for a writable loan (B46). The length
    // itself is bounded by the region, so the high bit is free; the table
    // still refuses unless the lender holds `WRITE` on an unsealed region.
    let writable = words[2] >> 63 != 0;
    let length = (words[2] & !(1 << 63)) as usize;

    // Both slots resolve through the caller's own table. A component that holds
    // neither the buffer nor a channel to the receiver is refused identically
    // to one that holds the wrong kind at that number, so the table cannot be
    // probed by watching which error comes back.
    let Some(graph::CapabilityEntry::SharedBuffer(capability)) =
        tasks.authority(id).and_then(|table| table.get(buffer_slot))
    else {
        return Response::error(IpcError::BadCapability);
    };
    let handle = capability.handle;
    // A slot holding nothing and a slot holding real authority of another kind
    // are refused identically: which one it was is not the caller's business,
    // and distinguishing them would let a component map its own table by
    // probing. One marker covers both for the same reason.
    //
    // **Two kinds resolve here**, and the difference is which question the
    // caller is answering.
    //
    // A `Supervision` handle names its subject outright: it was minted by the
    // spawn that created that task and names nothing else, ever. That is how
    // the retired kernel does it, and it is what `sample-lender` — unmodified
    // — passes at `RECEIVER_SLOT`.
    //
    // A **declared native endpoint** names its peer. The generation fixed both
    // ends of that edge before either task ran, so the slot identifies exactly
    // one counterpart and the caller cannot point it elsewhere. This is what
    // breaks the stream plane's ordering cycle (B46): the fabric loans a ring
    // to each participant while `fabric-publisher-b` loans its large sample
    // back to the fabric, so requiring supervision in both directions would
    // need each to be spawned before the other.
    //
    // Neither widens the other. A supervision handle is authority over a task
    // the caller *created*; an endpoint is authority over a task the
    // generation *connected* it to. Both name the receiver through a
    // capability rather than an ambient task id, which is what the exit
    // condition asks for.
    let authority = tasks
        .authority(id)
        .and_then(|table| table.get(receiver_slot));
    let resolved = match authority {
        Some(graph::CapabilityEntry::Supervision(capability))
            if capability.rights.allows(RIGHT_SUPERVISE) =>
        {
            Some(capability.task)
        }
        // `id` names a live task regardless of how it was constructed, so its
        // own instance is read from `tasks` directly rather than from
        // `launched.instance_for_task`, which only ever recorded root-autostart
        // instances (`main.rs`'s one `launched_instances.record` call site,
        // in the boot-time staging pass). A dynamically spawned sender —
        // every C9.6 fabric worker — is invisible to that table on both ends.
        None => tasks.get(id).and_then(|task| task.instance).and_then(|sender_instance| {
            // The endpoint namespace is disjoint from the logical-authority
            // table. Resolve a declared endpoint only when no logical
            // capability occupies the same relative number; otherwise a
            // shared-buffer slot could accidentally name an unrelated peer.
            // A loan also crosses authority, so the generation must have
            // delegated the edge with RIGHT_TRANSFER.
            let resolved = unsafe { &*ptr::addr_of!(PEER_ENDPOINTS) }.receiver_for(
                generation,
                sender_instance,
                receiver_slot,
                launched,
                tasks,
            );
            match resolved {
                Some((receiver, true)) => Some(receiver),
                Some((_receiver, false)) => {
                    crate::diagnostic_println!(
                        "SLIME_GRAPH loan refused task={} slot={receiver_slot} class=undelegated",
                        id.0,
                    );
                    None
                }
                None => None,
            }
        }),
        Some(_) => None,
    };
    let Some(peer) = resolved else {
        crate::diagnostic_println!(
            "SLIME_GRAPH loan refused task={} slot={receiver_slot} class=absent",
            id.0
        );
        return Response::error(IpcError::BadCapability);
    };
    if peer == id {
        return Response::error(IpcError::BadCapability);
    }
    let receiver = HolderId(u64::from(peer.0));

    // The table decides: it holds the region's rights, its sealed state, the
    // range, and the lender's `loan_count` ceiling. Nothing is re-checked here
    // that it already checks, so there is one place a loan can be refused.
    let handle = match buffers.loan(lender, receiver, handle, offset, length, writable) {
        Ok(handle) => handle,
        Err(error) => {
            crate::diagnostic_println!(
                "SLIME_GRAPH loan refused task={} slot={buffer_slot} class={}",
                id.0,
                buffer_error_class(error),
            );
            return Response::error(buffer_error_status(error));
        }
    };
    // The loan capability goes to the *lender*, which is what the ABI returns
    // and what `sample-lender` then names in its `send`. The receiver gets it
    // only when that send delivers — a loan the lender minted but never
    // transferred is one the receiver cannot map.
    let installed = tasks.authority_mut(id).and_then(|table| {
        let slot = table.free_slot_from(1)?;
        let rights =
            RIGHT_BUFFER_MAP | RIGHT_TRANSFER | if writable { RIGHT_BUFFER_WRITE } else { 0 };
        let capability = graph::CapabilityEntry::loan(handle, rights)?;
        table.install(slot, capability).ok()?;
        Some(slot)
    });
    let Some(slot) = installed else {
        // The loan exists in the table but the lender cannot name it, so it
        // would be charged against the quota forever. Revoking is the only way
        // back to the state before the call.
        //
        // A fresh loan has no mappings, so the teardown this drives issues no
        // adapter action at all — but it is run through the real adapter rather
        // than assumed empty, because "a loan just minted maps nothing" is a
        // property of the table, not something this call site should encode.
        let mut adapter = BufferAdapter::new(allocator);
        let _ = buffers.revoke_loan(&mut adapter, lender, handle);
        crate::diagnostic_println!("SLIME_GRAPH loan slot unavailable task={}", id.0);
        return Response::error(IpcError::DestinationSlotsExhausted);
    };
    *served += 1;
    crate::diagnostic_println!(
        "SLIME_GRAPH loan created task={} slot={slot} id={} to={} offset={offset} length={length}",
        id.0,
        handle.id.0,
        peer.0,
    );
    Response::success(i64::from(slot), handle.id.0)
}

/// Answer loan-map, return, and revoke for a loan the caller holds.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_loan_lifecycle(
    operation: LoanLifecycleRequest,
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    io_service: &mut IoResourceService,
    io_authority: &mut platform::AuthorityInventory,
    tasks: &mut TaskTable<MAX_TASKS>,
    id: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
    served: &mut usize,
) -> Response {
    let holder = HolderId(u64::from(id.0));
    let slot = (words[0] & 0xffff_ffff) as u32;
    let handle = if operation == LoanLifecycleRequest::Revoke {
        let Some(graph::CapabilityEntry::SharedBuffer(capability)) =
            tasks.authority(id).and_then(|table| table.get(slot))
        else {
            return Response::error(IpcError::BadCapability);
        };
        shared_buffer::LoanHandle {
            id: shared_buffer::LoanId(words[1]),
            buffer: capability.handle.id,
            epoch: buffers.epoch(),
            receiver: holder,
            writable: false,
        }
    } else {
        let Some(graph::CapabilityEntry::Loan(capability)) =
            tasks.authority(id).and_then(|table| table.get(slot))
        else {
            return Response::error(IpcError::BadCapability);
        };
        capability.handle
    };

    let Some(task) = tasks.get(id) else {
        return Response::error(IpcError::InvalidOperation);
    };
    let vspace = VSpaceCap(task.vspace.vspace.bits() as usize);
    let outcome = match operation {
        LoanLifecycleRequest::Map => {
            let mut adapter = BufferAdapter::new(allocator);
            match admit_mapping_destination(task, words[1] as usize, words[3] as usize) {
                Ok(()) => buffers.map_loan(
                    &mut adapter,
                    holder,
                    handle,
                    vspace,
                    words[1] as usize,
                    words[2] as usize,
                    words[3] as usize,
                ),
                Err(response) => return response,
            }
        }
        LoanLifecycleRequest::Return => {
            let mut adapter = BufferAdapter::new(allocator);
            buffers.return_loan(&mut adapter, holder, handle)
        }
        LoanLifecycleRequest::Revoke => {
            if let Err(error) = revoke_buffer_lease(
                io_service,
                io_authority,
                allocator,
                tasks,
                id,
                LeaseId(handle.id.0),
            ) {
                crate::diagnostic_println!(
                    "SLIME_IO loan revoke accounting failed task={} lease={} error={error:?}",
                    id.0,
                    handle.id.0,
                );
                return Response::error(IpcError::InvalidOperation);
            }
            let mut adapter = BufferAdapter::new(allocator);
            buffers.revoke_loan(&mut adapter, holder, handle)
        }
    };
    match outcome {
        Ok(()) => {
            *served += 1;
            if let Some(table) = tasks.authority_mut(id) {
                match operation {
                    LoanLifecycleRequest::Return => {
                        table.drop_slot(slot);
                    }
                    LoanLifecycleRequest::Revoke => drop_loan_slots(table, handle.id),
                    LoanLifecycleRequest::Map => {}
                }
            }
            crate::diagnostic_println!(
                "SLIME_GRAPH loan {} task={} slot={slot} id={}",
                loan_operation_name(operation),
                id.0,
                handle.id.0,
            );
            Response::success(0, 0)
        }
        Err(error) => {
            if operation == LoanLifecycleRequest::Return
                && error == shared_buffer::SharedBufferError::NotFound
                && let Some(table) = tasks.authority_mut(id)
            {
                table.drop_slot(slot);
            }
            crate::diagnostic_println!(
                "SLIME_GRAPH loan {} refused task={} slot={slot} class={}",
                loan_operation_name(operation),
                id.0,
                buffer_error_class(error),
            );
            Response::error(buffer_error_status(error))
        }
    }
}

pub(super) fn drop_loan_slots(table: &mut graph::AuthorityTable, id: shared_buffer::LoanId) {
    for slot in 0..graph::MAX_TASK_CAPS as u32 {
        if let Some(graph::CapabilityEntry::Loan(capability)) = table.get(slot)
            && capability.handle.id == id
        {
            table.drop_slot(slot);
        }
    }
}

pub(super) const fn loan_operation_name(operation: LoanLifecycleRequest) -> &'static str {
    match operation {
        LoanLifecycleRequest::Map => "mapped",
        LoanLifecycleRequest::Return => "returned",
        LoanLifecycleRequest::Revoke => "revoked",
    }
}

/// Which ceiling or check refused an operation, as a stable marker token.
///
/// The wire status a component sees is deliberately coarse — `slime_rt` has six
/// codes and every quota class collapses to `ERR_OUT_OF_MEMORY`, exactly as the
/// retired kernel's does. That is the right ABI: a component's response to a
/// full quota does not depend on which of the four ceilings it hit.
///
/// A gate's does. "Each of the four quota classes fails at ceiling+1" is not
/// observable from a status code that says only "quota", so the class is named
/// in the marker instead. Widening the status would change the ABI to make a
/// test easier; widening the marker changes nothing a component can see.
pub(super) const fn buffer_error_class(error: shared_buffer::SharedBufferError) -> &'static str {
    use shared_buffer::SharedBufferError as Error;
    match error {
        Error::QuotaExceeded => "quota",
        Error::BytesExhausted => "pages",
        Error::ObjectsExhausted => "buffers",
        Error::MappingsExhausted => "mappings",
        Error::LoansExhausted => "loans",
        Error::NotSealed => "unsealed",
        Error::RightsDenied => "rights",
        Error::WriteDenied => "write",
        Error::WrongOwner => "owner",
        Error::WrongReceiver => "receiver",
        Error::BadRange => "range",
        Error::BadSize => "size",
        Error::NotFound => "absent",
        Error::EpochMismatch => "epoch",
        _ => "other",
    }
}

/// The Slime status a shared-buffer failure answers with.
///
/// Every exhausted ceiling is `ERR_OUT_OF_MEMORY` and every authority failure
/// is `ERR_BAD_CAP`, so a component sees one stable status vocabulary
/// regardless of which ceiling or gate refused it.
pub(super) const fn buffer_error_status(error: shared_buffer::SharedBufferError) -> IpcError {
    use shared_buffer::SharedBufferError as Error;
    match error {
        // Every exhausted ceiling, whether the holder's declared quota or a
        // fixed table bound, is `ERR_OUT_OF_MEMORY`.
        Error::QuotaExceeded
        | Error::BytesExhausted
        | Error::ObjectsExhausted
        | Error::MappingsExhausted
        | Error::LoansExhausted
        | Error::ChargesExhausted
        | Error::IdentityExhausted => IpcError::DestinationSlotsExhausted,
        // Every authority failure — absent, wrong holder, insufficient rights,
        // stale epoch — is `ERR_BAD_CAP`, indistinguishable to the caller.
        Error::NotFound
        | Error::WrongOwner
        | Error::WrongReceiver
        | Error::RightsDenied
        | Error::WriteDenied
        | Error::NotSealed
        | Error::EpochMismatch => IpcError::BadCapability,
        // A malformed range or size is a bad argument, not bad authority.
        Error::BadSize | Error::BadRange | Error::BadFrameAnchors => IpcError::InvalidLength,
        _ => IpcError::TransferFailed,
    }
}

/// Width of each packed occupancy field in the reply's auxiliary word.
const OCCUPANCY_FIELD_BITS: u32 = 16;

/// Pack one holder's four live shared-buffer charges into the reply's single
/// auxiliary word: pages, buffers, mappings, loans, from the low 16 bits up.
///
/// Four counts in one word rather than four registers, because the reply
/// convention gives an operation exactly one auxiliary value
/// (`docs/syscall-abi.md`), and a transfer-window frame for sixteen bytes
/// would make a pure query the only read-only operation that needs a bound
/// window. Sixteen bits each is not a truncation risk: every count is bounded
/// by a table ceiling far below `u16::MAX` -- `MAX_TOTAL_PAGES` is 256,
/// `MAX_SHARED_BUFFERS` 32, `MAX_MAPPINGS` and `MAX_LOANS` 64 -- and a
/// holder's own declared quota is narrower still. The saturating branch below
/// is therefore unreachable today, and is written out rather than left to
/// `as u16` so the packing stays total if a ceiling is ever raised.
pub(super) const fn pack_occupancy(occupancy: shared_buffer::HolderOccupancy) -> sel4::Word {
    occupancy_field(occupancy.pages)
        | occupancy_field(occupancy.buffers) << OCCUPANCY_FIELD_BITS
        | occupancy_field(occupancy.mappings) << (OCCUPANCY_FIELD_BITS * 2)
        | occupancy_field(occupancy.loans) << (OCCUPANCY_FIELD_BITS * 3)
}

/// Saturate one count into a 16-bit packed field.
///
/// Shared by both occupancy packers, and saturating rather than `as u16` for
/// the same reason: a wrapped 65_536 reads as 0, which turns a ceiling breach
/// into an empty holder — the one answer a bounded count must never give.
pub(super) const fn occupancy_field(count: u32) -> sel4::Word {
    if count > u16::MAX as u32 {
        u16::MAX as sel4::Word
    } else {
        count as sel4::Word
    }
}

/// Pack one child's CSpace occupancy into the reply's auxiliary word
/// (C8.13.3): declared-space live count, declared-space peak, and physical
/// occupancy, from the low 16 bits up.
///
/// Three fields in one word rather than three registers, because the reply
/// convention gives an operation exactly one auxiliary value
/// (`docs/syscall-abi.md`).
///
/// The peak is root-tracked rather than left to the caller: declared occupancy
/// moves on every install, drop, transfer, and retirement, all of them root
/// operations, so a component sampling twice would report the higher of two
/// snapshots rather than the run's high-water mark.
///
/// The physical count rides along because it is a count in a *different* space
/// with a different bound — `capabilitySlots` budgets the declared numbering,
/// the CNode's capacity bounds the physical one — and a logical index of 3 lives
/// at physical slot 36, so neither can stand in for the other. The CNode's
/// capacity itself is not shipped: it is a compile-time constant of this root
/// (`CHILD_CNODE_SIZE_BITS`), not a per-holder fact.
///
/// The graph's declared `capabilitySlots` is deliberately not a field either.
/// It is a generation-wide limit rather than a property of this CSpace, so
/// including it would make a self-scoped query disclose a graph fact to callers
/// the graph grants nothing. The root keeps it for `breaches_ceiling`.
///
/// All three are far below `u16::MAX`: this root builds a 128-slot child CNode
/// and `graph::MAX_TASK_CAPS` is 64.
pub(super) const fn pack_slot_occupancy(
    declared: u32,
    declared_peak: u32,
    populated: u32,
) -> sel4::Word {
    occupancy_field(declared)
        | occupancy_field(declared_peak) << OCCUPANCY_FIELD_BITS
        | occupancy_field(populated) << (OCCUPANCY_FIELD_BITS * 2)
}

/// Answer map/unmap/seal/release for a region the caller already holds.
///
/// Every one resolves through the table, which is where rights and quota live,
/// so a task naming a region it does not hold is refused by the same mechanism
/// that bounds one it does.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_buffer_lifecycle(
    operation: BufferLifecycleRequest,
    buffers: &mut SharedBufferTable,
    allocator: &mut ObjectAllocator,
    tasks: &mut TaskTable<MAX_TASKS>,
    id: TaskId,
    words: &[sel4::Word; ipc::FAST_MESSAGE_REGISTERS],
    served: &mut usize,
) -> Response {
    let holder = HolderId(u64::from(id.0));
    let slot = (words[0] & 0xffff_ffff) as u32;
    // The handle is resolved from the caller's own table, never reconstructed
    // from the message: it carries rights and an epoch, so accepting one off
    // the wire would let a component name authority it was not issued.
    //
    // **A loan slot resolves here too**, for `unmap` alone, because
    // `sys_shared_buffer_unmap` accepts one: its resolution arm is
    // `SharedBufferLoan(loan) => loan.region()`, so a receiver that mapped
    // through `loan_map` unmaps through the same slot it mapped with. Without
    // this a component doing exactly that — which `fabric-subscriber` does on
    // every shared sample — is answered `ERR_BAD_CAP` on a slot it holds, and
    // has no other slot to name: the region belongs to the *lender*, and the
    // receiver was never issued a buffer capability for it.
    //
    // Only `unmap`. The oracle's `map`, `seal`, and `release` each require a
    // `SharedBuffer` and refuse a loan, so widening those would grant a
    // receiver authority over a region it merely borrows. The asymmetry is the
    // oracle's, not this function's.
    //
    // A loan resolves to a *different table call* rather than to a converted
    // handle, because the two authorize differently: a receiver does not own
    // the region, so `unmap`'s owner check would refuse it. See
    // `SharedBufferTable::unmap_loan`.
    enum Subject {
        Buffer(shared_buffer::BufferHandle),
        Loan(shared_buffer::LoanHandle),
    }
    let resolved = tasks.authority(id).and_then(|table| match table.get(slot) {
        Some(graph::CapabilityEntry::SharedBuffer(capability)) => {
            Some(Subject::Buffer(capability.handle))
        }
        Some(graph::CapabilityEntry::Loan(capability))
            if operation == BufferLifecycleRequest::Unmap =>
        {
            Some(Subject::Loan(capability.handle))
        }
        _ => None,
    });
    let Some(subject) = resolved else {
        // `ERR_BAD_CAP`, which is what a component tests for: `sample-lender`
        // proves a released buffer is unnameable by requiring exactly that code
        // from the second release, and the slot is empty by then because the
        // first one emptied it.
        return Response::error(IpcError::BadCapability);
    };
    let Some(task) = tasks.get(id) else {
        return Response::error(IpcError::InvalidOperation);
    };
    let vspace = VSpaceCap(task.vspace.vspace.bits() as usize);
    let mut adapter = BufferAdapter::new(allocator);
    // A loan reaches only the unmap arm, by construction above.
    let handle = match subject {
        Subject::Buffer(handle) => handle,
        Subject::Loan(loan) => {
            let outcome = buffers.unmap_loan(&mut adapter, holder, loan, vspace, words[1] as usize);
            return finish_buffer_lifecycle(operation, tasks, id, slot, outcome, served);
        }
    };
    let outcome = match operation {
        BufferLifecycleRequest::Map => {
            let writable = words[0] >> 32 != 0;
            match admit_mapping_destination(task, words[1] as usize, words[3] as usize) {
                Ok(()) => buffers.map(
                    &mut adapter,
                    holder,
                    handle,
                    vspace,
                    words[1] as usize,
                    words[2] as usize,
                    words[3] as usize,
                    if writable {
                        MappingRights::ReadWrite
                    } else {
                        MappingRights::ReadOnly
                    },
                ),
                Err(response) => return response,
            }
        }
        BufferLifecycleRequest::Unmap => {
            buffers.unmap(&mut adapter, holder, handle, vspace, words[1] as usize)
        }
        BufferLifecycleRequest::Seal => buffers.seal(&mut adapter, holder, handle),
        BufferLifecycleRequest::Release => buffers.release(&mut adapter, holder, handle),
    };
    finish_buffer_lifecycle(operation, tasks, id, slot, outcome, served)
}

/// Refuse a mapping whose destination runs into the caller's own task-private
/// memory window (C10.4).
///
/// The two memory planes are otherwise independent by construction — separate
/// tables, separate ceilings, separate allocation sources, and no capability
/// kind for a private region — but they share one thing: the child's address
/// space. The private window is *reserved* address space whose leaf frames
/// arrive on demand, so an address inside it that the component's allocator has
/// not yet grown into is simply unmapped, and a shared-buffer mapping there
/// succeeds. This is the one check that keeps the last shared resource from
/// being a way to alias the two.
///
/// Enforced here rather than inside `SharedBufferTable`, for two reasons. The
/// table holds no task records: the window lives on the child VSpace, and this
/// dispatcher is the one place that has already resolved both. And the rule is
/// about the *caller*, not about the region — a buffer legitimately maps into
/// any other component's address space at the same numeric address, so it is
/// not a property of the buffer that could be checked once when it is created.
///
/// A malformed length is left to the table, which owns every other range rule
/// and reports them uniformly; this refuses only what it can decide.
pub(super) fn admit_mapping_destination(
    task: &task::Task,
    base: usize,
    length: usize,
) -> Result<(), Response> {
    let Some(end) = base.checked_add(length) else {
        // Not this check's refusal to make: `validate_mapping_range` reports
        // the same overflow as `BadRange` for every mapping path, and answering
        // it here would give one caller a different status for one operation.
        return Ok(());
    };
    if task.private_memory.overlaps(&(base..end)) {
        let window = task.private_memory.window();
        crate::diagnostic_println!(
            "SLIME_MEM mapping refused task={} base={base:#x} end={end:#x} window={:#x}..{:#x}",
            task.id.0,
            window.start,
            window.end,
        );
        // `InvalidOperation`, which is the variant answering `ERR_INVALID_ARG`
        // — the same class every other malformed mapping request gets. The
        // refusal is deliberately not distinguishable on the wire from a bad
        // range: a component that could tell the two apart could map its own
        // window's bounds by watching which code a probe returns, and the
        // window's placement is not something a component is told. The root's
        // marker above names the cause for the transcript, which is where an
        // attributable refusal belongs.
        return Err(Response::error(IpcError::InvalidOperation));
    }
    Ok(())
}

/// Turn a buffer-lifecycle table outcome into the wire response.
///
/// Extracted so the loan-unmap path and the buffer path answer identically:
/// the same success accounting, the same marker, and the same error mapping.
/// Two copies would be two places for those to drift.
pub(super) fn finish_buffer_lifecycle(
    operation: BufferLifecycleRequest,
    tasks: &mut TaskTable<MAX_TASKS>,
    id: TaskId,
    slot: u32,
    outcome: Result<(), shared_buffer::SharedBufferError>,
    served: &mut usize,
) -> Response {
    match outcome {
        Ok(()) => {
            *served += 1;
            // A released region is no longer authority the task holds, so its
            // slot is emptied here rather than left naming a dead handle.
            if operation == BufferLifecycleRequest::Release
                && let Some(table) = tasks.authority_mut(id)
            {
                table.drop_slot(slot);
            }
            Response::success(0, 0)
        }
        Err(error) => {
            // The stage *and* the class, because they answer different
            // questions: which operation was refused, and which ceiling or
            // check refused it. A gate asserting that the mapping quota bites
            // at ceiling+1 needs the second, and the wire status cannot carry
            // it — see `buffer_error_class`.
            crate::diagnostic_println!(
                "SLIME_GRAPH buffer {} refused task={} slot={slot} class={}",
                buffer_operation_name(operation),
                id.0,
                buffer_error_class(error),
            );
            Response::error(buffer_error_status(error))
        }
    }
}

pub(super) const fn buffer_operation_name(operation: BufferLifecycleRequest) -> &'static str {
    match operation {
        BufferLifecycleRequest::Map => "map",
        BufferLifecycleRequest::Unmap => "unmap",
        BufferLifecycleRequest::Seal => "seal",
        BufferLifecycleRequest::Release => "release",
    }
}
