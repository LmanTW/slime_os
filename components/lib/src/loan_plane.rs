//! B49/B13: the C7 shared-buffer loan plane, driven by `init`.
//!
//! Extracted from `init.rs` by B65. The launchers there had grown to 895 lines
//! across 21 planes in one 2286-line binary, so every plane's edit shared a file
//! with every other plane's. This module holds the loan plane and the helpers
//! only it uses; `console_send_slot`, `wait_clean`, and the other genuinely
//! cross-plane helpers stay in `init.rs` and are passed or re-exported.
//!
//! `#[path]`-included rather than a crate module because each `src/bin/*.rs` is
//! its own `no_std`/`no_main` target, which is the same mechanism
//! `fabric_call_scenario.rs` and `launch_context.rs` already use.

use slime_rt::CapabilityDisposition;

// Init resolves its slot numbers through the root, and the helpers that do so
// live in `init.rs`, so they are reached through `super` rather than imported.
// The generated boot-layout table this used to describe is gone (B70): a slot
// is now asked for by declared name at run time rather than compiled in.
use super::{RIGHT_TRANSFER, console_send_slot, resolve_buffer_factory, resolve_executable};

/// Drive the P5.3.2 loan plane, as the lender.
///
/// Only reachable for the authenticated `loan` action declared by
/// `contracts/generation-manifest/v1/compositions/sel4-loan.zti`; see the `.md` beside it.
///
/// This is `sample-lender`'s shape, and deliberately not `sample-lender`
/// itself: that component is spawned by init on x86 and receives its peer
/// through a spawn grant. Init stands in as the lender so the *loan* plane can
/// be exercised without depending on the *spawn* plane's composition. The receiver is the real `sample-receiver`, unmodified —
/// which is the point: a component written against the retired kernel's loan
/// ABI runs unchanged on seL4.
pub fn drive_loan_plane() {
    const PAGE: u64 = 4096;
    const PAGES: usize = 2;
    const PAYLOAD_LEN: u64 = PAGES as u64 * PAGE;
    const BASE: u64 = 0x0000_0009_0000_0000;
    // The whole point of a loan: a payload the control message cannot carry.
    const _: () = assert!(PAYLOAD_LEN > slime_rt::MAX_MSG as u64);

    // ---- B13: the factory grant, independent of the budget ----
    //
    // The generation declares init a budget *and* a `bufferCreate` grant, and
    // the two are independent gates: the grant authorizes the operation, the
    // budget bounds it. Naming a slot that holds no factory must therefore be
    // refused however much quota the holder has left — which is the whole
    // ceiling here, since this runs first.
    //
    // `MAX_CAPS - 1` is inside the table and init was granted nothing there.
    if slime_rt::shared_buffer_create(63, 1, true).is_ok() {
        fail_loan(b"an empty slot named a buffer factory");
    }
    // A slot holding real authority of another kind, so the check is on kind
    // rather than on possession.
    if slime_rt::shared_buffer_create(receiver_slot(), 1, true).is_ok() {
        fail_loan(b"a channel slot named a buffer factory");
    }
    slime_rt::debug_write(b"[init] ungranted buffer factory refused\n");

    // ---- the four quota ceilings, each at ceiling + 1 ----
    //
    // Run before the loan, because a refusal must be a refusal against an
    // ungrazed ceiling rather than against whatever the loan happened to leave.
    // The generation declares init 4 pages / 2 buffers / 2 mappings / 1 loan;
    // every probe below asks for exactly one more than one of those.
    probe_quota_ceilings(BASE);

    let buffer = match slime_rt::shared_buffer_create(resolve_buffer_factory(), PAGES, true) {
        Ok(buffer) => buffer,
        Err(_) => fail_loan(b"create"),
    };
    if slime_rt::shared_buffer_map(buffer.slot, BASE, 0, PAYLOAD_LEN, true) != slime_rt::ERR_SUCCESS
    {
        fail_loan(b"writable map");
    }
    // SAFETY: the root installed a writable mapping of exactly `PAYLOAD_LEN`
    // bytes at `BASE`, and it stays mapped until the unmap below.
    unsafe {
        let bytes = BASE as *mut u8;
        for index in 0..PAYLOAD_LEN as usize {
            bytes.add(index).write_volatile((index % 251) as u8);
        }
    }
    slime_rt::debug_write(b"[init] payload written\n");

    // The receiver has to be running before it can be loaned to: a loan names
    // its receiver as the unique live holder of the channel's other end, so
    // with nothing spawned the root answers `absent-or-ambiguous` (B52) --
    // including for the unsealed probe below, which would otherwise be
    // refused for the wrong reason and pass vacuously.
    //
    // One grant: the receiver's own end of the channel init keeps the other
    // half of. That edge is generation-declared, so the preflight expects
    // exactly it -- which is what the docstring above says this cutover lacked
    // "until P5.3.3", and now has.
    if slime_rt::spawn(resolve_executable(b"executable:sample-receiver"), &[]).is_err() {
        fail_loan(b"spawn the receiver");
    }
    slime_rt::debug_write(b"[init] loan receiver spawned\n");

    // A loan requires an irreversibly sealed source, so an unsealed one must be
    // refused. Checked before sealing, because afterwards it is unobservable.
    if slime_rt::shared_buffer_loan(buffer.slot, receiver_slot(), 0, PAYLOAD_LEN, false).is_ok() {
        fail_loan(b"unsealed region was loanable");
    }
    slime_rt::debug_write(b"[init] unsealed loan denied\n");

    if slime_rt::shared_buffer_seal(buffer.slot) != slime_rt::ERR_SUCCESS {
        fail_loan(b"seal");
    }

    // How the receiver is named is the exit condition's own words — "a receiver
    // named by capability" — so the ways of naming one badly are checked before
    // the way that works. Each must be refused, and each for its own reason.
    //
    // A slot holding nothing. `MAX_CAPS - 1` is inside the table's bounds and
    // this component was granted nothing there, so this is the empty-slot case
    // rather than an out-of-range one.
    if slime_rt::shared_buffer_loan(buffer.slot, 63, 0, PAYLOAD_LEN, false).is_ok() {
        fail_loan(b"an empty slot named a receiver");
    }
    // A slot holding the wrong *kind*. The buffer's own slot is real authority
    // this component holds — it is the source of the loan — and it still names
    // no receiver, so the check is on kind rather than on possession.
    if slime_rt::shared_buffer_loan(buffer.slot, buffer.slot, 0, PAYLOAD_LEN, false).is_ok() {
        fail_loan(b"a buffer slot named a receiver");
    }
    slime_rt::debug_write(b"[init] unnamed receiver denied\n");

    // A real channel to a real peer, over an edge the generation declared
    // `transferable = false`. Everything else about this loan would succeed —
    // the source is sealed, the receiver is a live task at the other end of a
    // channel this component holds — so the only thing refusing it is the
    // generation's delegation bit, which is what makes that bit load-bearing
    // rather than decorative.
    if slime_rt::shared_buffer_loan(buffer.slot, console_send_slot(), 0, PAYLOAD_LEN, false).is_ok()
    {
        fail_loan(b"an undelegated channel carried a loan");
    }
    slime_rt::debug_write(b"[init] undelegated loan denied\n");

    let loan =
        match slime_rt::shared_buffer_loan(buffer.slot, receiver_slot(), 0, PAYLOAD_LEN, false) {
            Ok(loan) => loan,
            Err(_) => fail_loan(b"loan"),
        };
    slime_rt::debug_write(b"[init] loan created\n");

    // The loan ceiling is one. A second loan of the same sealed region is
    // therefore refused by the quota rather than by anything about the range.
    if slime_rt::shared_buffer_loan(buffer.slot, receiver_slot(), 0, PAGE, false).is_ok() {
        fail_loan(b"loan quota did not bite");
    }
    slime_rt::debug_write(b"[init] loan quota refused\n");

    // Only the descriptor crosses the channel; the payload never enters a
    // queue. The loan capability rides with it, which is the transfer this
    // slice adds — and it is the loan, not the buffer, that moves: the receiver
    // gets a read-only window onto an exact subrange, not the region.
    let descriptor = sample_descriptor(loan.id, PAYLOAD_LEN);
    if slime_rt::capability_delegate(
        receiver_slot(),
        loan.slot,
        CapabilityDisposition::Move,
        slime_proto::capability_transfer::OBJECT_KIND_SHARED_BUFFER_LOAN,
        1 << 9,
        &descriptor,
    ) != slime_rt::ERR_SUCCESS
    {
        fail_loan(b"send descriptor");
    }
    slime_rt::debug_write(b"[init] loan transferred\n");

    // The capability moved, so this component can no longer name it. Naming it
    // again must be refused: a transfer that left the sender holding the
    // capability would be a copy, not a move.
    if slime_rt::shared_buffer_return(loan.slot) == slime_rt::ERR_SUCCESS {
        fail_loan(b"transferred loan still nameable");
    }
    slime_rt::debug_write(b"[init] transferred loan released by sender\n");

    // Wait for the receiver to settle before reclaiming. Not politeness: this
    // component's own termination would settle every loan it owns, so exiting
    // early would reclaim the region out from under a receiver that has not
    // mapped it yet. That retention is the C7.5 property under test.
    let mut done = [0u8; slime_rt::MAX_MSG];
    let mut no_caps = [0u64; slime_rt::MAX_CAPS_PER_MSG];
    loop {
        match slime_rt::recv(receiver_slot(), &mut done, &mut no_caps) {
            slime_rt::ERR_WOULDBLOCK => {
                slime_rt::yield_now();
            }
            n if n < 0 => fail_loan(b"await receiver"),
            _ => break,
        }
    }
    slime_rt::debug_write(b"[init] receiver settled\n");

    // With the loan returned, the creator may reclaim.
    if slime_rt::shared_buffer_unmap(buffer.slot, BASE) != slime_rt::ERR_SUCCESS {
        fail_loan(b"unmap");
    }
    if slime_rt::shared_buffer_release(buffer.slot) != slime_rt::ERR_SUCCESS {
        fail_loan(b"release");
    }
    if slime_rt::shared_buffer_release(buffer.slot) != slime_rt::ERR_BAD_CAP {
        fail_loan(b"released buffer still nameable");
    }
    slime_rt::debug_write(b"[init] released\n");

    // Let `console` — the third holder, which took no part in any of the above
    // — prove its own quota is intact. This is the "without disturbing an
    // unrelated holder" half: init exhausted all four of its own ceilings, and
    // console's are untouched.
    if slime_rt::send(
        console_send_slot(),
        b"[console] unrelated holder intact\n",
        &[],
    ) != slime_rt::ERR_SUCCESS
    {
        fail_loan(b"notify unrelated holder");
    }
    for _ in 0..PEER_PARK_YIELDS {
        slime_rt::yield_now();
    }
    // Leave one finalized logical export unclaimed. The root must reclaim it
    // when the graph drains; otherwise the terminal capability summary remains
    // nonzero. Retain the source so init's normal task cleanup independently
    // reclaims the buffer itself.
    let abandoned = slime_rt::shared_buffer_create(resolve_buffer_factory(), 1, true)
        .unwrap_or_else(|_| fail_loan(b"create abandoned export source"));
    let leave = || {
        slime_rt::capability_delegate(
            console_send_slot(),
            abandoned.slot,
            CapabilityDisposition::Retain,
            slime_proto::capability_transfer::OBJECT_KIND_SHARED_BUFFER,
            RIGHT_TRANSFER,
            &[b'x'; 64],
        )
    };
    for _ in 0..4 {
        if leave() != slime_rt::ERR_SUCCESS {
            fail_loan(b"leave export ticket");
        }
    }
    if leave() != slime_rt::ERR_OUT_OF_MEMORY {
        fail_loan(b"export share did not bite");
    }
    slime_rt::debug_write(b"[init] export share refused\n");
    if slime_rt::send(console_send_slot(), b"SLIME.CONSOLE.CLOSE", &[]) != slime_rt::ERR_SUCCESS {
        fail_loan(b"close console");
    }
    slime_rt::debug_write(b"[init] export ticket left for reclamation\n");
}
/// Ask for exactly one more than each declared ceiling, and require a refusal.
///
/// Each probe is a single operation past one ceiling with the other three
/// unspent, so a refusal names the class it was aimed at rather than whichever
/// limit happened to be reached first. The root prints the class it refused on,
/// which is what the gate asserts — the wire status collapses all four to
/// `ERR_OUT_OF_MEMORY` by design.
fn probe_quota_ceilings(base: u64) {
    const PAGE: u64 = 4096;
    // Pages: the ceiling is 4, so a single 5-page region can never fit.
    if slime_rt::shared_buffer_create(resolve_buffer_factory(), 5, true).is_ok() {
        fail_loan(b"page quota did not bite");
    }
    slime_rt::debug_write(b"[init] page quota refused\n");

    // Buffers: the ceiling is 2. Three single-page regions exceed it while
    // staying inside the 4-page budget, so it is the buffer count that refuses.
    let first = match slime_rt::shared_buffer_create(resolve_buffer_factory(), 1, true) {
        Ok(buffer) => buffer,
        Err(_) => fail_loan(b"first probe region"),
    };
    let second = match slime_rt::shared_buffer_create(resolve_buffer_factory(), 1, true) {
        Ok(buffer) => buffer,
        Err(_) => fail_loan(b"second probe region"),
    };
    if slime_rt::shared_buffer_create(resolve_buffer_factory(), 1, true).is_ok() {
        fail_loan(b"buffer quota did not bite");
    }
    slime_rt::debug_write(b"[init] buffer quota refused\n");

    // Mappings: the ceiling is 2. Two land, the third is refused — and it is a
    // mapping of a region already charged, so no page or buffer limit is
    // involved.
    for (index, buffer) in [first, second].into_iter().enumerate() {
        if slime_rt::shared_buffer_map(buffer.slot, base + index as u64 * PAGE, 0, PAGE, true)
            != slime_rt::ERR_SUCCESS
        {
            fail_loan(b"probe mapping");
        }
    }
    if slime_rt::shared_buffer_map(first.slot, base + 2 * PAGE, 0, PAGE, true)
        == slime_rt::ERR_SUCCESS
    {
        fail_loan(b"mapping quota did not bite");
    }
    slime_rt::debug_write(b"[init] mapping quota refused\n");

    // Hand every probe resource back, so the loan below runs against ceilings
    // that are entirely unspent. A probe that left a charge behind would make
    // the loan's own refusals ambiguous.
    for (index, buffer) in [first, second].into_iter().enumerate() {
        if slime_rt::shared_buffer_unmap(buffer.slot, base + index as u64 * PAGE)
            != slime_rt::ERR_SUCCESS
        {
            fail_loan(b"probe unmap");
        }
        if slime_rt::shared_buffer_release(buffer.slot) != slime_rt::ERR_SUCCESS {
            fail_loan(b"probe release");
        }
    }
    slime_rt::debug_write(b"[init] quota probes reclaimed\n");
}
/// The 64-byte sample descriptor naming this loan, in the wire form
/// `sample-receiver` validates.
fn sample_descriptor(loan_id: u64, length: u64) -> [u8; slime_rt::MAX_MSG] {
    slime_proto::sample_descriptor::WireSampleDescriptor {
        magic: slime_proto::sample_descriptor::SAMPLE_DESCRIPTOR_MAGIC,
        version: slime_proto::sample_descriptor::FORMAT_VERSION,
        flags: slime_proto::sample_descriptor::FLAG_LAST,
        capability_kind: slime_proto::sample_descriptor::CAPABILITY_KIND_LOAN,
        loan_id,
        offset: 0,
        length,
        type_identity: slime_proto::interface_schema::telemetry_stream::TYPE_TAG,
        sequence: 1,
        reserved: [0; 8],
    }
    .encode()
}
fn fail_loan(reason: &[u8]) -> ! {
    slime_rt::console_line::Line::<256>::new()
        .bytes(b"[init] loan plane fail: ")
        .bytes(reason)
        .bytes(b"\n")
        .emit();
    slime_rt::exit(1)
}
/// Yields given up so a peer can reach its first `recv` and park. Generous
/// against the two operations `console` issues before blocking — a transfer
/// window bind and the receive itself — while still bounding the wait.
pub const PEER_PARK_YIELDS: usize = 64;
/// The channel to `sample-receiver`, which is also how the loan names its
/// receiver.
///
/// One slot for both because the root resolves the loan's receiver as the task
/// at the other end of this channel — see
/// `slime-root/src/main.rs::serve_buffer_loan` for why that stands in for the
/// supervision handle the retired kernel uses, and what replaces it in P5.3.3.
///
/// Resolved by grant name rather than compiled in (CP2/B70): `sample-receiver-side`
/// is an ordinary endpoint binding in init's own list.
fn receiver_slot() -> u32 {
    slime_rt::resolve_binding(b"sample-receiver-side").unwrap_or_else(|_| slime_rt::exit(1))
}
