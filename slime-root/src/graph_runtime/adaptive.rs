//! Adaptive private-memory policy, bound to real tasks.
//!
//! Owns the three things an entitlement needs to be more than a number: the
//! admitted ledger, the physical reservations its guarantees were taken into,
//! and the incarnation each subject task is bound to. Nothing here allocates;
//! it decides who may ask, for how much, and against which reservation, and
//! records what actually happened.
//!
//! Ordering is the point. Reservations are materialized before any task is
//! constructed, because a guarantee a later static construction could spend is
//! not a guarantee; a subject binds its incarnation during construction and
//! before publication, so a staged task can neither be dispatched nor grow
//! without one; and a boot that cannot fund every guarantee fails closed
//! before a single component is published.

use boot_contracts::private_memory_policy::{
    self as policy, Policy,
    ledger::{self, Ledger},
};

use crate::generation::{self, GuaranteeReservations};
use crate::object_allocator::ObjectAllocator;
use crate::private_memory::{MAX_WINDOW_PAGES, window_pages};
use crate::task::{PrivateBinding, TaskId};

/// A root-derivable name for an entitlement.
///
/// The encoded policy carries only the 32-byte identity, which is a hash of
/// the declared name, so the root cannot print the name itself. This is the
/// identity's first eight bytes in lowercase hex: a checker that knows the
/// declared name computes the same token. It is an identity prefix and not a
/// name, and two entitlements colliding in these eight bytes would be
/// indistinguishable here.
pub struct EntitlementToken([u8; 16]);

impl EntitlementToken {
    pub fn new(identity: &[u8; 32]) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut token = [0u8; 16];
        for (index, byte) in identity[..8].iter().enumerate() {
            token[2 * index] = DIGITS[(byte >> 4) as usize];
            token[2 * index + 1] = DIGITS[(byte & 0xf) as usize];
        }
        Self(token)
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: every byte written above is an ASCII hex digit.
        core::str::from_utf8(&self.0).unwrap_or("????????????????")
    }
}

/// Why a growth was refused, in the vocabulary the transcript reports.
fn refusal_cause(error: &crate::private_memory::elastic::ElasticGrowError) -> &'static str {
    use crate::private_memory::elastic::ElasticGrowError;
    match error {
        ElasticGrowError::Window { .. } => "maximum",
        ElasticGrowError::Reservation { .. } => "reservation",
        ElasticGrowError::Policy(ledger::Error::Maximum) => "maximum",
        ElasticGrowError::Policy(ledger::Error::Guarantee) => "entitlement",
        ElasticGrowError::Policy(ledger::Error::Denied | ledger::Error::Incarnation) => {
            "entitlement"
        }
        ElasticGrowError::Policy(ledger::Error::Unavailable) => "pool",
        ElasticGrowError::Demand(refusal) => match refusal.resource() {
            "ordinary-bytes" => "pool",
            _ => "resource",
        },
        _ => "resource",
    }
}

/// The policy runtime for one booted graph.
pub struct AdaptivePolicy<'a> {
    policy: Policy<'a>,
    ledger: Ledger<'a>,
    reservations: GuaranteeReservations,
    live: usize,
    root_baseline: u64,
    system_baseline: u64,
}

impl<'a> AdaptivePolicy<'a> {
    /// Admit the policy and make every guarantee physical, before any task.
    ///
    /// Returns `None` when the generation declares no adaptive policy, which
    /// is not a failure: it declares that no component holds an entitlement.
    /// A policy the machine cannot fund fails the boot closed here, which is
    /// the only point at which nothing has been published yet.
    pub fn admit(
        policy: Policy<'a>,
        instances: &[policy::Instance],
        allocator: &mut ObjectAllocator,
    ) -> Result<Self, AdmissionFailure> {
        if let Some(pages) = (0..policy.subject_count())
            .filter_map(|index| policy.subject(index))
            .filter(|subject| subject.maximum_mode == policy::FIXED)
            .map(|subject| subject.maximum_pages)
            .find(|pages| window_pages(*pages, false).is_none())
        {
            return Err(AdmissionFailure::Window {
                pages,
                limit: MAX_WINDOW_PAGES as u64,
            });
        }
        let available = allocator.elastic_inventory();
        let required = (0..policy.entitlement_count())
            .filter_map(|index| policy.entitlement(index))
            .try_fold(0u64, |total, entitlement| {
                total.checked_add(entitlement.guarantee_pages)
            })
            .ok_or(AdmissionFailure::Overflow)?;
        // Reserve first, admit against what the reservation left. A ledger
        // admitted against capacity the reservation has already taken would
        // hand the same bytes out twice.
        let reservations = generation::reserve_private_memory_guarantees(allocator, policy)
            .map_err(|_| AdmissionFailure::Unfundable {
                required,
                available: available.bytes / policy::PAGE_BYTES,
            })?;
        allocator
            .reserve_operational_resources(policy.reserve())
            .map_err(|_| AdmissionFailure::Unfundable {
                required,
                available: allocator.elastic_inventory().bytes / policy::PAGE_BYTES,
            })?;
        let residual = allocator
            .elastic_inventory()
            .checked_add(ledger::Resources {
                slots: policy.reserve().slots,
                descriptors: policy.reserve().descriptors,
                extents: policy.reserve().extents,
                ..ledger::Resources::ZERO
            })
            .map_err(|_| AdmissionFailure::Overflow)?;
        let ledger =
            generation::admit_private_memory_ledger(policy, instances, residual).map_err(|_| {
                AdmissionFailure::Unfundable {
                    required,
                    available: residual.bytes / policy::PAGE_BYTES,
                }
            })?;
        allocator.enable_adaptive_reserve(policy.reserve().bytes);
        Ok(Self {
            policy,
            ledger,
            reservations,
            live: 0,
            root_baseline: allocator.infrastructure_owned_bytes() as u64,
            system_baseline: allocator.system_backing_bytes(),
        })
    }

    /// Report the admitted policy and the reservations behind it.
    ///
    /// Emitted before any task is staged, because everything after it is
    /// spending what this line accounts for. `pool_bytes` is the residual
    /// after reservation: a report of what remains, never a promise about it.
    pub fn report(&self) {
        crate::diagnostic_println!(
            "SLIME_MEM policy entitlements={} subjects={} guarantee_pages={} reserved_bytes={} reserved_slots={} reserved_descriptors={} reserved_extents={} reserved_tables={} pool_bytes={}",
            self.policy.entitlement_count(),
            self.policy.subject_count(),
            self.reservations.guarantee_pages,
            self.reservations.reserved_bytes,
            self.reservations.reserved_slots,
            self.reservations.reserved_descriptors,
            self.reservations.reserved_extents,
            self.reservations.reserved_tables,
            self.ledger.available().bytes,
        );
    }

    /// The address maximum an instance is admitted against, if it is a subject.
    pub fn maximum_pages(&self, instance: &str) -> Option<usize> {
        let index = self
            .policy
            .subject_index(&policy::subject_identity(instance))?;
        let subject = self.policy.subject(index)?;
        if subject.maximum_mode == policy::FIXED {
            // Admission refused every fixed maximum no window can reserve.
            window_pages(subject.maximum_pages, false)
        } else {
            window_pages(self.ledger.pool_pages(), true)
        }
    }

    /// Bind one constructed task's incarnation before it is published.
    ///
    /// A duplicate live incarnation is refused rather than multiplying the
    /// entitlement, and the refusal is recorded: a subject whose replacement
    /// arrived while the original was still live is a lifecycle fault, not a
    /// second holder.
    pub fn bind(&mut self, instance: &str) -> Option<PrivateBinding> {
        let identity = policy::subject_identity(instance);
        let index = self.policy.subject_index(&identity)?;
        let subject = self.policy.subject(index)?;
        let entitlement_index = self.policy.entitlement_index(&subject.entitlement)?;
        let entitlement = self.policy.entitlement(entitlement_index)?;
        let token = EntitlementToken::new(&entitlement.identity);
        let bound = self.ledger.bind_with_maximum(&identity);
        let admitted = bound.is_ok();
        if admitted {
            self.live += 1;
        }
        crate::diagnostic_println!(
            "SLIME_MEM adaptive incarnation instance={} entitlement={} live={} admitted={} cause={}",
            instance,
            token.as_str(),
            self.live,
            u8::from(admitted),
            match bound {
                Ok(_) => "ok",
                Err(ledger::Error::Incarnation) => "duplicate",
                Err(_) => "denied",
            },
        );
        let binding = bound.ok()?;
        Some(PrivateBinding {
            token: binding.token,
            entitlement: entitlement_index,
            reservation: self.reservations.reservation_for(entitlement_index),
            guarantee_pages: usize::try_from(entitlement.guarantee_pages).unwrap_or(usize::MAX),
            maximum_pages: usize::try_from(binding.maximum_pages).unwrap_or(usize::MAX),
            pooled_maximum: subject.maximum_mode != policy::FIXED,
            lent_descriptors: 0,
            lent_slots: 0,
        })
    }

    /// One constructed task's resolved entitlement, read back from the task.
    ///
    /// Emitted for every constructed task on a policy-carrying plane,
    /// including an instance the policy names no subject for: a declared
    /// non-subject that silently printed nothing would be indistinguishable
    /// from a subject whose binding was lost.
    pub fn report_task(
        &self,
        id: TaskId,
        instance: &str,
        binding: Option<PrivateBinding>,
        installed: usize,
        base: usize,
    ) {
        let Some(binding) = binding else {
            crate::diagnostic_println!(
                "SLIME_MEM entitlement task={} instance={} entitlement=none incarnation=0 guarantee=0 maximum=0 mode=none installed=0 base=0x0",
                id.0,
                instance,
            );
            return;
        };
        let token = self
            .policy
            .entitlement(binding.entitlement)
            .map(|entitlement| EntitlementToken::new(&entitlement.identity));
        crate::diagnostic_println!(
            "SLIME_MEM entitlement task={} instance={} entitlement={} incarnation={} guarantee={} maximum={} mode={} installed={} base={:#x}",
            id.0,
            instance,
            token.as_ref().map_or("none", EntitlementToken::as_str),
            // The subject's own incarnation ordinal, which its first life
            // reports as 0. The ledger counts epochs from one so that zero
            // can mean "never bound", so the ordinal is one less; reporting
            // the raw epoch here would number the same incarnation
            // differently in the root's line and in the holder's.
            binding.token.epoch().saturating_sub(1),
            binding.guarantee_pages,
            binding.maximum_pages,
            if binding.pooled_maximum {
                "pool"
            } else {
                "fixed"
            },
            installed,
            base,
        );
    }

    /// Guaranteed pages this incarnation's entitlement can still redeem.
    pub fn redeemable(&self, binding: &PrivateBinding) -> usize {
        usize::try_from(self.ledger.redeemable_guarantee(binding.token).unwrap_or(0)).unwrap_or(0)
    }

    pub fn ledger_mut(&mut self) -> &mut Ledger<'a> {
        &mut self.ledger
    }

    /// Read independent ownership censuses; never balance an unexplained
    /// inventory difference into a system charge.
    pub fn reconcile_ownership(
        &mut self,
        allocator: &ObjectAllocator,
    ) -> Result<(), ledger::Error> {
        let root = (allocator.infrastructure_owned_bytes() as u64)
            .checked_sub(self.root_baseline)
            .ok_or(ledger::Error::Inventory)?;
        let system = allocator
            .system_backing_bytes()
            .checked_sub(self.system_baseline)
            .ok_or(ledger::Error::Inventory)?;
        self.ledger.reconcile_ownership(
            ledger::Resources {
                bytes: root,
                ..ledger::Resources::ZERO
            },
            ledger::Resources {
                bytes: system,
                ..ledger::Resources::ZERO
            },
        )
    }

    fn token_for(&self, entitlement: usize) -> Option<EntitlementToken> {
        self.policy
            .entitlement(entitlement)
            .map(|entry| EntitlementToken::new(&entry.identity))
    }

    /// Record one settled growth, granted or refused.
    ///
    /// Receipt order, one line per nonzero-delta request: a refusal reports
    /// the holder's unchanged page count and its entitlement's unchanged
    /// commitment, which is what makes "the refusal cost nothing" checkable
    /// rather than asserted.
    #[allow(clippy::too_many_arguments)]
    pub fn report_growth(
        &self,
        id: TaskId,
        instance: &str,
        binding: &PrivateBinding,
        delta: usize,
        previous: usize,
        pages: usize,
        guaranteed: usize,
        base: usize,
        outcome: Result<(), &crate::private_memory::elastic::ElasticGrowError>,
    ) {
        let token = self.token_for(binding.entitlement);
        let committed = self.ledger.entitlement_pages(binding.entitlement);
        let pool = self.ledger.available().bytes;
        match outcome {
            Ok(()) => crate::diagnostic_println!(
                "SLIME_MEM adaptive grant task={} instance={} entitlement={} delta={} previous={} pages={} guaranteed={} elastic={} entitlement_committed={} pool_bytes={} base={:#x}",
                id.0,
                instance,
                token.as_ref().map_or("none", EntitlementToken::as_str),
                delta,
                previous,
                pages,
                guaranteed,
                delta - guaranteed,
                committed,
                pool,
                base,
            ),
            Err(error) => crate::diagnostic_println!(
                "SLIME_MEM adaptive refused task={} instance={} entitlement={} delta={} pages={} cause={} entitlement_committed={} pool_bytes={}",
                id.0,
                instance,
                token.as_ref().map_or("none", EntitlementToken::as_str),
                delta,
                pages,
                refusal_cause(error),
                committed,
                pool,
            ),
        }
    }

    /// Name the resource behind one refused growth and the pool beside it.
    ///
    /// Follows the refusal line it explains. An exhaustion claim is only
    /// reconcilable if the limiting resource, the ledger's residual and the
    /// allocator's residual are reported separately, at the moment of refusal:
    /// ordinary bytes the ledger withholds as a reserve, bytes metadata already
    /// funded, and bytes no aligned extent can place are three different
    /// reasons a page was not served. The census line after it breaks the
    /// allocator residual down by owner.
    pub fn report_limit(
        &self,
        allocator: &ObjectAllocator,
        id: TaskId,
        instance: &str,
        delta: usize,
        error: &crate::private_memory::elastic::ElasticGrowError,
    ) {
        let (resource, required, available) = error.limit();
        let inventory = allocator.elastic_inventory();
        crate::diagnostic_println!(
            "SLIME_MEM adaptive limit task={} instance={} delta={} resource={} required={} available={} ledger_pool={} inventory_bytes={} inventory_slots={} largest_block={}",
            id.0,
            instance,
            delta,
            resource,
            required,
            available,
            self.ledger.available().bytes,
            inventory.bytes,
            inventory.slots,
            allocator.largest_aligned_ordinary_block(),
        );
        crate::diagnostic_println!(
            "SLIME_MEM funding reserve={} root_owned={} system_owned={} common_held={} inventory_bytes={}",
            self.ledger.operational_reserve().bytes,
            self.ledger.root_owned().bytes,
            self.ledger.system_owned().bytes,
            self.ledger.common_held().bytes,
            inventory.bytes,
        );
        crate::diagnostic_println!(
            "SLIME_MEM operational remaining={} spent={}",
            self.ledger.remaining_operational_reserve().bytes,
            self.ledger.operational_spent().bytes,
        );
        allocator.report_elastic_census("limit");
    }

    /// Refuse a growth asked for by a task the policy names no subject for.
    ///
    /// Deny-by-default, reported in the adjudication line rather than left to
    /// the fixed path's window refusal: on a plane that carries a policy, the
    /// reason such a task cannot grow is that it holds no entitlement, and a
    /// transcript that said "reservation" instead would describe the symptom.
    /// A zero delta is a size query and still answers.
    pub fn refuse_unbound(&self, id: TaskId, instance: &str, delta: usize, pages: usize) {
        crate::diagnostic_println!(
            "SLIME_MEM adaptive refused task={} instance={} entitlement=none delta={} pages={} cause=entitlement entitlement_committed=0 pool_bytes={}",
            id.0,
            instance,
            delta,
            pages,
            self.ledger.available().bytes,
        );
    }

    /// Retire one incarnation, returning its capacity to its entitlement.
    ///
    /// `revoked` is whether the task's backing actually went away. A failed
    /// revoke quarantines the incarnation instead of refunding it: capacity
    /// the machine has not recovered is never reported as returned.
    pub fn retire(
        &mut self,
        allocator: &mut ObjectAllocator,
        id: TaskId,
        instance: &str,
        binding: &PrivateBinding,
        revoked: bool,
        returned_pages: usize,
    ) {
        // What this incarnation drew from its entitlement's withheld funding,
        // read before the ledger forgets it. A successful revoke returned the
        // descriptors and CSlots to the common pool, so the entitlement's
        // floor has to be restored or the next incarnation cannot be funded;
        // a failed revoke returns nothing, so neither does this.
        let held = self
            .ledger
            .guaranteed_held(binding.token)
            .unwrap_or(ledger::Resources::ZERO);
        let outcome = self.ledger.retire(binding.token, revoked);
        if outcome.is_ok()
            && let Some(reservation) = binding.reservation
        {
            allocator.restore_reserved_resources(
                reservation,
                usize::try_from(held.descriptors).unwrap_or(0),
                usize::try_from(held.slots).unwrap_or(0),
            );
        }
        let quarantined = u8::from(outcome.is_err());
        if outcome.is_ok() {
            self.live = self.live.saturating_sub(1);
        }
        let token = self.token_for(binding.entitlement);
        crate::diagnostic_println!(
            "SLIME_MEM adaptive retired task={} instance={} entitlement={} returned_pages={} entitlement_committed={} quarantined={}",
            id.0,
            instance,
            token.as_ref().map_or("none", EntitlementToken::as_str),
            if outcome.is_ok() { returned_pages } else { 0 },
            self.ledger.entitlement_pages(binding.entitlement),
            quarantined,
        );
    }
}

/// Why an adaptive policy could not be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionFailure {
    Malformed,
    Overflow,
    Unfundable {
        required: u64,
        available: u64,
    },
    /// A fixed maximum no window can reserve.
    Window {
        pages: u64,
        limit: u64,
    },
}

impl AdmissionFailure {
    /// The fail-closed record. Printed before anything is published, and the
    /// boot stops: a graph launched against an unfunded guarantee looks
    /// healthy until the promise is redeemed.
    pub fn report(self) {
        match self {
            Self::Unfundable {
                required,
                available,
            } => crate::diagnostic_println!(
                "SLIME_MEM FAIL adaptive guarantee exceeds inventory required={required} available={available} published=0"
            ),
            Self::Window { pages, limit } => crate::diagnostic_println!(
                "SLIME_MEM FAIL adaptive maximum exceeds window pages={pages} limit={limit} published=0"
            ),
            other => crate::diagnostic_println!(
                "SLIME_MEM FAIL adaptive guarantee exceeds inventory required=0 available=0 published=0 detail={other:?}"
            ),
        }
    }
}
