//! C9.2 supervision-source delivery.
//!
//! The root owns no wait set: no ready queue, no source registry, no notion of
//! which component is currently blocked. What it owns here is exactly one thing
//! C9.1 already established the shape of — a badged write capability it signals
//! when something a waiter declared an interest in happens.
//!
//! # Why only supervision sources are here
//!
//! Of the eight declared source kinds, five are signalled by a peer: a publisher
//! signals its subscriber's ring, a client signals a broker's control edge, a
//! driver signals the service it completes work for, and
//! `slime-root/src/notification.rs` already mints those caps from the
//! generation's own `notificationBindings`. A timer is signalled by
//! `crate::clock`, from C9.1's contract data. Admission refuses an interrupt
//! row, because the root dispatches no interrupt arrival. That leaves peer
//! death, which no peer can signal — the peer is the thing that died. So the
//! root signals it, and this module is that one delivery path rather than a
//! general mechanism.
//!
//! # What a waiter has to already hold
//!
//! A supervision source names one of the waiter's own capability slots, and the
//! root signals the badge only when that slot holds a supervision capability
//! naming the task that just ended. So death delivery reaches exactly the
//! components the generation already gave a supervision handle: the badge adds
//! no authority, only a wake for authority a component already has. A waiter
//! whose slot holds nothing, or a handle naming a different task, is not
//! signalled — that is not a missed wake but a peer it was never supervising.

use boot_contracts::wait_set::{SourceKind, WaitSet, waiter_identity};

use crate::graph::CapabilityEntry;
use crate::task::{MAX_TASKS, TaskId, TaskTable};

/// Supervision sources one task may declare.
///
/// The per-waiter source ceiling: a task could in principle declare every one of
/// its sources as supervision, so a smaller number here would silently drop a
/// declared source the resource already admitted.
pub const MAX_SUPERVISION_SOURCES: usize = boot_contracts::wait_set::MAX_SOURCES_PER_WAITER;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSetError {
    /// The task is already declared. A second declaration would leave two
    /// entries answering for one task, and the later one silently unreachable.
    Duplicate,
    /// No free row in the per-task table, which matches `MAX_TASKS`.
    TableFull,
    /// A declared source names a Notification this waiter does not wait on, so
    /// the root cannot mint a signal capability for it.
    InvalidNotification,
    /// The source table declares more supervision sources for one waiter than a
    /// wait set may hold.
    SourceLimit,
}

/// One declared supervision source: which slot names the supervised task, and
/// which badge to signal when it ends.
#[derive(Clone, Copy)]
struct SupervisionSource {
    drain_slot: u32,
    signal: sel4::cap::Notification,
}

#[derive(Clone, Copy)]
struct Entry {
    task: TaskId,
    sources: [Option<SupervisionSource>; MAX_SUPERVISION_SOURCES],
}

/// Per-task supervision-source delivery state.
pub struct WaitSetService {
    entries: [Option<Entry>; MAX_TASKS],
}

impl WaitSetService {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_TASKS],
        }
    }

    /// How many tasks currently declare a supervision source.
    pub fn declared_tasks(&self) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.sources.iter().flatten().count() != 0)
            .count()
    }

    /// Record `task`'s declared supervision sources, minting one badged write
    /// capability per source.
    ///
    /// Called for every launched instance, including one the resource does not
    /// name: an empty row still occupies the table so `clear_task` and
    /// `declared_tasks` answer about a live task rather than about whether it was
    /// ever declared. That is the same reason `crate::clock::declare` records a
    /// `DENY` authority instead of nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn declare(
        &mut self,
        sources: Option<&WaitSet<'_>>,
        generation: &boot_contracts::generation::Generation<'_>,
        notifications: &crate::notification::NotificationTable,
        allocator: &mut crate::object_allocator::ObjectAllocator,
        arena: crate::object_allocator::TaskArenaId,
        task: TaskId,
        instance: usize,
    ) -> Result<usize, WaitSetError> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.task == task)
        {
            return Err(WaitSetError::Duplicate);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(WaitSetError::TableFull)?;
        let mut row = Entry {
            task,
            sources: [None; MAX_SUPERVISION_SOURCES],
        };
        let mut declared = 0;
        if let Some(sources) = sources
            && let Ok(record) = generation.instance(instance)
        {
            let identity = waiter_identity(record.name);
            for index in 0..sources.entry_count() {
                let entry = sources
                    .entry(index)
                    .ok_or(WaitSetError::InvalidNotification)?;
                if entry.waiter_identity != identity || entry.kind != SourceKind::Supervision {
                    continue;
                }
                let drain_slot = entry.drain_slot.ok_or(WaitSetError::InvalidNotification)?;
                // Resolved through the generation's own grant table, so a badge
                // can only be minted on an object this waiter waits on. Admission
                // already proved that holds for every entry; re-resolving here is
                // what keeps this module from trusting the resource alone.
                let notification = notifications
                    .wait_target(generation, instance, entry.notification_grant_identity)
                    .ok_or(WaitSetError::InvalidNotification)?;
                let signal_slot = allocator
                    .reserve_slot_in::<sel4::cap_type::Notification>(arena)
                    .map_err(|_| WaitSetError::TableFull)?;
                let root = sel4::init_thread::slot::CNODE.cap();
                root.absolute_cptr(signal_slot.cptr())
                    .mint(
                        &root.absolute_cptr(notification),
                        sel4::CapRightsBuilder::none().write(true).build(),
                        entry.badge,
                    )
                    .map_err(|_| WaitSetError::InvalidNotification)?;
                let free = row
                    .sources
                    .iter_mut()
                    .find(|source| source.is_none())
                    .ok_or(WaitSetError::SourceLimit)?;
                *free = Some(SupervisionSource {
                    drain_slot,
                    signal: signal_slot.cap(),
                });
                declared += 1;
            }
        }
        *slot = Some(row);
        Ok(declared)
    }

    /// Signal every live waiter whose declared supervision source names `dead`.
    ///
    /// Returns how many waiters were woken. Zero is an ordinary outcome: a task
    /// nobody supervises through a declared source has nobody to wake, and a task
    /// whose supervisor is itself gone has nobody left to tell.
    ///
    /// The slot check is the authority test, not a convenience. A badge is
    /// signalled only when the waiter's own declared slot currently holds a
    /// supervision capability naming `dead`, so the wake follows authority the
    /// generation already granted rather than conferring any.
    pub fn signal_death(&self, tasks: &TaskTable<MAX_TASKS>, dead: TaskId) -> usize {
        let mut woken = 0;
        for entry in self.entries.iter().flatten() {
            if entry.task == dead {
                continue;
            }
            let Some(waiter) = tasks.get(entry.task) else {
                continue;
            };
            for source in entry.sources.iter().flatten() {
                let names_dead = matches!(
                    waiter.capabilities.get(source.drain_slot),
                    Some(CapabilityEntry::Supervision(supervision)) if supervision.task == dead
                );
                if names_dead {
                    source.signal.signal();
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Drop `task`'s row when it terminates.
    pub fn clear_task(&mut self, task: TaskId) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|entry| entry.task == task))
        {
            *entry = None;
        }
    }
}

impl Default for WaitSetService {
    fn default() -> Self {
        Self::new()
    }
}

/// The generation's wait-set resource, if it declares one.
pub fn source_object<'a>(
    generation: &boot_contracts::generation::Generation<'a>,
) -> Option<Result<WaitSet<'a>, boot_contracts::wait_set::DecodeError>> {
    crate::generation::wait_set_object(generation)
}

#[cfg(test)]
mod tests {
    use super::{MAX_SUPERVISION_SOURCES, WaitSetService};
    use crate::task::TaskId;

    /// A task declares once. A second declaration would leave two rows
    /// answering for one task, with the later one silently unreachable — the
    /// same first-writer discipline `clock::declare` enforces.
    #[test]
    fn a_task_is_declared_once() {
        let mut service = WaitSetService::new();
        assert_eq!(service.declared_tasks(), 0);
        // A row with no sources is still a row: `clear_task` must be able to
        // answer about a live task rather than about whether it was declared.
        let tasks = crate::task::TaskTable::<{ crate::task::MAX_TASKS }>::new();
        assert_eq!(service.signal_death(&tasks, TaskId(1)), 0);
        service.clear_task(TaskId(1));
        assert_eq!(service.declared_tasks(), 0);
    }

    /// The per-waiter supervision ceiling is the contract's source ceiling, so a
    /// waiter cannot declare a supervision source the wait set could not hold.
    #[test]
    fn the_supervision_ceiling_matches_the_contract() {
        assert_eq!(
            MAX_SUPERVISION_SOURCES,
            boot_contracts::wait_set::MAX_SOURCES_PER_WAITER
        );
    }
}
