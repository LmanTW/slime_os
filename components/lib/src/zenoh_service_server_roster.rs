//! The roster of the Zenoh service's holders: where each stands, and when the service is done.
//!
//! A holder is idle until it attaches, attached until it detaches, and settled once it has detached, died or expired.
//! The service ends when every holder is settled, so a holder that faults or never detaches cannot keep it running.
//! Death is what the root's supervision status reports for the holder's task, as `network-service` observes a dead
//! client. A holder that is alive and has not detached expires when the service has run for the wait.
//!
//! The roster holds no session, buffer or loan. The component closes the session of a holder that the roster reports as
//! reclaimed, and calls [`Server::lose`](crate::zenoh_service_server::Server::lose) so that holder is refused from then
//! on. `scripts/lib/zenoh_holder_fault_exam.py` owns every line the test of this module must print.

/// Where a holder stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No session. The holder may attach.
    Idle,
    /// The holder attached and has not detached.
    Attached,
    /// The holder detached or aborted.
    Detached,
    /// The root reported the holder's task dead.
    Dead,
    /// The holder was alive and had not detached when the wait ended.
    Expired,
}

impl Standing {
    /// Whether the service has nothing more to wait for from this holder.
    pub const fn settled(self) -> bool {
        !matches!(self, Self::Idle | Self::Attached)
    }
}

/// What a death report changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Death {
    /// An attached holder died. Its session must be closed.
    Reclaimed,
    /// An idle holder died. It has no session, so there is nothing to reclaim.
    Noted,
    /// The holder had settled already, or its death was reported before. Nothing changed.
    Ignored,
}

/// The standing of each of `H` holders, of which the first `count` are named by the grants.
#[derive(Debug)]
pub struct Roster<const H: usize> {
    standing: [Standing; H],
    count: usize,
    wait_ms: i64,
}

impl<const H: usize> Roster<H> {
    /// A roster of `count` holders, at most `H`, each of which expires `wait_ms` after the service started.
    pub const fn new(count: usize, wait_ms: i64) -> Self {
        Self {
            standing: [Standing::Idle; H],
            count: if count < H { count } else { H },
            wait_ms,
        }
    }

    /// Where `holder` stands, or `None` for a holder the grants do not name.
    pub fn standing(&self, holder: usize) -> Option<Standing> {
        if holder < self.count {
            self.standing.get(holder).copied()
        } else {
            None
        }
    }

    /// Records an attach. Only an idle holder attaches, and a settled holder never does again.
    pub fn attach(&mut self, holder: usize) -> bool {
        self.change(holder, Standing::Idle, Standing::Attached)
    }

    /// Records a detach or an abort. Only an attached holder detaches.
    pub fn detach(&mut self, holder: usize) -> bool {
        self.change(holder, Standing::Attached, Standing::Detached)
    }

    /// Records that the root reported `holder`'s task dead. A holder settles once, so a report after the holder
    /// detached, expired or died changes nothing.
    pub fn death(&mut self, holder: usize) -> Death {
        match self.standing(holder) {
            Some(Standing::Attached) => {
                self.set(holder, Standing::Dead);
                Death::Reclaimed
            }
            Some(Standing::Idle) => {
                self.set(holder, Standing::Dead);
                Death::Noted
            }
            _ => Death::Ignored,
        }
    }

    /// Expires every holder that is idle or attached once `now_ms` has reached the wait, and marks each one it expired.
    /// One millisecond before the wait ends it expires none.
    pub fn expire(&mut self, now_ms: i64) -> [bool; H] {
        let mut expired = [false; H];
        if now_ms < self.wait_ms {
            return expired;
        }
        for (standing, flag) in self
            .standing
            .iter_mut()
            .zip(expired.iter_mut())
            .take(self.count)
        {
            if matches!(*standing, Standing::Idle | Standing::Attached) {
                *standing = Standing::Expired;
                *flag = true;
            }
        }
        expired
    }

    /// Whether every holder the grants name is settled.
    pub fn done(&self) -> bool {
        self.standing
            .iter()
            .take(self.count)
            .all(|standing| standing.settled())
    }

    fn change(&mut self, holder: usize, from: Standing, to: Standing) -> bool {
        if self.standing(holder) != Some(from) {
            return false;
        }
        self.set(holder, to);
        true
    }

    fn set(&mut self, holder: usize, to: Standing) {
        if let Some(standing) = self.standing.get_mut(holder) {
            *standing = to;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Death, Roster, Standing};
    use crate::zenoh_service::exam::params;
    use crate::zenoh_service::{Core, OverLink, Row};
    use crate::zenoh_service_link::pair::{Far, Svc, pair};
    use crate::zenoh_service_server::{HEADER_BYTES, Server};
    use slime_proto::zenoh_service_client as wire;
    use slime_proto::zenoh_service_client_wire::WireServiceRequest;
    use std::string::{String, ToString};
    use std::vec::Vec;

    const KEY: &str = "0/slime_holder_fault/key";
    const WAIT_MS: i64 = 30000;
    const START: i64 = 100;
    const PAGE: usize = 4096;
    const GID: [u8; 16] = [0xe0; 16];

    /// The scripted events of each scenario. `scripts/lib/zenoh_holder_fault_exam.py` writes the same table.
    const SCENARIOS: [(&str, &[&str]); 8] = [
        (
            "fault-after-attach",
            &[
                "attach0", "attach1", "publish0", "death0", "publish0", "take0", "attach0",
                "detach0", "publish1", "take1", "take1", "take1", "detach1",
            ],
        ),
        (
            "fault-before-attach",
            &["death0", "attach0", "attach1", "detach1"],
        ),
        (
            "never-detach",
            &[
                "attach0",
                "attach1",
                "detach0",
                "tick29999",
                "tick30000",
                "detach1",
            ],
        ),
        (
            "never-attach",
            &["attach0", "detach0", "tick30000", "attach1"],
        ),
        ("both-fault", &["death0", "death1"]),
        (
            "death-after-detach",
            &["attach0", "detach0", "death0", "attach1", "detach1"],
        ),
        (
            "death-after-expiry",
            &["attach0", "tick30000", "death0", "death1", "detach0"],
        ),
        (
            "silent-live-holder",
            &[
                "attach0", "attach1", "detach1", "tick100", "publish0", "take0",
            ],
        ),
    ];

    fn request(op: i64, row: u16, sequence: i64) -> [u8; 32] {
        WireServiceRequest {
            magic: wire::SERVICE_MAGIC as u32,
            version: wire::FORMAT_VERSION as u16,
            op: op as u8,
            flags: 0,
            row,
            reserved: [0; 2],
            sequence,
            reserved2: [0; 12],
        }
        .encode()
    }

    fn status(completion: &[u8]) -> i64 {
        i64::from(i32::from_le_bytes(
            completion[8..12].try_into().expect("four bytes"),
        ))
    }

    fn word(standing: Standing) -> &'static str {
        match standing {
            Standing::Idle => "idle",
            Standing::Attached => "attached",
            Standing::Detached => "detached",
            Standing::Dead => "dead",
            Standing::Expired => "expired",
        }
    }

    /// What a refusal is called in a line. Only a denial is a status the exam expects.
    fn refusal(code: i64) -> String {
        if code == wire::STATUS_DENIED {
            "denied".to_string()
        } else {
            format!("status{code}")
        }
    }

    /// One service run: both holders have one row that publishes and subscribes the same key, so a publication reaches
    /// both rings whatever either holder's standing.
    struct World {
        server: Server<2>,
        core: Core<'static, 2, 4, 12, 2>,
        over: OverLink<'static, 12>,
        link: Svc,
        _peer: Far,
        handle: crate::zenoh_link::LinkHandle,
        roster: Roster<2>,
        sequence: i64,
        tick: u64,
    }

    impl World {
        fn new() -> Self {
            let (link, peer, handle, _) = pair();
            let rows = [0, 1].map(|holder| Row {
                holder,
                key: KEY,
                publish: true,
                subscribe: true,
            });
            Self {
                server: Server::new(),
                core: Core::new(&rows, GID, &params()).expect("the grants"),
                over: OverLink::new(),
                link,
                _peer: peer,
                handle,
                roster: Roster::new(2, WAIT_MS),
                sequence: 0,
                tick: 100,
            }
        }

        fn ring(
            &mut self,
            holder: usize,
            bytes: &[u8],
            payload: &[u8],
            page: &mut [u8],
        ) -> [u8; 24] {
            self.tick += 1;
            self.server
                .request(
                    &mut self.core,
                    &mut self.over,
                    &mut self.link,
                    self.handle,
                    holder,
                    bytes,
                    payload,
                    page,
                    START,
                    self.tick,
                )
                .completion
        }

        fn lose(&mut self, holder: usize) {
            self.server.lose(holder);
        }

        fn event(&mut self, event: &str) -> String {
            if let Some(time) = event.strip_prefix("tick") {
                let expired = self.roster.expire(time.parse().expect("a time"));
                let held: Vec<String> = (0..2)
                    .filter(|holder| expired[*holder])
                    .map(|holder| holder.to_string())
                    .collect();
                for (holder, gone) in expired.iter().enumerate() {
                    if *gone {
                        self.lose(holder);
                    }
                }
                return format!(
                    "expired:{}",
                    if held.is_empty() {
                        "none".to_string()
                    } else {
                        held.join("+")
                    }
                );
            }
            let (verb, holder) = event.split_at(event.len() - 1);
            let holder: usize = holder.parse().expect("a holder");
            let mut page = [0u8; PAGE];
            match verb {
                "attach" | "detach" => {
                    let op = if verb == "attach" {
                        wire::OP_ATTACH
                    } else {
                        wire::OP_DETACH
                    };
                    let answer = self.server.control(&self.core, holder, &request(op, 0, 0));
                    let code = status(&answer.completion);
                    if code != 0 {
                        return refusal(code);
                    }
                    let agreed = if verb == "attach" {
                        self.roster.attach(holder)
                    } else {
                        self.roster.detach(holder)
                    };
                    assert!(agreed, "the roster refused a {verb} the server accepted");
                    "ok".to_string()
                }
                "death" => match self.roster.death(holder) {
                    Death::Reclaimed => {
                        self.lose(holder);
                        "reclaimed".to_string()
                    }
                    Death::Noted => {
                        self.lose(holder);
                        "noted".to_string()
                    }
                    Death::Ignored => "ignored".to_string(),
                },
                "publish" => {
                    let sequence = self.sequence;
                    let completion = self.ring(
                        holder,
                        &request(wire::OP_PUBLISH, 0, sequence),
                        &[sequence as u8],
                        &mut page,
                    );
                    let code = status(&completion);
                    if code != 0 {
                        return refusal(code);
                    }
                    self.sequence += 1;
                    let reached =
                        u32::from_le_bytes(completion[16..20].try_into().expect("four bytes"));
                    let flags =
                        u32::from_le_bytes(completion[20..24].try_into().expect("four bytes"));
                    let peer = if flags & wire::FLAG_PEER_SENT as u32 != 0 {
                        "sent"
                    } else {
                        "none"
                    };
                    format!("ok:reached={reached}:peer={peer}")
                }
                "take" => {
                    let completion =
                        self.ring(holder, &request(wire::OP_TAKE, 0, 0), &[], &mut page);
                    let code = status(&completion);
                    if code != 0 {
                        return refusal(code);
                    }
                    match i64::from(completion[7]) {
                        wire::ITEM_NONE => "none".to_string(),
                        wire::ITEM_SAMPLE => {
                            let sequence =
                                i64::from_le_bytes(page[..8].try_into().expect("eight bytes"));
                            assert!(HEADER_BYTES <= page.len());
                            format!("sample:{sequence}")
                        }
                        other => format!("item{other}"),
                    }
                }
                other => panic!("an event the exam does not script: {other}"),
            }
        }

        fn states(&self) -> String {
            (0..2)
                .map(|holder| word(self.roster.standing(holder).expect("a named holder")))
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    /// The holder roster: a holder that faults is reclaimed, a holder that never detaches expires, and the other
    /// holder is served throughout. The test prints one `[zenoh-exam] holderfault ...` line for each scripted event.
    /// The checker looks for this test by its path.
    #[test]
    fn the_holder_fault_exam() {
        for (name, events) in SCENARIOS {
            let mut world = World::new();
            for (number, event) in events.iter().enumerate() {
                let result = world.event(event);
                println!(
                    "[zenoh-exam] holderfault {name} {} {event} {result} states {} done {}",
                    number + 1,
                    world.states(),
                    u8::from(world.roster.done()),
                );
            }
        }
        println!("[zenoh-exam] holderfault ok a-faulted-or-silent-holder-is-reclaimed");
    }
}
