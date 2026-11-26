//! The liveliness exam: a client-role Profile 0 session answers a router's INTEREST for tokens, and a listener
//! admits a Client.
//!
//! A client-role connector is opened against a router handshake, holds tokens, and is asked INTERESTs. The test
//! prints one `[zenoh-exam] liveliness ...` line for each scenario, frame, count and refusal.
//! `scripts/lib/zenoh_liveliness_exam.py` owns what those lines must be, and `scripts/check/check-zenoh-profile0.py
//! --slice liveliness` runs this test and judges them.

use crate::zenoh_profile0::MAX_BATCH_BYTES;
use crate::zenoh_profile0::encode;
use crate::zenoh_profile0::session::{Config, Role, Session, SessionError, State};
use std::string::String;
use std::vec::Vec;

const ANSWERER_SN: u32 = 7000;
const ROUTER_SN: u32 = 100;
const LEASE_MS: u64 = 10_000;
const KEY: &str = "@/liveliness/slime/node";
const KEY_SECOND: &str = "@/liveliness/slime/second";
const KEY_ROS: &str = "@ros2_lv/0";
const KEY_UNDER: &str = "@ros2_lv/0/slime_node";
const KEY_OTHER: &str = "@/liveliness/slime/elsewhere";
const ZID: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

const MODE_FINAL: u8 = 0;
const MODE_CURRENT: u8 = 1;
const MODE_FUTURE: u8 = 2;
const MODE_CURRENT_FUTURE: u8 = 3;
const TOKENS: u8 = 0x08;
const RESTRICTED: u8 = 0x70;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("a string takes the digits");
    }
    out
}

fn leb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return out;
        }
        out.push(low | 0x80);
    }
}

/// A reliable FRAME holding `messages`.
fn frame(sn: u32, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = std::vec![0x25];
    out.extend(leb(sn));
    for message in messages {
        out.extend(message);
    }
    out
}

/// What an INTEREST can say on the wire, as the reference writes it.
struct Interest<'a> {
    id: u32,
    mode: u8,
    options: u8,
    key: Option<&'a str>,
    qos: bool,
    unknown_extension: bool,
}

impl<'a> Interest<'a> {
    fn tokens(id: u32, mode: u8) -> Self {
        Self {
            id,
            mode,
            options: TOKENS,
            key: None,
            qos: false,
            unknown_extension: false,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let stated = self.qos || self.unknown_extension;
        let mut out = std::vec![25 | (self.mode << 5) | if stated { 0x80 } else { 0 }];
        out.extend(leb(self.id));
        if self.mode != MODE_FINAL {
            out.push(self.options | if self.key.is_some() { RESTRICTED } else { 0 });
            if let Some(key) = self.key {
                out.extend(leb(0));
                out.extend(leb(key.len() as u32));
                out.extend(key.as_bytes());
            }
        }
        if self.qos {
            out.extend([0x21, 0x08]);
        }
        if self.unknown_extension {
            out.extend([0x5F, 0x02, 0x00, 0x00]);
        }
        out
    }
}

fn config(sn: u32, zid: &'static [u8], cookie: &'static [u8]) -> Config<'static> {
    Config {
        zid,
        lease_ms: LEASE_MS,
        initial_sn: sn,
        cookie,
    }
}

fn feed(session: &mut Session, batch: &[u8]) -> Result<Vec<u8>, SessionError> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(batch, 1, &mut out)?;
    Ok(out[..outcome.sent].to_vec())
}

/// A session that answers and the sequence number of the router's next frame.
struct Answerer {
    session: Session,
    router_sn: u32,
}

impl Answerer {
    /// A connector, with the client role if `client`, opened through the handshake of a router that accepts batches
    /// of `peer_batch` bytes.
    fn open(client: bool, peer_batch: u16) -> Self {
        let mut session = Session::new(Role::Connector, &config(ANSWERER_SN, &[0xA1; 8], &[]))
            .expect("connector");
        if client {
            session = session.with_client_role().expect("the role");
        }
        let mut out = [0u8; MAX_BATCH_BYTES];
        session.connect(0, &mut out).expect("connect");
        let mut ack = [0u8; MAX_BATCH_BYTES];
        let length = encode::init_ack(&mut ack, &[0xB2; 8], peer_batch, &[0xC0]).expect("INIT_ACK");
        if client {
            // The router's INIT_ACK names whatami 0.
            ack[2] &= !0x03;
        }
        feed(&mut session, &ack[..length]).expect("the INIT_ACK is taken");
        let length = encode::open_ack(&mut ack, LEASE_MS, ROUTER_SN).expect("OPEN_ACK");
        feed(&mut session, &ack[..length]).expect("the OPEN_ACK is taken");
        assert_eq!(session.state(), State::Open);
        Self {
            session,
            router_sn: ROUTER_SN,
        }
    }

    fn declare(&mut self, id: u32, key: &str) {
        let mut out = [0u8; MAX_BATCH_BYTES];
        self.session
            .send_declare_token(id, key, &mut out)
            .expect("the token is declared");
    }

    fn withdraw(&mut self, id: u32) -> Vec<u8> {
        let mut out = [0u8; MAX_BATCH_BYTES];
        let outcome = self
            .session
            .send_undeclare_token(id, &mut out)
            .expect("the token is withdrawn");
        out[..outcome.sent].to_vec()
    }

    /// The router sends `message` in the next frame it owns. A frame the session refuses keeps its number.
    fn ask(&mut self, messages: &[Vec<u8>]) -> Result<Vec<u8>, SessionError> {
        let sent = feed(&mut self.session, &frame(self.router_sn, messages));
        if sent.is_ok() {
            self.router_sn += 1;
        }
        sent
    }

    fn held(&self) -> usize {
        self.session.tokens_held().len()
    }
}

fn init_syn_named(whatami: u8) -> Vec<u8> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let length = encode::init_syn_client(&mut out, &ZID, 512).expect("INIT_SYN");
    out[2] = (out[2] & !0x03) | whatami;
    out[..length].to_vec()
}

fn listener(admit: bool) -> Session {
    let session =
        Session::new(Role::Listener, &config(9000, &[0xB2; 8], &[0xC0; 32])).expect("listener");
    if admit {
        session.with_client_admission().expect("admission")
    } else {
        session
    }
}

const OK: [&str; 11] = [
    "current-interest-answers-each-token-then-final",
    "current-future-interest-answers-like-current",
    "future-interest-answers-nothing",
    "final-interest-answers-nothing",
    "no-token-answers-final-alone",
    "withdrawn-token-is-not-answered",
    "restricted-interest-answers-the-tokens-under-its-key",
    "interest-with-the-qos-extension-is-answered",
    "refused-answer-spends-no-sequence-number",
    "listener-admits-a-client-when-configured",
    "default-configuration-unchanged",
];

const FRAMES: [&str; 8] = [
    "answer-current-interest-7",
    "answer-current-future-interest-8",
    "answer-empty-interest-9",
    "answer-restricted-interest-11",
    "answer-interest-with-qos-12",
    "next-frame-after-refused-answer",
    "init-ack-to-a-client",
    "answer-after-withdrawal-interest-10",
];

const HELD: [&str; 4] = [
    "answered-two",
    "after-withdrawal",
    "refused-answer",
    "after-restricted-answer",
];

const REFUSED: [&str; 15] = [
    "interest-in-subscribers",
    "interest-in-queryables",
    "interest-in-key-expressions",
    "interest-restricted-to-a-key-without-a-wildcard-suffix",
    "interest-restricted-with-a-wildcard-inside-the-key",
    "interest-restricted-and-in-key-expressions-only",
    "interest-in-key-expressions-and-tokens-unrestricted",
    "interest-in-tokens-and-subscribers",
    "interest-with-an-unknown-extension",
    "interest-to-a-session-with-no-client-role",
    "two-interests-in-one-frame",
    "answer-beyond-the-peer-batch",
    "client-init-to-a-listener-that-admits-none",
    "router-init-to-a-listener",
    "reserved-role-init",
];

/// Prints `kind` lines in the order the exam names them; every name must have been recorded once.
fn emit(kind: &str, order: &[&str], seen: &[(String, String)]) {
    assert_eq!(
        seen.len(),
        order.len(),
        "{kind}: a line is missing or repeated"
    );
    for name in order {
        let (_, value) = seen
            .iter()
            .find(|(seen_name, _)| seen_name == name)
            .unwrap_or_else(|| panic!("{kind} {name} was not recorded"));
        if value.is_empty() {
            std::println!("[zenoh-exam] liveliness {kind} {name}");
        } else {
            std::println!("[zenoh-exam] liveliness {kind} {name} {value}");
        }
    }
}

fn record(into: &mut Vec<(String, String)>, name: &str, value: impl Into<String>) {
    into.push((String::from(name), value.into()));
}

#[test]
fn the_liveliness_exam() {
    let mut ok = Vec::new();
    let mut frames = Vec::new();
    let mut held = Vec::new();
    let mut refused = Vec::new();

    // Two tokens, then a Current INTEREST: each token, then a DeclareFinal, in the frame after the two declarations.
    let mut answerer = Answerer::open(true, 512);
    answerer.declare(1, KEY);
    answerer.declare(2, KEY_SECOND);
    let answer = answerer
        .ask(&[Interest::tokens(7, MODE_CURRENT).bytes()])
        .expect("the INTEREST is answered");
    record(&mut frames, "answer-current-interest-7", hex(&answer));
    record(&mut held, "answered-two", answerer.held().to_string());
    // Future and Final answer nothing, and a later answer still takes the next number.
    let nothing = answerer
        .ask(&[Interest::tokens(8, MODE_FUTURE).bytes()])
        .expect("a Future INTEREST is taken");
    assert!(
        nothing.is_empty(),
        "a Future INTEREST is answered with nothing"
    );
    record(&mut ok, "future-interest-answers-nothing", "");
    let nothing = answerer
        .ask(&[Interest::tokens(7, MODE_FINAL).bytes()])
        .expect("a Final INTEREST is taken");
    assert!(
        nothing.is_empty(),
        "a Final INTEREST is answered with nothing"
    );
    record(&mut ok, "final-interest-answers-nothing", "");
    record(
        &mut ok,
        "current-interest-answers-each-token-then-final",
        "",
    );

    // CurrentFuture answers the current tokens as Current does.
    let mut answerer = Answerer::open(true, 512);
    answerer.declare(1, KEY);
    answerer.declare(2, KEY_SECOND);
    let answer = answerer
        .ask(&[Interest::tokens(8, MODE_CURRENT_FUTURE).bytes()])
        .expect("the INTEREST is answered");
    record(
        &mut frames,
        "answer-current-future-interest-8",
        hex(&answer),
    );
    record(&mut ok, "current-future-interest-answers-like-current", "");

    // No token: the DeclareFinal alone, at the first number.
    let mut answerer = Answerer::open(true, 512);
    let answer = answerer
        .ask(&[Interest::tokens(9, MODE_CURRENT).bytes()])
        .expect("the INTEREST is answered");
    record(&mut frames, "answer-empty-interest-9", hex(&answer));
    record(&mut ok, "no-token-answers-final-alone", "");

    // A restricted INTEREST answers the tokens under its prefix and not the other.
    let mut answerer = Answerer::open(true, 512);
    answerer.declare(1, KEY_UNDER);
    answerer.declare(2, KEY_OTHER);
    let restricted = Interest {
        options: TOKENS | 0x01,
        key: Some(&std::format!("{KEY_ROS}/**")),
        ..Interest::tokens(11, MODE_CURRENT)
    };
    let answer = answerer
        .ask(&[restricted.bytes()])
        .expect("the INTEREST is answered");
    record(&mut frames, "answer-restricted-interest-11", hex(&answer));
    record(
        &mut held,
        "after-restricted-answer",
        answerer.held().to_string(),
    );
    record(
        &mut ok,
        "restricted-interest-answers-the-tokens-under-its-key",
        "",
    );

    // The network QoS extension may follow the INTEREST.
    let mut answerer = Answerer::open(true, 512);
    answerer.declare(1, KEY_UNDER);
    let stated = Interest {
        qos: true,
        ..Interest::tokens(12, MODE_CURRENT)
    };
    let answer = answerer
        .ask(&[stated.bytes()])
        .expect("the INTEREST is answered");
    record(&mut frames, "answer-interest-with-qos-12", hex(&answer));
    record(&mut ok, "interest-with-the-qos-extension-is-answered", "");

    // An answer that does not fit the peer's batch is refused, spends no number, and the withdrawal after it takes
    // the number the answer would have taken.
    let mut small = Answerer::open(true, 36);
    small.declare(1, KEY);
    let error = small
        .ask(&[Interest::tokens(13, MODE_CURRENT).bytes()])
        .expect_err("the answer does not fit");
    record(&mut refused, "answer-beyond-the-peer-batch", error.class());
    record(&mut held, "refused-answer", small.held().to_string());
    let next = small.withdraw(1);
    record(&mut frames, "next-frame-after-refused-answer", hex(&next));
    record(&mut ok, "refused-answer-spends-no-sequence-number", "");

    // A withdrawn token is not answered, and the answer takes the number after the withdrawal.
    let mut answerer = Answerer::open(true, 512);
    answerer.declare(1, KEY);
    answerer.declare(2, KEY_SECOND);
    answerer.withdraw(1);
    let answer = answerer
        .ask(&[Interest::tokens(10, MODE_CURRENT).bytes()])
        .expect("the INTEREST is answered");
    record(
        &mut frames,
        "answer-after-withdrawal-interest-10",
        hex(&answer),
    );
    record(&mut held, "after-withdrawal", answerer.held().to_string());
    record(&mut ok, "withdrawn-token-is-not-answered", "");

    // Refused INTERESTs. Each is the first frame of a session that holds no token, so the frame is the only cause.
    let mut refuse = |name: &str, interest: Interest<'_>| {
        let mut answerer = Answerer::open(true, 512);
        let error = answerer
            .ask(&[interest.bytes()])
            .expect_err("the INTEREST is refused");
        record(&mut refused, name, error.class());
    };
    refuse(
        "interest-in-subscribers",
        Interest {
            options: 0x02,
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-in-queryables",
        Interest {
            options: 0x04,
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-in-key-expressions",
        Interest {
            options: 0x01,
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-restricted-to-a-key-without-a-wildcard-suffix",
        Interest {
            key: Some(KEY_ROS),
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-restricted-with-a-wildcard-inside-the-key",
        Interest {
            key: Some("@ros2_lv/*/slime/**"),
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-restricted-and-in-key-expressions-only",
        Interest {
            options: 0x01,
            key: Some("@ros2_lv/0/**"),
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-in-key-expressions-and-tokens-unrestricted",
        Interest {
            options: TOKENS | 0x01,
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-in-tokens-and-subscribers",
        Interest {
            options: TOKENS | 0x02,
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );
    refuse(
        "interest-with-an-unknown-extension",
        Interest {
            unknown_extension: true,
            ..Interest::tokens(1, MODE_CURRENT)
        },
    );

    // A session with no client role refuses every INTEREST, and it is refused whole.
    let mut plain = Answerer::open(false, 512);
    let error = plain
        .ask(&[Interest::tokens(1, MODE_CURRENT).bytes()])
        .expect_err("a session with no client role takes no INTEREST");
    record(
        &mut refused,
        "interest-to-a-session-with-no-client-role",
        error.class(),
    );

    // Two INTERESTs in one frame are refused whole.
    let mut answerer = Answerer::open(true, 512);
    answerer.declare(1, KEY);
    let error = answerer
        .ask(&[
            Interest::tokens(1, MODE_CURRENT).bytes(),
            Interest::tokens(2, MODE_CURRENT).bytes(),
        ])
        .expect_err("two INTERESTs are refused");
    record(&mut refused, "two-interests-in-one-frame", error.class());

    // A listener admits a Client only when it is configured to, and answers with the INIT_ACK of a peer.
    let mut admitting = listener(true);
    let ack = feed(&mut admitting, &init_syn_named(2)).expect("a Client INIT_SYN is admitted");
    record(&mut frames, "init-ack-to-a-client", hex(&ack));
    assert_eq!(admitting.state(), State::AwaitOpenSyn);
    record(&mut ok, "listener-admits-a-client-when-configured", "");

    // The default listener refuses what the admitting one takes, and answers a peer exactly as before.
    let mut default = listener(false);
    let error = feed(&mut default, &init_syn_named(2)).expect_err("no client is admitted");
    record(
        &mut refused,
        "client-init-to-a-listener-that-admits-none",
        error.class(),
    );
    assert_eq!(default.state(), State::Idle);
    let peer_ack = feed(&mut default, &init_syn_named(1)).expect("a peer is taken");
    let mut also = listener(true);
    assert_eq!(
        feed(&mut also, &init_syn_named(1)).expect("a peer is taken"),
        peer_ack,
        "admission changes nothing for a peer"
    );
    record(&mut ok, "default-configuration-unchanged", "");

    // A router and the reserved role stay refused, with and without admission.
    for admit in [false, true] {
        let mut session = listener(admit);
        let error = feed(&mut session, &init_syn_named(0)).expect_err("a router is refused");
        assert_eq!(error.class(), "unsupported-whatami");
        let mut session = listener(admit);
        let error = feed(&mut session, &init_syn_named(3)).expect_err("a reserved role is refused");
        assert_eq!(error.class(), "malformed-message");
    }
    let mut session = listener(true);
    let error = feed(&mut session, &init_syn_named(0)).expect_err("a router is refused");
    record(&mut refused, "router-init-to-a-listener", error.class());
    let mut session = listener(true);
    let error = feed(&mut session, &init_syn_named(3)).expect_err("a reserved role is refused");
    record(&mut refused, "reserved-role-init", error.class());

    emit("ok", &OK, &ok);
    emit("frame", &FRAMES, &frames);
    emit("held", &HELD, &held);
    emit("refused", &REFUSED, &refused);
}
