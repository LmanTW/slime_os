//! Host tests for the Profile 0 client role.
//!
//! A connector with the client role is driven against two handshakes that `rmw_zenohd` wrote. The captures reach
//! the test through `ZENOH_RMW_ROUTER_RUNS`, one run to a line: its name, the INIT_SYN, the INIT_ACK and the
//! OPEN_ACK in hex. The `[zenoh-exam] client` lines are what `scripts/lib/zenoh_rmw_client_exam.py` judges; each is
//! printed after the assertions of its scenario passed.

use super::session::{Config, Role, Session, SessionError, SessionOf, State};
use super::{MAX_BATCH_BYTES, Message, Refusal, decode_batch};
use std::string::String;
use std::vec::Vec;

const ZID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const LEASE_MS: u64 = 10_000;
const INITIAL_SN: u32 = 7;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").expect("a string takes the digits");
    }
    if out.is_empty() {
        String::from("-")
    } else {
        out
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "an odd number of hex digits");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
        .collect()
}

fn line(text: &str) {
    std::println!("[zenoh-exam] client {text}");
}

/// The captures the checker hands over, or none when the test runs without it. A run with no captures prints
/// no line, and the `rmw-client` slice refuses a transcript with none.
/// One captured run: its name, the INIT_SYN the client wrote, and the INIT_ACK and OPEN_ACK of the router.
type Run = (String, Vec<u8>, Vec<u8>, Vec<u8>);

fn runs() -> Option<Vec<Run>> {
    let record = std::env::var("ZENOH_RMW_ROUTER_RUNS").ok()?;
    Some(
        record
            .lines()
            .map(|row| {
                let fields: Vec<&str> = row.split(' ').collect();
                assert_eq!(fields.len(), 4, "a run is a name and three batches");
                (
                    String::from(fields[0]),
                    unhex(fields[1]),
                    unhex(fields[2]),
                    unhex(fields[3]),
                )
            })
            .collect(),
    )
}

fn config() -> Config<'static> {
    Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: INITIAL_SN,
        cookie: &[],
    }
}

fn connector() -> Session {
    Session::new(Role::Connector, &config()).expect("connector")
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Idle => "idle",
        State::AwaitInitAck => "await-init-ack",
        State::AwaitOpenSyn => "await-open-syn",
        State::AwaitOpenAck => "await-open-ack",
        State::Open => "open",
        State::Closed => "closed",
    }
}

fn class(error: &SessionError) -> &'static str {
    match error {
        SessionError::Decode(Refusal::UnsupportedWhatami) => "unsupported-whatami",
        SessionError::InvalidConfig => "invalid-config",
        other => panic!("a refusal the exam does not name: {other:?}"),
    }
}

/// What `session` writes when it connects, as a stream-free batch body.
fn connect(session: &mut Session) -> Vec<u8> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.connect(0, &mut out).expect("connect");
    out[..outcome.sent].to_vec()
}

fn feed(session: &mut Session, batch: &[u8]) -> Result<Vec<u8>, SessionError> {
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = session.on_batch(batch, 1, &mut out)?;
    Ok(out[..outcome.sent].to_vec())
}

#[test]
fn the_client_exam() {
    let Some(runs) = runs() else {
        return;
    };
    for (name, syn, ack, open_ack) in &runs {
        line(&std::format!("fed {name} {} {}", hex(ack), hex(open_ack)));
        let mut session = connector().with_client_role().expect("the role");
        assert!(session.is_client());
        let written = connect(&mut session);
        assert_eq!(&written, syn, "the client INIT_SYN is the capture's");
        line(&std::format!("syn {name} {}", hex(&written)));
        assert_eq!(session.state(), State::AwaitInitAck);
        let open_syn = feed(&mut session, ack).expect("the router's INIT_ACK is taken");
        assert_eq!(session.state(), State::AwaitOpenAck);
        line(&std::format!("open-syn {name} {}", hex(&open_syn)));
        feed(&mut session, open_ack).expect("the router's OPEN_ACK is taken");
        assert_eq!(session.state(), State::Open);
        line(&std::format!(
            "opened {name} state={}",
            state_name(session.state())
        ));
    }

    let mut plain = connector();
    assert!(!plain.is_client());
    let written = connect(&mut plain);
    assert_eq!(
        decode_batch(&written).map(|m| matches!(m, Message::InitSyn { .. })),
        Ok(true)
    );
    line(&std::format!("default-syn {}", hex(&written)));

    // A connector with no client role refuses the router's INIT_ACK and stays where it was.
    let (_, _, router_ack, _) = &runs[0];
    let mut session = connector();
    let written = connect(&mut session);
    let error = feed(&mut session, router_ack).expect_err("a peer takes no router");
    assert_eq!(session.state(), State::AwaitInitAck);
    line(&std::format!(
        "refused default-session-takes-a-router-ack {} state={} {}",
        class(&error),
        state_name(session.state()),
        hex(&written)
    ));

    // A client refuses an INIT_ACK whose `whatami` is a peer or a client, and stays where it was.
    for (name, whatami) in [
        ("client-takes-a-peer-ack", 1u8),
        ("client-takes-a-client-ack", 2u8),
    ] {
        let mut session = connector().with_client_role().expect("the role");
        let written = connect(&mut session);
        let mut ack = router_ack.clone();
        ack[2] = (ack[2] & !3) | whatami;
        let error = feed(&mut session, &ack).expect_err("a client takes only a router");
        assert_eq!(session.state(), State::AwaitInitAck);
        line(&std::format!(
            "refused {name} {} state={} {}",
            class(&error),
            state_name(session.state()),
            hex(&written)
        ));
    }

    // A listener cannot take the role: it writes no INIT_SYN.
    let listener = SessionOf::<1, 2>::new(
        Role::Listener,
        &Config {
            zid: &ZID,
            lease_ms: LEASE_MS,
            initial_sn: INITIAL_SN,
            cookie: &[0xc0; 8],
        },
    )
    .expect("listener");
    let error = listener
        .with_client_role()
        .expect_err("a listener takes no role");
    line(&std::format!(
        "refused client-as-a-listener {} state=none {}",
        class(&error),
        hex(&[])
    ));
}
