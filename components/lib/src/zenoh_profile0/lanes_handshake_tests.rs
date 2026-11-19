//! Host tests for the QoS offer on an INIT. The byte strings are what `zenoh-codec` 1.0.0 wrote for a ZID of
//! `112233`, a batch of 2048 and a cookie of `aabbccdd`; `scripts/lib/zenoh_lanes_exam.py` holds the same
//! four and requires its host reference to write them.

use super::*;
use crate::zenoh_profile0::encode::{init_ack, init_ack_qos, init_syn, init_syn_qos};
use crate::zenoh_profile0::{decode_batch, decode_batch_qos};

const ZID: [u8; 3] = [0x11, 0x22, 0x33];
const PEER_ZID: [u8; 3] = [0x44, 0x55, 0x66];
const COOKIE: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
const BATCH: u16 = 2048;
const SYN: &str = "4109211122330a0008";
const SYN_QOS: &str = "c109211122330a000801";
const ACK: &str = "6109211122330a000804aabbccdd";
const ACK_QOS: &str = "e109211122330a000804aabbccdd01";

fn hex(bytes: &[u8]) -> std::string::String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> std::vec::Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn config<'a>(zid: &'a [u8], cookie: &'a [u8]) -> Config<'a> {
    Config {
        zid,
        lease_ms: 2000,
        initial_sn: 7000,
        cookie,
    }
}

fn params() -> Params {
    Params {
        announced: BATCH,
        bounds: Bounds {
            batch: usize::from(BATCH) - STREAM_LENGTH_BYTES,
            ..Bounds::DEMO
        },
        ..Params::DEMO
    }
}

fn session(role: Role, runs: usize) -> Session {
    let cookie = if role == Role::Listener {
        &COOKIE[..]
    } else {
        &[]
    };
    Session::with_lanes(role, &config(&ZID, cookie), params(), runs).expect("session")
}

#[test]
fn the_encoder_writes_what_upstream_wrote() {
    let mut out = [0u8; 64];
    let written = |len: usize, out: &[u8]| hex(&out[..len]);
    let n = init_syn(&mut out, &ZID, BATCH).expect("syn");
    assert_eq!(written(n, &out), SYN);
    let n = init_syn_qos(&mut out, &ZID, BATCH).expect("syn qos");
    assert_eq!(written(n, &out), SYN_QOS);
    let n = init_ack(&mut out, &ZID, BATCH, &COOKIE).expect("ack");
    assert_eq!(written(n, &out), ACK);
    let n = init_ack_qos(&mut out, &ZID, BATCH, &COOKIE).expect("ack qos");
    assert_eq!(written(n, &out), ACK_QOS);
}

#[test]
fn the_decoder_reports_the_extension_and_refuses_it_where_it_always_did() {
    let bounds = Bounds::DEMO;
    for (text, qos, ack) in [
        (SYN, false, false),
        (SYN_QOS, true, false),
        (ACK, false, true),
    ] {
        let bytes = unhex(text);
        for message in [decode_batch_qos(&bytes, &bounds), decode_batch(&bytes)] {
            match message.expect("decodes") {
                Message::InitSyn { qos: got, .. } => assert!(!ack && got == qos, "{text}"),
                Message::InitAck { qos: got, .. } => assert!(ack && got == qos, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
    }
    // A session with one run reads an INIT_SYN with the extension as it always did, and an INIT_ACK with it is
    // refused. Only a session that offers the extension takes it on an INIT_ACK.
    let ack_qos = unhex(ACK_QOS);
    assert_eq!(decode_batch(&ack_qos), Err(Refusal::UnsupportedExtension));
    assert!(matches!(
        decode_batch_qos(&ack_qos, &bounds),
        Ok(Message::InitAck { qos: true, .. })
    ));
}

#[test]
fn a_session_with_one_run_writes_the_init_it_always_wrote() {
    for runs in [0, 1] {
        let mut connector = session(Role::Connector, runs);
        let mut out = [0u8; MAX_BATCH_BYTES];
        let outcome = connector.connect(0, &mut out).expect("connect");
        assert_eq!(hex(outcome.batch(&out)), SYN, "{runs} runs");
        assert!(!connector.lanes());
    }
}

#[test]
fn a_connector_with_runs_offers_and_the_peer_accepts() {
    let mut connector = session(Role::Connector, 2);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let outcome = connector.connect(0, &mut out).expect("connect");
    assert_eq!(hex(outcome.batch(&out)), SYN_QOS);
    let peer = unhex("e109214455660a000804aabbccdd01");
    let reply = connector.on_batch(&peer, 1, &mut out).expect("INIT_ACK");
    assert!(reply.sent > 0);
    assert!(connector.lanes());
}

#[test]
fn a_connector_with_runs_whose_peer_declines_has_one_lane() {
    let mut connector = session(Role::Connector, 2);
    let mut out = [0u8; MAX_BATCH_BYTES];
    connector.connect(0, &mut out).expect("connect");
    let peer = unhex("6109214455660a000804aabbccdd");
    connector.on_batch(&peer, 1, &mut out).expect("INIT_ACK");
    assert!(!connector.lanes());
}

#[test]
fn a_connector_with_one_run_refuses_an_init_ack_with_the_extension() {
    let mut connector = session(Role::Connector, 1);
    let mut out = [0u8; MAX_BATCH_BYTES];
    connector.connect(0, &mut out).expect("connect");
    let peer = unhex("e109214455660a000804aabbccdd01");
    assert_eq!(
        connector.on_batch(&peer, 1, &mut out).err(),
        Some(SessionError::Decode(Refusal::UnsupportedExtension))
    );
    assert_eq!(connector.state(), State::AwaitInitAck);
}

#[test]
fn a_listener_with_runs_answers_an_offer_with_the_extension() {
    let mut listener = session(Role::Listener, 2);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let peer = unhex("c109214455660a000801");
    let reply = listener.on_batch(&peer, 0, &mut out).expect("INIT_SYN");
    assert_eq!(hex(reply.batch(&out)), ACK_QOS);
    assert!(listener.lanes());
}

#[test]
fn a_listener_with_runs_answers_a_silent_peer_without_it() {
    let mut listener = session(Role::Listener, 2);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let peer = unhex("4109214455660a0008");
    let reply = listener.on_batch(&peer, 0, &mut out).expect("INIT_SYN");
    assert_eq!(hex(reply.batch(&out)), ACK);
    assert!(!listener.lanes());
}

#[test]
fn a_listener_with_one_run_answers_an_offer_without_the_extension() {
    let mut listener = session(Role::Listener, 1);
    let mut out = [0u8; MAX_BATCH_BYTES];
    let peer = unhex("c109214455660a000801");
    let reply = listener.on_batch(&peer, 0, &mut out).expect("INIT_SYN");
    assert_eq!(hex(reply.batch(&out)), ACK);
    assert!(!listener.lanes());
}

#[test]
fn the_run_count_is_at_most_sixteen() {
    let config = config(&ZID, &[]);
    assert!(Session::with_lanes(Role::Connector, &config, params(), 16).is_ok());
    assert_eq!(
        Session::with_lanes(Role::Connector, &config, params(), 17).err(),
        Some(SessionError::InvalidConfig)
    );
    assert_eq!(PEER_ZID.len(), 3);
}
