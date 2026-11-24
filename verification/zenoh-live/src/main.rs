//! A client-role Slime link against a live `rmw_zenohd`.
//!
//! `scripts/check/check-zenoh-profile0.py --slice rmw-live` starts the router and a ROS node, then runs this program with
//! `inbound` or `outbound`. The program prints one `[zenoh-live] live ...` line for each thing it did, and no other kind
//! of line: the checker reads the listener's own output and adds the `ros` lines, and it fails the run on a program line
//! of any other kind. `scripts/lib/zenoh_rmw_live_exam.py` judges the whole transcript.
//!
//! * `inbound`: the link subscribes on the chatter key and prints each sample a `demo_nodes_cpp talker` publishes, until
//!   it has printed `SAMPLES` of them or `DEADLINE` passes.
//! * `outbound`: the link writes `PUTS` Puts on the chatter key, one every `PUT_GAP`, and closes. A ROS `listener`
//!   prints each. This program never learns whether the listener heard one, because the router writes nothing back.
//! * `discover`: the link declares the liveliness tokens of the node `slime_node` and of its publisher on the chatter
//!   topic, and holds the session open until a line arrives on stdin. The checker runs `ros2` while the session is open
//!   and then writes that line. The link then closes without withdrawing a token. This program never learns what `ros2`
//!   listed. `scripts/lib/zenoh_rmw_discover_exam.py` judges that.

use std::io::{BufRead, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use slime_components::zenoh_link::{ByteLink, Error, LinkError, LinkOf, Notice};
use slime_components::zenoh_profile0::encode;
use slime_components::zenoh_profile0::session::{Config, MAX_EVENTS, Params, Role, State};
use slime_components::zenoh_profile0::{MAX_BATCH_BYTES, MAX_KEY_BYTES, STREAM_LENGTH_BYTES};

const ROUTER: &str = "127.0.0.1:7447";
const KEY: &str = "0/chatter/std_msgs::msg::dds_::String_/RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18";
const ZID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const GID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const LEASE_MS: u64 = 10_000;
const INITIAL_SN: u32 = 7;
const SUBSCRIPTION: u32 = 1;
/// The most bytes a sample's payload holds: a `std_msgs/String` of up to 22 characters in classic CDR is 32 bytes.
const PAYLOAD: usize = 32;
const NOTICES: usize = 8;
/// The framed size of a batch of the first release: the stream length and a 512-byte body.
const FRAMED: usize = STREAM_LENGTH_BYTES + MAX_BATCH_BYTES;
const SAMPLES: usize = 6;
const PUTS: usize = 6;
const PUT_GAP: Duration = Duration::from_millis(500);
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const DEADLINE: Duration = Duration::from_secs(30);
/// How long `discover` waits for the checker's release line: two `ros2` listings run in that time.
const RELEASE_DEADLINE: Duration = Duration::from_secs(120);
/// The longest key a token carries: a publisher token's key is 186 bytes, over the first release's bound.
const TOKEN_KEY_BYTES: usize = 253;
const NODE_TOKEN: u32 = 10;
const PUBLISHER_TOKEN: u32 = 11;

type Link = LinkOf<Tcp, FRAMED, 1, 2, MAX_KEY_BYTES, PAYLOAD, NOTICES, MAX_EVENTS>;
type TokenLink = LinkOf<Tcp, FRAMED, 1, 2, TOKEN_KEY_BYTES, PAYLOAD, NOTICES, MAX_EVENTS>;

/// A non-blocking TCP stream as the link's byte stream.
struct Tcp {
    stream: TcpStream,
    eof: bool,
}

impl ByteLink for Tcp {
    fn send(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        match self.stream.write(buf) {
            Ok(taken) => Ok(taken),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(_) => Err(LinkError::Reset),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        match self.stream.read(buf) {
            Ok(0) => {
                self.eof = true;
                Ok(0)
            }
            Ok(read) => Ok(read),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(_) => Err(LinkError::Reset),
        }
    }

    fn eof(&self) -> bool {
        self.eof
    }
}

fn say(text: &str) {
    println!("[zenoh-live] live {text}");
}

fn params(key: usize) -> Params {
    let mut params = Params::DEMO;
    params.bounds.key = key;
    params.bounds.payload = PAYLOAD;
    params.samples = NOTICES / 2;
    params
}

fn connect() -> Result<Link, String> {
    connect_with::<MAX_KEY_BYTES>()
}

fn connect_with<const K: usize>()
-> Result<LinkOf<Tcp, FRAMED, 1, 2, K, PAYLOAD, NOTICES, MAX_EVENTS>, String> {
    let stream =
        TcpStream::connect(ROUTER).map_err(|error| format!("no router on {ROUTER}: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let config = Config {
        zid: &ZID,
        lease_ms: LEASE_MS,
        initial_sn: INITIAL_SN,
        cookie: &[],
    };
    let io = Tcp { stream, eof: false };
    LinkOf::<Tcp, FRAMED, 1, 2, K, PAYLOAD, NOTICES, MAX_EVENTS>::with_params(
        io,
        Role::Connector,
        &config,
        params(K),
        1,
    )
    .and_then(LinkOf::with_client_role)
    .map_err(|error| format!("the link refused its configuration: {error:?}"))
}

fn now(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Pumps the link once and gives the stream a moment, so a loop does not spin.
fn pump<const K: usize>(
    link: &mut LinkOf<Tcp, FRAMED, 1, 2, K, PAYLOAD, NOTICES, MAX_EVENTS>,
    start: Instant,
) -> Result<(), Error> {
    let handle = link.handle();
    link.pump(handle, now(start))?;
    std::thread::sleep(Duration::from_millis(5));
    Ok(())
}

/// Opens the session and prints what the router announced. Returns once the link is open. The exam holds one
/// `router-ready` line for each run, so `inbound` and `discover` print it and `outbound` does not. The outbound direction
/// connects to a router on the same address, and its handshake line is what shows that a router answered.
fn open<const K: usize>(
    link: &mut LinkOf<Tcp, FRAMED, 1, 2, K, PAYLOAD, NOTICES, MAX_EVENTS>,
    start: Instant,
    ready: bool,
) -> Result<(), String> {
    if ready {
        say(&format!("router-ready tcp/{ROUTER}"));
    }
    let handle = link.handle();
    link.open(handle, now(start))
        .map_err(|error| format!("the INIT_SYN was not queued: {error:?}"))?;
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    while link.session().state() != State::Open {
        if Instant::now() > deadline {
            return Err(String::from("the handshake did not finish"));
        }
        pump(link, start).map_err(|error| format!("the handshake failed: {error:?}"))?;
    }
    // The library does not expose the router's `whatami`. The client decoder takes an INIT_ACK of `whatami` 0 and no
    // other, so a session that reached `Open` with the client role was answered by a router. The batch and the lease are
    // what the session read from the router's INIT_ACK and OPEN_ACK.
    let session = link.session();
    say(&format!(
        "handshake whatami=0 batch={} lease_s={}",
        session.peer_batch(),
        session.peer_lease_ms() / 1000
    ));
    Ok(())
}

fn text(payload: &[u8]) -> Option<String> {
    if payload.get(..4) != Some(&[0x00, 0x01, 0x00, 0x00][..]) {
        return None;
    }
    let length = u32::from_le_bytes(payload.get(4..8)?.try_into().ok()?) as usize;
    if payload.len() != 8 + length || length == 0 {
        return None;
    }
    String::from_utf8(payload[8..payload.len() - 1].to_vec()).ok()
}

fn inbound() -> Result<(), String> {
    let start = Instant::now();
    let mut link = connect()?;
    open(&mut link, start, true)?;
    let handle = link.handle();
    link.declare_subscriber(handle, SUBSCRIPTION, KEY)
        .map_err(|error| format!("the subscription was not queued: {error:?}"))?;
    say(&format!("subscribed {SUBSCRIPTION}"));
    let mut delivered = 0usize;
    let deadline = Instant::now() + DEADLINE;
    while delivered < SAMPLES && Instant::now() < deadline {
        pump(&mut link, start).map_err(|error| format!("the link failed: {error:?}"))?;
        while let Some(notice) = link.next_notice() {
            match notice {
                Notice::SampleDelivered(sample) => {
                    let Some(string) = text(sample.payload()) else {
                        return Err(String::from("a sample is not a CDR string"));
                    };
                    say(&format!(
                        "sample inbound sequence={} text={}",
                        sample.sequence,
                        string.replace(' ', "_")
                    ));
                    delivered += 1;
                }
                Notice::Closed { reason } => {
                    return Err(format!("the link closed with reason {reason}"));
                }
                _ => {}
            }
        }
    }
    say(&format!("inbound-done delivered={delivered}"));
    Ok(())
}

fn cdr_string(text: &str) -> Vec<u8> {
    let mut out = vec![0x00, 0x01, 0x00, 0x00];
    out.extend_from_slice(&(text.len() as u32 + 1).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out
}

fn outbound() -> Result<(), String> {
    let start = Instant::now();
    let mut link = connect()?;
    open(&mut link, start, false)?;
    let handle = link.handle();
    for number in 0..PUTS {
        let attachment = encode::attachment(number as i64 + 1, 1_000_000_000 + number as i64, &GID)
            .map_err(|error| format!("{error:?}"))?;
        let payload = cdr_string(&format!("Hello Slime {number}"));
        // The send slot is free once the stream took the last batch.
        let deadline = Instant::now() + HANDSHAKE_DEADLINE;
        while link.send_pending() {
            if Instant::now() > deadline {
                return Err(String::from("the send slot did not empty"));
            }
            pump(&mut link, start).map_err(|error| format!("the link failed: {error:?}"))?;
        }
        link.publish(handle, KEY, &attachment, &payload)
            .map_err(|error| format!("the Put {number} was refused: {error:?}"))?;
        say(&format!("put outbound number={number}"));
        let until = Instant::now() + PUT_GAP;
        while Instant::now() < until {
            pump(&mut link, start).map_err(|error| format!("the link failed: {error:?}"))?;
        }
    }
    say(&format!("outbound-done written={PUTS}"));
    while link.send_pending() {
        pump(&mut link, start).map_err(|error| format!("the link failed: {error:?}"))?;
    }
    link.close(handle, 0)
        .map_err(|error| format!("the close was refused: {error:?}"))?;
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    while link.send_pending() && Instant::now() < deadline {
        pump(&mut link, start).map_err(|error| format!("the link failed: {error:?}"))?;
    }
    say("closed reason=0");
    Ok(())
}

fn zid_hex() -> String {
    ZID.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The token of the node, in the form `rmw_zenoh_cpp` names it: `@ros2_lv/<domain>/<zid>/<nid>/<id>/<kind>/...`. The
/// enclave and the namespace are `/`, which a key writes as `%`.
fn node_key() -> String {
    format!("@ros2_lv/0/{}/0/0/NN/%/%/slime_node", zid_hex())
}

/// The token of the node's publisher on the chatter topic, with the type hash taken from the chatter key.
fn publisher_key() -> String {
    let hash = KEY.rsplit('/').next().unwrap_or_default();
    format!(
        "@ros2_lv/0/{}/0/1/MP/%/%/slime_node/%chatter/std_msgs::msg::dds_::String_/{hash}/::,:,:,:,,",
        zid_hex()
    )
}

/// Pumps until the stream took the batch in the send slot.
fn flush(link: &mut TokenLink, start: Instant) -> Result<(), String> {
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    while link.send_pending() {
        if Instant::now() > deadline {
            return Err(String::from("the send slot did not empty"));
        }
        pump(link, start).map_err(|error| format!("the link failed: {error:?}"))?;
    }
    Ok(())
}

fn discover() -> Result<(), String> {
    let start = Instant::now();
    let mut link = connect_with::<TOKEN_KEY_BYTES>()?;
    open(&mut link, start, true)?;
    let handle = link.handle();
    link.declare_token(handle, NODE_TOKEN, &node_key())
        .map_err(|error| format!("the node token was refused: {error:?}"))?;
    flush(&mut link, start)?;
    say(&format!("token-declared node id={NODE_TOKEN}"));
    link.declare_token(handle, PUBLISHER_TOKEN, &publisher_key())
        .map_err(|error| format!("the publisher token was refused: {error:?}"))?;
    flush(&mut link, start)?;
    say(&format!("token-declared publisher id={PUBLISHER_TOKEN}"));
    // The checker writes one line when it has read what `ros2` lists. The session stays open and the link keeps pumping
    // until then, so its lease holds.
    let released = Arc::new(AtomicBool::new(false));
    let flag = released.clone();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        flag.store(true, Ordering::SeqCst);
    });
    let deadline = Instant::now() + RELEASE_DEADLINE;
    while !released.load(Ordering::SeqCst) {
        if Instant::now() > deadline {
            return Err(String::from("the checker did not release the session"));
        }
        pump(&mut link, start).map_err(|error| format!("the link failed: {error:?}"))?;
        while let Some(notice) = link.next_notice() {
            if let Notice::Closed { reason } = notice {
                return Err(format!("the link closed with reason {reason}"));
            }
        }
    }
    // A pump can leave a keep-alive in the send slot, and a close is refused while the slot is busy.
    flush(&mut link, start)?;
    link.close(handle, 0)
        .map_err(|error| format!("the close was refused: {error:?}"))?;
    flush(&mut link, start)?;
    say("closed reason=0");
    Ok(())
}

fn main() -> ExitCode {
    let direction = std::env::args().nth(1).unwrap_or_default();
    let result = match direction.as_str() {
        "inbound" => inbound(),
        "outbound" => outbound(),
        "discover" => discover(),
        other => Err(format!(
            "a direction is `inbound`, `outbound` or `discover`, not {other:?}"
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("zenoh-live: {message}");
            ExitCode::FAILURE
        }
    }
}
