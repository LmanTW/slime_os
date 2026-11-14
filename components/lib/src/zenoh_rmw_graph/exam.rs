// The rmw graph exam: the tokens an rmw_zenoh peer declared, read into a graph.
//
// Included into `zenoh_rmw_graph` so the tests are named `zenoh_rmw_graph::<name>`, as
// `scripts/check/check-zenoh-profile0.py --slice rmw-graph` requires. The session's fixtures are the three
// captured sessions of `contracts/zenoh-rmw-session/v1`; the synthetic rows are `fixtures.rs`, generated
// from `contracts/zenoh-rmw-graph/v1`. Each printed line is one the checker builds again from its own host
// reference, so nothing printed here is trusted for its value.

fn graph_line(text: &str) {
    std::println!("[zenoh-exam] graph {text}");
}

fn graph_unhex(text: &str) -> std::vec::Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn demangled(text: &str) -> std::string::String {
    text.replace('%', "/")
}

fn duration(pair: (u64, u64)) -> std::string::String {
    std::format!("{}.{}", pair.0, pair.1)
}

fn qos_text(qos: &Qos) -> std::string::String {
    std::format!(
        "rel={},dur={},his={},dep={},dl={},ls={},lv={},le={}",
        qos.reliability,
        qos.durability,
        qos.history,
        qos.depth,
        duration(qos.deadline),
        duration(qos.lifespan),
        qos.liveliness,
        duration(qos.lease)
    )
}

fn entity_line(entity: &Entity) -> std::string::String {
    let none = std::string::String::from("-");
    let (topic, type_name, type_hash, qos) = match entity.topic() {
        Some(topic) => (
            demangled(topic),
            demangled(entity.type_name().expect("a topic has a type")),
            demangled(entity.type_hash().expect("a topic has a hash")),
            qos_text(entity.qos().expect("a topic has a QoS")),
        ),
        None => (none.clone(), none.clone(), none.clone(), none),
    };
    std::format!(
        "{} {} {} {} {} {} {} {} {} {} {}",
        entity.kind().name(),
        entity.zid(),
        entity.nid(),
        entity.id(),
        demangled(entity.enclave()),
        demangled(entity.namespace()),
        demangled(entity.node()),
        topic,
        type_name,
        type_hash,
        qos
    )
}

const GRAPH_CAPACITY: usize = 16;
const GRAPH_DOMAIN: u64 = 0;
const CAPACITY_ZID: &str = "7abf42d448a5a4fdeb112b7a1f051072";

/// One captured session replayed into a graph listener, and the live graph its tokens leave.
fn replay_session(rows: &[(&str, &str)]) -> Graph<GRAPH_CAPACITY> {
    use crate::zenoh_profile0::graph::{GraphSession, Kind as SessionKind};
    use crate::zenoh_profile0::session::{Config, Params, Role};
    let config = Config {
        zid: &[
            0x51, 0x10, 0xaa, 0x0b, 0xb0, 0xcc, 0x0d, 0xd0, 0xee, 0x0f, 0xf0, 0x01, 0x12, 0x23, 0x34,
            0x45,
        ],
        lease_ms: 30_000,
        initial_sn: 7,
        cookie: b"slime-rmw-capture-cookie-01",
    };
    let mut session =
        GraphSession::new(Role::Listener, &config, Params::GRAPH).expect("a graph listener");
    let mut graph = Graph::<GRAPH_CAPACITY>::new(GRAPH_DOMAIN);
    let mut out = [0u8; 512];
    for (at, (name, hexed)) in rows.iter().enumerate() {
        let batch = graph_unhex(hexed);
        session
            .on_batch_visit(&batch, 1 + at as u64, &mut out, &mut |change| {
                if change.kind != SessionKind::Token {
                    return;
                }
                let key = core::str::from_utf8(change.key).expect("a token key is UTF-8");
                if change.declared {
                    graph.declare(key).expect("the graph takes a captured token");
                } else {
                    graph.withdraw(key).expect("the graph takes a withdrawn token");
                }
            })
            .unwrap_or_else(|error| panic!("{name}: refused as {}", error.class()));
    }
    graph
}

fn print_graph(group: &str, graph: &Graph<GRAPH_CAPACITY>) {
    use std::collections::{BTreeMap, BTreeSet};
    let mut entities: std::vec::Vec<&Entity> = graph.iter().collect();
    entities.sort_by(|a, b| (a.zid(), a.nid(), a.id()).cmp(&(b.zid(), b.nid(), b.id())));
    for entity in &entities {
        graph_line(&std::format!("entity {group} {}", entity_line(entity)));
    }
    let mut topics: BTreeMap<std::string::String, (u32, u32)> = BTreeMap::new();
    let mut services: BTreeMap<std::string::String, (u32, u32)> = BTreeMap::new();
    let mut nodes: BTreeSet<std::string::String> = BTreeSet::new();
    for entity in &entities {
        let name = entity.topic().map(demangled);
        match (entity.kind(), name) {
            (Kind::Publisher, Some(name)) => topics.entry(name).or_default().0 += 1,
            (Kind::Subscription, Some(name)) => topics.entry(name).or_default().1 += 1,
            (Kind::Service, Some(name)) => services.entry(name).or_default().0 += 1,
            (Kind::Client, Some(name)) => services.entry(name).or_default().1 += 1,
            (Kind::Node, _) => {
                nodes.insert(demangled(entity.node()));
            }
            _ => {}
        }
    }
    for (name, (publishers, subscriptions)) in &topics {
        graph_line(&std::format!("topic {group} {name} {publishers} {subscriptions}"));
    }
    for (name, (servers, clients)) in &services {
        graph_line(&std::format!("service {group} {name} {servers} {clients}"));
    }
    for name in &nodes {
        graph_line(&std::format!("node {group} {name}"));
    }
    graph_line(&std::format!("ignored {group} {}", graph.ignored()));
    graph_line(&std::format!("ok {group}-graph"));
}

/// A graph filled with one node token after another until it refuses one: how many it held and why.
fn capacity_run() -> (usize, &'static str) {
    let mut graph = Graph::<GRAPH_CAPACITY>::new(GRAPH_DOMAIN);
    for number in 0..=GRAPH_CAPACITY {
        let key = std::format!("@ros2_lv/0/{CAPACITY_ZID}/0/{number}/NN/%/%/n{number}");
        if let Err(error) = graph.declare(&key) {
            return (graph.len(), error.class());
        }
    }
    panic!("the graph never refused a token past its capacity");
}

/// Every section, in the order the exam lists them.
#[test]
fn the_rmw_graph_exam() {
    use crate::zenoh_rmw::fixtures as session;
    for (group, rows) in [
        ("talker", &session::TALKER[..]),
        ("listener", &session::LISTENER[..]),
        ("lists", &session::LISTS[..]),
    ] {
        print_graph(group, &replay_session(rows));
    }
    for (name, text) in fixtures::QOS {
        let qos = parse_qos(text).unwrap_or_else(|error| panic!("{name}: {}", error.class()));
        let mut written = std::string::String::new();
        qos.write_keyexpr(&mut written).expect("a QoS is written");
        assert_eq!(written, text, "{name}: the QoS written again is not the substring read");
        graph_line(&std::format!("qos {name} {}", qos_text(&qos)));
    }
    for (name, key) in fixtures::TOKENS {
        let entity = Entity::parse(key, GRAPH_DOMAIN)
            .unwrap_or_else(|error| panic!("{name}: refused as {}", error.class()))
            .unwrap_or_else(|| panic!("{name}: is outside the admin space"));
        graph_line(&std::format!("token {name} {}", entity_line(&entity)));
        let mut again = [0u8; KEY_BYTES];
        let length = entity.rebuild(&mut again).expect("a token is written again");
        assert_eq!(&again[..length], key.as_bytes(), "{name}: the token written again differs");
        graph_line(&std::format!("build {name} ok"));
    }
    for (name, key) in fixtures::IGNORED {
        assert!(
            matches!(Entity::parse(key, GRAPH_DOMAIN), Ok(None)),
            "{name}: a key outside the admin space is not ignored"
        );
        graph_line(&std::format!("ignored-key {name} ok"));
    }
    for (name, key) in fixtures::REFUSE {
        match Entity::parse(key, GRAPH_DOMAIN) {
            Ok(_) => panic!("{name}: the graph took it"),
            Err(error) => graph_line(&std::format!("refused {name} {}", error.class())),
        }
    }
    for (name, text) in fixtures::QOS_REFUSE {
        match parse_qos(text) {
            Ok(_) => panic!("{name}: the graph took it"),
            Err(error) => graph_line(&std::format!("refused {name} {}", error.class())),
        }
    }
    let (held, class) = capacity_run();
    graph_line(&std::format!("capacity {held} {class}"));
}

#[test]
fn the_constants_are_the_handed_off_record() {
    assert_eq!(fixtures::FORMAT_VERSION, 1);
    let Some(path) = std::env::var_os("ZENOH_RMW_GRAPH_FIXTURES") else {
        return;
    };
    let record = std::fs::read_to_string(&path).expect("the hand-off record is readable");
    let mut wanted = std::string::String::new();
    wanted.push_str("{\n");
    wanted.push_str(&std::format!("  formatVersion = {};\n", fixtures::FORMAT_VERSION));
    for (group, rows) in [
        ("qos", &fixtures::QOS[..]),
        ("tokens", &fixtures::TOKENS[..]),
        ("refuse", &fixtures::REFUSE[..]),
        ("qosRefuse", &fixtures::QOS_REFUSE[..]),
        ("ignored", &fixtures::IGNORED[..]),
    ] {
        wanted.push_str(&std::format!("  {group} = [\n"));
        for (name, key) in rows {
            wanted.push_str(&std::format!("    {{ name = \"{name}\"; key = \"{key}\"; }};\n"));
        }
        wanted.push_str("  ];\n");
    }
    wanted.push_str("}\n");
    assert_eq!(
        record, wanted,
        "fixtures.rs differs from the record the exam handed over; run `just zenoh_rmw_graph_gen`"
    );
}
