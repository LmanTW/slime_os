"""Independent, bounded packet evidence for native DNS/HTTP qualification.

Parses externally specified classic PCAP, Ethernet, IPv4, UDP, TCP and DNS bytes.
No host name lookup or HTTP request is performed. Summaries are transient Python
values, not a persisted Slime format. A capture proves observed packets, not DNS
cryptographic authenticity or the quality of the launch entropy source.
"""

from __future__ import annotations

import ipaddress
import struct

GUEST = "10.0.2.15"
MAX_CAPTURE = 32 * 1024 * 1024
MAX_FRAMES = 100_000
MAX_DNS = 512


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(f"HTTP capture: {reason}")


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frames(data: bytes, *, allow_empty: bool = False, max_bytes: int = MAX_CAPTURE, max_frames: int = MAX_FRAMES):
    _need(24 <= len(data) <= max_bytes, "capture size outside bound")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    _need(data[:4] in formats, "not classic PCAP")
    endian, scale = formats[data[:4]]
    major, minor, _zone, _accuracy, snaplen, linktype = struct.unpack_from(endian + "HHiiII", data, 4)
    _need((major, minor) == (2, 4) and linktype == 1, "PCAP version/linktype")
    _need(14 <= snaplen <= 65536, "PCAP snap length")
    offset, count, previous = 24, 0, 0
    while offset < len(data):
        _need(offset + 16 <= len(data), "truncated PCAP record")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        _need(fraction < scale, "invalid PCAP timestamp")
        timestamp = seconds * scale + fraction
        _need(timestamp >= previous, "PCAP timestamps reordered")
        previous = timestamp
        _need(14 <= captured <= snaplen and captured == original, "truncated/oversized frame")
        _need(offset + captured <= len(data), "truncated PCAP payload")
        count += 1
        _need(count <= max_frames, "frame count bound")
        yield timestamp / scale, data[offset:offset + captured]
        offset += captured
    _need(count != 0 or allow_empty, "empty packet observation")


def _name(packet: bytes, start: int) -> tuple[str, int]:
    labels: list[str] = []
    position, end, hops = start, None, 0
    seen: set[int] = set()
    while True:
        _need(position < len(packet) and position not in seen, "DNS name bounds/loop")
        seen.add(position)
        tag = packet[position]
        if tag & 0xC0 == 0xC0:
            _need(position + 2 <= len(packet), "DNS short pointer")
            target = int.from_bytes(packet[position:position + 2], "big") & 0x3FFF
            _need(12 <= target < position, "DNS forward/header pointer")
            hops += 1
            _need(hops <= 16, "DNS pointer hop bound")
            if end is None:
                end = position + 2
            position = target
            continue
        _need(tag < 64, "DNS reserved label")
        position += 1
        if not tag:
            return ".".join(labels), position if end is None else end
        _need(position + tag <= len(packet), "DNS short label")
        label = packet[position:position + tag]
        _need(all(65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57 or b == 45 for b in label), "DNS non-host label")
        labels.append(label.decode("ascii").lower())
        _need(sum(map(len, labels)) + len(labels) - 1 <= 64, "DNS expanded-name bound")
        position += tag


def _question(packet: bytes) -> tuple[int, int, str, int]:
    _need(12 <= len(packet) <= MAX_DNS, "DNS packet size")
    identity, flags, questions, _answers, _authority, _additional = struct.unpack_from("!6H", packet)
    _need(questions == 1, "DNS question count")
    name, cursor = _name(packet, 12)
    _need(name != "" and cursor + 4 <= len(packet), "DNS question bounds")
    _need(packet[cursor:cursor + 4] == b"\0\x01\0\x01", "DNS question not A/IN")
    return identity, flags, name, cursor + 4


def _answers(packet: bytes, hostname: str) -> tuple[list[str], int]:
    _identity, flags, name, cursor = _question(packet)
    _need(name == hostname and flags & 0x8000 != 0 and flags & 0x7A4F == 0, "DNS response flags/question")
    answer_count, authority_count, additional_count = struct.unpack_from("!3H", packet, 6)
    total = answer_count + authority_count + additional_count
    _need(total <= 32, "DNS record count")
    records: list[tuple[str, int, str, int]] = []
    for index in range(total):
        owner, cursor = _name(packet, cursor)
        _need(cursor + 10 <= len(packet), "DNS record header")
        kind, record_class, ttl, length = struct.unpack_from("!HHIH", packet, cursor)
        cursor += 10
        end = cursor + length
        _need(end <= len(packet), "DNS RDATA length")
        value = ""
        if kind in (1, 5):
            _need(record_class == 1, "DNS answer class")
            if kind == 1:
                _need(length == 4, "DNS A length")
                value = str(ipaddress.IPv4Address(packet[cursor:end]))
            else:
                value, used = _name(packet, cursor)
                _need(value != "" and used == end, "DNS CNAME length")
            if index < answer_count:
                records.append((owner, kind, value, ttl if ttl < (1 << 31) else 0))
        cursor = end
    _need(cursor == len(packet), "DNS trailing bytes")
    visited: set[str] = set()
    ttl = (1 << 32) - 1
    for _depth in range(5):
        _need(name not in visited, "DNS alias cycle")
        visited.add(name)
        addresses: list[str] = []
        aliases: set[str] = set()
        for owner, kind, value, lifetime in records:
            if owner != name:
                continue
            ttl = min(ttl, lifetime)
            if kind == 1 and value not in addresses:
                addresses.append(value)
            if kind == 5:
                aliases.add(value)
        _need(len(addresses) <= 4 and len(aliases) <= 1, "DNS RRset bound/conflict")
        _need(not (addresses and aliases), "DNS CNAME/A conflict")
        if addresses:
            return addresses, ttl
        _need(bool(aliases), "DNS no terminal A")
        name = next(iter(aliases))
    raise ValueError("HTTP capture: DNS alias depth")


def _public(address: str) -> bool:
    value = ipaddress.IPv4Address(address)
    # Conservative match to service policy, without trusting platform-dependent
    # is_global classification for special-purpose IPv4 registry entries.
    return not any(value in ipaddress.IPv4Network(network) for network in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "192.0.0.0/24",
        "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/3",
    ))


def verify_capture(
    data: bytes, *, hostname: str | None, resolver: tuple[str, int], port: int,
    expected_destination: str | None = None, expect_connect: bool = True,
    expect_no_application_traffic: bool = False,
) -> dict:
    """Validate guest egress and DNS-to-TCP binding; raise ValueError on refusal.

    ``expected_destination`` is an exact controlled/numeric exception, never an
    allow-private switch. ``expect_connect=False`` requires a real DNS question
    but permits negative/malformed/spoofed replies and requires no TCP initiation.
    It does not weaken Ethernet/IP/transport integrity validation. TCP payload is
    counted, not interpreted as HTTP; the independent ordinary server and client
    body comparator own request/body semantics. ``expect_no_application_traffic``
    is only for pre-attach URL refusal: it requires no hostname/no connect, allows
    a valid empty capture, and rejects all UDP/TCP traffic in either direction.
    """
    resolver = (str(ipaddress.IPv4Address(resolver[0])), resolver[1])
    _need(1 <= port <= 65535 and 1 <= resolver[1] <= 65535, "configuration port")
    if hostname is not None:
        _need(0 < len(hostname) <= 64 and hostname.isascii(), "configuration hostname")
        hostname = hostname.lower()
    if expected_destination is not None:
        expected_destination = str(ipaddress.IPv4Address(expected_destination))
    _need(not expect_no_application_traffic or (hostname is None and not expect_connect), "inconsistent no-application mode")
    _need(expect_no_application_traffic or hostname is not None or expected_destination is not None, "numeric destination absent")
    queries: dict[tuple[int, int], tuple[float, str]] = {}
    permitted: dict[str, float] = {}
    connections: set[tuple[int, str, int]] = set()
    query_count, response_count, tcp_bytes, frame_count = 0, 0, 0, 0
    returned: list[str] = []
    selected: list[str] = []
    for timestamp, frame in _frames(data, allow_empty=expect_no_application_traffic):
        frame_count += 1
        ethertype = int.from_bytes(frame[12:14], "big")
        if ethertype == 0x0806:
            _need(len(frame) >= 42, "short ARP")
            continue
        _need(ethertype == 0x0800, "unexpected Ethernet protocol")
        ip = frame[14:]
        _need(len(ip) >= 20 and ip[0] >> 4 == 4, "IPv4 header")
        header_len, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        _need(20 <= header_len <= total <= len(ip), "IPv4 lengths")
        _need(_checksum(ip[:header_len]) == 0, "IPv4 checksum")
        _need(int.from_bytes(ip[6:8], "big") & 0xBFFF == 0, "fragmented/reserved IPv4")
        source, destination = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        _need(source == GUEST or destination == GUEST, "unrelated IPv4 endpoints")
        protocol, payload = ip[9], ip[header_len:total]
        outgoing = source == GUEST
        pseudo = ip[12:20] + bytes((0, protocol)) + len(payload).to_bytes(2, "big")
        if protocol == 1:
            _need(len(payload) >= 8 and _checksum(payload) == 0, "ICMP integrity")
            _need(not outgoing or payload[0] in (0, 3), "unrelated guest ICMP")
            continue
        _need(not expect_no_application_traffic, "application traffic after pre-attach refusal")
        if protocol == 17:
            _need(len(payload) >= 8, "UDP header")
            src_port, dst_port, length, check = struct.unpack_from("!4H", payload)
            _need(length == len(payload), "UDP length")
            _need(check == 0 or _checksum(pseudo + payload) == 0, "UDP checksum")
            packet = payload[8:]
            if outgoing:
                _need(hostname is not None, "numeric HTTP emitted DNS/UDP")
                _need((destination, dst_port) == resolver and src_port >= 49152, "unauthorized guest UDP tuple")
                identity, flags, name, end = _question(packet)
                _need(flags == 0x0100 and packet[6:12] == b"\0" * 6 and end == len(packet), "not exactly recursive DNS query")
                _need(name == hostname, "unauthorized DNS question")
                _need((src_port, identity) not in queries, "reused DNS transaction tuple")
                queries[src_port, identity] = (timestamp, name)
                query_count += 1
                _need(query_count <= 3, "DNS retry bound")
            elif (source, src_port) == resolver:
                # Bad resolver responses are allowed evidence only when they do
                # not authorize a subsequent TCP destination.
                try:
                    identity, _flags, name, _end = _question(packet)
                    query = queries.get((dst_port, identity))
                    if query is None or query[1] != name:
                        continue
                    addresses, ttl = _answers(packet, name)
                    _need(ttl != 0, "zero DNS lifetime")
                    _need(all(_public(address) or (resolver[1] == 1053 and address == expected_destination) for address in addresses), "sensitive DNS result")
                except ValueError:
                    continue
                response_count += 1
                for address in addresses:
                    permitted[address] = timestamp + min(ttl, 60)
                    if address not in returned:
                        returned.append(address)
            continue
        _need(protocol == 6, "unexpected IPv4 transport")
        _need(len(payload) >= 20, "TCP header")
        src_port, dst_port = struct.unpack_from("!2H", payload)
        header_len = (payload[12] >> 4) * 4
        _need(20 <= header_len <= len(payload) and payload[12] & 15 == 0, "TCP data offset")
        _need(_checksum(pseudo + payload) == 0, "TCP checksum")
        flags = payload[13]
        if outgoing:
            connection = (src_port, destination, dst_port)
            if flags & 2 and not flags & 16:
                _need(expect_connect, "DNS refusal unexpectedly initiated TCP")
                _need(dst_port == port and src_port >= 49152, "unauthorized TCP destination port")
                if hostname is not None:
                    _need(timestamp < permitted.get(destination, -1), "TCP target lacks live matching DNS answer")
                else:
                    _need(destination == expected_destination, "numeric TCP target differs")
                if expected_destination is not None:
                    _need(destination == expected_destination, "controlled TCP target differs")
                connections.add(connection)
                _need(len(connections) <= 4, "TCP address-attempt bound")
                if destination not in selected:
                    selected.append(destination)
            _need(connection in connections, "TCP egress without admitted SYN")
            tcp_bytes += len(payload) - header_len
        else:
            _need((dst_port, source, src_port) in connections, "TCP response without observed connection")
    _need(hostname is None or query_count != 0, "missing guest DNS query")
    _need(not expect_connect or bool(connections), "missing guest TCP SYN")
    return {"frames": frame_count, "dns_queries": query_count, "dns_responses": response_count,
            "answers": returned, "selected": selected, "tcp_connections": len(connections),
            "tcp_payload_bytes": tcp_bytes}
