from __future__ import annotations

import ipaddress
import struct


def _transform(kind: int, transform_id: int, last: int, attributes: bytes = b"") -> bytes:
    length = 8 + len(attributes)
    return struct.pack("!BBHBBH", last, 0, length, kind, 0, transform_id) + attributes


def _ike_init() -> bytes:
    transforms = b"".join([
        _transform(1, 12, 0, struct.pack("!HH", 0x800E, 128)),
        _transform(2, 2, 0),
        _transform(3, 2, 0),
        _transform(4, 2, 3),
    ])
    proposal = struct.pack("!BBHBBBB", 2, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    total_length = 28 + len(sa_payload)
    ike_header = (
        bytes.fromhex("0102030405060708")
        + bytes.fromhex("0000000000000000")
        + struct.pack("!BBBBII", 33, 0x20, 34, 8, 1, total_length)
    )
    return ike_header + sa_payload


def _udp(source_port: int, dest_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, dest_port, 8 + len(payload), 0) + payload


def _ipv4(source: str, destination: str, protocol: int, payload: bytes, identification: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), identification, 0x4000, 64, protocol, 0,
        ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed,
    )
    checksum = 0
    padded = header + (b"\x00" if len(header) % 2 else b"")
    for index in range(0, len(padded), 2):
        checksum += (padded[index] << 8) | padded[index + 1]
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return header[:10] + struct.pack("!H", (~checksum) & 0xFFFF) + header[12:] + payload


def _ethernet(ip_packet: bytes) -> bytes:
    return bytes.fromhex("0200000000020200000000010800") + ip_packet


def build_demo_pcap() -> bytes:
    """Build deterministic, synthetic lab frames with structurally parseable IPsec headers."""
    frames = [
        _ethernet(_ipv4("192.0.2.10", "198.51.100.20", 17, _udp(500, 500, _ike_init()), 1)),
        _ethernet(_ipv4("192.0.2.10", "198.51.100.20", 50, struct.pack("!II", 0x10203040, 1) + bytes(32), 2)),
        _ethernet(_ipv4("198.51.100.20", "192.0.2.10", 51, struct.pack("!BBHII", 1, 0, 0, 0x50607080, 1) + bytes(20), 3)),
        _ethernet(_ipv4("192.0.2.10", "198.51.100.20", 6, bytes.fromhex("c35001bb00000000000000005002000000000000"), 4)),
    ]
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
    for index, frame in enumerate(frames):
        capture.extend(struct.pack("<IIII", 1_767_000_000 + index, 250_000, len(frame), len(frame)))
        capture.extend(frame)
    return bytes(capture)
