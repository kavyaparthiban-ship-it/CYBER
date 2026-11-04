from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any


MAX_CAPTURE_BYTES = 20 * 1024 * 1024
MAX_PACKETS = 200_000
MAX_PACKET_DETAILS = 100


class CaptureError(ValueError):
    """A capture is invalid, unsupported, or contains no analyzable IPsec traffic."""


@dataclass
class CaptureResult:
    packet_count: int = 0
    ike_count: int = 0
    esp_count: int = 0
    ah_count: int = 0
    other_ip_count: int = 0
    malformed_packets: int = 0
    ike_messages: list[dict[str, Any]] = field(default_factory=list)
    esp_packets: list[dict[str, Any]] = field(default_factory=list)
    ah_packets: list[dict[str, Any]] = field(default_factory=list)
    details: list[dict[str, Any]] = field(default_factory=list)
    transforms: list[dict[str, Any]] = field(default_factory=list)
    link_type: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "ike_count": self.ike_count,
            "esp_count": self.esp_count,
            "ah_count": self.ah_count,
            "other_ip_count": self.other_ip_count,
            "malformed_packets": self.malformed_packets,
            "ike_messages": self.ike_messages,
            "esp_packets": self.esp_packets,
            "ah_packets": self.ah_packets,
            "details": self.details,
            "transforms": self.transforms,
            "link_type": self.link_type,
        }


ENCR_NAMES = {3: "3DES-CBC", 12: "AES-CBC", 20: "AES-GCM-16"}
INTEG_NAMES = {2: "HMAC-SHA1-96", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}
PRF_NAMES = {2: "PRF-HMAC-SHA1", 5: "PRF-HMAC-SHA2-256", 6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512"}
DH_NAMES = {2: "MODP-1024 (group 2)", 14: "MODP-2048 (group 14)", 19: "ECP-256 (group 19)", 20: "ECP-384 (group 20)", 31: "Curve25519 (group 31)"}
TRANSFORM_TYPES = {1: "encryption", 2: "prf", 3: "integrity", 4: "dh_group"}


def _parse_ike_sa(data: bytes, next_payload: int) -> list[dict[str, Any]]:
    """Read IKEv2 SA proposal transforms. These are offered, not negotiated."""
    transforms: list[dict[str, Any]] = []
    offset = 28
    while next_payload and offset + 4 <= len(data):
        payload_type = next_payload
        following = data[offset]
        payload_length = struct.unpack_from("!H", data, offset + 2)[0]
        if payload_length < 4 or offset + payload_length > len(data):
            break
        body = data[offset + 4:offset + payload_length]
        if payload_type == 33 and len(body) >= 8:
            proposal_offset = 0
            while proposal_offset + 8 <= len(body):
                last_proposal = body[proposal_offset]
                proposal_length = struct.unpack_from("!H", body, proposal_offset + 2)[0]
                spi_size = body[proposal_offset + 6]
                transform_count = body[proposal_offset + 7]
                proposal_end = proposal_offset + proposal_length
                position = proposal_offset + 8 + spi_size
                if proposal_length < 8 or proposal_end > len(body) or position > proposal_end:
                    break
                parsed_count = 0
                while position + 8 <= proposal_end and parsed_count < transform_count:
                    transform_last = body[position]
                    transform_length = struct.unpack_from("!H", body, position + 2)[0]
                    if transform_length < 8 or position + transform_length > proposal_end:
                        break
                    transform_type = body[position + 4]
                    transform_id = struct.unpack_from("!H", body, position + 6)[0]
                    attributes: dict[int, int] = {}
                    attr_pos = position + 8
                    while attr_pos + 4 <= position + transform_length:
                        attr_type_raw, attr_value = struct.unpack_from("!HH", body, attr_pos)
                        attr_type = attr_type_raw & 0x7FFF
                        if attr_type_raw & 0x8000:
                            attributes[attr_type] = attr_value
                            attr_pos += 4
                        else:
                            attr_size = attr_value
                            if attr_pos + 4 + attr_size > position + transform_length:
                                break
                            attr_pos += 4 + attr_size
                    names = {1: ENCR_NAMES, 2: PRF_NAMES, 3: INTEG_NAMES, 4: DH_NAMES}
                    item: dict[str, Any] = {
                        "type": TRANSFORM_TYPES.get(transform_type, f"transform_{transform_type}"),
                        "id": transform_id,
                        "name": names.get(transform_type, {}).get(transform_id, f"Unknown ({transform_id})"),
                    }
                    if transform_type == 1 and 14 in attributes:
                        item["key_length_bits"] = attributes[14]
                        item["name"] += f"-{attributes[14]}"
                    transforms.append(item)
                    position += transform_length
                    parsed_count += 1
                    if transform_last == 3:
                        break
                if last_proposal == 2:
                    break
                proposal_offset = proposal_end
        offset += payload_length
        next_payload = following
    return transforms


def _parse_ike(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 28:
        return None
    version = payload[17]
    message_length = struct.unpack_from("!I", payload, 24)[0]
    if version >> 4 not in (1, 2) or message_length < 28 or message_length > len(payload):
        return None
    packet = payload[:message_length]
    next_payload = packet[16]
    transforms = _parse_ike_sa(packet, next_payload) if version >> 4 == 2 else []
    return {
        "version": f"IKEv{version >> 4}.{version & 0x0F}",
        "exchange_type": packet[18],
        "message_id": struct.unpack_from("!I", packet, 20)[0],
        "length": message_length,
        "transforms": transforms,
    }


def _network_header(frame: bytes, link_type: int) -> tuple[int, bytes] | None:
    if link_type == 1:
        if len(frame) < 14:
            return None
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ether_type == 0x0800:
            return 4, frame[offset:]
        if ether_type == 0x86DD:
            return 6, frame[offset:]
        return None
    if link_type == 101:
        if not frame:
            return None
        version = frame[0] >> 4
        return (version, frame) if version in (4, 6) else None
    return None


def _ipv4(data: bytes) -> tuple[str, str, int, bytes] | None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    header_len = (data[0] & 15) * 4
    total_len = struct.unpack_from("!H", data, 2)[0]
    fragment = struct.unpack_from("!H", data, 6)[0] & 0x1FFF
    if header_len < 20 or total_len < header_len or len(data) < header_len or fragment:
        return None
    total_len = min(total_len, len(data))
    return str(ipaddress.IPv4Address(data[12:16])), str(ipaddress.IPv4Address(data[16:20])), data[9], data[header_len:total_len]


def _ipv6(data: bytes) -> tuple[str, str, int, bytes] | None:
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    total_len = min(40 + struct.unpack_from("!H", data, 4)[0], len(data))
    source, destination = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
    next_header = data[6]
    offset = 40
    while next_header in (0, 43, 60):
        if offset + 2 > total_len:
            return None
        following = data[offset]
        length = (data[offset + 1] + 1) * 8
        if offset + length > total_len:
            return None
        next_header, offset = following, offset + length
    if next_header == 44:
        if offset + 8 > total_len:
            return None
        fragment = struct.unpack_from("!H", data, offset + 2)[0]
        if (fragment >> 3) & 0x1FFF:
            return None
        next_header, offset = data[offset], offset + 8
    return source, destination, next_header, data[offset:total_len]


def _inspect_ip(result: CaptureResult, frame: bytes, timestamp: float, original_len: int) -> None:
    network = _network_header(frame, result.link_type)
    if network is None:
        return
    version, packet = network
    parsed = _ipv4(packet) if version == 4 else _ipv6(packet)
    if parsed is None:
        result.malformed_packets += 1
        return
    source, destination, protocol, transport = parsed
    detail: dict[str, Any] = {
        "timestamp": timestamp,
        "source": source,
        "destination": destination,
        "packet_length": original_len,
        "ip_protocol": protocol,
        "protocol": "Other IP",
    }
    if protocol == 50 and len(transport) >= 8:
        spi, sequence = struct.unpack_from("!II", transport)
        result.esp_count += 1
        result.esp_packets.append({"source": source, "destination": destination, "spi": f"0x{spi:08x}", "sequence": sequence, "length": original_len})
        detail.update(protocol="ESP", spi=f"0x{spi:08x}", sequence=sequence)
    elif protocol == 51 and len(transport) >= 12:
        header_len = (transport[1] + 2) * 4
        if header_len <= len(transport):
            spi, sequence = struct.unpack_from("!II", transport, 4)
            result.ah_count += 1
            result.ah_packets.append({"source": source, "destination": destination, "spi": f"0x{spi:08x}", "sequence": sequence, "header_length": header_len, "length": original_len})
            detail.update(protocol="AH", spi=f"0x{spi:08x}", sequence=sequence)
        else:
            result.malformed_packets += 1
    elif protocol == 17 and len(transport) >= 8:
        source_port, dest_port, udp_len = struct.unpack_from("!HHH", transport)
        if udp_len < 8 or udp_len > len(transport):
            result.malformed_packets += 1
            return
        udp_payload = transport[8:udp_len]
        detail.update(source_port=source_port, destination_port=dest_port)
        if source_port in (500, 4500) or dest_port in (500, 4500):
            ike_payload = udp_payload
            if (source_port == 4500 or dest_port == 4500) and len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                ike_payload = udp_payload[4:]
            elif (source_port == 4500 or dest_port == 4500) and len(udp_payload) >= 8:
                spi, sequence = struct.unpack_from("!II", udp_payload)
                result.esp_count += 1
                result.esp_packets.append({"source": source, "destination": destination, "spi": f"0x{spi:08x}", "sequence": sequence, "length": original_len, "encapsulation": "UDP/4500"})
                detail.update(protocol="ESP (UDP-encapsulated)", spi=f"0x{spi:08x}", sequence=sequence)
                result.details.append(detail)
                return
            ike = _parse_ike(ike_payload)
            if ike is not None:
                result.ike_count += 1
                result.transforms.extend(ike.pop("transforms"))
                result.ike_messages.append({"source": source, "destination": destination, "source_port": source_port, "destination_port": dest_port, **ike})
                detail.update(protocol="IKE", ike_version=ike["version"], exchange_type=ike["exchange_type"])
        if detail["protocol"] == "Other IP":
            result.other_ip_count += 1
    else:
        result.other_ip_count += 1
    if len(result.details) < MAX_PACKET_DETAILS:
        result.details.append(detail)


def parse_pcap(data: bytes) -> CaptureResult:
    if not data:
        raise CaptureError("The uploaded file is empty.")
    if len(data) > MAX_CAPTURE_BYTES:
        raise CaptureError(f"Capture exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MB upload limit.")
    if len(data) < 24:
        raise CaptureError("File is too short to contain a classic PCAP global header.")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        if magic in (b"\x0a\x0d\x0d\x0a",):
            raise CaptureError("PCAPNG input is not supported in this PoC. Export as classic PCAP (Ethernet) and try again.")
        raise CaptureError("Unsupported or invalid file. Expected a classic PCAP capture.")
    endian, time_resolution = formats[magic]
    _, major, minor, _, _, snaplen, link_type = struct.unpack_from(f"{endian}IHHIIII", data, 0)
    if (major, minor) != (2, 4):
        raise CaptureError(f"Unsupported PCAP version {major}.{minor}; classic PCAP 2.4 is required.")
    if link_type not in (1, 101):
        raise CaptureError(f"Unsupported PCAP link type {link_type}; Ethernet or raw IP is required.")
    result = CaptureResult(link_type=link_type)
    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise CaptureError("Capture ends with an incomplete packet record header.")
        seconds, fraction, captured_len, original_len = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if captured_len > snaplen or captured_len > len(data) - offset or captured_len > 65_535:
            raise CaptureError("Capture contains a truncated or invalid packet record.")
        if result.packet_count >= MAX_PACKETS:
            raise CaptureError(f"Capture exceeds the {MAX_PACKETS:,} packet processing limit.")
        frame = data[offset:offset + captured_len]
        offset += captured_len
        result.packet_count += 1
        timestamp = seconds + fraction / time_resolution
        _inspect_ip(result, frame, timestamp, original_len)
    if result.packet_count == 0:
        raise CaptureError("Capture contains no packets.")
    if not (result.ike_count or result.esp_count or result.ah_count):
        raise CaptureError("No identifiable IKE, ESP, or AH packets were found in this capture.")
    return result
