import struct
import unittest

from backend.app.demo import build_demo_pcap
from backend.app.pcap import CaptureError, parse_pcap
from backend.app.security import assess


class PcapTests(unittest.TestCase):
    def test_synthetic_capture_is_parsed_from_bytes(self):
        capture = parse_pcap(build_demo_pcap())
        self.assertEqual(capture.packet_count, 4)
        self.assertEqual((capture.ike_count, capture.esp_count, capture.ah_count), (1, 1, 1))
        self.assertEqual(capture.other_ip_count, 1)
        self.assertEqual(capture.malformed_packets, 0)
        self.assertEqual(capture.ike_messages[0]["version"], "IKEv2.0")
        self.assertEqual(
            {(item["type"], item["name"]) for item in capture.transforms},
            {
                ("encryption", "AES-CBC-128"),
                ("prf", "PRF-HMAC-SHA1"),
                ("integrity", "HMAC-SHA1-96"),
                ("dh_group", "MODP-1024 (group 2)"),
            },
        )
        self.assertEqual(capture.esp_packets[0]["spi"], "0x10203040")
        self.assertEqual(capture.ah_packets[0]["spi"], "0x50607080")

    def test_invalid_inputs_are_explicit(self):
        cases = [
            (b"", "empty"),
            (b"not a capture", "short"),
            (b"\x0a\x0d\x0d\x0a" + bytes(40), "PCAPNG"),
        ]
        for data, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(CaptureError, message):
                parse_pcap(data)

    def test_capture_without_ipsec_is_rejected(self):
        data = bytearray(build_demo_pcap()[:24])
        frame = bytes.fromhex("0200000000020200000000010800")
        ip = bytes.fromhex("450000140001400040060000c0000201c6336414")
        frame += ip
        data.extend(struct.pack("<IIII", 1, 0, len(frame), len(frame)))
        data.extend(frame)
        with self.assertRaisesRegex(CaptureError, "No identifiable"):
            parse_pcap(bytes(data))

    def test_risk_is_reproducible_from_observed_transforms(self):
        capture = parse_pcap(build_demo_pcap())
        assessment = assess(capture.transforms)
        self.assertEqual(assessment["score"], 90)
        self.assertEqual(assessment["category"], "CRITICAL")
        statuses = {item["parameter"]: item["status"] for item in assessment["findings"]}
        self.assertEqual(statuses["Encryption algorithm"], "WARNING")
        self.assertEqual(statuses["PRF algorithm"], "WARNING")
        self.assertEqual(statuses["Integrity algorithm"], "FAIL")
        self.assertEqual(statuses["Diffie-Hellman group"], "FAIL")
        self.assertEqual(statuses["Perfect Forward Secrecy"], "UNKNOWN")
        self.assertEqual(statuses["Key lifetime"], "UNKNOWN")

    def test_unknown_and_modern_aead_transforms_are_not_failed(self):
        unknown = assess([])
        self.assertEqual(unknown["score"], 0)
        self.assertTrue(all(item["status"] == "UNKNOWN" for item in unknown["findings"]))

        modern = assess([
            {"type": "encryption", "id": 20, "name": "AES-GCM-16"},
            {"type": "prf", "id": 5, "name": "PRF-HMAC-SHA2-256"},
            {"type": "dh_group", "id": 14, "name": "MODP-2048 (group 14)"},
        ])
        statuses = {item["parameter"]: item["status"] for item in modern["findings"]}
        self.assertEqual(modern["score"], 0)
        self.assertEqual(statuses["Encryption algorithm"], "PASS")
        self.assertEqual(statuses["PRF algorithm"], "PASS")
        self.assertEqual(statuses["Integrity algorithm"], "UNKNOWN")
        self.assertEqual(statuses["Diffie-Hellman group"], "PASS")


if __name__ == "__main__":
    unittest.main()
