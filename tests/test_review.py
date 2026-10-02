import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import unittest

from lnk_evidence_review import Limits, encode_report, review_bytes
from fixtures import (
    block,
    counted,
    environment,
    header,
    independent_outline,
    linkinfo,
    property_store,
    typed,
    u16,
    u32,
)


class ReviewTests(unittest.TestCase):
    def codes(self, report):
        return {finding["code"] for finding in report["findings"]}

    def records(self, report, kind):
        return [record for record in report["records"] if record["kind"] == kind]

    def test_minimal_and_all_terminal_values(self):
        for value in range(4):
            with self.subTest(value=value):
                r = review_bytes(header() + u32(value))
                self.assertEqual(r["status"], "PASS")
                self.assertTrue(r["complete"])
                self.assertEqual(self.records(r, "extra_terminal")[0]["terminal_value"], value)
                self.assertTrue(all(value == "OPEN" for value in r["assumptions"].values()))

    def test_all_header_declarations_and_reserved_failures(self):
        data = bytearray(header())
        struct.pack_into("<Q", data, 28, 2**64 - 1)
        struct.pack_into("<i", data, 56, -3)
        struct.pack_into("<I", data, 60, 99)
        r = review_bytes(bytes(data) + u32(0))
        rec = self.records(r, "header")[0]
        self.assertEqual(rec["declared_creation_filetime"], 2**64 - 1)
        self.assertEqual(rec["declared_icon_index"], -3)
        self.assertEqual(rec["effective_show_command"], 1)
        for offset, width, value in (
            (0, 4, 75),
            (4, 1, 0),
            (24, 4, 8),
            (24, 4, 0x90),
            (64, 2, 0x8001),
            (66, 2, 1),
            (68, 4, 1),
            (72, 4, 1),
        ):
            changed = bytearray(header())
            changed[offset : offset + width] = value.to_bytes(width, "little")
            with self.subTest(offset=offset, value=value):
                self.assertEqual(review_bytes(bytes(changed) + u32(0))["status"], "FAIL")

    def test_unused_flags_ignored_unknown_flags_open(self):
        self.assertEqual(review_bytes(header(0x10800) + u32(0))["status"], "PASS")
        self.assertEqual(review_bytes(header(1 << 31) + u32(0))["status"], "OPEN")

    def test_all_five_unicode_strings_physical_counts(self):
        strings = ["标题", ".\\note.txt", "C:\\example", "--note 😀", "%EXAMPLE%\\icon"]
        data = header(0xFC) + b"".join(counted(text) for text in strings) + u32(0)
        r = review_bytes(data, show_text=True)
        values = [record["text"] for record in r["records"] if record["kind"].startswith("string_")]
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(values, strings)
        self.assertEqual(independent_outline(data)["strings"]["arguments"], strings[3])
        for record in r["records"]:
            self.assertEqual(
                hashlib.sha256(
                    data[record["offset"] : record["offset"] + record["size"]]
                ).hexdigest(),
                record["sha256"],
            )

    def test_ansi_encoding_requires_explicit_finite_assertion(self):
        data = header(4) + counted("café", False) + u32(0)
        self.assertEqual(review_bytes(data)["status"], "OPEN")
        r = review_bytes(data, show_text=True, ansi_codepage="cp1252")
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(self.records(r, "string_name")[0]["text"], "café")
        self.assertEqual(
            review_bytes(header(4) + u16(1) + b"\x81" + u32(0), ansi_codepage="cp1252")["status"],
            "OPEN",
        )
        self.assertEqual(
            review_bytes(header(4) + u16(1) + b"\x81" + u32(0), ansi_codepage="cp437")["status"],
            "PASS",
        )

    def test_counted_strings_empty_nul_and_invalid_unicode(self):
        self.assertEqual(review_bytes(header(0x84) + u16(0) + u32(0))["status"], "PASS")
        self.assertEqual(review_bytes(header(0x84) + counted("x\0y") + u32(0))["status"], "OPEN")
        self.assertEqual(review_bytes(header(0x84) + u16(1) + b"\0\xd8" + u32(0))["status"], "FAIL")

    def test_arguments_above_260_advance_using_full_count(self):
        data = header(0xA0) + counted("a" * 1000) + u32(0)
        r = review_bytes(data, show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(self.records(r, "extra_terminal")[0]["offset"], 2078)
        self.assertEqual(len(self.records(r, "string_arguments")[0]["text"]), 1000)
        r = review_bytes(header(0x84) + counted("a" * 261) + u32(0))
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(self.records(r, "extra_terminal")[0]["offset"], 600)

    def test_local_network_ansi_unicode_independent_branches(self):
        for local, network, unicode in (
            (True, False, False),
            (False, True, False),
            (True, False, True),
            (False, True, True),
            (True, True, True),
        ):
            data = header(2) + linkinfo(local, network, unicode) + u32(0)
            with self.subTest(local=local, network=network, unicode=unicode):
                r = review_bytes(data, show_text=True)
                self.assertEqual(r["status"], "PASS")
                self.assertEqual(bool(self.records(r, "volume_id")), local)
                self.assertEqual(bool(self.records(r, "network_link_info")), network)
                self.assertEqual(self.records(r, "common_path_suffix_ansi")[0]["text"], "note.txt")
                if unicode:
                    self.assertEqual(
                        self.records(r, "common_path_suffix_unicode")[0]["text"], "note.txt"
                    )
                self.assertEqual(independent_outline(data)["suffix"], "note.txt")

    def test_force_no_linkinfo_does_not_skip_physical_region(self):
        data = header(0x186) + linkinfo() + counted("later") + u32(0)
        r = review_bytes(data, show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertTrue(self.records(r, "link_info")[0]["resolution_ignored_by_header"])
        self.assertEqual(self.records(r, "string_name")[0]["text"], "later")

    def test_every_linkinfo_offset_size_owner_boundary(self):
        original = linkinfo()
        for at in (0, 4, 12, 16, 20, 24, 28, 32):
            for value in (0, 1, 27, len(original), len(original) + 100, 2**32 - 1):
                if value == int.from_bytes(original[at : at + 4], "little") or (
                    at == 32 and value == 0
                ):
                    continue
                changed = bytearray(original)
                changed[at : at + 4] = u32(value)
                with self.subTest(at=at, value=value):
                    self.assertEqual(
                        review_bytes(header(2) + bytes(changed) + u32(0))["status"], "FAIL"
                    )
        for at in (12, 20):
            parent = int.from_bytes(original[at : at + 4], "little")
            for value in (0, 4, len(original), 2**32 - 1):
                changed = bytearray(original)
                changed[parent : parent + 4] = u32(value)
                self.assertEqual(
                    review_bytes(header(2) + bytes(changed) + u32(0))["status"], "FAIL"
                )

    def test_network_offsets_false_flags_provider_and_terminator(self):
        data = bytearray(linkinfo(False, True, False))
        at = int.from_bytes(data[20:24], "little")
        for relative in (8, 12):
            changed = bytearray(data)
            changed[at + relative : at + relative + 4] = u32(2**32 - 1)
            self.assertEqual(review_bytes(header(2) + bytes(changed) + u32(0))["status"], "FAIL")
        changed = bytearray(data)
        changed[at + 4 : at + 8] = u32(2)
        self.assertEqual(review_bytes(header(2) + bytes(changed) + u32(0))["status"], "FAIL")
        changed = bytearray(data)
        changed[at + 16 : at + 20] = u32(0x20000)
        self.assertEqual(review_bytes(header(2) + bytes(changed) + u32(0))["status"], "OPEN")
        changed = bytearray(data)
        stop = at + int.from_bytes(data[at : at + 4], "little")
        changed[at + 20 : stop] = b"a" * (stop - at - 20)
        self.assertEqual(review_bytes(header(2) + bytes(changed) + u32(0))["status"], "FAIL")

    def test_volume_unicode_label(self):
        original = linkinfo(True, False, True)
        old_at = int.from_bytes(original[12:16], "little")
        label = "磁盘".encode("utf-16-le") + b"\0\0"
        volume = u32(20 + len(label)) + u32(3) + u32(5) + u32(20) + u32(20) + label
        delta = len(volume) - int.from_bytes(original[old_at : old_at + 4], "little")
        data = bytearray(original[:old_at] + volume + original[old_at + 20 :])
        data[:4] = u32(len(data))
        for offset in (16, 24, 28, 32):
            data[offset : offset + 4] = u32(
                int.from_bytes(original[offset : offset + 4], "little") + delta
            )
        r = review_bytes(header(2) + bytes(data) + u32(0), show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(self.records(r, "volume_label_unicode")[0]["text"], "磁盘")

    def test_network_unicode_without_device_paired_and_ambiguous_headers(self):
        ansi = b"\\\\example.invalid\\share\0"
        unicode = "\\\\example.invalid\\share".encode("utf-16-le") + b"\0\0"
        network = (
            u32(24 + len(ansi) + len(unicode))
            + u32(2)
            + u32(24)
            + u32(0)
            + u32(0x200000)
            + u32(24 + len(ansi))
            + ansi
            + unicode
        )
        info = (
            u32(28 + len(network) + 1)
            + u32(28)
            + u32(2)
            + u32(0)
            + u32(0)
            + u32(28)
            + u32(28 + len(network))
            + network
            + b"\0"
        )
        r = review_bytes(header(2) + info + u32(0), show_text=True)
        self.assertEqual(r["status"], "OPEN")
        self.assertIn("ambiguous_single_unicode_offset_layout", self.codes(r))
        self.assertEqual(
            self.records(r, "network_name_unicode")[0]["text"], "\\\\example.invalid\\share"
        )
        self.assertFalse(self.records(r, "network_link_info")[0]["unicode_device_offset_present"])
        paired = (
            u32(28 + len(ansi) + len(unicode))
            + u32(2)
            + u32(28)
            + u32(0)
            + u32(0x200000)
            + u32(28 + len(ansi))
            + u32(0)
            + ansi
            + unicode
        )
        info = (
            u32(28 + len(paired) + 1)
            + u32(28)
            + u32(2)
            + u32(0)
            + u32(0)
            + u32(28)
            + u32(28 + len(paired))
            + paired
            + b"\0"
        )
        r = review_bytes(header(2) + info + u32(0), show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertTrue(self.records(r, "network_link_info")[0]["unicode_device_offset_present"])
        changed = bytearray(info)
        changed[28 + 24 : 28 + 28] = u32(999)
        r = review_bytes(header(2) + bytes(changed) + u32(0))
        self.assertEqual(r["status"], "OPEN")
        self.assertIn("inactive_unicode_device_offset_nonzero", self.codes(r))

    def test_idlist_items_terminal_namespace_and_tail(self):
        self.assertEqual(review_bytes(header(1) + u16(2) + u16(0) + u32(0))["status"], "PASS")
        item = u16(5) + b"abc"
        r = review_bytes(header(1) + u16(7) + item + u16(0) + u32(0))
        self.assertEqual(r["status"], "OPEN")
        self.assertEqual(self.records(r, "namespace_item")[0]["class_byte"], 97)
        for payload in (u16(1), u16(8) + b"ab", item):
            self.assertEqual(
                review_bytes(header(1) + u16(len(payload)) + payload + u32(0))["status"], "FAIL"
            )
        self.assertEqual(
            review_bytes(header(1) + u16(4) + u16(0) + b"ab" + u32(0))["status"], "OPEN"
        )

    def test_environment_icon_darwin_fixed_fields_and_padding(self):
        for signature, flag, status in (
            (0xA0000001, 0x200, "PASS"),
            (0xA0000007, 0x4000, "PASS"),
            (0xA0000006, 0x1000, "OPEN"),
        ):
            data = bytearray(environment(signature))
            data[40:60] = b"x" * 20  # undefined bytes after null ignored
            r = review_bytes(header(flag) + bytes(data) + u32(0), show_text=True)
            self.assertEqual(r["status"], status)
            self.assertTrue(
                any("environment_marker" in item.get("indicators", []) for item in r["records"])
            )
            data = bytearray(environment(signature))
            data[8:268] = b"x" * 260
            self.assertEqual(review_bytes(header(flag) + bytes(data) + u32(0))["status"], "FAIL")

    def test_all_known_extra_sizes_and_flag_consistency(self):
        for signature, size in (
            (0xA0000001, 788),
            (0xA0000002, 204),
            (0xA0000003, 96),
            (0xA0000004, 12),
            (0xA0000005, 16),
            (0xA0000006, 788),
            (0xA0000007, 788),
            (0xA000000B, 28),
        ):
            for delta in (-1, 1):
                r = review_bytes(header() + block(signature, b"\0" * (size - 8 + delta)) + u32(0))
                self.assertEqual(r["status"], "FAIL")
        for signature in (0xA0000008, 0xA0000009, 0xA000000C):
            self.assertEqual(
                review_bytes(header() + block(signature, b"") + u32(0))["status"], "FAIL"
            )
        self.assertEqual(review_bytes(header(0x200) + u32(0))["status"], "FAIL")
        self.assertEqual(review_bytes(header() + environment() + u32(0))["status"], "OPEN")

    def test_console_all_colors_and_positive_boolean(self):
        payload = bytearray(196)
        payload[104:108] = u32(2)
        for index in range(16):
            payload[132 + index * 4 : 136 + index * 4] = u32(index + 100)
        r = review_bytes(header() + block(0xA0000002, bytes(payload)) + u32(0))
        self.assertEqual(r["status"], "PASS")
        rec = self.records(r, "extra_console")[0]
        self.assertTrue(rec["full_screen"])
        self.assertEqual(rec["color_table"], list(range(100, 116)))

    def test_tracker_codepage_shim_vista_and_folder_boundaries(self):
        tracker = block(
            0xA0000003, u32(88) + u32(0) + b"machine\0".ljust(16, b"\0") + bytes(range(64))
        )
        r = review_bytes(header() + tracker + u32(0))
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(len(self.records(r, "droid_volume")), 1)
        changed = bytearray(tracker)
        changed[12:16] = u32(1)
        self.assertEqual(review_bytes(header() + bytes(changed) + u32(0))["status"], "FAIL")
        cp = block(0xA0000004, u32(1200))
        r = review_bytes(header() + cp + u32(0))
        self.assertFalse(self.records(r, "extra_console_codepage")[0]["used_for_ansi_decoding"])
        shim = block(0xA0000008, ("层".encode("utf-16-le") + b"\0\0").ljust(128, b"\0"))
        r = review_bytes(header(0x20000) + shim + u32(0), show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(self.records(r, "shim_layer")[0]["text"], "层")
        self.assertEqual(
            review_bytes(header() + block(0xA000000C, u16(0)) + u32(0))["status"], "PASS"
        )
        folder = block(0xA0000005, u32(2) + u32(0))
        self.assertEqual(review_bytes(header() + folder + u32(0))["status"], "OPEN")
        self.assertEqual(
            review_bytes(header(1) + u16(2) + u16(0) + folder + u32(0))["status"], "FAIL"
        )
        item = u16(3) + b"a" + u16(0)
        self.assertEqual(
            review_bytes(header(1) + u16(len(item)) + item + folder + u32(0))["status"], "OPEN"
        )

    def test_unknown_duplicate_and_tail_lossless_provenance(self):
        raw = block(0xDEADBEEF, b"secret opaque bytes")
        data = header() + raw + raw + u32(1) + b"tail"
        r = review_bytes(data)
        self.assertEqual(r["status"], "OPEN")
        self.assertEqual(len(self.records(r, "unknown_extra")), 2)
        self.assertIn("duplicate_extra_signature", self.codes(r))
        for item in self.records(r, "unknown_extra") + self.records(r, "post_terminal_bytes"):
            self.assertEqual(
                hashlib.sha256(data[item["offset"] : item["offset"] + item["size"]]).hexdigest(),
                item["sha256"],
            )
        self.assertNotIn("secret", encode_report(r))
        self.assertNotIn("tail", json.dumps(r.get("text", {})))

    def test_truncated_string_missing_terminal_block4to7(self):
        for data in (
            header(),
            header(0x84) + u16(5) + b"x\0",
            header() + u32(8),
            header() + block(4, b"a"),
        ):
            self.assertEqual(review_bytes(data)["status"], "FAIL")
        for size in range(4, 8):
            self.assertEqual(review_bytes(header() + u32(size) + b"abcd")["status"], "FAIL")

    def test_property_scalar_subset_and_signed_i2(self):
        table = [
            (2, struct.pack("<hH", -3, 0), -3),
            (3, struct.pack("<i", -42), -42),
            (4, struct.pack("<f", 1.5), 1.5),
            (5, struct.pack("<d", 2.5), 2.5),
            (11, struct.pack("<hH", -1, 0), -1),
            (16, b"\xff\0\0\0", -1),
            (17, b"\xff\0\0\0", 255),
            (18, u16(123) + u16(0), 123),
            (19, u32(42), 42),
            (20, struct.pack("<q", -(2**40)), -(2**40)),
            (21, struct.pack("<Q", 2**63), 2**63),
            (22, u32(42), 42),
            (23, u32(42), 42),
            (64, struct.pack("<Q", 2**64 - 1), 2**64 - 1),
        ]
        data = (
            header()
            + property_store(
                [(index + 1, typed(typ, payload)) for index, (typ, payload, _) in enumerate(table)]
            )
            + u32(0)
        )
        r = review_bytes(data, show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(
            [item["value"] for item in self.records(r, "typed_property")],
            [expected for _, _, expected in table],
        )
        self.assertTrue(
            all("value" not in item for item in self.records(review_bytes(data), "typed_property"))
        )

    def test_property_names_unicode_blob_unknown_and_nonfinite(self):
        text = "note".encode("utf-16-le") + b"\0\0"
        padded = text.ljust((len(text) + 3) & ~3, b"\0")
        prop = property_store([("label", typed(31, u32(len(text) // 2) + padded))], True)
        r = review_bytes(header() + prop + u32(0), show_text=True)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(self.records(r, "property_string")[0]["text"], "note")
        for value in (
            typed(65, u32(3) + b"abc\0"),
            typed(0x101F, b"opaque"),
            typed(5, struct.pack("<d", float("nan"))),
        ):
            r = review_bytes(header() + property_store([(1, value)]) + u32(0))
            self.assertEqual(r["status"], "OPEN")
            json.loads(encode_report(r))

    def test_property_duplicate_size_padding_version_terminal(self):
        p = property_store([(1, typed(3, u32(1))), (1, typed(3, u32(2)))])
        self.assertEqual(review_bytes(header() + p + u32(0))["status"], "FAIL")
        p = property_store([("x", typed(3, u32(1))), ("x", typed(3, u32(2)))], True)
        self.assertEqual(review_bytes(header() + p + u32(0))["status"], "FAIL")
        p = property_store([(1, typed(2, u16(1) + u16(1)))])
        self.assertEqual(review_bytes(header() + p + u32(0))["status"], "FAIL")
        p = bytearray(property_store([(1, typed(3, u32(1)))]))
        for at, value in ((8, 4), (12, 0), (32, 2**32 - 1), (40, 1)):
            q = bytearray(p)
            q[at : at + 4] = u32(value)
            self.assertNotEqual(review_bytes(header() + bytes(q) + u32(0))["status"], "PASS")

    def test_official_fixed_sample_reference_outline(self):
        data = bytes.fromhex((Path(__file__).parent / "ms-shllink-10.0-file.hex").read_text())
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            "09ac337f52c4c9dc49772e97060145a316cb4af076cfb122fb4a219ecbfbfdd7",
        )
        expected = independent_outline(data)
        r = review_bytes(data, show_text=True)
        self.assertEqual(r["status"], "OPEN")
        self.assertEqual(self.codes(r), {"vendor_namespace_payload_uninterpreted"})
        self.assertEqual(self.records(r, "header")[0]["link_flags"], expected["flags"])
        for name, value in expected["strings"].items():
            self.assertEqual(self.records(r, "string_" + name)[0]["text"], value)
        self.assertEqual(self.records(r, "extra_terminal")[0]["offset"], 455)
        self.assertEqual(
            [
                (item["offset"], item["size"], item["signature"])
                for item in self.records(r, "extra_tracker")
            ],
            expected["extra"],
        )

    def test_known_folder_guid_and_property_empty_null_clsid(self):
        import uuid

        folder = block(
            0xA000000B, uuid.UUID("000214a0-0000-0000-c000-000000000046").bytes_le + u32(0)
        )
        item = u16(3) + b"a" + u16(0)
        r = review_bytes(header(1) + u16(len(item)) + item + folder + u32(0), show_text=True)
        self.assertEqual(r["status"], "OPEN")
        self.assertEqual(self.records(r, "extra_known_folder")[0]["target_idlist_offset"], 0)
        self.assertEqual(
            self.records(r, "known_folder_id")[0]["guid"], "000214a0-0000-0000-c000-000000000046"
        )
        value = property_store(
            [
                (1, typed(0, b"")),
                (2, typed(1, b"")),
                (3, typed(72, uuid.UUID("000214a0-0000-0000-c000-000000000046").bytes_le)),
            ]
        )
        r = review_bytes(header() + value + u32(0))
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(len(self.records(r, "property_guid")), 1)
        self.assertEqual(
            review_bytes(header() + block(0xA0000009, u32(0)) + u32(0))["status"], "PASS"
        )

    def test_malformed_known_extra_keeps_later_unknown_and_fail_open(self):
        data = header() + block(0xA0000002, b"bad") + block(0xABC, b"opaque") + u32(0)
        r = review_bytes(data)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual({item["status"] for item in r["findings"]}, {"FAIL", "OPEN"})
        self.assertEqual(len(self.records(r, "malformed_known_extra")), 1)
        self.assertEqual(len(self.records(r, "unknown_extra")), 1)
        self.assertEqual(self.records(r, "extra_terminal")[0]["offset"], len(data) - 4)

    def test_every_prefix_of_official_sample_is_incomplete(self):
        data = bytes.fromhex((Path(__file__).parent / "ms-shllink-10.0-file.hex").read_text())
        for cut in range(len(data)):
            r = review_bytes(data[:cut])
            self.assertNotEqual(r["status"], "PASS")
            self.assertFalse(r["complete"])

    def test_every_budget_and_fail_retention(self):
        strings = header(0x84) + counted("abcdef") + u32(0)
        table = [
            (strings, Limits(input_bytes=80)),
            (strings, Limits(structures=1)),
            (strings, Limits(text_bytes=1)),
            (strings, Limits(text_field_bytes=1)),
            (header(1) + u16(8) + u16(3) + b"a" + u16(3) + b"b" + u16(0) + u32(0), Limits(items=1)),
            (header() + block(99, b"") + block(98, b"") + u32(0), Limits(extra_blocks=1)),
            (
                header() + property_store([(1, typed(3, u32(1))), (2, typed(3, u32(1)))]) + u32(0),
                Limits(properties=1),
            ),
            (header() + block(99, b"") + block(98, b"") + u32(0), Limits(findings=1)),
        ]
        for data, limits in table:
            r = review_bytes(data, limits=limits)
            self.assertEqual(r["status"], "OPEN")
            self.assertFalse(r["complete"])
        changed = bytearray(strings)
        changed[68:72] = u32(1)
        for limits in (Limits(structures=1), Limits(text_field_bytes=1), Limits(report_bytes=2048)):
            r = review_bytes(bytes(changed), limits=limits)
            self.assertEqual(r["status"], "FAIL")
            self.assertFalse(r["complete"])
            self.assertLessEqual(len(encode_report(r).encode("ascii")), limits.report_bytes)
        r = review_bytes(strings, limits=Limits(input_bytes=1))
        self.assertIsNone(r["input"]["sha256"])

    def test_report_budget_with_disclosed_text_and_privacy(self):
        secret = "UNC_SECRET_名字\\note & command\n"
        data = header(0xA0) + counted(secret * 100) + u32(0)
        r = review_bytes(data)
        self.assertNotIn("UNC_SECRET", encode_report(r))
        r = review_bytes(data, show_text=True, limits=Limits(report_bytes=2048))
        self.assertEqual(r["status"], "OPEN")
        self.assertEqual(r["records"], [])
        self.assertLessEqual(len(encode_report(r).encode("ascii")), 2048)
        r = review_bytes(header(0xA0) + counted(secret) + u32(0), show_text=True)
        line = encode_report(r)
        self.assertEqual(line.count("\n"), 1)
        self.assertIn("\\n", line)
        self.assertIn("\\u", line)

    def test_input_api_contract_and_limits(self):
        for data in (None, bytearray(header()), memoryview(header()), "text"):
            with self.assertRaises(TypeError):
                review_bytes(data)
        for limits in (False, {}, 0):
            with self.assertRaises(TypeError):
                review_bytes(header(), limits=limits)
        for values in (
            {"items": 0},
            {"items": True},
            {"report_bytes": 2047},
            {"input_bytes": 2**40},
        ):
            with self.assertRaises(ValueError):
                Limits(**values)
        with self.assertRaises(ValueError):
            review_bytes(header(), ansi_codepage="utf-8")
        with self.assertRaises(TypeError):
            review_bytes(header(), show_text=1)

    def test_no_runtime_file_network_process_or_module_side_effect(self):
        data = (
            header(0xA0)
            + counted("\\\\example.invalid\\share & command http://example.invalid %EXAMPLE%")
            + u32(0)
        )
        before = hashlib.sha256(data).hexdigest()
        active = [True]
        attempts = []

        def guard(event, args):
            if active[0] and (
                event
                in ("open", "os.system", "os.exec", "os.posix_spawn", "subprocess.Popen", "import")
                or event.startswith("socket.")
            ):
                attempts.append(event)
                raise AssertionError(event)

        sys.addaudithook(guard)
        try:
            for _ in range(10):
                self.assertEqual(review_bytes(data)["status"], "PASS")
        finally:
            active[0] = False
        self.assertEqual(attempts, [])
        self.assertEqual(hashlib.sha256(data).hexdigest(), before)

    def test_seeded_mutation_bounded_output_and_no_input_change(self):
        seeds = [
            header() + u32(0),
            header(2) + linkinfo() + u32(0),
            header(0x200) + environment() + u32(0),
            header() + property_store([(1, typed(3, u32(42)))]) + u32(0),
        ]
        rng = random.Random(0x4C4E4B)
        for _ in range(1000):
            data = bytearray(rng.choice(seeds))
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            frozen = bytes(data)
            digest = hashlib.sha256(frozen).hexdigest()
            r = review_bytes(frozen, limits=Limits(report_bytes=2048))
            self.assertIn(r["status"], ("PASS", "FAIL", "OPEN"))
            json.loads(encode_report(r))
            self.assertLessEqual(len(encode_report(r).encode("ascii")), 2048)
            self.assertEqual(hashlib.sha256(frozen).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
