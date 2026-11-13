import struct
import unittest
import zlib

import release_check as rc
from test_archive_scan import zipped

TERM = "HiddenPerson"
SCAN_DATA = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x12\x34" * 200 + b"\xff\xd9"


def ifd(entries: dict[int, tuple[int, int, bytes]], start: int) -> bytes:
    body, extra = struct.pack("<H", len(entries)), b""
    tail = start + 2 + 12 * len(entries) + 4
    for tag, (kind, count, value) in sorted(entries.items()):
        if len(value) <= 4:
            body += struct.pack("<HHI", tag, kind, count) + value.ljust(4, b"\0")
        else:
            body += struct.pack("<HHII", tag, kind, count, tail + len(extra))
            extra += value
    return body + b"\0\0\0\0" + extra


def tiff(ascii_tags: dict[int, str], wide_tags: dict[int, str] | None = None, gps: bool = False) -> bytes:
    entries = {tag: (2, len(text) + 1, text.encode() + b"\0") for tag, text in ascii_tags.items()}
    entries |= {tag: (1, len(text) * 2 + 2, text.encode("utf-16-le") + b"\0\0") for tag, text in (wide_tags or {}).items()}
    first = ifd(entries, 8)
    if gps:
        entries[0x8825] = (4, 1, b"\0" * 4)
        pointer = 8 + len(ifd(entries, 8))
        entries[0x8825] = (4, 1, struct.pack("<I", pointer))
        first = ifd(entries, 8) + ifd({1: (2, 2, b"N\0"), 2: (5, 3, struct.pack("<6I", 51, 1, 30, 1, 0, 1))}, pointer)
    return b"II*\0" + struct.pack("<I", 8) + first


def jpeg(exif: bytes) -> bytes:
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"
    payload = b"Exif\0\0" + exif
    return b"\xff\xd8" + app0 + b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload + SCAN_DATA


def png(chunks: list[tuple[bytes, bytes]]) -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    header = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    image = chunk(b"IDAT", zlib.compress(b"\0\0"))
    return b"\x89PNG\r\n\x1a\n" + header + b"".join(chunk(k, d) for k, d in chunks) + image + chunk(b"IEND", b"")


def denylisted(raw: bytes, path: str) -> set[str]:
    scanner = rc.Scanner([TERM])
    scanner.file(raw, "tree", path)
    return {f["path"] for f in scanner.findings if f["kind"] == "denylist"}


class MetadataScanTests(unittest.TestCase):
    def test_jpeg_exif_author_equal_to_a_denylist_term_fails(self):
        raw = jpeg(tiff({0x013B: TERM, 0x0131: "Editor 1.0"}))
        scanner = rc.Scanner([TERM])
        scanner.file(raw, "tree", "photo.jpg")
        self.assertIn("photo.jpg!metadata", {f["path"] for f in scanner.findings if f["kind"] == "denylist"})
        report = {"findings": scanner.findings, "verification": {"status": "pass"},
                  "license": {"status": "pass", "dependencies": "pass"}, "stats": {"tree_files": 1, "history_commits": 1}}
        self.assertEqual(rc.outcome(report)["outcome"], "FAIL")
        self.assertIn("denylist", rc.outcome(report)["reasons"])

    def test_utf16_windows_author_hidden_from_raw_bytes_is_decoded(self):
        raw = jpeg(tiff({}, {0x9C9D: TERM}))
        self.assertNotIn(TERM.encode(), raw)
        self.assertEqual(denylisted(raw, "photo.jpg"), {"photo.jpg!metadata"})

    def test_gps_software_and_creator_path_fields_are_rendered(self):
        raw = jpeg(tiff({0x0131: "Editor 1.0", 0x010E: "/home/guest/shot.jpg"}, gps=True))
        fields, problems = rc.metadata_text(raw, [1 << 20, 10])
        self.assertEqual(problems, set())
        scanner = rc.Scanner([])
        scanner.file(raw, "tree", "photo.jpg")
        self.assertIn(("home-path", "photo.jpg!metadata"), {(f["kind"], f["path"]) for f in scanner.findings})
        self.assertIn(b"Editor 1.0", fields)
        self.assertIn(b"/home/guest/shot.jpg", fields)
        self.assertIn(b"N", fields.splitlines())
        self.assertIn(b"51 1 30 1 0 1", fields)

    def test_exif_after_fill_bytes_and_between_progressive_scans_is_decoded_and_stripped(self):
        app1 = jpeg(tiff({}, {0x9C9D: TERM}))[20:-len(SCAN_DATA)]
        raw = b"\xff\xd8\xff\xff" + SCAN_DATA[:-2] + b"\xff\xff" + app1 + SCAN_DATA
        self.assertEqual(denylisted(raw, "photo.jpg"), {"photo.jpg!metadata"})
        stripped = rc.strip_metadata(raw)
        self.assertEqual(denylisted(stripped, "photo.jpg"), set())
        self.assertEqual(stripped.count(b"\x12\x34"), 400)

    def test_pdf_literal_with_nested_parentheses_is_decoded_in_full(self):
        octal = "".join("\\%03o" % ord(c) for c in TERM)
        raw = b"%PDF-1.7\n1 0 obj << /Author (Team (Internal) " + octal.encode() + b") >> endobj\n"
        self.assertEqual(denylisted(raw, "paper.pdf"), {"paper.pdf!metadata"})

    def test_a_malformed_block_does_not_hide_later_blocks_and_is_reported(self):
        raw = png([(b"zTXt", b"Comment\0\0not zlib"), (b"zTXt", b"Author\0\0" + zlib.compress(TERM.encode()))])
        scanner = rc.Scanner([TERM])
        scanner.file(raw, "tree", "logo.png")
        kinds = {(f["kind"], f["path"]) for f in scanner.findings}
        self.assertIn(("denylist", "logo.png!metadata"), kinds)
        self.assertIn(("metadata-unreadable", "logo.png"), kinds)

    def test_out_of_range_exif_offset_is_unreadable_and_keeps_earlier_fields(self):
        exif = tiff({0x0131: TERM, 0x013B: "Editor 1.0"})
        broken = exif[:8 + 2 + 12 + 8] + struct.pack("<I", 1 << 20) + exif[8 + 2 + 12 + 12:]
        scanner = rc.Scanner([TERM])
        scanner.file(jpeg(broken), "tree", "photo.jpg")
        self.assertIn(("metadata-unreadable", "photo.jpg"), {(f["kind"], f["path"]) for f in scanner.findings})
        fields, problems = rc.metadata_text(jpeg(broken), [1 << 20, 10])
        self.assertEqual(problems, {"metadata-unreadable"})
        self.assertIn(TERM.encode(), fields)

    def test_fields_before_an_over_limit_chunk_are_still_scanned(self):
        raw = png([(b"zTXt", b"Author\0\0" + zlib.compress(TERM.encode("utf-16-le"))),
                   (b"iTXt", b"Author\0\1\0\0\0" + zlib.compress(TERM.encode())),
                   (b"zTXt", b"Comment\0\0" + zlib.compress(b"0" * 64))])
        scanner = rc.Scanner([TERM])
        scanner.file(raw, "tree", "logo.png", budget=[len(TERM) * 3 + 10, 10])
        kinds = {(f["kind"], f["path"]) for f in scanner.findings}
        self.assertIn(("denylist", "logo.png!metadata"), kinds)
        self.assertIn(("archive-limit", "logo.png"), kinds)

    def test_truncated_compressed_text_is_unreadable(self):
        fields, problems = rc.metadata_text(png([(b"zTXt", b"Comment\0\0" + zlib.compress(b"text " * 50)[:-6])]), [1 << 20, 10])
        self.assertEqual(problems, {"metadata-unreadable"})

    def test_pdf_indirect_and_crlf_continued_values_are_decoded(self):
        wide = "<FEFF" + TERM.encode("utf-16-be").hex() + ">"
        raw = (b"%PDF-1.7\n2 0 obj " + wide.encode() + b" endobj\n3 0 obj << /Author 2 0 R /Title (Hidden\\\r\nPerson) >> endobj\n"
               b"4 0 obj << /Subject 9 0 R >> endobj\n")
        fields, problems = rc.metadata_text(raw, [1 << 20, 10])
        self.assertEqual(fields.count(TERM.encode()), 2)
        self.assertEqual(problems, {"metadata-unreadable"})

    def test_pdf_comment_between_key_and_value_does_not_hide_it(self):
        wide = "<FEFF" + TERM.encode("utf-16-be").hex() + ">"
        raw = b"%PDF-1.7\n1 0 obj << /Author % note\n" + wide.encode() + b" >> endobj\n"
        self.assertEqual(denylisted(raw, "paper.pdf"), {"paper.pdf!metadata"})

    def test_truncated_png_chunk_is_unreadable_and_not_stripped(self):
        raw = png([]) + struct.pack(">I", 1000) + b"tEXtAuthor\0" + TERM.encode()
        self.assertEqual(rc.metadata_text(raw, [1 << 20, 10])[1], {"metadata-unreadable"})
        self.assertIsNone(rc.strip_metadata(raw))

    def test_png_compressed_text_chunk_is_decoded(self):
        raw = png([(b"zTXt", b"Author\0\0" + zlib.compress(TERM.encode()))])
        self.assertNotIn(TERM.encode(), raw)
        self.assertEqual(denylisted(raw, "logo.png"), {"logo.png!metadata"})

    def test_png_compressed_text_over_the_limit_is_incomplete(self):
        raw = png([(b"zTXt", b"Comment\0\0" + zlib.compress(b"0" * (rc.ARCHIVE_MAX_BYTES + 1)))])
        scanner = rc.Scanner([TERM])
        scanner.file(raw, "tree", "logo.png")
        self.assertIn(("archive-limit", "logo.png"), {(f["kind"], f["path"]) for f in scanner.findings})

    def test_pdf_info_hex_utf16_author_is_decoded(self):
        author = "<FEFF" + TERM.encode("utf-16-be").hex() + ">"
        raw = b"%PDF-1.7\n1 0 obj << /Author " + author.encode() + b" /Producer (Tool\\051) >> endobj\n%%EOF\n"
        self.assertNotIn(TERM.encode(), raw)
        self.assertEqual(denylisted(raw, "paper.pdf"), {"paper.pdf!metadata"})

    def test_pdf_info_inside_a_compressed_object_stream_is_decoded(self):
        author = "<FEFF" + TERM.encode("utf-16-be").hex() + ">"
        stream = zlib.compress(b"<< /Author " + author.encode() + b" >>")
        raw = b"%PDF-1.7\n1 0 obj << /Length 1 /Filter /FlateDecode >> stream\n" + stream + b"\nendstream endobj\n"
        self.assertEqual(denylisted(raw, "paper.pdf"), {"paper.pdf!stream/1!metadata"})

    def test_office_core_properties_creator_is_scanned(self):
        raw = zipped({"docProps/core.xml": f"<cp:coreProperties><dc:creator>{TERM}</dc:creator></cp:coreProperties>".encode()})
        self.assertIn("report.docx!docProps/core.xml", denylisted(raw, "report.docx"))

    def test_strip_metadata_clears_jpeg_and_png_fields_and_keeps_image_data(self):
        photo = jpeg(tiff({0x013B: TERM}, {0x9C9D: TERM}, gps=True))
        stripped = rc.strip_metadata(photo)
        self.assertEqual(rc.metadata_text(stripped, [1 << 20, 10]), (b"", set()))
        self.assertEqual(denylisted(stripped, "photo.jpg"), set())
        self.assertTrue(stripped.startswith(b"\xff\xd8\xff\xe0") and stripped.endswith(SCAN_DATA))
        logo = png([(b"tEXt", b"Author\0" + TERM.encode()), (b"eXIf", tiff({0x013B: TERM}))])
        stripped = rc.strip_metadata(logo)
        self.assertEqual(denylisted(stripped, "logo.png"), set())
        self.assertIn(b"IDAT", stripped)
        self.assertIsNone(rc.strip_metadata(b"%PDF-1.7\n"))


if __name__ == "__main__":
    unittest.main()
