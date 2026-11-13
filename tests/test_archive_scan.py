import gzip
import io
import tarfile
import unittest
import zipfile
import zlib

import release_check as rc

TERM = "HiddenPerson"


def zipped(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def tarred(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def docx(body: str) -> bytes:
    return zipped({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types/>',
        "word/document.xml": f'<w:document><w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body></w:document>'.encode(),
    })


def bomb(size: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("zeros.txt", "w") as handle:
            chunk = b"0" * (1 << 20)
            for _ in range(size // len(chunk)):
                handle.write(chunk)
    return buffer.getvalue()


class ArchiveScanTests(unittest.TestCase):
    def scan(self, raw: bytes, path: str):
        scanner = rc.Scanner([TERM])
        scanner.file(raw, "tree", path)
        return scanner.findings

    def outcome(self, findings):
        return rc.outcome({"findings": findings, "verification": {"status": "pass"},
                           "license": {"status": "pass", "dependencies": "pass"},
                           "stats": {"tree_files": 1, "history_commits": 1}})

    def kinds(self, findings):
        return {(f["kind"], f["path"]) for f in findings}

    def test_docx_with_denylist_term_fails_at_member_path(self):
        findings = self.scan(docx(TERM), "report.docx")
        self.assertIn(("denylist", "report.docx!word/document.xml"), self.kinds(findings))
        self.assertEqual(self.outcome(findings)["outcome"], "FAIL")

    def test_zip_with_denylist_term_fails_at_member_path(self):
        findings = self.scan(zipped({"inner/notes.txt": f"owner {TERM}\n".encode()}), "bundle.zip")
        self.assertIn(("denylist", "bundle.zip!inner/notes.txt"), self.kinds(findings))
        self.assertEqual(self.outcome(findings)["outcome"], "FAIL")

    def test_clean_archives_still_need_review(self):
        for raw, path in ((zipped({"a.txt": b"public\n"}), "clean.zip"), (docx("Public text"), "clean.docx"),
                          (zipped({"a.txt": b"public\n"}), "clean.jar"), (tarred({"a.txt": b"public\n"}), "clean.tar"),
                          (gzip.compress(b"public\n"), "clean.txt.gz")):
            with self.subTest(path=path):
                findings = self.scan(raw, path)
                self.assertEqual(self.kinds(findings), {("binary-review", path)})
                self.assertEqual(self.outcome(findings)["outcome"], "FAIL")

    def test_nested_tar_gz_and_zip_members_are_scanned(self):
        inner = zipped({"deep/secret.txt": f"{TERM}\n".encode()})
        raw = gzip.compress(tarred({"pkg/inner.zip": inner}))
        findings = self.scan(raw, "release.tgz")
        self.assertIn(("denylist", "release.tgz!release.tar!pkg/inner.zip!deep/secret.txt"), self.kinds(findings))

    def test_gz_member_takes_name_without_suffix(self):
        findings = self.scan(gzip.compress(f"{TERM}\n".encode()), "logs/app.log.gz")
        self.assertIn(("denylist", "logs/app.log.gz!app.log"), self.kinds(findings))

    def test_archive_member_secrets_and_credential_names_are_detected(self):
        findings = self.scan(zipped({".env": b"x\n", "conf/.env": b"x\n", "key.txt": b"-----BEGIN RSA PRIVATE" + b" KEY-----\n"}), "conf.zip")
        kinds = self.kinds(findings)
        self.assertIn(("credential-file", "conf.zip!.env"), kinds)
        self.assertIn(("credential-file", "conf.zip!conf/.env"), kinds)
        self.assertIn(("private-key", "conf.zip!key.txt"), kinds)

    def test_pdf_flate_stream_text_is_scanned(self):
        stream = zlib.compress(f"BT ({TERM}) Tj ET".encode())
        raw = b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(stream)).encode() + b" /Filter /FlateDecode >>\nstream\n" + stream + b"\nendstream\nendobj\n%%EOF\n"
        findings = self.scan(raw, "paper.pdf")
        self.assertIn(("denylist", "paper.pdf!stream/1"), self.kinds(findings))
        self.assertIn(("manual-review", "paper.pdf"), self.kinds(findings))

    def test_docx_term_split_across_runs_fails(self):
        raw = zipped({"word/document.xml": b"<w:p><w:r><w:t>Hidden</w:t></w:r><w:r><w:t>Person</w:t></w:r></w:p>"})
        findings = self.scan(raw, "split.docx")
        self.assertIn(("denylist", "split.docx!word/document.xml"), self.kinds(findings))
        self.assertEqual(self.outcome(findings)["outcome"], "FAIL")

    def test_xml_character_references_are_decoded(self):
        raw = zipped({"word/document.xml": b"<w:t>Hidden&#80;erson</w:t>"})
        findings = self.scan(raw, "ref.docx")
        self.assertIn(("denylist", "ref.docx!word/document.xml"), self.kinds(findings))

    def test_utf16_xml_split_runs_are_detected(self):
        xml = "<w:r><w:t>Hidden</w:t></w:r><w:r><w:t>Person</w:t></w:r>".encode("utf-16")
        findings = self.scan(zipped({"word/document.xml": xml}), "wide.docx")
        self.assertIn(("denylist", "wide.docx!word/document.xml"), self.kinds(findings))

    def test_tar_link_and_directory_names_are_checked(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            link = tarfile.TarInfo(".env")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/" + TERM
            archive.addfile(link)
            folder = tarfile.TarInfo(TERM + "-notes")
            folder.type = tarfile.DIRTYPE
            archive.addfile(folder)
        findings = self.scan(buffer.getvalue(), "links.tar")
        kinds = {f["kind"] for f in findings}
        self.assertIn(("credential-file", "links.tar!.env"), self.kinds(findings))
        self.assertIn("denylist", kinds)
        self.assertEqual(self.outcome(findings)["outcome"], "FAIL")

    def test_pdf_header_does_not_hide_binary_review(self):
        findings = self.scan(b"%PDF-\0not really a pdf", "document.bin")
        self.assertIn(("binary-review", "document.bin"), self.kinds(findings))
        self.assertEqual(self.outcome(findings)["outcome"], "FAIL")

    def test_pdf_content_requires_manual_review_under_any_name(self):
        text = b"BT (" + b"x" * 290 + b") Tj ET"
        compressor = zlib.compressobj(0)
        stream = compressor.compress(text) + compressor.flush()
        pdf = (b"%PDF-1.4\n1 0 obj << /Length " + str(len(stream)).encode()
               + b" /Filter /FlateDecode >> stream\n" + stream + b"\nendstream endobj\n%%EOF\n")
        self.assertNotIn(b"\0", pdf)
        for name in ("paper.dat", "paper"):
            findings = self.scan(pdf, name)
            self.assertIn(("manual-review", name), self.kinds(findings))
            self.assertEqual(self.outcome(findings)["outcome"], "INCOMPLETE")

    def test_directory_entries_count_toward_member_limit(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for i in range(rc.ARCHIVE_MAX_MEMBERS + 1):
                archive.writestr(f"d{i}/", b"")
        findings = self.scan(buffer.getvalue(), "dirs.zip")
        self.assertIn(("archive-limit", "dirs.zip"), self.kinds(findings))
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for i in range(rc.ARCHIVE_MAX_MEMBERS + 1):
                info = tarfile.TarInfo(f"l{i}")
                info.type, info.linkname = tarfile.SYMTYPE, "x"
                archive.addfile(info)
        findings = self.scan(buffer.getvalue(), "links.tar")
        self.assertIn(("archive-limit", "links.tar"), self.kinds(findings))

    def test_zip_bomb_is_incomplete_archive_limit(self):
        findings = self.scan(bomb(rc.ARCHIVE_MAX_BYTES + (1 << 20)), "bomb.zip")
        self.assertIn(("archive-limit", "bomb.zip"), self.kinds(findings))
        self.assertNotIn("binary-review", {f["kind"] for f in findings})
        result = self.outcome(findings)
        self.assertEqual(result["outcome"], "INCOMPLETE")
        self.assertIn("archive-limit", result["reasons"])

    def test_gzip_bomb_is_incomplete_archive_limit(self):
        raw = gzip.compress(b"0" * (rc.ARCHIVE_MAX_BYTES + 1))
        findings = self.scan(raw, "bomb.gz")
        self.assertIn(("archive-limit", "bomb.gz"), self.kinds(findings))
        self.assertEqual(self.outcome(findings)["outcome"], "INCOMPLETE")

    def test_nesting_beyond_depth_limit_is_incomplete(self):
        raw = b"public\n"
        for _ in range(rc.ARCHIVE_MAX_DEPTH + 1):
            raw = zipped({"layer.zip": raw})
        findings = self.scan(raw, "nested.zip")
        self.assertIn("archive-limit", {f["kind"] for f in findings})
        self.assertEqual(self.outcome(findings)["outcome"], "INCOMPLETE")

    def test_too_many_members_is_incomplete(self):
        raw = zipped({f"m{i}.txt": b"" for i in range(rc.ARCHIVE_MAX_MEMBERS + 1)})
        findings = self.scan(raw, "many.zip")
        self.assertIn(("archive-limit", "many.zip"), self.kinds(findings))

    def test_unopenable_formats_keep_binary_review(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("x.txt", b"public")
        encrypted = bytearray(buffer.getvalue())
        encrypted[6] |= 1
        central = encrypted.find(b"PK\x01\x02")
        encrypted[central + 8] |= 1
        for raw, path in ((b"binary\0bytes", "archive.zip"), (b"7z\xbc\xaf\x27\x1c\0\0", "a.7z"),
                          (b"PK\x03\x04truncated\0", "broken.zip"), (bytes(encrypted), "locked.zip"),
                          (b"PK\x03\x04truncated", "broken.docx"), (b"\x1f\x8bnot gzip", "notes.txt")):
            with self.subTest(path=path):
                findings = self.scan(raw, path)
                self.assertIn(("binary-review", path), self.kinds(findings))
                self.assertEqual(self.outcome(findings)["outcome"], "FAIL")


if __name__ == "__main__":
    unittest.main()
