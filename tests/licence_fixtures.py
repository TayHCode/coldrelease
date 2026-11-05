"""Genuine, bundled license texts for portable offline regression tests.

Canonical texts copied from Debian /usr/share/common-licenses. Original
notices and full terms are preserved; MIT uses this repository's LICENSE.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def genuine(identifier):
    path = ROOT / 'LICENSE' if identifier == 'MIT' else (
        ROOT / 'tests/fixtures/licenses' / (identifier + '.txt'))
    return path.read_text(encoding='utf-8')
