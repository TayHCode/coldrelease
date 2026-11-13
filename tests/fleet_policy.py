import json
import re

COLD = "co" + "ld"
COLD_SUBCOMMANDS = ("model", "launch", "usage", "verify", "doctor", "stalled", "check", "gh-token", "gate", "review",
                    "new-repo", "update-skills")
FLEET_PATTERNS = [
    {"kind": "fleet-cli",
     "pattern": r"(?-i:(?<![\w.-])" + COLD + r"\s+(?:" + "|".join(map(re.escape, COLD_SUBCOMMANDS)) + r")(?![\w-]))"},
    {"kind": "fleet-reference", "pattern": r"(?<![A-Za-z0-9])" + "gr" + r"ok(?:[_-]|\s+)?bots?(?![A-Za-z0-9])"},
]


def add_fleet_pack(testbed):
    policy = json.loads(testbed.denylist.read_text())
    testbed.denylist.write_text(json.dumps({**policy, "patterns": FLEET_PATTERNS}))
    testbed.terms = testbed.terms + FLEET_PATTERNS
