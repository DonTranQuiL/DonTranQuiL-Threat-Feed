#!/usr/bin/env python3
"""AEGIS Community Intelligence Security Gate.

Designed for DonTranQuiL-Threat-Feed.

The script has three phases:
  1. Structural/policy validation of the complete feed and newly-added lines.
  2. Mark candidate changes for manual security review.
  3. Final deterministic allow/fail decision.

It never uploads samples and performs no external reputation API lookups.
Filename-only community entries are treated as low-confidence identifiers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT_DEFAULT = Path(os.environ.get("RUNNER_TEMP", ".")) / "aegis-validation.json"

FEEDS = {
    "whitelist": ROOT / "global_whitelist.txt",
    "blacklist": ROOT / "global_blacklist.txt",
    "pending_whitelist": ROOT / "pending" / "community_whitelist_candidates.txt",
    "pending_blacklist": ROOT / "pending" / "community_blacklist_candidates.txt",
}

MAX_LINE = 255
MAX_TOTAL = int(os.environ.get("AEGIS_MAX_TOTAL_FEED_LINES", "5000"))
MAX_NEW = int(os.environ.get("AEGIS_MAX_NEW_ENTRIES", "500"))

# External reputation API safety limits. These are deliberately conservative.
# They cap requests per workflow run and add pacing between requests.
VT_MAX_REQUESTS_PER_RUN = int(os.environ.get("AEGIS_VT_MAX_REQUESTS_PER_RUN", "2"))
VT_DELAY_SECONDS = float(os.environ.get("AEGIS_VT_DELAY_SECONDS", "30"))
MB_MAX_REQUESTS_PER_RUN = int(os.environ.get("AEGIS_MB_MAX_REQUESTS_PER_RUN", "5"))
MB_DELAY_SECONDS = float(os.environ.get("AEGIS_MB_DELAY_SECONDS", "5"))

SHA256_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$", re.I)
HASH_RECORD_RE = re.compile(r"^([a-z0-9][a-z0-9._ -]{2,199})\|([0-9a-f]{64})$", re.I)
SHA1_RE = re.compile(r"^(?:sha1:)?([0-9a-f]{40})$", re.I)
MD5_RE = re.compile(r"^(?:md5:)?([0-9a-f]{32})$", re.I)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._ -]{2,199}$", re.I)

# Names that should never be community-controlled. These are deliberately
# conservative: the feed must not be able to redefine core OS components.
PROTECTED_NAMES = {
    "system", "system32", "windows", "winlogon.exe", "lsass.exe",
    "csrss.exe", "smss.exe", "services.exe", "svchost.exe", "explorer.exe",
    "dwm.exe", "wininit.exe", "taskhostw.exe", "runtimebroker.exe",
    "securityhealthservice.exe", "msmpeng.exe", "mrt.exe", "powershell.exe",
    "pwsh.exe", "cmd.exe", "conhost.exe", "dllhost.exe", "rundll32.exe",
    "regsvr32.exe", "msiexec.exe", "wmic.exe", "wscript.exe", "cscript.exe",
    "bash", "sh", "sudo", "init", "kernel", "systemd",
}

SUSPICIOUS_WL_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "wmic.exe",
    "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe",
}

# Obvious control characters / path and rule syntax are forbidden.
FORBIDDEN_CHARS = set("\x00\r\n\t")
FORBIDDEN_SUBSTRINGS = ("../", "..\\", "\\", "/", "*", "?", ";", "&&", "||")


def result():
    return {
        "schema": 1,
        "decision": "PENDING",
        "changed_additions": 0,
        "entries": [],
        "errors": [],
        "warnings": [],
        "reputation": [],
    }


def save_report(data, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_report(path: Path):
    if not path.exists():
        raise SystemExit(f"Report not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def feed_lines(path: Path):
    if not path.exists():
        return []
    lines = []
    for n, raw in enumerate(path.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
        value = raw.strip().lower()
        if not value or value.startswith("#"):
            continue
        lines.append((n, value))
    return lines


def classify(value: str):
    record = HASH_RECORD_RE.fullmatch(value)
    if record:
        return "hash_record", f"{record.group(1).lower()}|{record.group(2).lower()}"
    if SHA256_RE.fullmatch(value):
        return "sha256", SHA256_RE.fullmatch(value).group(1).lower()
    if SHA1_RE.fullmatch(value):
        return "sha1", SHA1_RE.fullmatch(value).group(1).lower()
    if MD5_RE.fullmatch(value):
        return "md5", MD5_RE.fullmatch(value).group(1).lower()
    return "name", value


def validate_entry(value: str, feed_type: str, where: str, data: dict):
    if any(c in value for c in FORBIDDEN_CHARS):
        data["errors"].append(f"{where}: control character in entry")
        return False
    if len(value) > MAX_LINE:
        data["errors"].append(f"{where}: entry exceeds {MAX_LINE} characters")
        return False
    if any(token in value for token in FORBIDDEN_SUBSTRINGS):
        data["errors"].append(f"{where}: path/wildcard/rule syntax is forbidden: {value!r}")
        return False

    kind, normalized = classify(value)
    if kind == "hash_record":
        if feed_type != "whitelist":
            data["errors"].append(f"{where}: filename|SHA256 records are allowed only in the whitelist feed")
            return False
        name, digest = normalized.split("|", 1)
        base = name.rsplit(".", 1)[0] if "." in name else name
        if name in PROTECTED_NAMES or base in PROTECTED_NAMES:
            data["errors"].append(f"{where}: protected operating-system identifier cannot receive a community hash record: {name!r}")
            return False
        data["warnings"].append(f"{where}: cryptographic whitelist identity: {name}|SHA256:{digest[:12]}...")
        return True

    if kind == "name":
        if not NAME_RE.fullmatch(normalized):
            data["errors"].append(f"{where}: invalid community identifier: {value!r}")
            return False
        base = normalized.rsplit(".", 1)[0] if "." in normalized else normalized
        if normalized in PROTECTED_NAMES or base in PROTECTED_NAMES:
            data["errors"].append(f"{where}: protected operating-system identifier: {value!r}")
            return False
        if feed_type == "whitelist" and normalized in SUSPICIOUS_WL_NAMES:
            data["errors"].append(
                f"{where}: high-risk executable cannot be promoted to whitelist by name alone: {value!r}"
            )
            return False
        if feed_type == "whitelist":
            data["warnings"].append(
                f"{where}: filename-only whitelist entry has no cryptographic identity: {value!r}"
            )
    else:
        if kind == "sha256":
            pass
        elif kind in {"sha1", "md5"}:
            data["warnings"].append(f"{where}: {kind.upper()} is accepted for compatibility; SHA-256 is preferred")
    return True


def collect_all(data):
    total = 0
    seen_global = {}
    for key, path in FEEDS.items():
        feed_type = "whitelist" if "whitelist" in key else "blacklist"
        rows = feed_lines(path)
        if len(rows) > MAX_TOTAL:
            data["errors"].append(f"{path.relative_to(ROOT)}: exceeds {MAX_TOTAL} active lines")
        for line_no, value in rows:
            total += 1
            validate_entry(value, feed_type, f"{path.relative_to(ROOT)}:{line_no}", data)
            kind, norm = classify(value)
            marker = (feed_type, norm)
            if marker in seen_global:
                data["errors"].append(
                    f"duplicate {feed_type} entry: {value!r} also appears at {seen_global[marker]}"
                )
            else:
                seen_global[marker] = f"{path.relative_to(ROOT)}:{line_no}"

    # Same identifier in production whitelist and blacklist is an explicit conflict.
    wl = {v for _, v in feed_lines(FEEDS["whitelist"])}
    bl = {v for _, v in feed_lines(FEEDS["blacklist"])}
    for conflict in sorted(wl & bl):
        data["errors"].append(f"identifier exists in BOTH production feeds: {conflict!r}")

    return total


def git_output(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.STDOUT)


def changed_additions(base_sha: str | None, head_sha: str | None):
    if not base_sha or not head_sha:
        return []
    try:
        patch = git_output("diff", "--unified=0", base_sha, head_sha, "--", "pending", "global_whitelist.txt", "global_blacklist.txt")
    except Exception as exc:
        raise SystemExit(f"Unable to inspect PR diff: {exc}")

    additions = []
    current_file = None
    for raw in patch.splitlines():
        if raw.startswith("+++"):
            current_file = raw[6:] if raw.startswith("+++ b/") else None
            continue
        if not raw.startswith("+") or raw.startswith("+++") or not current_file:
            continue
        value = raw[1:].strip().lower()
        if not value or value.startswith("#"):
            continue
        if current_file.endswith("global_whitelist.txt"):
            feed_type = "whitelist"
        elif current_file.endswith("global_blacklist.txt"):
            feed_type = "blacklist"
        elif "community_whitelist_candidates.txt" in current_file:
            feed_type = "whitelist"
        elif "community_blacklist_candidates.txt" in current_file:
            feed_type = "blacklist"
        else:
            continue
        additions.append((current_file, feed_type, value))
    return additions



def prepare_manual_review(data: dict):
    """Mark the report for human review without contacting external APIs."""
    data["manual_review"] = {
        "required": True,
        "external_reputation_apis": False,
        "virus_total_requests": 0,
        "malwarebazaar_requests": 0,
        "action": "Human reviewer must independently verify candidates before merge.",
    }

    data["warnings"].append(
        "Manual security review is required before community intelligence is promoted."
    )
    data["warnings"].append(
        "No VirusTotal or MalwareBazaar API requests are performed by AEGIS."
    )



def phase_validate(args, report: Path):
    data = result()
    total = collect_all(data)
    data["total_feed_entries"] = total

    additions = changed_additions(args.base_sha, args.head_sha)
    if len(additions) > MAX_NEW:
        data["errors"].append(f"PR adds {len(additions)} entries; maximum allowed is {MAX_NEW}")
    data["changed_additions"] = len(additions)

    for path, feed_type, value in additions:
        kind, normalized = classify(value)
        item = {"path": path, "feed_type": feed_type, "value": value, "kind": kind, "normalized": normalized}
        data["entries"].append(item)
        validate_entry(value, feed_type, f"PR addition {path}", data)

    prepare_manual_review(data)

    # Explicit anti-poisoning rule: community whitelist must not be promoted by
    # merely adding a name that looks like a Windows/system executable.
    if any(x["feed_type"] == "whitelist" for x in data["entries"]):
        data["warnings"].append("Whitelist changes require human review; this gate never auto-merges or auto-trusts them.")

    data["decision"] = "PASS" if not data["errors"] else "FAIL"
    save_report(data, report)
    print(json.dumps({"decision": data["decision"], "changed_additions": len(additions), "errors": len(data["errors"]), "warnings": len(data["warnings"])}, indent=2))
    return data


def finalize(report: Path):
    data = load_report(report)
    data["decision"] = "PASS" if not data.get("errors") else "FAIL"
    save_report(data, report)
    print(json.dumps(data, indent=2))
    if data["decision"] != "PASS":
        print("AEGIS SECURITY GATE: FAIL", file=sys.stderr)
        sys.exit(1)
    print("AEGIS SECURITY GATE: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--report", default=str(REPORT_DEFAULT))
    parser.add_argument("--finalize", action="store_true")
    args = parser.parse_args()
    report = Path(args.report)

    if args.finalize:
        finalize(report)
        return
    data = phase_validate(args, report)
    if data["decision"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
