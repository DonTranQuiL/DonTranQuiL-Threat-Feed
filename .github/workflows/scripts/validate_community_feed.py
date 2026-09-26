#!/usr/bin/env python3
"""
AEGIS Community Intelligence Security Gate.

Designed for:
    DonTranQuiL-Threat-Feed

Security model:

    PR
     |
     +--> structural validation
     |
     +--> duplicate detection
     |
     +--> protected-name detection
     |
     +--> whitelist poisoning checks
     |
     +--> hash validation
     |
     +--> VirusTotal lookup
     |
     +--> MalwareBazaar lookup
     |
     +--> deterministic PASS / FAIL

Important:

- This script NEVER uploads malware samples.
- Reputation lookups are hash-only.
- Filename-only whitelist entries are considered low confidence.
- Community intelligence never automatically becomes local trust.
- Community intelligence never automatically kills a local process.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

REPORT_DEFAULT = (
    Path(os.environ.get("RUNNER_TEMP", "."))
    / "aegis-validation.json"
)


FEEDS = {
    "whitelist": ROOT / "global_whitelist.txt",
    "blacklist": ROOT / "global_blacklist.txt",

    "pending_whitelist":
        ROOT / "pending" / "community_whitelist_candidates.txt",

    "pending_blacklist":
        ROOT / "pending" / "community_blacklist_candidates.txt",
}


# ============================================================
# LIMITS
# ============================================================

MAX_LINE = 255

MAX_TOTAL = int(
    os.environ.get(
        "AEGIS_MAX_TOTAL_FEED_LINES",
        "5000",
    )
)

MAX_NEW = int(
    os.environ.get(
        "AEGIS_MAX_NEW_ENTRIES",
        "500",
    )
)


# ============================================================
# HASH FORMATS
# ============================================================

SHA256_RE = re.compile(
    r"^(?:sha256:)?([0-9a-f]{64})$",
    re.I,
)

SHA1_RE = re.compile(
    r"^(?:sha1:)?([0-9a-f]{40})$",
    re.I,
)

MD5_RE = re.compile(
    r"^(?:md5:)?([0-9a-f]{32})$",
    re.I,
)


# ============================================================
# HUMAN-READABLE IDENTIFIER
# ============================================================

NAME_RE = re.compile(
    r"^[a-z0-9][a-z0-9._ -]{2,199}$",
    re.I,
)


# ============================================================
# PROTECTED SYSTEM NAMES
#
# These must never become remotely controlled trust rules.
# ============================================================

PROTECTED_NAMES = {
    "system",
    "system32",
    "windows",

    "winlogon.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "wininit.exe",
    "taskhostw.exe",
    "runtimebroker.exe",

    "securityhealthservice.exe",
    "msmpeng.exe",
    "mrt.exe",

    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "conhost.exe",

    "dllhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "wmic.exe",

    "wscript.exe",
    "cscript.exe",

    "bash",
    "sh",
    "sudo",
    "init",
    "kernel",
    "systemd",
}


# ============================================================
# HIGH-RISK WINDOWS EXECUTABLES
#
# A whitelist entry for one of these names is not acceptable.
# ============================================================

SUSPICIOUS_WL_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",

    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "wmic.exe",

    "certutil.exe",
    "bitsadmin.exe",
    "curl.exe",
    "wget.exe",
}


# ============================================================
# FORBIDDEN CONTENT
# ============================================================

FORBIDDEN_CHARS = {
    "\x00",
    "\r",
    "\n",
    "\t",
}


FORBIDDEN_SUBSTRINGS = (
    "../",
    "..\\",
    "\\",
    "/",
    "*",
    "?",
    "|",
    ";",
    "&&",
    "||",
)


# ============================================================
# RESULT STRUCTURE
# ============================================================

def result():
    return {
        "schema": 1,
        "decision": "PENDING",
        "changed_additions": 0,
        "total_feed_entries": 0,
        "entries": [],
        "errors": [],
        "warnings": [],
        "reputation": [],
    }


# ============================================================
# REPORT HANDLING
# ============================================================

def save_report(data: dict, path: Path) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def load_report(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(
            f"Report not found: {path}"
        )

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


# ============================================================
# FEED READING
# ============================================================

def feed_lines(path: Path):
    if not path.exists():
        return []

    lines = []

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="strict",
        )
    except Exception as exc:
        raise SystemExit(
            f"Unable to read feed {path}: {exc}"
        )

    for number, raw in enumerate(
        content.splitlines(),
        1,
    ):
        value = raw.strip().lower()

        if not value:
            continue

        if value.startswith("#"):
            continue

        lines.append(
            (
                number,
                value,
            )
        )

    return lines


# ============================================================
# CLASSIFICATION
# ============================================================

def classify(value: str):
    match = SHA256_RE.fullmatch(value)

    if match:
        return (
            "sha256",
            match.group(1).lower(),
        )

    match = SHA1_RE.fullmatch(value)

    if match:
        return (
            "sha1",
            match.group(1).lower(),
        )

    match = MD5_RE.fullmatch(value)

    if match:
        return (
            "md5",
            match.group(1).lower(),
        )

    return (
        "name",
        value,
    )


# ============================================================
# ENTRY VALIDATION
# ============================================================

def validate_entry(
    value: str,
    feed_type: str,
    where: str,
    data: dict,
):
    # --------------------------------------------------------
    # Control characters
    # --------------------------------------------------------

    if any(
        char in value
        for char in FORBIDDEN_CHARS
    ):
        data["errors"].append(
            f"{where}: control character in entry"
        )

        return False

    # --------------------------------------------------------
    # Length
    # --------------------------------------------------------

    if len(value) > MAX_LINE:
        data["errors"].append(
            f"{where}: entry exceeds "
            f"{MAX_LINE} characters"
        )

        return False

    # --------------------------------------------------------
    # Path / wildcard / rule injection
    # --------------------------------------------------------

    if any(
        token in value
        for token in FORBIDDEN_SUBSTRINGS
    ):
        data["errors"].append(
            f"{where}: path/wildcard/rule syntax "
            f"is forbidden: {value!r}"
        )

        return False

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    kind, normalized = classify(value)

    # --------------------------------------------------------
    # Filename / name
    # --------------------------------------------------------

    if kind == "name":

        if not NAME_RE.fullmatch(
            normalized
        ):
            data["errors"].append(
                f"{where}: invalid community "
                f"identifier: {value!r}"
            )

            return False

        # Get executable base name.
        base = (
            normalized.rsplit(".", 1)[0]
            if "." in normalized
            else normalized
        )

        # ----------------------------------------------------
        # Protected operating-system names
        # ----------------------------------------------------

        if (
            normalized in PROTECTED_NAMES
            or base in PROTECTED_NAMES
        ):
            data["errors"].append(
                f"{where}: protected "
                f"operating-system identifier: "
                f"{value!r}"
            )

            return False

        # ----------------------------------------------------
        # Suspicious whitelist names
        # ----------------------------------------------------

        if (
            feed_type == "whitelist"
            and normalized in SUSPICIOUS_WL_NAMES
        ):
            data["errors"].append(
                f"{where}: high-risk executable "
                f"cannot be promoted to whitelist "
                f"by name alone: {value!r}"
            )

            return False

        # ----------------------------------------------------
        # Filename-only whitelist warning
        # ----------------------------------------------------

        if feed_type == "whitelist":
            data["warnings"].append(
                f"{where}: filename-only whitelist "
                f"entry has no cryptographic identity: "
                f"{value!r}"
            )

    # --------------------------------------------------------
    # Hash
    # --------------------------------------------------------

    else:

        if kind == "sha256":
            pass

        elif kind in {
            "sha1",
            "md5",
        }:
            data["warnings"].append(
                f"{where}: {kind.upper()} is accepted "
                f"for compatibility; SHA-256 is preferred"
            )

    return True


# ============================================================
# COMPLETE FEED VALIDATION
# ============================================================

def collect_all(data: dict):

    total = 0

    seen_global = {}

    for key, path in FEEDS.items():

        feed_type = (
            "whitelist"
            if "whitelist" in key
            else "blacklist"
        )

        rows = feed_lines(path)

        if len(rows) > MAX_TOTAL:

            data["errors"].append(
                f"{path.relative_to(ROOT)}: "
                f"exceeds {MAX_TOTAL} active lines"
            )

        for line_number, value in rows:

            total += 1

            validate_entry(
                value,
                feed_type,
                (
                    f"{path.relative_to(ROOT)}:"
                    f"{line_number}"
                ),
                data,
            )

            kind, normalized = classify(
                value
            )

            marker = (
                feed_type,
                normalized,
            )

            if marker in seen_global:

                data["errors"].append(
                    f"duplicate {feed_type} entry: "
                    f"{value!r} also appears at "
                    f"{seen_global[marker]}"
                )

            else:

                seen_global[
                    marker
                ] = (
                    f"{path.relative_to(ROOT)}:"
                    f"{line_number}"
                )

    # --------------------------------------------------------
    # Whitelist / blacklist conflict
    # --------------------------------------------------------

    whitelist_values = {
        value
        for _, value in feed_lines(
            FEEDS["whitelist"]
        )
    }

    blacklist_values = {
        value
        for _, value in feed_lines(
            FEEDS["blacklist"]
        )
    }

    conflicts = (
        whitelist_values
        & blacklist_values
    )

    for conflict in sorted(conflicts):

        data["errors"].append(
            "identifier exists in BOTH "
            f"production feeds: {conflict!r}"
        )

    return total


# ============================================================
# GIT
# ============================================================

def git_output(*args):

    return subprocess.check_output(
        [
            "git",
            *args,
        ],
        cwd=ROOT,
        text=True,
        stderr=subprocess.STDOUT,
    )


# ============================================================
# FIND NEW PR ENTRIES
# ============================================================

def changed_additions(
    base_sha: str | None,
    head_sha: str | None,
):

    if not base_sha or not head_sha:
        return []

    try:

        patch = git_output(
            "diff",
            "--unified=0",
            base_sha,
            head_sha,
            "--",
            "pending",
            "global_whitelist.txt",
            "global_blacklist.txt",
        )

    except Exception as exc:

        raise SystemExit(
            f"Unable to inspect PR diff: {exc}"
        )

    additions = []

    current_file = None

    for raw in patch.splitlines():

        # ----------------------------------------------------
        # Current file
        # ----------------------------------------------------

        if raw.startswith("+++"):

            if raw.startswith("+++ b/"):
                current_file = raw[6:]
            else:
                current_file = None

            continue

        # ----------------------------------------------------
        # Only additions
        # ----------------------------------------------------

        if (
            not raw.startswith("+")
            or raw.startswith("+++")
            or not current_file
        ):
            continue

        value = raw[1:].strip().lower()

        if not value:
            continue

        if value.startswith("#"):
            continue

        # ----------------------------------------------------
        # Feed type
        # ----------------------------------------------------

        if current_file.endswith(
            "global_whitelist.txt"
        ):
            feed_type = "whitelist"

        elif current_file.endswith(
            "global_blacklist.txt"
        ):
            feed_type = "blacklist"

        elif (
            "community_whitelist_candidates.txt"
            in current_file
        ):
            feed_type = "whitelist"

        elif (
            "community_blacklist_candidates.txt"
            in current_file
        ):
            feed_type = "blacklist"

        else:
            continue

        additions.append(
            (
                current_file,
                feed_type,
                value,
            )
        )

    return additions


# ============================================================
# VIRUSTOTAL
# ============================================================

def vt_lookup(
    sha256: str,
    api_key: str,
):

    url = (
        "https://www.virustotal.com/api/v3/files/"
        + urllib.parse.quote(
            sha256
        )
    )

    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "accept": "application/json",
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=20,
        ) as response:

            return (
                response.status,
                json.loads(
                    response.read().decode(
                        "utf-8",
                        errors="strict",
                    )
                ),
            )

    except urllib.error.HTTPError as exc:

        body = (
            exc.read()
            .decode(
                "utf-8",
                errors="replace",
            )[:500]
        )

        return (
            exc.code,
            {
                "error": body,
            },
        )


# ============================================================
# MALWAREBAZAAR
# ============================================================

def mb_lookup(
    indicator: str,
    auth_key: str,
):

    payload = urllib.parse.urlencode(
        {
            "query": "get_info",
            "hash": indicator,
        }
    ).encode()

    request = urllib.request.Request(
        "https://mb-api.abuse.ch/api/v1/",
        headers={
            "Auth-Key": auth_key,
            "Content-Type":
                "application/x-www-form-urlencoded",
        },
        data=payload,
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=20,
        ) as response:

            return (
                response.status,
                json.loads(
                    response.read().decode(
                        "utf-8",
                        errors="strict",
                    )
                ),
            )

    except urllib.error.HTTPError as exc:

        body = (
            exc.read()
            .decode(
                "utf-8",
                errors="replace",
            )[:500]
        )

        return (
            exc.code,
            {
                "error": body,
            },
        )


# ============================================================
# REPUTATION ENGINE
# ============================================================

def run_reputation(
    provider: str,
    data: dict,
):

    # --------------------------------------------------------
    # API key
    # --------------------------------------------------------

    if provider == "virustotal":

        key = os.environ.get(
            "VIRUSTOTAL_API_KEY",
            "",
        ).strip()

        if not key:

            data["warnings"].append(
                "VirusTotal check skipped: "
                "VIRUSTOTAL_API_KEY is not configured"
            )

            return

    elif provider == "malwarebazaar":

        key = os.environ.get(
            "MALWAREBAZAAR_AUTH_KEY",
            "",
        ).strip()

        if not key:

            data["warnings"].append(
                "MalwareBazaar check skipped: "
                "MALWAREBAZAAR_AUTH_KEY is not configured"
            )

            return

    else:

        raise SystemExit(
            f"Unknown reputation provider: "
            f"{provider}"
        )

    # --------------------------------------------------------
    # Only hash indicators
    # --------------------------------------------------------

    hashes = []

    for item in data.get(
        "entries",
        [],
    ):

        if item["kind"] in {
            "sha256",
            "sha1",
            "md5",
        }:

            hashes.append(item)

    seen = set()

    for item in hashes:

        key_id = item[
            "normalized"
        ]

        if key_id in seen:
            continue

        seen.add(key_id)

        feed_type = item[
            "feed_type"
        ]

        # ----------------------------------------------------
        # VirusTotal uses SHA-256 here.
        # ----------------------------------------------------

        if (
            provider == "virustotal"
            and item["kind"] != "sha256"
        ):

            data["warnings"].append(
                "VirusTotal skipped non-SHA256 "
                f"indicator: {key_id}"
            )

            continue

        try:

            # =================================================
            # VIRUSTOTAL
            # =================================================

            if provider == "virustotal":

                status, body = vt_lookup(
                    key_id,
                    key,
                )

                # ------------------------------------------------
                # Unknown hash
                # ------------------------------------------------

                if status == 404:

                    record = {
                        "provider":
                            provider,
                        "indicator":
                            key_id,
                        "status":
                            "not_found",
                    }

                # ------------------------------------------------
                # API error
                # ------------------------------------------------

                elif status != 200:

                    record = {
                        "provider":
                            provider,
                        "indicator":
                            key_id,
                        "status":
                            "error",
                        "http":
                            status,
                    }

                    data["warnings"].append(
                        "VirusTotal lookup failed "
                        f"for {key_id}: HTTP {status}"
                    )

                # ------------------------------------------------
                # Result
                # ------------------------------------------------

                else:

                    attributes = (
                        body
                        .get("data", {})
                        .get("attributes", {})
                    )

                    stats = (
                        attributes
                        .get(
                            "last_analysis_stats",
                            {},
                        )
                        or {}
                    )

                    malicious = int(
                        stats.get(
                            "malicious",
                            0,
                        )
                        or 0
                    )

                    suspicious = int(
                        stats.get(
                            "suspicious",
                            0,
                        )
                        or 0
                    )

                    record = {
                        "provider":
                            provider,
                        "indicator":
                            key_id,
                        "status":
                            "found",
                        "malicious":
                            malicious,
                        "suspicious":
                            suspicious,
                        "reputation":
                            attributes.get(
                                "reputation"
                            ),
                    }

                    min_detections = int(
                        os.environ.get(
                            "AEGIS_VT_MIN_DETECTIONS",
                            "2",
                        )
                    )

                    # ------------------------------------------------
                    # NEVER allow known malicious hash into whitelist
                    # ------------------------------------------------

                    if (
                        feed_type == "whitelist"
                        and malicious >= 1
                    ):

                        data["errors"].append(
                            "VirusTotal: whitelist "
                            "hash has "
                            f"{malicious} malicious "
                            "detections: {key_id}"
                        )

                    # ------------------------------------------------
                    # Blacklist corroboration
                    # ------------------------------------------------

                    elif (
                        feed_type == "blacklist"
                        and malicious >= min_detections
                    ):

                        data["warnings"].append(
                            "VirusTotal corroborates "
                            "blacklist hash "
                            f"({malicious} malicious "
                            f"detections): {key_id}"
                        )

                    # ------------------------------------------------
                    # Suspicious whitelist
                    # ------------------------------------------------

                    elif (
                        feed_type == "whitelist"
                        and suspicious >= 1
                    ):

                        data["warnings"].append(
                            "VirusTotal: whitelist "
                            "hash has suspicious "
                            f"detections: {key_id}"
                        )

            # =================================================
            # MALWAREBAZAAR
            # =================================================

            else:

                status, body = mb_lookup(
                    key_id,
                    key,
                )

                if status != 200:

                    record = {
                        "provider":
                            provider,
                        "indicator":
                            key_id,
                        "status":
                            "error",
                        "http":
                            status,
                    }

                    data["warnings"].append(
                        "MalwareBazaar lookup failed "
                        f"for {key_id}: HTTP {status}"
                    )

                elif (
                    body.get(
                        "query_status"
                    )
                    == "hash_not_found"
                ):

                    record = {
                        "provider":
                            provider,
                        "indicator":
                            key_id,
                        "status":
                            "not_found",
                    }

                else:

                    record = {
                        "provider":
                            provider,
                        "indicator":
                            key_id,
                        "status":
                            "found",
                    }

                    # ------------------------------------------------
                    # Known malware can NEVER enter whitelist
                    # ------------------------------------------------

                    if feed_type == "whitelist":

                        data["errors"].append(
                            "MalwareBazaar: "
                            "whitelist hash is "
                            "known malware: "
                            f"{key_id}"
                        )

                    else:

                        data["warnings"].append(
                            "MalwareBazaar corroborates "
                            "blacklist hash: "
                            f"{key_id}"
                        )

            data["reputation"].append(
                record
            )

        except Exception as exc:

            # ------------------------------------------------
            # Reputation service outage is NOT treated as
            # a clean result.
            # ------------------------------------------------

            data["warnings"].append(
                f"{provider} lookup error "
                f"for {key_id}: "
                f"{str(exc)[:180]}"
            )

            data["reputation"].append(
                {
                    "provider":
                        provider,
                    "indicator":
                        key_id,
                    "status":
                        "error",
                }
            )


# ============================================================
# VALIDATION PHASE
# ============================================================

def phase_validate(
    args,
    report: Path,
):

    data = result()

    # --------------------------------------------------------
    # Validate current repository feed
    # --------------------------------------------------------

    total = collect_all(
        data
    )

    data[
        "total_feed_entries"
    ] = total

    # --------------------------------------------------------
    # Inspect PR additions
    # --------------------------------------------------------

    additions = changed_additions(
        args.base_sha,
        args.head_sha,
    )

    if len(additions) > MAX_NEW:

        data["errors"].append(
            f"PR adds {len(additions)} "
            f"entries; maximum allowed is "
            f"{MAX_NEW}"
        )

    data[
        "changed_additions"
    ] = len(additions)

    # --------------------------------------------------------
    # Validate every added entry
    # --------------------------------------------------------

    for (
        path,
        feed_type,
        value,
    ) in additions:

        kind, normalized = classify(
            value
        )

        item = {
            "path": path,
            "feed_type":
                feed_type,
            "value":
                value,
            "kind":
                kind,
            "normalized":
                normalized,
        }

        data[
            "entries"
        ].append(item)

        validate_entry(
            value,
            feed_type,
            f"PR addition {path}",
            data,
        )

    # --------------------------------------------------------
    # Whitelist warning
    # --------------------------------------------------------

    if any(
        item["feed_type"] == "whitelist"
        for item in data["entries"]
    ):

        data["warnings"].append(
            "Whitelist changes require human "
            "review; this gate never "
            "auto-merges or auto-trusts them."
        )

    # --------------------------------------------------------
    # Initial decision
    # --------------------------------------------------------

    data["decision"] = (
        "PASS"
        if not data["errors"]
        else "FAIL"
    )

    save_report(
        data,
        report,
    )

    print(
        json.dumps(
            {
                "decision":
                    data["decision"],
                "changed_additions":
                    len(additions),
                "errors":
                    len(data["errors"]),
                "warnings":
                    len(data["warnings"]),
            },
            indent=2,
        )
    )

    return data


# ============================================================
# FINAL DECISION
# ============================================================

def finalize(
    report: Path,
):

    data = load_report(
        report
    )

    data["decision"] = (
        "PASS"
        if not data.get("errors")
        else "FAIL"
    )

    save_report(
        data,
        report,
    )

    print(
        json.dumps(
            data,
            indent=2,
        )
    )

    if data["decision"] != "PASS":

        print(
            "AEGIS SECURITY GATE: FAIL",
            file=sys.stderr,
        )

        sys.exit(1)

    print(
        "AEGIS SECURITY GATE: PASS"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "AEGIS Community "
            "Intelligence Security Gate"
        )
    )

    parser.add_argument(
        "--base-sha"
    )

    parser.add_argument(
        "--head-sha"
    )

    parser.add_argument(
        "--report",
        default=str(
            REPORT_DEFAULT
        ),
    )

    parser.add_argument(
        "--reputation",
        choices=[
            "virustotal",
            "malwarebazaar",
        ],
    )

    parser.add_argument(
        "--finalize",
        action="store_true",
    )

    args = parser.parse_args()

    report = Path(
        args.report
    )

    # --------------------------------------------------------
    # Finalize existing report
    # --------------------------------------------------------

    if args.finalize:

        finalize(
            report
        )

        return

    # --------------------------------------------------------
    # Reputation phase
    # --------------------------------------------------------

    if args.reputation:

        data = load_report(
            report
        )

        run_reputation(
            args.reputation,
            data,
        )

        data["decision"] = (
            "PASS"
            if not data["errors"]
            else "FAIL"
        )

        save_report(
            data,
            report,
        )

        print(
            f"{args.reputation}: "
            f"checked; "
            f"errors="
            f"{len(data['errors'])}, "
            f"warnings="
            f"{len(data['warnings'])}"
        )

        return

    # --------------------------------------------------------
    # Normal validation
    # --------------------------------------------------------

    phase_validate(
        args,
        report,
    )


if __name__ == "__main__":
    main()
