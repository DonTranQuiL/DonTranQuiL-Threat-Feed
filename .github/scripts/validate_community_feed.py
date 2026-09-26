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
- Reputation lookups are throttled, capped per run and cached;
  anything that could not be checked fails closed.
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
import time
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


# Files a community PR is allowed to touch.
FEED_PATHS = {
    path.relative_to(ROOT).as_posix()
    for path in FEEDS.values()
}


# Only these PR authors may change anything else
# (workflows, scripts, README, ...).
TRUSTED_ASSOCIATIONS = {
    "OWNER",
    "MEMBER",
}


# author_association says CONTRIBUTOR for PRIVATE org members, so the
# workflow also passes the author's real repository permission
# (GET /repos/{repo}/collaborators/{user}/permission; maintain -> write).
TRUSTED_PERMISSIONS = {
    "admin",
    "write",
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
# REPUTATION RATE LIMITS
#
# Free VirusTotal API: 4 lookups / minute, 500 / day.
# Anything we could not check is an ERROR (fail closed).
# ============================================================

VT_MIN_INTERVAL = float(
    os.environ.get(
        "AEGIS_VT_MIN_INTERVAL_SECONDS",
        "16",
    )
)

MB_MIN_INTERVAL = float(
    os.environ.get(
        "AEGIS_MB_MIN_INTERVAL_SECONDS",
        "1",
    )
)

MAX_LOOKUPS = int(
    os.environ.get(
        "AEGIS_MAX_REPUTATION_LOOKUPS",
        "20",
    )
)

# More "suspicious" VT verdicts than this on a whitelist
# hash is an error (1 is only a warning by default).
VT_MAX_SUSPICIOUS = int(
    os.environ.get(
        "AEGIS_VT_MAX_SUSPICIOUS",
        "1",
    )
)


# ============================================================
# REPUTATION CACHE
#
# Only definitive answers are cached. Errors / 429 never.
# ============================================================

CACHE_DEFAULT = os.environ.get(
    "AEGIS_REPUTATION_CACHE",
    "",
)

CACHE_TTL = {
    # Unknown hashes may be uploaded soon: re-check daily.
    "not_found": 24 * 3600,

    # Detection counts / MalwareBazaar hits: one week.
    "found": 7 * 24 * 3600,
}

REPUTATION_PROVIDERS = (
    "virustotal",
    "malwarebazaar",
)

PROVIDER_LABEL = {
    "virustotal": "VirusTotal",
    "malwarebazaar": "MalwareBazaar",
}

HASH_KINDS = {
    "sha256",
    "sha1",
    "md5",
}


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

def feed_lines(
    path: Path,
    ref: str | None = None,
):
    # --------------------------------------------------------
    # PR mode: read the feed as it is in the PR head commit
    # (data only - PR code is never executed).
    # --------------------------------------------------------

    if ref:

        content = git_file(
            ref,
            path,
        )

        if content is None:
            return []

    elif not path.exists():
        return []

    else:

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="strict",
            )
        except Exception as exc:
            raise SystemExit(
                f"Unable to read feed {path}: {exc}"
            )

    lines = []

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

def collect_all(
    data: dict,
    ref: str | None = None,
):

    total = 0

    seen_global = {}

    for key, path in FEEDS.items():

        feed_type = (
            "whitelist"
            if "whitelist" in key
            else "blacklist"
        )

        rows = feed_lines(
            path,
            ref,
        )

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
            FEEDS["whitelist"],
            ref,
        )
    }

    blacklist_values = {
        value
        for _, value in feed_lines(
            FEEDS["blacklist"],
            ref,
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


def git_file(
    ref: str,
    path: Path,
):
    """Return a file's text at a commit, or None if absent."""

    relative = path.relative_to(ROOT).as_posix()

    try:

        listing = subprocess.check_output(
            [
                "git",
                "ls-tree",
                "--name-only",
                ref,
                "--",
                relative,
            ],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
        )

        if not listing.strip():
            return None

        return subprocess.check_output(
            [
                "git",
                "show",
                f"{ref}:{relative}",
            ],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
        ).decode(
            "utf-8",
            errors="strict",
        )

    except (
        subprocess.CalledProcessError,
        UnicodeDecodeError,
    ) as exc:

        raise SystemExit(
            f"Unable to read feed {relative} "
            f"at {ref}: {exc}"
        )


# ============================================================
# FILES CHANGED BY THE PR
# ============================================================

def changed_paths(
    base_sha: str | None,
    head_sha: str | None,
):

    if not base_sha or not head_sha:
        return []

    # Prefer merge-base (three-dot) so a PR that is behind
    # main is not blamed for main's own changes. Without a
    # merge base fall back to two-dot, which can only list
    # MORE files (fail closed).
    for spec in (
        [f"{base_sha}...{head_sha}"],
        [base_sha, head_sha],
    ):

        try:

            output = subprocess.check_output(
                [
                    "git",
                    "diff",
                    "--name-only",
                    "--no-renames",
                    *spec,
                ],
                cwd=ROOT,
                text=True,
                stderr=subprocess.DEVNULL,
            )

        except subprocess.CalledProcessError:
            continue

        return sorted(
            {
                line.strip()
                for line in output.splitlines()
                if line.strip()
            }
        )

    raise SystemExit(
        "Unable to list files changed by the PR"
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
# THROTTLE
# ============================================================

LAST_CALL = {}


def throttle(
    provider: str,
):
    """Sleep until the provider's minimum interval has passed."""

    interval = (
        VT_MIN_INTERVAL
        if provider == "virustotal"
        else MB_MIN_INTERVAL
    )

    last = LAST_CALL.get(
        provider
    )

    if last is None:
        return 0.0

    wait = interval - (
        time.monotonic() - last
    )

    if wait > 0:

        time.sleep(
            wait
        )

        return wait

    return 0.0


# ============================================================
# REPUTATION CACHE
# ============================================================

def cache_entry_valid(
    cache_key: str,
    record,
    now: float,
):

    if not isinstance(
        record,
        dict,
    ):
        return False

    provider = record.get(
        "provider"
    )

    indicator = str(
        record.get(
            "indicator",
            "",
        )
    )

    status = record.get(
        "status"
    )

    checked_at = record.get(
        "checked_at"
    )

    if (
        provider not in REPUTATION_PROVIDERS
        or status not in CACHE_TTL
        or cache_key != f"{provider}:{indicator}"
        or classify(indicator)[0] not in HASH_KINDS
        or not isinstance(
            checked_at,
            (int, float),
        )
    ):
        return False

    # Future timestamps are never trusted.
    if checked_at > now + 300:
        return False

    # Expired.
    if now - checked_at > CACHE_TTL[status]:
        return False

    if (
        provider == "virustotal"
        and status == "found"
    ):

        for field in (
            "malicious",
            "suspicious",
            "engines",
        ):

            value = record.get(
                field
            )

            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                return False

    return True


def cache_load(
    path: str | None,
):
    """Return (entries, dirty). Invalid/expired entries are dropped."""

    if not path:
        return {}, False

    cache_file = Path(
        path
    )

    if not cache_file.exists():
        return {}, False

    try:

        raw = json.loads(
            cache_file.read_text(
                encoding="utf-8"
            )
        )

    except (
        OSError,
        ValueError,
    ):

        # A corrupt cache only costs lookups; never trust it.
        return {}, True

    entries = (
        raw.get("entries")
        if isinstance(raw, dict)
        else None
    )

    if not isinstance(
        entries,
        dict,
    ):
        return {}, True

    now = time.time()

    valid = {
        cache_key: record
        for cache_key, record in entries.items()
        if cache_entry_valid(
            cache_key,
            record,
            now,
        )
    }

    return valid, len(valid) != len(entries)


def cache_save(
    path: str | None,
    entries: dict,
):

    if not path:
        return

    cache_file = Path(
        path
    )

    cache_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = cache_file.with_suffix(
        cache_file.suffix + ".tmp"
    )

    temporary.write_text(
        json.dumps(
            {
                "schema": 1,
                "entries": entries,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    os.replace(
        temporary,
        cache_file,
    )


# ============================================================
# LOOKUP RESULT INTERPRETATION
#
# Status values:
#   found / not_found    definitive (cacheable)
#   rate_limited         429 / quota -> stop provider
#   auth_error           bad key     -> stop provider
#   error                anything else (not cacheable)
# ============================================================

def vt_record(
    key_id: str,
    status,
    body,
):

    body = body if isinstance(body, dict) else {}

    record = {
        "provider":
            "virustotal",
        "indicator":
            key_id,
    }

    error_text = str(
        body.get(
            "error",
            "",
        )
    )

    # ------------------------------------------------
    # Unknown hash
    # ------------------------------------------------

    if status == 404:

        record["status"] = "not_found"

    # ------------------------------------------------
    # Rate limit / quota
    # ------------------------------------------------

    elif (
        status == 429
        or "QuotaExceeded" in error_text
    ):

        record["status"] = "rate_limited"
        record["http"] = status

    elif status in {
        401,
        403,
    }:

        record["status"] = "auth_error"
        record["http"] = status

    # ------------------------------------------------
    # API error
    # ------------------------------------------------

    elif status != 200:

        record["status"] = "error"
        record["http"] = status

        if error_text:
            record["detail"] = error_text[:180]

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

        counts = {
            name: int(
                stats.get(
                    name,
                    0,
                )
                or 0
            )
            for name in (
                "malicious",
                "suspicious",
                "undetected",
                "harmless",
            )
        }

        record.update(
            {
                "status":
                    "found",
                "malicious":
                    counts["malicious"],
                "suspicious":
                    counts["suspicious"],

                # Engines that returned a real verdict.
                "engines":
                    sum(counts.values()),

                "reputation":
                    attributes.get(
                        "reputation"
                    ),
            }
        )

    return record


def mb_record(
    key_id: str,
    status,
    body,
):

    body = body if isinstance(body, dict) else {}

    record = {
        "provider":
            "malwarebazaar",
        "indicator":
            key_id,
    }

    query_status = str(
        body.get(
            "query_status",
            "",
        )
    ).lower()

    if status == 429:

        record["status"] = "rate_limited"
        record["http"] = status

    elif status in {
        401,
        403,
    }:

        record["status"] = "auth_error"
        record["http"] = status

    elif status != 200:

        record["status"] = "error"
        record["http"] = status

        if body.get("error"):
            record["detail"] = str(
                body["error"]
            )[:180]

    elif query_status == "hash_not_found":

        record["status"] = "not_found"

    elif query_status == "ok":

        record["status"] = "found"

        samples = body.get(
            "data"
        )

        if (
            isinstance(samples, list)
            and samples
            and isinstance(samples[0], dict)
        ):
            record["signature"] = samples[0].get(
                "signature"
            )

    elif (
        "limit" in query_status
        or "quota" in query_status
    ):

        record["status"] = "rate_limited"
        record["query_status"] = query_status

    elif (
        "auth" in query_status
        or "blacklisted" in query_status
    ):

        record["status"] = "auth_error"
        record["query_status"] = query_status

    else:

        # illegal_hash etc. is NOT a clean result.
        record["status"] = "error"
        record["query_status"] = query_status

    return record


# ============================================================
# VERDICT FOR A DEFINITIVE RECORD
# ============================================================

def judge_record(
    record: dict,
    feed_type: str,
    data: dict,
):

    if record.get("status") != "found":
        return

    key_id = record["indicator"]

    # =================================================
    # VIRUSTOTAL
    # =================================================

    if record["provider"] == "virustotal":

        malicious = record.get(
            "malicious",
            0,
        )

        suspicious = record.get(
            "suspicious",
            0,
        )

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
                f"detections: {key_id}"
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
            and suspicious > VT_MAX_SUSPICIOUS
        ):

            data["errors"].append(
                "VirusTotal: whitelist "
                f"hash has {suspicious} suspicious "
                f"detections (limit "
                f"{VT_MAX_SUSPICIOUS}): {key_id}"
            )

        elif (
            feed_type == "whitelist"
            and suspicious >= 1
        ):

            data["warnings"].append(
                "VirusTotal: whitelist "
                "hash has suspicious "
                f"detections: {key_id}"
            )

        # ------------------------------------------------
        # Known to VT but never analysed: not verified
        # ------------------------------------------------

        elif (
            feed_type == "whitelist"
            and record.get("engines", 0) == 0
        ):

            data["errors"].append(
                "VirusTotal: whitelist hash "
                "has no completed analysis; "
                f"manual review required: {key_id}"
            )

    # =================================================
    # MALWAREBAZAAR
    # =================================================

    else:

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


def mark_unchecked(
    provider: str,
    item: dict,
    reason: str,
    data: dict,
):
    """An unchecked hash is NEVER approved (fail closed)."""

    data["errors"].append(
        f"{PROVIDER_LABEL[provider]} reputation "
        f"check incomplete for "
        f"{item['feed_type']} hash "
        f"{item['normalized']}: {reason}; "
        "NOT approved - re-run the gate "
        "(cached results are reused) or "
        "review manually"
    )

    data["reputation"].append(
        {
            "provider":
                provider,
            "indicator":
                item["normalized"],
            "status":
                "unchecked",
            "reason":
                reason,
        }
    )


# ============================================================
# REPUTATION ENGINE
# ============================================================

def run_reputation(
    provider: str,
    data: dict,
    cache_path: str | None = None,
):

    if provider not in REPUTATION_PROVIDERS:

        raise SystemExit(
            f"Unknown reputation provider: "
            f"{provider}"
        )

    label = PROVIDER_LABEL[provider]

    # --------------------------------------------------------
    # Only hash indicators (one per hash + feed type)
    # --------------------------------------------------------

    hashes = []

    seen = set()

    for item in data.get(
        "entries",
        [],
    ):

        if item["kind"] not in HASH_KINDS:
            continue

        marker = (
            item["normalized"],
            item["feed_type"],
        )

        if marker in seen:
            continue

        seen.add(marker)

        hashes.append(item)

    # --------------------------------------------------------
    # API key
    # --------------------------------------------------------

    env_name = (
        "VIRUSTOTAL_API_KEY"
        if provider == "virustotal"
        else "MALWAREBAZAAR_AUTH_KEY"
    )

    key = os.environ.get(
        env_name,
        "",
    ).strip()

    if not key:

        data["warnings"].append(
            f"{label} check skipped: "
            f"{env_name} is not configured"
        )

        # Unverified whitelist hashes are never approved.
        for item in hashes:

            if item["feed_type"] == "whitelist":

                mark_unchecked(
                    provider,
                    item,
                    f"{env_name} is not configured",
                    data,
                )

        return

    # --------------------------------------------------------
    # Nothing to check: no API calls, no quota spent.
    # --------------------------------------------------------

    if not hashes:
        return

    cache, cache_dirty = cache_load(
        cache_path
    )

    answers = {}

    stopped = ""

    lookups = 0

    cache_hits = 0

    for item in hashes:

        key_id = item[
            "normalized"
        ]

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

            if feed_type == "whitelist":

                data["errors"].append(
                    "VirusTotal: whitelist "
                    "entries must be SHA-256; "
                    f"{item['kind'].upper()} "
                    f"indicator is unverified: {key_id}"
                )

            else:

                data["warnings"].append(
                    "VirusTotal skipped non-SHA256 "
                    f"indicator: {key_id}"
                )

            continue

        cache_key = f"{provider}:{key_id}"

        record = answers.get(
            key_id
        )

        # ----------------------------------------------------
        # Cache hit: never look a hash up twice.
        # ----------------------------------------------------

        if (
            record is None
            and cache_key in cache
        ):

            record = dict(
                cache[cache_key],
                cached=True,
            )

            cache_hits += 1

        # ----------------------------------------------------
        # Live lookup (throttled, capped)
        # ----------------------------------------------------

        if record is None:

            if stopped:

                mark_unchecked(
                    provider,
                    item,
                    stopped,
                    data,
                )

                continue

            if lookups >= MAX_LOOKUPS:

                mark_unchecked(
                    provider,
                    item,
                    "per-run lookup cap reached "
                    "(AEGIS_MAX_REPUTATION_LOOKUPS="
                    f"{MAX_LOOKUPS})",
                    data,
                )

                continue

            throttle(
                provider
            )

            lookups += 1

            try:

                if provider == "virustotal":

                    status, body = vt_lookup(
                        key_id,
                        key,
                    )

                else:

                    status, body = mb_lookup(
                        key_id,
                        key,
                    )

            except Exception as exc:

                # ------------------------------------------------
                # Reputation service outage is NOT treated as
                # a clean result.
                # ------------------------------------------------

                status, body = (
                    None,
                    {
                        "error":
                            str(exc)[:180],
                    },
                )

            LAST_CALL[provider] = time.monotonic()

            record = (
                vt_record(
                    key_id,
                    status,
                    body,
                )
                if provider == "virustotal"
                else mb_record(
                    key_id,
                    status,
                    body,
                )
            )

            if record["status"] in CACHE_TTL:

                cache[cache_key] = dict(
                    record,
                    checked_at=int(
                        time.time()
                    ),
                )

                cache_dirty = True

        answers[key_id] = record

        # ----------------------------------------------------
        # 429 / quota / bad key: stop this provider NOW.
        # ----------------------------------------------------

        if record["status"] in {
            "rate_limited",
            "auth_error",
        }:

            detail = (
                f"HTTP {record['http']}"
                if record.get("http")
                else record.get(
                    "query_status",
                    "",
                )
            )

            stopped = stopped or (
                f"{label} "
                + (
                    "rate limit / quota reached"
                    if record["status"] == "rate_limited"
                    else "rejected the API key"
                )
                + f" ({detail}); no further "
                f"{label} calls in this run"
            )

            mark_unchecked(
                provider,
                item,
                stopped,
                data,
            )

            continue

        if record["status"] == "error":

            mark_unchecked(
                provider,
                item,
                "lookup failed ("
                + (
                    f"HTTP {record['http']}"
                    if record.get("http")
                    else record.get(
                        "query_status"
                    )
                    or record.get(
                        "detail"
                    )
                    or "no response"
                )
                + ")",
                data,
            )

            continue

        data["reputation"].append(
            record
        )

        judge_record(
            record,
            feed_type,
            data,
        )

    if cache_dirty:

        cache_save(
            cache_path,
            cache,
        )

    data.setdefault(
        "reputation_runs",
        {},
    )[provider] = {
        "lookups":
            lookups,
        "cache_hits":
            cache_hits,
        "cap":
            MAX_LOOKUPS,
        "stopped":
            stopped or None,
    }


# ============================================================
# WHITELIST HASH VERIFICATION (cross-provider, fail closed)
# ============================================================

def verify_whitelist_hashes(
    data: dict,
):

    errors = data.setdefault(
        "errors",
        [],
    )

    reputation = data.get(
        "reputation",
        [],
    )

    seen = set()

    for item in data.get(
        "entries",
        [],
    ):

        if (
            item.get("feed_type") != "whitelist"
            or item.get("kind") not in HASH_KINDS
        ):
            continue

        key_id = item["normalized"]

        if key_id in seen:
            continue

        seen.add(key_id)

        # Already failing with a more specific reason.
        if any(
            key_id in error
            for error in errors
        ):
            continue

        records = [
            record
            for record in reputation
            if record.get("indicator") == key_id
        ]

        checked = {
            record.get("provider")
            for record in records
            if record.get("status") in CACHE_TTL
        }

        missing = [
            PROVIDER_LABEL[provider]
            for provider in REPUTATION_PROVIDERS
            if provider not in checked
        ]

        if missing:

            errors.append(
                f"whitelist hash {key_id} was not "
                f"checked by {', '.join(missing)}; "
                "unverified hashes are never approved"
            )

        elif not any(
            record.get("status") == "found"
            for record in records
        ):

            errors.append(
                f"whitelist hash {key_id} is unknown "
                "to every reputation provider "
                "(not_found); it cannot be trusted "
                "automatically - manual review required"
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
    # Validate the complete feed. In PR mode this is the feed
    # as it is in the PR head (read with git, never executed),
    # so a PR that fixes the feed can pass and a PR that
    # introduces duplicates / conflicts is caught.
    # --------------------------------------------------------

    total = collect_all(
        data,
        args.head_sha
        if args.base_sha
        else None,
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
    # Files outside the community feed
    # --------------------------------------------------------

    non_feed = [
        path
        for path in changed_paths(
            args.base_sha,
            args.head_sha,
        )
        if path not in FEED_PATHS
    ]

    data[
        "non_feed_changes"
    ] = non_feed

    if non_feed:

        association = (
            args.author_association
            or ""
        ).strip().upper()

        permission = (
            args.author_permission
            or ""
        ).strip().lower()

        listed = ", ".join(
            non_feed[:20]
        ) + (
            " ..."
            if len(non_feed) > 20
            else ""
        )

        if (
            association in TRUSTED_ASSOCIATIONS
            or permission in TRUSTED_PERMISSIONS
        ):

            data["warnings"].append(
                f"PR changes {len(non_feed)} file(s) "
                "outside the community feed "
                f"(author: {association or 'UNKNOWN'}, "
                f"permission: {permission or 'unknown'}); "
                f"review them manually: {listed}"
            )

        else:

            data["errors"].append(
                "PR changes files outside the "
                "community feed; only repository "
                "owners/members may do that "
                f"(author: {association or 'UNKNOWN'}, "
                f"permission: {permission or 'unknown'}): "
                f"{listed}"
            )

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

    # Whitelist hashes must be positively known and clean.
    verify_whitelist_hashes(
        data
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

    parser.add_argument(
        "--cache",
        default=CACHE_DEFAULT,
        help=(
            "Reputation cache file "
            "(env AEGIS_REPUTATION_CACHE)"
        ),
    )

    parser.add_argument(
        "--author-association",
        default="",
        help=(
            "PR author association "
            "(OWNER, MEMBER, ...)"
        ),
    )

    parser.add_argument(
        "--author-permission",
        default="",
        help=(
            "PR author repository permission "
            "(admin, write, read, none)"
        ),
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
            args.cache,
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

        stats = data.get(
            "reputation_runs",
            {},
        ).get(
            args.reputation,
            {},
        )

        print(
            f"{args.reputation}: "
            f"checked; "
            f"lookups={stats.get('lookups', 0)}, "
            f"cache_hits={stats.get('cache_hits', 0)}, "
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
