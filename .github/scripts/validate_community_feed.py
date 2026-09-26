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
     +--> CIRCL hashlookup      (known-good catalogue, no key)
     |
     +--> VirusTotal lookup     (only hashes CIRCL does not know)
     |
     +--> MetaDefender Cloud    (optional: only if a key is set)
     |
     +--> MalwareBazaar lookup  (every hash: a hit is malware)
     |
     +--> deterministic PASS / FAIL

Entry formats (one per line, "#" starts a comment):

    name.exe                    filename only (low confidence)
    <sha256>                    hash (sha1 / md5 accepted with a warning,
                                never for the whitelist)
    name.exe|<sha256>           filename pinned to one exact binary
                                (kind "name_sha256"; the single "|" is
                                the only place a "|" is ever accepted)

A whitelist hash (bare or pinned) is approved only if it is
known-good - found in CIRCL hashlookup, or found by VirusTotal
with 0 malicious detections - AND MalwareBazaar (plus
MetaDefender, when configured) checked it without a hit.

Important:

- This script NEVER uploads malware samples.
- Reputation lookups are hash-only.
- Reputation lookups are throttled, capped per run and cached;
  anything that could not be checked fails closed.
- Filename-only whitelist entries are considered low confidence:
  a new one is accepted in pending/community_whitelist_candidates.txt
  only as "needs hash" (warning, listed in the report under
  "needs_hash"); adding one to global_whitelist.txt is an error.
- A protected operating-system name is only accepted in the
  whitelist when pinned to a SHA-256 that is verified known-good
  (the hash pins the exact binary); high-risk "living off the
  land" binaries (powershell.exe, cmd.exe, ...) are never
  whitelisted, pinned or not.
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


GLOBAL_WHITELIST_PATH = (
    FEEDS["whitelist"]
    .relative_to(ROOT)
    .as_posix()
)


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
# CIRCL hashlookup: free, no key, best effort (be polite).
# MetaDefender Cloud: daily limit per key (not-found hashes
# count 1/5).
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

CIRCL_MIN_INTERVAL = float(
    os.environ.get(
        "AEGIS_CIRCL_MIN_INTERVAL_SECONDS",
        "0.5",
    )
)

MD_MIN_INTERVAL = float(
    os.environ.get(
        "AEGIS_MD_MIN_INTERVAL_SECONDS",
        "1",
    )
)

# Live lookups per provider per run (cache hits are free).
# 120 fits a ~100-hash PR in one run.
MAX_LOOKUPS = int(
    os.environ.get(
        "AEGIS_MAX_REPUTATION_LOOKUPS",
        "120",
    )
)

# A provider that keeps failing (outage, network) is stopped
# after this many failures in a row, so a dead service cannot
# burn the job timeout; the rest stays unchecked (fail closed).
MAX_CONSECUTIVE_ERRORS = int(
    os.environ.get(
        "AEGIS_MAX_CONSECUTIVE_ERRORS",
        "5",
    )
)

# CIRCL "hashlookup:trust" (0-100, 50 = no opinion). Below this
# a CIRCL hit does NOT count as known-good.
CIRCL_MIN_TRUST = int(
    os.environ.get(
        "AEGIS_CIRCL_MIN_TRUST",
        "50",
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

# Workflow order: circl -> virustotal -> metadefender ->
# malwarebazaar -> finalize.
REPUTATION_PROVIDERS = (
    "circl",
    "virustotal",
    "metadefender",
    "malwarebazaar",
)

PROVIDER_LABEL = {
    "circl": "CIRCL hashlookup",
    "virustotal": "VirusTotal",
    "metadefender": "MetaDefender Cloud",
    "malwarebazaar": "MalwareBazaar",
}

# Secret each provider needs (None: no key needed).
PROVIDER_KEY_ENV = {
    "circl": None,
    "virustotal": "VIRUSTOTAL_API_KEY",
    "metadefender": "METADEFENDER_API_KEY",
    "malwarebazaar": "MALWAREBAZAAR_AUTH_KEY",
}

# Used only when its key is configured; skipped silently
# otherwise. Once configured it is fail closed like the rest.
OPTIONAL_PROVIDERS = {
    "metadefender",
}

HASH_KINDS = {
    "sha256",
    "sha1",
    "md5",
}

# MetaDefender scan_all_result_i values meaning "bad"
# (1 Infected/Known, 8 Blocklisted, 38 Known Bad).
MD_BAD_RESULTS = {
    1,
    8,
    38,
}

MD_SUSPICIOUS_RESULTS = {
    2,
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
# HASH-PINNED FILENAME ("name.exe|<sha256>")
#
# Exactly one "|", no whitespace around it, a filename on the
# left (checked with the normal name rules) and a SHA-256 on
# the right. Every other "|" stays forbidden.
# ============================================================

NAME_SHA256_SEPARATOR = "|"


def split_name_sha256(value: str):
    """Return (name, sha256) for a pinned entry, else None."""

    if value.count(NAME_SHA256_SEPARATOR) != 1:
        return None

    name, _, digest = value.partition(
        NAME_SHA256_SEPARATOR
    )

    match = SHA256_RE.fullmatch(
        digest
    )

    if (
        not match
        or not name
        or name != name.strip()
    ):
        return None

    return (
        name.lower(),
        match.group(1).lower(),
    )


# ============================================================
# HUMAN-READABLE IDENTIFIER
#
# Letters, digits and . _ space - + ( ) after an alphanumeric
# first character, e.g. "notepad++.exe" or
# "lenovovantage-(genericmessagingaddin).exe". Everything in
# FORBIDDEN_CHARS / FORBIDDEN_SUBSTRINGS stays rejected.
# ============================================================

NAME_RE = re.compile(
    r"^[a-z0-9][a-z0-9._ +()-]{2,199}$",
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
    pinned = split_name_sha256(value)

    if pinned:
        return (
            "name_sha256",
            f"{pinned[0]}{NAME_SHA256_SEPARATOR}{pinned[1]}",
        )

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


def value_indicator(value: str):
    """Hash a feed value is looked up by (None for names)."""

    kind, normalized = classify(value)

    if kind in HASH_KINDS:
        return normalized

    if kind == "name_sha256":
        return split_name_sha256(normalized)[1]

    return None


def reputation_indicator(item: dict):
    """Hash to look up for a report entry (None for names).

    Always derived from the normalized value, never from a
    stored field, so a report cannot smuggle another hash in.
    """

    kind = item.get("kind")

    if kind in HASH_KINDS:
        return item.get("normalized")

    if kind == "name_sha256":

        pinned = split_name_sha256(
            str(item.get("normalized", ""))
        )

        return pinned[1] if pinned else None

    return None


def reputation_kind(item: dict):
    """Hash algorithm of an entry's indicator."""

    return (
        "sha256"
        if item.get("kind") == "name_sha256"
        else item.get("kind")
    )


def is_protected_name(name: str) -> bool:

    base = (
        name.rsplit(".", 1)[0]
        if "." in name
        else name
    )

    return (
        name in PROTECTED_NAMES
        or base in PROTECTED_NAMES
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
    #
    # A hash-pinned entry ("name|sha256") may contain its ONE
    # separator; its name part still gets the full check.
    # --------------------------------------------------------

    pinned = split_name_sha256(
        value
    )

    checked_text = (
        pinned[0]
        if pinned
        else value
    )

    if any(
        token in checked_text
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

        return check_name(
            normalized,
            value,
            feed_type,
            where,
            data,
        )

    # --------------------------------------------------------
    # Filename pinned to a SHA-256
    # --------------------------------------------------------

    if kind == "name_sha256":

        return check_name(
            pinned[0],
            value,
            feed_type,
            where,
            data,
            pinned=True,
        )

    # --------------------------------------------------------
    # Hash
    # --------------------------------------------------------

    if kind in {
        "sha1",
        "md5",
    }:
        data["warnings"].append(
            f"{where}: {kind.upper()} is accepted "
            f"for compatibility; SHA-256 is preferred"
        )

    return True


def check_name(
    name: str,
    value: str,
    feed_type: str,
    where: str,
    data: dict,
    pinned: bool = False,
):
    """Filename rules, for name-only and hash-pinned entries."""

    if not NAME_RE.fullmatch(
        name
    ):
        data["errors"].append(
            f"{where}: invalid community "
            f"identifier: {value!r}"
        )

        return False

    protected = is_protected_name(
        name
    )

    high_risk = (
        feed_type == "whitelist"
        and name in SUSPICIOUS_WL_NAMES
    )

    # --------------------------------------------------------
    # Hash-pinned: "name.exe|<sha256>"
    # --------------------------------------------------------

    if pinned:

        if classify(name)[0] != "name":

            data["errors"].append(
                f"{where}: hash-pinned entry needs a "
                f"filename left of '|': {value!r}"
            )

            return False

        # The GENUINE binary is what attackers abuse, so a
        # hash does not make these safe to trust.
        if high_risk:

            data["errors"].append(
                f"{where}: high-risk executable "
                f"cannot be promoted to whitelist, "
                f"even pinned to a SHA-256: {value!r}"
            )

            return False

        # Never let a remote rule target a critical OS
        # process for blocking; a bare SHA-256 entry can
        # still blacklist the malicious file itself.
        if (
            protected
            and feed_type != "whitelist"
        ):

            data["errors"].append(
                f"{where}: protected "
                f"operating-system identifier "
                f"cannot be blacklisted by name, "
                f"even pinned to a SHA-256 (use a "
                f"bare SHA-256 entry): {value!r}"
            )

            return False

        # Whitelist: the hash pins the exact binary, so a
        # masquerading file with the same name does NOT
        # match. Approved only if the hash is verified
        # known-good (checked again in --finalize).
        if protected:

            data["warnings"].append(
                f"{where}: protected operating-system "
                f"name pinned to a SHA-256; approved only "
                f"if that exact hash is verified "
                f"known-good (CIRCL hashlookup, or "
                f"VirusTotal with 0 malicious and 0 "
                f"suspicious) and MalwareBazaar has no "
                f"hit: {value!r}"
            )

        return True

    # --------------------------------------------------------
    # Protected operating-system names
    # --------------------------------------------------------

    if protected:
        data["errors"].append(
            f"{where}: protected "
            f"operating-system identifier: "
            f"{value!r}"
        )

        return False

    # --------------------------------------------------------
    # Suspicious whitelist names
    # --------------------------------------------------------

    if high_risk:
        data["errors"].append(
            f"{where}: high-risk executable "
            f"cannot be promoted to whitelist "
            f"by name alone: {value!r}"
        )

        return False

    # --------------------------------------------------------
    # Filename-only whitelist warning
    # --------------------------------------------------------

    if feed_type == "whitelist":
        data["warnings"].append(
            f"{where}: filename-only whitelist "
            f"entry has no cryptographic identity: "
            f"{value!r}"
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

    # Same binary trusted and blocked, e.g. "a.exe|<h>" in the
    # whitelist and "<h>" in the blacklist.
    whitelist_hashes = {
        value_indicator(value)
        for value in whitelist_values
    } - {None}

    blacklist_hashes = {
        value_indicator(value)
        for value in blacklist_values
    } - {None}

    for digest in sorted(
        whitelist_hashes
        & blacklist_hashes
    ):

        if digest in conflicts:
            continue

        data["errors"].append(
            "hash exists in BOTH "
            f"production feeds: {digest}"
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
# HTTP (hash-only GET/POST, JSON answer)
# ============================================================

USER_AGENT = "AEGIS-Threat-Feed-Security-Gate"


def http_json(
    request,
):
    """Return (HTTP status, parsed JSON | {"error": text})."""

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
# CIRCL HASHLOOKUP (no key; 200 = known, 404 = unknown)
# https://hashlookup.circl.lu/lookup/<md5|sha1|sha256>/<hash>
# ============================================================

def circl_lookup(
    indicator: str,
    kind: str = "sha256",
):

    url = (
        "https://hashlookup.circl.lu/lookup/"
        + urllib.parse.quote(
            kind
        )
        + "/"
        + urllib.parse.quote(
            indicator
        )
    )

    return http_json(
        urllib.request.Request(
            url,
            headers={
                "accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
    )


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

    return http_json(
        urllib.request.Request(
            url,
            headers={
                "x-apikey": api_key,
                "accept": "application/json",
            },
        )
    )


# ============================================================
# METADEFENDER CLOUD (OPSWAT) - optional
# GET https://api.metadefender.com/v4/hash/<hash>, header
# "apikey". 404 + code 404003 = hash not found.
# ============================================================

def md_lookup(
    indicator: str,
    api_key: str,
):

    url = (
        "https://api.metadefender.com/v4/hash/"
        + urllib.parse.quote(
            indicator
        )
    )

    return http_json(
        urllib.request.Request(
            url,
            headers={
                "apikey": api_key,
                "accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
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

    return http_json(
        urllib.request.Request(
            "https://mb-api.abuse.ch/api/v1/",
            headers={
                "Auth-Key": auth_key,
                "Content-Type":
                    "application/x-www-form-urlencoded",
            },
            data=payload,
            method="POST",
        )
    )


# ============================================================
# THROTTLE
# ============================================================

LAST_CALL = {}


def throttle(
    provider: str,
):
    """Sleep until the provider's minimum interval has passed."""

    interval = {
        "circl": CIRCL_MIN_INTERVAL,
        "virustotal": VT_MIN_INTERVAL,
        "metadefender": MD_MIN_INTERVAL,
        "malwarebazaar": MB_MIN_INTERVAL,
    }.get(
        provider,
        MB_MIN_INTERVAL,
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

    if (
        provider == "circl"
        and status == "found"
    ):

        trust = record.get(
            "trust"
        )

        if (
            not isinstance(
                record.get("known_malicious"),
                bool,
            )
            or (
                trust is not None
                and (
                    not isinstance(trust, int)
                    or isinstance(trust, bool)
                )
            )
        ):
            return False

    if (
        provider == "metadefender"
        and status == "found"
    ):

        detected = record.get(
            "detected"
        )

        result_code = record.get(
            "result"
        )

        if (
            not isinstance(detected, int)
            or isinstance(detected, bool)
            or detected < 0
            or (
                result_code is not None
                and (
                    not isinstance(result_code, int)
                    or isinstance(result_code, bool)
                )
            )
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


def as_int(
    value,
):
    """int(value) for JSON numbers / digit strings, else None."""

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(value)

    if (
        isinstance(value, str)
        and value.strip().isdigit()
    ):
        return int(value.strip())

    return None


CIRCL_HASH_FIELD = {
    "sha256": "SHA-256",
    "sha1": "SHA-1",
    "md5": "MD5",
}


def circl_record(
    key_id: str,
    status,
    body,
):

    body = body if isinstance(body, dict) else {}

    record = {
        "provider":
            "circl",
        "indicator":
            key_id,
    }

    kind = classify(key_id)[0]

    if status == 404:

        record["status"] = "not_found"

    elif status in {
        429,
        503,
    }:

        record["status"] = "rate_limited"
        record["http"] = status

    elif status != 200:

        record["status"] = "error"
        record["http"] = status

        if body.get("error"):
            record["detail"] = str(
                body["error"]
            )[:180]

    else:

        reported = str(
            body.get(
                CIRCL_HASH_FIELD.get(kind, "SHA-256"),
                "",
            )
        ).strip().lower()

        # A 200 must describe exactly the hash we asked for.
        if reported != key_id:

            record["status"] = "error"
            record["detail"] = (
                "response does not match the "
                "requested hash"
            )

        else:

            record.update(
                {
                    "status":
                        "found",
                    "trust":
                        as_int(
                            body.get(
                                "hashlookup:trust"
                            )
                        ),
                    "known_malicious":
                        bool(
                            body.get(
                                "KnownMalicious"
                            )
                        ),
                    "filename":
                        str(
                            body.get(
                                "FileName"
                            )
                            or ""
                        )[:160],
                    "source":
                        str(
                            body.get(
                                "source"
                            )
                            or ""
                        )[:80],
                }
            )

    return record


def md_record(
    key_id: str,
    status,
    body,
):

    body = body if isinstance(body, dict) else {}

    record = {
        "provider":
            "metadefender",
        "indicator":
            key_id,
    }

    error_text = str(
        body.get(
            "error",
            "",
        )
    )

    if status == 404:

        # Only "the hash was not found" is a definitive
        # answer; any other 404 (wrong endpoint) is not.
        if (
            "404003" in error_text
            or "hash was not found"
            in error_text.lower()
        ):
            record["status"] = "not_found"

        else:
            record["status"] = "error"
            record["http"] = status
            record["detail"] = error_text[:180]

    elif status == 429:

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

        if error_text:
            record["detail"] = error_text[:180]

    elif body.get("error"):

        record["status"] = "error"
        record["detail"] = error_text[:180]

    else:

        scan = body.get(
            "scan_results"
        )

        scan = scan if isinstance(scan, dict) else {}

        record.update(
            {
                "status":
                    "found",
                "result":
                    as_int(
                        scan.get(
                            "scan_all_result_i"
                        )
                    ),
                "detected":
                    max(
                        as_int(
                            scan.get(
                                "total_detected_avs"
                            )
                        )
                        or 0,
                        0,
                    ),
            }
        )

    return record


def make_record(
    provider: str,
    key_id: str,
    status,
    body,
):

    if provider == "circl":
        return circl_record(key_id, status, body)

    if provider == "virustotal":
        return vt_record(key_id, status, body)

    if provider == "metadefender":
        return md_record(key_id, status, body)

    return mb_record(key_id, status, body)


def circl_counts_as_known_good(
    record: dict,
) -> bool:
    """A definitive CIRCL hit that vouches for the file."""

    if (
        record.get("provider") != "circl"
        or record.get("status") != "found"
        or record.get("known_malicious")
    ):
        return False

    trust = record.get(
        "trust"
    )

    # CIRCL always sends a trust level; 50 = "no opinion"
    # (catalogued in one source) is the documented default.
    if trust is None:
        trust = 50

    return trust >= CIRCL_MIN_TRUST


def circl_known_good(
    indicator: str,
    data: dict,
) -> bool:
    """True if this run's CIRCL phase vouched for the hash."""

    return any(
        record.get("indicator") == indicator
        and circl_counts_as_known_good(record)
        for record in data.get(
            "reputation",
            [],
        )
    )


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
    # CIRCL HASHLOOKUP
    # =================================================

    elif record["provider"] == "circl":

        trust = record.get(
            "trust"
        )

        if record.get("known_malicious"):

            if feed_type == "whitelist":

                data["errors"].append(
                    "CIRCL hashlookup: whitelist "
                    "hash is flagged KnownMalicious: "
                    f"{key_id}"
                )

            else:

                data["warnings"].append(
                    "CIRCL hashlookup corroborates "
                    "blacklist hash (KnownMalicious): "
                    f"{key_id}"
                )

        elif feed_type == "whitelist":

            if not circl_counts_as_known_good(
                record
            ):

                data["warnings"].append(
                    "CIRCL hashlookup: whitelist hash "
                    f"has low trust ({trust} < "
                    f"{CIRCL_MIN_TRUST}); not counted "
                    f"as known-good: {key_id}"
                )

        else:

            data["warnings"].append(
                "CIRCL hashlookup catalogues "
                "blacklist hash as a known file "
                f"(source: {record.get('source') or '?'}, "
                f"trust: {trust}); possible false "
                f"positive - review: {key_id}"
            )

    # =================================================
    # METADEFENDER CLOUD
    # =================================================

    elif record["provider"] == "metadefender":

        detected = record.get(
            "detected",
            0,
        )

        result_code = record.get(
            "result"
        )

        bad = (
            result_code in MD_BAD_RESULTS
            or detected >= 1
        )

        if (
            feed_type == "whitelist"
            and bad
        ):

            data["errors"].append(
                "MetaDefender Cloud: whitelist "
                f"hash flagged ({detected} engine "
                f"detections, result {result_code}): "
                f"{key_id}"
            )

        elif (
            feed_type == "whitelist"
            and result_code in MD_SUSPICIOUS_RESULTS
        ):

            data["warnings"].append(
                "MetaDefender Cloud: whitelist "
                f"hash is suspicious: {key_id}"
            )

        elif (
            feed_type == "blacklist"
            and bad
        ):

            data["warnings"].append(
                "MetaDefender Cloud corroborates "
                f"blacklist hash ({detected} engine "
                f"detections): {key_id}"
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
    """An unchecked hash is NEVER approved (fail closed).

    CIRCL is the exception: an unanswered CIRCL lookup simply
    does not vouch for the hash, which then needs VirusTotal
    (and fails there if VirusTotal cannot verify it).
    """

    if provider == "circl":

        data["warnings"].append(
            f"{PROVIDER_LABEL[provider]} check "
            f"incomplete for {item['feed_type']} "
            f"hash {item['normalized']}: {reason}; "
            "not counted as known-good - "
            "VirusTotal must verify it"
        )

    else:

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

def reputation_items(
    data: dict,
):
    """One lookup item per (hash, feed type).

    Bare hashes and the hash part of "name|sha256" entries
    are looked up alike.
    """

    items = []

    seen = set()

    for item in data.get(
        "entries",
        [],
    ):

        indicator = reputation_indicator(
            item
        )

        if not indicator:
            continue

        marker = (
            indicator,
            item["feed_type"],
        )

        if marker in seen:
            continue

        seen.add(marker)

        items.append(
            {
                "feed_type":
                    item["feed_type"],
                "kind":
                    reputation_kind(item),
                "normalized":
                    indicator,
                "value":
                    item.get(
                        "value",
                        indicator,
                    ),
            }
        )

    return items


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

    runs = data.setdefault(
        "reputation_runs",
        {},
    )

    # --------------------------------------------------------
    # Only hash indicators (one per hash + feed type)
    # --------------------------------------------------------

    hashes = reputation_items(
        data
    )

    # --------------------------------------------------------
    # API key
    # --------------------------------------------------------

    env_name = PROVIDER_KEY_ENV[
        provider
    ]

    key = (
        os.environ.get(
            env_name,
            "",
        ).strip()
        if env_name
        else ""
    )

    if env_name and not key:

        runs[provider] = {
            "configured": False,
            "lookups": 0,
            "cache_hits": 0,
            "cap": MAX_LOOKUPS,
            "stopped": None,
        }

        # Optional provider: skipped silently, never fails.
        if provider in OPTIONAL_PROVIDERS:

            print(
                f"{label}: {env_name} is not set; "
                "optional provider skipped"
            )

            return

        data["warnings"].append(
            f"{label} check skipped: "
            f"{env_name} is not configured"
        )

        # Unverified whitelist hashes are never approved.
        # (VirusTotal is not needed for hashes CIRCL
        # already vouched for.)
        for item in hashes:

            if item["feed_type"] != "whitelist":
                continue

            if (
                provider == "virustotal"
                and item["kind"] == "sha256"
                and circl_known_good(
                    item["normalized"],
                    data,
                )
            ):
                continue

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

        runs[provider] = {
            "configured": True,
            "lookups": 0,
            "cache_hits": 0,
            "cap": MAX_LOOKUPS,
            "stopped": None,
        }

        return

    cache, cache_dirty = cache_load(
        cache_path
    )

    answers = {}

    stopped = ""

    lookups = 0

    cache_hits = 0

    skipped_known = 0

    failures_in_row = 0

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

        # ----------------------------------------------------
        # CIRCL already vouches for it: no VirusTotal quota.
        # ----------------------------------------------------

        if (
            provider == "virustotal"
            and circl_known_good(
                key_id,
                data,
            )
        ):

            skipped_known += 1

            data["reputation"].append(
                {
                    "provider":
                        provider,
                    "indicator":
                        key_id,
                    "status":
                        "skipped",
                    "reason":
                        "known-good in CIRCL hashlookup",
                }
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

                if provider == "circl":

                    status, body = circl_lookup(
                        key_id,
                        item["kind"],
                    )

                elif provider == "virustotal":

                    status, body = vt_lookup(
                        key_id,
                        key,
                    )

                elif provider == "metadefender":

                    status, body = md_lookup(
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

            record = make_record(
                provider,
                key_id,
                status,
                body,
            )

            if record["status"] in CACHE_TTL:

                cache[cache_key] = dict(
                    record,
                    checked_at=int(
                        time.time()
                    ),
                )

                cache_dirty = True

                failures_in_row = 0

            elif record["status"] == "error":

                failures_in_row += 1

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

            # A dead service must not burn the job timeout.
            if (
                failures_in_row
                >= MAX_CONSECUTIVE_ERRORS
                and not stopped
            ):

                stopped = (
                    f"{label} failed {failures_in_row} "
                    "lookups in a row; no further "
                    f"{label} calls in this run"
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

    runs[provider] = {
        "configured":
            True,
        "lookups":
            lookups,
        "cache_hits":
            cache_hits,
        "skipped_known_good":
            skipped_known,
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
    """Every whitelist hash must be positively known-good.

    known-good = found in CIRCL hashlookup (trust >= minimum,
    not flagged), OR found by VirusTotal with 0 malicious,
    completed analysis and suspicious within the limit (0 for
    a protected OS name pinned to the hash).

    Always required: MalwareBazaar answered (a hit is already
    an error). VirusTotal is required when CIRCL does not vouch
    for the hash; MetaDefender when its key was configured.
    """

    errors = data.setdefault(
        "errors",
        [],
    )

    reputation = data.get(
        "reputation",
        [],
    )

    runs = data.get(
        "reputation_runs",
        {},
    ) or {}

    md_required = bool(
        (
            runs.get(
                "metadefender",
            )
            or {}
        ).get(
            "configured"
        )
    )

    # indicator -> {"kind", "protected"}
    whitelist_hashes = {}

    for item in data.get(
        "entries",
        [],
    ):

        if item.get("feed_type") != "whitelist":
            continue

        key_id = reputation_indicator(
            item
        )

        if not key_id:
            continue

        info = whitelist_hashes.setdefault(
            key_id,
            {
                "kind": reputation_kind(item),
                "protected": False,
            },
        )

        if item.get("kind") == "name_sha256":

            name = split_name_sha256(
                item["normalized"]
            )[0]

            if is_protected_name(name):
                info["protected"] = True

    for key_id, info in whitelist_hashes.items():

        # Already failing with a more specific reason.
        if any(
            key_id in error
            for error in errors
        ):
            continue

        if info["kind"] != "sha256":

            errors.append(
                f"whitelist hash {key_id} is "
                f"{str(info['kind']).upper()}; whitelist "
                "hash entries must be SHA-256"
            )

            continue

        definitive = {}

        for record in reputation:

            if (
                record.get("indicator") == key_id
                and record.get("status") in CACHE_TTL
            ):
                definitive[
                    record.get("provider")
                ] = record

        circl_ok = circl_counts_as_known_good(
            definitive.get("circl") or {}
        )

        vt = definitive.get(
            "virustotal"
        ) or {}

        vt_ok = (
            vt.get("status") == "found"
            and vt.get("malicious", 0) == 0
            and vt.get("engines", 0) > 0
            and vt.get("suspicious", 0)
            <= (
                0
                if info["protected"]
                else VT_MAX_SUSPICIOUS
            )
        )

        required = {
            "malwarebazaar",
        }

        if not circl_ok:
            required.add("virustotal")

        if md_required:
            required.add("metadefender")

        missing = [
            PROVIDER_LABEL[provider]
            for provider in REPUTATION_PROVIDERS
            if provider in required
            and provider not in definitive
        ]

        if missing:

            errors.append(
                f"whitelist hash {key_id} was not "
                f"checked by {', '.join(missing)}; "
                "unverified hashes are never approved"
            )

        elif not (
            circl_ok
            or vt_ok
        ):

            errors.append(
                f"whitelist hash {key_id} is unknown "
                "to every reputation provider that "
                "can vouch for it (CIRCL hashlookup, "
                "VirusTotal with 0 detections"
                + (
                    " and 0 suspicious for a protected "
                    "OS name"
                    if info["protected"]
                    else ""
                )
                + "); it cannot be trusted "
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
            getattr(
                args,
                "author_permission",
                "",
            )
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

    # Name-only whitelist entries already in production at the
    # PR base (see below).
    base_global_names = {
        value
        for _, value in feed_lines(
            FEEDS["whitelist"],
            args.base_sha,
        )
        if classify(value)[0] == "name"
    } if args.base_sha else set()

    data["needs_hash"] = []

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

        valid = validate_entry(
            value,
            feed_type,
            f"PR addition {path}",
            data,
        )

        # ----------------------------------------------------
        # Name-only whitelist additions (no hash):
        #   pending candidates  -> accepted as "needs hash"
        #                          (warning + report list)
        #   global_whitelist    -> ERROR: production trust
        #                          needs "name|sha256"
        # Lines already in the base global whitelist (moved /
        # re-sorted) are not new trust and are not blamed.
        # ----------------------------------------------------

        if (
            valid
            and feed_type == "whitelist"
            and kind == "name"
        ):

            if path == GLOBAL_WHITELIST_PATH:

                if normalized not in base_global_names:

                    data["errors"].append(
                        f"PR addition {path}: name-only "
                        "entry cannot be added to the "
                        "production whitelist; pin it "
                        "as 'name|<sha256>' or submit it "
                        "to pending/community_whitelist_"
                        f"candidates.txt: {value!r}"
                    )

            else:

                data["needs_hash"].append(
                    value
                )

                data["warnings"].append(
                    f"PR addition {path}: name-only "
                    "candidate accepted as NEEDS HASH "
                    "(not trusted until submitted as "
                    f"'name|<sha256>'): {value!r}"
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
                "needs_hash":
                    len(data["needs_hash"]),
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
        choices=list(
            REPUTATION_PROVIDERS
        ),
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
            + (
                "skipped (key not configured); "
                if stats.get("configured") is False
                else "checked; "
            )
            +
            f"lookups={stats.get('lookups', 0)}, "
            f"cache_hits={stats.get('cache_hits', 0)}, "
            f"skipped_known_good="
            f"{stats.get('skipped_known_good', 0)}, "
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
