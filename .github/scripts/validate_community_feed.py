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
     +--> Hybrid Analysis       (optional: only if a key is set;
     |                           Falcon Sandbox verdict)
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

global_whitelist.txt accepts ONLY "name.exe|<sha256>" lines.

A whitelist hash (bare or pinned) is approved only if it is
known-good - found in CIRCL hashlookup, or found by VirusTotal
with 0 malicious detections - AND MalwareBazaar (plus
MetaDefender and Hybrid Analysis, when configured) checked it
without a hit. Hybrid Analysis: "malicious" is a hard reject,
"suspicious" goes to human review; "no specific threat",
"whitelisted", "no verdict" and "not found" never block (and
never vouch) on their own.

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
- global_whitelist.txt holds ONLY "name|sha256" lines, and every
  one of them has a proof entry in verified_whitelist.json (which
  providers confirmed it, VirusTotal counts, first_verified /
  last_checked). The gate checks that both files match.
- Maintainer overrides (maintainer_overrides.txt, "sha256|name|reason"):
  a hash listed there by the repository owner is accepted in the
  whitelist despite a few VirusTotal detections (false positives,
  at most AEGIS_OVERRIDE_MAX_DETECTIONS malicious + suspicious),
  but only pinned to exactly that name. It never lifts a
  MalwareBazaar hit, a CIRCL KnownMalicious flag, a MetaDefender
  detection, a missing / unanalysed VirusTotal answer, the
  protected-name or high-risk (PowerShell / cmd ...) rules. The
  gate reads the file from main's trusted checkout (a PR can not
  override its own lines); changing it needs the owner / an admin.
  The proof entry records the override ("maintainer_override").
- pending/needs_review.txt is the human review queue: rejected
  and not-yet-verifiable staging lines (with reasons), maintained
  by the promotion job, never auto-trusted. Hard rejects
  (PowerShell / cmd / MalwareBazaar / CIRCL KnownMalicious) are
  marked hard_reject; everything else is review.
- IGNORED_NAMES (e.g. aegis-ransomware-guard) are dropped forever
  and never re-enter pending or needs_review.
- Promotion (--promote): after the gate ran on a staging PR
  (branch aegis-community-staging*), the entries that passed
  EVERY check are written onto a fresh copy of main and proposed
  in the "AEGIS verified promotion" PR; rejected lines stay in
  staging and are listed with their reasons. The promotion PR is
  gated again and squash-merged automatically once green.
- Staging inbox mode (--staging-inbox, set by the workflow only for
  an OPEN DRAFT PR from this repository on an aegis-community-
  staging* branch): the staging PR is never merged, every line is
  judged one by one by the promotion job (promoted / queued for
  review / retried / ignored), so per-line problems (reputation
  rejections, failed lookups, lines without a proof entry) do not
  fail the check. It still FAILS on structural problems: changes
  outside the feed by non-members, too many lines, a rewritten
  proof, a rejected / missing API key, feed errors not tied to one
  of the PR's lines. Marking the PR ready for review re-runs the
  gate in strict mode (red), so a staging PR can never be merged.
- Community intelligence never automatically becomes local trust.
- Community intelligence never automatically kills a local process.
"""

from __future__ import annotations

import argparse
import datetime
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


# Human review queue (promotion job writes it; never production trust).
NEEDS_REVIEW_REL = "pending/needs_review.txt"

NEEDS_REVIEW_PATH = ROOT / NEEDS_REVIEW_REL

# disposition values in needs_review.txt.
REVIEW_DISPOSITIONS = {
    "review",
    "hard_reject",
}

# Names the gate permanently drops (Sentinel / AEGIS internal, etc.).
# They never enter production feeds, pending candidates or needs_review.
IGNORED_NAMES = {
    "aegis-ransomware-guard",
}


GLOBAL_WHITELIST_PATH = (
    FEEDS["whitelist"]
    .relative_to(ROOT)
    .as_posix()
)


# Proof for every production whitelist line (generated by the
# promotion job, checked by the gate).
PROOF_PATH = ROOT / "verified_whitelist.json"

PROOF_REL = "verified_whitelist.json"

PROOF_SCHEMA = 1

PROOF_FIELDS = (
    "name",
    "sha256",
    "sources",
    "virustotal",
    "first_verified",
    "last_checked",
)

# Maintainer overrides: "sha256|name|reason", one per line.
# Read from the trusted checkout (main) for reputation decisions.
OVERRIDES_REL = "maintainer_overrides.txt"

OVERRIDE_FIELD = "maintainer_override"

# An override covers at most this many VirusTotal malicious +
# suspicious verdicts; above that it is not applied (a file that
# starts to be detected widely needs a new look).
OVERRIDE_MAX_DETECTIONS = int(
    os.environ.get(
        "AEGIS_OVERRIDE_MAX_DETECTIONS",
        "5",
    )
)

# Plain text only: no Markdown / HTML / mentions, no "|".
OVERRIDE_REASON_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9 .,:;()/+_'#&=-]{2,199}$"
)

# Who may change maintainer_overrides.txt in a PR.
OVERRIDE_ASSOCIATIONS = {
    "OWNER",
}

OVERRIDE_PERMISSIONS = {
    "admin",
}

ISO_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)

# Branches whose PRs are staging inboxes (never merged) and the
# branch / PR the promotion job maintains.
STAGING_PREFIX = "aegis-community-staging"

PROMOTION_BRANCH = "aegis-verified-promotion"

PROMOTION_TITLE = "AEGIS verified promotion"

PROMOTION_MARKER = "<!-- aegis-promotion-report -->"


# Files a community PR is allowed to touch.
FEED_PATHS = {
    path.relative_to(ROOT).as_posix()
    for path in FEEDS.values()
} | {
    PROOF_REL,
    NEEDS_REVIEW_REL,
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

# Hybrid Analysis (Falcon Sandbox): this repository's key is a
# "Restricted" key (hash search only) with 200 API requests /
# minute. At most one lookup per 0.5 s (<= 120 / minute) keeps
# well below that; cached answers cost nothing. API v2 also
# allows one key from at most 2 IPs per hour (a GitHub runner
# gets a new IP each run): the limit answer is treated as a
# quota (not verified yet, retried), never as a bad key.
# Only hash lookups are made - nothing is ever submitted.
HA_MIN_INTERVAL = float(
    os.environ.get(
        "AEGIS_HA_MIN_INTERVAL_SECONDS",
        "0.5",
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

# Optional extra cap for Hybrid Analysis live lookups per run
# (the rest is "not verified yet" and retried; cached answers
# are free). Default: the same as every provider.
HA_MAX_LOOKUPS = int(
    os.environ.get(
        "AEGIS_HA_MAX_LOOKUPS",
        str(MAX_LOOKUPS),
    )
)


def provider_cap(
    provider: str,
) -> int:
    """Live lookups allowed for this provider in one run."""

    if provider == "hybridanalysis":
        return min(
            MAX_LOOKUPS,
            HA_MAX_LOOKUPS,
        )

    return MAX_LOOKUPS

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
# hybridanalysis -> malwarebazaar -> finalize.
REPUTATION_PROVIDERS = (
    "circl",
    "virustotal",
    "metadefender",
    "hybridanalysis",
    "malwarebazaar",
)

PROVIDER_LABEL = {
    "circl": "CIRCL hashlookup",
    "virustotal": "VirusTotal",
    "metadefender": "MetaDefender Cloud",
    "hybridanalysis": "Hybrid Analysis",
    "malwarebazaar": "MalwareBazaar",
}

# Secret each provider needs (None: no key needed).
PROVIDER_KEY_ENV = {
    "circl": None,
    "virustotal": "VIRUSTOTAL_API_KEY",
    "metadefender": "METADEFENDER_API_KEY",
    "hybridanalysis": "HYBRID_ANALYSIS_API_KEY",
    "malwarebazaar": "MALWAREBAZAAR_AUTH_KEY",
}

# Used only when its key is configured; skipped silently
# otherwise. Once configured it is fail closed like the rest
# (no answer = not verified yet, retried).
OPTIONAL_PROVIDERS = {
    "metadefender",
    "hybridanalysis",
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

# Hybrid Analysis (Falcon Sandbox) verdicts, worst first. The
# API returns them as text ("no specific threat") in search
# results; the numeric search filter uses 1..5 (1 whitelisted,
# 2 no verdict, 3 no specific threat, 4 suspicious, 5 malicious).
HA_VERDICT_RANK = {
    "malicious": 5,
    "suspicious": 4,
    "no specific threat": 3,
    "no verdict": 2,
    "whitelisted": 1,
}

HA_VERDICT_CODES = {
    rank: verdict
    for verdict, rank in HA_VERDICT_RANK.items()
}

# malicious: hard reject. suspicious: human review. Everything
# else never blocks (and never vouches) on its own.
HA_BLOCK_VERDICTS = {
    "malicious",
}

HA_REVIEW_VERDICTS = {
    "suspicious",
}

# Proof entry field (optional; present when Hybrid Analysis
# answered for the hash): {"verdict": "<verdict | not found>"}
HA_PROOF_FIELD = "hybrid_analysis"

HA_PROOF_VERDICTS = (
    set(HA_VERDICT_RANK)
    - HA_BLOCK_VERDICTS
    - HA_REVIEW_VERDICTS
) | {
    "not found",
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

    # --------------------------------------------------------
    # maintainer_overrides.txt (format, no blacklisted hash)
    # --------------------------------------------------------

    check_overrides(
        data,
        ref,
        blacklist_hashes,
    )

    # --------------------------------------------------------
    # pending/needs_review.txt (format only; never production)
    # --------------------------------------------------------

    review_text = None

    if ref:

        review_text = git_file(
            ref,
            NEEDS_REVIEW_PATH,
        )

    elif NEEDS_REVIEW_PATH.exists():

        try:
            review_text = NEEDS_REVIEW_PATH.read_text(
                encoding="utf-8",
                errors="strict",
            )
        except Exception as exc:
            data["errors"].append(
                f"{NEEDS_REVIEW_REL}: unreadable: {exc}"
            )
            review_text = ""

    if review_text is not None:

        review_entries, review_errors = parse_needs_review(
            review_text
        )

        data["errors"].extend(
            review_errors
        )

        # The review queue is never production trust.
        for key, entry in sorted(
            review_entries.items()
        ):

            digest = value_indicator(
                key
            )

            if key in whitelist_values or (
                digest
                and digest in whitelist_hashes
            ):

                data["errors"].append(
                    f"{NEEDS_REVIEW_REL}:{entry['line']}: "
                    f"{key!r} is also in "
                    f"{GLOBAL_WHITELIST_PATH}; remove it from "
                    "one of the two files"
                )

    # --------------------------------------------------------
    # IGNORED_NAMES never live in the production feeds; in the
    # pending files they are only warned about (the promotion
    # job removes them from main automatically).
    # --------------------------------------------------------

    for key, path in FEEDS.items():

        for line_number, value in feed_lines(
            path,
            ref,
        ):

            hit = entry_ignored_name(
                value
            )

            if not hit:
                continue

            where = (
                f"{path.relative_to(ROOT)}:{line_number}"
            )

            if key in {
                "whitelist",
                "blacklist",
            }:

                data["errors"].append(
                    f"{where}: {hit!r} is permanently "
                    "ignored and never allowed in a "
                    "production feed"
                )

            else:

                data["warnings"].append(
                    f"{where}: {hit!r} is permanently "
                    "ignored (removed by the next promotion)"
                )

    # --------------------------------------------------------
    # Production whitelist: ONLY "name|sha256" lines (the app
    # reads this file raw; name-only / bare-hash candidates
    # live in pending/community_whitelist_candidates.txt).
    # --------------------------------------------------------

    pinned_lines = set()

    for line_number, value in feed_lines(
        FEEDS["whitelist"],
        ref,
    ):

        kind, normalized = classify(
            value
        )

        if kind == "name_sha256":

            pinned_lines.add(
                normalized
            )

            continue

        data["errors"].append(
            f"{GLOBAL_WHITELIST_PATH}:{line_number}: only "
            "'name|sha256' lines are allowed in the "
            "production whitelist (name-only / bare-hash "
            "candidates belong in pending/community_"
            f"whitelist_candidates.txt): {value!r}"
        )

    # --------------------------------------------------------
    # verified_whitelist.json must match global_whitelist.txt
    # --------------------------------------------------------

    check_proof_sync(
        data,
        pinned_lines,
        ref,
    )

    return total


# ============================================================
# PROOF FILE (verified_whitelist.json)
#
# {"schema": 1, "entries": [ {name, sha256, sources,
#  virustotal, first_verified, last_checked}, ... ]}
# One entry per production whitelist line, sorted by
# "name|sha256". Generated by --promote; never hand-edited.
# ============================================================

def proof_key(
    name,
    sha256,
) -> str:

    return f"{name}{NAME_SHA256_SEPARATOR}{sha256}"


def utc_iso(
    timestamp: float | None = None,
) -> str:

    return datetime.datetime.fromtimestamp(
        time.time()
        if timestamp is None
        else timestamp,
        datetime.timezone.utc,
    ).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def is_count(
    value,
) -> bool:

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def proof_entry_problem(
    entry,
    overrides: dict | None = None,
):
    """Why a proof entry is malformed (None if it is fine).

    overrides: maintainer_overrides.txt of the same tree; an
    entry with "maintainer_override" needs a matching line there.
    """

    if not isinstance(
        entry,
        dict,
    ):
        return "entry must be an object"

    if set(entry) - {HA_PROOF_FIELD} not in (
        set(PROOF_FIELDS),
        set(PROOF_FIELDS) | {OVERRIDE_FIELD},
    ):

        return (
            "fields must be exactly "
            + ", ".join(PROOF_FIELDS)
            + f" (plus {OVERRIDE_FIELD} when overridden, "
            f"{HA_PROOF_FIELD} when Hybrid Analysis answered)"
        )

    if HA_PROOF_FIELD in entry:

        ha = entry[HA_PROOF_FIELD]

        if (
            not isinstance(ha, dict)
            or set(ha) != {"verdict"}
            or ha["verdict"] not in HA_PROOF_VERDICTS
        ):
            return (
                f"{HA_PROOF_FIELD} must be "
                '{"verdict": "<'
                + " | ".join(sorted(HA_PROOF_VERDICTS))
                + '>"} (malicious / suspicious are '
                "never promoted)"
            )

    if (
        "hybridanalysis" in (entry.get("sources") or [])
        if isinstance(entry.get("sources"), list)
        else False
    ) != (HA_PROOF_FIELD in entry):
        return (
            f"hybridanalysis in sources needs the "
            f"{HA_PROOF_FIELD} verdict (and vice versa)"
        )

    name = entry["name"]

    sha256 = entry["sha256"]

    if (
        not isinstance(name, str)
        or name != name.lower()
        or not NAME_RE.fullmatch(name)
        or classify(name)[0] != "name"
    ):
        return f"invalid name {name!r}"

    if name in SUSPICIOUS_WL_NAMES:
        return f"high-risk executable {name!r}"

    if (
        not isinstance(sha256, str)
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            sha256,
        )
    ):
        return f"invalid sha256 {sha256!r}"

    overridden = OVERRIDE_FIELD in entry

    if overridden:

        marker = entry[OVERRIDE_FIELD]

        if (
            not isinstance(marker, dict)
            or set(marker) != {"reason"}
            or not isinstance(marker["reason"], str)
            or not OVERRIDE_REASON_RE.fullmatch(
                marker["reason"]
            )
        ):
            return (
                f"{OVERRIDE_FIELD} must be "
                '{"reason": "<plain text>"}'
            )

        if override_for(
            sha256,
            name,
            overrides or {},
        ) is None:
            return (
                f"{OVERRIDE_FIELD} has no matching "
                f"'{sha256}|{name}|...' line in "
                f"{OVERRIDES_REL}"
            )

    sources = entry["sources"]

    if (
        not isinstance(sources, list)
        or len(set(map(str, sources))) != len(sources)
        or not all(
            source in REPUTATION_PROVIDERS
            for source in sources
        )
    ):
        return (
            "sources must be a list of distinct "
            "providers ("
            + ", ".join(REPUTATION_PROVIDERS)
            + ")"
        )

    if "malwarebazaar" not in sources:
        return "sources must include malwarebazaar"

    # Overridden: the maintainer vouches instead of CIRCL / VT.
    if not overridden and not (
        "circl" in sources
        or "virustotal" in sources
    ):
        return (
            "sources must include a known-good source "
            "(circl or virustotal)"
        )

    vt = entry["virustotal"]

    if vt is not None:

        if (
            not isinstance(vt, dict)
            or set(vt) != {
                "malicious",
                "suspicious",
                "engines",
            }
            or not all(
                is_count(vt[field])
                for field in vt
            )
        ):
            return (
                "virustotal must be null or "
                "{malicious, suspicious, engines} counts"
            )

        if overridden:

            if (
                vt["engines"] == 0
                or vt["malicious"] + vt["suspicious"]
                > OVERRIDE_MAX_DETECTIONS
            ):
                return (
                    "virustotal reports "
                    f"{vt['malicious']} malicious + "
                    f"{vt['suspicious']} suspicious of "
                    f"{vt['engines']} engines; a maintainer "
                    "override covers at most "
                    f"{OVERRIDE_MAX_DETECTIONS} on an "
                    "analysed file"
                )

        elif vt["malicious"] > 0:

            return (
                f"virustotal reports {vt['malicious']} "
                "malicious detections"
            )

        limit = (
            OVERRIDE_MAX_DETECTIONS
            if overridden
            else 0
            if is_protected_name(name)
            else VT_MAX_SUSPICIOUS
        )

        if vt["suspicious"] > limit:

            return (
                f"virustotal reports {vt['suspicious']} "
                f"suspicious detections (limit {limit})"
            )

    if overridden and vt is None:
        return (
            f"{OVERRIDE_FIELD} needs the VirusTotal "
            "counts it overrides"
        )

    if overridden and "virustotal" in sources:
        return (
            "virustotal can not be a source of an "
            "overridden entry"
        )

    if "virustotal" in sources and (
        vt is None
        or vt["engines"] == 0
    ):
        return (
            "virustotal is listed as a source but has "
            "no completed analysis"
        )

    for field in (
        "first_verified",
        "last_checked",
    ):

        if (
            not isinstance(entry[field], str)
            or not ISO_UTC_RE.fullmatch(entry[field])
        ):
            return (
                f"{field} must be UTC ISO "
                "'YYYY-MM-DDTHH:MM:SSZ'"
            )

    if entry["first_verified"] > entry["last_checked"]:
        return "first_verified is after last_checked"

    return None


def read_proof(
    ref: str | None = None,
):
    """Return (entries by key or None if the file is absent, errors)."""

    path = ROOT / PROOF_REL

    if ref:

        text = git_file(
            ref,
            path,
        )

    elif path.exists():

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="strict",
            )
        except Exception as exc:
            return {}, [
                f"{PROOF_REL}: unreadable: {exc}"
            ]

    else:
        text = None

    if text is None:
        return None, []

    try:
        raw = json.loads(
            text
        )
    except ValueError as exc:
        return {}, [
            f"{PROOF_REL}: invalid JSON: {exc}"
        ]

    if (
        not isinstance(raw, dict)
        or raw.get("schema") != PROOF_SCHEMA
        or not isinstance(
            raw.get("entries"),
            list,
        )
    ):
        return {}, [
            f"{PROOF_REL}: expected "
            '{"schema": 1, "entries": [...]}'
        ]

    errors = []

    entries = {}

    order = []

    overrides = load_overrides(
        ref
    )[0]

    for index, entry in enumerate(
        raw["entries"],
        1,
    ):

        problem = proof_entry_problem(
            entry,
            overrides,
        )

        if problem:

            label = (
                f" ({entry.get('name')}|{entry.get('sha256')})"
                if isinstance(entry, dict)
                and isinstance(entry.get("name"), str)
                and isinstance(entry.get("sha256"), str)
                else ""
            )

            errors.append(
                f"{PROOF_REL}: entry {index}{label}: "
                f"{problem}"
            )

            continue

        key = proof_key(
            entry["name"],
            entry["sha256"],
        )

        order.append(
            key
        )

        if key in entries:

            errors.append(
                f"{PROOF_REL}: entry {index}: "
                f"duplicate proof for {key!r}"
            )

            continue

        entries[key] = entry

    if order != sorted(order):

        errors.append(
            f"{PROOF_REL}: entries must be sorted by "
            "name|sha256 (regenerate the file)"
        )

    return entries, errors


def short_list(
    values,
    limit: int = 10,
) -> str:

    values = list(values)

    return ", ".join(
        values[:limit]
    ) + (
        f" ... (+{len(values) - limit} more)"
        if len(values) > limit
        else ""
    )


def check_proof_sync(
    data: dict,
    pinned_lines: set,
    ref: str | None = None,
):
    """Every production whitelist line has exactly one proof."""

    entries, errors = read_proof(
        ref
    )

    data["errors"].extend(
        errors
    )

    if entries is None:

        if pinned_lines:

            data["errors"].append(
                f"{PROOF_REL}: file is missing; every "
                f"{GLOBAL_WHITELIST_PATH} line needs a "
                f"proof entry ({len(pinned_lines)} lines)"
            )

        return

    missing = sorted(
        pinned_lines - set(entries)
    )

    stale = sorted(
        set(entries) - pinned_lines
    )

    if missing:

        data["errors"].append(
            f"{PROOF_REL}: no proof for {len(missing)} "
            f"{GLOBAL_WHITELIST_PATH} line(s) (only the "
            "promotion job adds production whitelist "
            f"lines): {short_list(missing)}"
        )

    if stale:

        data["errors"].append(
            f"{PROOF_REL}: {len(stale)} proof entr"
            f"{'y has' if len(stale) == 1 else 'ies have'} "
            f"no line in {GLOBAL_WHITELIST_PATH}: "
            f"{short_list(stale)}"
        )


# ============================================================
# MAINTAINER OVERRIDES (maintainer_overrides.txt)
#
#     <sha256>|<name>|<reason>
#
# A known false positive: the hash is accepted in the whitelist
# despite up to OVERRIDE_MAX_DETECTIONS VirusTotal verdicts, but
# only as "<name>|<sha256>" with exactly this name. Nothing else
# is relaxed (MalwareBazaar, CIRCL KnownMalicious, MetaDefender,
# VirusTotal "not found" / "no analysis", protected / high-risk
# names, structure). Reputation decisions read the file from the
# trusted checkout (main), so an override has to be merged (by
# the owner / an admin) before a staging run can use it.
# ============================================================

def parse_overrides(
    text: str | None,
):
    """Return ({sha256: {"name", "reason", "line"}}, errors)."""

    entries = {}

    errors = []

    for number, raw in enumerate(
        (text or "").splitlines(),
        1,
    ):

        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        where = f"{OVERRIDES_REL}:{number}"

        parts = line.split(
            NAME_SHA256_SEPARATOR
        )

        if len(parts) != 3:

            errors.append(
                f"{where}: expected 'sha256|name|reason' "
                "(exactly two '|')"
            )

            continue

        digest, name, reason = (
            part.strip()
            for part in parts
        )

        digest = digest.lower()

        name = name.lower()

        if not re.fullmatch(
            r"[0-9a-f]{64}",
            digest,
        ):

            errors.append(
                f"{where}: invalid sha256 {digest!r}"
            )

            continue

        if (
            not NAME_RE.fullmatch(name)
            or classify(name)[0] != "name"
            or any(
                token in name
                for token in FORBIDDEN_SUBSTRINGS
            )
        ):

            errors.append(
                f"{where}: invalid name {name!r}"
            )

            continue

        if (
            is_protected_name(name)
            or name in SUSPICIOUS_WL_NAMES
        ):

            errors.append(
                f"{where}: protected / high-risk name "
                f"{name!r} can never be overridden"
            )

            continue

        if not OVERRIDE_REASON_RE.fullmatch(
            reason
        ):

            errors.append(
                f"{where}: reason must be 3-200 characters "
                "of plain text (letters, digits, "
                "space . , : ; ( ) / + _ ' # & = -)"
            )

            continue

        if digest in entries:

            errors.append(
                f"{where}: duplicate override for {digest} "
                f"(also line {entries[digest]['line']})"
            )

            continue

        entries[digest] = {
            "name": name,
            "reason": reason,
            "line": number,
        }

    return entries, errors


def load_overrides(
    ref: str | None = None,
):
    """Overrides at a git ref, or in the checkout (ref None)."""

    path = ROOT / OVERRIDES_REL

    if ref:

        text = git_file(
            ref,
            path,
        )

    elif path.exists():

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="strict",
            )
        except Exception as exc:
            return {}, [
                f"{OVERRIDES_REL}: unreadable: {exc}"
            ]

    else:
        text = None

    return parse_overrides(
        text
    )


def override_for(
    sha256: str,
    name: str,
    overrides: dict | None = None,
):
    """The override for exactly this name|sha256, else None."""

    if overrides is None:
        overrides = load_overrides()[0]

    entry = overrides.get(
        str(sha256).lower()
    )

    if (
        entry
        and entry["name"] == str(name).lower()
        and not is_protected_name(entry["name"])
        and entry["name"] not in SUSPICIOUS_WL_NAMES
    ):
        return entry

    return None


def override_applies(
    key_id: str,
    data: dict,
):
    """The trusted override for a whitelist hash of this run.

    Applies only if EVERY whitelist entry with this hash is
    "<override name>|<sha256>" (a bare hash or another name
    never inherits it).
    """

    overrides = load_overrides()[0]

    entry = overrides.get(
        key_id
    )

    if not entry:
        return None

    names = []

    for item in data.get(
        "entries",
        [],
    ):

        if (
            item.get("feed_type") != "whitelist"
            or reputation_indicator(item) != key_id
        ):
            continue

        pinned = (
            split_name_sha256(
                str(item.get("normalized", ""))
            )
            if item.get("kind") == "name_sha256"
            else None
        )

        names.append(
            pinned[0] if pinned else None
        )

    if not names or any(
        override_for(key_id, name, overrides) is None
        for name in names
    ):
        return None

    return entry


def vt_override_ok(
    record: dict,
) -> bool:
    """VirusTotal analysed the file and the detections are few."""

    return (
        record.get("provider") == "virustotal"
        and record.get("status") == "found"
        and record.get("engines", 0) > 0
        and (
            record.get("malicious", 0)
            + record.get("suspicious", 0)
        ) <= OVERRIDE_MAX_DETECTIONS
    )


def override_hint(
    key_id: str,
    data: dict,
) -> str:
    """Why an existing override did not apply ("" if none)."""

    entry = load_overrides()[0].get(
        key_id
    )

    if not entry:
        return ""

    return (
        f" (maintainer override for {entry['name']!r} not "
        "applied: every whitelist line with this hash must be "
        f"'{entry['name']}|<sha256>')"
    )


def check_overrides(
    data: dict,
    ref: str | None,
    blacklist_hashes: set,
):
    """Format of maintainer_overrides.txt at ref (or checkout)."""

    overrides, errors = load_overrides(
        ref
    )

    data["errors"].extend(
        errors
    )

    for digest in sorted(
        set(overrides) & blacklist_hashes
    ):

        data["errors"].append(
            f"{OVERRIDES_REL}:{overrides[digest]['line']}: "
            f"hash {digest} is in the production blacklist"
        )


# ============================================================
# HUMAN REVIEW QUEUE (pending/needs_review.txt)
#
#     <feed-line>|<disposition>|<reason>
#
# disposition is "review" (human may later open a PR) or
# "hard_reject" (policy / known malware; kept only as a record).
# The feed-line may itself contain one "|" (name|sha256); parse
# from the right. Maintained by the promotion job; never trusted.
# ============================================================

def sanitize_review_reason(
    reason: str,
) -> str:
    """Plain-text reason safe for needs_review.txt."""

    text = " ".join(
        str(reason or "unspecified")
        .replace("|", " ")
        .split()
    )[:200].rstrip()

    if not text:
        text = "unspecified"

    if not OVERRIDE_REASON_RE.fullmatch(
        text
    ):
        # Fall back to a conservative subset.
        text = "".join(
            char
            for char in text
            if char.isalnum() or char in " .,:;()/+_'-"
        )[:200] or "unspecified"

    return text


def parse_needs_review(
    text: str | None,
):
    """Return ({normalized_value: entry}, errors)."""

    entries = {}

    errors = []

    for number, raw in enumerate(
        (text or "").splitlines(),
        1,
    ):

        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        where = f"{NEEDS_REVIEW_REL}:{number}"

        parts = line.rsplit(
            NAME_SHA256_SEPARATOR,
            2,
        )

        if len(parts) != 3:

            errors.append(
                f"{where}: expected "
                "'<feed-line>|<disposition>|<reason>'"
            )

            continue

        value, disposition, reason = (
            part.strip()
            for part in parts
        )

        disposition = disposition.lower()

        value = value.lower()

        if disposition not in REVIEW_DISPOSITIONS:

            errors.append(
                f"{where}: disposition must be "
                + " or ".join(
                    sorted(REVIEW_DISPOSITIONS)
                )
            )

            continue

        kind, normalized = classify(
            value
        )

        if kind == "name" and not NAME_RE.fullmatch(
            normalized
        ):

            errors.append(
                f"{where}: invalid feed-line {value!r}"
            )

            continue

        if kind == "name" and (
            normalized in IGNORED_NAMES
            or is_protected_name(normalized)
            and disposition != "hard_reject"
        ):
            # Protected names in the queue must be hard_reject;
            # ignored names must not appear at all.
            if normalized in IGNORED_NAMES:

                errors.append(
                    f"{where}: ignored name {normalized!r} "
                    "must not appear in the review queue"
                )

                continue

        reason = sanitize_review_reason(
            reason
        )

        if normalized in entries:

            errors.append(
                f"{where}: duplicate review entry for "
                f"{normalized!r}"
            )

            continue

        entries[normalized] = {
            "value": normalized,
            "disposition": disposition,
            "reason": reason,
            "line": number,
        }

    return entries, errors


def needs_review_text(
    entries: dict,
) -> str:
    """Canonical file contents for pending/needs_review.txt."""

    header = (
        "# AEGIS human review queue. Lines the gate could not "
        "promote.\n"
        "# Never trusted automatically. A human reviews and may "
        "open a PR.\n"
        "#\n"
        "# Format (one per line, '#' starts a comment):\n"
        "#   <feed-line>|<disposition>|<reason>\n"
        "#\n"
        "# disposition:\n"
        "#   review       - needs a human look (e.g. low VT "
        "detections that may be false positives)\n"
        "#   hard_reject  - policy / known malware; kept only "
        "for the record\n"
        "#\n"
        "# Maintained by the AEGIS promotion job. Do not add "
        "production trust from here.\n"
    )

    rows = []

    for key in sorted(
        entries
    ):

        entry = entries[key]

        rows.append(
            f"{entry['value']}|"
            f"{entry['disposition']}|"
            f"{entry['reason']}"
        )

    body = "\n".join(
        rows
    )

    return header + (
        ("\n" + body + "\n")
        if body
        else "\n"
    )


def review_disposition_for(
    verdict: dict,
) -> str:
    """review or hard_reject for a rejected / retry verdict."""

    blob = " ".join(
        verdict.get("reasons") or []
    ).lower()

    hard_markers = (
        "high-risk",
        "protected operating-system",
        "protected ",
        "malwarebazaar",
        "knownmalicious",
        "metadefender cloud: whitelist hash flagged",
        "hybrid analysis: whitelist hash verdict malicious",
    )

    if any(
        marker in blob
        for marker in hard_markers
    ):
        return "hard_reject"

    name = None

    normalized = verdict.get(
        "normalized"
    ) or verdict.get(
        "value"
    ) or ""

    pinned = split_name_sha256(
        str(normalized)
    )

    if pinned:
        name = pinned[0]

    elif classify(str(normalized))[0] == "name":
        name = str(normalized)

    if name and (
        name in SUSPICIOUS_WL_NAMES
        or is_protected_name(name)
    ):
        return "hard_reject"

    return "review"


def entry_ignored_name(
    value: str,
):
    """The IGNORED_NAMES hit for a feed value, else None."""

    pinned = split_name_sha256(
        value
    )

    if pinned and pinned[0] in IGNORED_NAMES:
        return pinned[0]

    kind, normalized = classify(
        value
    )

    if kind == "name" and normalized in IGNORED_NAMES:
        return normalized

    return None


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

    # Merge-base (three-dot) diff first: a PR that is behind
    # main (e.g. the staging inbox) must not be blamed for - or
    # credited with - main's own changes. Without a merge base
    # fall back to two-dot (fail closed: more lines checked).
    patch = None

    for spec in (
        [f"{base_sha}...{head_sha}"],
        [base_sha, head_sha],
    ):

        try:

            patch = git_output(
                "diff",
                "--unified=0",
                "--no-renames",
                *spec,
                "--",
                "pending",
                "global_whitelist.txt",
                "global_blacklist.txt",
            )

            break

        except Exception as exc:

            failure = exc

    if patch is None:

        raise SystemExit(
            f"Unable to inspect PR diff: {failure}"
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
# HYBRID ANALYSIS (Falcon Sandbox public API v2) - optional
# GET https://hybrid-analysis.com/api/v2/search/hash?hash=<hash>
# headers "api-key: <key>" and "User-Agent: Falcon Sandbox".
# 200 {"sha256s": [...], "reports": [{"verdict": ...}, ...]};
# no reports = unknown. The endpoint is documented with
# x-auth-level "restricted" (API v2.38.0), so a Restricted key
# works; no sandbox submission endpoint is ever called.
# ============================================================

HA_SEARCH_URL = "https://hybrid-analysis.com/api/v2/search/hash"

HA_USER_AGENT = "Falcon Sandbox"


def ha_lookup(
    indicator: str,
    api_key: str,
):

    url = (
        HA_SEARCH_URL
        + "?"
        + urllib.parse.urlencode(
            {
                "hash": indicator,
            }
        )
    )

    return http_json(
        urllib.request.Request(
            url,
            headers={
                "api-key": api_key,
                "accept": "application/json",
                "User-Agent": HA_USER_AGENT,
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
        "hybridanalysis": HA_MIN_INTERVAL,
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

    if (
        provider == "hybridanalysis"
        and status == "found"
    ):

        reports = record.get(
            "reports"
        )

        if (
            record.get("verdict") not in HA_VERDICT_RANK
            or not isinstance(reports, int)
            or isinstance(reports, bool)
            or reports < 0
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


def ha_verdict_of(
    value,
):
    """Normalised Hybrid Analysis verdict text, or None."""

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return HA_VERDICT_CODES.get(value)

    if not isinstance(value, str):
        return None

    text = " ".join(
        value.strip()
        .lower()
        .replace("_", " ")
        .replace("-", " ")
        .split()
    )

    aliases = {
        "nospecificthreat": "no specific threat",
        "noverdict": "no verdict",
        "no threat": "no specific threat",
    }

    text = aliases.get(
        text.replace(" ", ""),
        text,
    )

    return (
        text
        if text in HA_VERDICT_RANK
        else None
    )


def ha_record(
    key_id: str,
    status,
    body,
):

    record = {
        "provider":
            "hybridanalysis",
        "indicator":
            key_id,
    }

    error_text = (
        str(body.get("error", ""))
        if isinstance(body, dict)
        else ""
    )

    message = error_text

    try:

        parsed = json.loads(
            error_text
        ) if error_text.startswith("{") else {}

        if isinstance(parsed, dict):
            message = str(
                parsed.get("message")
                or error_text
            )

    except ValueError:
        pass

    lowered = message.lower()

    if status == 429:

        record["status"] = "rate_limited"
        record["http"] = status

    elif status in {
        401,
        403,
    }:

        # The per-key limits (requests / hour, 2 IPs per hour)
        # are quota, not a bad key: retried, never "rejected".
        if any(
            marker in lowered
            for marker in (
                "limit",
                "quota",
                "too many",
                " ip",
                "ip address",
            )
        ):
            record["status"] = "rate_limited"

        else:
            record["status"] = "auth_error"

        record["http"] = status
        record["detail"] = message[:180]

    elif status == 404:

        # Only "this hash / sample is unknown" is definitive; a
        # wrong endpoint (HTML page, bare "Not Found") is not.
        if (
            not message.lstrip().startswith("<")
            and "not found" in lowered
            and any(
                word in lowered
                for word in ("hash", "sample", "report")
            )
        ):
            record["status"] = "not_found"

        else:
            record["status"] = "error"
            record["http"] = status
            record["detail"] = message[:180]

    elif status != 200:

        record["status"] = "error"
        record["http"] = status

        if message:
            record["detail"] = message[:180]

    else:

        if isinstance(body, list):
            reports = body
            sha256s = []

        elif isinstance(body, dict) and not body.get("error"):
            reports = body.get("reports")
            sha256s = body.get("sha256s")

        else:
            reports = None
            sha256s = None

        if not isinstance(reports, list) or (
            sha256s is not None
            and not isinstance(sha256s, list)
        ):

            record["status"] = "error"
            record["detail"] = (
                message
                or "unexpected Hybrid Analysis answer"
            )[:180]

            return record

        verdicts = [
            ha_verdict_of(
                report.get("verdict")
            )
            for report in reports
            if isinstance(report, dict)
        ]

        known = [
            verdict
            for verdict in verdicts
            if verdict
        ]

        if not reports and not sha256s:

            record["status"] = "not_found"

        else:

            # Worst verdict over every report returned (latest
            # 20 submissions): one "malicious" report decides.
            record.update(
                {
                    "status":
                        "found",
                    "verdict":
                        max(
                            known,
                            key=HA_VERDICT_RANK.get,
                        )
                        if known
                        else "no verdict",
                    "reports":
                        len(reports),
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

    if provider == "hybridanalysis":
        return ha_record(key_id, status, body)

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

        override = (
            override_applies(
                key_id,
                data,
            )
            if feed_type == "whitelist"
            else None
        )

        # ------------------------------------------------
        # Maintainer override (known false positive):
        # a few detections are accepted, never more.
        # ------------------------------------------------

        if (
            override
            and (
                malicious >= 1
                or suspicious > VT_MAX_SUSPICIOUS
            )
        ):

            if vt_override_ok(record):

                data["warnings"].append(
                    "VirusTotal: whitelist hash has "
                    f"{malicious} malicious / {suspicious} "
                    f"suspicious of {record.get('engines', 0)} "
                    "engines; accepted by maintainer override "
                    f"({OVERRIDES_REL}:{override['line']} "
                    f"{override['name']!r}: "
                    f"{override['reason']}): {key_id}"
                )

            else:

                data["errors"].append(
                    "VirusTotal: whitelist hash has "
                    f"{malicious} malicious / {suspicious} "
                    "suspicious detections, more than a "
                    "maintainer override covers "
                    f"({OVERRIDE_MAX_DETECTIONS}); override "
                    f"not applied: {key_id}"
                )

        # ------------------------------------------------
        # NEVER allow known malicious hash into whitelist
        # ------------------------------------------------

        elif (
            feed_type == "whitelist"
            and malicious >= 1
        ):

            data["errors"].append(
                "VirusTotal: whitelist "
                "hash has "
                f"{malicious} malicious "
                f"detections: {key_id}"
                + override_hint(
                    key_id,
                    data,
                )
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
    # HYBRID ANALYSIS (Falcon Sandbox verdict)
    # =================================================

    elif record["provider"] == "hybridanalysis":

        verdict = record.get(
            "verdict"
        )

        reports = record.get(
            "reports",
            0,
        )

        if (
            feed_type == "whitelist"
            and verdict in HA_BLOCK_VERDICTS
        ):

            data["errors"].append(
                "Hybrid Analysis: whitelist hash verdict "
                f"malicious ({reports} report(s)): {key_id}"
            )

        elif (
            feed_type == "whitelist"
            and verdict in HA_REVIEW_VERDICTS
        ):

            data["errors"].append(
                "Hybrid Analysis: whitelist hash verdict "
                f"suspicious ({reports} report(s)); "
                f"manual review required: {key_id}"
            )

        elif (
            feed_type == "blacklist"
            and verdict in (
                HA_BLOCK_VERDICTS
                | HA_REVIEW_VERDICTS
            )
        ):

            data["warnings"].append(
                "Hybrid Analysis corroborates blacklist "
                f"hash (verdict {verdict}): {key_id}"
            )

        elif (
            feed_type == "blacklist"
            and verdict == "whitelisted"
        ):

            data["warnings"].append(
                "Hybrid Analysis lists blacklist hash as "
                "whitelisted; possible false positive - "
                f"review: {key_id}"
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
            "cap": provider_cap(provider),
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
            "cap": provider_cap(provider),
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

            if lookups >= provider_cap(provider):

                mark_unchecked(
                    provider,
                    item,
                    "per-run lookup cap reached "
                    + (
                        "(AEGIS_HA_MAX_LOOKUPS="
                        if provider == "hybridanalysis"
                        else "(AEGIS_MAX_REPUTATION_LOOKUPS="
                    )
                    + f"{provider_cap(provider)})",
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

                elif provider == "hybridanalysis":

                    status, body = ha_lookup(
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

            record["checked_at"] = int(
                time.time()
            )

            if record["status"] in CACHE_TTL:

                cache[cache_key] = dict(
                    record
                )

                # Saved after every paid-for answer, so a run
                # that is cancelled (newer push) or times out
                # keeps its progress for the next run.
                cache_save(
                    cache_path,
                    cache,
                )

                cache_dirty = False

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
            provider_cap(provider),
        "stopped":
            stopped or None,
    }


# ============================================================
# WHITELIST HASH VERIFICATION (cross-provider, fail closed)
# ============================================================

def definitive_records(
    key_id: str,
    data: dict,
) -> dict:
    """provider -> this run's definitive record for a hash."""

    definitive = {}

    for record in data.get(
        "reputation",
        [],
    ):

        if (
            record.get("indicator") == key_id
            and record.get("status") in CACHE_TTL
        ):
            definitive[
                record.get("provider")
            ] = record

    return definitive


def optional_required(
    provider: str,
    data: dict,
) -> bool:
    """An optional provider is required once its key is set."""

    return bool(
        (
            (
                data.get(
                    "reputation_runs",
                    {},
                )
                or {}
            ).get(
                provider,
            )
            or {}
        ).get(
            "configured"
        )
    )


def metadefender_required(
    data: dict,
) -> bool:

    return optional_required(
        "metadefender",
        data,
    )


def hybridanalysis_required(
    data: dict,
) -> bool:

    return optional_required(
        "hybridanalysis",
        data,
    )


def vt_counts_as_known_good(
    record: dict,
    protected: bool = False,
) -> bool:

    return (
        record.get("provider") == "virustotal"
        and record.get("status") == "found"
        and record.get("malicious", 0) == 0
        and record.get("engines", 0) > 0
        and record.get("suspicious", 0)
        <= (
            0
            if protected
            else VT_MAX_SUSPICIOUS
        )
    )


def whitelist_hash_verdict(
    key_id: str,
    kind: str,
    protected: bool,
    data: dict,
    override: dict | None = None,
):
    """None if this whitelist hash is verified known-good, else why not.

    known-good = found in CIRCL hashlookup (trust >= minimum,
    not flagged), OR found by VirusTotal with 0 malicious,
    completed analysis and suspicious within the limit (0 for
    a protected OS name pinned to the hash).

    Always required: MalwareBazaar answered (a hit is judged
    separately). VirusTotal is required when CIRCL does not
    vouch for the hash; MetaDefender when its key was
    configured.
    """

    if kind != "sha256":

        return (
            f"whitelist hash {key_id} is "
            f"{str(kind).upper()}; whitelist "
            "hash entries must be SHA-256"
        )

    definitive = definitive_records(
        key_id,
        data,
    )

    circl_ok = circl_counts_as_known_good(
        definitive.get("circl") or {}
    )

    vt_ok = vt_counts_as_known_good(
        definitive.get("virustotal") or {},
        protected,
    ) or (
        # maintainer override: few detections on an analysed
        # file (never for protected names)
        override is not None
        and not protected
        and vt_override_ok(
            definitive.get("virustotal") or {}
        )
    )

    required = {
        "malwarebazaar",
    }

    if not circl_ok:
        required.add("virustotal")

    if metadefender_required(data):
        required.add("metadefender")

    if hybridanalysis_required(data):
        required.add("hybridanalysis")

    missing = [
        PROVIDER_LABEL[provider]
        for provider in REPUTATION_PROVIDERS
        if provider in required
        and provider not in definitive
    ]

    if missing:

        return (
            f"whitelist hash {key_id} was not "
            f"checked by {', '.join(missing)}; "
            "unverified hashes are never approved"
        )

    if not (
        circl_ok
        or vt_ok
    ):

        return (
            f"whitelist hash {key_id} is unknown "
            "to every reputation provider that "
            "can vouch for it (CIRCL hashlookup, "
            "VirusTotal with 0 detections"
            + (
                " and 0 suspicious for a protected "
                "OS name"
                if protected
                else ""
            )
            + "); it cannot be trusted "
            "automatically - manual review required"
        )

    return None


def whitelist_hash_info(
    data: dict,
) -> dict:
    """indicator -> {"kind", "protected"} for whitelist entries."""

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

    return whitelist_hashes


def verify_whitelist_hashes(
    data: dict,
):
    """Every whitelist hash must be positively known-good."""

    errors = data.setdefault(
        "errors",
        [],
    )

    for key_id, info in whitelist_hash_info(
        data
    ).items():

        # Already failing with a more specific reason.
        if any(
            key_id in error
            for error in errors
        ):
            continue

        reason = whitelist_hash_verdict(
            key_id,
            info["kind"],
            info["protected"],
            data,
            override_applies(
                key_id,
                data,
            ),
        )

        if reason:
            errors.append(
                reason
            )


def verify_proofs(
    data: dict,
):
    """A proof added by this PR must not contradict this run.

    Each hash is verified again by this run anyway; this only
    catches a proof that claims a source which, in this run,
    answered definitively that it does NOT vouch for the hash.
    """

    errors = data.setdefault(
        "errors",
        [],
    )

    for key, entry in sorted(
        (
            data.get("proofs")
            or {}
        ).items()
    ):

        sha256 = entry.get("sha256")

        definitive = definitive_records(
            sha256,
            data,
        )

        protected = is_protected_name(
            str(entry.get("name", ""))
        )

        for source in entry.get(
            "sources",
            [],
        ):

            record = definitive.get(
                source
            )

            if record is None:
                continue

            if source == "circl":
                confirmed = circl_counts_as_known_good(record)

            elif source == "virustotal":
                confirmed = vt_counts_as_known_good(
                    record,
                    protected,
                )

            elif source == "malwarebazaar":
                confirmed = record.get("status") == "not_found"

            elif source == "hybridanalysis":
                confirmed = not (
                    record.get("status") == "found"
                    and record.get("verdict") in (
                        HA_BLOCK_VERDICTS
                        | HA_REVIEW_VERDICTS
                    )
                )

            else:
                confirmed = not (
                    record.get("status") == "found"
                    and (
                        record.get("result") in MD_BAD_RESULTS
                        or record.get("detected", 0) >= 1
                    )
                )

            if not confirmed:

                errors.append(
                    f"{PROOF_REL}: proof for {key!r} lists "
                    f"{PROVIDER_LABEL[source]} as a source, "
                    "but this run's answer does not "
                    "confirm it"
                )


# ============================================================
# ADDITION POLICY (shared by the gate and the promotion)
# ============================================================

def addition_policy(
    path: str,
    feed_type: str,
    kind: str,
    normalized: str,
    value: str,
    base_global_names=frozenset(),
):
    """("error" | "needs_hash", message) for a new line, or None.

    Production whitelist: only "name|sha256" (a name-only line
    already in production at the base is not new trust).
    Pending whitelist: a name-only line is a NEEDS HASH
    candidate (accepted, never trusted).
    """

    if feed_type != "whitelist":
        return None

    if path == GLOBAL_WHITELIST_PATH:

        if kind == "name":

            if normalized in base_global_names:
                return None

            return (
                "error",
                f"PR addition {path}: name-only "
                "entry cannot be added to the "
                "production whitelist; pin it "
                "as 'name|<sha256>' or submit it "
                "to pending/community_whitelist_"
                f"candidates.txt: {value!r}",
            )

        if kind in HASH_KINDS:

            return (
                "error",
                f"PR addition {path}: bare hash cannot "
                "be added to the production whitelist; "
                "submit it as 'name|<sha256>': "
                f"{value!r}",
            )

        return None

    if kind == "name":

        return (
            "needs_hash",
            f"PR addition {path}: name-only "
            "candidate accepted as NEEDS HASH "
            "(not trusted until submitted as "
            f"'name|<sha256>'): {value!r}",
        )

    return None


def feed_values(
    ref: str | None,
) -> dict:
    """relative feed path -> set of normalized values at ref."""

    return {
        path.relative_to(ROOT).as_posix(): {
            classify(value)[1]
            for _, value in feed_lines(
                path,
                ref,
            )
        }
        for path in FEEDS.values()
    }


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

    # Errors so far come from the whole-feed check of the head.
    data["feed_check_errors"] = len(
        data["errors"]
    )

    # --------------------------------------------------------
    # Inspect PR additions
    # --------------------------------------------------------

    additions = changed_additions(
        args.base_sha,
        args.head_sha,
    )

    # Lines already in the same feed file at the base (main)
    # are not new: no lookups are spent on them. This is what
    # keeps the staging inbox cheap once its good lines have
    # been promoted and merged.
    base_values = feed_values(
        args.base_sha
    ) if args.base_sha else {}

    new_additions = [
        (path, feed_type, value)
        for path, feed_type, value in additions
        if classify(value)[1]
        not in base_values.get(path, set())
    ]

    data["already_in_base"] = (
        len(additions)
        - len(new_additions)
    )

    additions = new_additions

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

    all_changed = changed_paths(
        args.base_sha,
        args.head_sha,
    )

    data["proof_changed"] = (
        PROOF_REL in all_changed
    )

    non_feed = [
        path
        for path in all_changed
        if path not in FEED_PATHS
    ]

    data[
        "non_feed_changes"
    ] = non_feed

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

    trusted_author = (
        association in TRUSTED_ASSOCIATIONS
        or permission in TRUSTED_PERMISSIONS
    )

    if non_feed:

        listed = ", ".join(
            non_feed[:20]
        ) + (
            " ..."
            if len(non_feed) > 20
            else ""
        )

        if trusted_author:

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
    # maintainer_overrides.txt: the owner / admins only. It
    # takes effect after the merge (the gate reads main's copy).
    # --------------------------------------------------------

    if OVERRIDES_REL in non_feed:

        if (
            association in OVERRIDE_ASSOCIATIONS
            or permission in OVERRIDE_PERMISSIONS
        ):

            data["warnings"].append(
                f"PR changes {OVERRIDES_REL} (maintainer "
                "overrides for VirusTotal false positives); "
                "review every line - it applies to staging "
                "runs after this PR is merged"
            )

        else:

            data["errors"].append(
                f"PR changes {OVERRIDES_REL}; only the "
                "repository owner / admins may do that "
                f"(author: {association or 'UNKNOWN'}, "
                f"permission: {permission or 'unknown'})"
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

    # Indices of errors raised for ONE added line (staging mode).
    line_error_ids = set()

    for (
        path,
        feed_type,
        value,
    ) in additions:

        errors_before = len(
            data["errors"]
        )

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
        # Whitelist additions without a pinned hash:
        #   pending name-only   -> accepted as "needs hash"
        #                          (warning + report list)
        #   global name / hash  -> ERROR: production trust
        #                          needs "name|sha256"
        # ----------------------------------------------------

        policy = addition_policy(
            path,
            feed_type,
            kind,
            normalized,
            value,
            base_global_names,
        ) if valid else None

        if policy and policy[0] == "error":

            data["errors"].append(
                policy[1]
            )

        elif policy:

            data["needs_hash"].append(
                value
            )

            data["warnings"].append(
                policy[1]
            )

        line_error_ids.update(
            range(
                errors_before,
                len(data["errors"]),
            )
        )

    # --------------------------------------------------------
    # Proofs: entries for this PR's production whitelist
    # additions are checked against this run's answers in
    # --finalize; proofs of lines the PR does NOT add must not
    # be rewritten (except by owners / maintainers).
    # --------------------------------------------------------

    added_global = {
        item["normalized"]
        for item in data["entries"]
        if item["path"] == GLOBAL_WHITELIST_PATH
        and item["kind"] == "name_sha256"
    }

    if args.base_sha:

        head_proof = read_proof(
            args.head_sha
        )[0] or {}

        base_proof = read_proof(
            args.base_sha
        )[0] or {}

        data["proofs"] = {
            key: entry
            for key, entry in head_proof.items()
            if key in added_global
        }

        rewritten = sorted(
            key
            for key, entry in head_proof.items()
            if key in base_proof
            and key not in added_global
            and entry != base_proof[key]
        )

        if rewritten:

            message = (
                f"PR rewrites {len(rewritten)} existing "
                f"{PROOF_REL} entr"
                f"{'y' if len(rewritten) == 1 else 'ies'}: "
                f"{short_list(rewritten)}"
            )

            if trusted_author:

                data["warnings"].append(
                    message
                    + "; review manually"
                )

            else:

                data["errors"].append(
                    message
                    + "; only the promotion job or "
                    "maintainers may do that"
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
    # Staging inbox: split per-line from structural errors
    # --------------------------------------------------------

    if getattr(args, "staging_inbox", False):

        data["staging_mode"] = True

        data["structural_errors"] = staging_structural_errors(
            data,
            line_error_ids,
        )

    # --------------------------------------------------------
    # Initial decision
    # --------------------------------------------------------

    data["decision"] = (
        "PASS"
        if not data["errors"]
        else "FAIL"
    )

    # Errors up to here are about the PR's files as a whole
    # or single lines; later ones come from reputation. The
    # promotion uses this split to judge lines one by one.
    data["validate_errors"] = len(
        data["errors"]
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
                "already_in_base":
                    data.get("already_in_base", 0),
            },
            indent=2,
        )
    )

    return data


# ============================================================
# STAGING INBOX MODE
#
# A staging PR (Sentinel upload, draft, never merged) is only a
# data inbox: the promotion job judges each of its lines on its
# own and routes it to the promotion PR (passed every check),
# pending/needs_review.txt (rejected / not verified yet) or drops
# it (IGNORED_NAMES). A problem with ONE line is therefore handled
# and must not turn the staging check red. Red is kept for
# problems a human has to act on.
# ============================================================

# Reputation-phase errors that need a human (bad / missing API
# key): every line would otherwise wait forever.
STAGING_ACTION_MARKERS = (
    "rejected the API key",
    "is not configured",
)


def staging_structural_errors(
    data: dict,
    line_error_ids: set,
) -> list:
    """Validate-phase errors a human must act on (staging inbox).

    NOT structural (handled by the promotion job):
      - whole-feed checks of the staging head (errors[:feed_check_errors]):
        the head is an old copy of main plus Sentinel's lines and is
        never merged; the promotion rebuilds the feed from the
        current main, re-checks the COMPLETE result and demotes a
        line that breaks it to needs_review (or fails loudly);
      - errors raised for one added line (line_error_ids).
    Structural: everything else from the validate phase (too many
    lines, changes outside the feed by non-members, maintainer
    overrides, rewritten proofs) and any change of the proof file
    (only the promotion job writes verified_whitelist.json).
    """

    feed_check = int(
        data.get("feed_check_errors", 0) or 0
    )

    structural = [
        error
        for index, error in enumerate(
            data.get("errors") or []
        )
        if index >= feed_check
        and index not in line_error_ids
    ]

    if data.get("proof_changed"):

        structural.append(
            f"staging PR changes {PROOF_REL}; only the "
            "promotion job writes proof entries"
        )

    return structural


def staging_finalize(
    data: dict,
):
    """Staging inbox decision: FAIL only on structural errors."""

    later = (data.get("errors") or [])[
        int(data.get("validate_errors", 0) or 0):
    ]

    structural = list(
        data.get("structural_errors") or []
    ) + [
        error
        for error in later
        # a proof the PR ships that contradicts this run
        if error.startswith(f"{PROOF_REL}:")
        or any(
            marker in error
            for marker in STAGING_ACTION_MARKERS
        )
    ]

    structural = list(
        dict.fromkeys(
            structural
        )
    )

    data["structural_errors"] = structural

    data["decision"] = (
        "FAIL"
        if structural
        else "PASS"
    )


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

    # Proofs added by the PR must not contradict this run.
    verify_proofs(
        data
    )

    data["decision"] = (
        "PASS"
        if not data.get("errors")
        else "FAIL"
    )

    if data.get("staging_mode"):

        staging_finalize(
            data
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

    if data.get("staging_mode"):

        print(
            "AEGIS SECURITY GATE: PASS (staging inbox - every "
            "line is judged one by one by the promotion job; "
            f"{len(data.get('errors') or [])} per-line finding(s) "
            "are handled there, none is structural)"
        )

        return

    print(
        "AEGIS SECURITY GATE: PASS"
    )


# ============================================================
# PROMOTION (--promote)
#
# Runs in the trusted "promote" job after the gate finished on
# a staging PR. Input: that run's gate report (produced by the
# trusted script from main; PR lines are data only). Output:
# main's feed files + verified_whitelist.json rewritten in the
# working tree (a checkout of main) with ONLY the lines that
# passed every check, plus a plan / PR body / staging comment.
# Nothing here executes or checks out PR code.
# ============================================================

PENDING_WHITELIST_PATH = (
    FEEDS["pending_whitelist"]
    .relative_to(ROOT)
    .as_posix()
)

# Reasons that only mean "not checked (yet)": the line is
# retried on the next staging run (cached answers are reused).
RETRY_MARKERS = (
    "check incomplete",
    "was not checked by",
    "is not configured",
)

# Rows shown per section in the staging comment / PR body
# (GitHub comments are limited to 65536 characters).
REPORT_ROWS = 150


def feed_type_of(
    path: str,
):

    for key, feed_path in FEEDS.items():

        if feed_path.relative_to(ROOT).as_posix() == path:

            return (
                "whitelist"
                if "whitelist" in key
                else "blacklist"
            )

    return None


def strip_where(
    message: str,
) -> str:

    return (
        message[len("line: "):]
        if message.startswith("line: ")
        else message
    )


def evaluate_entry(
    item: dict,
    data: dict,
) -> dict:
    """Verdict for ONE staging line, independent of all others.

    status: promote | needs_hash | retry | rejected | ignored
    """

    path = str(
        item.get("path", "")
    )

    value = str(
        item.get("value", "")
    )

    feed_type = feed_type_of(
        path
    )

    verdict = {
        "path": path,
        "target": path,
        "feed_type": feed_type,
        "value": value,
        "kind": None,
        "normalized": None,
        "status": "rejected",
        "reasons": [],
    }

    if (
        feed_type is None
        or feed_type != item.get("feed_type")
    ):

        verdict["reasons"].append(
            f"not a community feed line: {path!r}"
        )

        return verdict

    ignored = entry_ignored_name(
        value.lower().strip()
    )

    if ignored:

        kind, normalized = classify(
            value.lower().strip()
        )

        verdict.update(
            kind=kind,
            normalized=normalized,
            status="ignored",
            reasons=[
                f"ignored permanently "
                f"({ignored!r} is an AEGIS / Sentinel "
                "internal name and is never accepted)"
            ],
        )

        return verdict

    # --------------------------------------------------------
    # Structure (same rules as the gate), on a scratch result
    # so other lines' problems never leak into this verdict.
    # --------------------------------------------------------

    scratch = {
        "errors": [],
        "warnings": [],
    }

    valid = validate_entry(
        value,
        feed_type,
        "line",
        scratch,
    )

    if not valid or scratch["errors"]:

        verdict["reasons"] = [
            strip_where(error)
            for error in scratch["errors"]
        ] or ["invalid entry"]

        return verdict

    kind, normalized = classify(
        value
    )

    verdict.update(
        kind=kind,
        normalized=normalized,
        status="promote",
    )

    policy = addition_policy(
        path,
        feed_type,
        kind,
        normalized,
        value,
    )

    if policy and policy[0] == "error":

        # A name-only line sent to the production whitelist
        # is routed to the pending candidates as NEEDS HASH.
        if (
            kind == "name"
            and path == GLOBAL_WHITELIST_PATH
        ):

            verdict.update(
                target=PENDING_WHITELIST_PATH,
                status="needs_hash",
            )

        else:

            verdict.update(
                status="rejected",
                reasons=[policy[1]],
            )

            return verdict

    elif policy:

        verdict["status"] = "needs_hash"

    # --------------------------------------------------------
    # Reputation (hash lines only)
    # --------------------------------------------------------

    indicator = value_indicator(
        value
    )

    if not indicator:
        return verdict

    later = data.get(
        "errors",
        [],
    )[int(data.get("validate_errors", 0) or 0):]

    reasons = [
        error
        for error in later
        if indicator in error
        # recomputed below, per line (protected names)
        and not error.startswith("whitelist hash ")
        and not error.startswith(PROOF_REL)
    ]

    if feed_type == "whitelist":

        protected = (
            kind == "name_sha256"
            and is_protected_name(
                split_name_sha256(normalized)[0]
            )
        )

        override = override_applies(
            indicator,
            data,
        )

        reason = whitelist_hash_verdict(
            indicator,
            "sha256"
            if kind == "name_sha256"
            else kind,
            protected,
            data,
            override,
        )

        if reason:
            reasons.append(
                reason
            )

        elif override and not vt_counts_as_known_good(
            definitive_records(indicator, data).get(
                "virustotal"
            ) or {},
            protected,
        ) and not circl_counts_as_known_good(
            definitive_records(indicator, data).get(
                "circl"
            ) or {}
        ):
            verdict["override"] = override["reason"]

    reasons = list(
        dict.fromkeys(
            reasons
        )
    )

    if reasons:

        verdict["reasons"] = reasons

        verdict["status"] = (
            "retry"
            if all(
                any(
                    marker in reason
                    for marker in RETRY_MARKERS
                )
                for reason in reasons
            )
            else "rejected"
        )

    return verdict


def build_proof_entry(
    name: str,
    sha256: str,
    data: dict,
    now_iso: str,
) -> dict:
    """Proof for a line promoted from this run's answers.

    sources = providers that checked the hash and passed it:
    circl / virustotal = known-good, metadefender /
    malwarebazaar = no detection.
    """

    definitive = definitive_records(
        sha256,
        data,
    )

    protected = is_protected_name(
        name
    )

    sources = []

    circl = definitive.get("circl")

    if circl and circl_counts_as_known_good(circl):
        sources.append("circl")

    vt = definitive.get("virustotal")

    vt_ok = bool(
        vt
        and vt_counts_as_known_good(vt, protected)
    )

    if vt_ok:
        sources.append("virustotal")

    # Recorded only when the override is what let it in.
    override = (
        override_for(
            sha256,
            name,
        )
        if (
            vt
            and not vt_ok
            and "circl" not in sources
            and not protected
            and vt_override_ok(vt)
        )
        else None
    )

    md = definitive.get("metadefender")

    if md and not (
        md.get("status") == "found"
        and (
            md.get("result") in MD_BAD_RESULTS
            or md.get("detected", 0) >= 1
        )
    ):
        sources.append("metadefender")

    ha = definitive.get("hybridanalysis")

    ha_verdict = (
        (
            ha.get("verdict")
            if ha.get("status") == "found"
            else "not found"
        )
        if ha
        else None
    )

    if ha_verdict in HA_PROOF_VERDICTS:
        sources.append("hybridanalysis")

    mb = definitive.get("malwarebazaar")

    if mb and mb.get("status") == "not_found":
        sources.append("malwarebazaar")

    checked = [
        record.get("checked_at")
        for record in definitive.values()
        if is_count(record.get("checked_at"))
    ]

    last_checked = (
        utc_iso(max(checked))
        if checked
        else now_iso
    )

    entry = {
        "name": name,
        "sha256": sha256,
        "sources": sources,
        "virustotal": (
            {
                "malicious": vt.get("malicious", 0),
                "suspicious": vt.get("suspicious", 0),
                "engines": vt.get("engines", 0),
            }
            if vt and vt.get("status") == "found"
            else None
        ),
        "first_verified": last_checked,
        "last_checked": last_checked,
    }

    if override:
        entry[OVERRIDE_FIELD] = {
            "reason": override["reason"],
        }

    if ha_verdict in HA_PROOF_VERDICTS:
        entry[HA_PROOF_FIELD] = {
            "verdict": ha_verdict,
        }

    return entry


def proof_text(
    entries: dict,
) -> str:

    return json.dumps(
        {
            "schema": PROOF_SCHEMA,
            "entries": [
                {
                    field: entries[key][field]
                    for field in (
                        *PROOF_FIELDS,
                        HA_PROOF_FIELD,
                        OVERRIDE_FIELD,
                    )
                    if field in entries[key]
                }
                for key in sorted(entries)
            ],
        },
        indent=2,
    ) + "\n"


def rewrite_feed(
    path: Path,
    original: str | None,
    additions,
    removals,
):
    """Main's file minus removals plus additions (appended)."""

    kept = []

    for raw in (original or "").splitlines():

        value = raw.strip().lower()

        if (
            value
            and not value.startswith("#")
            and classify(value)[1] in removals
        ):
            continue

        kept.append(
            raw
        )

    while kept and not kept[-1].strip():
        kept.pop()

    kept.extend(
        sorted(additions)
    )

    if original is None and not kept:
        return

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        "\n".join(kept) + ("\n" if kept else ""),
        encoding="utf-8",
    )


def review_key(
    value: str,
):
    """Safe normalized feed value for the review queue, else None."""

    value = str(
        value or ""
    ).strip().lower()

    if (
        not value
        or len(value) > MAX_LINE
        or any(
            char in value
            for char in FORBIDDEN_CHARS
        )
    ):
        return None

    kind, normalized = classify(
        value
    )

    if kind == "name":

        if not NAME_RE.fullmatch(normalized):
            return None

        if any(
            token in normalized
            for token in FORBIDDEN_SUBSTRINGS
        ):
            return None

    elif kind == "name_sha256":

        name = split_name_sha256(
            normalized
        )[0]

        if (
            not NAME_RE.fullmatch(name)
            or any(
                token in name
                for token in FORBIDDEN_SUBSTRINGS
            )
        ):
            return None

    return normalized


def update_needs_review(
    verdicts: list,
    carry_ref: str | None,
    paths: dict,
    data: dict | None = None,
) -> dict:
    """Merge this run's rejected / retry lines into the queue.

    - dedupe by normalized feed value (latest reason wins)
    - drop entries that are now in a production / pending feed
      (resolved) or ignored
    - never write a line that is in global_whitelist.txt
    """

    queue, _errors = parse_needs_review(
        NEEDS_REVIEW_PATH.read_text(encoding="utf-8")
        if NEEDS_REVIEW_PATH.exists()
        else None
    )

    if carry_ref:

        carried, _errors = parse_needs_review(
            git_file(
                carry_ref,
                NEEDS_REVIEW_PATH,
            )
        )

        for key, entry in carried.items():
            queue.setdefault(key, entry)

    added = 0

    updated = 0

    for verdict in verdicts:

        if verdict["status"] not in {
            "rejected",
            "retry",
        }:
            continue

        key = review_key(
            verdict.get("normalized")
            or verdict.get("value")
        )

        if not key or entry_ignored_name(key):
            continue

        indicator = value_indicator(
            key
        )

        reasons = []

        for reason in verdict.get("reasons") or []:

            text = str(reason)

            if indicator:
                text = text.replace(
                    NAME_SHA256_SEPARATOR + indicator,
                    "",
                ).replace(
                    indicator,
                    "(hash)",
                )

            reasons.append(
                text
            )

        prefix = (
            "not verified yet: "
            if verdict["status"] == "retry"
            else ""
        )

        vt = (
            definitive_records(
                indicator,
                data,
            ).get("virustotal")
            if indicator and data
            else None
        )

        if vt and vt.get("status") == "found":

            prefix += (
                f"VT {vt.get('malicious', 0)}/"
                f"{vt.get('engines', 0)} malicious"
                + (
                    f", {vt.get('suspicious', 0)} suspicious"
                    if vt.get("suspicious")
                    else ""
                )
                + "; "
            )

        entry = {
            "value": key,
            "disposition": review_disposition_for(
                verdict
            ),
            "reason": sanitize_review_reason(
                prefix + "; ".join(reasons)
            ),
            "line": 0,
        }

        if key in queue:

            if (
                queue[key]["disposition"],
                queue[key]["reason"],
            ) != (
                entry["disposition"],
                entry["reason"],
            ):
                updated += 1

        else:
            added += 1

        queue[key] = entry

    # Resolved: the value (or its hash) is now in a feed file.
    in_feeds = set()

    feed_hashes = set()

    for rel, path in paths.items():

        for _, value in feed_lines(
            path
        ):

            normalized = classify(
                value
            )[1]

            in_feeds.add(
                normalized
            )

            if rel == GLOBAL_WHITELIST_PATH:

                digest = value_indicator(
                    normalized
                )

                if digest:
                    feed_hashes.add(
                        digest
                    )

    removed = 0

    for key in list(queue):

        digest = value_indicator(
            key
        )

        if (
            key in in_feeds
            or (digest and digest in feed_hashes)
            or entry_ignored_name(key)
        ):
            del queue[key]
            removed += 1

    if queue or NEEDS_REVIEW_PATH.exists():

        NEEDS_REVIEW_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        NEEDS_REVIEW_PATH.write_text(
            needs_review_text(queue),
            encoding="utf-8",
        )

    return {
        "entries": len(queue),
        "added": added,
        "updated": updated,
        "resolved": removed,
        "hard_reject": sum(
            1
            for entry in queue.values()
            if entry["disposition"] == "hard_reject"
        ),
    }


def ha_summary(
    verdict: dict,
    data: dict,
    carried_proof: dict | None = None,
) -> str:
    """Hybrid Analysis result of one line for the report tables."""

    normalized = str(
        verdict.get("normalized")
        or verdict.get("value")
        or ""
    )

    indicator = value_indicator(
        normalized
    )

    if not indicator:
        return "-"

    if verdict.get("status") == "carried":

        entry = (carried_proof or {}).get(
            normalized
        ) or {}

        return (
            entry.get(HA_PROOF_FIELD) or {}
        ).get(
            "verdict",
            "earlier run",
        )

    if not hybridanalysis_required(data):
        return "not configured"

    record = definitive_records(
        indicator,
        data,
    ).get(
        "hybridanalysis"
    )

    if not record:
        return "not checked yet"

    if record.get("status") == "not_found":
        return "not found"

    return str(
        record.get("verdict")
        or "no verdict"
    )


def build_promotion(
    data: dict,
    carry_ref: str | None = None,
    now: float | None = None,
) -> dict:
    """Rewrite main's working tree with the verified lines."""

    now_iso = utc_iso(
        now
    )

    paths = {
        path.relative_to(ROOT).as_posix(): path
        for path in FEEDS.values()
    }

    originals = {
        rel: (
            path.read_text(encoding="utf-8")
            if path.exists()
            else None
        )
        for rel, path in paths.items()
    }

    proof_path = ROOT / PROOF_REL

    proof_original = (
        proof_path.read_text(encoding="utf-8")
        if proof_path.exists()
        else None
    )

    review_original = (
        NEEDS_REVIEW_PATH.read_text(encoding="utf-8")
        if NEEDS_REVIEW_PATH.exists()
        else None
    )

    main_values = feed_values(
        None
    )

    main_proof = read_proof(
        None
    )[0] or {}

    baseline = result()

    collect_all(
        baseline
    )

    baseline_errors = set(
        baseline["errors"]
    )

    # --------------------------------------------------------
    # 1. Per-line verdicts for the staging PR's new lines
    # --------------------------------------------------------

    verdicts = []

    seen = set()

    for item in data.get(
        "entries",
        [],
    ):

        verdict = evaluate_entry(
            item,
            data,
        )

        marker = (
            verdict["target"],
            verdict["normalized"] or verdict["value"],
        )

        if marker in seen:
            continue

        seen.add(
            marker
        )

        verdicts.append(
            verdict
        )

    hard_rejected = {
        verdict["normalized"] or verdict["value"]
        for verdict in verdicts
        if verdict["status"] == "rejected"
    }

    # --------------------------------------------------------
    # 2. Carry over lines already waiting in the open
    #    promotion PR (verified by an earlier run), unless this
    #    run rejected them.
    # --------------------------------------------------------

    carried_proof = {}

    if carry_ref:

        carried_proof = read_proof(
            carry_ref
        )[0] or {}

        for rel, path in paths.items():

            feed_type = feed_type_of(
                rel
            )

            for _, value in feed_lines(
                path,
                carry_ref,
            ):

                kind, normalized = classify(
                    value
                )

                if (
                    normalized in main_values[rel]
                    or (rel, normalized) in seen
                ):
                    continue

                if normalized in hard_rejected:
                    continue

                if entry_ignored_name(normalized):
                    continue

                scratch = {
                    "errors": [],
                    "warnings": [],
                }

                if (
                    not validate_entry(
                        value,
                        feed_type,
                        "line",
                        scratch,
                    )
                    or scratch["errors"]
                ):
                    continue

                policy = addition_policy(
                    rel,
                    feed_type,
                    kind,
                    normalized,
                    value,
                )

                if policy and policy[0] == "error":
                    continue

                if (
                    rel == GLOBAL_WHITELIST_PATH
                    and normalized not in carried_proof
                ):
                    continue

                seen.add(
                    (rel, normalized)
                )

                verdicts.append(
                    {
                        "path": rel,
                        "target": rel,
                        "feed_type": feed_type,
                        "value": value,
                        "kind": kind,
                        "normalized": normalized,
                        "status": "carried",
                        "reasons": [],
                    }
                )

    # --------------------------------------------------------
    # 3. Already on main / conflicts
    # --------------------------------------------------------

    def target_all(
        feed_type,
    ):

        return set().union(
            *(
                values
                for rel, values in main_values.items()
                if feed_type_of(rel) == feed_type
            )
        )

    main_all = {
        "whitelist": target_all("whitelist"),
        "blacklist": target_all("blacklist"),
    }

    main_global_hashes = {
        feed_type: {
            value_indicator(value)
            for value in main_values[
                paths_key
            ]
        } - {None}
        for feed_type, paths_key in (
            ("whitelist", GLOBAL_WHITELIST_PATH),
            ("blacklist", "global_blacklist.txt"),
        )
    }

    pinned_names = {
        split_name_sha256(value)[0]
        for value in main_values[GLOBAL_WHITELIST_PATH]
        if split_name_sha256(value)
    } | {
        split_name_sha256(verdict["normalized"])[0]
        for verdict in verdicts
        if verdict["status"] in {"promote", "carried"}
        and verdict["target"] == GLOBAL_WHITELIST_PATH
        and verdict["kind"] == "name_sha256"
    }

    active = {
        "promote",
        "needs_hash",
        "carried",
    }

    for verdict in verdicts:

        if verdict["status"] not in active:
            continue

        normalized = verdict["normalized"]

        target = verdict["target"]

        if target == GLOBAL_WHITELIST_PATH:
            on_main = normalized in main_values[target]

        else:
            on_main = normalized in main_all[
                verdict["feed_type"]
            ]

        if on_main:

            verdict["status"] = "already_on_main"

        elif (
            verdict["kind"] == "name"
            and verdict["feed_type"] == "whitelist"
            and normalized in pinned_names
        ):

            verdict["status"] = "already_on_main"

            verdict["reasons"] = [
                "already pinned to a verified "
                "SHA-256 in the production whitelist"
            ]

    # The same hash proposed for BOTH lists, or against the
    # other production list on main: never promoted.
    proposed = {
        "whitelist": set(),
        "blacklist": set(),
    }

    for verdict in verdicts:

        if verdict["status"] in active:

            indicator = value_indicator(
                verdict["normalized"]
            )

            if indicator:
                proposed[verdict["feed_type"]].add(
                    indicator
                )

    for verdict in verdicts:

        if verdict["status"] not in active:
            continue

        indicator = value_indicator(
            verdict["normalized"]
        )

        if not indicator:
            continue

        other = (
            "blacklist"
            if verdict["feed_type"] == "whitelist"
            else "whitelist"
        )

        if indicator in proposed[other]:

            verdict["status"] = "rejected"

            verdict["reasons"] = [
                f"hash {indicator} is proposed for "
                "both the whitelist and the blacklist"
            ]

        elif indicator in main_global_hashes[other]:

            verdict["status"] = "rejected"

            verdict["reasons"] = [
                f"hash {indicator} is already in the "
                f"production {other} on main"
            ]

    # --------------------------------------------------------
    # 4. Write, re-check the complete feed, demote culprits
    # --------------------------------------------------------

    for attempt in range(4):

        chosen = [
            verdict
            for verdict in verdicts
            if verdict["status"] in active
        ]

        additions = {
            rel: []
            for rel in paths
        }

        # Junk that must never come back (IGNORED_NAMES) is also
        # removed from main's own files.
        removals = {
            rel: {
                value
                for value in main_values[rel]
                if entry_ignored_name(value)
            }
            for rel in paths
        }

        for verdict in chosen:

            additions[verdict["target"]].append(
                verdict["normalized"]
            )

            if (
                verdict["target"] == GLOBAL_WHITELIST_PATH
                and verdict["kind"] == "name_sha256"
            ):

                # The hash arrived: the pending line
                # (pinned or name-only NEEDS HASH) is done.
                removals[PENDING_WHITELIST_PATH] |= {
                    verdict["normalized"],
                    split_name_sha256(
                        verdict["normalized"]
                    )[0],
                }

        for rel, path in paths.items():

            rewrite_feed(
                path,
                originals[rel],
                additions[rel],
                removals[rel],
            )

        final_global = {
            classify(value)[1]
            for _, value in feed_lines(
                paths[GLOBAL_WHITELIST_PATH]
            )
            if classify(value)[0] == "name_sha256"
        }

        proof = {}

        for key in final_global:

            if key in main_proof:
                proof[key] = main_proof[key]

            elif key in main_values[GLOBAL_WHITELIST_PATH]:
                # main's own gap (reported by the gate on
                # main already); never invented here.
                continue

            elif key in carried_proof and any(
                verdict["normalized"] == key
                and verdict["status"] == "carried"
                for verdict in chosen
            ):
                proof[key] = carried_proof[key]

            else:

                name, sha256 = split_name_sha256(
                    key
                )

                proof[key] = build_proof_entry(
                    name,
                    sha256,
                    data,
                    now_iso,
                )

        if proof or proof_original is not None:

            proof_path.write_text(
                proof_text(proof),
                encoding="utf-8",
            )

        # Human review queue (pending/needs_review.txt): this
        # run's rejected / retry lines in, resolved lines out.
        # Rebuilt from main's copy on every attempt.
        if review_original is None:
            NEEDS_REVIEW_PATH.unlink(missing_ok=True)
        else:
            NEEDS_REVIEW_PATH.write_text(
                review_original,
                encoding="utf-8",
            )

        review_counts = update_needs_review(
            verdicts,
            carry_ref,
            paths,
            data,
        )

        check = result()

        collect_all(
            check
        )

        new_errors = [
            error
            for error in check["errors"]
            if error not in baseline_errors
        ]

        if not new_errors:
            break

        culprits = [
            verdict
            for verdict in chosen
            if any(
                verdict["normalized"] in error
                or (
                    value_indicator(verdict["normalized"])
                    or "\0"
                ) in error
                for error in new_errors
            )
        ]

        if not culprits or attempt == 3:

            # Leave main untouched rather than propose a feed
            # that does not pass.
            for rel, path in paths.items():

                if originals[rel] is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(
                        originals[rel],
                        encoding="utf-8",
                    )

            if proof_original is None:
                proof_path.unlink(missing_ok=True)
            else:
                proof_path.write_text(
                    proof_original,
                    encoding="utf-8",
                )

            if review_original is None:
                NEEDS_REVIEW_PATH.unlink(missing_ok=True)
            else:
                NEEDS_REVIEW_PATH.write_text(
                    review_original,
                    encoding="utf-8",
                )

            raise SystemExit(
                "Promotion would introduce feed errors: "
                + "; ".join(new_errors[:5])
            )

        for verdict in culprits:

            verdict["status"] = "rejected"

            verdict["reasons"] = [
                "complete feed check failed: "
                + error
                for error in new_errors
                if verdict["normalized"] in error
                or (
                    value_indicator(verdict["normalized"])
                    or "\0"
                ) in error
            ]

    changed = any(
        (
            paths[rel].read_text(encoding="utf-8")
            if paths[rel].exists()
            else None
        ) != originals[rel]
        for rel in paths
    ) or (
        proof_path.read_text(encoding="utf-8")
        if proof_path.exists()
        else None
    ) != proof_original or (
        NEEDS_REVIEW_PATH.read_text(encoding="utf-8")
        if NEEDS_REVIEW_PATH.exists()
        else None
    ) != review_original

    for verdict in verdicts:

        verdict.setdefault(
            "ha",
            ha_summary(
                verdict,
                data,
                carried_proof,
            ),
        )

    plan = {
        "review": review_counts,
        "changed": changed,
        "generated": now_iso,
        "counts": {},
        "lines": verdicts,
        # Staging inbox gate outcome (red only when structural).
        "staging_gate": {
            "mode": bool(data.get("staging_mode")),
            "decision": data.get("decision"),
            "structural_errors": list(
                data.get("structural_errors") or []
            ),
        },
    }

    for verdict in verdicts:

        plan["counts"][verdict["status"]] = (
            plan["counts"].get(verdict["status"], 0)
            + 1
        )

    # Lines the gate already skipped because main has them (no
    # lookups spent) also count as "already on main" in the report.
    skipped = int(
        data.get("already_in_base", 0) or 0
    )

    if skipped:

        plan["counts"]["already_on_main"] = (
            plan["counts"].get("already_on_main", 0)
            + skipped
        )

    return plan


def md_cell(
    text,
    limit: int = 160,
) -> str:
    """Untrusted text -> inert Markdown table cell content."""

    text = " ".join(
        str(text).split()
    )

    if len(text) > limit:
        text = text[:limit] + "..."

    for char, entity in (
        ("&", "&amp;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("|", "&#124;"),
        ("`", "&#96;"),
        ("@", "&#64;"),
        ("[", "&#91;"),
        ("]", "&#93;"),
        ("*", "&#42;"),
        ("_", "&#95;"),
        ("~", "&#126;"),
        ("\\", "&#92;"),
    ):
        text = text.replace(
            char,
            entity,
        )

    return text


def md_table(
    rows,
    headers,
) -> list:

    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "---|" * len(headers),
    ]

    for row in rows[:REPORT_ROWS]:

        lines.append(
            "| "
            + " | ".join(
                md_cell(cell)
                for cell in row
            )
            + " |"
        )

    if len(rows) > REPORT_ROWS:

        lines.append(
            f"\n... and {len(rows) - REPORT_ROWS} more "
            "(see the gate run's report artifact)"
        )

    return lines


STATUS_LABEL = (
    ("promote", "verified - proposed in the promotion PR"),
    ("carried", "kept from the open promotion PR"),
    ("needs_hash", "name-only - proposed as NEEDS HASH candidate"),
    ("already_on_main", "already on main (nothing to do)"),
    ("retry", "not verified yet - queued for human review + retried"),
    ("rejected", "rejected - queued for human review"),
    ("ignored", "ignored permanently (never re-queued)"),
)


def promotion_texts(
    plan: dict,
    staging_pr: str = "",
    staging_sha: str = "",
    run_url: str = "",
):
    """(staging PR comment, promotion PR body) as Markdown."""

    counts = plan["counts"]

    lines = plan["lines"]

    source = (
        (f"staging PR #{md_cell(staging_pr)}" if staging_pr else "staging PR")
        + (f" at `{md_cell(staging_sha[:12])}`" if staging_sha else "")
        + (f" ([gate run]({run_url}))" if run_url.startswith("https://") else "")
    )

    summary = [
        "| result | lines |",
        "|---|---|",
    ] + [
        f"| {label} | {counts.get(status, 0)} |"
        for status, label in STATUS_LABEL
    ]

    comment = [
        PROMOTION_MARKER,
        "## AEGIS verified promotion report",
        "",
        f"Checked {source} on {plan['generated']}. This PR is "
        "the staging inbox and is never merged: lines that "
        "passed every check go to the "
        f"**{PROMOTION_TITLE}** PR (branch "
        f"`{PROMOTION_BRANCH}`, auto-merged when its gate is "
        f"green); rejected / not-yet-verifiable lines are "
        f"recorded in `{NEEDS_REVIEW_REL}` for a human.",
        "",
        *summary,
    ]

    gate = plan.get("staging_gate") or {}

    if gate.get("mode"):

        structural = gate.get("structural_errors") or []

        comment += [
            "",
            (
                "**Staging gate: green** - every line above was "
                "handled (promoted, already on main, queued for "
                "review, retried or ignored). A red staging gate "
                "means a structural problem that needs a human."
            )
            if not structural
            else (
                f"**Staging gate: red** - {len(structural)} "
                "structural problem(s) need a human (per-line "
                "findings are handled automatically):"
            ),
        ] + [
            f"- {md_cell(error, 300)}"
            for error in structural[:20]
        ]

    for status, title, columns in (
        (
            "rejected",
            "Rejected lines",
            ("line", "file", "Hybrid Analysis", "reason"),
        ),
        (
            "retry",
            "Not verified yet (quota / outage; retried next run)",
            ("line", "file", "Hybrid Analysis", "reason"),
        ),
        (
            "needs_hash",
            "NEEDS HASH (name-only, not trusted)",
            ("line", "file", "Hybrid Analysis", "note"),
        ),
    ):

        rows = [
            (
                verdict["value"],
                verdict["path"],
                verdict.get("ha") or "-",
                "; ".join(verdict["reasons"])
                or (
                    "moved to "
                    + verdict["target"]
                    if verdict["target"] != verdict["path"]
                    else ""
                ),
            )
            for verdict in lines
            if verdict["status"] == status
        ]

        if rows:

            comment += [
                "",
                f"### {title} ({len(rows)})",
                "",
                *md_table(rows, columns),
            ]

    promoted = [
        verdict
        for verdict in lines
        if verdict["status"] in {
            "promote",
            "carried",
            "needs_hash",
        }
    ]

    body = [
        "Generated by the AEGIS security gate from "
        f"{source}.",
        "",
        "Contains ONLY lines that passed every check "
        "(structure, policy, CIRCL hashlookup / VirusTotal, "
        "MalwareBazaar, MetaDefender and Hybrid Analysis if "
        "configured). Each "
        "production whitelist line has a proof entry in "
        f"`{PROOF_REL}`.",
        "",
        "- The security gate runs on this PR again (cached "
        "answers, few or no new API calls).",
        "- When that gate is green the promotion bot "
        "squash-merges this PR into main automatically.",
        f"- Rejected / not-yet-verifiable lines are recorded in "
        f"`{NEEDS_REVIEW_REL}` (human review queue, never "
        "auto-trusted).",
        f"- Do not edit this branch by hand: `{PROMOTION_BRANCH}` "
        "is regenerated from main (force-pushed) after every "
        "staging run; lines still waiting here are kept.",
        "",
        *summary,
        "",
        f"### Lines in this PR ({len(promoted)})",
        "",
        *md_table(
            [
                (
                    verdict["normalized"],
                    verdict["target"],
                    verdict.get("ha") or "-",
                    {
                        "promote": "verified in this run",
                        "carried": "verified in an earlier run",
                        "needs_hash": "NEEDS HASH candidate",
                    }[verdict["status"]]
                    + (
                        " (maintainer override: "
                        + verdict["override"]
                        + ")"
                        if verdict.get("override")
                        else ""
                    ),
                )
                for verdict in promoted
            ],
            ("line", "file", "Hybrid Analysis", "status"),
        ),
    ]

    return (
        "\n".join(comment) + "\n",
        "\n".join(body) + "\n",
    )


def phase_promote(
    args,
    report: Path,
):

    data = load_report(
        report
    )

    plan = build_promotion(
        data,
        args.carry_ref or None,
    )

    comment, body = promotion_texts(
        plan,
        args.staging_pr or "",
        args.staging_sha or "",
        args.run_url or "",
    )

    for target, text in (
        (args.plan, json.dumps(plan, indent=2, sort_keys=True)),
        (args.comment, comment),
        (args.pr_body, body),
    ):

        if target:

            Path(target).write_text(
                text,
                encoding="utf-8",
            )

    print(
        json.dumps(
            {
                "changed": plan["changed"],
                "counts": plan["counts"],
            },
            indent=2,
            sort_keys=True,
        )
    )

    return plan


# ============================================================
# HYBRID ANALYSIS REVIEW SCAN (manual, read-only)
# ============================================================
# Run by "AEGIS Hybrid Analysis review scan" (workflow_dispatch).
# Looks up ONLY the lines waiting for a human: the review queue
# (pending/needs_review.txt) and the pending candidate files.
# Hash lookups only: /search/hash through the gate's own
# run_reputation (same throttle, cap and cache) plus
# /overview/{sha256} for threat score / AV results. Both are
# x-auth-level "restricted"; nothing is ever submitted. No feed
# file is changed: the output is a Markdown table + JSON for
# the maintainer, who decides.
# ============================================================

HA_OVERVIEW_URL = "https://hybrid-analysis.com/api/v2/overview/"

# Overview lookups per run (one per SHA-256, after the search).
REVIEW_SCAN_MAX_OVERVIEWS = 50

REVIEW_SCAN_NO_HASH = "no hash, can't check"


def ha_overview_lookup(
    sha256: str,
    api_key: str,
):

    return http_json(
        urllib.request.Request(
            HA_OVERVIEW_URL
            + urllib.parse.quote(
                sha256,
                safe="",
            ),
            headers={
                "api-key": api_key,
                "accept": "application/json",
                "User-Agent": HA_USER_AGENT,
            },
        )
    )


def ha_overview_summary(
    status,
    body,
):
    """Threat score / AV results from an /overview answer."""

    if (
        status != 200
        or not isinstance(body, dict)
        or body.get("error")
    ):

        if status in {401, 403, 429}:
            # Same quota / bad-key rules as the search lookup.
            state = ha_record(
                "",
                status,
                body if isinstance(body, dict) else {},
            )["status"]
        elif status == 404:
            state = "not_found"
        else:
            state = "unavailable"

        return {
            "status": state,
            "http": status,
        }

    def as_int(value):

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

    scanners = []

    raw = body.get("scanners_v2")

    if isinstance(raw, dict):
        raw = [
            dict(value, name=value.get("name") or key)
            for key, value in raw.items()
            if isinstance(value, dict)
        ]

    if not isinstance(raw, list) or not raw:
        raw = body.get("scanners")

    for scanner in (
        raw
        if isinstance(raw, list)
        else []
    ):

        if not isinstance(scanner, dict):
            continue

        name = str(
            scanner.get("name") or ""
        ).strip()[:40]

        if not name:
            continue

        scanners.append(
            {
                "name": name,
                "status": str(
                    scanner.get("status") or ""
                ).strip()[:30],
                "positives": as_int(
                    scanner.get("positives")
                ),
                "total": as_int(
                    scanner.get("total")
                ),
                "percent": as_int(
                    scanner.get("percent")
                ),
            }
        )

    vx_family = body.get("vx_family")

    return {
        "status": "ok",
        "verdict": ha_verdict_of(
            body.get("verdict")
        ),
        "threat_score": as_int(
            body.get("threat_score")
        ),
        "multiscan_result": as_int(
            body.get("multiscan_result")
        ),
        "whitelisted":
            body.get("whitelisted") is True,
        "vx_family":
            str(vx_family)[:60]
            if vx_family
            else "",
        "last_file_name": str(
            body.get("last_file_name") or ""
        )[:80],
        "scanners": scanners[:12],
    }


def review_scan_items():
    """Every line of the review queue and pending candidates."""

    items = []

    counts = {}

    queue_path = NEEDS_REVIEW_PATH

    text = (
        queue_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        if queue_path.exists()
        else ""
    )

    queue, errors = parse_needs_review(
        text
    )

    counts[NEEDS_REVIEW_REL] = len(queue)

    for entry in sorted(
        queue.values(),
        key=lambda e: e["line"],
    ):

        items.append(
            {
                "file": NEEDS_REVIEW_REL,
                "line": entry["line"],
                "value": entry["value"],
                "disposition":
                    entry["disposition"],
                "reason": entry["reason"],
                # The queue holds lines that wanted production
                # trust (whitelist); only the verdict is used.
                "feed_type": "whitelist",
            }
        )

    for key, feed_type in (
        ("pending_whitelist", "whitelist"),
        ("pending_blacklist", "blacklist"),
    ):

        path = FEEDS[key]

        try:
            rel = path.relative_to(ROOT).as_posix()
        except ValueError:
            rel = path.name

        lines = feed_lines(path)

        counts[rel] = len(lines)

        for number, value in lines:

            items.append(
                {
                    "file": rel,
                    "line": number,
                    "value": value,
                    "disposition": "",
                    "reason": "",
                    "feed_type": feed_type,
                }
            )

    for item in items:

        kind, normalized = classify(
            item["value"]
        )

        item["kind"] = kind

        item["normalized"] = normalized

        pinned = split_name_sha256(
            normalized
        ) if kind == "name_sha256" else None

        item["name"] = (
            pinned[0]
            if pinned
            else (
                normalized
                if kind == "name"
                else ""
            )
        )

        item["hash"] = value_indicator(
            normalized
        )

    return items, counts, errors


def review_verdict(
    record,
    overview,
):
    """(display verdict, rank or None) from search + overview."""

    verdicts = []

    if record and record.get("status") == "found":
        verdicts.append(
            record.get("verdict") or "no verdict"
        )

    if overview and overview.get("status") == "ok":

        if overview.get("verdict"):
            verdicts.append(overview["verdict"])

        elif overview.get("whitelisted"):
            verdicts.append("whitelisted")

    if verdicts:

        worst = max(
            verdicts,
            key=lambda v: HA_VERDICT_RANK.get(v, 0),
        )

        return worst, HA_VERDICT_RANK.get(worst)

    if record and record.get("status") == "not_found":
        return "not found", None

    if (
        overview
        and overview.get("status") == "not_found"
        and not record
    ):
        return "not found", None

    if not record:
        return "not checked", None

    reason = (
        record.get("reason")
        or record.get("detail")
        or record.get("status")
        or "no answer"
    )

    return f"not checked ({reason})", None


def review_av_text(overview) -> str:

    if not overview or overview.get("status") != "ok":
        return "-"

    parts = []

    if overview.get("threat_score") is not None:
        parts.append(
            f"threat score {overview['threat_score']}/100"
        )

    if overview.get("multiscan_result") is not None:
        parts.append(
            f"AV multiscan {overview['multiscan_result']}%"
        )

    for scanner in overview.get("scanners", []):

        if (
            scanner.get("positives") is not None
            and scanner.get("total")
        ):
            parts.append(
                f"{scanner['name']} "
                f"{scanner['positives']}/{scanner['total']}"
            )

        elif scanner.get("status"):
            parts.append(
                f"{scanner['name']} {scanner['status']}"
            )

    if overview.get("vx_family"):
        parts.append(
            f"family {overview['vx_family']}"
        )

    if overview.get("whitelisted"):
        parts.append("HA whitelisted")

    return "; ".join(parts) or "none returned"


def review_short_reason(reason: str) -> str:

    if not reason:
        return "-"

    match = re.search(
        r"\bVT \d+/\d+\b",
        reason,
    )

    head = reason.split(";", 1)[0].strip()

    if match and match.group(0) not in head:
        head = f"{match.group(0)}; {head}"

    return head[:110]


def review_recommendation(
    item,
    verdict: str,
    overview,
) -> str:

    if not item.get("hash"):
        return (
            "Hybrid Analysis looks up hashes only; judge "
            "by publisher / path or add name|sha256"
        )

    score = (
        overview.get("threat_score")
        if overview and overview.get("status") == "ok"
        else None
    )

    retry = (
        " (the gate also still has to finish its own "
        "checks for this line)"
        if any(
            marker in item.get("reason", "")
            for marker in RETRY_MARKERS
        )
        or item.get("reason", "").startswith(
            "not verified yet"
        )
        else ""
    )

    if item.get("disposition") == "hard_reject":
        return "keep blocked (hard reject by policy)"

    if item.get("feed_type") == "blacklist":

        if verdict in {"malicious", "suspicious"}:
            return "Hybrid Analysis corroborates the block"

        return (
            "no Hybrid Analysis corroboration; needs "
            "other evidence before blocking"
        )

    if verdict == "malicious":
        return "keep blocked (Hybrid Analysis: malicious)"

    if verdict == "suspicious":
        return (
            "keep blocked (Hybrid Analysis: suspicious; "
            "needs manual analysis)"
        )

    if score is not None and score >= 50:
        return (
            f"keep blocked (threat score {score}/100 "
            "despite the verdict)"
        )

    if verdict in {"whitelisted", "no specific threat"}:
        return (
            f"Hybrid Analysis: {verdict} - looks like a "
            "false positive, safe to override if you trust "
            "the publisher" + retry
        )

    if verdict in {"not found", "no verdict"}:
        return (
            "no Hybrid Analysis evidence either way; keep "
            "in review" + retry
        )

    return "Hybrid Analysis not checked; re-run the scan"


def phase_review_scan(
    args,
):

    items, counts, queue_errors = review_scan_items()

    data = result()

    for item in items:

        if not item["hash"]:
            continue

        data["entries"].append(
            {
                "path": item["file"],
                "feed_type": item["feed_type"],
                "value": item["value"],
                "kind": item["kind"],
                "normalized": item["normalized"],
            }
        )

    run_reputation(
        "hybridanalysis",
        data,
        args.cache,
    )

    stats = data.get(
        "reputation_runs",
        {},
    ).get(
        "hybridanalysis",
        {},
    )

    configured = stats.get("configured") is not False

    records = {}

    for record in data["reputation"]:

        if record.get("provider") == "hybridanalysis":
            records[record.get("indicator")] = record

    # --------------------------------------------------------
    # Overview (threat score / AV) for each SHA-256 found.
    # --------------------------------------------------------

    overviews = {}

    overview_lookups = 0

    api_key = os.environ.get(
        PROVIDER_KEY_ENV["hybridanalysis"],
        "",
    ).strip()

    if configured and api_key and not stats.get("stopped"):

        for item in items:

            sha = item["hash"]

            if (
                not sha
                or sha in overviews
                or not SHA256_RE.fullmatch(sha)
            ):
                continue

            record = records.get(sha) or {}

            if record.get("status") == "rate_limited":
                break

            if overview_lookups >= REVIEW_SCAN_MAX_OVERVIEWS:
                break

            throttle("hybridanalysis")

            try:
                status, body = ha_overview_lookup(
                    sha,
                    api_key,
                )
            except Exception as exc:
                status, body = None, {
                    "error": str(exc)[:120]
                }

            LAST_CALL["hybridanalysis"] = time.monotonic()

            overview_lookups += 1

            overviews[sha] = ha_overview_summary(
                status,
                body,
            )

            if overviews[sha]["status"] == "rate_limited":
                break

    # --------------------------------------------------------
    # Rows
    # --------------------------------------------------------

    rows = []

    for item in items:

        sha = item["hash"]

        record = records.get(sha) if sha else None

        overview = overviews.get(sha) if sha else None

        if not sha:
            verdict = REVIEW_SCAN_NO_HASH
        elif not configured:
            verdict = "not checked (key not configured)"
        else:
            verdict, _rank = review_verdict(
                record,
                overview,
            )

        rows.append(
            {
                "file": item["file"],
                "line": item["line"],
                "name": item["name"] or "(bare hash)",
                "hash": sha or "",
                "short_hash":
                    f"{sha[:12]}..." if sha else "-",
                "verdict": verdict,
                "reports":
                    (record or {}).get("reports"),
                "threat_score_av": (
                    review_av_text(overview)
                    if sha
                    else "-"
                ),
                "overview": overview,
                "disposition": item["disposition"],
                "reason": item["reason"],
                "short_reason": review_short_reason(
                    item["reason"]
                ),
                "recommendation": (
                    review_recommendation(
                        item,
                        verdict,
                        overview,
                    )
                    if configured or not sha
                    else "configure HYBRID_ANALYSIS_API_KEY "
                    "and re-run"
                ),
            }
        )

    scanned_at = datetime.datetime.now(
        datetime.timezone.utc
    ).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    output = {
        "schema": 1,
        "scanned_at": scanned_at,
        "provider": "hybridanalysis",
        "configured": configured,
        "lookups": stats.get("lookups", 0),
        "cache_hits": stats.get("cache_hits", 0),
        "overview_lookups": overview_lookups,
        "stopped": stats.get("stopped"),
        "files": counts,
        "queue_errors": queue_errors,
        "rows": rows,
    }

    # --------------------------------------------------------
    # Markdown (untrusted API text goes through md_cell)
    # --------------------------------------------------------

    lines = [
        "## AEGIS Hybrid Analysis review scan",
        "",
        f"Scanned at {scanned_at} (UTC). Scope: the review "
        "queue and the pending candidate files only. Hash "
        "lookups only (search + overview); nothing was "
        "submitted and no list was changed.",
        "",
    ]

    if configured:
        lines.append(
            f"Hybrid Analysis: {output['lookups']} search "
            f"lookups, {output['cache_hits']} cache hits, "
            f"{overview_lookups} overview lookups."
        )
    else:
        lines.append(
            "Hybrid Analysis: HYBRID_ANALYSIS_API_KEY is not "
            "configured; nothing was looked up."
        )

    if output["stopped"]:
        lines.append(
            f"Stopped early: {md_cell(output['stopped'])}"
        )

    for error in queue_errors:
        lines.append(f"Queue parse error: {md_cell(error)}")

    for rel, count in counts.items():

        lines += [
            "",
            f"### {rel} ({count} "
            f"line{'s' if count != 1 else ''})",
            "",
        ]

        file_rows = [
            row for row in rows
            if row["file"] == rel
        ]

        if not file_rows:
            lines.append("_no entries_")
            continue

        lines += [
            "| Name | Hash | Hybrid verdict | Threat score "
            "/ AV | Current reason | Recommendation |",
            "|---|---|---|---|---|---|",
        ]

        for row in file_rows:

            verdict = row["verdict"]

            if row.get("reports"):
                verdict += (
                    f" ({row['reports']} report"
                    f"{'s' if row['reports'] != 1 else ''})"
                )

            lines.append(
                "| "
                + " | ".join(
                    md_cell(cell)
                    for cell in (
                        row["name"],
                        row["short_hash"],
                        verdict,
                        row["threat_score_av"],
                        row["short_reason"],
                        row["recommendation"],
                    )
                )
                + " |"
            )

    lines += [
        "",
        "No list was changed. The maintainer decides.",
        "",
    ]

    markdown = "\n".join(lines)

    Path(args.report).parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    Path(args.report).write_text(
        json.dumps(output, indent=2) + "\n",
        encoding="utf-8",
    )

    if args.summary:

        Path(args.summary).write_text(
            markdown,
            encoding="utf-8",
        )

    print(markdown)

    if not configured:
        print(
            "::warning::HYBRID_ANALYSIS_API_KEY is not "
            "configured; review scan did nothing"
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

    parser.add_argument(
        "--staging-inbox",
        action="store_true",
        help=(
            "The PR is an open draft staging inbox (set by the "
            "workflow): only structural errors fail the check"
        ),
    )

    parser.add_argument(
        "--promote",
        action="store_true",
        help=(
            "Build the verified promotion from a finished "
            "gate report (rewrites the working tree)"
        ),
    )

    parser.add_argument(
        "--review-scan",
        action="store_true",
        help=(
            "Read-only Hybrid Analysis lookup of the review "
            "queue and pending candidates (JSON to --report, "
            "Markdown to --summary); changes no file"
        ),
    )

    parser.add_argument(
        "--summary",
        default="",
        help="Markdown output file (--review-scan)",
    )

    parser.add_argument(
        "--carry-ref",
        default="",
        help=(
            "Open promotion branch whose waiting lines "
            "are kept (--promote)"
        ),
    )

    for option in (
        "--plan",
        "--comment",
        "--pr-body",
        "--staging-pr",
        "--staging-sha",
        "--run-url",
    ):
        parser.add_argument(
            option,
            default="",
        )

    args = parser.parse_args()

    report = Path(
        args.report
    )

    # --------------------------------------------------------
    # Hybrid Analysis review scan (read-only)
    # --------------------------------------------------------

    if args.review_scan:

        phase_review_scan(
            args
        )

        return

    # --------------------------------------------------------
    # Verified promotion
    # --------------------------------------------------------

    if args.promote:

        phase_promote(
            args,
            report,
        )

        return

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
