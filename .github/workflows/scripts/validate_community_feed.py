#!/usr/bin/env python3
"""Validate the DonTranQuiL Sentinel // AEGIS community definition feeds.

Checks ``global_blacklist.txt`` and ``global_whitelist.txt``:

* UTF-8 encoding, no NUL / control / bidi-override characters
* every entry is a SHA-256 hash (64 hex chars) or a safe file name
* no duplicate entries within a file (case-insensitive)
* no entry present in both the blacklist and the whitelist
* file size / line count sanity limits
* warnings (non-fatal) for whitelisted critical Windows system names

Syntax: one entry per line, optional trailing `` # comment``, lines starting
with ``#`` are comments, blank lines are ignored.

Usage::

    python validate_community_feed.py [--root PATH] [--base-ref REF]

Emits GitHub Actions ``::error`` / ``::warning`` annotations, writes a Markdown
summary to ``$GITHUB_STEP_SUMMARY`` when set and exits non-zero on errors.
Python 3 standard library only.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

BLACKLIST = "global_blacklist.txt"
WHITELIST = "global_whitelist.txt"
FEED_FILES = (BLACKLIST, WHITELIST)

MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB (keep in sync with the security gate)
MAX_LINES = 100_000
MAX_NAME_LENGTH = 255

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Something made only of hex digits and long enough to be meant as a hash
# (MD5 = 32, SHA-1 = 40, ...), but not a valid SHA-256.
HASHLIKE_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
# Allowed file-name characters: ASCII letters, digits, and a small set of
# punctuation that is common in real executable names and harmless in paths.
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._\-+() \[\]&,~!@]+$")
# Windows reserved device names (with or without an extension).
RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
# Characters used for file-name spoofing (e.g. "gpj.exe" shown as "exe.jpg").
BIDI_CONTROLS = set("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# Critical Windows binaries that malware frequently impersonates. Whitelisting
# them by *name* would let any file with that name bypass detection.
CRITICAL_SYSTEM_NAMES = {
    "svchost.exe", "explorer.exe", "lsass.exe", "lsaiso.exe", "csrss.exe",
    "winlogon.exe", "wininit.exe", "services.exe", "smss.exe", "spoolsv.exe",
    "rundll32.exe", "regsvr32.exe", "dllhost.exe", "taskhost.exe",
    "taskhostw.exe", "conhost.exe", "powershell.exe", "pwsh.exe",
    "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "msiexec.exe", "schtasks.exe", "taskmgr.exe", "wmic.exe",
    "wmiprvse.exe", "certutil.exe", "bitsadmin.exe", "sihost.exe",
    "runtimebroker.exe", "dwm.exe", "ctfmon.exe", "fontdrvhost.exe",
    "system", "registry", "msmpeng.exe", "searchindexer.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe",
}
# Generic names shipped by countless unrelated (and malicious) installers.
GENERIC_NAMES = {
    "setup.exe", "install.exe", "installer.exe", "update.exe",
    "updater.exe", "autoupdate.exe", "launcher.exe", "app.exe", "run.exe",
    "start.exe", "service.exe", "helper.exe",
}


@dataclass
class Issue:
    level: str  # "error" | "warning"
    file: str
    line: int | None
    message: str


@dataclass
class Entry:
    value: str
    key: str  # normalised (case-folded) value used for comparisons
    line: int
    kind: str  # "sha256" | "name"


@dataclass
class FeedResult:
    name: str
    entries: list[Entry] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    def error(self, line: int | None, message: str) -> None:
        self.issues.append(Issue("error", self.name, line, message))

    def warn(self, line: int | None, message: str) -> None:
        self.issues.append(Issue("warning", self.name, line, message))


def bad_characters(text: str) -> list[str]:
    """Return a description of each forbidden character in ``text``."""
    found = []
    for ch in text:
        if ch in ("\n", "\t"):
            continue
        if ch == "\x00":
            found.append("NUL (U+0000)")
        elif ch in BIDI_CONTROLS:
            found.append(f"bidi control U+{ord(ch):04X}")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            found.append(f"control/format character U+{ord(ch):04X}")
    return found


def split_entry(raw: str) -> tuple[str, bool]:
    """Strip an optional `` # comment`` from a line.

    Returns ``(entry_text, is_comment_or_blank)``. The entry text is *not*
    stripped so leading/trailing whitespace can be reported.
    """
    if raw.strip() == "" or raw.lstrip().startswith("#"):
        return "", True
    match = re.search(r"\s+#", raw)
    if match:
        return raw[: match.start()], False
    return raw, False


def classify(entry: str) -> tuple[str | None, str | None]:
    """Return ``(kind, error_message)`` for a stripped entry."""
    if SHA256_RE.match(entry):
        return "sha256", None
    if HASHLIKE_RE.match(entry):
        return None, (
            f"looks like a hash but has {len(entry)} hex characters; "
            "only SHA-256 (64 hex characters) is supported"
        )
    if "/" in entry or "\\" in entry:
        return None, "path separators are not allowed; use a bare file name"
    if ".." in entry:
        return None, "'..' is not allowed in file names"
    if len(entry) > MAX_NAME_LENGTH:
        return None, f"file name longer than {MAX_NAME_LENGTH} characters"
    if not SAFE_NAME_RE.match(entry):
        bad = sorted({c for c in entry if not SAFE_NAME_RE.match(c)})
        shown = " ".join(repr(c) for c in bad)
        return None, f"file name contains disallowed characters: {shown}"
    if entry.strip(". ") == "":
        return None, "file name consists only of dots/spaces"
    if entry.endswith((".", " ")):
        return None, "file name must not end with '.' or a space"
    if entry.split(".")[0].strip().lower() in RESERVED_NAMES:
        return None, "Windows reserved device name"
    return "name", None


def parse_text(name: str, text: str, result: FeedResult) -> None:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        result.error(None, f"{len(lines)} lines exceeds the limit of {MAX_LINES}")
        return
    crlf_reported = False
    for lineno, raw in enumerate(lines, start=1):
        if raw.endswith("\r"):
            raw = raw[:-1]
            if not crlf_reported:
                result.warn(lineno, "CRLF line endings found; LF is preferred")
                crlf_reported = True
        bad = bad_characters(raw)
        if bad:
            result.error(lineno, "forbidden characters: " + ", ".join(sorted(set(bad))))
            continue
        if "\t" in raw:
            result.error(lineno, "tab characters are not allowed")
            continue
        entry, skip = split_entry(raw)
        if skip:
            continue
        if entry != entry.strip():
            result.error(lineno, f"leading/trailing whitespace around entry {entry.strip()!r}")
            entry = entry.strip()
        kind, problem = classify(entry)
        if problem:
            result.error(lineno, f"invalid entry {entry!r}: {problem}")
            continue
        assert kind is not None
        result.entries.append(Entry(entry, entry.casefold(), lineno, kind))


def validate_file(root: Path, name: str) -> FeedResult:
    result = FeedResult(name)
    path = root / name
    if not path.is_file():
        result.error(None, "file is missing")
        return result
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        result.error(None, f"file is {size} bytes, limit is {MAX_FILE_BYTES}")
        return result
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        result.warn(1, "UTF-8 byte order mark found; please save without BOM")
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.error(None, f"not valid UTF-8 (byte offset {exc.start})")
        return result
    if data and not data.endswith(b"\n"):
        result.warn(None, "file does not end with a newline")
    parse_text(name, text, result)

    seen: dict[str, Entry] = {}
    for entry in result.entries:
        first = seen.get(entry.key)
        if first:
            result.error(
                entry.line,
                f"duplicate entry {entry.value!r} (first seen on line {first.line})",
            )
        else:
            seen[entry.key] = entry
    return result


def cross_checks(black: FeedResult, white: FeedResult) -> None:
    black_keys = {e.key: e for e in black.entries}
    for entry in white.entries:
        if entry.key in black_keys:
            white.error(
                entry.line,
                f"{entry.value!r} is in both {WHITELIST} and {BLACKLIST} "
                f"(blacklist line {black_keys[entry.key].line})",
            )
    for entry in white.entries:
        if entry.kind != "name":
            continue
        if entry.key in CRITICAL_SYSTEM_NAMES:
            white.warn(
                entry.line,
                f"whitelisting critical Windows system name {entry.value!r} by name is "
                "risky: malware commonly impersonates it. Prefer a SHA-256 hash.",
            )
        elif entry.key in GENERIC_NAMES:
            white.warn(
                entry.line,
                f"{entry.value!r} is a generic installer/updater name used by many "
                "unrelated programs. Prefer a SHA-256 hash.",
            )


def entries_at_ref(root: Path, ref: str, name: str) -> set[str] | None:
    """Return normalised entries of ``name`` at git ``ref`` (None on failure)."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "show", f"{ref}:{name}"],
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        exists = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        return set() if exists.returncode == 0 else None
    text = proc.stdout.decode("utf-8", errors="replace")
    keys = set()
    for raw in text.splitlines():
        entry, skip = split_entry(raw)
        if not skip and entry.strip():
            keys.add(entry.strip().casefold())
    return keys


def annotation(issue: Issue) -> str:
    props = f"file={issue.file}"
    if issue.line:
        props += f",line={issue.line}"
    message = issue.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::{issue.level} {props}::{message}"


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--base-ref", help="git ref to diff entries against")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    results = {name: validate_file(root, name) for name in FEED_FILES}
    cross_checks(results[BLACKLIST], results[WHITELIST])

    issues = [i for r in results.values() for i in r.issues]
    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    diffs: dict[str, tuple[list[str], list[str]]] = {}
    if args.base_ref:
        for name, result in results.items():
            old = entries_at_ref(root, args.base_ref, name)
            if old is None:
                msg = f"could not read {name} at ref {args.base_ref!r}; skipping diff"
                warnings.append(Issue("warning", name, None, msg))
                continue
            current = {e.key: e.value for e in result.entries}
            added = sorted(current[k] for k in current.keys() - old)
            removed = sorted(old - current.keys())
            diffs[name] = (added, removed)

    for issue in errors + warnings:
        print(annotation(issue))

    print()
    for name, result in results.items():
        hashes = sum(1 for e in result.entries if e.kind == "sha256")
        names = len(result.entries) - hashes
        print(f"{name}: {len(result.entries)} entries ({names} names, {hashes} SHA-256)")
    for name, (added, removed) in diffs.items():
        print(f"{name} vs {args.base_ref}: +{len(added)} / -{len(removed)}")
        for value in added:
            print(f"  + {value}")
        for value in removed:
            print(f"  - {value}")
    status = "FAILED" if errors else "OK"
    print(f"\nValidation {status}: {len(errors)} error(s), {len(warnings)} warning(s)")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        icon = "\u274c" if errors else "\u2705"
        out = [f"## {icon} AEGIS community feed validation: {status}", ""]
        out += ["| File | Entries | Names | SHA-256 |", "| --- | ---: | ---: | ---: |"]
        for name, result in results.items():
            hashes = sum(1 for e in result.entries if e.kind == "sha256")
            total = len(result.entries)
            out.append(f"| `{name}` | {total} | {total - hashes} | {hashes} |")
        out.append("")
        if errors or warnings:
            out += ["### Findings", "", "| Level | File | Line | Message |",
                    "| --- | --- | ---: | --- |"]
            for i in errors + warnings:
                out.append(
                    f"| {i.level} | `{i.file}` | {i.line or ''} | {md_escape(i.message)} |"
                )
            out.append("")
        if diffs:
            out += [f"### Changes vs `{md_escape(args.base_ref)}`", ""]
            for name, (added, removed) in diffs.items():
                out.append(f"**{name}**: +{len(added)} / -{len(removed)}")
                out.append("")
                if added or removed:
                    out.append("```diff")
                    out += [f"+ {v}" for v in added] + [f"- {v}" for v in removed]
                    out.append("```")
                    out.append("")
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
