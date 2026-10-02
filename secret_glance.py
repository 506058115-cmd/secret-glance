#!/usr/bin/env python3
"""Find likely secrets in text files without printing their values."""

import argparse
import os
from pathlib import Path
import re
import sys


MAX_FILE_BYTES = 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
# ponytail: line-based heuristics keep this dependency-free; add format-aware parsing only if needed.
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:^|[\s\"'#{,])(?:export\s+)?"
    r"[A-Za-z_][A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
    r"[A-Za-z0-9_.-]*\s*[:=]\s*(?P<value>[^\s,;#]+)"
)
PLACEHOLDERS = {
    "", "none", "null", "nil", "changeme", "change-me", "example", "dummy",
    "placeholder", "redacted", "your-secret", "your_token", "your-token", "xxx",
}
PATTERNS = (
    ("private-key", PRIVATE_KEY_RE),
    ("aws-access-key", AWS_KEY_RE),
    ("github-token", GITHUB_TOKEN_RE),
    ("slack-token", SLACK_TOKEN_RE),
    ("jwt-like", JWT_RE),
)


def inspect_file(path):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return [], None
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES or b"\0" in data:
            return [], None
        text = data.decode("utf-8-sig")
    except UnicodeError:
        return [], None
    except OSError as error:
        return [], f"{path}: {error}"

    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for label, pattern in PATTERNS:
            if pattern.search(line):
                findings.append((number, label))
        match = SECRET_ASSIGNMENT_RE.search(line)
        if match:
            value = match.group("value").strip("\"'`[]{}()")
            normalized = value.casefold().replace(" ", "")
            if len(value) >= 8 and normalized not in PLACEHOLDERS and not normalized.startswith(("your_", "your-", "<")):
                findings.append((number, "secret-assignment"))
    return sorted(set(findings)), None


def walk(path):
    if path.is_symlink():
        return
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        return
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not (Path(root) / name).is_symlink())
        for name in sorted(files):
            yield Path(root) / name


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="List likely secret locations without displaying any matched values."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories to scan")
    args = parser.parse_args(argv)

    seen = set()
    findings_count = 0
    errors = 0
    for root in args.paths:
        if not root.exists():
            print(f"secret-glance: path not found: {root}", file=sys.stderr)
            errors += 1
            continue
        for path in walk(root):
            try:
                identity = path.resolve()
            except OSError:
                identity = path.absolute()
            if identity in seen:
                continue
            seen.add(identity)
            findings, error = inspect_file(path)
            if error:
                print(f"secret-glance: {error}", file=sys.stderr)
                errors += 1
                continue
            for number, label in findings:
                print(f"{path}:{number}: {label}")
                findings_count += 1

    if not findings_count and not errors:
        print("No likely secrets found.")
    print(f"Scanned {len(seen)} files; {findings_count} likely finding(s).", file=sys.stderr)
    return 2 if errors else 1 if findings_count else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("secret-glance: interrupted", file=sys.stderr)
        raise SystemExit(130)
