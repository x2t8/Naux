#!/usr/bin/env python3
"""Fail when versionable Markdown links to a missing repository-local target."""

from __future__ import annotations

import re
import subprocess
import sys
import urllib.parse
from pathlib import Path, PurePosixPath


INLINE_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
FENCE = re.compile(r"^\s*(```|~~~)")


def tracked_paths(repo_root: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        stdout=subprocess.PIPE,
    )
    return tuple(path.decode("utf-8") for path in completed.stdout.split(b"\0") if path)


def without_fenced_code(text: str) -> str:
    kept: list[str] = []
    marker: str | None = None
    for line in text.splitlines(keepends=True):
        match = FENCE.match(line)
        if match:
            token = match.group(1)
            if marker is None:
                marker = token
            elif token == marker:
                marker = None
            kept.append("\n")
        elif marker is None:
            kept.append(line)
        else:
            kept.append("\n")
    return "".join(kept)


def destinations(text: str) -> tuple[str, ...]:
    visible = without_fenced_code(text)
    found = [match.group(1).strip() for match in INLINE_LINK.finditer(visible)]
    found.extend(match.group(1).strip() for match in REFERENCE_LINK.finditer(visible))
    return tuple(found)


def normalize_destination(raw: str) -> str | None:
    if raw.startswith("<") and ">" in raw:
        raw = raw[1 : raw.index(">")]
    else:
        raw = raw.split(maxsplit=1)[0]
    raw = urllib.parse.unquote(raw).split("#", 1)[0].split("?", 1)[0]
    if not raw:
        return None
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme or raw.startswith("//"):
        return None
    return raw


def resolve_target(source: str, destination: str) -> str | None:
    normalized = normalize_destination(destination)
    if normalized is None:
        return None
    if normalized.startswith("/"):
        candidate = PurePosixPath(normalized.lstrip("/"))
    else:
        candidate = PurePosixPath(source).parent / normalized
    parts: list[str] = []
    for part in candidate.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise ValueError("local link escapes the repository")
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath(*parts).as_posix()


def audit(repo_root: Path) -> list[str]:
    tracked = tracked_paths(repo_root)
    tracked_set = set(tracked)
    tracked_directories: set[str] = set()
    for item in tracked:
        parent = PurePosixPath(item).parent
        while parent != PurePosixPath("."):
            tracked_directories.add(parent.as_posix())
            parent = parent.parent

    failures: list[str] = []
    markdown = sorted(path for path in tracked if path.lower().endswith(".md"))
    link_count = 0
    for source in markdown:
        text = (repo_root / source).read_text(encoding="utf-8")
        for destination in destinations(text):
            try:
                target = resolve_target(source, destination)
            except ValueError as error:
                failures.append(f"{source}: {destination}: {error}")
                continue
            if target is None:
                continue
            link_count += 1
            if target not in tracked_set and target not in tracked_directories:
                failures.append(f"{source}: untracked or missing local target: {destination}")
    print(
        f"Markdown link audit: {len(markdown)} versionable files, "
        f"{link_count} local links"
    )
    return failures


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    try:
        failures = audit(repo_root)
    except (OSError, UnicodeDecodeError, subprocess.CalledProcessError) as error:
        print(f"Markdown link audit: FAIL: {error}", file=sys.stderr)
        return 1
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        print(f"Markdown link audit: FAIL ({len(failures)} broken link(s))", file=sys.stderr)
        return 1
    print("Markdown link audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
