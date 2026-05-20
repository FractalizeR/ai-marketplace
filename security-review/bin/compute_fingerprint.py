#!/usr/bin/env python3
"""Compute project_fingerprint and code_fingerprint for SECURITY_CONTEXT.md.

Deterministic SHA-256 over content of a fixed list of files (project_fingerprint)
and over tracked source tree + dirty state (code_fingerprint).

stdlib only. No external dependencies.

Usage:
    compute_fingerprint.py <project_root>
    compute_fingerprint.py <project_root> --json

Output (default): two lines — project_fingerprint, code_fingerprint.
Output (--json): {"project_fingerprint": "...", "code_fingerprint": "..."}.
"""

import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


PROJECT_FILES_FIXED = [
    "composer.json",
    "composer.lock",
    "symfony.lock",
    "package.json",
    "config/bundles.php",
    "config/services.yaml",
    "importmap.php",
    "webpack.config.js",
    "assets/entrypoints.json",
]

PROJECT_FILES_GLOB = [
    "config/packages/*.yaml",
    "config/packages/*.php",
    "config/packages/*.xml",
    "config/routes/*.yaml",
    "config/routes/*.php",
    "config/routes/*.xml",
    "config/services/*.yaml",
]

CODE_SCOPE_DIRS = ["src", "templates", "assets", "migrations"]


def sha256_of_content(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def collect_project_files(root: Path) -> list[Path]:
    """Return sorted list of existing project fingerprint files."""
    collected: set[Path] = set()
    for rel in PROJECT_FILES_FIXED:
        p = root / rel
        if p.is_file():
            collected.add(p)
    for pattern in PROJECT_FILES_GLOB:
        for match in glob.glob(str(root / pattern)):
            mp = Path(match)
            if mp.is_file():
                collected.add(mp)
    return sorted(collected)


def compute_project_fingerprint(root: Path) -> str:
    """SHA-256 over concatenation of (relative_path + content) for each file, sorted."""
    h = hashlib.sha256()
    for path in collect_project_files(root):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        h.update(b"PATH:")
        h.update(rel)
        h.update(b"\n")
        h.update(b"CONTENT:")
        h.update(path.read_bytes())
        h.update(b"\n---\n")
    return h.hexdigest()


def run_git(args: list[str], cwd: Path) -> str:
    """Run git command, return stdout. Empty string on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout
    except (FileNotFoundError, OSError):
        return ""


def _existing_scope_dirs(root: Path) -> list[str]:
    return [d for d in CODE_SCOPE_DIRS if (root / d).is_dir()]


def compute_code_fingerprint(root: Path) -> str:
    """SHA-256 over:
    1. `git ls-files -s` over scope directories (blob hashes of tracked content)
    2. `git diff HEAD` over scope directories (staged + unstaged diff)
    3. `git status --porcelain=v1` over scope directories (untracked and the rest)
    """
    h = hashlib.sha256()

    scope = _existing_scope_dirs(root)
    if not scope:
        # None of the scope directories exist — fingerprint is still deterministic.
        h.update(b"NO_SCOPE_DIRS\n")
        return h.hexdigest()

    # 1. Tracked blob hashes.
    ls_files = run_git(["ls-files", "-s", "--", *scope], root)
    h.update(b"LS_FILES:\n")
    h.update(ls_files.encode("utf-8"))
    h.update(b"\n---\n")

    # 2. Diff HEAD.
    diff = run_git(["diff", "HEAD", "--no-color", "--", *scope], root)
    h.update(b"DIFF_HEAD:\n")
    h.update(diff.encode("utf-8"))
    h.update(b"\n---\n")

    # 3. Porcelain v1 (untracked etc.).
    porcelain = run_git(["status", "--porcelain=v1", "--", *scope], root)
    h.update(b"PORCELAIN:\n")
    h.update(porcelain.encode("utf-8"))
    h.update(b"\n---\n")

    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute fingerprints for SECURITY_CONTEXT.md")
    parser.add_argument("project_root", type=Path, help="Project root directory")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args(argv)

    root: Path = args.project_root.resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2

    pf = compute_project_fingerprint(root)
    cf = compute_code_fingerprint(root)

    if args.json:
        print(json.dumps({"project_fingerprint": pf, "code_fingerprint": cf}))
    else:
        print(f"project_fingerprint: {pf}")
        print(f"code_fingerprint: {cf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
