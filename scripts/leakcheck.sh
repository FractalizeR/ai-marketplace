#!/usr/bin/env bash
#
# leakcheck.sh — machine check for internal identifiers leaking into this
# public repo (CLAUDE.md "Public repo — synthetic examples only").
#
# Patterns live in .leakcheck.local (gitignored, one regex per line, NOT
# committed — see .leakcheck.example for the form). A denylist of real
# internal names committed to a public repo would itself be the leak it is
# trying to prevent, so the two files are split: .leakcheck.example (in git,
# form only) vs .leakcheck.local (real patterns, local-only).
#
# Usage:
#   scripts/leakcheck.sh [--staged|--all]   # --all is the default
#
#   --all     scan the whole tracked tree (git ls-files)
#   --staged  scan only files staged in the index (git diff --cached)
#
# Scope is the tracked tree minus a denylist (dist/, .git/, the local
# pattern file itself) — not an allowlist, which goes stale as new
# directories are added.
#
# Exit 0: clean, or .leakcheck.local absent (nothing to check locally).
# Exit 1: at least one match found; matches are printed as file:line:content.
set -euo pipefail

usage() {
  echo "Usage: $(basename "$0") [--staged|--all]" >&2
  exit 2
}

mode="all"
case "$#" in
  0) ;;
  1)
    case "$1" in
      --staged) mode="staged" ;;
      --all) mode="all" ;;
      *) usage ;;
    esac
    ;;
  *) usage ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

local_file=".leakcheck.local"

if [[ ! -f "$local_file" ]]; then
  echo "leakcheck: no $local_file found — skipping (copy .leakcheck.example to $local_file and fill in real identifiers to enable this check locally)." >&2
  exit 0
fi

# Strip blank lines and comments. A pattern file with nothing left must not
# fall through to `grep -f`, which treats an empty pattern file as "match
# everything" — that would flag every scanned file as a leak.
patterns="$(grep -v -E '^[[:space:]]*(#|$)' "$local_file" || true)"

if [[ -z "$patterns" ]]; then
  exit 0
fi

pattern_file="$(mktemp)"
trap 'rm -f "$pattern_file"' EXIT
printf '%s\n' "$patterns" > "$pattern_file"

candidates=()
if [[ "$mode" == "staged" ]]; then
  while IFS= read -r -d '' f; do candidates+=("$f"); done \
    < <(git diff --cached --name-only --diff-filter=ACMR -z)
else
  while IFS= read -r -d '' f; do candidates+=("$f"); done \
    < <(git ls-files -z)
fi

files=()
for f in "${candidates[@]}"; do
  case "$f" in
    dist/*) continue ;;
    .git/*) continue ;;
    "$local_file") continue ;;
  esac
  [[ -f "$f" ]] || continue
  files+=("$f")
done

if [[ ${#files[@]} -eq 0 ]]; then
  exit 0
fi

if output="$(grep -InHiE -f "$pattern_file" -- "${files[@]}" 2>/dev/null)"; then
  echo "$output"
  echo "leakcheck: found potential internal-identifier leak(s) above — fix them or extend $local_file." >&2
  exit 1
fi

exit 0
