#!/usr/bin/env bash
#
# Build + install the fr-security-review OpenCode command/agent bundle.
#
# Scope (env OPENCODE_SCOPE):
#   global  (default) -> ~/.config/opencode/{commands,agents}/   (all projects)
#   project           -> ./.opencode/{commands,agents}/          (cwd only)
#
# The bundle's opencode.json carries a SCOPED permission posture (deny
# task/webfetch/websearch). It is deliberately NOT copied over your global
# ~/.config/opencode/opencode.json — that would deny those tools for all your
# OpenCode use. It is applied per-audit via OPENCODE_CONFIG (printed below).
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$REPO/dist/opencode"
SCOPE="${OPENCODE_SCOPE:-global}"

echo "==> Building OpenCode bundle -> $DIST"
python3 "$REPO/build/build.py" --harness=opencode --mode=write --out="$DIST"

case "$SCOPE" in
  global)  DEST="$HOME/.config/opencode" ;;
  project) DEST="$PWD/.opencode" ;;
  *) echo "error: OPENCODE_SCOPE must be 'global' or 'project' (got '$SCOPE')" >&2; exit 1 ;;
esac

echo "==> Installing commands + agents into $DEST (scope: $SCOPE)"
mkdir -p "$DEST/commands" "$DEST/agents"
cp "$DIST"/commands/* "$DEST/commands/"
cp "$DIST"/agents/*   "$DEST/agents/"
echo "    (left $DEST/opencode.json untouched)"

cat <<EOF

Done. Commands (/security-project, /security-changes) and agents (security,
security-recon, security-refute) are installed for scope: $SCOPE.

Before running an audit, point OpenCode at the bundle's scoped permission config
and export FR_SECURITY_CORE_ROOT (a plain shell variable OpenCode does not substitute):

  export OPENCODE_CONFIG="$DIST/opencode.json"
  export FR_SECURITY_CORE_ROOT="$DIST/core"

Do NOT put FR_SECURITY_CORE_ROOT in your shell rc globally — it is per-harness and would
collide with the Codex value. Set it in the session where you run the audit.

Run headless:
  opencode run --command security-project "project_root=. review_root=security-review-opencode"
Or in the TUI:  /security-project
EOF
