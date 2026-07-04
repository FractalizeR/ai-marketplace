#!/usr/bin/env bash
#
# Build + register + install the fr-security-review Codex plugin from a
# self-hosted local marketplace. Idempotent: re-running rebuilds the bundle and
# updates the installed plugin (cachebuster bump, per harness/codex/INSTALL.md §6).
#
# The Codex marketplace here is a LOCAL directory (not Git), so `marketplace
# upgrade` (Git-only) does not apply — updates go through a cachebuster bump +
# `codex plugin add`, which reinstalls from the registered path.
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$REPO/dist/codex"
PLUGIN_DIR="$DIST/plugins/fr-security-review"
MARKET="fractalizer-marketplace"
PLUGIN="fr-security-review"
CACHEBUST="$HOME/.codex/skills/.system/plugin-creator/scripts/update_plugin_cachebuster.py"

command -v codex >/dev/null || { echo "error: 'codex' CLI not found on PATH" >&2; exit 1; }

echo "==> Building Codex bundle -> $DIST"
python3 "$REPO/build/build.py" --harness=codex --mode=write --out="$DIST"

if codex plugin marketplace list 2>/dev/null | grep -qF "$DIST"; then
  echo "==> Marketplace already registered at $DIST"
else
  echo "==> Registering marketplace '$MARKET' at $DIST"
  codex plugin marketplace add "$DIST"
fi

# If the plugin is already installed, a plain rebuild won't be picked up (Codex
# caches by version) — bump the cachebuster in the registered dist path first.
# NB: match "…@market <spaces> installed" — the "not installed" status has "not"
# in that slot, so it must not trip the update branch.
if codex plugin list 2>/dev/null | grep -qE "${PLUGIN}@${MARKET}[[:space:]]+installed"; then
  if [ -f "$CACHEBUST" ]; then
    echo "==> Plugin already installed — bumping cachebuster for the update"
    python3 "$CACHEBUST" "$PLUGIN_DIR"
  else
    echo "==> WARNING: plugin installed but cachebuster tool not found;" >&2
    echo "    the reinstall below may be a no-op. See harness/codex/INSTALL.md §6." >&2
  fi
fi

echo "==> Installing/updating plugin '${PLUGIN}@${MARKET}'"
codex plugin add "${PLUGIN}@${MARKET}"

echo
echo "==> Status:"
codex plugin list 2>/dev/null | grep -F "${PLUGIN}@${MARKET}" || true

cat <<EOF

Done. Before running an audit in a Codex session, export FR_SECURITY_CORE_ROOT (the portable
engine — Codex does not substitute \${FR_SECURITY_CORE_ROOT}, it is a plain shell variable):

  export FR_SECURITY_CORE_ROOT="$PLUGIN_DIR/core"

Do NOT put FR_SECURITY_CORE_ROOT in your shell rc globally — it is per-harness and would
collide with the OpenCode value. Set it in the session where you run the audit.

Then start a NEW Codex thread and invoke the skill: security-project / security-changes.
EOF
