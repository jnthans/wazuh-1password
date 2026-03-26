#!/usr/bin/env bash
# =============================================================================
# run.sh – 1Password Events API Wazuh Wodle runtime wrapper
# =============================================================================
#
# PURPOSE
# ───────
# This script is the single target for the ossec.conf <command> entry.
# It sets all runtime configuration as environment variables, resolves the
# Python interpreter, and execs onepassword.py. ossec.conf never needs to
# change when configuration changes — only this file does.
#
# OSSEC.CONF REFERENCE
# ────────────────────
# <wodle name="command">
#   <disabled>no</disabled>
#   <tag>onepassword</tag>
#   <command>/var/ossec/wodles/onepassword/run.sh</command>
#   <interval>300</interval>
#   <ignore_output>no</ignore_output>
#   <run_on_start>yes</run_on_start>
#   <timeout>120</timeout>
# </wodle>
#
# CONFIGURATION
# ─────────────
# All variables below are documented with their default values.
# Credentials should NOT be set here — use .secrets or systemd credentials.
# See .secrets.example for the credential file format.
#
# CREDENTIAL PRIORITY (first match wins)
# ──────────────────────────────────────
# 1. systemd $CREDENTIALS_DIRECTORY  (most secure — memory-backed)
# 2. .secrets file                   (OP_SECRETS_FILE or default path below)
# 3. OP_BEARER_TOKEN env var in this file  (least secure — avoid)
#
# =============================================================================

set -euo pipefail

# ── Wodle directory (resolved relative to this script's location) ─────────────
WODLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─────────────────────────────────────────────────────────────────────────────
# REQUIRED — credentials
# Set via .secrets file (recommended) or systemd credentials.
# Uncomment and set here only if neither of those options is available.
# ─────────────────────────────────────────────────────────────────────────────
# export OP_BEARER_TOKEN="your-bearer-token-here"

# ─────────────────────────────────────────────────────────────────────────────
# Lookback on first run (hours)
# Controls how far back the initial fetch reaches when no state exists.
# Default 24 hours gives operators immediate dashboard visibility on day one.
# 1Password cursor-based pagination handles all catch-up automatically.
# ─────────────────────────────────────────────────────────────────────────────
export OP_LOOKBACK_HOURS="${OP_LOOKBACK_HOURS:-24}"

# ─────────────────────────────────────────────────────────────────────────────
# State file path
# Stores cursors and poll timestamps between runs.
# Must be writable by the wazuh user.
# ─────────────────────────────────────────────────────────────────────────────
export OP_STATE_FILE="${OP_STATE_FILE:-/var/ossec/wodles/onepassword/state.json}"

# ─────────────────────────────────────────────────────────────────────────────
# Secrets file path
# Plain-text KEY=VALUE file containing OP_BEARER_TOKEN.
# Must be owned root:wazuh with permissions 640.
# See .secrets.example for the expected format.
# ─────────────────────────────────────────────────────────────────────────────
export OP_SECRETS_FILE="${OP_SECRETS_FILE:-${WODLE_DIR}/.secrets}"

# ─────────────────────────────────────────────────────────────────────────────
# API base URL
# Default: https://events.1password.com
# Override for EU tenants: https://events.ent.1password.com
# Override for testing: http://localhost:8080
# ─────────────────────────────────────────────────────────────────────────────
export OP_BASE_URL="${OP_BASE_URL:-https://events.1password.com}"

# ─────────────────────────────────────────────────────────────────────────────
# Page limit — events per API request
# Valid range: 1-1000. Default 100 balances throughput and memory.
# Increase for high-volume accounts to reduce total API calls.
# ─────────────────────────────────────────────────────────────────────────────
export OP_PAGE_LIMIT="${OP_PAGE_LIMIT:-100}"

# ─────────────────────────────────────────────────────────────────────────────
# Multi-tenant / MSP mode (optional)
# Set to a path containing a JSON file with tenant configurations.
# When set, OP_BEARER_TOKEN is ignored — tokens come from the file.
# See configuration.md for the expected file format.
# ─────────────────────────────────────────────────────────────────────────────
# export OP_TOKENS_FILE="/var/ossec/wodles/onepassword/tenants.json"

# ─────────────────────────────────────────────────────────────────────────────
# Debug verbosity (stderr only — never reaches Wazuh's stdout pipe)
#   0 = off (default, production)
#   1 = info  (run summary, event counts, state transitions)
#   2 = verbose (per-page fetch details, API params, state values)
#   3 = trace (full response bodies, every emitted event)
# ─────────────────────────────────────────────────────────────────────────────
export OP_DEBUG="${OP_DEBUG:-0}"

# ─────────────────────────────────────────────────────────────────────────────
# Python interpreter resolution
# Prefer python3 in standard locations. Wazuh bundles its own Python under
# /var/ossec/framework/python — fall back to that if system python3 is absent.
# ─────────────────────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON="$(command -v python3)"
elif [[ -x /var/ossec/framework/python/bin/python3 ]]; then
    PYTHON="/var/ossec/framework/python/bin/python3"
else
    echo '{"integration":"1password","type":"error","op":{"source":"orchestrator","error_code":"PYTHON_VERSION_ERROR","error_message":"python3 not found in PATH or /var/ossec/framework/python/bin"}}' >&1
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Execute
# ─────────────────────────────────────────────────────────────────────────────
exec "${PYTHON}" "${WODLE_DIR}/onepassword.py" --debug "${OP_DEBUG}" "$@"
