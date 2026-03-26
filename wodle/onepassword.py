#!/usr/bin/env python3
"""
onepassword.py – 1Password Events API v2 -> Wazuh Wodle (entry point)

Orchestrates event ingestion from the 1Password Events API v2 across three
event streams: audit events, sign-in attempts, and item usage events.

All three streams use cursor-based pagination and are polled at the same
interval (controlled by the ossec.conf wodle block). No internal scheduling
is needed — unlike Proofpoint's daily People API, all 1Password streams
are equal peers.

Supports multi-tenant / MSP mode via OP_TOKENS_FILE for monitoring multiple
1Password accounts from a single Wazuh installation.

Run `onepassword.py --help` for CLI usage. See configuration.md for env vars.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import onepassword_utils as utils
from onepassword_events import fetch_and_emit_stream, introspect


# ─────────────────────────────────────────────────────────────────────────────
# Stream definitions
# ─────────────────────────────────────────────────────────────────────────────

# All three endpoints share the same interface (POST, cursor pagination).
# The feature name maps to the introspect response's "features" array.
STREAMS: Dict[str, Dict[str, str]] = {
    "audit": {
        "endpoint":   "/api/v2/auditevents",
        "event_type": "audit_event",
        "feature":    "auditevents",
    },
    "signin": {
        "endpoint":   "/api/v2/signinattempts",
        "event_type": "signin_attempt",
        "feature":    "signinattempts",
    },
    "itemusage": {
        "endpoint":   "/api/v2/itemusages",
        "event_type": "item_usage",
        "feature":    "itemusages",
    },
}

# Valid --source choices
_SOURCE_CHOICES = list(STREAMS.keys()) + ["all"]


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="onepassword",
        description="1Password Events API v2 → Wazuh wodle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  onepassword.py                                 # all streams
  onepassword.py --source audit                  # audit events only
  onepassword.py --source signin --all --lookback 24   # backfill 24 hours
  onepassword.py --all --debug 1                 # test all streams, verbose
        """
    )

    parser.add_argument("--source",
        choices=_SOURCE_CHOICES,
        default=None,
        metavar="SOURCE",
        help=(
            "Which stream(s) to run this execution: "
            "audit | signin | itemusage | all (default: all). "
            "Override with OP_SOURCE env var."
        ))

    parser.add_argument("-a", "--all",
        action="store_true", dest="all_mode",
        help=(
            "TEST/BACKFILL: ignore state; do not update state after run. "
            "Uses --lookback to control the time window."
        ))

    parser.add_argument("-l", "--lookback",
        type=float, default=None, metavar="HOURS",
        help=(
            "Hours to look back in --all mode or on first run. "
            "Default: OP_LOOKBACK_HOURS env var, or 1."
        ))

    parser.add_argument("-d", "--debug",
        type=int, choices=[0, 1, 2, 3], default=0, metavar="LEVEL",
        help="Debug verbosity to stderr: 0=off 1=info 2=verbose 3=trace")

    return parser.parse_args()


def _resolve_source(args: argparse.Namespace) -> str:
    """
    Resolve which source(s) to run.
    Priority: --source CLI flag > OP_SOURCE env var > 'all' default.
    """
    source = (
        args.source
        or os.environ.get("OP_SOURCE", "all").lower()
    )
    if source not in _SOURCE_CHOICES:
        print(
            f"[ERROR] Invalid source '{source}'. Must be: {' | '.join(_SOURCE_CHOICES)}",
            file=sys.stderr,
        )
        sys.exit(1)
    return source


# ─────────────────────────────────────────────────────────────────────────────
# Config loading
# ─────────────────────────────────────────────────────────────────────────────

def load_config(args: argparse.Namespace):
    """
    Populate utils.config with non-credential runtime settings.
    Credentials are absent here — validate_config() → load_secrets() loads
    them via the full priority chain so setting from env here would bypass it.
    """
    utils.config.update({
        "state_file": os.environ.get(
            "OP_STATE_FILE",
            "/var/ossec/wodles/onepassword/state.json"),
        "base_url": os.environ.get(
            "OP_BASE_URL",
            utils.OP_BASE_URL),
        "lookback_hours": float(
            args.lookback if args.lookback is not None
            else os.environ.get("OP_LOOKBACK_HOURS", "1")
        ),
        "page_limit": int(os.environ.get("OP_PAGE_LIMIT", "100")),
    })

    # ── Validate base URL ─────────────────────────────────────────────────
    _validate_base_url(utils.config["base_url"])

    # ── Early validation ─────────────────────────────────────────────────
    lh = utils.config["lookback_hours"]
    if lh <= 0:
        print(
            f"[ERROR] lookback={lh}h is invalid. Must be > 0.",
            file=sys.stderr,
        )
        sys.exit(1)

    pl = utils.config["page_limit"]
    if pl < 1 or pl > 1000:
        print(
            f"[ERROR] OP_PAGE_LIMIT={pl} is invalid. Must be 1-1000.",
            file=sys.stderr,
        )
        sys.exit(1)


_ALLOWED_BASE_URL_DOMAINS = {
    "events.1password.com",
    "events.ent.1password.com",
}


def _validate_base_url(url: str):
    """
    Validate OP_BASE_URL: must be HTTPS with a known 1Password domain,
    or localhost/127.0.0.1 (HTTP allowed) for testing.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()

    # Allow localhost/127.0.0.1 for testing (any scheme)
    if host in ("localhost", "127.0.0.1"):
        return

    if scheme != "https":
        print(
            f"[ERROR] OP_BASE_URL scheme must be https (got '{scheme}'). "
            f"Only localhost is allowed over HTTP.",
            file=sys.stderr,
        )
        sys.exit(1)

    if host not in _ALLOWED_BASE_URL_DOMAINS:
        utils.log(1,
            f"WARNING: OP_BASE_URL host '{host}' is not a known 1Password domain "
            f"({', '.join(sorted(_ALLOWED_BASE_URL_DOMAINS))}). "
            f"Proceeding, but verify this is correct."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Multi-tenant support
# ─────────────────────────────────────────────────────────────────────────────

def _load_tenants() -> Optional[List[Dict[str, str]]]:
    """
    Load multi-tenant configuration from OP_TOKENS_FILE.
    Returns None if no tokens file is configured (single-tenant mode).
    Returns a list of tenant dicts: [{"name": "...", "bearer_token": "...", ...}]
    """
    tokens_file = os.environ.get("OP_TOKENS_FILE")
    if not tokens_file:
        return None

    try:
        with open(tokens_file) as f:
            data = json.load(f)
    except Exception as exc:
        utils.emit_error(
            "orchestrator", "CONFIG_MISSING_CREDENTIAL",
            f"Cannot read multi-tenant tokens file: {tokens_file}",
            detail=str(exc),
        )
        sys.exit(1)

    tenants = data.get("tenants", [])
    if not tenants:
        utils.emit_error(
            "orchestrator", "CONFIG_MISSING_CREDENTIAL",
            "Multi-tenant tokens file has no tenants defined",
            detail=f"path={tokens_file}",
        )
        sys.exit(1)

    _TENANT_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

    for i, t in enumerate(tenants):
        if not t.get("name") or not t.get("bearer_token"):
            utils.emit_error(
                "orchestrator", "CONFIG_MISSING_CREDENTIAL",
                f"Tenant at index {i} is missing 'name' or 'bearer_token'",
                detail=f"path={tokens_file}",
            )
            sys.exit(1)

        if not _TENANT_NAME_RE.match(t["name"]):
            utils.emit_error(
                "orchestrator", "CONFIG_MISSING_CREDENTIAL",
                f"Tenant name '{t['name']}' at index {i} contains invalid characters — "
                f"use only letters, numbers, hyphens, and underscores",
                detail=f"path={tokens_file}",
            )
            sys.exit(1)

    utils.log(1, f"Multi-tenant mode: {len(tenants)} tenant(s) loaded from {tokens_file}")
    return tenants


# ─────────────────────────────────────────────────────────────────────────────
# Test / backfill banner
# ─────────────────────────────────────────────────────────────────────────────

def _print_test_banner(source: str, lookback_hours: float):
    print(
        "\n"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║       1Password Events API Wodle – TEST / ALL MODE        ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        f"║  Source  : {source:<47}║\n"
        f"║  Lookback: {str(lookback_hours) + 'h':<47}║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║  State NOT updated. All streams will run regardless.       ║\n"
        "╚══════════════════════════════════════════════════════════╝\n",
        file=sys.stderr,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stream runner
# ─────────────────────────────────────────────────────────────────────────────

def run_stream(
    stream_name: str,
    stream_cfg: Dict[str, str],
    state: dict,
    all_mode: bool,
    lookback_hours: float,
    page_limit: int,
    tenant_prefix: str = "",
) -> bool:
    """
    Execute a single event stream for this wodle run.

    Reads the cursor from state (or uses start_time on first run), calls
    fetch_and_emit_stream, and saves the new cursor to state on success.

    Returns True on success, False on failure (error already emitted).
    """
    cursor_key    = f"{tenant_prefix}{stream_name}_cursor"
    last_poll_key = f"{tenant_prefix}{stream_name}_last_poll"

    # Determine cursor or start_time
    cursor = None if all_mode else state.get(cursor_key)
    start_time = utils.lookback_start_time(lookback_hours) if not cursor else None

    utils.log(1,
        f"{stream_name}: cursor={'<from state>' if cursor else 'none'} "
        f"start_time={start_time or 'n/a'}"
    )

    try:
        count, new_cursor = fetch_and_emit_stream(
            stream_name = stream_name,
            endpoint    = stream_cfg["endpoint"],
            event_type  = stream_cfg["event_type"],
            cursor      = cursor,
            start_time  = start_time,
            limit       = page_limit,
        )
    except Exception as exc:
        utils.log(1, f"{stream_name} unhandled exception: {exc}")
        utils.emit_error(
            stream_name, "API_UNEXPECTED_ERROR",
            f"Unhandled exception in {stream_name} fetch module: {type(exc).__name__}",
        )
        return False

    if new_cursor is None:
        # fetch_and_emit_stream already emitted the root-cause error
        return False

    utils.log(1, f"{stream_name}: {count} events, cursor updated")

    # Save cursor to state
    if not all_mode:
        state[cursor_key] = new_cursor
        state[last_poll_key] = utils.utc_now_iso()
        utils.save_state(state, source=stream_name)

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if sys.version_info < (3, 8):
        import json as _json
        print(_json.dumps({
            "integration": "1password",
            "type":        "error",
            "op": {
                "source":        "orchestrator",
                "error_code":    "PYTHON_VERSION_ERROR",
                "error_message": f"Python {sys.version} is too old — 3.8+ required",
                "timestamp":     utils.utc_now_iso(),
            },
        }), flush=True)
        sys.exit(1)

    try:
        _run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        # Full traceback goes to stderr only — never emit it to stdout
        # because it may contain credentials, internal paths, or PII
        # that would be indexed in OpenSearch.
        print(f"[FATAL] {tb}", file=sys.stderr, flush=True)
        try:
            utils.emit_error(
                "orchestrator", "ORCHESTRATOR_FATAL",
                f"Unhandled fatal exception: {type(exc).__name__}: {exc}",
            )
        except Exception:
            import json as _json
            print(_json.dumps({
                "integration": "1password",
                "type":        "error",
                "op": {
                    "source":        "orchestrator",
                    "error_code":    "ORCHESTRATOR_FATAL",
                    "error_message": str(exc),
                },
            }), flush=True)
        sys.exit(1)


def _run():
    args = parse_args()
    utils.set_debug_level(args.debug)

    source = _resolve_source(args)

    load_config(args)

    # Check for multi-tenant mode
    tenants = _load_tenants()

    if tenants:
        _run_multi_tenant(args, source, tenants)
    else:
        _run_single_tenant(args, source)


def _run_single_tenant(args: argparse.Namespace, source: str):
    """Run in single-tenant mode with OP_BEARER_TOKEN."""
    utils.validate_config()

    utils.log(1,
        f"source={source} | "
        f"all_mode={args.all_mode} | "
        f"lookback={utils.config['lookback_hours']}h"
    )

    if args.all_mode:
        _print_test_banner(source, utils.config["lookback_hours"])

    # Introspect to validate token and discover features
    introspect_data, introspect_ok = introspect()
    enabled_features = introspect_data.get("features", []) if introspect_data else []

    state = utils.load_state()

    # Determine which streams to run
    streams_to_run = _resolve_streams(source, enabled_features)

    # Run each stream
    results: Dict[str, bool] = {}
    for stream_name, stream_cfg in streams_to_run.items():
        results[stream_name] = run_stream(
            stream_name    = stream_name,
            stream_cfg     = stream_cfg,
            state          = state,
            all_mode       = args.all_mode,
            lookback_hours = utils.config["lookback_hours"],
            page_limit     = utils.config["page_limit"],
        )

    _emit_run_summary(results)


def _run_multi_tenant(args: argparse.Namespace, source: str, tenants: List[Dict]):
    """Run in multi-tenant MSP mode, iterating over each tenant."""
    utils.log(1,
        f"source={source} | "
        f"all_mode={args.all_mode} | "
        f"lookback={utils.config['lookback_hours']}h | "
        f"tenants={len(tenants)}"
    )

    if args.all_mode:
        _print_test_banner(source, utils.config["lookback_hours"])

    state = utils.load_state()

    all_results: Dict[str, Dict[str, bool]] = {}

    for tenant in tenants:
        tenant_name = tenant["name"]
        utils.log(1, f"── Tenant: {tenant_name} ──")

        # Override bearer token for this tenant
        utils.config["bearer_token"] = tenant["bearer_token"]

        # Introspect to validate tenant token
        introspect_data, introspect_ok = introspect()
        if not introspect_ok:
            utils.log(1, f"Tenant {tenant_name}: introspect failed, skipping")
            all_results[tenant_name] = {}
            continue

        enabled_features = introspect_data.get("features", []) if introspect_data else []

        # Determine streams for this tenant
        streams_to_run = _resolve_streams(source, enabled_features)

        tenant_prefix = f"{tenant_name}."
        tenant_results: Dict[str, bool] = {}

        for stream_name, stream_cfg in streams_to_run.items():
            tenant_results[stream_name] = run_stream(
                stream_name    = stream_name,
                stream_cfg     = stream_cfg,
                state          = state,
                all_mode       = args.all_mode,
                lookback_hours = utils.config["lookback_hours"],
                page_limit     = utils.config["page_limit"],
                tenant_prefix  = tenant_prefix,
            )

        all_results[tenant_name] = tenant_results

    # Emit a combined run summary for multi-tenant
    _emit_multi_tenant_summary(all_results)


# ─────────────────────────────────────────────────────────────────────────────
# Stream resolution
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_streams(
    source: str,
    enabled_features: List[str],
) -> Dict[str, Dict[str, str]]:
    """
    Determine which streams to run based on the --source flag and
    the features authorized by the bearer token (from introspect).
    """
    if source == "all":
        requested = dict(STREAMS)
    else:
        requested = {source: STREAMS[source]}

    # Filter by enabled features (if introspect provided them)
    if enabled_features:
        filtered = {}
        for name, cfg in requested.items():
            if cfg["feature"] in enabled_features:
                filtered[name] = cfg
            else:
                utils.log(1,
                    f"Stream '{name}' skipped — feature '{cfg['feature']}' "
                    f"not in authorized features: {enabled_features}"
                )
        return filtered

    # If introspect didn't return features (or failed), try all requested
    return requested


# ─────────────────────────────────────────────────────────────────────────────
# Run summary emission
# ─────────────────────────────────────────────────────────────────────────────

def _emit_run_summary(results: Dict[str, bool]):
    """
    Emit a run_summary event for single-tenant mode.
    Wazuh rules can detect consecutive failures by matching
    data.op.{stream}_success=false appearing N times in a sliding time window.
    """
    summary: Dict[str, Any] = {
        "source":    "orchestrator",
        "timestamp": utils.utc_now_iso(),
    }

    for stream_name in STREAMS:
        if stream_name in results:
            summary[f"{stream_name}_ran"] = True
            summary[f"{stream_name}_success"] = results[stream_name]
        else:
            summary[f"{stream_name}_ran"] = False

    utils.emit(summary, "run_summary")

    status_parts = []
    for name, success in results.items():
        status_parts.append(f"{name}: {'ok' if success else 'FAILED'}")
    utils.log(1, f"Run complete — {' | '.join(status_parts)}")


def _emit_multi_tenant_summary(all_results: Dict[str, Dict[str, bool]]):
    """Emit a run_summary event for multi-tenant mode."""
    summary: Dict[str, Any] = {
        "source":    "orchestrator",
        "mode":      "multi_tenant",
        "timestamp": utils.utc_now_iso(),
        "tenants":   {},
    }

    for tenant_name, results in all_results.items():
        tenant_summary: Dict[str, Any] = {}
        for stream_name in STREAMS:
            if stream_name in results:
                tenant_summary[f"{stream_name}_ran"] = True
                tenant_summary[f"{stream_name}_success"] = results[stream_name]
            else:
                tenant_summary[f"{stream_name}_ran"] = False
        summary["tenants"][tenant_name] = tenant_summary

    utils.emit(summary, "run_summary")

    for tenant_name, results in all_results.items():
        parts = [f"{n}: {'ok' if s else 'FAILED'}" for n, s in results.items()]
        utils.log(1, f"Tenant {tenant_name} — {' | '.join(parts) if parts else 'skipped'}")


if __name__ == "__main__":
    main()
