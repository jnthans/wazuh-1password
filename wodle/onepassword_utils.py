#!/usr/bin/env python3
"""
onepassword_utils.py – Shared utilities for the 1Password Events API Wazuh wodle.

Covers Bearer token auth, API POST/GET, atomic state file management, structured
JSON emit to stdout, error event emission, debug logging (stderr only),
and RFC 3339 time helpers.

All 1Password event data is emitted under an "op" namespace object preserving
native nested structure (session, location, client, etc.).

Secret loading priority: systemd credentials > .secrets file > env vars.
See configuration.md for details.
"""

import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# ── Module-level config (populated by onepassword.py at startup) ─────────────
config: Dict[str, Any] = {}

# Debug level: 0=off, 1=info, 2=verbose, 3=trace
_debug_level = 0

INTEGRATION_TAG = "1password"
OP_BASE_URL     = "https://events.1password.com"

# Default secrets file path (non-executable, root:wazuh 640)
_DEFAULT_SECRETS_FILE = "/var/ossec/wodles/onepassword/.secrets"

# Maximum seconds to sleep on a 429 Retry-After before giving up
_MAX_RETRY_AFTER_SECS = 60


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def set_debug_level(level: int):
    global _debug_level
    _debug_level = level


def log(level: int, msg: str):
    """Write debug messages to stderr only — never pollutes Wazuh's stdout pipe."""
    if level <= _debug_level:
        prefix = ["", "[INFO]", "[DEBUG]", "[TRACE]"][min(level, 3)]
        print(f"{prefix} {msg}", file=sys.stderr, flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Structured error event emission
# ─────────────────────────────────────────────────────────────────────────────

def emit_error(source: str, error_code: str, message: str, detail: str = ""):
    """
    Emit a structured error event to stdout (ingested and alerted by Wazuh)
    and simultaneously write a message to stderr.

    Every failure condition — API errors, auth failures, rate limits,
    state corruption — calls this function so operators see failures in the
    Wazuh dashboard, not only in log files. Wazuh rules match on the stable
    data.op.error_code field for precise, threshold-based alerting.

    Error code taxonomy:
      API_HTTP_400             Bad request (expired cursor, malformed body)
      API_HTTP_401             Bad or expired bearer token
      API_HTTP_429             Rate limit exceeded (per-minute or per-hour)
      API_HTTP_500             1Password server-side error
      API_HTTP_UNEXPECTED      Any other non-200 HTTP status
      API_TIMEOUT              Request exceeded the configured timeout
      API_CONNECTION_ERROR     Network unreachable, DNS failure, socket error
      API_INVALID_RESPONSE     Response not valid JSON or missing expected keys
      STATE_READ_ERROR         State file exists but cannot be parsed or read
      STATE_WRITE_ERROR        Atomic state write failed
      CONFIG_MISSING_CREDENTIAL  OP_BEARER_TOKEN absent from all sources
      PYTHON_VERSION_ERROR     Python runtime is too old
      ORCHESTRATOR_FATAL       Unhandled top-level exception in main()
      API_UNEXPECTED_ERROR     Unhandled exception inside a source module

    Arguments:
      source:     'audit' | 'signin' | 'itemusage' | 'orchestrator'
      error_code: Stable machine-readable string from taxonomy above
      message:    Human-readable description for Wazuh dashboard display
      detail:     Optional diagnostic context: endpoint, HTTP status, exception text
    """
    print(
        f"[ERROR] [{source}] {error_code}: {message}"
        + (f" | {detail}" if detail else ""),
        file=sys.stderr,
        flush=True,
    )

    op: Dict[str, Any] = {
        "source":        source,
        "error_code":    error_code,
        "error_message": message,
        "timestamp":     utc_now_iso(),
    }
    if detail:
        op["error_detail"] = detail

    emit(op, "error")


# ─────────────────────────────────────────────────────────────────────────────
# HTTP client
# ─────────────────────────────────────────────────────────────────────────────

def _build_bearer_auth_header() -> str:
    """
    Construct the HTTP Bearer Authorization header value.
    The token is read from config at call time so it is never cached
    in a local variable where it could be accidentally surfaced.
    """
    return f"Bearer {config['bearer_token']}"


def api_post(
    path: str,
    body: Dict[str, Any],
    timeout: int = 30,
) -> Tuple[Optional[Dict], int]:
    """
    POST https://events.1password.com{path} with a JSON body.

    Includes automatic single-retry on 429 (rate limit) using the
    Retry-After header, capped at _MAX_RETRY_AFTER_SECS seconds.

    Return conventions:
      (dict,  200)   Successful response with parsed JSON body
      ({},    200)   Successful but empty body
      ({},    4xx)   HTTP client error (auth, rate limit, bad request, etc.)
      ({},    5xx)   HTTP server error
      (None,  -1)    Request timed out
      (None,   0)    Network / connection error (DNS, socket, etc.)

    This function never calls emit_error() — it only logs to stderr at debug
    level. The caller maps the returned status to a taxonomy code and emits.
    """
    base_url = config.get("base_url", OP_BASE_URL)
    url = f"{base_url}{path}"

    headers = {
        "Authorization": _build_bearer_auth_header(),
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }

    json_body = json.dumps(body).encode("utf-8")
    log(2, f"POST {url} body={body}")

    return _do_request(url, headers, json_body, timeout, retry_on_429=True)


def api_get(
    path: str,
    timeout: int = 30,
) -> Tuple[Optional[Dict], int]:
    """
    GET https://events.1password.com{path}

    Used for the introspect endpoint only.

    Return conventions match api_post().
    """
    base_url = config.get("base_url", OP_BASE_URL)
    url = f"{base_url}{path}"

    headers = {
        "Authorization": _build_bearer_auth_header(),
        "Accept":        "application/json",
    }

    log(2, f"GET {url}")
    return _do_request(url, headers, data=None, timeout=timeout, retry_on_429=False)


def _do_request(
    url: str,
    headers: Dict[str, str],
    data: Optional[bytes],
    timeout: int,
    retry_on_429: bool,
) -> Tuple[Optional[Dict], int]:
    """
    Internal HTTP request handler with optional 429 retry.
    """
    method = "POST" if data is not None else "GET"
    req = urllib.request.Request(url, headers=headers, data=data, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            raw = resp.read().decode("utf-8")
            log(3, f"Response ({status}): {raw[:500]}")
            if not raw.strip():
                return {}, status
            try:
                return json.loads(raw), status
            except json.JSONDecodeError as exc:
                log(2, f"JSON decode error from {url}: {exc}")
                return {}, status

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        status_code = exc.code
        log(1, f"HTTP {status_code} from {url}: {body[:400]}")

        # Single retry on 429 with Retry-After header
        if status_code == 429 and retry_on_429:
            retry_after = _parse_retry_after(exc.headers)
            if retry_after is not None and retry_after <= _MAX_RETRY_AFTER_SECS:
                log(1, f"429 rate limited — sleeping {retry_after}s then retrying")
                time.sleep(retry_after)
                return _do_request(url, headers, data, timeout, retry_on_429=False)
            else:
                log(1, f"429 rate limited — Retry-After {retry_after}s exceeds cap, not retrying")

        return {"_response_body": body[:400]}, status_code

    except TimeoutError:
        log(2, f"Timeout calling {url} after {timeout}s")
        return None, -1

    except urllib.error.URLError as exc:
        log(2, f"URL error calling {url}: {exc.reason}")
        return None, 0

    except Exception as exc:
        log(2, f"Unexpected error calling {url}: {exc}")
        return None, 0


def _parse_retry_after(headers) -> Optional[int]:
    """
    Parse the Retry-After header value as an integer number of seconds.
    Returns None if the header is absent or unparseable.
    """
    value = headers.get("Retry-After")
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HTTP status → error code mapping
# ─────────────────────────────────────────────────────────────────────────────

_HTTP_STATUS_ERROR_MAP: Dict[int, str] = {
    400: "API_HTTP_400",
    401: "API_HTTP_401",
    429: "API_HTTP_429",
    500: "API_HTTP_500",
    -1:  "API_TIMEOUT",
    0:   "API_CONNECTION_ERROR",
}

def http_status_to_error_code(status: int) -> str:
    """
    Map an HTTP status code (or sentinel value) to a stable error
    taxonomy code. Centralised here so all stream modules produce
    identical codes for identical conditions, which is essential for
    Wazuh rules that aggregate across sources.
    """
    return _HTTP_STATUS_ERROR_MAP.get(status, "API_HTTP_UNEXPECTED")


# ─────────────────────────────────────────────────────────────────────────────
# State management
# ─────────────────────────────────────────────────────────────────────────────

def _state_path() -> str:
    return config.get("state_file", "/var/ossec/wodles/onepassword/state.json")


def load_state() -> dict:
    """
    Load the state JSON from disk. Returns {} on a missing or corrupt file.

    A corrupt file emits a STATE_READ_ERROR event so the operator is alerted
    that state has been reset. The next run bootstraps from scratch, which
    may cause re-fetching of data within the lookback window.
    """
    path = _state_path()
    if not os.path.isfile(path):
        log(1, f"No state file at {path}, starting fresh")
        return {}

    try:
        with open(path) as f:
            state = json.load(f)
        log(2, f"Loaded state from {path}: {state}")
        return state

    except json.JSONDecodeError as exc:
        emit_error(
            "orchestrator", "STATE_READ_ERROR",
            "State file is corrupt and will be reset — next run bootstraps from scratch",
            detail=f"path={path} error={exc}",
        )
        return {}

    except Exception as exc:
        emit_error(
            "orchestrator", "STATE_READ_ERROR",
            "Cannot read state file",
            detail=f"path={path} error={exc}",
        )
        return {}


def save_state(state: dict, source: str = "orchestrator") -> bool:
    """
    Write state atomically using tempfile + os.replace (atomic on POSIX).

    The old file remains intact until the rename completes — a kill
    mid-write never corrupts existing state.

    Returns True on success. On failure, emits STATE_WRITE_ERROR and returns
    False. Already-emitted events are not affected, but the next run may
    re-fetch from the last successfully checkpointed state.

    source: sub-module requesting the save, included in any error event.
    """
    path = _state_path()
    dir_ = os.path.dirname(path) or "."
    os.makedirs(dir_, exist_ok=True)

    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=dir_, delete=False, suffix=".tmp"
        ) as tmp:
            json.dump(state, tmp)
            tmp_path = tmp.name

        os.replace(tmp_path, path)
        log(2, f"[{source}] Saved state → {path}: {state}")
        return True

    except Exception as exc:
        emit_error(
            source, "STATE_WRITE_ERROR",
            "Failed to persist state — next run may re-fetch already-seen events",
            detail=str(exc),
        )
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Event emission
# ─────────────────────────────────────────────────────────────────────────────

def strip_nulls(obj: Any) -> Any:
    """
    Recursively strip None values and empty strings from a nested structure.

    Applied to the entire 'op' payload before serialisation so that no null
    bytes reach OpenSearch regardless of nesting depth — including nulls inside
    session, location, client, and actor objects.

    Empty arrays and empty dicts are intentionally preserved. An empty
    location object is analytically meaningful (the event was processed but
    no geolocation data was available), whereas a null field carries no
    information and wastes index space.
    """
    if isinstance(obj, dict):
        return {
            k: strip_nulls(v)
            for k, v in obj.items()
            if v is not None and v != ""
        }
    if isinstance(obj, list):
        return [
            strip_nulls(item)
            for item in obj
            if item is not None
        ]
    return obj


def emit(record: dict, record_type: str):
    """
    Emit a single Wazuh-compatible JSON event to stdout.
    Each call produces exactly one newline-terminated JSON line; Wazuh reads
    these via <ignore_output>no</ignore_output> in the wodle command block.

    Output structure:
      {
        "integration": "1password",
        "op": {
          "event_type": "<record_type>",
          ...all 1Password fields, nulls recursively stripped...
        }
      }

    Geolocation: 1Password events include precise latitude/longitude
    coordinates in op.location. A custom Filebeat ingest pipeline processor
    converts data.op.location.latitude + data.op.location.longitude into
    Wazuh's root-level GeoLocation.location geo_point field, enabling map
    visualizations without custom index templates. See
    artifacts/guides/geopoint_setup.md for setup.

    event_type is placed INSIDE the op object so that rule <field> tags can
    reference it as op.event_type — consistent with all other op.* fields.

    Field access patterns:
      In Wazuh rules:  <field name="op.event_type">^audit_event$</field>
                       <field name="op.action">^grant$</field>
      In OpenSearch:   data.op.event_type : "audit_event"
                       data.op.location.country : "US"
      GeoLocation:     GeoLocation.location (geo_point for maps)
    """
    op = strip_nulls(record)
    op["event_type"] = record_type  # insert after null-stripping so it is never dropped

    out = {
        "integration": INTEGRATION_TAG,
        "op":          op,
    }

    line = json.dumps(out)
    print(line, flush=True)
    log(3, f"Emitted ({record_type}): {line[:200]}")


# ─────────────────────────────────────────────────────────────────────────────
# Time helpers
# ─────────────────────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """Return the current UTC time as an RFC 3339 string (Zulu notation)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now_rfc3339() -> str:
    """Return the current UTC time as an RFC 3339 string for 1Password API requests."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def epoch_now() -> float:
    """Return the current UTC time as a Unix epoch float."""
    return time.time()


def epoch_to_iso(epoch: float) -> str:
    """Convert a Unix epoch float to an RFC 3339 UTC string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_to_epoch(iso: str) -> float:
    """
    Parse an RFC 3339 UTC string to a Unix epoch float.
    Handles 'Z' suffix, '.000Z' millisecond variants, and microsecond variants
    returned by 1Password's event timestamp fields.
    """
    # Strip sub-second precision: "2026-03-01T14:00:00.123456Z" → "2026-03-01T14:00:00Z"
    if "." in iso:
        iso = iso.split(".")[0] + "Z"
    # Normalise 'Z' → '+00:00' for fromisoformat() (Python < 3.11 rejects 'Z')
    iso = iso.replace("Z", "+00:00")
    return datetime.fromisoformat(iso).timestamp()


def lookback_start_time(lookback_hours: float) -> str:
    """
    Calculate an RFC 3339 start_time for the 1Password Events API
    based on a lookback window in hours from now.
    """
    epoch = epoch_now() - (lookback_hours * 3600)
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ─────────────────────────────────────────────────────────────────────────────
# Secret loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_from_systemd_credentials() -> dict:
    """
    Read secrets injected by systemd via LoadCredential / LoadCredentialEncrypted.
    The $CREDENTIALS_DIRECTORY is memory-backed and encrypted at rest on
    systems with a TPM — the highest-security credential source available.
    Returns a dict with 'bearer_token' if the credential file exists.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not creds_dir or not os.path.isdir(creds_dir):
        return {}

    found: Dict[str, str] = {}
    cred_path = os.path.join(creds_dir, "op_bearer_token")
    if os.path.isfile(cred_path):
        try:
            with open(cred_path) as f:
                found["bearer_token"] = f.read().strip()
            log(2, "Loaded 'bearer_token' from systemd credentials directory")
        except Exception as exc:
            log(1, f"Could not read systemd credential 'op_bearer_token': {exc}")
    return found


def _load_from_secrets_file(path: str) -> dict:
    """
    Read a simple KEY=value secrets file (no subshell evaluation).

    Expected format:
        OP_BEARER_TOKEN=your-bearer-token-here

    Lines starting with '#' and blank lines are silently skipped.
    Recommended file permissions: chmod 640, chown root:wazuh
    """
    if not path or not os.path.isfile(path):
        return {}

    found:   Dict[str, str] = {}
    mapping: Dict[str, str] = {
        "OP_BEARER_TOKEN": "bearer_token",
    }

    try:
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    log(2, f"Secrets file line {lineno} skipped (no '=')")
                    continue
                key, _, value = line.partition("=")
                key   = key.strip()
                value = value.strip().strip('"').strip("'")
                if key in mapping:
                    found[mapping[key]] = value
                    log(2, f"Loaded '{mapping[key]}' from secrets file")

    except PermissionError:
        print(
            f"[ERROR] Cannot read secrets file {path} — "
            "check ownership (root:wazuh) and permissions (640)",
            file=sys.stderr,
        )
    except Exception as exc:
        log(1, f"Error reading secrets file {path}: {exc}")

    return found


def load_secrets():
    """
    Populate config['bearer_token'].

    Priority (first match wins):
      1. systemd $CREDENTIALS_DIRECTORY  (memory-backed, encrypted at rest)
      2. Secrets file                    ($OP_SECRETS_FILE or default path)
      3. Environment variable            ($OP_BEARER_TOKEN)

    Credential values are never logged. Only the winning source name is
    written at debug level 2.
    """
    from_env: Dict[str, str] = {
        "bearer_token": os.environ.get("OP_BEARER_TOKEN", ""),
    }
    from_file    = _load_from_secrets_file(
                       os.environ.get("OP_SECRETS_FILE", _DEFAULT_SECRETS_FILE))
    from_systemd = _load_from_systemd_credentials()

    merged = {**from_env, **from_file, **from_systemd}
    config["bearer_token"] = merged.get("bearer_token", "")

    sources = [("env", from_env), ("file", from_file), ("systemd", from_systemd)]
    winner = "not set"
    for src_name, src_dict in reversed(sources):
        if src_dict.get("bearer_token"):
            winner = src_name
            break
    log(2, f"Secret 'bearer_token' sourced from: {winner}")


# ─────────────────────────────────────────────────────────────────────────────
# Config validation (called once at startup by onepassword.py)
# ─────────────────────────────────────────────────────────────────────────────

def validate_config():
    """
    Load secrets and verify the bearer token is present.
    Emits a CONFIG_MISSING_CREDENTIAL error event (visible in the Wazuh
    dashboard) before exiting — failures are never silently buried in logs.
    """
    load_secrets()

    if not config.get("bearer_token"):
        emit_error(
            "orchestrator", "CONFIG_MISSING_CREDENTIAL",
            "Missing required 1Password bearer token — integration cannot start",
            detail="OP_BEARER_TOKEN / secrets file / systemd credential (op_bearer_token)",
        )
        sys.exit(1)

    log(1,
        f"Config OK — "
        f"bearer_token={'*' * 8} (len={len(config['bearer_token'])}) "
        f"state={config.get('state_file', 'default')} "
        f"base_url={config.get('base_url', OP_BASE_URL)}"
    )
