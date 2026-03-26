#!/usr/bin/env python3
"""
onepassword_events.py – Generic cursor-paginated event fetcher for 1Password Events API v2.

All three 1Password event endpoints (auditevents, signinattempts, itemusages)
share an identical interface: POST with JSON body, cursor-based pagination,
and the same response schema. This module provides a single generic function
that handles all three.

Public surface:
  count, cursor = fetch_and_emit_stream(stream_name, endpoint, event_type,
                                        cursor, start_time, limit)
  Returns (int, str | None). None cursor signals a failure.
"""

import os
import sys
from typing import Any, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import onepassword_utils as utils


# ─────────────────────────────────────────────────────────────────────────────
# Error messages
# ─────────────────────────────────────────────────────────────────────────────

_ERROR_MESSAGES: Dict[int, str] = {
    400: "Bad request — cursor may be expired or request body malformed",
    401: "Authentication failed — verify OP_BEARER_TOKEN is correct and not expired",
    429: "1Password Events API rate limit reached — retry after backoff",
    500: "1Password Events API returned an internal server error",
    -1:  "1Password Events API request timed out",
    0:   "1Password Events API unreachable — verify network connectivity to events.1password.com",
}


def _http_error_message(status: int) -> str:
    """Operator-friendly message for known HTTP status codes and sentinels."""
    return _ERROR_MESSAGES.get(
        status,
        f"1Password Events API returned an unexpected HTTP {status} status",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────────────────────────────────────────

def fetch_and_emit_stream(
    stream_name: str,
    endpoint: str,
    event_type: str,
    cursor: Optional[str],
    start_time: Optional[str],
    limit: int = 100,
) -> Tuple[int, Optional[str]]:
    """
    Fetch all available events from a 1Password Events API v2 endpoint
    using cursor-based pagination, emitting each event to Wazuh.

    The 1Password Events API uses cursor-based pagination:
    - First request: POST with {"start_time": "RFC3339", "limit": N}
    - Subsequent requests: POST with {"cursor": "...", "limit": N}
    - Response: {"cursor": "...", "has_more": bool, "items": [...]}
    - Continue until has_more is false.

    Arguments:
      stream_name: Human-readable label for logging (e.g. "audit")
      endpoint:    API path (e.g. "/api/v2/auditevents")
      event_type:  Wazuh event type string (e.g. "audit_event")
      cursor:      Cursor from previous run's state, or None for first fetch
      start_time:  RFC 3339 start time for first fetch (used when cursor is None)
      limit:       Events per page (1-1000, default 100)

    Returns:
      (count, new_cursor)  on success — count may be 0, cursor is always set
      (0,     None)        on any failure — error event already emitted
    """
    total_emitted = 0
    page = 0
    current_cursor = cursor

    while True:
        page += 1

        # Build request body
        body = _build_request_body(current_cursor, start_time, limit)
        utils.log(2, f"{stream_name} page {page}: POST {endpoint} body={body}")

        # Make API call
        data, status = utils.api_post(endpoint, body)

        # ── HTTP / network failure ───────────────────────────────────────
        if data is None or status != 200:
            api_body = data.get("_response_body", "") if isinstance(data, dict) else ""

            # Handle expired cursor: fall back to start_time if available
            if status == 400 and current_cursor and start_time:
                utils.log(1,
                    f"{stream_name}: cursor rejected (400), falling back to start_time={start_time}"
                )
                utils.emit_error(
                    source=stream_name,
                    error_code="API_HTTP_400",
                    message=f"Cursor rejected — falling back to start_time (some events may be duplicated or missed)",
                    detail=f"endpoint={endpoint} status={status}",
                )
                # Reset to start_time and retry
                current_cursor = None
                continue

            if api_body:
                utils.log(1, f"{stream_name} error body [{status}]: {api_body}")
            utils.emit_error(
                source=stream_name,
                error_code=utils.http_status_to_error_code(status),
                message=_http_error_message(status),
                detail=f"endpoint={endpoint} status={status}",
            )
            return 0, None

        # ── Response structure validation ────────────────────────────────
        if not isinstance(data, dict):
            utils.emit_error(
                source=stream_name,
                error_code="API_INVALID_RESPONSE",
                message=f"{stream_name} response is not a JSON object",
                detail=f"type={type(data).__name__}",
            )
            return 0, None

        items = data.get("items")
        new_cursor = data.get("cursor")
        has_more = data.get("has_more", False)

        if items is None or not isinstance(items, list):
            utils.emit_error(
                source=stream_name,
                error_code="API_INVALID_RESPONSE",
                message=f"{stream_name} response is missing or has invalid 'items' array",
                detail=f"keys={list(data.keys())}",
            )
            return 0, None

        if not new_cursor or not isinstance(new_cursor, str):
            utils.emit_error(
                source=stream_name,
                error_code="API_INVALID_RESPONSE",
                message=f"{stream_name} response is missing the 'cursor' field",
                detail=f"keys={list(data.keys())}",
            )
            return 0, None

        # ── Emit events ──────────────────────────────────────────────────
        page_count = 0
        for item in items:
            if not isinstance(item, dict):
                utils.log(2, f"{stream_name}: skipping non-dict entry on page {page}")
                continue
            utils.emit(item, event_type)
            page_count += 1

        total_emitted += page_count
        current_cursor = new_cursor
        utils.log(2, f"{stream_name} page {page}: {page_count} events, has_more={has_more}")

        # ── Pagination ───────────────────────────────────────────────────
        if not has_more:
            break

    utils.log(1, f"{stream_name}: {total_emitted} events across {page} page(s)")
    return total_emitted, current_cursor


# ─────────────────────────────────────────────────────────────────────────────
# Request body construction
# ─────────────────────────────────────────────────────────────────────────────

def _build_request_body(
    cursor: Optional[str],
    start_time: Optional[str],
    limit: int,
) -> Dict[str, Any]:
    """
    Build the POST request body for a 1Password Events API v2 endpoint.

    The v2 API uses two request formats:
      - Reset cursor (first fetch): {"ResetCursor": {"limit": N, "start_time": "RFC3339"}}
      - Continuing cursor (subsequent): {"cursor": "opaque-string"}

    Note: The v1 API used flat top-level fields, but v2 requires the
    ResetCursor wrapper object for initial requests.
    """
    if cursor:
        return {"cursor": cursor}
    reset_cursor: Dict[str, Any] = {"limit": limit}
    if start_time:
        reset_cursor["start_time"] = start_time
    return {"ResetCursor": reset_cursor}


# ─────────────────────────────────────────────────────────────────────────────
# Introspect endpoint
# ─────────────────────────────────────────────────────────────────────────────

def introspect() -> Tuple[Optional[Dict], bool]:
    """
    Call GET /api/v2/auth/introspect to validate the bearer token
    and discover which event types are authorized.

    Returns:
      (introspect_data, success)
      introspect_data includes: uuid, features (list), account_uuid, issued_at

    On failure, emits an error event and returns (None, False).
    """
    data, status = utils.api_get("/api/v2/auth/introspect")

    if data is None or status != 200:
        api_body = data.get("_response_body", "") if isinstance(data, dict) else ""
        utils.emit_error(
            source="orchestrator",
            error_code=utils.http_status_to_error_code(status),
            message=f"Introspect call failed — cannot validate bearer token",
            detail=f"endpoint=/api/v2/auth/introspect status={status}" +
                   (f" body={api_body}" if api_body else ""),
        )
        return None, False

    if not isinstance(data, dict):
        utils.emit_error(
            source="orchestrator",
            error_code="API_INVALID_RESPONSE",
            message="Introspect response is not a JSON object",
        )
        return None, False

    features = data.get("features", [])
    account_uuid = data.get("account_uuid", "")
    utils.log(1, f"Introspect OK — features={features} account_uuid={account_uuid}")
    return data, True
