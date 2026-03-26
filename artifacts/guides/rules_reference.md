# Rules Reference

## Rule ID Allocation

| Range | Category | Count |
|-------|----------|-------|
| 100700 | Base rule (all 1Password events) | 1 |
| 100701–100709 | Integration health (errors, run summary) | 9 |
| 100710–100724 | Audit events (admin actions) | 15 |
| 100730–100736 | Sign-in attempts | 7 |
| 100740–100747 | Item usage events | 8 |
| 100750–100754 | Composite / correlation | 5 |
| **Total** | | **45** |

---

## Integration Health Rules (100701–100709)

| ID | Level | Description |
|----|-------|-------------|
| 100701 | 8 | Any error event from any source |
| 100702 | 12 | Credential / auth failure (401 or missing token) |
| 100703 | 8 | Rate limit reached (429) |
| 100704 | 8 | Network / connectivity failure |
| 100705 | 8 | State file read or write error |
| 100706 | 10 | Audit stream failure in run summary |
| 100707 | 10 | Sign-in stream failure in run summary |
| 100708 | 6 | Item usage stream failure in run summary |
| 100709 | 14 | Repeated credential failures (2 in 10 min) |

---

## Audit Event Rules (100710–100724)

| ID | Level | Description |
|----|-------|-------------|
| 100710 | 3 | Base audit event |
| 100711 | 5 | User provisioning / deprovisioning (activate, deactivate, delete) |
| 100712 | 5 | Group membership change |
| 100713 | 8 | Vault access permissions change |
| 100714 | 10 | Security policy change |
| 100715 | 10 | Service account created / modified |
| 100716 | 12 | Account recovery initiated |
| 100717 | 10 | Firewall rule change |
| 100718 | 10 | Data export (potential exfiltration) |
| 100719 | 5 | Billing / subscription change |
| 100720 | 10 | SSO / integration configuration change |
| 100721 | 10 | MFA settings changed |
| 100722 | 8 | Vault created or deleted |
| 100723 | 10 | Master password changed |
| 100724 | 8 | Token revoked |

---

## Sign-In Attempt Rules (100730–100736)

| ID | Level | Description |
|----|-------|-------------|
| 100730 | 3 | Base sign-in attempt |
| 100731 | 3 | Successful sign-in |
| 100732 | 5 | Failed sign-in (credentials or MFA) |
| 100733 | 8 | Firewall-blocked sign-in |
| 100734 | 3 | SSO / passkey sign-in |
| 100735 | 12 | Multiple failed sign-ins same user (3 in 10 min) |
| 100736 | 10 | Repeated firewall blocks (5 in 10 min) |

---

## Item Usage Rules (100740–100747)

| ID | Level | Description |
|----|-------|-------------|
| 100740 | 3 | Base item usage event |
| 100741 | 5 | Item revealed or copied |
| 100742 | 8 | Item exported |
| 100743 | 8 | Item shared |
| 100744 | 5 | Server-side item operation (Connect) |
| 100745 | 3 | SSO provider selected |
| 100746 | 10 | Bulk item access same user (10 in 5 min) |
| 100747 | 12 | Multiple exports same user (3 in 10 min) |

---

## Correlation Rules (100750–100754)

| ID | Level | Description |
|----|-------|-------------|
| 100750 | 12 | Repeated stream failures (3 in 10 min) |
| 100751 | 12 | High volume failed sign-ins (10 in 10 min) |
| 100752 | 12 | Multiple policy changes (3 in 10 min) |
| 100753 | 10 | Multiple vault access changes (5 in 10 min) |
| 100754 | 10 | Multiple service account operations (3 in 10 min) |

---

## Field Reference

### Common Fields (all event types)

| Rule Field | OpenSearch Field | Description |
|------------|-----------------|-------------|
| `op.event_type` | `data.op.event_type` | Event type: `audit_event`, `signin_attempt`, `item_usage`, `error`, `run_summary` |
| `op.source` | `data.op.source` | Source module (error/summary events only) |
| `op.error_code` | `data.op.error_code` | Error taxonomy code (error events only) |

### Audit Event Fields

| Rule Field | OpenSearch Field | Description |
|------------|-----------------|-------------|
| `op.uuid` | `data.op.uuid` | Event UUID |
| `op.timestamp` | `data.op.timestamp` | When the action occurred |
| `op.actor_uuid` | `data.op.actor_uuid` | UUID of the acting user |
| `op.action` | `data.op.action` | Action type (create, delete, grant, update, etc.) |
| `op.object_type` | `data.op.object_type` | Object type (v=vault, gm=group member, p=policy, etc.) |
| `op.object_uuid` | `data.op.object_uuid` | UUID of the affected object |

### Sign-In Attempt Fields

| Rule Field | OpenSearch Field | Description |
|------------|-----------------|-------------|
| `op.uuid` | `data.op.uuid` | Event UUID |
| `op.timestamp` | `data.op.timestamp` | When the attempt occurred |
| `op.category` | `data.op.category` | Result: `success`, `credentials_failed`, `mfa_failed`, `firewall_failed` |
| `op.type` | `data.op.type` | Method: `password`, `sso`, `passkey` |
| `op.country` | `data.op.country` | Two-letter country code |
| `op.target_user.uuid` | `data.op.target_user.uuid` | UUID of the user signing in |
| `op.target_user.name` | `data.op.target_user.name` | Name of the user signing in |
| `op.client.app_name` | `data.op.client.app_name` | Client application name |

### Item Usage Fields

| Rule Field | OpenSearch Field | Description |
|------------|-----------------|-------------|
| `op.uuid` | `data.op.uuid` | Event UUID |
| `op.timestamp` | `data.op.timestamp` | When the usage occurred |
| `op.action` | `data.op.action` | Action: `fill`, `reveal`, `secure-copy`, `export`, `share`, etc. |
| `op.user.uuid` | `data.op.user.uuid` | UUID of the user |
| `op.user.name` | `data.op.user.name` | Name of the user |
| `op.vault_uuid` | `data.op.vault_uuid` | UUID of the vault |
| `op.item_uuid` | `data.op.item_uuid` | UUID of the item |
| `op.client.app_name` | `data.op.client.app_name` | Client application name |

---

## Error Code Taxonomy

| Code | Description |
|------|-------------|
| `API_HTTP_400` | Bad request (expired cursor, malformed body) |
| `API_HTTP_401` | Invalid or expired bearer token |
| `API_HTTP_429` | Rate limit exceeded |
| `API_HTTP_500` | 1Password server error |
| `API_HTTP_UNEXPECTED` | Any other non-200 HTTP status |
| `API_TIMEOUT` | Request timed out |
| `API_CONNECTION_ERROR` | Network / DNS failure |
| `API_INVALID_RESPONSE` | Response not valid JSON or missing fields |
| `STATE_READ_ERROR` | State file corrupt or unreadable |
| `STATE_WRITE_ERROR` | Atomic state write failed |
| `CONFIG_MISSING_CREDENTIAL` | Bearer token absent from all sources |
| `PYTHON_VERSION_ERROR` | Python < 3.8 |
| `ORCHESTRATOR_FATAL` | Unhandled top-level exception |
| `API_UNEXPECTED_ERROR` | Unhandled exception in fetch module |
