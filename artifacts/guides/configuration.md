# Configuration Reference

All runtime configuration is set as environment variables in `run.sh`. Credentials use the secure loading chain described below.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OP_BEARER_TOKEN` | *(required)* | 1Password Events API bearer token. Set via `.secrets` file (recommended), systemd credentials, or environment variable. |
| `OP_SOURCE` | `all` | Which event streams to poll: `audit`, `signin`, `itemusage`, or `all`. |
| `OP_LOOKBACK_HOURS` | `24` | Hours to look back on first run (no existing state) or in `--all` mode. Default 24 hours gives day-one dashboard visibility. 1Password retains events for 120 days — values beyond that have no effect. |
| `OP_STATE_FILE` | `/var/ossec/wodles/onepassword/state.json` | Path to the cursor/state persistence file. Must be writable by the wazuh user. |
| `OP_SECRETS_FILE` | `/var/ossec/wodles/onepassword/.secrets` | Path to the secrets file containing `OP_BEARER_TOKEN`. |
| `OP_BASE_URL` | `https://events.1password.com` | API base URL. Override for EU tenants (`https://events.ent.1password.com`) or testing. |
| `OP_PAGE_LIMIT` | `100` | Events per API request (1-1000). Increase for high-volume accounts. |
| `OP_DEBUG` | `0` | Debug verbosity to stderr: 0=off, 1=info, 2=verbose, 3=trace. |
| `OP_TOKENS_FILE` | *(none)* | Path to multi-tenant tokens JSON file. When set, enables MSP mode. |

---

## CLI Flags

```
onepassword.py [--source SOURCE] [-a] [-l HOURS] [-d LEVEL]

  --source SOURCE    audit | signin | itemusage | all (default: all)
  -a, --all          TEST/BACKFILL: ignore state; do not update state
  -l, --lookback H   Hours to look back (default: OP_LOOKBACK_HOURS or 1)
  -d, --debug LEVEL  0=off 1=info 2=verbose 3=trace
```

CLI flags take precedence over environment variables for `--source`, `--lookback`, and `--debug`.

---

## Credential Priority Chain

The bearer token is loaded from the first available source (highest priority first):

1. **systemd credentials** (`$CREDENTIALS_DIRECTORY/op_bearer_token`)
   Most secure — memory-backed, encrypted at rest on systems with a TPM.

2. **Secrets file** (`$OP_SECRETS_FILE` or default path)
   Plain-text `KEY=VALUE` file. Recommended permissions: `chmod 640, chown root:wazuh`.

3. **Environment variable** (`$OP_BEARER_TOKEN`)
   Least secure — visible in process listings. Use only for testing.

Credential values are never written to logs. Only the winning source name is logged at debug level 2.

---

## Secrets File Format

Create `.secrets` from `.secrets.example`:

```
# 1Password Events API credentials
OP_BEARER_TOKEN=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
```

- Lines starting with `#` are comments
- Blank lines are ignored
- Values may be quoted (single or double)
- No subshell evaluation

---

## State File

The state file tracks cursor positions for each event stream:

```json
{
  "audit_cursor": "eyJhbGci...",
  "audit_last_poll": "2026-03-22T10:00:00Z",
  "signin_cursor": "eyJhbGci...",
  "signin_last_poll": "2026-03-22T10:00:00Z",
  "itemusage_cursor": "eyJhbGci...",
  "itemusage_last_poll": "2026-03-22T10:00:00Z"
}
```

- **First run**: Uses `start_time` (now minus lookback hours). No cursor exists.
- **Subsequent runs**: Uses the stored cursor. The API resumes from the exact position.
- **`--all` mode**: Uses `start_time` from lookback. State is NOT updated.
- **State reset**: Delete the state file to force a fresh start from the lookback window.

In multi-tenant mode, state keys are namespaced per tenant:

```json
{
  "client-a.audit_cursor": "eyJhbGci...",
  "client-a.audit_last_poll": "2026-03-22T10:00:00Z",
  "client-b.signin_cursor": "eyJhbGci...",
  "client-b.signin_last_poll": "2026-03-22T10:00:00Z"
}
```

Writes are atomic (`tempfile` + `os.replace`). A process kill mid-write never corrupts the existing state.

---

## Multi-Tenant / MSP Mode

For MSSPs/MSPs monitoring multiple client 1Password accounts from a single Wazuh installation:

1. Create `tenants.json` from the provided template:
   ```bash
   cp /var/ossec/wodles/onepassword/.tenants.example.json /var/ossec/wodles/onepassword/tenants.json
   ```

2. Edit `tenants.json` — add each client's name and bearer token:
   ```json
   {
     "tenants": [
       {
         "name": "client-a",
         "bearer_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.client-a-token"
       },
       {
         "name": "client-b",
         "bearer_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.client-b-token"
       }
     ]
   }
   ```

   Tenant names must contain only letters, numbers, hyphens, and underscores.

3. Set file permissions:
   ```bash
   chmod 640 /var/ossec/wodles/onepassword/tenants.json
   chown root:wazuh /var/ossec/wodles/onepassword/tenants.json
   ```

4. Uncomment and set `OP_TOKENS_FILE` in `run.sh`:
   ```bash
   export OP_TOKENS_FILE="/var/ossec/wodles/onepassword/tenants.json"
   ```

5. Restart the Wazuh manager:
   ```bash
   systemctl restart wazuh-manager
   ```

**How it works:**
- When `OP_TOKENS_FILE` is set, `OP_BEARER_TOKEN` / `.secrets` are ignored — all tokens come from the tenants file.
- Each tenant is polled sequentially within a single wodle run.
- State cursors are namespaced per tenant: `client-a.audit_cursor`, `client-b.signin_cursor`, etc.
- Each emitted event includes the tenant name for filtering in rules and dashboards.
- The introspect endpoint is called per tenant to validate tokens and discover features.

---

## EU Tenants

1Password has separate infrastructure for EU accounts. Override the base URL:

```bash
export OP_BASE_URL="https://events.ent.1password.com"
```

---

## Rate Limits

The 1Password Events API enforces per-minute and per-hour rate limits. The wodle handles 429 responses automatically:

1. Reads the `Retry-After` header
2. Sleeps for the specified duration (capped at 60 seconds)
3. Retries the request once
4. If the retry also returns 429, emits an error event and moves on

At a 5-minute polling interval with 3 streams, typical usage is 3-10 requests per run — well within limits.
