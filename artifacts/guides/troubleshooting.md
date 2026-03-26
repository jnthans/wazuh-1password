# Troubleshooting

## Quick Test Commands

### 1. Test all streams (no state update)

```bash
cd /var/ossec/wodles/onepassword
./run.sh --all --debug 1
```

Expected: JSON lines on stdout, debug messages on stderr. State is not updated.

### 2. Test a single stream

```bash
./run.sh --source audit --all --lookback 1 --debug 2
```

Expected: Only audit events, verbose debug output.

### 3. Test with a 24-hour lookback

```bash
./run.sh --all --lookback 24 --debug 1
```

Expected: All events from the last 24 hours across all streams.

### 4. Validate bearer token only

```bash
cd /var/ossec/wodles/onepassword
python3 -c "
import onepassword_utils as utils
utils.config['bearer_token'] = 'YOUR_TOKEN_HERE'
utils.config['base_url'] = 'https://events.1password.com'
from onepassword_events import introspect
data, ok = introspect()
print('OK' if ok else 'FAILED')
if data:
    print(f'Features: {data.get(\"features\", [])}')
    print(f'Account:  {data.get(\"account_uuid\", \"\")}')
"
```

### 5. Check if the wodle is running

```bash
# Check wodle process
ps aux | grep onepassword

# Check Wazuh logs for wodle output
grep -i onepassword /var/ossec/logs/ossec.log | tail -20
```

### 6. Check decoded events in Wazuh

```bash
# Test the decoder with a sample event
echo '{"integration":"1password","op":{"event_type":"audit_event","action":"create","object_type":"v","actor_uuid":"ABC123"}}' | /var/ossec/bin/wazuh-logtest
```

### 7. Inspect state file

```bash
cat /var/ossec/wodles/onepassword/state.json | python3 -m json.tool
```

---

## Common Errors

### CONFIG_MISSING_CREDENTIAL

**Symptom**: Integration exits immediately with error event.

**Cause**: Bearer token not found in any source.

**Fix**:
1. Verify `.secrets` file exists and contains `OP_BEARER_TOKEN=...`
2. Check file permissions: `ls -la /var/ossec/wodles/onepassword/.secrets`
3. Should be `root:wazuh` with mode `640`
4. Run with `--debug 2` to see which source was checked

### API_HTTP_401

**Symptom**: Authentication failed error events.

**Cause**: Bearer token is invalid, expired, or revoked.

**Fix**:
1. Log into 1Password admin console
2. Navigate to Integrations > Events Reporting
3. Verify the integration is active and the token hasn't been revoked
4. Generate a new token if needed
5. Update `.secrets` and restart the manager

### API_HTTP_429

**Symptom**: Rate limit error events, possibly after recovery from a long outage.

**Cause**: Too many API requests in the rate limit window.

**Fix**:
1. The wodle automatically retries once with the `Retry-After` header
2. If persistent, increase the wodle `<interval>` in ossec.conf
3. Reduce `OP_PAGE_LIMIT` to decrease per-run request count
4. If in MSP mode with many tenants, consider spreading tenants across multiple wodle instances

### Fewer events than expected

**Symptom**: First run returns fewer events than expected for the lookback window.

**Cause**: The 1Password Events API retains events for **120 days**. Events older than that are not available via the API. Additionally, low-activity periods may genuinely have few events. Run with `--debug 2` to confirm the `start_time` in the request body matches your expected lookback window.

For events older than 120 days, use the audit log in the 1Password admin console.

### API_HTTP_400

**Symptom**: Bad request errors, possibly with cursor-related messages.

**Cause**: Cursor has expired (1Password cursors may have a TTL).

**Fix**:
1. The wodle automatically falls back to `start_time` on cursor rejection
2. If persistent, delete the state file to force a fresh start:
   ```bash
   rm /var/ossec/wodles/onepassword/state.json
   systemctl restart wazuh-manager
   ```

### STATE_READ_ERROR / STATE_WRITE_ERROR

**Symptom**: State file corruption or write failures.

**Cause**: Disk full, permission issue, or filesystem corruption.

**Fix**:
1. Check disk space: `df -h /var/ossec/wodles/onepassword/`
2. Check permissions: `ls -la /var/ossec/wodles/onepassword/state.json`
3. File should be writable by the `wazuh` user
4. Delete corrupt state file to reset: `rm state.json`

### No events appearing in Wazuh dashboard

**Checklist**:
1. Is the wodle enabled? Check `<disabled>no</disabled>` in ossec.conf
2. Is `<ignore_output>no</ignore_output>` set? (must be `no` to ingest)
3. Is the decoder installed? Check `/var/ossec/etc/decoders/onepassword_decoder.xml`
4. Are rules installed? Check `/var/ossec/etc/rules/onepassword_rules.xml`
5. Did you restart the manager after changes?
6. Run the wodle manually with `--debug 1` — are JSON lines being emitted?
7. Check `ossec.log` for decoder errors

---

## State Reset

To force a complete re-fetch from the lookback window:

```bash
rm /var/ossec/wodles/onepassword/state.json
systemctl restart wazuh-manager
```

The next run will use `OP_LOOKBACK_HOURS` (default 1 hour) as the starting point.

---

## Backfill Historical Data

To backfill a specific time range without affecting production state:

```bash
# Backfill 7 days of data (events will be ingested but state won't be updated)
./run.sh --all --lookback 168 --debug 1

# Backfill only sign-in attempts
./run.sh --source signin --all --lookback 48 --debug 1
```

Note: `--all` mode does NOT update the state file, so production polling continues normally from its last cursor position.

---

## Concurrent Invocations

The wodle does not use file locking — only one instance should run at a time. If two instances overlap (e.g., the previous run hasn't finished before the next interval triggers), both will load the same state and may produce duplicate events. Wazuh's wodle scheduler prevents this by default, but if you run the wodle manually while the scheduled instance is active, duplicates can occur.

---

## Multi-Tenant Debugging

When using MSP mode with `OP_TOKENS_FILE`:

```bash
# Test all tenants with verbose output
OP_TOKENS_FILE=/path/to/tenants.json ./run.sh --all --debug 2

# Check tenant-namespaced state
cat state.json | python3 -m json.tool
# Expected: "client-a.audit_cursor", "client-b.signin_cursor", etc.
```

If a specific tenant's token is failing:
1. Check the introspect output in debug logs
2. Verify the tenant's token independently (see "Validate bearer token only" above)
3. Check if the tenant has Events Reporting enabled in their 1Password admin console
