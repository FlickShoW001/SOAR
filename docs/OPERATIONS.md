# Operations Guide

## Daily operator workflow

1. Open the command center and confirm **Audit chain integrity** is verified.
2. Review the latest detection stream and elevated severity events.
3. Open event intelligence to inspect the raw evidence, enrichment, risk, confidence, approval rationale, and audit history.
4. Process the approval queue. Rejections require a meaningful reason.
5. Confirm response results and investigate `response_failed` or `processing_failed` states.
6. Escalate any audit integrity warning immediately.

## Health and monitoring

`GET /health` verifies database connectivity and the latest 100 audit entries.

Healthy response:

```json
{
  "status": "healthy",
  "database": "connected",
  "audit_chain": "valid"
}
```

The endpoint returns HTTP 503 when the database is unavailable or the audit segment is invalid. Monitor both status code and response body.

Recommended operational signals:

- Application process availability
- `/health` status and latency
- Login failures at the reverse proxy or identity layer
- Counts of `pending_approval`, `response_failed`, and `processing_failed`
- AbuseIPDB timeouts, authentication failures, and rate limits
- Audit verification failures
- Netmiko connection and command failures
- Database size, filesystem capacity, and backup age

## Configuration changes

Configuration is loaded at process startup. Restart after editing `.env` or `config.yaml`.

Before changing risk weights or thresholds:

1. Record the change request and expected outcome.
2. Confirm weights and thresholds use numeric YAML values.
3. Replay representative lab events.
4. Compare actions, scores, and approval requirements.
5. Retain simulation mode through validation.
6. Restart and verify `/health`.

## Database operations

The default database is `soar.db`. Stop the application or use a SQLite-safe backup procedure before copying it. Preserve file permissions and test restoration regularly.

Do not manually edit `audit_log` or `audit_anchor`. A legitimate manual change will invalidate integrity verification and destroy evidentiary value.

## Failure triage

### `processing_failed`

The event was persisted, but enrichment, decisioning, or audit processing raised an unexpected exception.

1. Inspect application logs around the event timestamp.
2. Check AbuseIPDB availability and credentials.
3. Validate `config.yaml` types and required mappings.
4. Confirm database write access and capacity.
5. Do not rewrite the event state manually; resubmit only under an established replay procedure.

### `response_failed`

Common causes:

- Source IP outside `LAB_ALLOWED_IPS`
- IPv6 target with the current IPv4-only responder
- Unsupported device type
- Missing device credentials
- Device IP outside the allow-list
- Connection, command, or commit failure

Review the event audit trail and service logs. Keep simulation enabled while correcting the issue.

### Audit integrity warning

Treat this as a security incident or data-integrity incident.

1. Stop approval and response activity.
2. Preserve a forensic copy of the database, external anchor, and logs.
3. Verify storage health and recent administrative actions.
4. Compare the local and external chain head.
5. Restore service only after the cause and evidence-handling decision are documented.

### Dashboard does not update

- Confirm `/health` succeeds.
- Check browser console and network errors.
- Confirm the session has not expired.
- Verify `/dashboard/data` returns JSON for the signed-in user.
- A `304` response is normal when nothing changed.

## Enrichment behavior

Successful AbuseIPDB results are cached in memory by source IP. A cache hit still creates an event-specific database row for traceability. Cache contents disappear on restart and are not shared between workers.

API failures create enrichment rows with neutral scores plus an error description. Approval rules treat failed or unknown enrichment conservatively.

## Response execution

Simulation and dry-run are independent safeguards: either one keeps the connector from opening a device session. Live response requires both to be `false`.

Review generated ACL/filter commands for the chosen platform before enabling live changes. Device configuration is environment-specific; the application cannot infer operational intent, interface topology, or rollback safety.

## Maintenance checklist

- [ ] Verify backups and restore tests.
- [ ] Rotate administrator, operator, API, and device credentials.
- [ ] Review users and roles.
- [ ] Inspect failure-state trends.
- [ ] Confirm audit-anchor storage remains separately protected.
- [ ] Review allow-list scope.
- [ ] Validate simulation behavior after dependency or device changes.
- [ ] Re-run the regression suite before release.
