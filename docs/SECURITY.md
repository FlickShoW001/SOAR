# Security Guide

## Security posture

SOAR uses defense-in-depth controls appropriate for a laboratory application, but it is not hardened for direct public exposure. Its most sensitive capability is generating and optionally applying network-device rules.

## Trust boundaries

| Boundary | Untrusted or sensitive input | Primary controls |
| --- | --- | --- |
| Browser → application | Credentials, sessions, approval actions | Signed HTTP-only cookies, strict same-site policy, role checks, validation |
| API client → application | Detection evidence and timestamps | HTTP Basic/session auth, Pydantic constraints, normalized text |
| Application → AbuseIPDB | Source IP and API key | TLS through Requests, timeout, error handling, no key persistence in records |
| Application → network device | Commands and device credentials | Approval state, allow-list, supported platform list, simulation defaults |
| Application → database | Events, decisions, identities, evidence | Request-scoped sessions, constraints, audit hashing |
| Database → operator | Stored raw evidence and enrichment | Authenticated viewer access and HTML escaping |

## Implemented controls

### Identity and session protection

- Constant-time credential and session-signature comparison
- Signed sessions with configurable positive TTL
- HTTP-only and `SameSite=Strict` cookies
- Optional HTTPS-only cookie flag
- Admin, operator, and viewer authorization roles
- Fail-closed parsing of malformed user configuration and session payloads
- No-store cache policy for login and dashboard HTML

### Browser protections

Responses include:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- Restricted `Permissions-Policy`
- `Cross-Origin-Opener-Policy: same-origin`

Dynamic values are escaped before browser rendering. No third-party frontend scripts or fonts are required.

### Input and workflow controls

- Valid IP addresses and bounded request fields
- Timezone-required event timestamps
- Rejection reasons required for accountable governance
- Atomic pending-event claims
- Explicit response-state ownership (`responding`)
- Persistent `processing_failed` state after partial pipeline errors

### Network response controls

- Simulation and dry-run enabled by default
- IPv4 allow-list checks for target and live device
- Supported-device allow-list
- Fail-closed unsupported platform behavior
- Required credentials before connection
- Guaranteed disconnect attempt
- Explicit Junos commit

### Audit controls

- Deterministic SHA-256 hash chain
- Event ID included in the protected payload
- Sequence and previous-hash verification
- Local chain-head anchor
- Optional external chain-head anchor
- Legacy verification for existing databases

## Deployment hardening

Before a shared deployment:

1. Replace all example credentials and secrets.
2. Serve only through TLS and enable secure cookies.
3. Restrict ingress to operator networks or a trusted VPN.
4. Use a secret manager for AbuseIPDB and device credentials.
5. Disable or protect interactive API documentation if not required.
6. Keep application login throttling enabled and add proxy or identity-provider limits as a second layer.
7. Centralize logs without recording secrets or full device output unnecessarily.
8. Protect and back up the database and external anchor separately.
9. Run the service with a dedicated, least-privileged operating-system account.
10. Replace SQLite and add schema migrations before production scaling.
11. Introduce a reviewed identity provider and MFA for real operational use.
12. Perform a threat model and penetration test for the target environment.

## Secrets

Never commit `.env`. Rotate a secret immediately if it appears in source control, logs, screenshots, tickets, or chat.

Changing `SOAR_SESSION_SECRET` invalidates all active browser sessions. Treat this as expected during rotation. Device credentials should be scoped to the minimum configuration privileges required for the tested command set.

## Audit limitations

Hash chaining proves that stored content is internally consistent with its recorded chain; it does not make storage immutable. An attacker who can rewrite the complete database and every anchor can forge a replacement history.

For stronger assurance:

- Export the chain head to independently controlled storage.
- Ship logs to an append-only or write-once system.
- Restrict database administration.
- Alert when verification fails.
- Preserve signed backups and restoration records.

## Current security limitations

- Local accounts support scrypt password verifiers and bounded per-IP/account login throttling. Shared deployments should still use named federated identity with MFA.
- CSRF protection relies primarily on strict same-site cookies; there are no synchronizer tokens.
- API documentation is public by default.
- Enrichment and response run synchronously and can consume request capacity.
- SQLite and process-local state constrain safe concurrency and scaling.
- Audit-chain creation is designed for the single-process deployment model.
- Raw evidence can contain sensitive log content. `SOAR_EVIDENCE_RETENTION_DAYS` minimizes aged terminal-event evidence and records the cleanup in the audit chain.

## Responsible operation

Only target systems and network ranges you are authorized to test. Keep the default allow-list narrow, retain simulation mode, and require a named human owner for any transition to live device changes.
