# SOAR Operations Platform

A security orchestration, automation, and response application for controlled cyber-range and laboratory environments. SOAR accepts authenticated detections, enriches source IPs through AbuseIPDB, produces explainable risk decisions, places high-impact actions behind a human approval gate, and records every transition in a tamper-evident audit chain.

> [!IMPORTANT]
> This project is simulation-first and intended for an isolated lab. Real network changes must only be enabled after validating device commands, interface names, allow-lists, credentials, rollback procedures, and operational ownership.

## Highlights

- Professional, responsive operations console with live polling, search, event intelligence, decision risk indicators, approval workflows, and audit-chain health
- Validated IPv4 and IPv6 detection intake with authenticated role-based access
- AbuseIPDB enrichment with process-local TTL caching and recorded failure states
- Configurable weighted risk scoring with human-readable decision reasoning
- Atomic approval claims that prevent an event from being reviewed twice
- Fail-closed Cisco IOS and Juniper Junos response connector
- Dry-run and simulation modes enabled by default
- Tamper-evident SHA-256 audit chain with local and optional external anchors
- Browser security headers, signed HTTP-only sessions, and separate admin/operator/viewer permissions
- Focused regression suite for authentication, validation, dashboard caching, and pipeline failure recovery

## How the platform works

```text
Authenticated detection
        │
        ▼
Persist event ──► audit: detect
        │
        ▼
Enrich source IP ──► audit: enrich
        │
        ▼
Score risk + explain decision ──► audit: decide
        │
        ├── approval required ──► operator approve/reject
        │
        └── automatic approval
                    │
                    ▼
           simulate/apply/skip response
                    │
                    ▼
               audit: respond
```

The default decision score is:

```text
risk = 100 × (
    abuse reputation × 0.40
  + normalized severity × 0.35
  + normalized report count × 0.25
)
```

Default actions are `block` at 75 or above, `monitor` at 50–74.9, and `ignore` below 50. Approval safety rules are evaluated before action-specific automatic approval.

## Requirements

- Python 3.12
- An AbuseIPDB API key for live reputation enrichment
- A supported lab device only when enabling real responses:
  - Cisco IOS
  - Juniper Junos

## Quick start

```bash
git clone https://github.com/FlickShoW001/SOAR.git
cd SOAR

python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
```

For reproducible deployments, install with `pip install --require-hashes -r requirements.lock`. Runtime and development tooling are split between `requirements.txt` and `requirements-dev.txt`; CI audits the lockfile and publishes a CycloneDX SBOM.

Set secure local credentials and an unpredictable session secret in `.env`:

```dotenv
SOAR_ADMIN_USERNAME=admin
SOAR_ADMIN_PASSWORD=use-a-unique-strong-password
SOAR_SESSION_SECRET=replace-with-a-long-random-value
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

Generate a suitable session secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Start the application:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Interactive API documentation is available at `/docs`.

> [!WARNING]
> Without environment overrides, the application falls back to example administrator credentials and an ephemeral session secret. Startup warnings identify both conditions. They are convenient for a local lab but unsafe for a shared or deployed environment.

## Authentication and roles

The browser uses a signed, HTTP-only, `SameSite=Strict` session cookie. API clients can authenticate with HTTP Basic credentials. Set `SOAR_SESSION_COOKIE_SECURE=true` whenever the application is served over HTTPS.

| Capability | Admin | Operator | Viewer |
| --- | :---: | :---: | :---: |
| View dashboard, events, and audit data | Yes | Yes | Yes |
| Submit detections | Yes | Yes | No |
| Approve or reject decisions | Yes | Yes | No |

Additional users can be configured with JSON:

```dotenv
SOAR_USERS_JSON={"operator":{"password_hash":"scrypt$...","role":"operator"},"analyst":{"password_hash":"scrypt$...","role":"viewer"}}
```

Malformed user records are ignored, and malformed top-level JSON fails closed to the built-in administrator only. Restart the application after changing account configuration.

## API overview

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/login` | Public | Render secure browser sign-in |
| `POST` | `/login` | Public | Create a signed browser session |
| `POST` | `/logout` | Public | Clear the browser session |
| `GET` | `/` | Browser session | Render the operations console |
| `GET` | `/dashboard/data` | Viewer+ | Return live dashboard data with ETag support |
| `POST` | `/detections` | Operator+ | Run the detection pipeline |
| `POST` | `/approvals/{event_id}` | Operator+ | Approve or reject one pending decision |
| `GET` | `/events/{event_id}` | Viewer+ | Return event, enrichment, decision, approval, and audit context |
| `GET` | `/health` | Public | Verify database connectivity and recent audit integrity |

### Submit a detection

```bash
curl -u admin:use-a-unique-strong-password \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "event_type": "port_scan",
    "severity": 4,
    "raw_log_line": "SYN scan from 192.168.1.100",
    "timestamp": "2026-08-24T10:00:00Z"
  }' \
  http://127.0.0.1:8000/detections
```

Validation rules:

- `source_ip` must be a valid IPv4 or IPv6 address.
- `event_type` must contain 1–50 non-whitespace characters.
- `severity` must be an integer from 1 through 5.
- `raw_log_line` must contain evidence and cannot exceed 10,000 characters.
- `timestamp`, when present, must include a timezone offset.

### Review a decision

```bash
# Approve
curl -u admin:use-a-unique-strong-password \
  -H "Content-Type: application/json" \
  -d '{"approved":true}' \
  http://127.0.0.1:8000/approvals/42

# Reject — a meaningful reason is required
curl -u admin:use-a-unique-strong-password \
  -H "Content-Type: application/json" \
  -d '{"approved":false,"rejected_reason":"Known cyber-range scanner"}' \
  http://127.0.0.1:8000/approvals/42
```

Only `pending_approval` events can be claimed. Concurrent or repeated review attempts receive `409 Conflict`.

## Event lifecycle

```text
new → enriched → decided
                    ├─→ pending_approval → rejected
                    └─→ responding
                              ├─→ responded
                              ├─→ closed
                              └─→ response_failed

Any unexpected processing exception after persistence:
processing_failed + pipeline_error audit entry
```

- `responded`: the block was simulated or applied successfully.
- `closed`: the decision did not require a network block.
- `response_failed`: the responder rejected or failed the operation.
- `processing_failed`: an earlier enrichment/decision pipeline stage failed after the event had been persisted.
- `rejected`: an operator declined the automated decision.

## Response safety

The connector only generates device commands for `block` decisions. It also requires:

1. An atomically claimed `responding` event.
2. A source IP inside `LAB_ALLOWED_IPS`.
3. A supported device type.
4. Complete device credentials for live execution.
5. Both `responder.dry_run` and `responder.simulation_mode` set to the YAML boolean `false`.
6. A lab device IP that is also inside the allow-list.

IPv6 detection intake is supported, but the current network response connector is IPv4-only and fails closed for IPv6 targets.

## Audit integrity

Each audit hash covers the UTC timestamp, event ID, actor, action, before/after state, reasoning, and previous entry hash. Verification detects modified content, broken links, event reassignment, entry deletion/reordering, and chain-head truncation.

The local chain head is stored in `audit_anchor`. For stronger truncation evidence, place an additional anchor on separately protected durable storage:

```dotenv
AUDIT_EXTERNAL_ANCHOR_PATH=/mnt/audit-anchor/soar-audit-head.json
```

Hash chaining is tamper-evident, not immutable storage. Protect the database and external anchor with access controls, backups, and independent monitoring.

## Configuration

`config.yaml` controls risk weights, action thresholds, approval rules, and responder safety modes. Environment variables control secrets, identity, database location, enrichment, device access, and process settings.

Important variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Project-local SQLite | SQLAlchemy connection URL |
| `ABUSEIPDB_API_KEY` | None | Reputation service authentication |
| `ABUSEIPDB_CACHE_TTL_MINUTES` | `60` | Positive process-local cache TTL |
| `SOAR_ADMIN_USERNAME` | `admin` | Built-in administrator name |
| `SOAR_ADMIN_PASSWORD` | `admin` | Built-in administrator password |
| `SOAR_ADMIN_PASSWORD_HASH` | None | Preferred scrypt verifier; generate with `scripts/hash_password.py` |
| `SOAR_USERS_JSON` | None | Additional role-based accounts |
| `SOAR_SESSION_SECRET` | Random per process | Session HMAC key |
| `SOAR_SESSION_TTL_SECONDS` | `28800` | Browser session lifetime |
| `SOAR_SESSION_COOKIE_SECURE` | `false` | HTTPS-only cookie flag |
| `LAB_DEVICE_*` | See `.env.example` | Netmiko device configuration |
| `LAB_ALLOWED_IPS` | Private lab CIDRs | Permitted targets and device networks |
| `AUDIT_EXTERNAL_ANCHOR_PATH` | None | Optional external chain-head file |
| `AUDIT_ANCHOR_HMAC_KEY` | None | HMAC key used to authenticate the external anchor |
| `SOAR_ALLOWED_HOSTS` | Local hosts | Host-header allow-list |
| `SOAR_ALLOWED_ORIGINS` | None | Additional browser origins accepted behind a reverse proxy |
| `SOAR_LOGIN_ATTEMPT_LIMIT` | `5` | Failed attempts allowed per IP/account window |
| `SOAR_EVIDENCE_RETENTION_DAYS` | `0` | Days before terminal-event evidence is minimized; `0` disables cleanup |

Relative SQLite paths are resolved against the project directory rather than the launch directory.

## Testing

```bash
pytest -q
```

The regression suite covers:

- Detection and rejection validation
- User configuration and session parsing
- Login page security headers and cache policy
- Username preservation after a failed sign-in
- Authenticated dashboard ETag revalidation
- Persistent and audited pipeline failure states

JavaScript syntax can be checked with Node.js:

```bash
node --check static/dashboard.js
node --check static/login.js
```

## Project structure

```text
.
├── main.py                    FastAPI application, auth, routes, and pipeline
├── models.py                  SQLAlchemy data model and database initialization
├── enrichment.py              AbuseIPDB integration and in-memory cache
├── decision_engine.py         Risk scoring and approval rules
├── responder.py               Network-device response connector
├── audit_log.py               Tamper-evident audit chain
├── config.yaml                Decision and response configuration
├── templates/                 Jinja login and command-center views
├── static/                    Responsive CSS and browser behavior
├── tests/                     Focused regression tests
├── docs/                      Architecture, operations, and security guides
├── DEPLOYMENT.md              Deployment checklist
├── .env.example               Environment configuration template
└── requirements.txt           Python dependencies
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — components, data model, pipeline, and design decisions
- [Operations guide](docs/OPERATIONS.md) — configuration, workflows, monitoring, recovery, and troubleshooting
- [Security guide](docs/SECURITY.md) — trust boundaries, controls, deployment hardening, and limitations
- [Deployment guide](DEPLOYMENT.md) — repeatable lab deployment checklist

## Known limitations

- Enrichment and device response are synchronous request-path operations.
- The cache is process-local and is not shared across workers or restarts.
- SQLite is appropriate for a single-process lab, not horizontal production scaling.
- There is no background job queue, retry scheduler, migration framework, or identity-provider integration.
- Several commented configuration sections are forward-looking and are not yet consumed by the runtime.
- Real device changes require environment-specific command validation and rollback planning.

## License

No explicit license file is included. Obtain the repository owner's permission before reuse or redistribution where required.
