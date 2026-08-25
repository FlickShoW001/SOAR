# Architecture

## Purpose and scope

SOAR is a single-service security automation application for controlled laboratories. It combines detection intake, reputation enrichment, deterministic decisioning, human governance, network response, and audit evidence in one FastAPI process.

## Component map

| Component | Responsibility |
| --- | --- |
| `main.py` | ASGI application, identity, validation, routes, state transitions, and orchestration |
| `models.py` | SQLAlchemy entities, engine creation, and session factory |
| `enrichment.py` | AbuseIPDB requests, failure recording, and process-local caching |
| `decision_engine.py` | Weighted scoring, confidence, actions, approval rules, and reasoning |
| `responder.py` | Allow-list enforcement, command generation, simulation, and Netmiko execution |
| `audit_log.py` | Audit entry creation, deterministic hashing, anchors, and integrity verification |
| `templates/` | Server-rendered authentication and operations views |
| `static/` | Responsive presentation and client-side dashboard behavior |

## Request architecture

FastAPI exposes synchronous pipeline operations through authenticated routes. SQLAlchemy uses one request-scoped session. SQLite is the default database, with relative paths resolved from the repository directory.

The browser dashboard receives server-rendered HTML, then polls `/dashboard/data` every five seconds. The API returns a weak ETag derived from the complete payload. A matching `If-None-Match` request returns `304 Not Modified`.

## Detection pipeline

1. Pydantic validates the source address, type, severity, evidence, and timestamp.
2. The event is flushed and the detection audit entry commits the initial state.
3. AbuseIPDB enrichment succeeds, uses a cache hit, or stores a structured failure.
4. The decision engine normalizes three signals and calculates a 0–100 risk score.
5. Approval rules decide whether human review is required.
6. Automatic or human approval claims the event for response.
7. Non-block actions close without a device change. Block actions simulate or execute after safety checks.
8. Audit entries record every completed transition.

If an unexpected exception occurs after event persistence, the event moves to `processing_failed` and receives a `pipeline_error` audit entry. This prevents partially processed events from appearing healthy or remaining indefinitely in an intermediate state.

## Data model

| Table | Important relationships and constraints |
| --- | --- |
| `events` | Root security record; indexed source, type, status, and timestamps |
| `enrichment_results` | Event-linked reputation snapshot; multiple rows can exist across events for one IP |
| `decisions` | One decision per event through a unique `event_id` |
| `approvals` | One approval result per event through a unique `event_id` |
| `audit_log` | Ordered, hash-linked action history |
| `audit_anchor` | Singleton local record of the current chain head |

No migration framework is included. Schema changes require a deliberate backup and migration plan.

## Decision model

Inputs are clamped before weighting:

- Abuse score: 0–100
- Severity: 1–5 normalized to 0–1
- Report count: saturated at 200 reports

The reasoning JSON stores normalized inputs, configured weights, confidence factors, the final score, and approval reasons. It is returned to authenticated event-detail clients.

## Approval concurrency

Approval uses an atomic conditional update:

```text
UPDATE events
SET status = responding|rejected
WHERE id = :event_id AND status = pending_approval
```

Only the reviewer who updates one row creates or modifies the approval record. Later reviewers receive a conflict instead of overwriting the first decision.

## Audit-chain design

The current entry hash includes:

```text
UTC timestamp | event ID | actor | action | canonical before state |
canonical after state | reasoning | previous hash
```

Canonical JSON uses stable key ordering and separators. Verification walks the selected recent segment, validates sequence continuity, recomputes hashes, checks the local chain-head anchor, and optionally verifies an external anchor. Legacy hash formats remain readable for existing databases.

## Frontend design

The interface uses native HTML, Jinja, CSS, and browser JavaScript without a frontend build step. Important design choices include:

- Inline vector icons rather than platform-dependent emoji
- Native dialogs for event intelligence and operator decisions
- A dedicated review queue with role-aware controls
- Critical/high/medium/low/informational severity semantics
- Search across events, decisions, approvals, and audit entries
- Responsive breakpoints for compact desktop, tablet, and mobile
- Reduced-motion support and visible keyboard focus states

## Scaling boundaries

The current system assumes one application process. Horizontal scaling requires:

- PostgreSQL or another production database
- Database migrations
- A shared enrichment cache
- A distributed task queue for enrichment and response
- Serialized or transactional audit-chain writes
- Central identity and secrets management
- Shared rate limiting and observability
