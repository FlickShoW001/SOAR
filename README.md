# SOAR Platform - Lightweight Security Orchestration, Automation & Response

A complete detect → enrich → decide → approve → respond → log pipeline for security events, built with FastAPI and Python for a Cybersecurity Diploma graduation project.

## Features

### 1. Detection Intake
- **POST `/detections`** endpoint accepts JSON security events
- Captures: source IP, event type, severity (1-5), raw log line, timestamp
- Automatically persists to SQLite database with status "new"

### 2. Enrichment
- Queries **AbuseIPDB API** for IP reputation data
- Returns: abuse score, country, ISP, report count, VPN/Proxy detection
- **In-memory caching** prevents duplicate API calls within TTL window
- Gracefully handles: timeouts, 429 rate limits, invalid API keys
- Environment variable `ABUSEIPDB_API_KEY` (never hardcoded)

### 3. Decision Engine
- **Rule-based risk scoring** (0-100) from weighted factors:
  - Abuse score (40% weight)
  - Event severity (35% weight)
  - Report count (25% weight)
- Explainable decisions with detailed reasoning logged
- Configurable thresholds in `config.yaml` (no magic numbers in code)
- Recommends: **BLOCK**, **MONITOR**, or **IGNORE**

### 4. Approval Gate
- Decisions marked `requires_approval=True` block execution until human approval
- Clear rules in `config.yaml` define "impactful" actions:
  - All BLOCK actions require approval
  - High-severity events require approval
  - Low-risk MONITOR/IGNORE actions auto-approve
- **POST `/approvals/{event_id}`** endpoint for approve/reject with audit trail

### 5. Response Connector
- **Netmiko integration** to push ACL rules to lab firewall/router
- Device credentials from environment variables only (no hardcoded secrets)
- **Lab IP allow-list** validation before any device connection
- **Dry-run & simulation mode** for safe testing
- Device type support: Cisco IOS, Juniper JunOS (extensible)
- Only executes after status is "approved" or auto-approved

### 6. Audit Trail (Tamper-Evident)
- **Hash-chaining**: each audit entry includes SHA256 hash of previous entry
- Detects tampering: `verify_audit_chain()` breaks if any entry is modified
- Tracks: timestamp, event_id, actor, action, before/after state, reasoning
- Every pipeline stage writes: detect, enrich, decide, approve, respond, close

### 7. Dashboard
- **GET `/`** renders real-time HTML dashboard
- Shows: pending approvals, recent decisions, audit log
- Filter by status, severity, IP address
- Displays audit chain integrity status

### 8. Storage
- **SQLite** via SQLAlchemy (persistent, not in-memory)
- Models: `Event`, `EnrichmentResult`, `Decision`, `Approval`, `AuditLog`

---

## Project Structure

```
soar-platform/
├── main.py                 # FastAPI application (detect → decide → respond pipeline)
├── models.py               # SQLAlchemy database models
├── enrichment.py           # AbuseIPDB API integration + caching
├── decision_engine.py      # Rule-based risk scoring + decision logic
├── audit_log.py            # Tamper-evident audit trail with hash-chaining
├── responder.py            # Netmiko device integration + lab allow-list validation
├── config.yaml             # Centralized thresholds & approval rules
├── .env.example            # Environment variables template
├── requirements.txt        # Python dependencies
├── tests.py                # Unit tests for enrichment, decision, API endpoints
└── README.md               # This file
```

---

## Installation & Setup

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/FlickShoW001/test.git
cd test
git checkout soar-platform

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings:
#   - ABUSEIPDB_API_KEY: Get from https://www.abuseipdb.com/register
#   - LAB_DEVICE_IP, LAB_DEVICE_USERNAME, LAB_DEVICE_PASSWORD: Your lab firewall
#   - LAB_ALLOWED_IPS: CIDR blocks to protect (e.g., 192.168.1.0/24)
```

### 3. Load Configuration

```bash
# config.yaml defines all thresholds—edit to customize:
#   - risk_score_weights: How much each factor contributes to risk
#   - action_thresholds: At what risk_score to recommend block/monitor/ignore
#   - approval_rules: Which decisions require human approval
```

### 4. Run the Application

```bash
python main.py
# Or use uvicorn directly:
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API starts at `http://localhost:8000`.

---

## API Endpoints

### Detection Intake

**POST `/detections`** — Ingest a security event

```json
{
  "source_ip": "192.168.1.100",
  "event_type": "port_scan",
  "severity": 4,
  "raw_log_line": "SYN scan from 192.168.1.100 to ports 22,80,443",
  "timestamp": "2026-08-19T10:00:00Z"
}
```

Response (auto-approved low-risk):
```json
{
  "id": 1,
  "source_ip": "192.168.1.100",
  "status": "responded",
  "message": "Auto-approved and responded",
  "response": {
    "status": "simulation",
    "commands_sent": ["...", "..."]
  }
}
```

Response (requires approval):
```json
{
  "id": 2,
  "source_ip": "192.168.1.101",
  "status": "pending_approval",
  "message": "Awaiting human approval",
  "decision": {
    "action": "block",
    "risk_score": 82.5,
    "confidence": 0.92
  }
}
```

### Approval Gate

**POST `/approvals/{event_id}`** — Approve or reject pending decision

```json
{
  "approved": true,
  "rejected_reason": null
}
```

Or reject:
```json
{
  "approved": false,
  "rejected_reason": "This is a known security researcher; ignore"
}
```

### Dashboard & Reporting

**GET `/`** — Render dashboard (HTML)
- Shows pending approvals, recent decisions, audit log
- Displays audit chain integrity status

**GET `/events/{event_id}`** — Retrieve full event details
- Event info, enrichment, decision, approval, audit trail

**GET `/health`** — Health check
```json
{
  "status": "healthy",
  "database": "connected",
  "audit_chain": "valid"
}
```

---

## Configuration (config.yaml)

All thresholds and rules are externalized for safety and auditability:

```yaml
decision_engine:
  risk_score_weights:
    abuse_score: 0.40      # 40% from reputation
    event_severity: 0.35   # 35% from severity
    report_count: 0.25     # 25% from frequency
  
  action_thresholds:
    block_min_risk: 75     # Risk >= 75 → recommend BLOCK
    monitor_min_risk: 50   # Risk >= 50 → recommend MONITOR
    ignore_min_risk: 0     # Risk >= 0 → recommend IGNORE
  
  approval_rules:
    block_requires_approval: true
    monitor_auto_approve_max_risk: 45
    high_severity_requires_approval: true
    uncached_ip_requires_approval: true

responder:
  dry_run: true            # CRITICAL: Set to false only after lab testing
  simulation_mode: true    # Log what would be sent
```

---

## Security & Non-Negotiable Constraints

✅ **No hardcoded secrets**: All credentials from `.env` file (`.env.example` provided)  
✅ **No real device execution without approval**: Approval gate enforces human review  
✅ **Lab IP allow-list validation**: Prevents accidental targeting of non-lab networks  
✅ **Dry-run/simulation mode**: Safe testing before enabling real device connections  
✅ **Tamper-evident audit trail**: Hash-chain detects any audit log modifications  
✅ **Explainable decisions**: Detailed reasoning logged for every decision  
✅ **Configurable thresholds**: No magic numbers inline; edit `config.yaml`  
✅ **Unit tests included**: Test enrichment, decision logic, API endpoints  

---

## Testing

Run the unit test suite:

```bash
pytest tests.py -v
```

Tests cover:
- Enrichment: API key validation, caching, error handling
- Decision Engine: High/medium/low-risk scoring, approval rules
- Audit Log: Hash-chain integrity
- API Endpoints: Detection intake, approval gate, health check, dashboard

---

## Workflow Example

### Scenario: Port scan detected from malicious IP

1. **Detection** → POST `/detections` with source IP `192.168.1.100`
   - Event stored in DB with status "new"
   - Audit entry: "detect" action logged

2. **Enrichment** → AbuseIPDB API called
   - IP has abuse_score=85, report_count=150
   - Audit entry: "enrich" action logged with results

3. **Decision** → Risk scoring applied
   - risk_score = (0.85 × 0.40) + (0.8 × 0.35) + (min(150/200, 1) × 0.25) × 100 ≈ **82.5**
   - action="block", confidence=0.92, requires_approval=true
   - Audit entry: "decide" action logged with reasoning

4. **Approval Gate** → Event status = "pending_approval"
   - Dashboard shows pending item
   - Human operator reviews and calls POST `/approvals/1?approved=true`
   - Audit entry: "approve" action logged with operator name

5. **Response** → Netmiko connects to lab router
   - ACL rules generated for blocking 192.168.1.100
   - Commands sent in simulation mode (dry_run=true): logged only
   - Event status = "responded"
   - Audit entry: "respond" action logged

6. **Audit Verification** → Chain integrity confirmed
   - Dashboard shows ✓ VALID
   - Any tampering detected by verify_audit_chain()

---

## Troubleshooting

### "ABUSEIPDB_API_KEY not set"
- Set the environment variable: `export ABUSEIPDB_API_KEY=your_key_here`
- Or add to `.env` file

### "429 rate limited by AbuseIPDB"
- Increase `cache_ttl_minutes` in `config.yaml`
- AbuseIPDB free tier: ~10 requests per day

### "Target IP not in lab allow-list"
- Add the IP/CIDR to `LAB_ALLOWED_IPS` in `.env`
- Example: `LAB_ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8`

### Audit chain broken
- Check if audit log was modified directly in database
- Run `verify_audit_chain()` to find tampered entries
- Restore from backup or investigate security incident

---

## Future Enhancements

- Support multiple enrichment sources (VirusTotal, AlienVault OTX, etc.)
- Async background processing for enrichment/response
- Database migration with Alembic
- Web UI with user authentication & RBAC
- Incident response playbooks (auto-chain multiple actions)
- Webhook notifications (Slack, Teams, email)
- Custom threat intelligence feeds
- Log file tailing as event source (alternative to POST endpoint)

---

## License

This is a graduation project for Cybersecurity Diploma studies. Customize freely for your lab environment.

---

## Author

**mahmoudali-dot** — Built for practical security automation & orchestration learning.

For questions or improvements, create an issue or pull request.
