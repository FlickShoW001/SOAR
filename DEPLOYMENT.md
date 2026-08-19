"""
SOAR Platform - Deployment & Quick Start Guide

This document provides immediate next steps to run the fully-built SOAR platform.
"""

## Files Created in soar-platform Branch

1. **main.py** - FastAPI application with full detect→enrich→decide→approve→respond→log pipeline
2. **models.py** - SQLAlchemy database models (Event, EnrichmentResult, Decision, Approval, AuditLog)
3. **enrichment.py** - AbuseIPDB API integration with caching & error handling
4. **decision_engine.py** - Rule-based risk scoring with explainable decisions
5. **audit_log.py** - Tamper-evident audit trail with SHA256 hash-chaining
6. **responder.py** - Netmiko integration for firewall/router rule deployment
7. **config.yaml** - Centralized thresholds & approval rules (no hardcoded magic numbers)
8. **.env.example** - Environment variables template (never commit secrets)
9. **requirements.txt** - Python dependencies (FastAPI, SQLAlchemy, Netmiko, etc.)
10. **tests.py** - Unit tests for enrichment, decision engine, and API endpoints
11. **README.md** - Comprehensive documentation with setup, API docs, examples

---

## Immediate Setup (5 minutes)

```bash
# 1. Ensure you're on soar-platform branch
git checkout soar-platform

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment template
cp .env.example .env

# 5. Edit .env with your settings (CRITICAL: add AbuseIPDB API key)
#    Obtain free API key from: https://www.abuseipdb.com/register
nano .env

# 6. Run the application
python main.py
```

Application starts at: **http://localhost:8000**

---

## API Quick Test

### Send a Detection Event

```bash
curl -X POST http://localhost:8000/detections \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "event_type": "port_scan",
    "severity": 4,
    "raw_log_line": "SYN scan from 192.168.1.100",
    "timestamp": "2026-08-19T10:00:00Z"
  }'
```

Expected response (if AbuseIPDB key is set):
- Low-risk IPs: Auto-approved with simulated response
- High-risk IPs: Awaiting approval via dashboard

### View Dashboard

```bash
open http://localhost:8000
# Or in browser: http://localhost:8000
```

Displays:
- Pending approvals
- Recent decisions with risk scores
- Audit log with hash-chain integrity status

### Approve a Decision

```bash
curl -X POST http://localhost:8000/approvals/1 \
  -H "Content-Type: application/json" \
  -d '{
    "approved": true,
    "rejected_reason": null
  }'
```

---

## Key Features Implemented

✅ **Detection Intake** (POST /detections)
   - Accepts JSON events: source_ip, event_type, severity, raw_log_line, timestamp
   - Persists to SQLite with status="new"

✅ **Enrichment** (enrichment.py)
   - Queries AbuseIPDB for abuse_score, country, ISP, report_count
   - In-memory caching (configurable TTL)
   - Handles timeouts, 429 rate limits, invalid API keys gracefully

✅ **Decision Engine** (decision_engine.py)
   - Weighted risk scoring: abuse_score (40%) + severity (35%) + reports (25%)
   - Explainable reasoning logged
   - Configurable thresholds in config.yaml (no magic numbers in code)
   - Actions: BLOCK, MONITOR, IGNORE

✅ **Approval Gate** (main.py)
   - Blocks high-impact decisions (BLOCK actions) until human approval
   - Clear approval rules in config.yaml
   - Low-risk actions auto-approve
   - POST /approvals/{event_id} endpoint to approve/reject

✅ **Response Connector** (responder.py)
   - Netmiko integration for Cisco IOS & Juniper JunOS
   - Lab IP allow-list validation (prevents mistakes)
   - Dry-run & simulation mode (safe testing)
   - Device credentials from .env only

✅ **Audit Trail** (audit_log.py)
   - Hash-chaining: each entry includes SHA256 of previous
   - Detects tampering via verify_audit_chain()
   - Tracks all pipeline stages: detect, enrich, decide, approve, reject, respond, close

✅ **Dashboard** (main.py)
   - Real-time HTML dashboard at GET /
   - Shows pending approvals, decisions, audit log
   - Audit chain integrity indicator

✅ **Storage** (models.py)
   - SQLite via SQLAlchemy (persistent, not in-memory)
   - 5 models: Event, EnrichmentResult, Decision, Approval, AuditLog

✅ **Tests** (tests.py)
   - Enrichment: API key validation, caching, error handling
   - Decision Engine: High/medium/low-risk scenarios, approval rules
   - Audit Log: Hash-chain integrity
   - API: Detection intake, approvals, health check

---

## Configuration Management

Edit **config.yaml** to customize without redeployment:

### Risk Scoring Weights
```yaml
risk_score_weights:
  abuse_score: 0.40    # IP reputation importance
  event_severity: 0.35 # Raw event severity importance
  report_count: 0.25   # Historical reports importance
```

### Action Thresholds
```yaml
action_thresholds:
  block_min_risk: 75     # >= 75 → recommend BLOCK
  monitor_min_risk: 50   # >= 50 → recommend MONITOR
  ignore_min_risk: 0     # >= 0 → recommend IGNORE
```

### Approval Rules
```yaml
approval_rules:
  block_requires_approval: true                  # All BLOCKs need approval
  monitor_auto_approve_max_risk: 45              # MONITOR auto-approves if risk < 45
  high_severity_requires_approval: true          # Critical events always need approval
  uncached_ip_requires_approval: true            # Unknown IPs require approval
```

---

## Security Checklist

Before deploying to production:

- [ ] Set ABUSEIPDB_API_KEY in .env (never commit)
- [ ] Configure LAB_DEVICE_IP/USERNAME/PASSWORD in .env
- [ ] Define LAB_ALLOWED_IPS in .env (protects non-lab networks)
- [ ] Set responder.dry_run=false only AFTER lab testing
- [ ] Run pytest tests.py to verify all modules
- [ ] Review config.yaml thresholds for your security posture
- [ ] Keep .env in .gitignore (never commit secrets)
- [ ] Regular audit chain verification: verify_audit_chain(db)

---

## Troubleshooting

**"ABUSEIPDB_API_KEY not set"**
→ Sign up at https://www.abuseipdb.com/register and add key to .env

**"429 rate limited by AbuseIPDB"**
→ Free tier has ~10 requests/day. Increase cache_ttl_minutes in config.yaml

**"Target IP not in lab allow-list"**
→ Add CIDR to LAB_ALLOWED_IPS in .env (e.g., 192.168.1.0/24,10.0.0.0/8)

**"Audit chain broken"**
→ Run verify_audit_chain() to detect tampering. Investigate root cause.

**Tests failing**
→ Run `pytest tests.py -v` to see detailed errors. Check .env is configured.

---

## Next Steps

1. **Deploy to lab**: Set responder.dry_run=false in config.yaml after validation
2. **Add webhook notifications**: Integrate with Slack/Teams/email for approvals
3. **Custom playbooks**: Extend decision_engine with industry-specific rules
4. **Log tailing**: Implement file watcher for event_intake alternative to POST endpoint
5. **Multi-factor enrichment**: Add VirusTotal, AlienVault OTX, custom feeds
6. **Database migration**: Use Alembic for schema versioning
7. **Authentication**: Add user login & RBAC to approval gate
8. **Scalability**: Move to PostgreSQL, async processing, message queue

---

## Support

For questions or issues:
- Check README.md for detailed API documentation
- Review config.yaml comments explaining thresholds
- Run tests with pytest tests.py -v
- Inspect audit logs via GET /events/{event_id}

Built with ❤️ for Cybersecurity Diploma graduation project.
"""
