# Deployment Guide

This guide describes a controlled, single-instance lab deployment. The current architecture is not a production reference deployment.

## 1. Prepare the runtime

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

## 2. Configure secrets

Replace every example credential in `.env`. At minimum:

```dotenv
SOAR_ADMIN_USERNAME=admin
SOAR_ADMIN_PASSWORD=<unique-strong-password>
SOAR_SESSION_SECRET=<long-random-secret>
ABUSEIPDB_API_KEY=<api-key>
SOAR_SESSION_COOKIE_SECURE=true
```

Generate the session secret with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

For additional accounts, use `SOAR_USERS_JSON`. Use only the roles `admin`, `operator`, and `viewer`.
Store generated `password_hash` values instead of plaintext passwords. Generate a verifier with `python scripts/hash_password.py`, then set `SOAR_ADMIN_PASSWORD_HASH` and hashed user records. Configure `SOAR_ALLOWED_HOSTS`, login throttling, an evidence-retention period, and `AUDIT_ANCHOR_HMAC_KEY` for the external anchor.

## 3. Keep responses in simulation

Confirm the following values remain enabled in `config.yaml`:

```yaml
responder:
  dry_run: true
  simulation_mode: true
```

Configure the lab boundary explicitly:

```dotenv
LAB_ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8
LAB_DEVICE_IP=192.168.1.1
LAB_DEVICE_TYPE=cisco_ios
LAB_DEVICE_INTERFACE=GigabitEthernet0/0
```

Do not enable live execution until the generated commands and rollback procedure have been tested on an isolated device.

## 4. Validate the release

```bash
pytest -q
python -m compileall -q .
node --check static/dashboard.js
node --check static/login.js
```

Start the application on loopback for initial validation:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

Verify:

```bash
curl --fail http://127.0.0.1:8000/health
```

Then sign in, confirm the audit indicator is verified, submit a synthetic lab detection, and complete an approval in simulation mode.

## 5. Place behind TLS

For any shared environment:

- Terminate TLS at a trusted reverse proxy.
- Set `SOAR_SESSION_COOKIE_SECURE=true`.
- Restrict ingress to authorized operator networks.
- Do not expose the service directly to the public internet.
- Decide whether `/docs`, `/redoc`, and `/openapi.json` should remain accessible.
- Forward only the headers required by the application and overwrite untrusted client forwarding headers.

Example process command:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
```

Use one worker with the current SQLite and process-local cache design. Move to a production database and shared cache before scaling horizontally.

## 6. Protect persistent state

- Store the database on durable, access-controlled storage.
- Back up `soar.db` on a tested schedule.
- Configure `AUDIT_EXTERNAL_ANCHOR_PATH` on a separately protected mount.
- Restrict `.env` to the service account.
- Keep device credentials in a secret manager when available.
- Retain application and reverse-proxy logs according to policy.

## 7. Pre-live response checklist

Before setting both responder flags to `false`:

- [ ] Lab allow-list contains only approved ranges.
- [ ] Device IP is inside the allow-list.
- [ ] Interface name is correct.
- [ ] Device type is supported.
- [ ] Generated rules preserve permitted traffic.
- [ ] Junos commit behavior is validated where applicable.
- [ ] A rollback command and responsible operator are documented.
- [ ] Approval permissions are assigned to named users.
- [ ] Simulation evidence has been reviewed.
- [ ] Change authorization has been obtained.

## Rollback

If an application release fails:

1. Stop the new process.
2. Restore the last known-good code and dependency environment.
3. Restore the database only if schema or data integrity requires it; preserve forensic copies first.
4. Verify `/health` and the audit chain.
5. Keep network response in simulation until the incident is understood.

Network-device rollback is environment-specific and must be prepared before live response is enabled.

See [Operations](docs/OPERATIONS.md) and [Security](docs/SECURITY.md) for monitoring and hardening guidance.
