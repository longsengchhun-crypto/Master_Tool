# Operations

## Deployment

The console is one Next.js application (`apps/admin`) plus PostgreSQL. Any Node 22+ host works (container, VM, PaaS).

* Build: `npm ci && npm run build -w @sentrix/admin`; run: `npm run start -w @sentrix/admin` (port 3100).
* A `Dockerfile` and a development `docker-compose.yml` are in `infrastructure/`.
* **TLS must be terminated in front** (platform load balancer, nginx, Caddy). The app sends HSTS and `Secure` cookies;
  it will not work for admin sign-in over plain HTTP outside localhost.
* Put it behind a proxy that sets `X-Forwarded-For` (per-IP rate limiting uses it; per-account limits do not depend on it).
* Run migrations as a deploy step (`npm run migrate -w @sentrix/admin`) before starting the new version.
* Health: `GET /api/health` → `{"status":"ok"}` (503 if the database is unreachable). It reveals nothing else.

## Secrets

| Secret | Purpose | Rotation impact |
|---|---|---|
| `DATABASE_URL` | Database access | Rotate in the DB provider, update the env var, restart. |
| `SESSION_SECRET` | Derives the AES-256-GCM key sealing TOTP seeds | **Changing it invalidates every stored TOTP seed**: all admins must re-enroll MFA (Super Admin → reset 2-step). Plan this as a maintenance event. |
| `DEVICE_TOKEN_PEPPER` | HMAC for device tokens, enrollment codes, license keys | **Changing it invalidates all device credentials, outstanding enrollment codes and license keys.** Devices must re-enroll. |
| Updater private key | Signs application updates | See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md). Not present on the server. |
| Provider API keys (future reputation lookups) | Server-side only | Never shipped to clients. |

Inject secrets through the platform's secret store, not files in the image. The development `.env` is gitignored.
The Neon credential used during development was pasted into a chat transcript: **rotate it** before production.

## Backups and recovery

* **Provider-managed (recommended):** enable point-in-time recovery on the database (Neon: history retention window;
  RDS/Cloud SQL: automated backups + PITR). Record the retention window you pay for here: **not yet configured**.
* **Logical backups (independent copy):** nightly `pg_dump --format=custom --no-owner "$DATABASE_URL" > sentrix-$(date +%F).dump`,
  encrypted at rest (e.g. `age`/KMS) and stored in a separate account/region. Keep 30 daily + 12 monthly.
* **Restore drill (do quarterly):** restore into a scratch database, run `node apps/admin/scripts/dbcheck.mjs`, start the
  console against it, sign in, and call `GET /api/admin/audit?verify=1`: it must report `intact: true`. *This drill has not been
  performed yet; `pg_dump` was not available in the build environment.*
* What is *not* in the database and must be backed up separately: the updater signing key (offline), release artifacts
  (object storage versioning), environment secrets (secret manager).

## Retention and deletion

`apps/admin/scripts/retention.mjs` enforces these defaults (override with env vars; run daily from a scheduler):

| Data | Default retention | Variable |
|---|---|---|
| Scan findings and scan sessions | 180 days | `RETENTION_DAYS_FINDINGS` |
| Security events | 180 days | `RETENTION_DAYS_EVENTS` |
| Quarantine metadata records | 365 days | `RETENTION_DAYS_QUARANTINE` |
| Revoked devices (and their dependent rows) | 90 days after revocation | `RETENTION_DAYS_REVOKED_DEVICES` |
| Expired sessions, expired/used enrollment codes, stale rate-limit buckets | immediately / 7 days | n/a |
| **Audit log** | **Not deleted automatically** (append-only; ≥ 1 year recommended) | Archiving requires a documented, audited procedure because the table is tamper-evident by design. |

A device user can end management at any time (Account → Leave management); the console then holds only what
retention allows. Customer deletion requests: revoke the device, then run retention with
`RETENTION_DAYS_REVOKED_DEVICES=0` for the affected organization, or delete the organization (cascades).

## Monitoring

* Alert on `/api/health` ≠ 200, 5xx rate, and database connectivity.
* Console Overview shows fleet health (devices silent ≥ 7 days, engine not running, signatures older than 72 h).
* Audit log events worth alerting on: `auth.login_failed` bursts, `auth.mfa_failed`, `auth.recovery_code_used`,
  `user.update` (role changes), `device.revoke`, `license.revoke`, `policy.write`, `release.publish`.
* Logs are structured JSON lines on stdout (`level`, `msg`, `path`, `method`). Error bodies returned to clients never include
  stack traces, SQL or secrets; the log line contains only the message.

## Capacity notes

Heartbeat every 5 minutes per device; each is one UPDATE + one policy SELECT + one license SELECT (+ jobs/update lookups).
Rate limits are stored in Postgres so they hold across instances; at large scale move them to Redis.
