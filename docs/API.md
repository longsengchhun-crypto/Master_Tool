# API reference

Base URL: the console origin (e.g. `https://console.example.com`). All bodies are JSON. Schemas live in
`packages/contracts/src/index.ts` and use `strictObject`: **unknown fields are rejected** (HTTP 400).

Errors always have this shape and never include stack traces, SQL or secrets:

```json
{ "error": { "code": "forbidden", "message": "Forbidden" } }
```

Common codes: `unauthenticated` 401, `mfa_required` 403, `forbidden` 403, `csrf` 403, `cross_origin` 403,
`reauth_required` 403, `not_found` 404 (also returned for another tenant's resource), `invalid_request` 400 (with
`issues[]`), `too_large` 413, `rate_limited` 429.

## Authentication models

| Surface | Mechanism |
|---|---|
| `/api/admin/*`, `/api/auth/*` | Cookie `__Host-sx_session` (HttpOnly, Secure, SameSite=Strict) + `x-csrf-token` on every non-GET + Origin check. MFA mandatory for every admin role. |
| `/api/device/*` | `Authorization: Bearer dev_<deviceId>.<secret>`. Cookies are ignored. Revocation is immediate. |
| `/api/updates/*`, `/api/public/*`, `/api/health` | Anonymous, rate-limited, read-only. |

Sensitive admin actions (`device:revoke`, `license:manage`, `policy:write`, `release:publish`, `user:manage_roles`) additionally
require a password re-entry within the last 10 minutes (`403 reauth_required` → `POST /api/auth/reauth`).

## Auth

| Method & path | Notes |
|---|---|
| `POST /api/auth/login` `{email,password,totp?}` | `200 {ok, mfaSetupRequired}` or `200 {mfaRequired:true}` (send again with `totp`: 6-digit code or recovery code). Same 401 for unknown email and wrong password. Limits: 40/10 min per IP, 8/15 min per account, 6 MFA tries/10 min. |
| `GET /api/auth/me` | Principal + CSRF token. |
| `POST /api/auth/logout` | Destroys the session server-side. |
| `POST /api/auth/mfa/setup` · `POST /api/auth/mfa/enable {token}` | Enable returns 10 one-time recovery codes **once**. |
| `POST /api/auth/reauth {password}` | Unlocks sensitive actions for 10 minutes. |

## Admin (cookie + CSRF)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /api/admin/overview` | telemetry:read | Operational and detection metrics, separated. Tenant-scoped. |
| `GET /api/admin/devices` · `GET /api/admin/devices/:id` | device:read | Detail includes events, scans, jobs. |
| `POST /api/admin/devices/:id/revoke` | device:revoke 🔐 | Token dead immediately, seat freed, jobs cancelled. |
| `POST /api/admin/devices/:id/jobs` `{kind}` | device:manage | `kind ∈ {scan_quick, intel_update, app_update}`. One open job per kind per device. |
| `POST /api/admin/enrollments` `{orgId,hoursValid?}` | device:manage | One-time code, shown once. |
| `GET/POST /api/admin/orgs` | org:read / org:manage | |
| `GET/POST /api/admin/licenses` · `POST …/:id/revoke` | license:read / license:manage 🔐 | Key shown once; only HMAC + last 4 stored. |
| `GET/PUT /api/admin/policies` | policy:read / policy:write 🔐 | Body validated against `DevicePolicy` (closed schema). |
| `GET/POST /api/admin/releases` · `POST …/:id/action {action,rolloutPct?}` | release:read / release:publish 🔐 | `stage`, `publish`, `cancel`, `rollback`. Needs artifact + SHA-256 + update signature. |
| `GET/POST /api/admin/users` · `PATCH …/:id` | user:manage_roles 🔐 | Create, role change, deactivate, reset MFA. No self-demotion; last Super Admin protected. |
| `GET /api/admin/audit[?verify=1]` | audit:read | Hash-chain verification. |
| `GET /api/admin/events` | telemetry:read | Findings (hash + verdict) and device events. |

🔐 = also requires fresh re-authentication.

## Device (bearer)

| Method & path | Notes |
|---|---|
| `POST /api/device/enroll` | Anonymous + one-time code. 402 if no free license seat, 400 for invalid/expired/used code. Returns token (once), org, license, policy. |
| `POST /api/device/heartbeat` | Body: versions + protection state, plus optional `queue {queued, failed, stuck}` and `telegram {botConnected, deliveryFailures24h, accountState, account? {scanned, threats, unverified}}`. and optional `groups {registered, protected, autoDelete, scans24h, threats24h, errors24h}` (Group Shield, counts only). All are strict objects of counts/booleans/enum: any other key (file name, hash, chat id, token, message text) is rejected. Returns `{policy, license{state}, jobs[], update?}`; policy includes `telegramBotAllowed`, `telegramAccountAllowed` and `telegramGroupsAllowed`. |
| `POST /api/device/scans` | Scan metadata: counts + per-finding `sha256`, `verdict`, `source`. `fileName` stored only if the org policy allows it. |
| `POST /api/device/events` | ≤ 50 events `{kind,severity,detail?}`. |
| `POST /api/device/jobs/:id/result` | Only for the device's own, delivered jobs. |
| `POST /api/device/unenroll` | Frees the seat; user can always leave. |

## Updates and public

| Method & path | Notes |
|---|---|
| `GET /api/updates/:platform/:currentVersion?id=<install id>` | Tauri updater format `{version, notes, pub_date, url, signature}` or `204`. Only published/staged releases with artifact + SHA-256 + signature; staged releases honor the stable cohort `sha256(id:version) mod 100 < rollout%`. |
| `GET /api/public/releases` | Latest published stable build per platform: version, URL, SHA-256, size, code-signed flag, notes. No internal ids. |
| `GET /api/health` | `{"status":"ok"}` or 503. |

## Relay (shared bot): `sentrix-botd`

Used by the desktop app to report through the shared bot. Not part of the console API. Run behind HTTPS.

| Call | Auth | Notes |
|---|---|---|
| `POST /v1/link` `{code, name}` | none | One-time code from the bot -> `{token, userName}`. Rate limited |
| `POST /v1/report` `{text}` | `Bearer <token>` | `202 {queued}`. Text reduced to `<b> <i> <code>`. Target is always the token owner. 6/min, 60/h |
| `GET /v1/status` | Bearer | `{linked, reachable}` |
| `DELETE /v1/link` | Bearer | Unlinks the computer (`204`) |

See [HOSTED_BOT.md](HOSTED_BOT.md).
