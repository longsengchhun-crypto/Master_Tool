# Environment variables

## Console (`apps/admin`)

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | yes | PostgreSQL URL. Use `sslmode=verify-full` (the Node driver otherwise warns about future semantics). `channel_binding=require` is not supported by the Node driver; omit it. |
| `SESSION_SECRET` | yes | ≥ 32 characters, random (`node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`). Derives the key that seals TOTP seeds. Changing it forces MFA re-enrollment. |
| `DEVICE_TOKEN_PEPPER` | yes | ≥ 32 characters, random. HMAC key for device tokens, enrollment codes and license keys. Changing it invalidates them all. |
| `NEXT_PUBLIC_SUPPORT_EMAIL` | no | Shown on the Support page. If unset the page says no contact is configured. |
| `RETENTION_DAYS_FINDINGS` `…_EVENTS` `…_QUARANTINE` `…_REVOKED_DEVICES` | no | See [OPERATIONS.md](OPERATIONS.md#retention-and-deletion). |
| `VIRUSTOTAL_API_KEY` | no | Reserved. Reputation lookups are not implemented; if added, keys stay server-side. |

`apps/admin/.env` is gitignored; `.env.example` documents the keys. Never put secrets in `NEXT_PUBLIC_*` variables.

## Desktop build

| Variable | When | Description |
|---|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` / `…_PASSWORD` | build | Updater private key (content) and passphrase. Set by `scripts/build-release.ps1`. |
| `SENTRIX_SIGNING_KEY_PATH` / `SENTRIX_SIGNING_KEY_PASSWORD` | build script | Where the production key lives. |
| `SENTRIX_UPDATE_BASE_URL` | compile time (optional) | Console base URL baked in for update checks on devices that are not enrolled. Enrolled devices use their console URL. |
| `SENTRIX_CLAMAV_DIR` | runtime / tests | Override for the ClamAV runtime location (installed app uses `<install dir>\engine\clamav`). |
| `SENTRIX_DATA_DIR` | CLI / tests | Data directory containing `clamav-db`. |

## Test harness

| Variable | Description |
|---|---|
| `SENTRIX_E2E_DESKTOP=1` | Enables the Rust-client ↔ console end-to-end test. |
| `SENTRIX_ARTIFACT` | Path to a built installer for the signature test. |
