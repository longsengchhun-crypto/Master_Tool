# Incident response and recovery

Severity guide: **SEV1** = possible compromise of user devices or admin accounts; **SEV2** = data exposure or loss of
integrity without device impact; **SEV3** = degraded service.

## First 30 minutes (any SEV1/SEV2)

1. Page the incident lead; open a private incident channel and a timeline document.
2. Preserve evidence: copy console logs and export the audit log (`GET /api/admin/audit?limit=500` pages, or `COPY` from the
   database). Run `GET /api/admin/audit?verify=1`. A broken chain is itself a finding, and the first broken `seq` tells you where.
3. Contain (below), then investigate. Do not delete anything.

## Playbooks

### Suspected admin account takeover
* Console → Users → **Deactivate** the account (kills all its sessions) and **Reset 2-step** if the second factor may be lost.
* Review `auth.*`, `user.update`, `device.revoke`, `license.*`, `policy.write`, `release.*` events for that actor.
* Rotate `SESSION_SECRET` only if sealed TOTP seeds may be exposed (forces all admins to re-enroll MFA).
* Revert malicious policies by writing the previous policy (every write logs the full config).

### Database exposure
* Rotate `DATABASE_URL` credentials first.
* Stored credentials are not directly usable: passwords are argon2id, device tokens / enrollment codes / license keys are
  HMACs (secret pepper is *not* in the database), TOTP seeds are AES-GCM sealed, sessions are stored hashed.
  Exposure of the database **plus** `DEVICE_TOKEN_PEPPER` allows forging device credentials → rotate the pepper
  (devices re-enroll) and revoke licenses/keys that may be abused.
* Findings metadata is hashes/verdicts (file names only for orgs that opted in): assess notification duties accordingly.

### Compromised or suspect release / updater key
Follow [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md#compromise-response). Immediately **rollback/cancel** the affected release in the console.

### A device reports a malicious finding
Informational for the operator: the user has the report. The console holds hash + verdict. Use `Security events`, confirm
the verdict source (`clamav` vs `heuristic.*`), and if the hash is a suspected false positive, ask the user for the report
(no file contents are ever uploaded) and confirm with a second engine.

### False positive affecting many users
Heuristic verdicts are SUSPICIOUS, never MALICIOUS. If ClamAV flags a legitimate file, report it to ClamAV (`clamsubmit`/web form).
Short term: org policy `allowUserRestoreSuspicious` lets users restore suspicious files; malicious restores require typed confirmation.

### Console outage
Devices keep scanning and protecting locally; they simply cannot check in. Heartbeat failures are shown on the device's
Account page and retried every 5 minutes. No protection feature depends on console reachability.

## Recovery

1. Restore the database from the latest good backup/PITR point into a **new** database.
2. Run migrations, point the console at it, run `GET /api/admin/audit?verify=1`.
3. Re-issue secrets that may have been exposed; ask admins to re-verify MFA if `SESSION_SECRET` rotated.
4. After a restore, devices that enrolled/updated *after* the restore point will present valid-looking tokens that the
   database no longer knows → they receive 401 and drop management locally (by design); re-enroll them.

## After action

Record: timeline, root cause, detection gap, data affected, changes made, tests added. Add a regression test for any
vulnerability found (the integration suite in `apps/admin/tests/security.test.ts` is the place).

## Reporting vulnerabilities (SECURITY.md)

Please report privately to the address in `SECURITY.md` (to be filled in with a real security mailbox before launch).
