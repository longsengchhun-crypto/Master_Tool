# Key management

SENTRIX has three families of keys. Do not confuse them.

| Key | Protects | Held by | In this repo |
|---|---|---|---|
| **Updater signing key** (minisign) | Integrity of application updates | Release manager, offline | Only the **public** key, in `tauri.conf.json` (currently a *development* key) |
| **Authenticode certificate** | Publisher identity / SmartScreen | Release manager / CA / Azure Trusted Signing | **None: blocked** |
| Console secrets (`SESSION_SECRET`, `DEVICE_TOKEN_PEPPER`) | Sealed TOTP seeds, hashed credentials | Secret manager | Never |

ClamAV signatures are signed by the ClamAV project (`.cvd`); `freshclam` verifies them. SENTRIX adds no key there.

## Generating the production updater key

On a clean, offline-capable machine (not a CI runner):

```powershell
cd apps\desktop
npx tauri signer generate -w D:\secure\sentrix-updater.key        # prompts for a strong password
```

* Output: the private key file and a `.pub` file. The `.pub` content is what goes into `tauri.conf.json` →
  `plugins.updater.pubkey`.
* Use a passphrase of ≥ 20 random characters from a password manager. The key is useless without it and the password
  cannot be recovered.

## Protecting it

* Store the private key **offline** (encrypted USB/HSM-backed vault) with the passphrase stored separately.
* Keep **two** encrypted copies in different physical locations (see recovery).
* CI must not hold it unless you accept that CI compromise = update compromise. If CI signs, use an isolated signing job,
  required approvals, and short-lived secret injection; prefer signing on a dedicated release machine.
* Never commit it, paste it into chat, or put it in an image. `.gitignore` excludes `*.key`, `*.pem`; CI runs gitleaks.
* The development key lives in `%USERPROFILE%\.sentrix-keys\` on the developer machine only. **Builds signed with it must
  never be distributed**: `build-release.ps1 -DevKey` records `updateKey: DEVELOPMENT` in the manifest.

## Rotation

Rotation is a **two-release** process because installed apps only trust the key they were built with:

1. Generate the new key pair.
2. Build release *N* containing the **new public key**, but sign it with the **old** private key (installed apps accept it).
3. Roll out *N* until the fleet has adopted it (Console → Overview → installed versions).
4. From release *N+1* onward, sign with the new key. Retire and securely destroy the old key.

Rotate on: personnel change with key access, suspected exposure, or on a yearly schedule.

## Compromise response

If the updater private key (or its passphrase) may be exposed:

1. **Stop** serving updates: roll back/cancel all staged and published releases in the console (offers stop immediately).
2. Treat any release signed after the suspected exposure as untrusted; do not re-offer it.
3. Generate a new key. Because installed apps trust only the old public key, the fleet cannot receive an update signed with the
   new key. Ship a **new full installer** (download page, checksum shown) and instruct users/administrators to reinstall;
   enrolled devices can be told via policy `minAppVersion` and the console release status.
4. Record the incident in the audit trail and follow [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md).

## Recovery (lost key)

If the private key or passphrase is lost without compromise: the same situation as step 3 above: no further signed updates
can be accepted by existing installs; distribute a new installer carrying a new public key. This is why two escrowed copies matter.

## Verification at every release

`scripts/build-release.ps1` verifies the produced `.sig` against the public key **in the built config** and also confirms a
single flipped byte in the installer fails verification. A release that fails this step must not ship.
