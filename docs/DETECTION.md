# Detection engine and verdict rules

## Layers

| Layer | Implementation | Notes |
|---|---|---|
| A. Identification | `identify.rs`: magic bytes (PE, ELF, Mach-O, LNK, PDF, ZIP→OOXML/JAR/APK, OLE2, 7z, RAR, GZIP, ISO, images, media), content sniffing for scripts, extension-mismatch and double-extension detection | The extension is only ever used to flag a *mismatch*. DMG is recognized by extension only (its trailer is at end of file). |
| B. Known threats | ClamAV 1.5.4 via `clamd` INSTREAM; EICAR test-file detector (`eicar.rs`, never counts toward CLEAN) | ClamAV does not detect everything. `Heuristics.Encrypted.*` and `Heuristics.Limits.*` are treated as **coverage gaps**; other `Heuristics.*` / `PUA.*` as SUSPICIOUS; everything else MALICIOUS. |
| C. Static heuristics | `heuristics.rs`, `archive.rs`: PE sections/imports/entropy/overlay/embedded PE, script download-and-execute patterns, PDF `/Launch` `/JavaScript`, OLE2 macros, LNK interpreters, ZIP traversal/double extension/bombs | **Evidence, not proof.** Cannot produce MALICIOUS by themselves. |
| Signature check | `signature.rs`: WinVerifyTrust, revocation disabled (no network side-effects) | Catalog-signed system files show as "unsigned". |
| D. Reputation | **Not implemented.** | Would query hashes only, server-side keys, with consent. |
| E. Sandbox | **Not implemented.** | Would require an isolated analysis service; deliberately not simulated. |
| Host security provider | `ERROR_VIRUS_INFECTED` (os error 225/226) when reading a file is reported as a detection by the OS security provider | Observed in testing with Microsoft Defender on EICAR. |

## Verdicts

`verdict.rs` is the single decision point.

| Verdict | Rule |
|---|---|
| **MALICIOUS** | A signature engine (ClamAV, EICAR test detector, or the host security provider) matched. Never from heuristics alone. |
| **SUSPICIOUS** | Weighted heuristic/integrity score ≥ 3, or any High-severity non-signature finding. Weights: Info 0, Low 1, Medium 3, High 5. Not a probability. |
| **CLEAN** | ClamAV **completed**, and no applicable check was unavailable, failed or partial. |
| **UNABLE TO VERIFY** | Everything else: no engine, parser failure, encrypted/oversized/nesting-limited content, unreadable file, cancellation. |
| **PENDING** | Analysis in progress. |

There is no confidence percentage: no validated statistical model supports one.

### Examples (from the test-suite)

* Benign text, ClamAV running → CLEAN.
* Same file, ClamAV not installed → UNABLE TO VERIFY ("no malware-signature engine was available").
* EICAR streamed to ClamAV → `Eicar-Test-Signature` → MALICIOUS.
* EICAR on disk with Defender active → read blocked by the OS → MALICIOUS via host provider, scan marked incomplete.
* PE renamed `.jpg` → identified as PE, extension mismatch (Medium) → SUSPICIOUS.
* Corrupt ZIP, over-limit file, cancelled scan → never CLEAN.

## Resource limits (defaults, user-adjustable where noted)

| Limit | Default |
|---|---|
| File loaded for static analysis | 128 MiB (larger files: signature engine only, reported partial) |
| File sent to ClamAV | 512 MiB (adjustable) |
| Archive nesting depth | 3 (adjustable, max 8) |
| Archive entries | 10 000 |
| Total decompressed per archive | 256 MiB |
| Single entry | 128 MiB |
| Compression ratio flagged as bomb | 200:1 (entries > 1 MiB) |

Archives are inspected **in memory** and never extracted to disk or executed. A lying archive header (data larger than
declared) is itself a finding. Parsers run under `catch_unwind`; a crash degrades the check to *Failed*.

## Threat knowledge (what kind of threat is it?)

Two pieces turn a bare "Suspicious" or a signature name into something a person can act on.

**Attacker-technique rules** (`rules.rs`: 34 content rules and 3 file-name rules). Each rule is a behaviour attackers need (steal browser logins and send
them to a Telegram bot, delete backups, open a reverse shell, build a download inside a web page, fetch an Office template from
the internet, put a launcher in a disk image, ask an Android app for SMS plus accessibility powers, ...), with a threat family
and MITRE ATT&CK technique ids. A rule fires only when **every** pattern group has a hit, so a lone common word never fires.
Patterns are matched in one Aho-Corasick pass, case-insensitively, as plain text and as UTF-16LE. Large files are sampled
(first 16 MiB and last 2 MiB). Archive members go through the same rules. Rules are **evidence**: they add to the score and can
reach SUSPICIOUS, never MALICIOUS. Low-severity rules (weight 1) stay below the threshold on their own.

Pattern strings contain a `~` break marker (`mimi~katz`) that is removed at start-up. Keyword-based antivirus treats a list of
attacker words as malware: Windows Defender deleted the first version of `rules.rs` for exactly that reason. A unit test requires
a marker inside every long pattern.

**Threat families** (`threat_kb.rs`, 23 families: ransomware, stealers, spyware, backdoors/RATs, loaders, credential theft,
phishing, web shells, miners, worms, botnets, wipers, exploits, malicious macros, mobile trojans, banking trojans, rootkits,
file infectors, adware, generic trojans, test files, unclassified malware). Each has the attacker's goal, how it usually arrives,
ATT&CK ids and advice. The report's **threat card** (desktop, Telegram, text export) uses them:

* **Identified as**: the signature engine named it (e.g. `Win.Ransomware.*`, `*.Stealer.*`); the name is mapped to a family.
  An engine name we cannot map is still shown as malware, never dropped.
* **Looks like**: no engine name, but a Medium or High technique rule matched. Always labelled a guess, not proof.
* No card for CLEAN, UNABLE TO VERIFY or findings below Medium.

**False-positive check.** `cargo test -p sentrix-core --test benign --release -- --ignored --nocapture` runs the heuristics over
~5000 ordinary files from Windows and installed programs and prints which technique rules fire. The first run showed noisy rules
(botnet names that are ordinary Japanese words, a ransom-note rule hitting JavaScript bundles); they were tightened (more pattern
groups, size limits for page-type rules, lower severity for weak ones). Current result on the author's machine: no technique rule
above Low on 4999 files. The older PE heuristics (API combinations) still raise Medium on about 1% of installed software; that is
a known trade-off, not a rule bug. The check also found a crash on empty files, now fixed and covered by a test.

## What this does **not** cover

No tool detects "all" malware, and this one does not claim to:

* **New or unknown malware** (zero-day, freshly recompiled, custom-made) has no signature; only the behaviour rules can notice it,
  and only if it shows one of the listed behaviours.
* **Packed, encrypted or obfuscated** content hides its strings from static rules. Password-protected archives are UNABLE TO VERIFY.
* **Fileless and in-memory attacks, network exploits, malicious websites, stolen passwords, social engineering** are not
  something a file scanner can see. SENTRIX looks at files.
* **Behaviour that needs running the file** (sandbox) is not implemented.
* Signature quality is ClamAV's: the database is refreshed every 2 hours while the bot service runs, and the desktop app updates it
  on its own schedule. ClamAV's free database is smaller than commercial ones.

## Known false-positive/false-negative behaviour

* Installers legitimately combine downloaders, registry writes and embedded executables; they may score SUSPICIOUS.
  That is intentional: the report explains the evidence and the user decides.
* Obfuscated or novel malware without a ClamAV signature and without the heuristic traits above will be CLEAN.
  This is the reason CLEAN is described everywhere as "no threat found by the checks that ran".
* Password-protected archives are reported UNABLE TO VERIFY (ClamAV runs with `AlertEncrypted yes`).
* 7z / RAR / ISO / DMG contents are inspected by ClamAV's unpackers only.

No detection-rate benchmarks are published here, because none were measured. Only EICAR and synthetic fixtures were used.
