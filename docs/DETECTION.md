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

## Known false-positive/false-negative behaviour

* Installers legitimately combine downloaders, registry writes and embedded executables; they may score SUSPICIOUS.
  That is intentional: the report explains the evidence and the user decides.
* Obfuscated or novel malware without a ClamAV signature and without the heuristic traits above will be CLEAN.
  This is the reason CLEAN is described everywhere as "no threat found by the checks that ran".
* Password-protected archives are reported UNABLE TO VERIFY (ClamAV runs with `AlertEncrypted yes`).
* 7z / RAR / ISO / DMG contents are inspected by ClamAV's unpackers only.

No detection-rate benchmarks are published here, because none were measured. Only EICAR and synthetic fixtures were used.
