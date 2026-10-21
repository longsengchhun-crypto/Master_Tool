# Performance: measured, not promised

Measured with `services/scanner/tests/perf.rs` (release build, real ClamAV 1.5.4, signatures current as of the run) on
**one machine**: Intel Core i7-13700KF (24 logical cores), 32 GB RAM, Windows 11, NVMe storage, Microsoft Defender
real-time protection active. These numbers describe that machine at that moment. They are not benchmarks and should not
be quoted for other hardware.

| Scenario | Result |
|---|---|
| `clamd` start (signature load) | 9.8 s (one-time per engine start; the app starts it in the background) |
| 3 000 small text files (~1 KB), 2 workers, cache disabled | 12.9 s, ≈ 233 files/s |
| The same 3 000 files unchanged, cache hits (path + size + mtime → hash + engine/signature version) | 0.08 s |
| One 256 MiB random file, first scan | 6.0 s, ≈ 43 MiB/s end to end (hash + stream to engine) |
| Same file again with a different `Scanner` instance | 0.6 s: **this is clamd's own content-hash cache answering, not streaming throughput**; do not read it as a speed |

What was *not* measured: memory high-water marks, whole-disk scans, many-large-files workloads, behaviour under heavy
disk contention, or CPU use while the UI is open. None of these numbers cover archives with deep nesting.

## Design measures that bound resource use (tested, not benchmarked)

* Heavy analysis runs on worker threads; the UI thread only receives throttled progress events (≤ ~7 per second).
* Discovery streams through a 2 048-entry bounded queue, so a whole-disk scan's memory use does not grow with the number
  of files; retained reports are capped (500 clean + up to 5 000 needing attention; counts stay exact).
* Files over 128 MiB are hashed by streaming and sent to the engine only; they are reported as partially analysed.
* Unchanged files are not rescanned (cache keyed by content hash and engine/signature versions); changed content always is.
* Every scan can be cancelled; a cancelled batch returns promptly and is marked incomplete (deadlock regression test).
* `clamd` is restarted on demand if it dies, and is killed with the app (Windows job object).
* Notifications are de-duplicated per file hash; the monitor waits for downloads to settle before scanning.

## Phase 2 measurements (automatic protection)

Same machine and method as above (real ClamAV 1.5.4, Defender active). Each figure is a **single run**, taken from
`cargo test -p sentrix-core --test service --test perf -- --ignored --nocapture`; run-to-run variation on this machine was
large (the same 3 000-file scenario gave 143 files/s in one release run and 215 files/s in an earlier debug run, so treat
throughput as "order of 100-250 files/s for tiny files", not a benchmark).

| Scenario | Result |
|---|---|
| New small file in a watched folder → report available (includes the 1.5 s settle delay and scan) | 2.5 s (one release run) |
| ... → message accepted by the local Bot API **test double** | 3.1 s (excludes real Telegram/network latency, which was not measured) |
| 3 000 small files, 2 workers, no cache | 13.9 s debug / 21.0 s release (215 / 143 files/s) |
| Same files unchanged (cache hits) | 0.08-0.18 s |
| `clamd` start (signature load) | 6.6-9.1 s |

Not measured: live Telegram delivery latency (no bot token), queue behaviour with tens of thousands of pending files,
memory use of the service over days, CPU use while idle. The queue and outbox are bounded (20 000 jobs / 1 000 pending
messages), which limits storage growth but was only unit-tested, not stress-tested at those sizes under real scanning.
