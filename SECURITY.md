# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** and give us a reasonable time to fix them before public disclosure.

> **Contact:** *to be set before public launch.* A monitored security mailbox (for example `security@<your-domain>`) and,
> ideally, GitHub private vulnerability reporting must be enabled. Until then this repository has no confirmed
> reporting channel.

Include: affected component and version, reproduction steps, impact, and whether you believe data or devices were exposed.
Please do not include real malware samples; a file hash and the SENTRIX report are enough.

## Scope

In scope: the desktop app and engine (`apps/desktop`, `services/scanner`), the console and its APIs (`apps/admin`),
the update feed and signing process, the installer. Out of scope: vulnerabilities in ClamAV itself (report to the ClamAV
project), social engineering, denial of service via volume, findings that require a compromised user account on the device
(see the residual-risk list in [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)).

## What we promise, and what we do not

SENTRIX does not claim to detect all malware, to be "100% secure", or to prevent every program from running. It reports
what it checked and what it could not check. A third-party penetration test has **not** been performed.

## Supported versions

Only the latest release receives security fixes during the pre-release phase.
