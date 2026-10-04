# Splunk SOC Detection Lab

A hands-on detection engineering lab built in Splunk Enterprise (running in Docker) against Splunk's public **Boss of the SOC v1 (BOTSv1)** attack dataset. Each detection is mapped to MITRE ATT&CK, validated against real attack data, and documented with its false positives, evasion paths and triage steps.

Rebuilt and extended from my Monash University Cybersecurity Bootcamp coursework.

> **Status:** in progress. Detections are added as they're validated.

## What's in the repo

| Path | What it is |
|---|---|
| `docker/` | Compose file to run Splunk locally (bound to localhost only; secrets live in `.env`, which is never committed) |
| `splunk-app/TA-botsv1-sysmon/` | My custom search-time field extractions for Sysmon XML, mounted read-only into Splunk |
| `detections/` | One file per detection: SPL, ATT&CK mapping, threshold rationale, validation evidence, false positives and evasion notes |
| `docs/screenshots/` | Evidence of each detection firing |

## Detections

| # | Detection | MITRE ATT&CK | Status |
|---|---|---|---|
| 01 | [Web vulnerability scanning](detections/01-web-vuln-scanning.md) | T1595.002 | Validated |
| 02 | [Brute force and credential reuse](detections/02-brute-force-credential-reuse.md) | T1110.001, T1078 | Validated |
| 03 | Suspicious executable on the web server | T1204 / T1059 | Planned |
| 04 | Office document spawning a shell | T1204.002 | Planned |
| 05 | Ransomware-style file activity over SMB | T1486 | Planned |
