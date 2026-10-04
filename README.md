# Splunk SOC Detection Lab

A detection engineering lab built in Splunk Enterprise, running locally in Docker, against Splunk's public Boss of the SOC v1 (BOTSv1) dataset. Each detection is mapped to MITRE ATT&CK, validated against the attack data, and written up with its threshold reasoning, likely false positives, evasion paths and response steps.

The project rebuilds and extends coursework from my Monash University Cybersecurity Bootcamp.

Status: in progress. Detections are added once they have been validated.

## Repository layout

| Path | Contents |
|---|---|
| `docker/` | Compose file for running Splunk locally. The web interface is bound to localhost only, and secrets are kept in an uncommitted `.env` file. |
| `splunk-app/TA-botsv1-sysmon/` | A small add-on I wrote to provide search-time field extraction for Sysmon XML events. It is mounted into Splunk read-only. |
| `detections/` | One file per detection, covering the search, ATT&CK mapping, threshold reasoning, validation, false positives and evasion. |
| `docs/screenshots/` | Evidence of each detection firing against the dataset. |

## Detections

| # | Detection | MITRE ATT&CK | Status |
|---|---|---|---|
| 01 | [Web vulnerability scanning](detections/01-web-vuln-scanning.md) | T1595.002 | Validated |
| 02 | [Brute force and credential reuse](detections/02-brute-force-credential-reuse.md) | T1110.001, T1078 | Validated |
| 03 | Suspicious executable on the web server | T1204 / T1059 | Planned |
| 04 | Office document spawning a shell | T1204.002 | Planned |
| 05 | Ransomware-style file activity over SMB | T1486 | Planned |
