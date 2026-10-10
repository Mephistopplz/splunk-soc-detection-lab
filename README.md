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
| 03 | [Web shell and executable in the web root](detections/03-web-shell-webroot-executable.md) | T1505.003, T1059.003, T1105 | Validated |
| 04 | [Office application starting a shell or script host](detections/04-office-spawns-shell.md) | T1204.002, T1059.003, T1059.005 | Validated |
| 05 | [Ransomware disabling system recovery](detections/05-inhibit-system-recovery.md) | T1490 | Validated |

## What I learned

### Detection 01: web scanning

Volume alone can be misleading, because it doesn't separate scanning from other traffic. Counting distinct paths targets the behaviour and leaves out most false positives. I also learned not to trust the user agent, because the scanner used a normal Chrome one for nearly every request.

### Detection 02: brute force and credential reuse

The brute force wasn't the important part. The login from a second IP with a single attempt was, and a per-source threshold would never have caught it. I also found out that stats drops events when one of the fields you group by is empty, which is why two of my counts were off by one.

### Detection 03: web shell

An attacker can change file names whenever they want, so the web server starting a shell is a much stronger signal than looking for `agent.php`. I learned to prove which host an IP belongs to before pivoting, instead of going on the hostname, and to check the sampling setting after one search showed me 6 events instead of 105.

### Detection 04: Office macro

I didn't search for Office straight away. I listed what started what and let the data show me. When I assumed `wscript.exe` had run the script, I had to go back and prove it, because "that's what Windows normally does" isn't evidence. Leaving off one filter gave me 588 events instead of 2, and the event count was what caught it.

### Detection 05: ransomware

The original plan was SMB file activity, but the data had a better signal, so I changed the plan instead of forcing it. The shadow copy deletion happened 26 minutes before the ransom note, which is the window where a defender could still act.

### Splunk in general

- A filter on a field only works after the command that creates it, so the order of the lines matters.
- An empty result or a wrong count usually means my search is wrong, not that nothing happened. Splunk doesn't give errors for typos in field names or values.
- Field value matching isn't case sensitive, so changing capitals doesn't get past a search.
- I check the event count, time range and sampling before trusting any result.
- Investigations grow fast. I parked anything that didn't help build the detection and kept it as future work.
