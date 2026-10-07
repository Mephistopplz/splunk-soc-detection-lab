# Detection 01: Web Vulnerability Scanning

Severity: low (useful for correlation rather than as a standalone alert)
Status: validated against the BOTSv1 attack-only dataset

## Overview

This search flags a single source requesting an unusually large number of distinct URL paths from our web servers within an hour. Automated vulnerability scanners behave this way regardless of which product is being used, because covering a site means requesting a great many paths.

## ATT&CK mapping

| Tactic | Technique |
|---|---|
| Reconnaissance (TA0043) | T1595.002 Active Scanning: Vulnerability Scanning |

The scan also carried SQL, command, LDAP and expression injection payloads, which relates it to T1190 Exploit Public-Facing Application. This search identifies the attempts but says nothing about whether any of them succeeded.

## Data

Splunk Stream HTTP data (`index=botsv1`, `sourcetype=stream:http`), using `src_ip`, `dest_ip`, `uri_path` and `http_user_agent`.

## Search

```spl
index=botsv1 sourcetype=stream:http
| bin _time span=1h
| stats count AS requests dc(uri_path) AS unique_paths dc(http_user_agent) AS unique_agents values(dest_ip) AS targets by _time src_ip
| where unique_paths > 500
| sort -unique_paths
```

The one-hour bins approximate an hourly scheduled search. The threshold applies only to `unique_paths`. The request count, number of user agents and target list are there to give whoever picks up the alert enough context to triage it without running further searches.

## Choosing the threshold

Before settling on a number, I compared every HTTP source in the dataset over the full time range:

| src_ip | requests | unique_paths | unique_agents |
|---|---|---|---|
| 40.80.148.42 | 17,547 | 1,872 | 50 |
| 23.22.63.114 | 1,429 | 2 | 183 |
| 192.168.2.50 | 818 | 163 | 2 |
| 192.168.250.100 | 93 | 42 | 11 |
| 192.168.250.70 | 7 | 4 | 0 |

The busiest legitimate client requested 163 distinct paths across the whole period, against 1,872 for the scanner. A threshold of 500 sits well clear of both.

The comparison also showed that user agent diversity would have been the wrong measure. `23.22.63.114` used the most user agents of any source but only ever requested two paths. That traffic turned out to be a separate attack, covered in Detection 02.

## Validation

The search returned one result and no false positives:

| _time | src_ip | requests | unique_paths | unique_agents | targets |
|---|---|---|---|---|---|
| 2016-08-10 21:00 | 40.80.148.42 | 9,501 | 1,870 | 50 | 192.168.250.40, 192.168.250.70 |

Almost the entire scan, 1,870 of its 1,872 paths, fell within a single hour and covered two internal servers.

![Detection 01 result](../docs/screenshots/01-web-vuln-scanning.png)

## Why the user agent isn't used

The scanner's name does appear in the data, as `acunetix_wvs_security_test`, but only in a handful of user agent strings that were themselves injection payloads. More than 99 per cent of its requests presented an ordinary Chrome user agent. Since the user agent is set by the client, a search that relied on it could be defeated by changing a single setting.

## Evasion

Thinking about how I would get past this search as the attacker:

- Running the scan slowly, below 500 paths an hour, would keep every hourly window under the threshold. A second search over 24 hours with a proportionally higher threshold would still catch it, only later.
- Spreading the scan across many source addresses would keep each one below the line. Aggregating by destination rather than by source would close that gap.
- Limiting the scan to a short list of paths known to be vulnerable would avoid the breadth this search depends on. That is the fundamental weakness of the approach, and the main reason I treat it as context rather than as an alert in its own right.

## False positives

Search engine crawlers, SEO tools, uptime monitoring and authorised internal vulnerability scanning can all request large numbers of paths. An allowlist of known crawler and scanner addresses, maintained as a Splunk lookup, would handle most of these. I have left that as future work.

## Limitations

The baseline is thin. I validated this against attack-only data containing five sources, whereas a production web server sees thousands of clients, so the threshold would need tuning against real traffic before I relied on it.

Internet-facing servers are also scanned constantly, which limits the value of this search on its own. It becomes useful when correlated with later activity from the same source, such as a successful login.

## Response

1. Check whether the source is an authorised internal scanner or a known crawler.
2. Review the response codes for any probes that succeeded against sensitive paths.
3. Search for any later activity from the same source, such as login attempts or uploads.
4. Block or monitor the source at the firewall or web application firewall (WAF) in line with policy.

## Investigation notes

I started by ranking every source of HTTP traffic by request count. One external address, 40.80.148.42, accounted for about three quarters of all requests, which made it the obvious candidate, but volume alone doesn't prove much. A monitoring service or a proxy can be just as noisy.

Looking at its user agents settled it. Almost every request claimed to be Chrome, but around fifty variants were injection payloads, several of them naming Acunetix. That was also what convinced me not to build the detection on the user agent.

My first attempt at a comparison returned a single row, because I had left the scanner's address in the search from the previous step. Removing it gave me all five sources side by side, which is what the threshold is based on. I then binned the data by hour to check the pattern would still stand out in the kind of window a scheduled search would use.
