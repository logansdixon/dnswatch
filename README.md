# dnswatch

Continuous DNS health monitor for incident response.

Hammers up to 4 DNS servers in parallel with randomized lookups of known-good
domains, shows a live pass/fail + latency dashboard, and logs every query to
CSV for the post-incident record. Queries any server by IP (internal,
corporate, or public) — unlike a browser, which only tells you whether
*something* worked.

## Two implementations

| File            | Runtime                                      | Dependencies          | Use when                                    |
| --------------- | -------------------------------------------- | --------------------- | ------------------------------------------- |
| `dnswatch.py`   | Python 3.9+                                  | `dnspython`, `rich`   | You have Python and want the rich dashboard |
| `dnswatch.ps1`  | PowerShell 5.1+ / 7+ (Windows / Linux / Mac) | None — pure .NET UDP  | Locked-down Windows box, no Python allowed  |

Both versions follow the same logic: query each server, distinguish transient
failures from definitive negatives, apply retries, and keep rolling stats.

## Install (Python)

```bash
git clone <this-repo> dnswatch
cd dnswatch
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Watch 4 servers, default 2s interval, A records
python3 dnswatch.py 10.1.1.53 10.1.2.53 8.8.8.8 1.1.1.1

# Two servers, 2s interval, 3s timeout
python3 dnswatch.py 10.1.1.53 8.8.8.8 --interval 2 --timeout 3

# Non-standard port + AAAA records
python3 dnswatch.py 192.168.1.1#5353 9.9.9.9 --type AAAA

# Custom domain list, custom log path
python3 dnswatch.py 10.1.1.53 --domains-file mydomains.txt --log incident.csv
```

PowerShell:

```powershell
.\dnswatch.ps1 10.1.1.53 10.1.2.53 8.8.8.8 1.1.1.1
.\dnswatch.ps1 10.1.1.53 8.8.8.8 -Interval 2 -Timeout 3
```

Server format: `<ip>` or `<ip>#<port>` (e.g. `10.1.1.53` or `10.1.1.53#5353`).
Stop with **Ctrl+C** — a summary prints and the CSV is flushed.

## CLI flags (Python)

| Flag                | Default            | Meaning                                                  |
| ------------------- | ------------------ | -------------------------------------------------------- |
| `servers`           | (required, 1–4)    | DNS server IPs, optionally `<ip>#<port>`                 |
| `-i, --interval`    | `2.0`              | Seconds between query rounds                             |
| `-t, --timeout`     | `2.0`              | Per-query timeout in seconds (retries use half this)     |
| `-T, --type`        | `A`                | Record type: `A`, `AAAA`, `MX`, `NS`, `TXT`, ...         |
| `-c, --count`       | `0` (forever)      | Stop after N rounds                                      |
| `--domains-file`    | (built-in list)    | One domain per line; `#` lines ignored                   |
| `--log`             | `dnswatch_log.csv` | CSV output path                                          |
| `-r, --retries`     | `1`                | Retry transient failures (timeout/SERVFAIL) up to N      |
| `--no-validate`     | off                | Skip the startup domain-pool sanity check                |
| `--no-rich`         | off                | Plain line-by-line output instead of the live dashboard  |

## Dashboard

The live view shows per server:

- Queries / OK / Fail counts, success %
- Last latency and rolling-20 average latency
- Last result (answer text, or error reason like `TIMEOUT`, `NXDOMAIN`, `SERVFAIL`)
- A status dot — grey before first query, green/yellow/red by health, **blinking red** after 3+ consecutive failures

A recent-activity log panel below the table shows the last 10 rounds.

## CSV log format

```
timestamp,server,domain,type,ok,latency_ms,result
2026-06-16T14:37:58,10.0.0.53,akamai.com,A,True,922,23.11.231.192  [ok after 1 retry]
2026-06-16T14:38:03,10.0.0.54,akamai.com,A,False,-,TIMEOUT (>3.0s)
```

Successful retries are annotated in the `result` column.

## Retries and validation

- **Transient failures** (timeout, SERVFAIL) are retried up to `--retries` times,
  the way a real stub resolver does. Retries use half the timeout so a dead
  server doesn't stall the dashboard. The result column notes when a query
  recovered on retry.
- **Definitive negatives** (NXDOMAIN, no-such-record) are *not* retried —
  retrying them just hides bad domains in your pool.
- At startup, every domain is probed against every server. Domains where at
  least one server returns a definitive negative and no server returns a
  valid answer are dropped (e.g. apex `cloudfront.net` has no A record).
  Timeouts never drop a domain — during an outage the servers, not the
  domain, may be the problem. Skip this check with `--no-validate`.

## Domain pool

The built-in list spans a spread of globally distributed, stable domains
across *different* authoritative DNS providers, so the test isn't just
measuring one CDN's health. Override with `--domains-file <path>` (one domain
per line, `#` comments allowed).

## Exit summary

On Ctrl+C, dnswatch prints a per-server verdict:

```
  10.1.1.53                99.4% ok  (487/490)  avg 18ms     -> HEALTHY
  10.1.2.53                52.1% ok  (255/490)  avg 412ms    -> DEGRADED
  8.8.8.8                  100.0% ok (490/490)  avg 22ms     -> HEALTHY
```

Thresholds: `>=99%` HEALTHY, `>=50%` DEGRADED, otherwise DOWN/FAILING.
