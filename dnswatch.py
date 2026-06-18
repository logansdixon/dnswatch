#!/usr/bin/env python3
"""
dnswatch.py - Continuously test DNS resolution across up to 20 DNS servers.

Built for incident response during a DNS outage: hammers each server with
randomized lookups of known-good domains, shows a live pass/fail + latency
dashboard, and logs everything to a CSV for the post-incident record.

Queries any server by IP (internal/corporate or public), unlike a browser.

Usage:
    python3 dnswatch.py 10.1.1.53 10.1.2.53 8.8.8.8 1.1.1.1
    python3 dnswatch.py 10.1.1.53 8.8.8.8 --interval 2 --timeout 3
    python3 dnswatch.py 192.168.1.1#5353 9.9.9.9 --type AAAA
    python3 dnswatch.py 10.1.1.53 --domains-file mydomains.txt --log incident.csv

Server format:  <ip>  or  <ip>#<port>   (e.g. 10.1.1.53  or  10.1.1.53#5353)
Stop with Ctrl+C; a summary is printed and the CSV is flushed.

Requires: dnspython, rich   ->   pip install dnspython rich
"""

import argparse
import csv
import random
import signal
import socket
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit("Missing dependency. Install with:  pip install dnspython rich")

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.console import Group
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False


# A spread of globally distributed, stable domains across *different*
# authoritative DNS providers, so we're not just testing one CDN's health.
DEFAULT_DOMAINS = [
    "google.com", "cloudflare.com", "microsoft.com", "amazon.com", "apple.com",
    "github.com", "wikipedia.org", "mozilla.org", "cisco.com", "akamai.com",
    "fastly.com", "netflix.com", "ietf.org", "debian.org", "ubuntu.com",
    "python.org", "stackoverflow.com", "reddit.com", "bbc.co.uk", "nytimes.com",
    "salesforce.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "adobe.com", "dropbox.com", "slack.com", "zoom.us", "office.com",
    "bing.com", "yahoo.com", "wordpress.org", "gnu.org", "kernel.org",
    "archive.org", "cnn.com", "paypal.com", "ebay.com", "linkedin.com",
    "spotify.com", "twitch.tv", "nucor.com", "azure.com",
]


def parse_server(spec):
    """Parse '<ip>' or '<ip>#<port>' into (ip, port). Validates the IP."""
    ip, _, port = spec.partition("#")
    ip = ip.strip()
    port = int(port) if port else 53
    # Validate as IPv4 or IPv6
    valid = False
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, ip)
            valid = True
            break
        except OSError:
            continue
    if not valid:
        raise argparse.ArgumentTypeError(
            f"'{ip}' is not a valid IPv4/IPv6 address (use <ip> or <ip>#<port>)"
        )
    return (ip, port)


class ServerStat:
    """Rolling stats for one DNS server."""

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.label = ip if port == 53 else f"{ip}#{port}"
        self.queries = 0
        self.ok = 0
        self.fail = 0
        self.total_ms = 0.0
        self.recent_ms = deque(maxlen=20)
        self.last_ms = None
        self.last_ok = None          # None=unknown, True=ok, False=fail
        self.last_result = ""        # answer string or error reason
        self.consecutive_fail = 0
        self.lock = threading.Lock()

    def record(self, ok, ms, result):
        with self.lock:
            self.queries += 1
            self.last_ok = ok
            self.last_ms = ms
            self.last_result = result
            if ok:
                self.ok += 1
                self.consecutive_fail = 0
                self.total_ms += ms
                self.recent_ms.append(ms)
            else:
                self.fail += 1
                self.consecutive_fail += 1

    @property
    def success_pct(self):
        return (self.ok / self.queries * 100) if self.queries else 0.0

    @property
    def recent_avg_ms(self):
        return (sum(self.recent_ms) / len(self.recent_ms)) if self.recent_ms else None

    @property
    def overall_avg_ms(self):
        return (self.total_ms / self.ok) if self.ok else None


def query_once(stat, domain, rdtype, timeout):
    """One lookup. Returns (category, ms, result_str).

    category: 'ok'       got a valid answer
              'negative'  NXDOMAIN/NoAnswer - definitive, not worth retrying
              'transient' timeout/servfail - worth retrying
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [stat.ip]
    resolver.port = stat.port
    resolver.timeout = timeout
    resolver.lifetime = timeout
    start = time.perf_counter()
    try:
        answer = resolver.resolve(domain, rdtype)
        ms = (time.perf_counter() - start) * 1000
        records = [r.to_text() for r in answer]
        return "ok", ms, (", ".join(records[:2]) if records else "(empty answer)")
    except dns.resolver.NXDOMAIN:
        ms = (time.perf_counter() - start) * 1000
        return "negative", ms, "NXDOMAIN (no such name)"
    except dns.resolver.NoAnswer:
        ms = (time.perf_counter() - start) * 1000
        return "negative", ms, f"NoAnswer (no {rdtype} record)"
    except dns.resolver.NoNameservers:
        return "transient", None, "SERVFAIL / no nameservers"
    except dns.exception.Timeout:
        return "transient", None, f"TIMEOUT (>{timeout}s)"
    except Exception as e:  # noqa: BLE001 - surface anything unexpected
        return "transient", None, f"{type(e).__name__}: {e}"


def query_with_retries(stat, domain, rdtype, timeout, retries):
    """Retry transient failures (timeout/servfail) up to `retries` times, the
    way a real stub resolver does. Definitive negatives (NXDOMAIN/NoAnswer) are
    returned immediately - retrying them just hides bad domains. Retries use
    half the timeout so a dead server doesn't stall the dashboard.
    Returns (ok, ms, result_str, category)."""
    cat, ms, result = query_once(stat, domain, rdtype, timeout)
    attempt = 0
    retry_timeout = timeout / 2.0
    while cat == "transient" and attempt < retries:
        attempt += 1
        cat, ms, result = query_once(stat, domain, rdtype, retry_timeout)
    if cat == "ok" and attempt:
        result += f"  [ok after {attempt} retr{'y' if attempt == 1 else 'ies'}]"
    return (cat == "ok"), ms, result, cat


def validate_pool(domains, stats, rdtype, timeout, retries):
    """Probe every domain across all servers once at startup. Drop a domain
    only if a server gives a definitive negative (NXDOMAIN/NoAnswer) and no
    server returns a valid answer - those would count as a failure every round
    and skew the success rate (e.g. apex cloudfront.net has no A record).
    Timeouts never drop a domain, since during an outage the servers - not the
    domain - may be the problem. Returns (usable, dropped, unknown)."""
    vtimeout = min(timeout, 2.0)
    cats = {d: [] for d in domains}
    with ThreadPoolExecutor(max_workers=30) as ex:
        fut_map = {ex.submit(query_with_retries, s, d, rdtype, vtimeout, retries): d
                   for d in domains for s in stats}
        for fut, d in fut_map.items():
            cats[d].append(fut.result()[3])
    good = [d for d in domains if "ok" in cats[d]]
    dropped = [d for d in domains if "ok" not in cats[d] and "negative" in cats[d]]
    unknown = [d for d in domains if cats[d] and all(c == "transient" for c in cats[d])]
    return good + unknown, dropped, unknown


def fmt_ms(ms):
    return f"{ms:.0f}" if ms is not None else "-"


def build_dashboard(stats, rounds, started, last_domain, events, rdtype, interval):
    table = Table(expand=True, header_style="bold")
    table.add_column("", width=2)
    table.add_column("DNS Server", style="bold")
    table.add_column("Queries", justify="right")
    table.add_column("OK", justify="right", style="green")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("Success", justify="right")
    table.add_column("Last ms", justify="right")
    table.add_column("Avg ms", justify="right")
    table.add_column("Last result", overflow="fold")

    for s in stats:
        if s.last_ok is None:
            dot, succ_style = "[grey50]o[/]", "grey50"
        elif s.last_ok:
            dot = "[green]●[/]"
            succ_style = "green" if s.success_pct >= 99 else "yellow"
        else:
            dot = "[red]●[/]"
            succ_style = "red"
        if s.consecutive_fail >= 3:
            dot = "[bold red blink]●[/]"
        pct = f"[{succ_style}]{s.success_pct:5.1f}%[/]"
        table.add_row(
            dot, s.label, str(s.queries), str(s.ok), str(s.fail), pct,
            fmt_ms(s.last_ms), fmt_ms(s.recent_avg_ms), s.last_result,
        )

    elapsed = int(time.time() - started)
    header = (
        f"[bold]DNS Watch[/]   type=[cyan]{rdtype}[/]  interval=[cyan]{interval}s[/]  "
        f"rounds=[cyan]{rounds}[/]  elapsed=[cyan]{elapsed//60}m{elapsed%60:02d}s[/]  "
        f"last domain=[magenta]{last_domain or '-'}[/]"
    )
    log_lines = "\n".join(events) if events else "  (warming up...)"
    return Group(
        Panel(header, border_style="blue"),
        table,
        Panel(log_lines, title="recent activity", border_style="grey37", height=12),
    )


def main():
    ap = argparse.ArgumentParser(
        description="Continuously test DNS resolution across up to 20 DNS servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Server format: <ip> or <ip>#<port>  e.g.  10.1.1.53  or  10.1.1.53#5353",
    )
    ap.add_argument("servers", nargs="+", type=parse_server,
                    help="1 to 20 DNS server IPs (optionally <ip>#<port>)")
    ap.add_argument("-i", "--interval", type=float, default=2.0,
                    help="seconds between query rounds (default 2)")
    ap.add_argument("-t", "--timeout", type=float, default=2.0,
                    help="per-query timeout in seconds (default 2; retries use half this)")
    ap.add_argument("-T", "--type", default="A", dest="rdtype",
                    help="record type to query: A, AAAA, MX, NS, ... (default A)")
    ap.add_argument("-c", "--count", type=int, default=0,
                    help="number of rounds then stop (0 = run forever, default)")
    ap.add_argument("--domains-file",
                    help="file with one domain per line (overrides built-in list)")
    ap.add_argument("--log", default="dnswatch_log.csv",
                    help="CSV log path (default dnswatch_log.csv)")
    ap.add_argument("-r", "--retries", type=int, default=1,
                    help="retry transient failures (timeout/servfail) up to N times "
                         "per query, like a real resolver (default 1; retries use "
                         "timeout/2; 0 = raw)")
    ap.add_argument("--no-validate", action="store_true",
                    help="skip the startup domain-pool sanity check")
    ap.add_argument("--no-rich", action="store_true",
                    help="plain line-by-line output instead of the live dashboard")
    args = ap.parse_args()

    if len(args.servers) > 20:
        ap.error("at most 20 DNS servers are supported")
    rdtype = args.rdtype.upper()

    domains = DEFAULT_DOMAINS
    if args.domains_file:
        with open(args.domains_file) as f:
            domains = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        if not domains:
            ap.error("domains file is empty")

    stats = [ServerStat(ip, port) for ip, port in args.servers]
    use_rich = HAVE_RICH and not args.no_rich
    console = Console() if HAVE_RICH else None

    def emit(msg, style=None):
        if console:
            console.print(f"[{style}]{msg}[/]" if style else msg)
        else:
            print(msg)

    if not args.no_validate:
        emit("validating domain pool...", "grey50")
        usable, dropped, unknown = validate_pool(domains, stats, rdtype,
                                                 args.timeout, args.retries)
        if dropped:
            emit(f"dropped {len(dropped)} domain(s) with no {rdtype} record: "
                 + ", ".join(dropped), "yellow")
        if unknown and len(unknown) == len(domains):
            emit("WARNING: no server answered any startup probe - servers may be "
                 "down or no connectivity. Keeping full pool; failures are real.",
                 "bold red")
        elif unknown:
            emit(f"note: {len(unknown)} domain(s) inconclusive at startup "
                 "(timeouts), kept in pool", "grey50")
        if usable:
            domains = usable
    events = deque(maxlen=10)
    started = time.time()
    stop = threading.Event()

    def handle_sigint(_sig, _frm):
        stop.set()
    signal.signal(signal.SIGINT, handle_sigint)

    logfile = open(args.log, "w", newline="")
    writer = csv.writer(logfile)
    writer.writerow(["timestamp", "server", "domain", "type", "ok", "latency_ms", "result"])

    last_domain = ""
    rounds = 0
    last_pick = None

    def run_round():
        nonlocal rounds, last_domain, last_pick
        # pick a domain, avoiding an immediate repeat
        domain = random.choice(domains)
        while domain == last_pick and len(domains) > 1:
            domain = random.choice(domains)
        last_pick = domain
        last_domain = domain
        rounds += 1
        ts = datetime.now().strftime("%H:%M:%S")

        with ThreadPoolExecutor(max_workers=len(stats)) as ex:
            futs = {ex.submit(query_with_retries, s, domain, rdtype,
                              args.timeout, args.retries): s
                    for s in stats}
            results = {}
            for fut, s in futs.items():
                ok, ms, result, _cat = fut.result()
                s.record(ok, ms, result)
                results[s] = (ok, ms, result)
                writer.writerow([datetime.now().isoformat(timespec="seconds"),
                                 s.label, domain, rdtype, ok, fmt_ms(ms), result])
        logfile.flush()

        parts = []
        for s in stats:
            ok, ms, _ = results[s]
            mark = "OK" if ok else "FAIL"
            parts.append(f"{s.label}={mark}/{fmt_ms(ms)}ms")
        line = f"{ts}  {domain:<22} " + "  ".join(parts)
        if use_rich:
            colored = line
            for tok, col in (("OK", "[green]OK[/]"), ("FAIL", "[red]FAIL[/]")):
                colored = colored.replace(tok, col)
            events.append(colored)
        return line

    try:
        if use_rich:
            with Live(build_dashboard(stats, rounds, started, last_domain, list(events),
                                      rdtype, args.interval),
                      console=console, refresh_per_second=4, screen=False) as live:
                while not stop.is_set():
                    run_round()
                    live.update(build_dashboard(stats, rounds, started, last_domain,
                                                list(events), rdtype, args.interval))
                    if args.count and rounds >= args.count:
                        break
                    stop.wait(args.interval)
        else:
            print(f"DNS Watch  type={rdtype} interval={args.interval}s  "
                  f"servers: {', '.join(s.label for s in stats)}  (Ctrl+C to stop)")
            while not stop.is_set():
                print(run_round())
                if args.count and rounds >= args.count:
                    break
                stop.wait(args.interval)
    finally:
        logfile.close()
        print_summary(stats, rounds, started, args.log, console if HAVE_RICH else None)


def print_summary(stats, rounds, started, logpath, console):
    elapsed = int(time.time() - started)
    lines = ["", "=" * 64,
             f"  SUMMARY  ({rounds} rounds, {elapsed//60}m{elapsed%60:02d}s)",
             "=" * 64]
    for s in stats:
        avg = f"{s.overall_avg_ms:.0f}ms" if s.overall_avg_ms is not None else "n/a"
        verdict = "HEALTHY" if s.success_pct >= 99 else (
            "DEGRADED" if s.success_pct >= 50 else "DOWN/FAILING")
        lines.append(
            f"  {s.label:<22} {s.success_pct:6.1f}% ok  "
            f"({s.ok}/{s.queries})  avg {avg:<7}  -> {verdict}"
        )
    lines.append("=" * 64)
    lines.append(f"  CSV log written to: {logpath}")
    text = "\n".join(lines)
    if console:
        console.print(text)
    else:
        print(text)


if __name__ == "__main__":
    main()
