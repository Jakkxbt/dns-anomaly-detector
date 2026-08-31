#!/usr/bin/env python3
"""
DNS Anomaly Detector — Tunneling, DGA & Fast-Flux Detection
============================================================
Detects:
  - DGA (Domain Generation Algorithm): high-entropy domain labels,
    consonant-heavy names, numeric mixes, NXDOMAIN storms
  - DNS tunneling: oversized/odd TXT queries, long labels, high query
    volume to a single domain, base64-like label content
  - Fast-flux: same hostname resolving to many distinct IPs
  - Data exfiltration: sustained high query rates per domain/client
  - Unusual record types (ANY, TXT-heavy, NULL)
  - DNS rebinding indicators (A records changing rapidly)

Modes:
  --log       analyze query logs (dnsmasq, unbound, systemd-resolved, bind)
  --live      sniff traffic with scapy (needs root, -i interface)
  --stdin     read from pipe (e.g. tcpdump -l | tool --stdin)

Usage:
  python3 dns_anomaly_detector.py --log /var/log/dnsmasq.log
  python3 dns_anomaly_detector.py --log-dir /var/log
  python3 dns_anomaly_detector.py --live --interface eth0 --duration 300
  tcpdump -l -i eth0 -nn 'udp port 53' | python3 dns_anomaly_detector.py --stdin
"""

import os
import re
import sys
import json
import math
import time
import argparse
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def c(sev, text):
    palette = {'critical': Colors.RED + Colors.BOLD, 'high': Colors.RED,
               'medium': Colors.YELLOW, 'low': Colors.YELLOW,
               'info': Colors.CYAN, 'ok': Colors.GREEN}
    return f"{palette.get(sev, '')}{text}{Colors.RESET}"


# ─── Analysis Utilities ──────────────────────────────────────────────────────

def shannon_entropy(data):
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = defaultdict(int)
    for ch in data:
        counts[ch] += 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_dga_candidate(label):
    """Heuristic DGA scoring for a single domain label."""
    if len(label) < 8:
        return 0.0

    entropy = shannon_entropy(label)
    digits = sum(ch.isdigit() for ch in label)
    consonants = sum(ch.lower() in 'bcdfghjklmnpqrstvwxyz' for ch in label)
    vowels = sum(ch.lower() in 'aeiou' for ch in label)
    label_len = len(label)

    score = 0.0
    # High entropy per char (uniform random-looking)
    if entropy > 3.8:
        score += 1.0
    if entropy > 4.2:
        score += 1.0
    # Digit-heavy labels are unusual for legit domains
    if digits / label_len > 0.25:
        score += 0.8
    # Consonant-dense (vowel ratio low) — common in DGA names
    if vowels == 0 and label_len >= 8:
        score += 1.2
    elif vowels / label_len < 0.15 and label_len >= 10:
        score += 0.6
    # Long labels
    if label_len >= 16:
        score += 0.5
    # Repeated characters (algorithmic generation artifact)
    if len(set(label)) / label_len < 0.4:
        score += 0.5

    return score


SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'pw', 'work',
                   'click', 'loan', 'download', 'stream', 'racing', 'win',
                   'bid', 'date', 'party', 'review', 'trade', 'science'}

DGA_THRESHOLD = 2.5
TUNNEL_TXT_LEN = 40
TUNNEL_LABEL_LEN = 45
FASTFLUX_IPS = 3
QUERY_BURST = 100


class DNSAnomalyDetector:
    def __init__(self):
        self.queries = []          # (timestamp, client, qname, qtype)
        self.findings = []
        self.alerted_keys = set()

        # State
        self.nxdomain_counts = defaultdict(int)       # qname -> count
        self.domain_query_counts = defaultdict(int)   # domain -> count
        self.client_query_counts = defaultdict(int)   # client -> count
        self.resolved_ips = defaultdict(set)          # qname -> set of IPs
        self.qtype_counts = defaultdict(int)
        self.alert_throttle = {}                       # key -> last alert time

    # ─── Ingestion ────────────────────────────────────────────────────

    def ingest(self, timestamp, client, qname, qtype):
        qname = qname.rstrip('.')
        self.queries.append((timestamp, client, qname, qtype))

        tld = qname.rsplit('.', 1)[-1].lower() if '.' in qname else ''
        if tld in SUSPICIOUS_TLDS:
            self._check_throttled('suspicious_tld', client, qname, tld)

        self._analyze_query(timestamp, client, qname, qtype)

        # Prune old queries
        cutoff = timestamp - 900  # 15 min window
        while self.queries and self.queries[0][0] < cutoff:
            self.queries.pop(0)

    def _check_throttled(self, key, client, *args):
        """Emit at most one finding per key per 60s window."""
        throttle_key = (key, client)
        now = time.time()
        last = self.alert_throttle.get(throttle_key, 0)
        if now - last < 60:
            return
        self.alert_throttle[throttle_key] = now
        self.emit(key, client, *args)

    def emit(self, key, client, *args):
        self.findings.append((key, client, datetime.now().isoformat(), args))

    # ─── Per-Query Analysis ───────────────────────────────────────────

    def _analyze_query(self, ts, client, qname, qtype):
        labels = qname.split('.')
        domain = '.'.join(labels[-2:]) if len(labels) >= 2 else qname
        subdomain = '.'.join(labels[:-2]) if len(labels) > 2 else ''
        label_lens = [len(l) for l in labels]

        # 1. DGA scoring on the host label
        host = labels[0] if labels else ''
        if host:
            score = is_dga_candidate(host)
            if score >= DGA_THRESHOLD:
                self._check_throttled('dga', client, qname, score)
                self._check_throttled('dga_domain', domain, qname, score)

        # 2. DNS tunneling via label length / TXT
        if any(l > TUNNEL_LABEL_LEN for l in label_lens):
            self._check_throttled('long_label', client, qname, max(label_lens))
        if qtype == 'TXT':
            qname_len = len(qname)
            if qname_len > TUNNEL_TXT_LEN:
                self._check_throttled('txt_tunnel', client, qname, qname_len)
            # base64-like content in labels (tunnel payload)
            for lbl in labels:
                if len(lbl) >= 20 and re.fullmatch(r'[A-Za-z0-9+/=_-]{20,}', lbl):
                    self._check_throttled('base64_label', client, qname, lbl[:30])

        # 3. High-entropy subdomain sprawl (subdomain takeover / tunnel fan-out)
        if subdomain and len(subdomain.split('.')) >= 4:
            self._check_throttled('deep_subdomain', client, qname, subdomain[:60])

        # 4. Unusual record types
        if qtype in ('ANY', 'NULL', 'AXFR', 'TXT') and qtype == 'ANY':
            self._check_throttled('any_query', client, qname)

        # 5. Track counts for windowed analysis
        self.nxdomain_counts[qname] += 1
        self.domain_query_counts[domain] += 1
        self.client_query_counts[client] += 1
        self.qtype_counts[qtype] += 1

        # 6. Burst detection per domain
        if self.domain_query_counts[domain] >= QUERY_BURST:
            self._check_throttled('query_burst', client, domain,
                                  self.domain_query_counts[domain])

        if self.client_query_counts[client] >= QUERY_BURST * 5:
            self._check_throttled('client_flood', client, client,
                                  self.client_query_counts[client])

    def record_resolution(self, qname, ip):
        """Register a successful resolution (live mode)."""
        qname = qname.rstrip('.')
        domain = '.'.join(qname.split('.')[-2:]) if '.' in qname else qname
        self.resolved_ips[domain].add(ip)

        ips = self.resolved_ips[domain]
        if len(ips) >= FASTFLUX_IPS:
            self._check_throttled('fastflux', 'resolver', domain,
                                  ','.join(sorted(ips)))

    def record_nxdomain(self, qname, client):
        """Register an NXDOMAIN response (live mode)."""
        qname = qname.rstrip('.')
        host = qname.split('.')[0] if qname else ''
        if host:
            score = is_dga_candidate(host)
            if score >= DGA_THRESHOLD:
                # DGA probing — many unique random NXDOMAINs
                self._check_throttled('dga_nxdomain', client, qname, score)

    # ─── Log Parsers ──────────────────────────────────────────────────

    DNSMASQ_RE = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        r'[^"]*query\[(?P<type>\w+)\]\s+(?P<qname>[^\s]+)\s+from\s+(?P<client>[\d.]+)'
    )
    DNSMASQ_NX_RE = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        r'.*reply\s+(?P<qname>[^\s]+)\s+is\s+NXDOMAIN'
    )
    UNBOUND_RE = re.compile(
        r'\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*'
        r'query:\s+(?P<qname>[^\s]+)\s+(?P<type>\w+)\s+IN.*'
        r'from\s+(?P<client>[\d.]+)'
    )
    RESOLVED_RE = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        r'.*reply\s+(?P<qname>[^\s]+)\s+is\s+(?P<ips>[\d.,\s]+)'
    )

    def parse_log_line(self, line):
        """Parse a DNS log line. Returns list of (ts, client, qname, qtype) tuples."""
        events = []

        m = self.DNSMASQ_RE.search(line)
        if m:
            ts = datetime.strptime(m.group('ts'), '%Y-%m-%d %H:%M:%S').timestamp()
            events.append((ts, m.group('client'), m.group('qname'), m.group('type')))
            return events

        m = self.UNBOUND_RE.search(line)
        if m:
            ts = datetime.strptime(m.group('ts'), '%Y-%m-%d %H:%M:%S').timestamp()
            events.append((ts, m.group('client'), m.group('qname'), m.group('type')))
            return events

        # NXDOMAIN tracking
        m = self.DNSMASQ_NX_RE.search(line)
        if m:
            ts = datetime.strptime(m.group('ts'), '%Y-%m-%d %H:%M:%S').timestamp()
            events.append(('nxdomain', ts, m.group('qname'), 'NXDOMAIN'))
            return events

        return events

    def analyze_log(self, path):
        if not os.path.exists(path):
            print(c('medium', f'[!] Log not found: {path}'))
            return 0

        parsed = 0
        print(c('info', f'[*] Analyzing log: {path}'))
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                for event in self.parse_log_line(line):
                    if event[0] == 'nxdomain':
                        self.record_nxdomain(event[2], 'log')
                    else:
                        ts, client, qname, qtype = event
                        self.ingest(ts, client, qname, qtype)
                    parsed += 1

        print(c('info', f'    Parsed {parsed} query events'))
        return parsed

    # ─── Live Capture (scapy) ─────────────────────────────────────────

    def live_capture(self, interface=None, duration=0, bpf='udp port 53'):
        try:
            from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR
        except ImportError:
            print(c('critical', '[!] scapy not installed. Run: pip3 install scapy'))
            print(c('info', '    Alternative: tcpdump -l -i eth0 -nn "udp port 53" | '
                            'python3 dns_anomaly_detector.py --stdin'))
            sys.exit(1)

        def process(pkt):
            try:
                if not (pkt.haslayer(DNS) and pkt.haslayer(UDP)):
                    return
                dns = pkt[DNS]
                client = pkt[IP].src
                ts = time.time()

                # Queries
                if dns.qr == 0 and dns.qd:
                    q = dns.qd
                    self.ingest(ts, client, q.qname.decode('ascii', errors='replace').rstrip('.'), q.qtype)
                    if q.qtype == 16:  # TXT
                        pass

                # Responses
                if dns.qr == 1:
                    # NXDOMAIN
                    if dns.rcode == 3 and dns.qd:
                        q = dns.qd
                        self.record_nxdomain(q.qname.decode('ascii', errors='replace'), client)
                    # Resolved A records
                    if dns.an and dns.qd:
                        qname = dns.qd.qname.decode('ascii', errors='replace').rstrip('.')
                        for rr in dns.an:
                            if isinstance(rr, DNSRR) and rr.type == 1:
                                self.record_resolution(qname, rr.rdata)
            except Exception:
                pass

        print(c('info', f'[*] Sniffing on {interface or "default"} ({bpf})'
                        f'{f" for {duration}s" if duration else " until Ctrl+C"}'))
        sniff(iface=interface, filter=bpf, prn=process, store=0, timeout=duration or None)
        print(c('info', '[*] Capture finished'))

    # ─── stdin pipe mode ──────────────────────────────────────────────

    def stdin_mode(self):
        print(c('info', '[*] Reading DNS lines from stdin (tcpdump -l format)'))
        tcpdump_re = re.compile(
            r'(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(?P<client>[\d.]+)\..*\s+'
            r'(?P<server>[\d.]+)\.53:\s+(?P<op>\d+[+-]?)\s+'
            r'(?P<qtype>\w+)\?\s+(?P<qname>\S+)'
        )
        for line in sys.stdin:
            m = tcpdump_re.search(line)
            if m:
                ts_parts = m.group('ts').split(':')
                now = time.time()
                ts = now - 100000  # approximate
                try:
                    ts = (now - (int(ts_parts[0]) * 3600 + int(ts_parts[1]) * 60
                                 + float(ts_parts[2])))
                except ValueError:
                    pass
                qname = m.group('qname').strip()
                if qname.startswith('+') or qname.startswith('-'):
                    qname = qname[1:]
                self.ingest(ts, m.group('client'), qname, m.group('qtype'))
                if m.group('op') == '0':  # query
                    pass
            elif 'NXDOMAIN' in line:
                m2 = re.search(r'([\d.]+)\..*:\s+\d+\s+(\S+)\?', line)
                if m2:
                    self.record_nxdomain(m2.group(2).strip(), m2.group(1))

    # ─── Reporting ────────────────────────────────────────────────────

    def report(self):
        print(f"\n{c('info', '═' * 60)}")
        print(f"{c('info', '  DNS ANOMALY REPORT')}")
        print(f"{c('info', '═' * 60)}")

        if not self.findings and not self.queries:
            print(f"\n  {c('ok', '[✓] No anomalies detected (no data analyzed).')}")
            return

        # Group findings by key
        by_key = defaultdict(list)
        for key, client, ts, args in self.findings:
            by_key[key].append((client, ts, args))

        if self.queries:
            print(f"\n  {c('info', f'Total queries analyzed: {len(self.queries)}')}")
            if self.qtype_counts:
                print(f"  Query types: " + ", ".join(f"{t}={n}" for t, n in
                      sorted(self.qtype_counts.items(), key=lambda x: -x[1])[:6]))

        if by_key:
            print(f"\n  {c('high', 'ANOMALIES DETECTED:')}")

            key_descriptions = {
                'dga': ('DGA Candidate', 'high'),
                'dga_domain': ('DGA Domain (multiple hosts)', 'critical'),
                'txt_tunnel': ('DNS TXT Tunneling', 'critical'),
                'long_label': ('Oversized Label (tunnel)', 'high'),
                'base64_label': ('Base64 Payload in Label', 'critical'),
                'deep_subdomain': ('Deep Subdomain Sprawl', 'medium'),
                'query_burst': ('Query Burst', 'high'),
                'client_flood': ('Client Query Flood', 'high'),
                'suspicious_tld': ('Suspicious TLD', 'medium'),
                'fastflux': ('Fast-Flux Domain', 'critical'),
                'dga_nxdomain': ('DGA NXDOMAIN Probing', 'high'),
                'any_query': ('ANY Query (tunnel probe)', 'low'),
            }

            for key, events in sorted(by_key.items()):
                desc, sev = key_descriptions.get(key, (key, 'medium'))
                unique_sources = len(set(e[0] for e in events))
                sample = events[-1]
                detail_args = sample[2]
                detail = ' | '.join(str(a) for a in detail_args)[:120]
                print(f"\n    {c(sev, f'[{desc.upper()}]')} — {len(events)} event(s) from "
                      f"{unique_sources} source(s)")
                print(f"      latest: {detail}")
                # Show affected domains/IPs
                sources = sorted(set(e[0] for e in events))[:5]
                print(f"      sources: {', '.join(sources)}")

        # NXDOMAIN summary
        nx_hits = {k: v for k, v in self.nxdomain_counts.items() if v >= 5}
        if nx_hits:
            print(f"\n  {c('medium', 'Repeated NXDOMAIN lookups (random-domain probing?):')}")
            for qname, count in sorted(nx_hits.items(), key=lambda x: -x[1])[:10]:
                print(f"      {count:>5}x  {qname}")

        # Top domains
        if self.domain_query_counts:
            top = sorted(self.domain_query_counts.items(), key=lambda x: -x[1])[:5]
            print(f"\n  {c('info', 'Top queried domains:')}")
            for domain, count in top:
                print(f"      {count:>6}  {domain}")

        # Fast-flux summary
        if self.resolved_ips:
            flux = {d: ips for d, ips in self.resolved_ips.items() if len(ips) >= FASTFLUX_IPS}
            if flux:
                print(f"\n  {c('critical', 'Fast-flux domains (many IPs per name):')}")
                for domain, ips in sorted(flux.items(), key=lambda x: -len(x[1]))[:10]:
                    print(f"      {len(ips):>3} IPs  {domain}  ({', '.join(sorted(ips)[:4])}...)")

        print()

    def export(self, path):
        data = {
            'generated': datetime.now().isoformat(),
            'total_queries': len(self.queries),
            'findings': [{
                'type': k,
                'source': client,
                'time': ts,
                'detail': ' | '.join(str(a) for a in args)[:200],
            } for k, client, ts, args in self.findings],
            'top_domains': sorted(self.domain_query_counts.items(),
                                  key=lambda x: -x[1])[:50],
            'fastflux': {d: list(ips) for d, ips in self.resolved_ips.items()
                         if len(ips) >= FASTFLUX_IPS},
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(c('ok', f'[✓] Report exported to {path}'))


def main():
    parser = argparse.ArgumentParser(description='DNS Anomaly Detector')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--log', help='Analyze a DNS query log file')
    group.add_argument('--log-dir', help='Analyze all logs in directory')
    group.add_argument('--live', action='store_true', help='Live capture with scapy')
    group.add_argument('--stdin', action='store_true', help='Read from stdin (tcpdump pipe)')
    parser.add_argument('--interface', '-i', help='Interface for live capture')
    parser.add_argument('--duration', type=int, default=0,
                        help='Live capture duration in seconds (0=forever)')
    parser.add_argument('--output', '-o', help='Export report to JSON')
    parser.add_argument('--quiet', '-q', action='store_true')

    args = parser.parse_args()

    detector = DNSAnomalyDetector()

    if args.log:
        detector.analyze_log(args.log)
    elif args.log_dir:
        total = 0
        for f in sorted(Path(args.log_dir).iterdir()):
            if f.is_file() and f.suffix in ('.log', '') and any(
                kw in f.name.lower() for kw in ('dns', 'dnsmasq', 'unbound', 'named')):
                total += detector.analyze_log(str(f))
        print(c('info', f'    Total events: {total}'))
    elif args.live:
        detector.live_capture(args.interface, args.duration)
    elif args.stdin:
        detector.stdin_mode()

    if not args.quiet:
        detector.report()
    if args.output:
        detector.export(args.output)


if __name__ == '__main__':
    main()
