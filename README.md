# dns-anomaly-detector

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

## Requirements

- Python 3.8+ (standard library only — no external dependencies)

## Usage

```
python3 dns_anomaly_detector.py --help
```

```
usage: dns_anomaly_detector.py [-h] (--log LOG | --log-dir LOG_DIR | --live |
                               --stdin) [--interface INTERFACE]
                               [--duration DURATION] [--output OUTPUT]
                               [--quiet]

DNS Anomaly Detector

options:
  -h, --help            show this help message and exit
  --log LOG             Analyze a DNS query log file
  --log-dir LOG_DIR     Analyze all logs in directory
  --live                Live capture with scapy
  --stdin               Read from stdin (tcpdump pipe)
  --interface, -i INTERFACE
                        Interface for live capture
  --duration DURATION   Live capture duration in seconds (0=forever)
  --output, -o OUTPUT   Export report to JSON
  --quiet, -q
```

## Notes

- Defensive tooling: run only on systems you own or are authorized to assess.
- Read-only by design where possible; review flags before use on production hosts.
- Some checks (disk sectors, process memory, raw sockets) require root.
