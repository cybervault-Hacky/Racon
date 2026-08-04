# Feature List

## CLI & UX
- Gradient ASCII logo rendered with Rich
- Live progress dashboard (spinner, bar, ETA, elapsed time)
- Colour-coded module results table
- Interactive command mode with keyboard-navigable commands
- Graceful `Ctrl+C` handling
- `--quiet` headless mode for scripting/CI

## Scanning Capabilities
- **Basic Information**: site title, HTTP status, IPs, reverse DNS, server,
  technology & CMS detection, WAF/CDN detection, security headers
- **DNS Intelligence**: A/AAAA/MX/TXT/CNAME/NS/SOA, reverse DNS, SPF, DMARC, DNSSEC
- **Domain Intelligence**: WHOIS registrar, dates, domain age, name servers
- **Network**: ping, traceroute, banner grabbing, service detection, Nmap
- **Web Enumeration**: robots.txt, sitemap, links, emails, social, JS, cookies,
  security headers, sensitive-file probing, crawler
- **WordPress**: version, theme, plugins, REST API
- **Subdomain Intelligence**: passive (crt.sh/HackerTarget) + wordlist, live-host & wildcard detection
- **SSL Analysis**: issuer, validity, expiry, signature algorithm, SANs, TLS version

## Reporting
- HTML report (self-contained, dark theme, responsive)
- JSON report (machine-readable, full module data)
- CSV report (findings table + metadata)
- PDF report (ReportLab, executive summary + findings)
- Executive summary, severity distribution, screenshots placeholder, metadata, timestamp

## Performance & Reliability
- `ThreadPoolExecutor` concurrency
- HTTP connection pooling (urllib3 adapters)
- Automatic retries with exponential backoff
- Smart GET/HEAD response caching
- Robust timeout handling and graceful exceptions

## Configuration
- YAML configuration with deep merge + CLI overrides
- User-agent rotation
- Configurable thread count, timeout, retries, output dir, logging level, theme
- Per-module enable/disable toggles

## Logging & History
- DEBUG / INFO / WARNING / ERROR levels
- Rich console logging + file logging (`output/logs/racon.log`)
- Per-scan history persisted to `output/scans/history.jsonl`

## Code Quality
- Type hints throughout
- Docstrings and modular classes
- PEP 8-compliant formatting
- Reusable utilities (`core/utils.py`)
- Unit & integration tests (`tests/`)
