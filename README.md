# 🛰️ RACON — Reconnaissance & Analysis Console

**RACON** is a production-quality, defensive cybersecurity reconnaissance and
OSINT framework built for **authorized security assessments**, **asset
inventory**, and **defensive reconnaissance**. It ships with a premium Rich
terminal UI, a modular and extensible architecture, and professional HTML /
JSON / CSV / PDF reporting.

> ⚠️ **Authorized use only.** RACON is a **passive and low-impact auditing**
> tool. It contains **no exploit, brute-force, password-cracking, SQLi,
> authentication-bypass, privilege-escalation, or malware** functionality.
> Use it exclusively on systems you own or are explicitly authorized to assess.

---

## ✨ Highlights

- 🔍 **8 modular scan modules** — basic info, DNS, WHOIS/domain, network, web
  enumeration, WordPress, subdomain intelligence, and SSL/TLS analysis.
- 🎨 **Premium Rich CLI** — gradient ASCII logo, live progress dashboard,
  colour-coded results, tables, panels, and an interactive command mode.
- ⚡ **Fast & concurrent** — `ThreadPoolExecutor`, HTTP connection pooling,
  retries with backoff, and smart response caching.
- 📄 **4 report formats** — HTML, JSON, CSV, and PDF, each with an executive
  summary, findings (informational severity labels), a screenshots
  placeholder, metadata, and a timestamp.
- ⚙️ **Fully configurable** — YAML configuration, user-agent rotation,
  timeouts, thread counts, output directories, logging levels, and themes.
- 🌍 **Cross-platform** — Linux, macOS, Windows, and Termux.

---

## 🚀 Quick Start

```bash
# 1. Clone & enter the project
git clone https://github.com/your-org/RACON.git && cd RACON

# 2. Create a virtual environment (Python 3.12+)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Scan a target
python racon.py --target example.com
```

---

## 📖 Basic Usage

```bash
# Full scan with default report format (HTML)
python racon.py -t example.com

# Specify multiple report formats
python racon.py -t example.com -f html,json,pdf

# Generate all report formats
python racon.py -t example.com -f all

# Scan an IP with an explicit port/scheme
python racon.py -t http://192.168.1.10:8080

# Run selected modules only
python racon.py -t example.com --modules basic_info,dns_intelligence

# Tune concurrency / timeouts / verbosity
python racon.py -t example.com --threads 20 --timeout 10 -v

# Use a custom config file
python racon.py -t example.com -c my-config.yaml

# Open interactive command mode
python racon.py --command
```

All scan results are stored under the `output/` tree:

```
output/
├── reports/     # Generated reports (HTML, JSON, CSV, PDF)
├── logs/        # racon.log + per-scan logging
└── scans/       # Scan history metadata (history.jsonl)
```

---

## 🧩 Modules

| Module | Key | What it collects |
|--------|-----|------------------|
| Basic Information | `basic_info` | Site title, HTTP status, IPs, reverse DNS, server & tech fingerprinting, CMS, WAF/CDN, security headers, SSL info, headers |
| DNS Intelligence | `dns_intelligence` | A/AAAA/MX/TXT/CNAME/NS/SOA records, reverse DNS, SPF, DMARC, DNSSEC |
| Domain Intelligence | `domain_intelligence` | WHOIS: registrar, creation/expiry dates, domain age, name servers |
| Network | `network` | Ping, traceroute, banner grabbing, service detection, optional Nmap port scan |
| Web Enumeration | `web_enumeration` | robots.txt, sitemap.xml, link/email/social extraction, JS discovery, cookie & security-header analysis, sensitive-file probing, crawler |
| WordPress | `wordpress` | Core version, theme, plugin enumeration, REST API detection |
| Subdomain Intelligence | `subdomains` | Passive subdomain enumeration (crt.sh, HackerTarget, wordlist), DNS resolution, live-host & wildcard detection |
| SSL Analysis | `ssl_analysis` | Certificate issuer/subject, validity & expiry, signature algorithm, SAN entries, TLS version |

See [docs/MODULES.md](docs/MODULES.md) for full details.

---

## ⚙️ Configuration

The default configuration lives in [`config.yaml`](config.yaml). Highlights:

```yaml
scan:
  threads: 10              # worker threads
  request_timeout: 15      # HTTP timeout (s)
  max_retries: 3           # retries on transient failures
  crawl_depth: 2           # crawler depth
  max_pages: 50            # crawler page cap

output:
  directory: output        # base output directory
  report_format: html      # html / json / csv / pdf / all

logging:
  level: INFO              # DEBUG / INFO / WARNING / ERROR

modules:
  network: true            # toggle individual modules
```

---

## 🧪 Testing

```bash
python -m pytest tests/ -v
```

The suite covers configuration loading, URL/DNS/email utilities, the HTTP
client, each HTTP-based module (against a local test server), report
generation in every format, and end-to-end scans.

---

## 🗺️ Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md).

## 🤝 Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## 📦 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [Module Reference](docs/MODULES.md)
- [Feature List](docs/FEATURES.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing Guide](docs/CONTRIBUTING.md)

## 📜 License

[MIT](LICENSE)

---

*RACON — Reconnaissance & Analysis Console. For authorized assessments and
defensive reconnaissance only.*
