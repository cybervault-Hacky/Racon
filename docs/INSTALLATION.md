# Installation Guide

RACON targets **Python 3.10+** and is tested against **Python 3.12**. It runs
on Linux, macOS, Windows, and Termux.

## Prerequisites

- Python 3.10+ (tested on 3.12, compatible with 3.14)
- `pip` and `venv` available
- (Optional) [`nmap`](https://nmap.org/) binary for the Network module's
  port scan. Without it, the module runs ping / traceroute / banner-grabbing
  checks and logs a notice.
- (Optional) A MaxMind **GeoLite2-City.mmdb** file placed at `data/GeoLite2-City.mmdb`
  to enable GeoIP enrichment. Without it, GeoIP is silently skipped.

## Install

```bash
# Clone
git clone https://github.com/your-org/RACON.git
cd RACON

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate            # Linux / macOS / Termux
# .venv\Scripts\activate             # Windows (PowerShell)

# Upgrade pip and install core dependencies (Termux-compatible)
python -m pip install --upgrade pip
pip install -r requirements.txt

# Optional native-heavy extras ( PDF / XML / TLS )
# pip install -r requirements-optional.txt
```

### Verify the installation

```bash
python racon.py --version
python -m pytest tests/ -v           # run the test suite
```

## Termux (Android)

```bash
pkg update && pkg install python python-pip git
# Optional: pkg install python@3.14  (if available)
git clone https://github.com/cybervault-Hacky/Racon.git
cd Racon
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Optional extras for PDF / advanced TLS / XML acceleration:
# pip install -r requirements-optional.txt
python racon.py -t example.com
```

## Development setup

```bash
pip install -r requirements.txt
pip install pytest
python -m pytest tests/ -v
```

## Troubleshooting

- **`ModuleNotFoundError: No module named 'yaml'`** — install PyYAML:
  `pip install pyyaml`.
- **Nmap warning** — install the `nmap` binary on your platform, or set
  `network.nmap_enabled: false` in `config.yaml`.
- **Offline environments** — RACON's `tldextract` is configured to avoid
  network fetches. WHOIS and passive subdomain APIs require connectivity and
  degrade gracefully when unreachable.
