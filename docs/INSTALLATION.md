# Installation Guide

RACON targets **Python 3.10+** and is tested against **Python 3.12**. It runs
on Linux, macOS, Windows, and Termux.

## Prerequisites

- Python 3.10+ (recommend 3.12)
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

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Verify the installation

```bash
python racon.py --version
python -m pytest tests/ -v           # run the test suite
```

## Termux (Android)

```bash
pkg install python python-pip git
git clone https://github.com/your-org/RACON.git
cd RACON
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
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
