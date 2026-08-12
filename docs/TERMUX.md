# Termux (Android) Compatibility

RACON runs natively on **Termux** (Android) without requiring a full Linux
chroot or proot environment. All core dependencies are pure-Python or provide
pre-built ARM64 wheels, so installation is fast and does not need a Rust
compiler, `libxml2-dev`, or other heavy build toolchains.

## What changed for Termux

- `requirements.txt` now contains only lightweight, widely-available packages.
- Heavy native-build packages (`lxml`, `reportlab`, `cryptography`) moved to
  `requirements-optional.txt`.
- `ruamel.yaml` replaces `PyYAML` to avoid the `libyaml` C-extension build.
- Graceful fallbacks added wherever optional packages are missing:
  - `BeautifulSoup` falls back from `lxml` to `html.parser`.
  - `SSLAnalysisModule` falls back from `cryptography` to `getpeercert`.
  - `ReportGenerator` skips PDF generation if `reportlab` is unavailable.

## Installation on Termux

```bash
# 1. Install Python and git via Termux package manager
pkg update && pkg install python python-pip git

# 2. Clone
 git clone https://github.com/cybervault-Hacky/Racon.git
cd Racon

# 3. Create a virtual environment
python -m venv .venv && source .venv/bin/activate

# 4. Install core dependencies (pure Python / wheels only)
pip install -r requirements.txt

# 5. (Optional) Install native-heavy extras for PDF reports, XML parsing,
#    or advanced TLS analysis. These may require build tools on ARM:
# pip install -r requirements-optional.txt

# 6. Verify
python racon.py --version
python racon.py -t example.com
```

## Python 3.14 compatibility

The project uses only standard-library and pure-Python third-party APIs.
There are **no deprecated features** tied to 3.11/3.12, and `ruamel.yaml`
fully supports 3.14. On Termux you can install Python 3.14 via:

```bash
pkg install python@3.14
```

and then recreate the virtual environment with `python3.14 -m venv .venv`.

## Defensive reconnaissance features preserved

All defensive/reconnaissance modules remain operational without optional
packages:

- Basic info, DNS, domain, network, web enumeration, WordPress, subdomains,
  SSL analysis all degrade gracefully.
- No functionality is blocked when `lxml`, `reportlab`, or `cryptography`
  are absent.
