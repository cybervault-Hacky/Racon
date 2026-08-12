<p align="center">
  <img src="assets/banner.jpg" alt="RACON Banner" width="100%">
</p>

<h1 align="center">RACON</h1>
<h3 align="center">Reconnaissance & Analysis Console</h3>

<p align="center">
A modern, modular and professional OSINT & reconnaissance framework built for
authorized security assessments, asset discovery and defensive security research.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" />
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20Termux-success" />
  <img src="https://img.shields.io/badge/License-MIT-green" />
  <img src="https://img.shields.io/badge/Status-Stable-brightgreen" />
</p>

---

## Overview

RACON (Reconnaissance & Analysis Console) is a professional reconnaissance and OSINT framework designed for defensive cybersecurity operations.

It combines multiple reconnaissance modules into one clean terminal interface while generating professional HTML, JSON, CSV and PDF reports.

> **For authorized security assessments and defensive reconnaissance only.**

---

# Features

- Professional Rich Terminal UI
- Multi-threaded Scanning
- DNS Intelligence
- WHOIS Lookup
- HTTP Header Analysis
- Web Technology Detection
- CMS Detection
- Cloudflare Detection
- SSL/TLS Analysis
- robots.txt Scanner
- Sitemap Discovery
- Security Header Analysis
- Banner Grabbing
- WordPress Detection
- Passive Subdomain Enumeration
- HTML / JSON / CSV / PDF Reports
- Cross Platform Support
- Termux Compatible

---

# Screenshots

## Startup

<p align="center">
<img src="assets/screenshots/starter.jpg" width="100%">
</p>

---

## Full Scan

<p align="center">
<img src="assets/screenshots/full-scan.jpg" width="100%">
</p>

---

## Report Generation

<p align="center">
<img src="assets/screenshots/report.jpg" width="100%">
</p>

---

# Installation

```bash
git clone https://github.com/cybervault-Hacky/Racon.git

cd Racon

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

__________________________________________

# Quick Start

* Basic Scan =
python racon.py -t example.com

* Generate All Reports =
python racon.py -t example.com -f all

* Specific Modules =
python racon.py -t example.com --modules

* basic_info,dns_intelligence
Interactive Mode =
python racon.py --command

* Project Structure
RACON
│
├── assets
├── core
├── modules
├── templates
├── docs
├── output
├── tests
├── requirements.txt
├── config.yaml
├── racon.py
└── README.md
Reports

* RACON automatically generates professional reports including
==>
   °HTML
   °JSON
   °CSV
   °PDF

Reports are saved inside
output/reports/
Documentation

* Installation Guide
* Usage Guide
* Module Reference
* Feature List
* Roadmap
* Contributing Guide
* Termux Guide
* Platform Support
* Platform
* Supported

* Linux = ✅

* Windows = ✅

* macOS = ✅

* Termux = ✅

Author 
Sarthak Bharambe

YouTube: Cyber Vault

Instagram: @cyber_vault123

License
MIT License

Made with ❤️ for the Cybersecurity Community

Created by Sarthak Bharambe

