# Roadmap

RACON is an evolving framework. The roadmap below reflects intended direction
and is ordered by priority. All features remain within the **defensive /
authorized-auditing** scope.

## v1.0 (current)
- Core module framework and Rich CLI
- 8 initial modules
- HTML / JSON / CSV / PDF reporting
- YAML configuration, logging, scan history
- Unit test suite

## v1.1 — Reporting & UX polish
- [ ] Interactive per-finding triage workflow
- [ ] Report diffing across scan runs
- [ ] Export findings to Markdown / Slack
- [ ] Custom CSS themes for HTML reports

## v1.2 — Deeper enumeration
- [ ] Technology version database (fingerprint DB)
- [ ] Additional passive OSINT sources (SecurityTrails, VirusTotal API keys)
- [ ] Asset inventory persistence (SQLite)
- [ ] Subdomain + certificate correlation timeline

## v1.3 — Automation & integration
- [ ] CI-friendly JSON output mode and exit codes
- [ ] Plugin system for third-party modules
- [ ] Docker image and docker-compose
- [ ] Config profiles per assessment type

## v1.4 — Scale & scheduling
- [ ] Distributed / queue-based scanning
- [ ] Scheduled recurring assessments
- [ ] Dashboard web UI (read-only view of reports)

## Backlog (nice-to-have)
- [ ] GeoIP mapping UI in reports
- [ ] TLS cipher/SSL Labs-style grading (informational)
- [ ] Export to DefectDojo-compatible JSON
- [ ] Multi-language banner/ASCII themes

> ⚠️ RACON will never include exploit development, credential attacks, or
> active exploitation features. Any future module must preserve the defensive
> and authorized-use scope.
