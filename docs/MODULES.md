# Module Reference

Each module is a class subclassing `modules.base.BaseModule`. Modules return a
`ModuleResult` containing free-form `data` and structured `Finding` records.

---

## Basic Information (`basic_info`)

Gathers the fundamentals about a target web host.

- Site `<title>` extraction
- HTTP status code and final URL
- Resolved IP addresses (A/AAAA) and reverse DNS
- `Server` header fingerprinting
- Technology detection (generator meta tags, headers, script frameworks)
- CMS detection (WordPress, Joomla, Drupal, Squarespace, Wix, Shopify, Ghost, …)
- Cloudflare / WAF / CDN detection from headers
- TLS certificate summary
- HTTP header dump and security-header posture

## DNS Intelligence (`dns_intelligence`)

- A, AAAA, MX, TXT, CNAME, NS, SOA record queries
- Reverse DNS for resolved addresses
- SPF (`v=spf1`) and DMARC (`_dmarc`) record detection
- DNSSEC detection (DS / DNSKEY)

## Domain Intelligence (`domain_intelligence`)

- WHOIS lookup
- Registrar identification
- Registration, updated, and expiry dates
- Domain age (days since creation)
- Name servers and domain status

## Network (`network`)

- ICMP ping with RTT parsing
- Traceroute (Unix-like platforms)
- TCP banner grabbing
- Service detection on common ports
- Optional Nmap integration (`python-nmap`) for authorized port scans

## Web Enumeration (`web_enumeration`)

- `robots.txt` and `sitemap.xml` discovery
- Internal/external link extraction
- Email address extraction
- Social-media link detection
- JavaScript asset discovery
- Cookie flag analysis (HttpOnly / Secure)
- Sensitive public-file probing (`.env`, `.git/config`, `phpinfo.php`, …)
- Bounded same-origin crawler with depth/page limits

## WordPress (`wordpress`)

- WordPress presence detection
- Core version detection (generator meta / comments)
- Active theme identification
- Plugin slug enumeration
- REST API (`/wp-json/`, `?rest_route=/`) detection

## Subdomain Intelligence (`subdomains`)

- Passive enumeration via crt.sh certificate transparency
- Passive enumeration via HackerTarget API
- Bundled wordlist brute-force against DNS
- Live-host resolution and wildcard DNS detection
- Configurable subdomain limit

## SSL Analysis (`ssl_analysis`)

- Certificate issuer and subject
- Validity period and remaining days
- Signature algorithm
- Subject Alternative Names (DNS / IP)
- Negotiated TLS version and cipher

---

## Module Result & Findings

Every finding carries an informational severity label
(`info`, `low`, `medium`, `high`, `critical`) — **RACON does not assign
exploit-oriented ratings**; severities describe configuration observations to
help an operator prioritize hardening.
