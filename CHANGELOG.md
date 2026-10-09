# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Vulnerability & weakness intelligence** — 5 new tools (37 → 42), 2 new free sources (12 → 14):
  - `internetdb_host` — free passive per-IP snapshot (ports, CPEs, tags, known CVEs) via Shodan InternetDB, no API key.
  - `cve_lookup` / `cve_search` — Shodan CVEDB enrichment: CVSS v2/v3/v4, EPSS score + ranking, KEV, ransomware association, proposed mitigation, and CPE→CVE search (filter by KEV, sort by EPSS, date range). No API key.
  - `shodan_count` — host counts with facet breakdowns (`vuln,port,tag,org`) without spending query credits.
  - `osint_host_exposure` — meta-tool that fans out to InternetDB + Shodan + Censys (whichever keys are set), enriches every CVE through CVEDB, ranks them KEV → EPSS → CVSS, and flags weaknesses (risky exposed services, end-of-life software, deprecated TLS, expired/self-signed certs, threat/compromise tags). Degrades gracefully with no keys.

### Changed
- **`shodan_host`** now returns per-CVE vulnerability details (CVSS, EPSS, KEV, `verified` flag, affected ports) with a severity summary, plus service-level TLS/HTTP metadata, tags and CPEs; added an optional `history` parameter.
- **`shodan_search`** results now include `vulns`, `tags`, `version` and `cpe`; facets are returned as `{value, count}` lists.
- **Censys** host/service normalization now surfaces `vulns` (CVSS/EPSS/KEV/CWE), `threats`, `exposures`, `misconfigs`, end-of-life software, service labels and TLS metadata, with a host-level vulnerability summary (requires the relevant Censys plan).

### Changed
- **Censys migrated to Platform API v3** (`api.platform.censys.io`). The legacy Search API v2 (`search.censys.io`) is being retired.
  - Auth: `CENSYS_API_TOKEN` (Personal Access Token, Bearer) + optional `CENSYS_ORG_ID` (required on Starter/Search/Core plans).
  - **Breaking:** `CENSYS_API_ID` / `CENSYS_API_SECRET` are no longer used.
  - Queries use CenQL (`host.services.port=22`, `cert.names: "example.com"`); a bare domain passed to `censys_certificates` is searched in `cert.names`.
  - `censys_hosts` / `censys_certificates` accept `page_token` and return `nextPageToken`; host results now include software, DNS names and labels.

## [0.2.0] - 2025-05-18

### Added
- **CLI mode** — run any tool directly from terminal: `npx osint-mcp-server --tool dns_lookup '{"domain":"example.com"}'`
- **GitHub Action** — use all 37 tools in CI/CD pipelines: `uses: badchars/osint-mcp-server@v0.2.0`
- `--list` flag to display all available tools with categories
- `--format text` option for human-readable output
- `--help` flag with usage examples
- Published to [GitHub Marketplace](https://github.com/marketplace/actions/osint-mcp-server) (Security + AI Assisted)
- CI workflow for build validation

## [0.1.0] - 2025-05-17

### Added
- Initial release with **37 tools** across **12 data sources**
- **MCP server** (stdio transport) for AI agent integration
- **DNS** (6 tools) — lookup, reverse, email security, SPF chain, SRV discovery, wildcard check
- **WHOIS / RDAP** (2 tools) — domain and IP registration data
- **Certificate Transparency** (1 tool) — crt.sh subdomain search
- **GeoIP** (2 tools) — single and batch IP geolocation
- **BGP / ASN** (3 tools) — ASN details, IP-to-ASN, prefix lookup
- **Wayback Machine** (2 tools) — URL history and snapshots
- **HackerTarget** (3 tools) — host search, reverse IP, AS lookup
- **Microsoft 365** (2 tools) — tenant detection, user realm discovery
- **Shodan** (4 tools) — host lookup, search, DNS resolve, exploit search
- **VirusTotal** (4 tools) — domain, IP, subdomain, URL analysis
- **SecurityTrails** (3 tools) — subdomains, DNS history, WHOIS
- **Censys** (3 tools) — host search, host details, certificate search
- **Meta** (2 tools) — list sources, full domain reconnaissance
- 21 tools work without any API keys
- README translations in 23 languages
- Dark/light mode SVG banners
- Social preview image
- Terminal demo GIF
