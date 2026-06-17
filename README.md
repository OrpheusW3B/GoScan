# SCANNER — Multi-Tool Pentest Reconnaissance Suite

 ▄▄▄▄   ▄▀▀▄   ▄▄▄▄▄   ▄▄▄▄  ▄▀▀▄  █▄▀█▄
▄█ ▀▀  ▄█  █▄ ██   ▒█ ▄█ ▀▀ ▓█  █▄ ▓█  █▄
██     ██  ██ ▀▀▄▄▄   ██    ██  ██ ██  ██
▓▓▐▀██ ██  ██   ▀▀▀▒▄ ▓▓    ██▀▀██ ██  ██
▓▓  ▄▄ ▓▓  ▓▓ ▄▄   ▓▓ ▓▓    ▓▓  ▓▓ ▓▓  ▓▓
▀█  ▓▓ ▀█  █▀ ▀█   ██ ▀█    ██  ██ ██  ██
 ▀▀▀ ▀  ▀▄▄▀   ▀▀██▀   ▀▀▀  ▀▀  ██ ▀▀  ██

**62 modules · 11 categories · TUI + CLI**

---

## Features

| Category | Modules | Description |
|----------|---------|-------------|
| **Port Scanning** | 1 | TCP port scan on top 1000 ports with banner grabbing and service detection |
| **DNS Enumeration** | 10 | A, AAAA, MX, NS, CNAME, TXT, SOA, SRV, CAA, PTR records + DNSSEC + zone transfer |
| **Subdomain Discovery** | 2 | crt.sh certificate transparency + 700-entry wordlist brute-force |
| **Email Recon** | 6 | MX lookup, SPF record, DMARC policy, DKIM selector, SMTP open-relay test, common email format generator |
| **WHOIS Lookup** | 1 | Domain registration lookup via who.is / iana.org with structured field extraction |
| **SSL/TLS** | 6 | Certificate parsing, SAN extraction, expiry check, cipher suite scan, protocol version support, Heartbleed check |
| **HTTP Analysis** | 9 | Status/headers, security headers audit, cookie analysis, CORS config, redirect chain, robots.txt, sitemap.xml, favicon hash, full response body |
| **Directory Busting** | 1 | 600-entry wordlist with common extensions (php, asp, aspx, jsp, do, html, bak, zip, tar.gz), page title extraction |
| **Web Tech Detection** | 150+ | Regex patterns across 30+ categories, server header, X-Powered-By, cookie fingerprinting, script src version extraction |
| **GeoIP** | 2 | Geolocation via ip-api.com + PTR reverse DNS lookup |
| **Traceroute** | 1 | Simplified multi-hop TCP traceroute |

## Interactive TUI

- **Menu** — Quick Scan, Full Scan, Custom Scan, View Last Report, Settings, Exit
- **Custom Scan** — Toggle individual modules on/off
- **Live Dashboard** — Real-time per-module status with progress bar, status messages, and elapsed timer
- **Results View** — Dot-summary table per module, raw JSON toggle (r key)
- **Settings** — Configure concurrency, timeouts, port count, output directory

## Installation

```bash
# Clone the repository
git clone <repo-url> SCANNER
cd SCANNER

# Build
go build -o SCANNER.exe .

# Run (TUI mode — no arguments)
./SCANNER.exe
```

## Usage

### TUI Mode
Run with no arguments to launch the interactive terminal UI:

```
SCANNER.exe
```

### CLI Mode
Pass a target URL as an argument for non-interactive output:

```
SCANNER.exe example.com
SCANNER.exe https://example.com
```

CLI mode runs all modules and prints a text summary to stdout.

## Output

Reports are saved to the `output/` directory:

- `scan_<timestamp>.json` — Full structured JSON results
- `scan_<timestamp>.html` — Formatted HTML report with dark theme

## Requirements

- Go 1.21+
- Dependencies (go mod download):
  - github.com/charmbracelet/bubbletea
  - github.com/charmbracelet/bubbles
  - github.com/charmbracelet/lipgloss
  - github.com/miekg/dns

## Profiles

Three scan profiles:
- **Quick** — Port scanning, DNS, subdomains, HTTP, WHOIS, SSL (faster subset)
- **Full** — All 62 modules
- **Custom** — User-selected modules

## Project Structure

```
SCANNER/
├── main.go               # Entry point — TUI vs CLI dispatch
├── config/
│   └── config.go         # Configuration, profiles, module registry
├── scanner/
│   ├── runner.go         # Scan orchestrator with channel-based streaming
│   ├── types.go          # All result data structures
│   ├── utils.go          # Worker pool, port lists, shared helpers
│   ├── port.go           # TCP port scanner
│   ├── dns.go            # DNS record enumeration
│   ├── subdomain.go      # Subdomain discovery (crt.sh + wordlist)
│   ├── email.go          # Email recon (SPF, DMARC, DKIM, SMTP)
│   ├── whois.go          # WHOIS lookup
│   ├── ssl.go            # SSL/TLS scanner + vulnerability checks
│   ├── http.go           # HTTP/HTTPS analysis
│   ├── directory.go      # Directory busting
│   ├── tech.go           # Web technology fingerprinting
│   ├── geo.go            # GeoIP lookup
│   ├── traceroute.go     # Traceroute
│   └── output.go         # JSON + HTML report generation
├── tui/
│   ├── model.go          # Bubble Tea model
│   ├── update.go         # Update loop and key handling
│   ├── views.go          # All centered views
│   ├── commands.go       # Async commands and message types
│   └── styles.go         # Lipgloss dark theme styles
├── assets/
│   └── wordlists/
│       ├── subdomains.txt  # ~700 subdomains
│       └── directories.txt # ~600 paths
└── output/               # Scan report output directory
```

## Disclaimer

For authorized security testing and educational purposes only. Unauthorized scanning of systems you do not own or have explicit permission to test may be illegal.
