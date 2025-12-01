# Vulnerability Management System

A lightweight Flask application for tracking newly published CVEs that match the Common Platform Enumeration (CPE) strings you care about. It integrates with the [Vulnerability-Lookup API](https://vulnerability.circl.lu) (successor to cve-search) with automated scheduling, scan comparison, EPSS scoring, and a modern web experience for managing watchlists.

## Table of contents
- [Features](#features)
- [Architecture overview](#architecture-overview)
- [Quick start](#quick-start)
- [Running the web UI](#running-the-web-ui)
- [Running the scheduler](#running-the-scheduler)
- [Running one-off scans](#running-one-off-scans)
- [Data & persistence](#data--persistence)
- [Understanding the Vulnerability-Lookup API](#understanding-the-vulnerability-lookup-api)
- [Development workflow](#development-workflow)
- [Project layout](#project-layout)

## Features
- **Automated scanning** – Schedule vulnerability scans at configured times (default: 07:30, 12:30, 16:00, 19:30) with the built-in scheduler
- **Scan comparison** – Automatically detect "New" vulnerabilities by comparing consecutive scans and track scan history for up to 90 days
- **EPSS scoring** – View Exploit Prediction Scoring System (EPSS) scores alongside CVSS to prioritize based on exploitation probability
- **Advanced filtering** – Filter by severity, CVSS score, EPSS score, KEV status, and "New" vulnerabilities with real-time updates
- **Watchlist management** – Create and organize CPE watchlists with fast 24h and 90d scanning windows
- **High-signal results** – Merge duplicate CVEs, annotate KEV status (CISA Known Exploited Vulnerabilities), compute preferred CVSS v4/v3 metrics
- **Flexible exports** – Export results as CSV or NDJSON for downstream automation
- **CPE tooling** – Interactive CPE 2.3 builder with field validation
- **Operational niceties** – Per-watchlist overrides for proxies, CA bundles, TLS verification, and resilient retry/backoff logic

## Architecture overview
- **Flask web app** – `app/web.py` provides watchlist CRUD, scan orchestration, and export functionality with a responsive Tailwind UI
- **Scanner core** – `app/scan.py` coordinates scans, deduplicates CVEs, enriches metadata (CVSS, EPSS, KEV), and persists state
- **Vulnerability-Lookup integration** – `app/vulnerabilitylookup.py` implements retry-friendly HTTP client for the Vulnerability-Lookup API with date-based filtering
- **Scan history** – `app/scan_history.py` tracks historical scans for comparison and "New" vulnerability detection
- **Scheduler** – `app/scheduler.py` provides automated scanning at configured times with continuous or one-off execution modes
- **Configuration & state** – `app/config.py` defines paths (under `./data`) and timing constants. `app/utils.py` ensures atomic writes and robust ISO timestamp parsing

## Quick start
1. **Prerequisites** – Python 3.10+ and network access to vulnerability.circl.lu
2. **Clone & install**
   ```bash
   git clone https://github.com/your-org/cpexvuln.git
   cd cpexvuln
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
3. **Seed data directories** – the first run creates `./data`, `./data/watchlists.json`, `./data/state.json`, and `./data/scan_history.json`
4. **Environment** – Set optional environment variables:
   - `HTTPS_PROXY`, `HTTP_PROXY` – for proxy configuration
   - `REQUESTS_CA_BUNDLE` – custom CA certificate bundle
   - `SCAN_SCHEDULE` – comma-separated scan times in HH:MM format (default: "07:30,12:30,16:00,19:30")
   - `SCAN_HISTORY_RETENTION_DAYS` – how long to keep scan history (default: 90)

## Running the web UI
Start the interactive dashboard (binds to `127.0.0.1:5000` by default):

```bash
python main.py web
```

**With integrated scheduler:**

```bash
python main.py web --with-scheduler
```

Key UI capabilities:

- Create and manage watchlists with one or more CPE strings
- Use the CPE 2.3 builder with field validation
- Trigger 24h or 90d scans and review results immediately
- Filter by:
  - **Text search** – CVE ID, description, or CPE
  - **Severity** – Critical, High, Medium, Low, None
  - **Min CVSS** – numeric threshold (0-10)
  - **Min EPSS %** – exploitation probability threshold (0-100%)
  - **Status** – Show only "New" vulnerabilities from latest scan
  - **KEV only** – CISA Known Exploited Vulnerabilities
- Sort results by CVE, Severity, CVSS, EPSS, Published, or Last Modified
- View detailed CVE information including EPSS scores and percentiles
- Export filtered results as CSV or NDJSON

To deploy behind a reverse proxy:

```bash
python main.py web --host 0.0.0.0 --port 8080
```

## Running the scheduler

The scheduler automatically runs scans for all configured watchlists at the specified times.

**Continuous mode** (runs until stopped):

```bash
python main.py scheduler
```

This will:
- Start the scheduler with configured scan times (default: 07:30, 12:30, 16:00, 19:30)
- Run scans for all watchlists at each scheduled time
- Store scan results in scan history for comparison
- Log all activity to stdout
- Continue running until Ctrl+C

**One-time mode** (run all watchlists once and exit):

```bash
python main.py scheduler --once
```

**Configure scan times** via environment variable:

```bash
export SCAN_SCHEDULE="06:00,12:00,18:00"
python main.py scheduler
```

**Recommended deployment:**

Use systemd (Linux) or supervisor to run the scheduler as a background service:

```ini
# /etc/systemd/system/vuln-scanner.service
[Unit]
Description=Vulnerability Scanner Scheduler
After=network.target

[Service]
Type=simple
User=vulnscan
WorkingDirectory=/opt/cpexvuln
Environment="SCAN_SCHEDULE=07:30,12:30,16:00,19:30"
ExecStart=/opt/cpexvuln/.venv/bin/python main.py scheduler
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Running one-off scans
Use the CLI to pull CVEs for a list of CPEs:

```bash
python main.py run --cpes-file ./cpes/sample.txt --win 24h --out-dir ./exports
```

- `--win 24h` scans the past day; `--win 90d` performs a deeper historical crawl
- Optional connection flags: `--https-proxy`, `--http-proxy`, `--ca-bundle`, `--timeout`, `--insecure`
- Input files accept one CPE per line or comma-separated entries. Comments beginning with `#` are ignored
- Results are written as newline-delimited JSON (NDJSON) including CVSS, EPSS, KEV flags, severity, references, and matched CPE

## Data & persistence

### File structure
```
data/
├── watchlists.json      # Watchlist definitions
├── state.json           # Scan state and cursors
├── scan_history.json    # Historical scan results for comparison
└── out/                 # Export directory
```

### watchlists.json
Contains a `lists` array with watchlist entries:
```json
{
  "lists": [
    {
      "id": "uuid",
      "name": "My Watchlist",
      "cpes": ["cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"],
      "insecure": false
    }
  ]
}
```

### state.json
Tracks scan state using SHA-256 hash of CPE set:
```json
{
  "vuln:abc123": {
    "version": 3,
    "last_long_rescan": "2025-12-01T12:30:00.000Z",
    "per_cpe": {
      "cpe:2.3:...": "2025-12-01T12:30:00.000Z"
    }
  }
}
```

### scan_history.json
Stores historical scan results for comparison:
```json
{
  "scans": [
    {
      "id": "uuid",
      "timestamp": "2025-12-01T07:30:00.000Z",
      "watchlist_id": "uuid",
      "watchlist_name": "My Watchlist",
      "cpes": ["cpe:2.3:..."],
      "window": "24h",
      "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
      "summary": {
        "total": 150,
        "critical": 12,
        "high": 45,
        "medium": 60,
        "low": 33,
        "kev_count": 8,
        "epss_high_count": 25
      },
      "total_count": 150
    }
  ]
}
```

Scans older than `SCAN_HISTORY_RETENTION_DAYS` (default: 90) are automatically removed.

All JSON files are written atomically with a `.tmp` swap to avoid corruption.

## Understanding the Vulnerability-Lookup API

The application uses the [Vulnerability-Lookup API](https://vulnerability.circl.lu) which aggregates vulnerability data from multiple sources:

### Key endpoints used
- `/api/cvefor/<cpe>` – Retrieve all CVEs matching a CPE string

### Data enrichment
The API provides:
- **CVSS metrics** – v4.0, v3.1, v3.0, v2.0 (prioritized in that order)
- **EPSS scores** – Exploit Prediction Scoring System with probability (0-1) and percentile ranking
- **KEV data** – CISA Known Exploited Vulnerabilities with dateAdded, dueDate, requiredAction
- **CWE identifiers** – Common Weakness Enumeration
- **Reference links** – with tags (Patch, Vendor Advisory, etc.)

### Client-side filtering
Since the Vulnerability-Lookup API returns all CVEs for a CPE, the application performs client-side date filtering based on the `last-modified` field to implement 24h and 90d windows.

### No authentication required
The public API endpoints do not require authentication.

For more information, visit [vulnerability.circl.lu](https://vulnerability.circl.lu)

## Development workflow

### Testing
Run the test suite:
```bash
pytest
```

### Code structure
- `app/vulnerabilitylookup.py` – API client for Vulnerability-Lookup
- `app/scan.py` – Core scanning and enrichment logic
- `app/scan_history.py` – Scan tracking and comparison
- `app/scheduler.py` – Automated scan scheduling
- `app/web.py` – Flask routes and UI template
- `app/config.py` – Configuration constants
- `app/utils.py` – Utility functions (JSON I/O, time helpers, CPE parsing)

### Adding features
1. Add business logic to appropriate module
2. Update `web.py` routes if UI changes needed
3. Add tests in `tests/`
4. Update this README

## Project layout
```
cpexvuln/
├── app/
│   ├── config.py              # Configuration
│   ├── vulnerabilitylookup.py # API client
│   ├── scan.py                # Scan orchestration
│   ├── scan_history.py        # Scan tracking
│   ├── scheduler.py           # Automated scanning
│   ├── state.py               # Window planning
│   ├── utils.py               # Utilities
│   └── web.py                 # Flask app
├── data/                      # Runtime data (created on first run)
│   ├── watchlists.json
│   ├── state.json
│   ├── scan_history.json
│   └── out/
├── tests/
│   ├── test_vulnerabilitylookup.py
│   ├── test_scan.py
│   └── test_utils.py
├── main.py                    # Entry point
├── requirements.txt
└── README.md
```

## Features in detail

### EPSS Integration
EPSS (Exploit Prediction Scoring System) predicts the probability that a vulnerability will be exploited in the wild within the next 30 days:
- **Score**: 0-100% exploitation probability
- **Percentile**: Ranking compared to all CVEs
- **Display**: Red highlight for EPSS ≥ 50%
- **Filtering**: Set minimum EPSS threshold (e.g., show only CVEs with >50% exploitation probability)

### Scan Comparison
Automatically compares consecutive scans to identify new vulnerabilities:
- Each scan is stored with timestamp and CVE list
- "New" filter shows only CVEs that weren't in the previous scan
- Useful for daily monitoring workflows (e.g., "What changed in the 12:30 scan vs 07:30?")
- Green "NEW" badge displayed on newly detected vulnerabilities

### Scheduled Scanning
The scheduler runs automatically at configured times:
- Default times: 07:30, 12:30, 16:00, 19:30 (UTC)
- Scans all watchlists using 24h window
- Stores results in scan history
- Handles errors gracefully (logs and continues)
- Can run standalone or alongside web UI

### Advanced Filtering
Combine multiple filters for precise results:
- **Text search**: CVE ID, description, matched CPE
- **Severity**: Critical/High/Medium/Low/None
- **CVSS**: Minimum base score (0-10)
- **EPSS**: Minimum exploitation probability (0-100%)
- **Status**: Show only new vulnerabilities from latest scan
- **KEV**: Show only CISA Known Exploited Vulnerabilities

All filters work together (AND logic) and update the table in real-time.

## Migration from NVD API
This application has been migrated from the NVD 2.0 API to Vulnerability-Lookup:
- **More data sources**: Vulnerability-Lookup aggregates from NVD, CISA, and other sources
- **EPSS included**: Exploitation prediction built-in
- **No API key needed**: Public access without authentication
- **Same CPE format**: CPE 2.3 strings work identically
- **Client-side filtering**: Date filtering handled by the application

## License
[Include your license information here]

## Contributing
[Include contribution guidelines here]

## Support
For issues or questions, please file an issue on GitHub.
