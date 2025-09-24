# NVD CPE Watch

A lightweight Flask application for tracking newly published CVEs that match the Common Platform Enumeration (CPE) strings you care about. It wraps the [NVD 2.0 CVE API](https://nvd.nist.gov/developers/vulnerabilities) with a stateful scheduler, a modern web experience for managing watchlists, and a command-line runner for automating exports.

## Table of contents
- [Features](#features)
- [Architecture overview](#architecture-overview)
- [Quick start](#quick-start)
- [Running the web UI](#running-the-web-ui)
- [Running one-off scans](#running-one-off-scans)
- [Data & persistence](#data--persistence)
- [Understanding the NVD API usage](#understanding-the-nvd-api-usage)
- [Development workflow](#development-workflow)
- [Project layout](#project-layout)

## Features
- **Projects & watchlists** – organise watches into collapsible folders with drag-and-drop, keyboard shortcuts, import/export, and bulk deletion.
- **Fast scanning windows** – query the NVD API for the last 24 hours, 90 days, or an extended 120 day sweep while respecting the 120-day API window cap.
- **High-signal results** – merge duplicate CVEs, annotate KEV status, compute preferred CVSS v4/v3 metrics, list affected CPEs, CWEs, references, and surface filter pills that mirror active search criteria.
- **Flexible exports** – export the current grid view as CSV or NDJSON, or run the CLI to emit normalised NDJSON snapshots for downstream automation.
- **CPE tooling** – build strings with the interactive builder, fetch name suggestions from the NVD Products API, and validate isVulnerable requests when versions are wildcards.
- **Operational niceties** – per-watchlist overrides for API keys, proxies, CA bundles, TLS skipping, and timeouts plus resilient retry/backoff logic.

## Architecture overview
- **Flask web app** – `app/web.py` wires endpoints for watchlist CRUD, scan orchestration, and export helpers while rendering a responsive Tailwind-powered interface located in `app/templates` and `app/static`.
- **Scanner core** – `app/scan.py` coordinates date windows, deduplicates CVEs, enriches metadata, and persists per-watchlist cursors.
- **NVD integration** – `app/nvd.py` configures a retry-friendly `requests` session, slices queries into 120-day windows (NVD limit), and automatically falls back to strict lookups when wildcard queries fail.
- **Configuration & state** – `app/config.py` defines on-disk paths (under `./data`) and key timing constants. JSON helpers in `app/utils.py` ensure atomic writes and robust ISO timestamp parsing even if the feed format drifts.

## Quick start
1. **Prerequisites** – Python 3.10+ and a network route to the NVD APIs. Request an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits (optional but recommended).
2. **Clone & install**
   ```bash
   git clone https://github.com/your-org/cpexvuln.git
   cd cpexvuln
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
3. **Seed data directories** – the first run creates `./data`, `./data/watchlists.json`, and `./data/state.json`. You can pre-populate watchlists by editing the JSON file if desired.
4. **Environment** – export `NVD_API_KEY` if you have one and set `HTTPS_PROXY`, `HTTP_PROXY`, or `REQUESTS_CA_BUNDLE` to mirror your network. The CLI accepts the same values via flags (`--https-proxy`, `--http-proxy`, `--ca-bundle`, `--timeout`, `--insecure`).

## Running the web UI
Start the interactive dashboard (binds to `127.0.0.1:5000` by default):

```bash
python main.py web --insecure  # omit --insecure in production
```

Key UI capabilities include:

- creating or editing watchlists inside projects (folders) with drag-and-drop reordering and keyboard shortcuts (`N`, `P`, `A`, `Del`)
- using the CPE 2.3 builder with live suggestions from the Products API and piping finished strings into the watch form
- triggering 24 h, 90 d, or 120 d scans, reviewing per-project match counts, and re-running watches directly from the sidebar quick actions
- filtering results with search/severity/min-score/KEV toggles, removing filters via pills, and exporting the current grid as CSV or NDJSON

Results are cached on disk so repeated scans are incremental rather than exhaustive.

To deploy behind a reverse proxy, override the bind host/port:

```bash
python main.py web --host 0.0.0.0 --port 8080
```

## Running one-off scans
Use the CLI to pull CVEs for a list of CPEs and write NDJSON snapshots that can feed other tooling:

```bash
python main.py run --cpes-file ./cpes/sample.txt --win 24h --out-dir ./exports
```

- `--win 24h` scans the past day; `--win 90d` performs a deeper historical crawl and updates the `last_long_rescan` marker for the watchlist hash.
- Optional connection flags mirror the web server: `--nvd-api-key`, `--https-proxy`, `--http-proxy`, `--ca-bundle`, `--timeout`, and `--insecure`.
- `--win 24h` scans the past day; `--win 90d` or `--win 120d` perform deeper historical crawls and update the `last_long_rescan` marker.
- Input files accept one CPE per line or comma-separated entries. Comments beginning with `#` are ignored.
- Results are written as newline-delimited JSON with the file name `nvd_<timestamp>.jsonl`. Each entry mirrors the schema returned by the web UI, including KEV flags, severity, references, and the CPE that matched.

## Data & persistence
- **Projects & watchlists** live in `data/watchlists.json`. The file contains a `projects` array (folders) and a `lists` array (watchlists). Each list entry stores a UUID, project ID, ordered CPE strings, and an `options` object (e.g., `noRejected`, `isVulnerable`, `minCvss`, API key, proxies, timeout).
- **Scan state** resides in `data/state.json`. Keys are derived from the SHA-256 hash of the sorted CPE set, enabling deduplication of overlapping watchlists. The state tracks the last run per CPE and the timestamp of the most recent 90-day backfill.
- **Exports** created through the CLI go into `data/out/` by default but you can point `--out-dir` elsewhere.

Both JSON files are written atomically with a `.tmp` swap to avoid corruption if the process stops mid-write.

## Understanding the NVD API usage
The scanner follows the official NVD CVE 2.0 feed contract:

- Queries use `virtualMatchString=<CPE>` to support wildcard matching. If NVD rejects the combination and the CPE includes a precise version, the code retries with `cpeName=<CPE>` for strict matching.
- Requests are chunked into 120-day slices (`MAX_RANGE_DAYS`) and paginated until `totalResults` are exhausted. Retries are configured for HTTP 429/5xx responses with exponential backoff.
- Responses are normalized to surface CVSS v4/v3 metrics when available, severity labels, CISA KEV indicators, CWE identifiers, and reference links.
- The watchlist options map to supported parameters (`noRejected`, `hasKev`, `cveId`, `cweId`, `cvssV3Severity`, `cvssV4Severity`, etc.). Per-watchlist `isVulnerable=true` automatically switches to `cpeName` queries because `virtualMatchString` is not accepted by the API in that mode.
- CPE suggestions in the builder query the [NVD Products API](https://nvd.nist.gov/developers/products) using `cpeMatchString` plus `keywordSearch`, retrieving up to 10 000 results per page and deduplicating by `cpeName`.

Consult the [NVD API documentation](https://nvd.nist.gov/vuln/data-feeds) for query semantics, authentication, and service limits.

## Development workflow
1. Install dev dependencies (they’re lightweight and included in `requirements.txt`).
2. Format and lint before sending changes:
   ```bash
   pytest
   flake8
   bandit -r .
   ```
3. The front-end assets live in `app/static` (Tailwind CSS + vanilla JS). Any new UI logic should remain framework-free for easy auditing and should keep accessibility in mind.
4. Use `python main.py web` while developing to exercise the Jinja template and client-side behaviour.

## Project layout
```
├── app/
│   ├── web.py          # Flask routes & UI helpers
│   ├── scan.py         # Core scanning + result shaping
│   ├── nvd.py          # API client and response parsing
│   ├── utils.py        # JSON persistence, CPE utilities, time helpers
│   ├── config.py       # Paths, timing constants, defaults
│   ├── templates/      # Jinja HTML templates
│   └── static/         # CSS & JavaScript for the web UI
├── data/               # Watchlist & state JSON (created on first run)
├── cpes/               # Sample CPE lists and helpers
├── main.py             # Entry point for web or batch runs
└── requirements.txt    # Runtime dependencies
```

Happy shipping, and keep an eye on that KEV feed!
