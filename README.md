# CPExVTOPS - Vulnerability Management System

A lightweight Flask application for tracking newly published CVEs that match the Common Platform Enumeration (CPE) strings you care about. It integrates with the [Vulnerability-Lookup API](https://vulnerability.circl.lu) (successor to cve-search) with automated scheduling, scan comparison, EPSS scoring, and a modern web experience for managing watchlists.

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Step-by-Step Installation Guide](#step-by-step-installation-guide)
  - [PyCharm Setup](#pycharm-setup)
  - [VS Code Setup](#vs-code-setup)
- [Running the Application](#running-the-application)
  - [Running the Web UI](#running-the-web-ui)
  - [Running the Scheduler](#running-the-scheduler)
  - [Running One-off Scans](#running-one-off-scans)
- [Configuration](#configuration)
- [Data & Persistence](#data--persistence)
- [API Reference](#api-reference)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)

---

## Features

- **Automated scanning** – Schedule vulnerability scans at configured times (default: 07:30, 12:30, 16:00, 19:30 UTC) with the built-in scheduler
- **Scan comparison** – Automatically detect "New" vulnerabilities by comparing consecutive scans and track scan history for up to 90 days
- **EPSS scoring** – View Exploit Prediction Scoring System (EPSS) scores alongside CVSS to prioritize based on exploitation probability
- **Advanced filtering** – Filter by severity, CVSS score, EPSS score, KEV status, and "New" vulnerabilities with real-time updates
- **Watchlist management** – Create and organize CPE watchlists with fast 24h and 90d scanning windows
- **Team organization** – Group watchlists by teams/projects for better organization
- **High-signal results** – Merge duplicate CVEs, annotate KEV status (CISA Known Exploited Vulnerabilities), compute preferred CVSS v4/v3 metrics
- **Flexible exports** – Export results as CSV or NDJSON for downstream automation
- **CPE tooling** – Interactive CPE 2.3 builder with field validation
- **Operational niceties** – Per-watchlist overrides for proxies, CA bundles, TLS verification, and resilient retry/backoff logic

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CPExVTOPS Architecture                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌──────────────────────────────┐  │
│  │   Browser   │────▶│  Flask App  │────▶│  Vulnerability-Lookup API    │  │
│  │  (Frontend) │◀────│  (Backend)  │◀────│  (vulnerability.circl.lu)    │  │
│  └─────────────┘     └─────────────┘     └──────────────────────────────┘  │
│        │                   │                                                │
│        │                   ▼                                                │
│        │             ┌─────────────┐                                        │
│        │             │  Scheduler  │  (Optional: automated scans)           │
│        │             └─────────────┘                                        │
│        │                   │                                                │
│        ▼                   ▼                                                │
│  ┌─────────────────────────────────────┐                                    │
│  │            data/ Directory          │                                    │
│  │  ├── watchlists.json               │                                    │
│  │  ├── state.json                    │                                    │
│  │  ├── scan_history.json             │                                    │
│  │  └── out/ (exports)                │                                    │
│  └─────────────────────────────────────┘                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Components:**

| Component | File | Purpose |
|-----------|------|---------|
| **Flask Web App** | `app/web.py` | REST API endpoints, CSRF protection, HTML rendering |
| **Scanner Core** | `app/scan.py` | CVE fetching, deduplication, metadata enrichment |
| **API Client** | `app/vulnerabilitylookup.py` | HTTP client with retry logic for Vulnerability-Lookup API |
| **Scan History** | `app/scan_history.py` | Historical scan tracking and "New" vulnerability detection |
| **Scheduler** | `app/scheduler.py` | Automated scanning at configured times |
| **Frontend** | `app/static/js/app.js` | Single Page Application (SPA) with vanilla JavaScript |
| **Styles** | `app/static/css/app.css` | Tailwind-based custom styling |

---

## Requirements

- **Python**: 3.10 or higher
- **Operating System**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 20.04+, Debian 11+, etc.)
- **Network**: Internet access to `vulnerability.circl.lu` (port 443)
- **Disk Space**: ~50MB for application + data storage
- **RAM**: 512MB minimum

---

## Installation

### Step-by-Step Installation Guide

#### Step 1: Verify Python Installation

Open your terminal (Command Prompt on Windows, Terminal on macOS/Linux) and verify Python is installed:

```bash
python --version
# or on some systems:
python3 --version
```

You should see output like `Python 3.10.x` or higher. If Python is not installed:

- **Windows**: Download from [python.org](https://www.python.org/downloads/) and run the installer. **Important**: Check "Add Python to PATH" during installation.
- **macOS**: Install via Homebrew: `brew install python@3.11`
- **Linux (Ubuntu/Debian)**: `sudo apt update && sudo apt install python3 python3-pip python3-venv`

#### Step 2: Clone the Repository

```bash
# Using HTTPS
git clone https://github.com/your-org/cpexvuln.git

# Or using SSH
git clone git@github.com:your-org/cpexvuln.git

# Navigate to project directory
cd cpexvuln
```

#### Step 3: Create a Virtual Environment

Virtual environments isolate project dependencies from your system Python.

**On Windows (Command Prompt):**
```cmd
python -m venv .venv
.venv\Scripts\activate
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

> **Note**: If you get a script execution error in PowerShell, run:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

**On macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

After activation, your terminal prompt should show `(.venv)` at the beginning.

#### Step 4: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs:
- **Flask**: Web framework for the backend
- **requests**: HTTP client for API calls

#### Step 5: Verify Installation

```bash
python main.py --help
```

You should see:
```
usage: main.py [-h] {web,scheduler,run} ...

Vulnerability Management System – web UI, scheduler, and scans

positional arguments:
  {web,scheduler,run}
    web                Start the web UI
    scheduler          Run automated vulnerability scanning scheduler
    run                Run a one-off scan from a CPE file

optional arguments:
  -h, --help           show this help message and exit
```

#### Step 6: Start the Application

```bash
python main.py web
```

Open your browser and navigate to: **http://127.0.0.1:5000**

You should see the CPExVTOPS dashboard.

---

### PyCharm Setup

PyCharm provides excellent Python development support with integrated debugging, code completion, and virtual environment management.

#### Option A: Opening an Existing Project

1. **Open PyCharm** and select **File → Open**
2. Navigate to the `cpexvuln` folder and click **Open**
3. PyCharm will detect the project structure

#### Option B: Cloning from Version Control

1. **Open PyCharm** and select **Get from VCS** (or **File → New → Project from Version Control**)
2. Enter the repository URL and click **Clone**

#### Configuring the Python Interpreter

1. Go to **File → Settings** (Windows/Linux) or **PyCharm → Preferences** (macOS)
2. Navigate to **Project: cpexvuln → Python Interpreter**
3. Click the **gear icon** → **Add...**
4. Select **Virtualenv Environment → New environment**
5. Set location to: `<project-path>/.venv`
6. Ensure **Base interpreter** is Python 3.10+
7. Click **OK**

PyCharm will create and configure the virtual environment automatically.

#### Installing Dependencies in PyCharm

After configuring the interpreter:

1. Open the **Terminal** tab at the bottom of PyCharm
2. Run: `pip install -r requirements.txt`

Or use PyCharm's package manager:

1. Go to **File → Settings → Project → Python Interpreter**
2. Click the **+** button
3. Search and install: `Flask`, `requests`

#### Creating a Run Configuration

**For the Web UI:**

1. Go to **Run → Edit Configurations...**
2. Click **+** → **Python**
3. Configure:
   - **Name**: `CPExVTOPS Web`
   - **Script path**: `<project-path>/main.py`
   - **Parameters**: `web`
   - **Python interpreter**: Project interpreter (.venv)
   - **Working directory**: `<project-path>`
4. Click **OK**

**For the Web UI with Scheduler:**

1. Create another configuration with:
   - **Name**: `CPExVTOPS Web + Scheduler`
   - **Parameters**: `web --with-scheduler`

**For the Scheduler only:**

1. Create another configuration with:
   - **Name**: `CPExVTOPS Scheduler`
   - **Parameters**: `scheduler`

#### Running and Debugging

- Click the **green play button** ▶ to run
- Click the **bug icon** 🐛 to debug with breakpoints
- Use **Shift+F10** to run or **Shift+F9** to debug

#### PyCharm Tips

- **Enable Flask debug mode**: The app runs with `debug=False` by default to avoid issues with PyCharm's debugger. PyCharm's native debugger works better.
- **View logs**: Check the **Run** tab at the bottom for application logs
- **Set breakpoints**: Click in the left gutter next to line numbers
- **Use the Python Console**: **Tools → Python Console** for interactive testing

---

### VS Code Setup

Visual Studio Code is a lightweight, powerful editor with excellent Python support through extensions.

#### Step 1: Install Required Extensions

Open VS Code and install these extensions (Ctrl+Shift+X):

1. **Python** (by Microsoft) - Essential for Python development
2. **Pylance** (by Microsoft) - Enhanced Python language support
3. **Python Debugger** (by Microsoft) - Debugging support

Optional but recommended:
- **GitLens** - Enhanced Git integration
- **Thunder Client** or **REST Client** - API testing
- **Prettier** - Code formatting

#### Step 2: Open the Project

1. **File → Open Folder...**
2. Select the `cpexvuln` directory
3. Click **Select Folder**

#### Step 3: Select Python Interpreter

1. Press **Ctrl+Shift+P** (or **Cmd+Shift+P** on macOS)
2. Type: `Python: Select Interpreter`
3. Choose **Enter interpreter path...** → **Find...**
4. Navigate to `.venv/Scripts/python.exe` (Windows) or `.venv/bin/python` (macOS/Linux)

Or if the virtual environment exists:
- VS Code should auto-detect it and show `.venv` in the list

#### Step 4: Create Virtual Environment (if needed)

If you haven't created a virtual environment yet:

1. Press **Ctrl+Shift+P**
2. Type: `Python: Create Environment`
3. Select **Venv**
4. Select Python 3.10+ interpreter
5. Check **requirements.txt** when prompted to install dependencies

#### Step 5: Configure Launch Settings

Create `.vscode/launch.json`:

1. Click the **Run and Debug** icon in the sidebar (or press **Ctrl+Shift+D**)
2. Click **create a launch.json file**
3. Select **Python Debugger** → **Python File**
4. Replace the content with:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "CPExVTOPS: Web UI",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "args": ["web"],
            "console": "integratedTerminal",
            "cwd": "${workspaceFolder}",
            "env": {
                "FLASK_ENV": "development"
            }
        },
        {
            "name": "CPExVTOPS: Web + Scheduler",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "args": ["web", "--with-scheduler"],
            "console": "integratedTerminal",
            "cwd": "${workspaceFolder}"
        },
        {
            "name": "CPExVTOPS: Scheduler Only",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "args": ["scheduler"],
            "console": "integratedTerminal",
            "cwd": "${workspaceFolder}"
        },
        {
            "name": "CPExVTOPS: One-off Scan",
            "type": "debugpy",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "args": [
                "run",
                "--cpes-file", "${workspaceFolder}/cpes/sample.txt",
                "--win", "24h",
                "--out-dir", "${workspaceFolder}/data/out"
            ],
            "console": "integratedTerminal",
            "cwd": "${workspaceFolder}"
        },
        {
            "name": "Python: Current File",
            "type": "debugpy",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal"
        }
    ]
}
```

#### Step 6: Configure Workspace Settings (Optional)

Create `.vscode/settings.json` for project-specific settings:

```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
    "python.terminal.activateEnvironment": true,
    "python.analysis.typeCheckingMode": "basic",
    "python.analysis.autoImportCompletions": true,
    "editor.formatOnSave": true,
    "editor.rulers": [120],
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        ".venv": true
    },
    "[python]": {
        "editor.tabSize": 4,
        "editor.insertSpaces": true
    }
}
```

#### Step 7: Running and Debugging

1. Open the **Run and Debug** panel (Ctrl+Shift+D)
2. Select a configuration from the dropdown (e.g., "CPExVTOPS: Web UI")
3. Click the **green play button** ▶ or press **F5**
4. The terminal will show the Flask server starting
5. Open http://127.0.0.1:5000 in your browser

#### VS Code Tips

- **Set breakpoints**: Click in the left gutter next to line numbers
- **View variables**: Check the **Variables** panel while debugging
- **Integrated terminal**: Use **Ctrl+`** to open/close terminal
- **Quick file navigation**: Use **Ctrl+P** and type filename
- **Go to definition**: **F12** or **Ctrl+Click** on a function/variable
- **Find all references**: **Shift+F12**

---

## Running the Application

### Running the Web UI

Start the interactive dashboard (binds to `127.0.0.1:5000` by default):

```bash
python main.py web
```

While the web UI is open, scheduled watchlist times also trigger automatic refresh scans in the browser session (keep the tab open to receive updates).

**With integrated scheduler** (scans run automatically at configured times):

```bash
python main.py web --with-scheduler
```

**Command-line options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address (use `0.0.0.0` for all interfaces) |
| `--port` | `5000` | Port number |
| `--with-scheduler` | disabled | Run scheduler alongside web UI |
| `--https-proxy` | none | HTTPS proxy URL |
| `--http-proxy` | none | HTTP proxy URL |
| `--ca-bundle` | none | Path to custom CA bundle |
| `--insecure` | disabled | Skip TLS verification (not recommended) |
| `--timeout` | `60` | HTTP timeout in seconds |

**Example: Production deployment behind reverse proxy:**

```bash
python main.py web --host 0.0.0.0 --port 8080
```

### Running the Scheduler

The scheduler automatically runs scans for all configured watchlists at specified times.

**Continuous mode** (runs until stopped):

```bash
python main.py scheduler
```

**One-time mode** (scan all watchlists once and exit):

```bash
python main.py scheduler --once
```

### Running One-off Scans

Scan a list of CPEs from a file:

```bash
python main.py run --cpes-file ./cpes/sample.txt --win 24h --out-dir ./exports
```

**Options:**

| Option | Required | Description |
|--------|----------|-------------|
| `--cpes-file` | Yes | Path to file with CPEs (one per line or comma-separated) |
| `--win` | No | Time window: `24h` (default) or `90d` |
| `--out-dir` | No | Output directory (default: `./data/out`) |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTPS_PROXY` | none | HTTPS proxy URL |
| `HTTP_PROXY` | none | HTTP proxy URL |
| `REQUESTS_CA_BUNDLE` | system | Custom CA certificate bundle path |
| `SCAN_SCHEDULE` | `07:30,12:30,16:00,19:30` | Comma-separated scan times (HH:MM, UTC) |
| `SCAN_HISTORY_RETENTION_DAYS` | `90` | Days to retain scan history |
| `SECRET_KEY` | auto-generated | Flask session encryption key |
| `VULN_LOOKUP_API_BASE` | `https://vulnerability.circl.lu/api` | Custom API endpoint |

### Example: Configure via Environment

**Linux/macOS:**
```bash
export SCAN_SCHEDULE="06:00,12:00,18:00"
export HTTPS_PROXY="http://proxy.company.com:8080"
python main.py web --with-scheduler
```

**Windows (Command Prompt):**
```cmd
set SCAN_SCHEDULE=06:00,12:00,18:00
set HTTPS_PROXY=http://proxy.company.com:8080
python main.py web --with-scheduler
```

**Windows (PowerShell):**
```powershell
$env:SCAN_SCHEDULE = "06:00,12:00,18:00"
$env:HTTPS_PROXY = "http://proxy.company.com:8080"
python main.py web --with-scheduler
```

---

## Data & Persistence

### File Structure

```
data/
├── watchlists.json      # Watchlist and team definitions
├── state.json           # Scan state and cursors
├── scan_history.json    # Historical scan results for comparison
└── out/                 # Export directory for NDJSON files
```

All files are created automatically on first run. JSON files use atomic writes (`.tmp` swap) to prevent corruption.

### watchlists.json

Contains team/project definitions and watchlists:

```json
{
  "projects": [
    {
      "id": "uuid",
      "name": "Security Team",
      "order": 0
    }
  ],
  "lists": [
    {
      "id": "uuid",
      "name": "Windows Servers",
      "projectId": "project-uuid",
      "cpes": ["cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"],
      "comments": "Production Windows servers",
      "options": {
        "insecure": false,
        "hasKev": false
      }
    }
  ]
}
```

### scan_history.json

Stores historical scan results for "New" vulnerability detection:

```json
{
  "scans": [
    {
      "id": "uuid",
      "timestamp": "2025-01-12T07:30:00.000Z",
      "watchlist_id": "uuid",
      "watchlist_name": "Windows Servers",
      "cpes": ["cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"],
      "window": "24h",
      "cve_ids": ["CVE-2025-1234", "CVE-2025-5678"],
      "summary": {
        "total": 150,
        "critical": 12,
        "high": 45,
        "medium": 60,
        "low": 33,
        "kev_count": 8,
        "epss_high_count": 25
      }
    }
  ]
}
```

---

## API Reference

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main SPA interface |
| `GET` | `/api/watchlists` | Get all teams and watchlists |
| `POST` | `/api/watchlists` | Create new watchlist |
| `PUT` | `/api/watchlists/<id>` | Update watchlist |
| `DELETE` | `/api/watchlists/<id>` | Delete watchlist |
| `POST` | `/api/projects` | Create new team/project |
| `PATCH` | `/api/projects/<id>` | Rename team |
| `DELETE` | `/api/projects/<id>` | Delete team (must be empty) |
| `POST` | `/api/run` | Trigger vulnerability scan |
| `GET` | `/export/<id>.csv` | Export results as CSV |
| `GET` | `/export/<id>.json` | Export results as JSON |

### CSRF Protection

All POST/PUT/DELETE requests require a CSRF token:
- Header: `X-CSRF-Token`
- Or form field: `csrf_token`

The token is provided in the initial page load via the bootstrap JSON.

---

## Development Workflow

### Running Tests

```bash
# Install pytest first
pip install pytest

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_scan.py

# Run specific test
pytest tests/test_scan.py::test_run_scan_logs_warning_on_error
```

### Code Linting

```bash
# Install flake8
pip install flake8

# Run linter
flake8 app/ main.py
```

### Adding Features

1. Add business logic to the appropriate module in `app/`
2. Update `app/web.py` routes if UI changes are needed
3. Add tests in `tests/`
4. Update this README if documenting new features

---

## Troubleshooting

### Common Issues

#### "No module named 'flask'" or "No module named 'requests'"

**Cause**: Dependencies not installed or virtual environment not activated.

**Solution**:
```bash
# Activate virtual environment first
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

#### "Address already in use" (port 5000)

**Cause**: Another application is using port 5000.

**Solution**:
```bash
# Use a different port
python main.py web --port 5001
```

#### "Connection refused" to vulnerability.circl.lu

**Cause**: Network/firewall blocking outbound HTTPS connections.

**Solution**:
- Check your firewall settings
- Configure proxy if behind corporate firewall:
  ```bash
  export HTTPS_PROXY="http://proxy.company.com:8080"
  ```

#### Empty scan results

**Cause**: The CPE string might not match any known vulnerabilities, or the time window is too narrow.

**Solution**:
- Verify CPE format (use the CPE builder in the UI)
- Try a longer scan window (90d instead of 24h)
- Check if the vendor/product combination exists in the NVD database

#### PyCharm: "No Python interpreter configured"

**Solution**:
1. Go to **File → Settings → Project → Python Interpreter**
2. Click the gear icon → **Add...**
3. Select the `.venv` interpreter or create a new one

#### VS Code: Python extension not finding interpreter

**Solution**:
1. Press **Ctrl+Shift+P**
2. Type: `Python: Select Interpreter`
3. Choose **Enter interpreter path...**
4. Navigate to `.venv/bin/python` or `.venv/Scripts/python.exe`

---

## Project Layout

```
cpexvuln/
├── app/                          # Main application package
│   ├── __init__.py              # Package initialization
│   ├── config.py                # Configuration constants
│   ├── web.py                   # Flask routes and API endpoints
│   ├── scan.py                  # Scan orchestration and CVE enrichment
│   ├── scan_history.py          # Scan history tracking
│   ├── scheduler.py             # Automated scan scheduling
│   ├── state.py                 # State management helpers
│   ├── utils.py                 # Utility functions
│   ├── vulnerabilitylookup.py   # Vulnerability-Lookup API client
│   ├── static/
│   │   ├── css/
│   │   │   └── app.css          # Custom styles
│   │   └── js/
│   │       └── app.js           # Frontend SPA logic
│   └── templates/
│       └── index.html           # Main HTML template
├── cpes/
│   └── sample.txt               # Sample CPE file
├── data/                         # Runtime data (created on first run)
│   ├── watchlists.json
│   ├── state.json
│   ├── scan_history.json
│   └── out/
├── tests/                        # Test suite
│   ├── test_vulnerabilitylookup.py
│   ├── test_scan.py
│   └── test_utils.py
├── .vscode/                      # VS Code configuration (optional)
│   ├── launch.json
│   └── settings.json
├── main.py                       # Application entry point
├── requirements.txt              # Python dependencies
├── setup.cfg                     # Flake8 configuration
└── README.md                     # This file
```

---

## Features in Detail

### EPSS Integration

EPSS (Exploit Prediction Scoring System) predicts the probability that a vulnerability will be exploited in the wild within the next 30 days:

- **Score**: 0-100% exploitation probability
- **Percentile**: Ranking compared to all CVEs
- **Display**: Red highlight for EPSS >= 50%
- **Filtering**: Set minimum EPSS threshold

### Scan Comparison

Automatically compares consecutive scans to identify new vulnerabilities:

- Each scan is stored with timestamp and CVE list
- "New" filter shows only CVEs that weren't in the previous scan
- Green "NEW" badge displayed on newly detected vulnerabilities

### Scheduled Scanning

The scheduler runs automatically at configured times:

- Default times: 07:30, 12:30, 16:00, 19:30 (UTC)
- Scans all watchlists using 24h window
- Stores results in scan history
- Can run standalone or alongside web UI

### Advanced Filtering

Combine multiple filters for precise results:

- **Text search**: CVE ID, description, matched CPE
- **Severity**: Critical/High/Medium/Low/None
- **CVSS**: Minimum base score (0-10)
- **EPSS**: Minimum exploitation probability (0-100%)
- **Status**: Show only new or mitigated vulnerabilities
- **KEV**: Show only CISA Known Exploited Vulnerabilities

---

## Production Deployment

### systemd Service (Linux)

Create `/etc/systemd/system/cpexvtops.service`:

```ini
[Unit]
Description=CPExVTOPS Vulnerability Scanner
After=network.target

[Service]
Type=simple
User=vulnscan
WorkingDirectory=/opt/cpexvuln
Environment="SCAN_SCHEDULE=07:30,12:30,16:00,19:30"
ExecStart=/opt/cpexvuln/.venv/bin/python main.py web --with-scheduler --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cpexvtops
sudo systemctl start cpexvtops
```

### Docker (Optional)

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "main.py", "web", "--host", "0.0.0.0"]
```

Build and run:
```bash
docker build -t cpexvtops .
docker run -p 5000:5000 -v $(pwd)/data:/app/data cpexvtops
```

---

## License

[Include your license information here]

## Contributing

[Include contribution guidelines here]

## Support

For issues or questions, please file an issue on GitHub.
