# Claude Scanner

Enterprise-grade vulnerability scanner for fleet device management. Supports agentless scanning (SSH/WinRM) and agent-based scanning across Windows, Linux, macOS, and Unix systems. Integrates with NVD, OSV, and EPSS for comprehensive vulnerability intelligence.

## Architecture Overview

| Component | Technology | Purpose |
|---|---|---|
| API Server | Python / FastAPI | REST API, auth, scan orchestration |
| Task Worker | Celery + Redis | Background scan jobs, enrichment |
| Database | PostgreSQL 16 | Persistent storage for all data |
| Web Dashboard | React + Vite + Tailwind | Browser UI |
| Go Agent | Go 1.22 | Deep scan agent deployed to endpoints |
| Network Scanner | Go 1.22 | TCP/banner/TLS scanning binary |
| Reverse Proxy | nginx | Routes `/api/` to FastAPI, serves SPA |

## Prerequisites

| Tool | Minimum Version |
|---|---|
| Docker | 24.x |
| Docker Compose | 2.x (plugin) |
| Go | 1.22 |
| Python | 3.11 |
| Node.js | 20.x |
| make | any |

> **Optional:** A [1Password Connect Server](https://developer.1password.com/docs/connect/) for credential management. Without it, fallback env var credentials are used.

---

## Quick Start (Docker)

This is the recommended way to run the full stack.

### 1. Clone and configure

```bash
git clone https://github.com/ogrejake/claude-scanner.git
cd claude-scanner

cp deploy/.env.example deploy/.env
```

Edit `deploy/.env` and fill in all `CHANGE_ME` values:

```bash
# Required — generate a strong random key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")

# Required — shared secret for the Go agent
AGENT_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# Required — set a real database password
POSTGRES_PASSWORD=your_strong_db_password

# Update DATABASE_URL to match POSTGRES_PASSWORD
DATABASE_URL=postgresql+asyncpg://scanner:your_strong_db_password@postgres:5432/claude_scanner
```

> **NVD API Key:** Request a free key at https://nvd.nist.gov/developers/request-an-api-key and set `NVD_API_KEY` in `.env`. Without it the scanner still works but is rate-limited to 5 requests/30 seconds.

### 2. Start all services

```bash
make docker-up
```

This builds and starts: PostgreSQL, Redis, API server, Celery worker, and the nginx-fronted web dashboard.

### 3. Run database migrations

```bash
make db-upgrade
```

### 4. Create your first user

```bash
curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme","email":"admin@example.com"}' | python3 -m json.tool
```

The first registered user is automatically granted admin privileges.

### 5. Open the dashboard

Navigate to **http://localhost:3000** and sign in.

---

## Service Ports

| Service | Port | Description |
|---|---|---|
| Web Dashboard | `3000` | nginx — serves React SPA and proxies `/api/` |
| API Server | `8000` | FastAPI (also accessible directly) |
| PostgreSQL | `5432` | Exposed for local dev/migrations only |
| Redis | `6379` | Internal only |

---

## Local Development

### Python API server

```bash
# Install dependencies
pip install -e ".[dev]"

# Start PostgreSQL and Redis via Docker (without building app images)
docker compose -f deploy/docker-compose.yml up -d postgres redis

# Run database migrations
make db-upgrade

# Start API server with hot-reload
make run-dev

# Start Celery worker (separate terminal)
make run-worker
```

### Web dashboard

```bash
# Install dependencies
cd web && npm install

# Start Vite dev server (proxies /api to localhost:8000)
make web-dev
# → http://localhost:5173
```

### Go binaries

```bash
# Build agent and network scanner for current platform
make build

# Cross-compile agent for all supported platforms
make build-all-agents
# Outputs to bin/agents/
```

---

## Go Agent Deployment

The Go agent runs on target devices and exposes a local HTTPS API that the scanner calls during agent-based scans.

### Build

```bash
# Current platform
make build-agent

# Specific platform
GOOS=linux  GOARCH=amd64  go build -o bin/claude-agent-linux-amd64       ./cmd/agent
GOOS=windows GOARCH=amd64 go build -o bin/claude-agent-windows-amd64.exe ./cmd/agent
GOOS=darwin GOARCH=arm64  go build -o bin/claude-agent-darwin-arm64      ./cmd/agent
```

### Deploy and run

Copy the binary to the target device and run it with the shared agent token:

```bash
# Linux / macOS
AGENT_TOKEN=<token_from_env> ./claude-agent

# Windows (PowerShell)
$env:AGENT_TOKEN = "<token_from_env>"
.\claude-agent.exe
```

The agent listens on port `9443` (HTTPS, self-signed cert). Set the `agent_endpoint` field on the device record to `https://<device-ip>:9443`.

### Agent endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Liveness check |
| `GET /api/v1/collect/osinfo` | OS information |
| `GET /api/v1/collect/packages` | Installed packages |
| `GET /api/v1/collect/full` | Full collection (all of the above) |

All endpoints require `Authorization: Bearer <AGENT_TOKEN>`.

---

## Network Scanner

The `claude-netscanner` binary performs TCP port scanning, banner grabbing, and TLS certificate inspection independently of the main scan workflow.

```bash
make build-netscanner

# Scan a single host (top 1000 ports)
./bin/claude-netscanner --host 192.168.1.10

# Scan from a host file with all 65535 ports
./bin/claude-netscanner --host-file targets.txt --all-ports

# JSON output, specific ports
./bin/claude-netscanner --host 10.0.0.1 --ports 22,80,443,8080 --output json

# Faster scan — disable banner grabbing and TLS inspection
./bin/claude-netscanner --host 10.0.0.1 --no-banner --no-tls
```

---

## CLI

The `claude-scanner` CLI provides shell access to the API for scripting and automation.

```bash
pip install -e .

# Authenticate
claude-scanner auth login

# Device management
claude-scanner device list
claude-scanner device add --hostname web01 --ip 10.0.0.5 --os linux
claude-scanner device import devices.csv

# Scan management
claude-scanner scan start --devices web01,db01 --type full
claude-scanner scan status <scan-id>
claude-scanner scan list

# Device discovery
claude-scanner discover 10.0.0.0/24

# Reports
claude-scanner report findings --severity critical
claude-scanner report pdf <scan-id> --output report.pdf
```

---

## Credential Management

The scanner resolves device credentials in order:

1. **1Password Connect** — if `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` are set, credentials are fetched using the device's `credential_ref` field (`vault-uuid/item-uuid` format) or by hostname search.
2. **Environment fallback** — `SCANNER_DEFAULT_USER` and `SCANNER_DEFAULT_PASS` env vars are used when 1Password is unavailable.

Configure 1Password in `deploy/.env`:

```bash
OP_CONNECT_HOST=http://your-op-connect-server:8080
OP_CONNECT_TOKEN=your_token_here
OP_VAULT_ID=optional_vault_uuid   # restrict lookups to one vault
```

---

## CIS Benchmark Compliance

Compliance checks are defined in YAML files under `benchmarks/`:

```
benchmarks/
  linux/cis_level1.yaml     # 30+ CIS Level 1 checks
  windows/cis_level1.yaml   # 20+ CIS Level 1 checks
  macos/cis_level1.yaml     # 25+ CIS Level 1 checks
```

Checks are automatically synced to the database on API startup. Results are available via `GET /api/compliance/results` and exportable as CSV from the dashboard Reports page.

To add custom checks, create a YAML file in the relevant `benchmarks/<os>/` directory following the same schema.

---

## Database Migrations

```bash
# Apply all pending migrations
make db-upgrade

# Create a new migration after changing models
make migrate MESSAGE="add foo table"

# Roll back one migration
make db-downgrade
```

---

## Makefile Reference

| Target | Description |
|---|---|
| `make build` | Build Go binaries for current platform |
| `make build-all-agents` | Cross-compile agent for Linux/Windows/macOS/BSD/ARM |
| `make run-dev` | Run API server with hot-reload |
| `make run-worker` | Run Celery background worker |
| `make web-dev` | Run Vite dev server |
| `make web-build` | Build web dashboard for production |
| `make migrate` | Create Alembic migration in api container (`MESSAGE=` required) |
| `make db-upgrade` | Apply pending migrations in api container |
| `make docker-up` | Build and start all services |
| `make docker-down` | Stop all services |
| `make docker-logs` | Tail all service logs |
| `make test` | Run Python and Go tests |
| `make lint` | Run ruff + go vet |
| `make clean` | Remove build artifacts |

---

## Project Structure

```
claude-scanner/
├── cmd/
│   ├── agent/              Go agent binary (HTTPS server)
│   └── netscanner/         Go network scanner binary
├── internal/
│   ├── collector/          OS-specific package collectors (build tags per OS)
│   └── network/            TCP scanner and TLS inspector
├── server/
│   ├── api/routes/         FastAPI route handlers
│   ├── core/               Scan engine, transports, parsers, enrichment
│   ├── db/                 SQLAlchemy models and Alembic migrations
│   ├── reports/            PDF and CSV report generators
│   └── tasks/              Celery tasks (scans, discovery, enrichment)
├── cli/                    Typer CLI application
├── web/                    React + Vite dashboard
│   └── src/
│       ├── components/     Shared UI components
│       ├── lib/            Axios API client
│       ├── pages/          Dashboard, Devices, Scans, Findings, Vulnerabilities
│       └── types/          TypeScript interfaces
├── benchmarks/             CIS benchmark YAML definitions
│   ├── linux/
│   ├── windows/
│   └── macos/
└── deploy/
    ├── docker-compose.yml
    ├── Dockerfile.server
    ├── Dockerfile.web
    ├── nginx.conf
    └── .env.example
```

---

## Vulnerability Data Sources

| Source | Data | Cache |
|---|---|---|
| [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVE details, CVSS v2/v3, affected CPEs | 24 hours |
| [OSV.dev](https://osv.dev/docs/) | Package-level vulnerabilities (pip, npm, deb, rpm, apk, etc.) | Per-scan |
| [EPSS (FIRST.org)](https://www.first.org/epss/) | Exploitation probability scores (0–1) with percentile | Bulk-refreshed |

EPSS scores influence finding severity: any finding with CVSS ≥ 7.0 **and** EPSS ≥ 0.90 is automatically escalated to **Critical**.

---

## Roadmap

- **Phase 2:** Jira integration, email alerts, scheduled scans
- **Phase 3:** LDAP / SSO authentication

---

## Security Notes

- `deploy/.env` contains secrets and is listed in `.gitignore` — never commit it.
- The Go agent uses a self-signed TLS certificate. For production, replace with a CA-issued cert or pin the expected fingerprint.
- The API server runs as a non-root user (`scanner`, uid 1000) inside the container.
- Rotate any credentials that were ever stored in plaintext or committed to version control.
