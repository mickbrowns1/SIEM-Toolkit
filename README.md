# Parallax — SentinelOne AI-SIEM Coverage Toolkit

> *Inspired by Pineapple Boy!* 🍍

A self-hosted coverage visibility tool for SentinelOne AI-SIEM SecOps engineers. Runs as a Docker Compose stack against your SentinelOne demo or production tenant and provides real-time insight into parser coverage, detection library mapping, ingest volume, and data quality — all without leaving a single interface.

---

## What's Inside

| Page | Purpose |
|---|---|
| **Overview** | Live health stats — coverage %, active sources, top uncovered sources by volume |
| **Parser Coverage Map** | Which active data sources have a parser? Detection rule mapping per source. Unlabelled event detection. |
| **Ingest Dashboard** | Event volume, top sources, cost projection, filter simulator |
| **Parser Quality** | Live event sampler, field population rate, parser test runner, attributes missing audit |
| **Threat Coverage** | MITRE ATT&CK heatmap across all detection library rules, rule firing status (active vs never-fired) |
| **Onboarding Accelerator** | Prompt template for onboarding new log sources with Claude Code |
| **Settings** | Manage your `.env` credentials directly from the interface |

---

## Architecture

```
browser → nginx (port 3001) → single-page HTML/JS application
                ↓ API calls
          FastAPI backend (port 8001)
                ↓
    ┌───────────────────────────┐
    │  PostgreSQL (SQLAlchemy)  │  rules, parser fields, active sources,
    │                           │  firing cache, coverage snapshots
    └───────────────────────────┘
                ↓
    ┌───────────────────────────┐
    │  SentinelOne APIs         │
    │  • Management API v2.1    │  STAR rules, detection library, platform rules
    │  • Scalyr XDR PowerQuery  │  live event queries, source volumes
    │  • SDL Config File API    │  parser file sync (/logParsers/)
    └───────────────────────────┘
```

All services run via Docker Compose. The `parsers/` directory is volume-mounted into the backend so SDL parser files may be loaded without rebuilding the image.

---

## Setup

### 1. Clone and Configure

```bash
git clone https://github.com/mickbrowns1/SIEM-Toolkit.git
cd SIEM-Toolkit
cp .env.example .env
```

Edit `.env` with your credentials:

```env
S1_BASE_URL=https://demo.sentinelone.net       # Your console URL
S1_API_TOKEN=eyJ...                             # Service user API token (account or site scope)
SDL_XDR_URL=https://xdr.us1.sentinelone.net    # Scalyr XDR endpoint
SDL_LOG_READ_KEY=1j2IU0S...                     # Data Lake read key (query events)
SDL_CONFIG_READ_KEY=...                         # Data Lake config key (sync parser files)
SDL_PQ_TIMEOUT=600                              # PowerQuery timeout in seconds (default: 600)
SDL_PQ_TIMEOUT_RETRIES=1                        # Retries on timeout (default: 1)
ANTHROPIC_API_KEY=                              # Optional — not currently used
```

**S1_API_TOKEN** — generate at *Policies and settings → Users → Service Users*. Account scope gives broadest access; site scope works for most features with some limitations.

**SDL_LOG_READ_KEY** — found at *Policies and settings → Integrations → Data Lake API Keys → Log Read*.

**SDL_CONFIG_READ_KEY** — found at *Policies and settings → Integrations → Data Lake API Keys → Configuration Read*. Required to sync parser files directly from SDL via the Coverage Map. Without it, you can still load parser files manually from the `parsers/` directory.

### 2. Start the Stack

```bash
docker compose up -d --build
```

Open **http://localhost:3001** in your browser and you're off.

### 3. First Run — Sync Everything

Click **Sync All** on the Parser Coverage Map. This runs three steps in sequence:

1. **Sync SDL Parsers** — downloads all `/logParsers/` parser files from your SDL tenant into the `parsers/` volume (requires `SDL_CONFIG_READ_KEY`)
2. **Sync Detection Library** — imports all platform detection rules from the S1 API, including MITRE ATT&CK tactic/technique mappings and per-rule alert counts
3. **Sync Live Sources** — queries the data lake for every `dataSource.name` active in the last 7 days

### 4. Detection Library (alternative: local file)

If the live API import fails (e.g. token scope is too narrow), the toolkit falls back to a local `detections.json` generated from the [detection-validator](https://github.com/mickbrowns1/detection-validator) repository:

```bash
mkdir -p data
cp /path/to/detection-validator/data/detections/extracted.json data/detections.json
```

The `data/` directory is gitignored and never committed.

---

## Features

### Overview Dashboard

The landing page gives you an at-a-glance health summary drawn live from the database:

- **Parser Coverage %** — proportion of active sources with a confirmed parser
- **Active Sources** — total number of `dataSource.name` values seen in the last 7 days
- **Covered / Need Parser** — counts for each status

If any sources are uncovered, the **Top Sources Needing a Parser** table lists the highest-volume offenders. Click any source name to jump directly to the Parser Quality page with that source pre-selected.

---

### Parser Coverage Map

Answers the question: *does each active data source have a parser running, and is it covered by detection rules?*

#### Syncing

- **Sync All** — runs all three sync operations in sequence (SDL parsers → detection library → live sources) with one click
- **Sync SDL Parsers** — downloads parser files from `/logParsers/` on your SDL tenant via the Config File API
- **Sync Detection Library** — imports platform rules from the S1 API with MITRE mappings and alert counts
- **Sync Live Sources** — queries the data lake for active `dataSource.name` values and event counts

#### Matching Logic (three-tier)

1. Exact `dataSource.name` match between the active source and the parser attribute
2. Normalised substring match (ignores spaces, dashes, case) between active source name and parser `dataSource.name`
3. Normalised substring match against the parser filename

#### Parser Detection from Data

During sync, a parallel PowerQuery checks whether each source has events with `event.type` populated in the data lake. If so, a parser is confirmed running — the source is marked **Covered** even without a local parser file. This handles built-in and cloud-managed parsers not present in `parsers/`.

#### Status Values

- 🟢 **Covered** — parser confirmed (local file or detected via parsed fields in the data lake)
- 🟡 **Incomplete Parser** — parser file exists but is missing `dataSource.name` attribute
- 🔴 **Parser Needed** — no parser found, or only a grok/dottedJson format

#### Filter Pills

- **All** — show every source
- **Complete Parser** — sources with a working custom or detected parser
- **Attributes Missing** — sources whose parser file lacks `dataSource.name`

#### Detections Column

Each source row shows how many detection library rules target it, with close-match suggestions when the `dataSource.name` doesn't align exactly with the library's naming. Once the **Rule Firing Status** cache is populated (via Threat Coverage page), each rule badge also shows its alert count — rules that have never fired are highlighted in amber (⚠).

#### Unlabelled Events Banner

A banner at the bottom of the coverage map lets you sample events that arrived with no `dataSource.name` — these are events whose parser is missing the `dataSource.name` attribute. Click **Sample Events** to run the query; the time window matches the Sync Live Sources period.

---

### Ingest Dashboard

Answers the question: *where is my event volume coming from, and what would happen if I filtered some of it?*

**Time range:** 1h, 3d, 5d, 7d

**Daily Event Volume** — bar chart of total events per day.

**Top Sources** — the 25 highest-volume `dataSource.name` values with event count and estimated GB (at 0.5 GB per million events).

**Filter Simulator** — enter a source name and an optional event type, then press Simulate. The backend runs a live PowerQuery counting matching events and projects matched events, estimated GB saved, and projected monthly figures. Entirely read-only — no filter is created or applied.

---

### Parser Quality

Four tools for diagnosing and auditing parser health.

#### Live Event Sampler

Pulls raw events from a selected source directly from the data lake and renders every field that came back. Empty fields display as `∅` in grey — immediately highlighting fields the parser is failing to populate. The `message` column is pinned to the right with a **⎘ copy** button on each row.

#### Unlabelled Event Sampler

Samples events that have *no* `dataSource.name` — events the SDL received but couldn't attribute to any parser. Uses the filter expression `!(dataSource.name = *) !(source = 'scalyr')` to eliminate internal SDL noise. Returns a sample plus a count of how many such events exist in the time window.

#### Field Population Rate

Samples up to 500 events from a source and measures what percentage have each field populated, sorted worst-first.

- 🟢 ≥ 80% — healthy extraction
- 🟡 40–79% — partial; check regex patterns
- 🔴 < 40% — rarely populated; parser likely not matching this log format variant

#### Parser Test Runner

Paste a raw log line, select a loaded parser, and press Test. Supports:
- **Regex parsers** — extracts SDL `$field=pattern$` format strings and matches against your log line
- **JSON parsers** — parses JSON input directly, flattens to dotted keys, and applies any `input/output/match/replace` rewrite rules
- **NDJSON** — multiple JSON objects separated by newlines

#### Attributes Missing

A sub-section listing all parser files in the `parsers/` directory that have a `formats:` section but no `dataSource.name` attribute. These parsers are loaded into SDL but won't attach a source label to events they process — surfaced here regardless of whether they have active traffic.

---

### Threat Coverage

Two views for understanding detection effectiveness across your estate.

#### MITRE ATT&CK Heatmap

Shows which MITRE ATT&CK tactics and techniques are covered by your detection library. Rules are imported from the S1 platform-rules API, which returns structured MITRE metadata per rule.

- **Tactic cards** — ordered by ATT&CK kill chain (Reconnaissance → Impact), colour-coded by rule count
- **Technique chips** — each technique ID and name within a tactic; expands to show all if > 12
- **Stats** — Total Library Rules, Rules with MITRE Mapping, Tactics Covered, Techniques Covered

Click **Sync Detection Library** to re-import rules and refresh MITRE data.

#### Rule Firing Status

Shows which detection rules have actually triggered alerts — and which have never fired.

Click **Sync Alert Firing Status**. The backend reads `generatedAlerts` directly from the platform-rules API data stored during the last Detection Library sync — no SDL PowerQuery needed. Results are cached in the database.

- **Active** (green) — rule has fired at least once in the monitored period
- **Silent** (amber) — rule has never fired; may be misconfigured or require a data source not yet active

The Coverage Map Detections column also reflects this data — fired rule counts appear inline on each source row.

---

### Onboarding Accelerator

A prompt template for using Claude Code to onboard a new log source. Copy the template, paste sample raw log lines, and Claude Code will generate an SDL parser skeleton with field mappings and test assertions. No Anthropic API key required.

---

### Settings

Read and write your `.env` credentials from the interface. Secret fields are masked by default with a show/hide toggle. Changes are written to the mounted `.env` file and take effect after restarting the backend:

```bash
docker compose up -d --build backend
```

---

## Rebuilding

```bash
# Full rebuild
docker compose up -d --build

# Backend only (after Python changes)
docker compose build backend && docker compose up -d backend

# Frontend only (after HTML/JS changes)
docker compose build frontend && docker compose up -d frontend

# Reset the database (clears all synced data)
curl -X DELETE http://localhost:8001/api/coverage/reset
```

---

## Project Layout

```
.
├── backend/
│   ├── main.py                  # FastAPI app, router registration, startup migrations
│   ├── db.py                    # SQLAlchemy models (ParsedRule, ActiveSource,
│   │                            #   ParserField, RuleFiringCache, IngestSnapshot)
│   ├── routers/
│   │   ├── coverage.py          # Coverage map, MITRE heatmap, firing status, SDL sync
│   │   ├── ingest.py            # Ingest dashboard, filter simulator
│   │   ├── quality.py           # Parser quality tools, unlabelled event sampler
│   │   └── settings.py          # .env read/write
│   └── services/
│       ├── s1_client.py         # SentinelOne Management API + Scalyr PowerQuery client
│       └── rule_parser.py       # SDL format string field extraction
├── frontend/
│   └── index.html               # Single-page application (Tailwind, vanilla JS)
├── parsers/                     # SDL parser files (volume-mounted, gitignored)
├── data/                        # detections.json fallback (gitignored)
├── db/
│   └── init.sql                 # Postgres initialisation
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `S1_BASE_URL` | ✅ | SentinelOne console URL (e.g. `https://demo.sentinelone.net`) |
| `S1_API_TOKEN` | ✅ | Service user API token — account scope recommended |
| `SDL_XDR_URL` | ✅ | Scalyr XDR endpoint (e.g. `https://xdr.us1.sentinelone.net`) |
| `SDL_LOG_READ_KEY` | ✅ | Data Lake log read key — for PowerQuery event queries |
| `SDL_CONFIG_READ_KEY` | ⚪ | Data Lake config read key — for SDL parser file sync |
| `SDL_PQ_TIMEOUT` | ⚪ | PowerQuery read timeout in seconds (default: `600`) |
| `SDL_PQ_TIMEOUT_RETRIES` | ⚪ | Extra retries on timeout (default: `1`) |
| `ANTHROPIC_API_KEY` | ⚪ | Not currently used |

---

## Notes

- Parser files in `parsers/` are read at query time — add or update files without rebuilding.
- The filter simulator is entirely read-only and makes no changes to your tenant.
- `SDL_CONFIG_READ_KEY` requires the *Manage config files* permission in the console. Without it, Sync SDL Parsers is skipped but all other features remain available.
- Site-scoped tokens work for most features. Account-scoped tokens are needed for the detection library API and provide broader source visibility.
- The `parsers/` directory is gitignored except for specific tracked parser files. SDL dashboard and saved-search files downloaded during sync are intentionally not committed.
