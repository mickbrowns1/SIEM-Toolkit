# SIEM Toolkit — SentinelOne AI-SIEM

> *Inspired by Pineapple Boy!* 🍍

A self-hosted troubleshooting and visibility tool for SentinelOne AI-SIEM SecOps engineers. Runs as a Docker Compose stack against your SentinelOne demo or production tenant and provides real-time insight into parser coverage, ingest volume, and data quality — all without leaving a single interface.

---

## What's Inside

| Page | Purpose |
|---|---|
| **Parser Coverage Map** | Which active data sources have a parser? Which don't? |
| **Ingest Dashboard** | Event volume, top sources, cost projection, filter simulator |
| **Parser Quality** | Live event sampler, field population rate, parser test runner |
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
    │  PostgreSQL (SQLAlchemy)  │  parsed rules, parser fields, active sources
    └───────────────────────────┘
                ↓
    ┌───────────────────────────┐
    │  SentinelOne APIs         │
    │  • Management API (STAR)  │  demo.sentinelone.net
    │  • Scalyr XDR PowerQuery  │  xdr.us1.sentinelone.net
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
S1_API_TOKEN=eyJ...                             # Service user API token
SDL_XDR_URL=https://xdr.us1.sentinelone.net    # Scalyr XDR endpoint
SDL_LOG_READ_KEY=1j2IU0S...                     # Data Lake read key
ANTHROPIC_API_KEY=                              # Optional — Onboarding page only
```

**S1_API_TOKEN** — generate at *Settings → Users → Service Users* in the console.  
**SDL_LOG_READ_KEY** — found at *Settings → Integrations → Data Lake API Keys*.

### 2. Add Parser Files (optional but strongly recommended)

Place your SDL parser JSON files into the `parsers/` directory. The backend reads them directly at query time — no rebuild is necessary.

```bash
cp ~/my-parsers/*.json parsers/
```

### 3. Start the Stack

```bash
docker-compose up -d --build
```

Open **http://localhost:3001** in your browser and you're off.

---

## Features

### Parser Coverage Map

Answers the question: *does each active data source have a parser running?*

**How it works:**

1. **Sync Live Sources** — executes a PowerQuery against your data lake to retrieve every `dataSource.name` seen in the last 7 days, along with event counts.
2. **Load SDL Parsers** — reads parser files from `parsers/`, extracts the `dataSource.name` attribute from each, and stores the field list in the database.
3. **Load STAR Rules** — retrieves your STAR detection rules from the management API and indexes which data sources each rule references.

**Matching logic (three-tier):**
1. Exact `dataSource.name` match between the active source and the parser attribute
2. Normalised substring match (ignores spaces, dashes, and case) between the active source name and the parser's `dataSource.name`
3. Normalised substring match against the parser filename — catches files where the `dataSource.name` attribute is incorrect or missing

**Parser detection from data:** During sync, a parallel PowerQuery checks whether each source has events with `event.type` populated in the data lake. If so, a parser is confirmed as running — the source is marked **Covered** even without a local parser file. This handles built-in and cloud-managed parsers that are not present in your `parsers/` folder.

**Status values:**
- 🟢 **Covered** — custom parser confirmed (local file or detected via parsed events in the data lake)
- 🔴 **Parser Needed** — no parser found, or only a grok/dottedJson format (which typically indicates an incomplete parser)

**Expected results:** After syncing sources and loading parsers, sources with active SDL parsers will appear as Covered. Sources sending raw, unparsed data — where only `message` and `timestamp` appear in the data lake — will appear as Parser Needed.

---

### Ingest Dashboard

Answers the question: *where is my event volume coming from, and what would happen if I filtered some of it?*

**Time range:** 1h (default), 3d, 5d, 7d

**Daily Event Volume** — bar chart of total events per day. In 1h mode, this switches to a by-source breakdown of the current hour's activity.

**Top Sources** — a table of the 25 highest-volume `dataSource.name` values with event count and estimated GB (calculated at 0.5 GB per million events).

**Filter Simulator** — enter a source name and an optional event type, then press Simulate. The backend runs a live PowerQuery counting matching events and projects:
- Matched events in the selected period
- Estimated GB that would be saved
- Projected monthly events and GB if the filter were applied permanently

This is entirely read-only — no filter is created or applied. Use the results to inform an exclusion rule you apply manually in the console.

**Expected results:** Top sources should reflect what you see in the SentinelOne console PowerQuery tool. The filter simulator provides a reasonable GB estimate assuming uniform event size across the source.

---

### Parser Quality

Three tools for diagnosing parser extraction failures.

#### Live Event Sampler

Pulls raw events from a selected source directly from the data lake and renders every field that came back. The `message` column is pinned to the right of the table, with a **⎘ copy** button on each row for convenient extraction of raw log lines.

- **Empty fields** are displayed as `∅` in grey — immediately highlighting fields the parser is failing to populate
- **Healthy source:** many fields populated (`src.ip`, `user.name`, `event.type`, etc.), with `message` present as the raw log backup
- **Unhealthy source:** only `timestamp` and `message` populated — the parser is not extracting anything of value

#### Field Population Rate

Samples up to 500 events from a source and measures what percentage of them have each field populated. Results are sorted worst-first so the most pressing gaps are immediately visible.

When you select a source, the tool automatically discovers which fields exist in that source's events and pre-fills the field list — merged with SDL schema defaults. The list is fully editable before running the analysis.

**Colour coding:**
- 🟢 ≥ 80% — healthy extraction
- 🟡 40–79% — partial extraction; check your regex patterns
- 🔴 < 40% — field is rarely populated; the parser is likely not matching this log format variant

**Healthy parser:** Key fields such as `src.ip`, `event.type`, and `user.name` should sit between 70–100%. Niche fields like `src.process.cmdline` or `tgt.file.path` will naturally be lower, as not every event type produces them.

**Broken parser:** All SDL fields at 0%, with only `timestamp` and `message` visible in the "fields seen in sample" chip list at the bottom of the results.

#### Parser Test Runner

Paste a raw log line, select a loaded parser, and press Test. The backend extracts SDL `$field=pattern$` format strings from the parser file, converts them to Python named-group regular expressions, and tries each against your log line.

- **Matched:** displays the format string that matched and every field extracted with its value
- **No match:** none of the parser's format strings apply to this log line — the log may contain a format variant the parser does not yet cover

> **Note:** Only parsers using SDL custom format strings are supported by the test runner. Grok and dottedJson parsers are not currently testable here.

---

### Onboarding Accelerator

A prompt template for using Claude Code to onboard a new log source. Copy the template, paste a sample of raw log lines, and Claude Code will generate:

- An SDL parser skeleton in augmented-JSON format
- Field mappings to the SDL common schema
- 2–3 starter STAR detection rules
- 5 parser test assertions

No Anthropic API key is required — this uses Claude Code directly from your terminal.

---

### Settings

Read and write your `.env` credentials from the interface. Secret fields (API tokens, keys) are masked by default with a show/hide toggle. Changes are written to the mounted `.env` file and take effect after restarting the backend:

```bash
docker-compose up -d --build backend
```

---

## Rebuilding

```bash
# Full rebuild
docker-compose up -d --build

# Backend only (after Python changes)
docker-compose up -d --build backend

# Frontend only (after HTML/JS changes)
docker-compose up -d --build frontend

# Reset the database
curl -X DELETE http://localhost:8001/api/coverage/reset
```

---

## Project Layout

```
.
├── backend/
│   ├── main.py                  # FastAPI application, router registration
│   ├── db.py                    # SQLAlchemy models
│   ├── routers/
│   │   ├── coverage.py          # Parser coverage map endpoints
│   │   ├── ingest.py            # Ingest dashboard + filter simulator
│   │   ├── quality.py           # Parser quality tools
│   │   └── settings.py          # .env read/write
│   └── services/
│       ├── s1_client.py         # SentinelOne + Scalyr API client
│       └── rule_parser.py       # SDL/Sigma/STAR field extraction
├── frontend/
│   └── index.html               # Single-page application (Tailwind, vanilla JS)
├── parsers/                     # SDL parser files (volume-mounted)
├── db/
│   └── init.sql                 # Postgres initialisation (tables created by SQLAlchemy)
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Notes

- The backend queries your **demo tenant** (`demo.sentinelone.net`) — not usea1-purple or any other tenant. Ensure your `S1_BASE_URL` and `SDL_LOG_READ_KEY` are pointed at the same tenant.
- Parser files in `parsers/` are read at query time, not on startup — add or update files at any point without rebuilding the image.
- The filter simulator is entirely read-only and makes no changes whatsoever to your tenant configuration.
