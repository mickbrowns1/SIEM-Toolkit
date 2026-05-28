# Sigma → SentinelOne PowerQuery pipeline

End-to-end workflow that turns SigmaHQ rules into SentinelOne SDL
Scheduled custom-detection rules, **starting from the coverage gaps the
SIEM-toolkit identifies**.

## TL;DR

1. **SIEM-toolkit** provides the coverage map to find what's thin —
   MITRE ATT&CK heatmap across all detection library rules, rule firing
   status (active vs never-fired).
2. **Pick Sigma rules** ([SigmaHQ/sigma](https://github.com/SigmaHQ/sigma))
   that target those tactics.
3. **Convert** the Sigma rules to PowerQuery with
   [`pysigma-backend-sentinelone-pq`](https://pypi.org/project/pysigma-backend-sentinelone-pq/).
4. **Smoke-test** against your tenant's `/api/powerQuery`, **deploy**
   via `/web/api/v2.1/cloud-detection/rules` as Scheduled PQ rules in
   Draft.
5. **Re-running on a different tenant** is just re-pointing the
   credentials — the converted `.pq` bodies travel as-is.

## Setup (once)

```bash
# 1. Tooling
python3 -m venv /tmp/sigma_venv
/tmp/sigma_venv/bin/pip install pysigma pysigma-backend-sentinelone-pq
brew install gh && gh auth login                # avoids GitHub rate limits

# 2. Credentials
cp tenant_config.example.json tenant_config.json
$EDITOR tenant_config.json                      # fill in 5 keys
# tenant_config.json is gitignored.
```

`tenant_config.json` shape:
```json
{
  "S1_CONSOLE_URL":       "https://<region>-<tenant>.example",
  "S1_CONSOLE_API_TOKEN": "<S1 Mgmt API token>",
  "SDL_XDR_URL":          "https://xdr.<region>.example",
  "SDL_LOG_READ_KEY":     "<SDL Log Read scope>",
  "SDL_CONFIG_READ_KEY":  "<SDL Configuration Read scope>"
}
```

Optional environment overrides:

| Variable | Default | Purpose |
|---|---|---|
| `SIEM_TOOLKIT_CONFIG` | `./tenant_config.json` | path to credentials |
| `SIGMA_OUT_DIR` | `/tmp/sigma_converted_v4` | where `.pq` artefacts land |
| `SIGMA_VENV_PY` | `/tmp/sigma_venv/bin/python3` | Python that hosts pysigma |
| `GH_BIN` | `gh` | GitHub CLI binary |
| `SITE_ID` | (auto-discovered) | force-deploy into a specific site |
| `DEPLOYED_IDS_FILE` | `./deployed_rule_ids.json` | input for verify scripts |

## The 5-step workflow

### Step 1 — Find thin tactics

```bash
python3 recommend_sigma_imports.py
```

Reads the SIEM-toolkit coverage endpoints (`/api/coverage/health`,
`/api/coverage/mitre`, `/api/coverage/map`) and prints, in order:

- Tenant **health row** (`health_score`, `firing_pct`, active sources).
- **Active log sources** ranked by event volume — only import Sigma
  rules whose `logsource` matches a source that actually produces
  events here.
- **MITRE tactic depth** — tactics with `rule_count < 100` and a high
  `technique_count` are the THIN ones. Typical findings:
  Reconnaissance, Discovery, Lateral Movement, Collection, Exfiltration.
- **Recommended SigmaHQ folders** with GitHub-verified rule counts.
- A curated **14-rule shortlist** for the thinnest gaps.

### Step 2 — Pick Sigma rules

The picker in `convert_test_deploy_sigma.py` matches filename-stem
keywords against the SigmaHQ tree it lists via `gh api`. Edit the
`WANTED` table to change the 10 rules. Each row is
`(tactic, technique_label, [keywords], allow_powershell_folder)`.

The default list covers:

| Tactic | Technique | Sigma file |
|---|---|---|
| Lateral Movement | T1021.006 WinRM (evil-winrm) | `proc_creation_win_hktl_evil_winrm.yml` |
| Collection | T1113 Screen Capture (Psr.exe) | `proc_creation_win_psr_capture_screenshots.yml` |
| Collection | T1115 Clipboard (Get-Clipboard) | `proc_creation_win_powershell_get_clipboard.yml` |
| Exfiltration | T1560.001 RAR (.dmp files) | `proc_creation_win_winrar_exfil_dmp_files.yml` |
| Exfiltration | T1567.002 rclone | `proc_creation_win_pua_rclone_execution.yml` |
| Reconnaissance | T1016 netsh portproxy | `proc_creation_win_netsh_port_forwarding.yml` |
| Discovery | T1087/T1033 whoami /priv | `proc_creation_win_whoami_priv_discovery.yml` |
| Discovery | T1087/T1482 SharpHound | `proc_creation_win_hktl_bloodhound_sharphound.yml` |
| Credential Access | T1003.001 Mimikatz cmd-line | `proc_creation_win_hktl_mimikatz_command_line.yml` |
| Credential Access | T1003.001 ProcDump LSASS | `proc_creation_win_sysinternals_procdump_lsass.yml` |

### Step 3 — Convert + smoke-test + deploy

Optional preliminary: probe what fields the tenant's WEL parser
actually emits so the WEL-mapped variant queries land on real columns:

```bash
python3 probe_wel_schema.py
```

Then run the master pipeline:

```bash
# Convert + smoke-test only:
python3 convert_test_deploy_sigma.py

# Convert + smoke-test + create SDL Scheduled rules in Draft:
python3 convert_test_deploy_sigma.py --deploy
```

For each of the 10 rules the script writes **three** PowerQuery variants:

| File | Purpose |
|---|---|
| `<stem>.pq` | **faithful** — S1 DV schema (production form) |
| `<stem>.relaxed.pq` | strips `endpoint.os` and `event.type` clauses (useful on tenants where those fields are null) |
| `<stem>.wel.pq` | rewritten onto the `microsoft_windows_eventlog-latest` parser fields (`CommandLine`, `Image`, `ParentImage`, `EventID=4688\|1`, `dataSource.name='Windows Event Logs'`) |

Each variant is smoke-tested against `POST {SDL_XDR_URL}/api/powerQuery`
(last 24 h). HTTP 200 is what we want; rows=0 simply means no telemetry
matched in the window.

With `--deploy`, the **faithful** variant is also POSTed to
`/web/api/v2.1/cloud-detection/rules` as a `Scheduled` rule in `Draft`
status, then `deployed_rule_ids.json` is written next to the script
mapping each rule ID back to its source.

#### Edge cases the converter handles

- **Unsupported Sigma fields** (e.g. `OriginalFileName`) cause the
  backend to print its known-field list as the error.
  `fixup_rules_6_7.py` strips those keys from the YAML and re-converts.
  The rule remains semantic because `Image|endswith:` is the primary
  selector.
- **Wrong folder** — some rules live under `rules/windows/powershell/`
  not `process_creation/`. The picker can expand its scope.
- **`event.type='Process Creation'` and `endpoint.os='windows'`** are
  often empty on real tenants — that's why the **relaxed** and **WEL**
  variants exist.

### Step 4 — Verify

The service-user role that can POST a rule often **cannot** GET it
back (`cloudDetectionRulesView` missing). The collection endpoint
silently filters the rule out, and `GET /rules/{id}` returns HTTP 405
on this API version. PUT is the definitive existence test:

```bash
python3 verify_rule_exists_via_put.py
```

Reads `deployed_rule_ids.json` and PUTs each rule ID. 200/204 = EXISTS,
404 = NOT FOUND. Optional deeper diagnostic:

```bash
python3 verify_deployed_sigma_rules.py
```

Probes the list endpoint with several scope-filter variants so you can
see exactly which RBAC layer is hiding what.

### Step 5 — Run on another tenant

The 30 `.pq` files in `SIGMA_OUT_DIR` are tenant-agnostic. Point the
credentials at a different tenant and re-run only Step 3's deploy +
Step 4:

```bash
# Option A: replace tenant_config.json
cp tenant_config.example.json tenant_config.json && $EDITOR tenant_config.json
python3 run_sigma_on_tenant.py

# Option B: keep separate config files
SIEM_TOOLKIT_CONFIG=./tenant_prod.json   python3 run_sigma_on_tenant.py
SIEM_TOOLKIT_CONFIG=./tenant_lab.json    python3 run_sigma_on_tenant.py
```

`run_sigma_on_tenant.py` is a single-shot probe → smoke-test → deploy
→ PUT-verify, useful when you already have the converted bodies and
just want to land them on a new tenant.

## Files

| File | Role |
|---|---|
| `recommend_sigma_imports.py` | Reads coverage endpoints, recommends folders + curated rule list |
| `probe_wel_schema.py` | Discovers WEL parser field schema on the tenant |
| `convert_test_deploy_sigma.py` | Master pipeline: pick + convert (3 variants) + smoke + `--deploy` |
| `fixup_rules_6_7.py` | Handles Sigma rules with backend-unsupported keys (e.g. `OriginalFileName`) |
| `run_sigma_on_tenant.py` | Re-deploys already-converted bodies to another tenant |
| `verify_rule_exists_via_put.py` | PUT-existence test (definitive when GET is RBAC-blocked) |
| `verify_deployed_sigma_rules.py` | Probes scope/filter variants to diagnose RBAC |
| `tenant_config.example.json` | Template — copy to `tenant_config.json` (gitignored) |

## Where it fits in the SIEM-toolkit story

```
SIEM-toolkit Threat Coverage map
    │
    ▼
recommend_sigma_imports.py      ──┐
    │  (suggests SigmaHQ folders) │
    ▼                             │
convert_test_deploy_sigma.py      ├── single workflow
    │  (Sigma → PQ → SDL)         │
    ▼                             │
verify_rule_exists_via_put.py   ──┘
    │
    ▼
Activate rules in console UI
    │
    ▼
Re-run SIEM-toolkit Threat Coverage  → firing_pct grows
```

## Pitfalls collected so far

- **`event.type='Process Creation'`** has near-zero population unless a
  live S1 EDR agent is reporting; relax variant works around it.
- **`endpoint.os='windows'`** is `null` on many tenants; always strip
  for the relaxed variant.
- **GitHub anonymous rate limit** (60 req/h) kills the listing step —
  use `gh auth login`.
- **Service-user RBAC** without `cloudDetectionRulesView` makes POSTed
  rules invisible to GET. PUT confirms they exist.
- **`OriginalFileName`** in Sigma YAML breaks the S1-PQ backend; strip
  with the pre-processor.
- **PowerQuery parser quirks** — bare `*` as a query is rejected;
  comments with `/`, `-`, or non-ASCII characters cause Load Failed at
  rule-validation time even when the body POSTs fine to
  `/api/powerQuery`. Keep comments out of any body that will be
  deployed as a Scheduled rule.
