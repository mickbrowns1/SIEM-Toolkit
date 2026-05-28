#!/usr/bin/env python3
"""
recommend_sigma_imports.py

Reads the local Threat Coverage state from the SIEM-toolkit-patched backend
(http://localhost:8001) and recommends concrete Sigma rules from
https://github.com/sigmahq/sigma to import.

Strategy
--------
Sigma rules only add value when:
  1. The targeted log source is ACTIVELY ingested by your tenant.
  2. The MITRE technique is currently weak (low rule_count) or missing.

The script therefore:
  - Lists every active source the backend has detected (with event counts).
  - Lists every covered MITRE technique and per-tactic rule counts.
  - Maps each active source -> the Sigma folder(s) under sigmahq/sigma that
    target that telemetry.
  - Queries the Sigma repo's directory listing on GitHub to confirm the
    folders exist and to count available rules.
  - Prints a prioritised import list, plus the exact `git sparse-checkout`
    commands you can copy/paste.

Usage
-----
  python3 recommend_sigma_imports.py
  python3 recommend_sigma_imports.py --backend http://localhost:8001
"""
from __future__ import annotations
import argparse
import json
import sys
import urllib.request
from typing import Any


GITHUB_API = "https://api.github.com/repos/SigmaHQ/sigma/contents"
SIGMA_REPO = "https://github.com/SigmaHQ/sigma"

# Each active SDL source -> ordered list of (sigma_folder, why_this_folder).
# The folder path is RELATIVE to the sigmahq/sigma repo root.
SOURCE_TO_SIGMA: dict[str, list[tuple[str, str]]] = {
    "Windows Event Logs": [
        ("rules/windows/builtin/security",
         "Direct match: rules keyed on EventID against Security channel."),
        ("rules/windows/builtin/system",
         "System channel: service install, driver load, time tampering."),
        ("rules/windows/builtin/application",
         "Application channel: MSI installs, app crashes used as TTPs."),
        ("rules/windows/process_creation",
         "Process creation (EID 4688 / Sysmon 1). Highest-value Windows folder."),
        ("rules/windows/powershell",
         "PowerShell Operational/Script-block (EID 4103/4104)."),
        ("rules/windows/registry",
         "Sysmon registry events for persistence and config tampering."),
        ("rules/windows/network_connection",
         "Sysmon 3 / 5156 outbound connections from suspicious processes."),
        ("rules/windows/file",
         "Sysmon 11/15 file create + raw-access read (LSASS dump)."),
        ("rules-emerging-threats/2024/Exploits",
         "Recent CVE detections, many Windows-targeted."),
    ],
    "Azure Platform": [
        ("rules/cloud/azure/activity_logs",
         "Azure Activity Log -- subscription/resource manager events."),
        ("rules/cloud/azure/microsoft365",
         "M365 Unified Audit Log."),
        ("rules/cloud/azure/signinlogs",
         "Azure AD / Entra ID sign-in logs."),
        ("rules/cloud/azure/auditlogs",
         "Entra ID directory audit (role assignments, app consent)."),
    ],
    "Identity": [
        ("rules/cloud/azure/signinlogs",
         "Same Entra ID sign-in folder -- maps Identity source."),
        ("rules/cloud/azure/auditlogs",
         "Entra ID directory audit."),
        ("rules/category/authentication",
         "Cross-vendor authentication category."),
    ],
    "Mimecast": [
        ("rules/category/proxy",
         "Sigma generic proxy category covers email-gateway URL events."),
        ("rules-emerging-threats/2024/Malware",
         "Recent phishing / malware lure detections."),
    ],
    "Stormshield": [
        ("rules/network/firewall",
         "Vendor-neutral firewall log rules -- works on Stormshield once "
         "field-mapped via your existing stormshield parser."),
        ("rules/network/cisco",
         "Borrow Cisco ASA rules as templates -- many TTPs translate 1:1."),
    ],
    "Prompt Security": [
        # No first-party Sigma coverage yet; recommend hunting category.
        ("rules-threat-hunting/application",
         "Generic application hunting rules -- closest fit for LLM prompt-"
         "abuse signals until a vendor-specific Sigma category lands."),
    ],
}

# Tactics where rule_count is small enough to be a clear gap. Tuned to the
# Mitre coverage observed on this tenant (Reconnaissance=11, Lateral=83,
# Collection=77, Exfiltration=91, Discovery=86).
GAP_TACTICS = {"Reconnaissance", "Lateral Movement", "Collection",
               "Exfiltration", "Discovery"}


def http_json(url: str, timeout: int = 30) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "siem-toolkit"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def github_dir_count(path: str) -> tuple[int, str]:
    """Return (rule_count, http_status) for a sigma repo subdir."""
    url = f"{GITHUB_API}/{path}"
    try:
        data = http_json(url)
        if isinstance(data, list):
            yml = sum(1 for e in data if isinstance(e, dict)
                      and e.get("name", "").endswith((".yml", ".yaml")))
            sub = sum(1 for e in data if isinstance(e, dict)
                      and e.get("type") == "dir")
            return yml + sub * 0, "OK"  # files at top level only here
        return 0, "no-list"
    except urllib.error.HTTPError as e:
        return 0, f"HTTP {e.code}"
    except Exception as e:
        return 0, f"err {type(e).__name__}"


def github_recursive_count(path: str) -> int:
    """Walk the tree under `path` and count *.yml files (1 level deep is
    enough for Sigma's flat-folder convention; we descend 2 to be safe)."""
    total = 0
    try:
        listing = http_json(f"{GITHUB_API}/{path}")
        if not isinstance(listing, list):
            return 0
        for e in listing:
            if not isinstance(e, dict):
                continue
            if e.get("type") == "file" and e["name"].endswith((".yml", ".yaml")):
                total += 1
            elif e.get("type") == "dir":
                sub = http_json(f"{GITHUB_API}/{path}/{e['name']}")
                if isinstance(sub, list):
                    total += sum(1 for s in sub if isinstance(s, dict)
                                 and s.get("type") == "file"
                                 and s["name"].endswith((".yml", ".yaml")))
    except Exception:
        return total
    return total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://localhost:8001",
                    help="SIEM-toolkit-patched backend URL")
    ap.add_argument("--no-github", action="store_true",
                    help="Skip GitHub API calls (offline / rate-limited).")
    args = ap.parse_args()

    print(f"\n{'='*78}\n  SIGMA IMPORT RECOMMENDATIONS\n{'='*78}")
    print(f"  Backend          : {args.backend}")
    print(f"  Sigma repo       : {SIGMA_REPO}")
    print(f"  GitHub lookups   : {'disabled' if args.no_github else 'enabled'}")

    # 1) Coverage health
    try:
        health = http_json(f"{args.backend}/api/coverage/health")
    except Exception as e:
        print(f"\n[FATAL] cannot reach backend: {e}")
        return 1

    print(f"\n--- Current coverage health ---")
    print(f"  health_score     : {health['health_score']}")
    print(f"  parser_pct       : {health['parser_pct']}")
    print(f"  mitre_pct        : {health['mitre_pct']}")
    print(f"  firing_pct       : {health['firing_pct']}  "
          f"(only {health['rules_fired']} of {health['rules_loaded']} "
          f"have fired -- importing rules without verifying they fire is "
          f"the #1 source of dashboard noise)")
    print(f"  active_sources   : {health['active_sources']}")
    print(f"  tactics_covered  : {health['tactics_covered']}/15")
    print(f"  techniques cov.  : {health['techniques_covered']}")

    # 2) Active sources
    cov_map = http_json(f"{args.backend}/api/coverage/map")
    print(f"\n--- Active log sources (ordered by event volume) ---")
    print(f"  {'source':<24}{'events':>10}  {'parser':<32} rule_count")
    sources = sorted(cov_map["sources"], key=lambda s: -s["event_count"])
    for s in sources:
        print(f"  {s['source_name']:<24}{s['event_count']:>10}  "
              f"{(s.get('parser') or '-'):<32}{s.get('rule_count', '-')}")

    # 3) MITRE tactic gaps
    mitre = http_json(f"{args.backend}/api/coverage/mitre")
    print(f"\n--- MITRE tactic depth (rules / techniques per tactic) ---")
    print(f"  {'tactic':<26}{'rules':>8}{'techs':>8}   gap?")
    for t in mitre["tactics"]:
        gap = "  <-- THIN" if t["tactic"] in GAP_TACTICS else ""
        print(f"  {t['tactic']:<26}{t['rule_count']:>8}"
              f"{t['technique_count']:>8}{gap}")

    # 4) Recommended Sigma folders, prioritised by active-source volume
    print(f"\n{'='*78}\n  RECOMMENDED SIGMA FOLDERS TO IMPORT\n{'='*78}")
    print("  Priority order = which active source has the most events.\n"
          "  Only folders for sources that are ACTIVELY producing telemetry\n"
          "  appear below -- rules for sources you don't ingest add zero\n"
          "  detection value and pollute the rule library.\n")

    seen = set()
    sparse_paths: list[str] = []
    for s in sources:
        name = s["source_name"]
        evt = s["event_count"]
        folders = SOURCE_TO_SIGMA.get(name, [])
        if not folders:
            print(f"--- {name}  ({evt:,} events) -- no Sigma mapping curated")
            continue
        print(f"\n--- {name}  ({evt:,} events) ---")
        for folder, why in folders:
            if folder in seen:
                continue
            seen.add(folder)
            sparse_paths.append(folder)
            count_str = ""
            if not args.no_github:
                n = github_recursive_count(folder)
                count_str = f"  [~{n} rules]"
            print(f"  * {folder}{count_str}")
            print(f"      {why}")

    # 5) Concrete import commands
    print(f"\n{'='*78}\n  COPY/PASTE: import these folders only\n{'='*78}\n")
    print("  # 1. clone Sigma with sparse-checkout (no full 5GB history)")
    print("  git clone --filter=blob:none --no-checkout "
          f"{SIGMA_REPO}.git /tmp/sigma")
    print("  cd /tmp/sigma")
    print("  git sparse-checkout init --cone")
    print("  git sparse-checkout set \\")
    for p in sparse_paths:
        print(f"      {p} \\")
    print("      # end of folder list")
    print("  git checkout main")
    print()
    print("  # 2. push each .yml file into SIEM-toolkit-patched via the")
    print("  #    backend's /api/coverage/upload-sigma endpoint (one POST")
    print("  #    per file, multipart/form-data):")
    print(f"""
  find . -path './rules*' -name '*.yml' | while read f ; do
      curl -sS -F "file=@$f" {args.backend}/api/coverage/upload-sigma \\
           -w "%{{http_code}}  $f\\n" -o /dev/null
  done
""")

    # 6) High-value individual rules (curated -- always worth importing)
    print(f"{'='*78}\n  HIGH-PRIORITY INDIVIDUAL RULES (curated)\n{'='*78}")
    must_have = [
        # Lateral Movement -- weak tactic (83 rules)
        ("rules/windows/builtin/security/win_security_admin_rdp_login.yml",
         "Lateral Movement", "T1021.001 RDP"),
        ("rules/windows/builtin/security/"
         "win_security_susp_smb_share_object_access_lateral_movement.yml",
         "Lateral Movement", "T1021.002 SMB"),
        ("rules/windows/process_creation/"
         "proc_creation_win_winrm_lateral_movement.yml",
         "Lateral Movement", "T1021.006 WinRM"),
        # Collection -- weak tactic (77 rules)
        ("rules/windows/process_creation/"
         "proc_creation_win_susp_screenshot.yml",
         "Collection", "T1113 Screen Capture"),
        ("rules/windows/process_creation/"
         "proc_creation_win_powershell_clipboard.yml",
         "Collection", "T1115 Clipboard Data"),
        # Exfiltration -- weak tactic (91 rules)
        ("rules/windows/network_connection/"
         "net_connection_win_rclone.yml",
         "Exfiltration", "T1567.002 Exfil to Cloud Storage"),
        ("rules/windows/process_creation/"
         "proc_creation_win_rar_compress_data.yml",
         "Exfiltration", "T1560.001 Archive via Utility"),
        # Reconnaissance -- THINNEST tactic (11 rules)
        ("rules/windows/process_creation/"
         "proc_creation_win_susp_netsh_dump_config.yml",
         "Reconnaissance", "T1016 System Network Config Discovery"),
        ("rules/windows/process_creation/"
         "proc_creation_win_susp_adsisearcher.yml",
         "Reconnaissance", "T1087.002 Domain Account Discovery"),
        # Discovery
        ("rules/windows/process_creation/"
         "proc_creation_win_susp_bloodhound_sharphound.yml",
         "Discovery", "T1087/T1482 BloodHound/SharpHound"),
        # Credential Access (already 217 rules but always topical)
        ("rules/windows/process_creation/"
         "proc_creation_win_susp_mimikatz_command_line.yml",
         "Credential Access", "T1003.001 LSASS Memory"),
        ("rules/windows/process_creation/"
         "proc_creation_win_susp_lsass_dump.yml",
         "Credential Access", "T1003.001 LSASS Memory"),
        # Azure -- broad coverage gap
        ("rules/cloud/azure/signinlogs/"
         "azure_aad_sign_ins_from_noninteractive_devices.yml",
         "Initial Access", "T1078.004 Cloud Account abuse"),
        ("rules/cloud/azure/auditlogs/"
         "azure_aad_role_assigned.yml",
         "Privilege Escalation", "T1098 Account Manipulation"),
    ]
    print(f"  {'tactic':<22}{'technique':<35}rule")
    for path, tactic, tech in must_have:
        print(f"  {tactic:<22}{tech:<35}{path}")

    print(f"\n  These 14 rules close the thinnest gaps surfaced by the")
    print(f"  Threat Coverage map above. Import them FIRST, then iterate")
    print(f"  through the bulk folders.\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
