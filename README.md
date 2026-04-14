# DefenseFlow Alerts Parsing

Unified Radware report tool that parses DefensePro, Kentik, and Arbor alert logs and produces CSV attack reports and weekly HTML trend reports.

---

## Repository layout

```
radware_reports.py      ← main script (run this)
alert_parser.ini        ← configuration (paths, time range)

Input/                  ← DefensePro alert log files
Reports/                ← DefensePro CSV output

Kentik/
  Input/                ← Kentik alert log files
  Reports/              ← Kentik CSV and HTML output

Arbor/
  Input/                ← Arbor alert log files
  Reports/              ← Arbor CSV and HTML output
```

Log files may be plain `alert*.log` files or zip archives containing `logs/alert*` members (nested zip archives are supported automatically).

---

## Quick start

```bash
python radware_reports.py
```

An interactive menu is displayed:

```
  Select report type:
    [1] DefensePro        — parse logs → attack session CSV
    [2] Kentik            — parse logs → attack cycle CSV
    [3] Arbor             — parse logs → attack cycle CSV
    [4] Kentik Weekly HTML  — attack cycle trends (HTML report)
    [5] Arbor Weekly HTML   — attack cycle trends (HTML report)
    [Q] Quit
```

---

## Report types

### [1] DefensePro — attack session CSV

Parses `DEFENSE_PRO` log lines (event codes `DFC00701` / `DFC00703`) and groups raw detection events into discrete attack sessions using a configurable gap threshold.

- **Input:** `Input/` (plain logs or zips)
- **Output:** `Reports/defensepro_attack_sessions_<datetime>.csv`
- **CSV columns:** `Sensor`, `ProtectedObject`, `TargetNetwork`, `Protocol`, `SessionStart`, `SessionEnd`, `DurationMin`, `EventCount`, `PeakBW_human`, `PeakBW_bps`, `ProtectedName`, `PolicyName`, `SourceLogFile`

### [2] Kentik — attack cycle CSV

Parses Kentik-sourced attack events (`kentik_<id>`) including mitigation UP/DOWN events (`DFC00360` / `DFC00361`).

- **Input:** `Kentik/Input/`
- **Output:** `Kentik/Reports/kentik_attack_cycles_<datetime>.csv`
- **CSV columns:** `Kentik_ID`, `Status`, `Target_Network`, `Protocol`, `Peak_Bandwidth`, `Peak_Bandwidth_bps`, `Peak_PPS`, `Peak_PPS_raw`, `Attack_Start`, `Attack_End`, `Duration_min`, `Mitigation_UP`, `Mitigation_DOWN`, `ProtectedName`, `PolicyName`, `Source_Log_File`

### [3] Arbor — attack cycle CSV

Parses Arbor/external-detector attack events (`DFC00701` with `EXTERNAL_DETECTOR` or `Arbor` keyword), mitigation UP/DOWN, and policy provisioning (`DFC00712`).

- **Input:** `Arbor/Input/`
- **Output:** `Arbor/Reports/arbor_attack_cycles_<datetime>.csv`
- **CSV columns:** `Arbor_ID`, `Status`, `Protected_Object`, `Policy_Name`, `Target_Network`, `Protocol`, `Peak_Bandwidth`, `Peak_Bandwidth_bps`, `Peak_PPS`, `Peak_PPS_raw`, `Attack_Start`, `Attack_End`, `Duration_min`, `Mitigation_UP`, `Mitigation_DOWN`, `Source_Log_File`

### [4] Kentik Weekly HTML

Reads all `kentik_attack_cycles_*.csv` files from `Kentik/Reports/` and generates a self-contained HTML report with:

- Overview stat cards (total attacks, peak bandwidth, peak PPS, most targeted IP)
- Interactive bar charts (attack count, peak BW, peak PPS, top destination per week)
- Clickable peak-attack detail modal
- Weekly detail table

- **Output:** `Kentik/Reports/kentik_weekly_report_<datetime>.html`

### [5] Arbor Weekly HTML

Same as above but sourced from `Arbor/Reports/arbor_attack_cycles_*.csv`.

- **Output:** `Arbor/Reports/arbor_weekly_report_<datetime>.html`

---

## Configuration — `alert_parser.ini`

```ini
[range]
start      = 2026-03-01 00:00:00
end        = 2026-03-31 23:59:59
# last_hours = 24
# last_days  = 7

[defensepro]
log_dir     = Input
out_file    = Reports/defensepro_attack_sessions_{datetime}.csv
gap_minutes = 10

[kentik]
log_dir  = Kentik/Input
out_file = Kentik/Reports/kentik_attack_cycles_{datetime}.csv

[arbor]
log_dir  = Arbor/Input
out_file = Arbor/Reports/arbor_attack_cycles_{datetime}.csv
```

**Time range priority:** `start/end` → `last_hours` → `last_days` → no filter (all records).

The `{datetime}` token in `out_file` is replaced with `YYYY-MM-DD_HH-MM-SS` at run time.

---

## CLI usage (skip the menu)

```bash
# Run a specific report directly
python radware_reports.py --report dp
python radware_reports.py --report kentik
python radware_reports.py --report arbor

# Weekly HTML reports
python radware_reports.py --report kentik-weekly
python radware_reports.py --report arbor-weekly

# Override the date range
python radware_reports.py --report arbor-weekly --start 2026-03-01 --end 2026-03-31

# Interactive time-range prompt
python radware_reports.py --report dp --interactive

# Use a specific config file
python radware_reports.py --config alert_parser.ini

# Override paths on the fly
python radware_reports.py --report kentik --log-dir /path/to/logs --out /path/to/output.csv

# Override DefensePro gap threshold
python radware_reports.py --report dp --gap-minutes 15
```

### All CLI options

| Option | Description |
|---|---|
| `--report` | `dp` / `kentik` / `arbor` / `kentik-weekly` / `arbor-weekly` |
| `--interactive` / `-i` | Prompt for time-range filter interactively |
| `--config` / `-c` | Path to INI config file (default: `alert_parser.ini`) |
| `--start` | Start date `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` |
| `--end` | End date `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` |
| `--log-dir` | Override log input directory |
| `--csv-dir` | Override CSV directory for weekly reports |
| `--out` | Override output file path |
| `--gap-minutes` | DefensePro session gap in minutes (default: 10) |

> `--interactive` and `--config` are mutually exclusive.

---

## Requirements

- Python 3.8+
- Standard library only (no third-party packages required)
- Internet access for the weekly HTML report (loads Chart.js from CDN; works offline if CDN is cached)