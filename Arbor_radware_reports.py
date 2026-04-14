#!/usr/bin/env python3
"""
radware_reports.py  —  Unified Radware Report Tool

Combines all three report types into a single interactive menu:
  [1] DefensePro   — parse alert logs → attack session CSV
  [2] Arbor       — parse alert logs → attack cycle CSV
  [3] Both         — run DefensePro + Arbor parsers together
  [4] Weekly HTML  — read arbor_attack_cycles_*.csv → weekly trend HTML report

Usage:
    python radware_reports.py                          # interactive menu
    python radware_reports.py --report dp              # skip menu, run DefensePro
    python radware_reports.py --report arbor          # skip menu, run Arbor
    python radware_reports.py --report both            # skip menu, run both parsers
    python radware_reports.py --report weekly          # skip menu, weekly HTML
    python radware_reports.py --report weekly --start 2026-03-01 --end 2026-03-30
    python radware_reports.py --config alert_parser.ini
    python radware_reports.py --report dp --interactive
"""

import argparse
import calendar
import configparser
import csv
import io
import json
import re
import sys
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import groupby
from pathlib import Path

TS_FMT       = "%Y-%m-%d %H:%M:%S"
DATE_FMT     = "%Y-%m-%d"
DATETIME_FMT = "%Y-%m-%d_%H-%M-%S"
SCRIPT_DIR   = Path(__file__).parent
REPORTS_DIR  = SCRIPT_DIR / "Reports"
DEFAULT_CFG  = SCRIPT_DIR / "alert_parser.ini"


# ══════════════════════════════════════════════════════════════════
#  Shared helpers
# ══════════════════════════════════════════════════════════════════

def human_bw(bps: int) -> str:
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps > 0:
        return f"{bps:,} bps"
    return "N/A"


def human_pps(pps: int) -> str:
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f}M pps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f}K pps"
    if pps > 0:
        return f"{pps} pps"
    return "N/A"


def format_duration(minutes: int) -> str:
    if minutes <= 0:
        return "N/A"
    if minutes >= 60:
        h, m = divmod(minutes, 60)
        return f"{h}h {m:02d}m" if m else f"{h}h"
    return f"{minutes} min"


def _parse_dt(value: str) -> "datetime | None":
    """Parse a date/time string; returns None on failure."""
    for fmt in (TS_FMT, DATE_FMT):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            pass
    return None


def _prompt(label: str, required: bool = True) -> str:
    while True:
        val = input(f"  {label}: ").strip()
        if val or not required:
            return val
        print("  Value is required, please try again.")


def _separator(char: str = "─", width: int = 52) -> str:
    return char * width


def _collect_log_sources(path: Path) -> tuple:
    """Return ``(sources, zip_handles)`` for the given *path*.

    *path* may be:

    - A **zip file** — members matching ``logs/alert*`` are extracted.
    - A **directory** — all ``*.zip`` files are searched for ``logs/alert*``
      members.  Falls back to ``alert*.log`` plain files if no zips found.

    Nested zip members (e.g. ``logs/alert.1.log.zip``) are unpacked
    automatically and their inner log file is added as a source.

    Each entry in *sources* is a ``(name, opener)`` pair where ``opener()``
    returns an open text-mode file handle ready for line iteration.
    *zip_handles* is a list of open :class:`zipfile.ZipFile` objects; the
    caller must close all of them after parsing.
    """
    zip_handles: list = []
    sources: list = []

    def _alert_sort_key(m: zipfile.ZipInfo) -> tuple:
        # Process oldest rotated archives first (alert.9.log.zip → alert.1.log.zip
        # → alert.log) so end events are never encountered before their starts.
        num = re.search(r"alert\.(\d+)\.log", m.filename)
        return (-int(num.group(1)), "") if num else (1, m.filename)

    def _process_outer_zip(zf: zipfile.ZipFile) -> None:
        members = sorted(
            (m for m in zf.infolist() if re.match(r"logs[/\\]alert", m.filename)),
            key=_alert_sort_key,
        )
        for m in members:
            if m.filename.endswith(".zip"):
                # Nested zip — read bytes eagerly then open as inner ZipFile
                inner_bytes = zf.read(m.filename)
                inner_zf = zipfile.ZipFile(io.BytesIO(inner_bytes))
                zip_handles.append(inner_zf)
                for im in inner_zf.infolist():
                    sources.append((
                        im.filename,
                        lambda inner_zf=inner_zf, im=im: io.TextIOWrapper(
                            inner_zf.open(im), encoding="utf-8", errors="replace"),
                    ))
            else:
                entry_name = Path(m.filename).name
                sources.append((
                    entry_name,
                    lambda zf=zf, m=m: io.TextIOWrapper(
                        zf.open(m), encoding="utf-8", errors="replace"),
                ))

    if path.is_file() and zipfile.is_zipfile(path):
        outer = zipfile.ZipFile(path, "r")
        zip_handles.append(outer)
        _process_outer_zip(outer)
    elif path.is_dir():
        zip_paths = sorted(path.glob("*.zip"))
        if zip_paths:
            for zp in zip_paths:
                outer = zipfile.ZipFile(zp, "r")
                zip_handles.append(outer)
                _process_outer_zip(outer)
        else:
            for p in sorted(path.glob("alert*.log")):
                sources.append((p.name, lambda p=p: open(p, encoding="utf-8", errors="replace")))

    return sources, zip_handles


# ══════════════════════════════════════════════════════════════════
#  Time-range
# ══════════════════════════════════════════════════════════════════

class TimeRange:
    """Optional inclusive [start, end] filter applied to attack/session start."""

    def __init__(self, start: "datetime | None", end: "datetime | None"):
        self.start = start
        self.end   = end

    @property
    def active(self) -> bool:
        return self.start is not None or self.end is not None

    def contains_dt(self, dt: datetime) -> bool:
        if self.start and dt < self.start:
            return False
        if self.end and dt > self.end:
            return False
        return True

    def contains_str(self, ts_str: str) -> bool:
        if not self.active:
            return True
        if not ts_str:
            return False
        try:
            return self.contains_dt(datetime.strptime(ts_str, TS_FMT))
        except ValueError:
            return False

    def label(self) -> str:
        s = self.start.strftime(TS_FMT) if self.start else "—"
        e = self.end.strftime(TS_FMT)   if self.end   else "—"
        return f"{s}  →  {e}"

    def as_tuple(self):
        """Return (start_dt, end_dt) for the weekly report functions."""
        return self.start, self.end


def _range_from_last_hours(n: float) -> TimeRange:
    end   = datetime.now().replace(second=59, microsecond=0)
    start = end - timedelta(hours=n)
    return TimeRange(start, end)


def _range_from_last_days(n: float) -> TimeRange:
    end   = datetime.now().replace(hour=23, minute=59, second=59, microsecond=0)
    start = (end - timedelta(days=n)).replace(hour=0, minute=0, second=0)
    return TimeRange(start, end)


def interactive_range() -> TimeRange:
    """Prompt the user to define a time-range filter."""
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          Time Range Filter Setup               │")
    print("└" + _separator("─", 48) + "┘")
    print()
    print("  [1] Fixed date/time range")
    print("  [2] Last N hours")
    print("  [3] Last N days")
    print("  [4] No filter  (include all records)")
    print()

    choice = ""
    while choice not in ("1", "2", "3", "4"):
        choice = input("  Selection [1-4]: ").strip()

    if choice == "1":
        print()
        print("  Format: YYYY-MM-DD HH:MM:SS  or  YYYY-MM-DD")
        while True:
            raw = _prompt("Start (inclusive)")
            start = _parse_dt(raw)
            if start:
                break
            print(f"  ERROR: Cannot parse '{raw}' — use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
        while True:
            raw = _prompt("End   (inclusive, Enter = now)", required=False)
            if not raw:
                end = datetime.now()
                break
            # date-only → treat as end of that day
            end = _parse_dt(raw)
            if end:
                if len(raw.strip()) == 10:
                    end = end.replace(hour=23, minute=59, second=59)
                break
            print(f"  ERROR: Cannot parse '{raw}'")
        if end < start:
            print("  WARNING: end is before start — swapping.")
            start, end = end, start
        return TimeRange(start, end)

    if choice == "2":
        while True:
            try:
                hours = float(_prompt("Hours back (e.g. 24)"))
                if hours <= 0:
                    raise ValueError
                return _range_from_last_hours(hours)
            except ValueError:
                print("  ERROR: Enter a positive number.")

    if choice == "3":
        while True:
            try:
                days = float(_prompt("Days back (e.g. 7)"))
                if days <= 0:
                    raise ValueError
                return _range_from_last_days(days)
            except ValueError:
                print("  ERROR: Enter a positive number.")

    return TimeRange(None, None)


# ══════════════════════════════════════════════════════════════════
#  Config helpers
# ══════════════════════════════════════════════════════════════════

def load_config(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    return cfg


def _cfg_str(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    return cfg.get(section, key, fallback="").strip()


def _cfg_int(cfg: configparser.ConfigParser, section: str, key: str, default: int) -> int:
    val = _cfg_str(cfg, section, key)
    try:
        return int(val) if val else default
    except ValueError:
        return default


def range_from_config(cfg: configparser.ConfigParser) -> TimeRange:
    """Build a TimeRange from the [range] section of the INI config."""
    if not cfg.has_section("range"):
        return TimeRange(None, None)

    start_s = _cfg_str(cfg, "range", "start")
    end_s   = _cfg_str(cfg, "range", "end")
    if start_s:
        start = _parse_dt(start_s)
        if start:
            end_raw = _parse_dt(end_s) if end_s else datetime.now()
            return TimeRange(start, end_raw)

    hours_s = _cfg_str(cfg, "range", "last_hours")
    if hours_s:
        try:
            return _range_from_last_hours(float(hours_s))
        except ValueError:
            pass

    days_s = _cfg_str(cfg, "range", "last_days")
    if days_s:
        try:
            return _range_from_last_days(float(days_s))
        except ValueError:
            pass

    return TimeRange(None, None)


# ══════════════════════════════════════════════════════════════════
#  DefensePro parser
# ══════════════════════════════════════════════════════════════════

def dp_parse_logs(log_sources: list) -> tuple:
    start_events, end_events = [], []
    for name, opener in log_sources:
        with opener() as fh:
            for line in fh:
                if "DEFENSE_PRO" not in line:
                    continue
                m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), TS_FMT)
                except ValueError:
                    continue

                m2 = re.search(r"detection source name (\S+?)[\s.]", line)
                sensor = m2.group(1) if m2 else "Unknown"
                m3 = re.search(r"Protected object (\S+):", line)
                po = m3.group(1) if m3 else "Unknown"
                m4 = re.search(r"attack (?:started|ended) on network (\S+)", line)
                net = m4.group(1) if m4 else "Unknown"
                m5 = re.search(r"protocol (\S+) external", line)
                proto = m5.group(1) if m5 else "N/A"
                m_bw = re.search(r"bandwidth (\d+)\(bps\)", line)
                bw = int(m_bw.group(1)) if m_bw else 0

                event = dict(ts=ts, sensor=sensor, po=po, net=net,
                             proto=proto, bw=bw, file=name)
                if "DFC00701" in line:
                    start_events.append(event)
                elif "DFC00703" in line:
                    end_events.append(event)
    return start_events, end_events


def dp_build_sessions(start_events: list, gap: timedelta) -> list:
    start_events.sort(key=lambda e: (e["sensor"], e["po"], e["net"], e["ts"]))
    sessions = []

    for _key, group_iter in groupby(
        start_events, key=lambda e: (e["sensor"], e["po"], e["net"])
    ):
        evts      = list(group_iter)
        ses_start = evts[0]["ts"]
        ses_end   = evts[0]["ts"]
        max_bw    = 0
        event_cnt = 0
        sensor    = evts[0]["sensor"]
        po        = evts[0]["po"]
        net       = evts[0]["net"]
        proto     = evts[0]["proto"]
        src_file  = evts[0]["file"]

        def _close():
            dur_min = int((ses_end - ses_start).total_seconds() / 60)
            sessions.append({
                "Sensor":          sensor,
                "ProtectedObject": po,
                "TargetNetwork":   net,
                "Protocol":        proto,
                "SessionStart":    ses_start.strftime(TS_FMT),
                "SessionEnd":      ses_end.strftime(TS_FMT),
                "_start_dt":       ses_start,
                "DurationMin":     dur_min,
                "EventCount":      event_cnt,
                "PeakBW_human":    human_bw(max_bw),
                "PeakBW_bps":      max_bw,
                "SourceLogFile":   src_file,
            })

        for i, e in enumerate(evts):
            if i > 0 and (e["ts"] - ses_end) > gap:
                _close()
                ses_start = e["ts"]; ses_end = e["ts"]
                max_bw = 0; event_cnt = 0; src_file = e["file"]
            ses_end = e["ts"]
            if e["bw"] > max_bw:
                max_bw = e["bw"]
            event_cnt += 1

        _close()

    return sessions


def dp_print_summary(sessions: list, start_cnt: int, end_cnt: int) -> None:
    if not sessions:
        print("  No sessions matched.")
        return

    total   = len(sessions)
    durs    = [s["DurationMin"] for s in sessions if s["DurationMin"] > 0]
    avg_dur = sum(durs) / len(durs) if durs else 0

    print()
    print("══════════════════════════════════════════════════════")
    print("  DEFENSEPRO ATTACK SESSION SUMMARY")
    print("══════════════════════════════════════════════════════")
    print(f"  Period      : {sessions[0]['SessionStart']} → {sessions[-1]['SessionStart']}")
    print(f"  Sessions    : {total}")
    print(f"  Raw events  : {start_cnt} start / {end_cnt} end")
    print(f"  Avg duration: {avg_dur:.0f} min")

    def _tbl(label, counter):
        print(f"\n── {label}")
        for name, cnt in sorted(counter.items(), key=lambda x: -x[1]):
            print(f"    {name:<38}  {cnt:>4}  ({cnt / total * 100:.1f}%)")

    by_sensor: dict = defaultdict(int)
    by_po:     dict = defaultdict(int)
    by_proto:  dict = defaultdict(int)
    for s in sessions:
        by_sensor[s["Sensor"]]       += 1
        by_po[s["ProtectedObject"]]  += 1
        by_proto[s["Protocol"]]      += 1

    _tbl("By Sensor",           by_sensor)
    _tbl("By Protected Object", by_po)
    _tbl("By Protocol",         by_proto)

    print(f"\n── Top 15 Most Targeted Networks")
    by_net: dict = defaultdict(list)
    for s in sessions:
        by_net[s["TargetNetwork"]].append(s)
    print(f"    {'Network':<22}  {'Sess':>5}  {'Sensors':<28}  {'Protocols':<18}  PeakBW")
    print(f"    {'-'*22}  {'-'*5}  {'-'*28}  {'-'*18}  {'-'*12}")
    for net, grp in sorted(by_net.items(), key=lambda x: -len(x[1]))[:15]:
        sensors   = ", ".join(sorted({s["Sensor"]   for s in grp}))
        protocols = ", ".join(sorted({s["Protocol"] for s in grp}))
        peak      = max(grp, key=lambda s: s["PeakBW_bps"])["PeakBW_human"]
        print(f"    {net:<22}  {len(grp):>5}  {sensors:<28}  {protocols:<18}  {peak}")

    def _row(s):
        return (
            f"    {s['Sensor']:<18}  {s['ProtectedObject']:<18}  {s['TargetNetwork']:<22}  "
            f"{s['Protocol']:<10}  {s['SessionStart']:<20}  {s['DurationMin']:>7} min  "
            f"{s['EventCount']:>6} evts  {s['PeakBW_human']}"
        )

    hdr = (
        f"    {'Sensor':<18}  {'ProtectedObject':<18}  {'TargetNetwork':<22}  "
        f"{'Protocol':<10}  {'SessionStart':<20}  {'DurMin':>7}  {'Evts':>8}  PeakBW"
    )
    sep = f"    {_separator('-', 130)}"

    print(f"\n── Top 10 Longest Sessions")
    print(hdr); print(sep)
    for s in sorted(sessions, key=lambda s: -s["DurationMin"])[:10]:
        print(_row(s))

    print(f"\n── Top 10 by Peak Bandwidth")
    print(hdr); print(sep)
    for s in sorted(sessions, key=lambda s: -s["PeakBW_bps"])[:10]:
        print(_row(s))

    print(f"\n── Sensor × Protected Object Matrix")
    by_pair: dict = defaultdict(int)
    for s in sessions:
        by_pair[f"{s['Sensor']} × {s['ProtectedObject']}"] += 1
    for pair, cnt in sorted(by_pair.items(), key=lambda x: -x[1]):
        print(f"    {pair:<55}  {cnt:>4}")


def run_defensepro(log_dir: Path, out_file: Path,
                   time_range: TimeRange, gap_minutes: int) -> None:
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          DefensePro Attack Session Parser      │")
    print("└" + _separator("─", 48) + "┘")
    print(f"  Log directory : {log_dir}")
    print(f"  Gap threshold : {gap_minutes} minutes")
    print(f"  Output file   : {out_file}")
    print(f"  Time filter   : {time_range.label() if time_range.active else 'none'}")
    print()

    out_file.parent.mkdir(parents=True, exist_ok=True)
    log_sources, zip_handles = _collect_log_sources(log_dir)
    if not log_sources:
        print(f"  ERROR: No logs/alert* files found in {log_dir}", file=sys.stderr)
        return

    print(f"  Found {len(log_sources)} log file(s): {', '.join(n for n, _ in log_sources)}")
    print("  Parsing DEFENSE_PRO events...")

    try:
        start_events, end_events = dp_parse_logs(log_sources)
    finally:
        for _zh in zip_handles:
            _zh.close()
    print(f"    Start events (DFC00701) : {len(start_events)}")
    print(f"    End events   (DFC00703) : {len(end_events)}")

    gap         = timedelta(minutes=gap_minutes)
    all_sessions = dp_build_sessions(start_events, gap)
    print(f"  Total sessions built      : {len(all_sessions)}")

    if time_range.active:
        sessions = [s for s in all_sessions if time_range.contains_dt(s["_start_dt"])]
        print(f"  Sessions within filter    : {len(sessions)}")
    else:
        sessions = all_sessions

    for s in sessions:
        s.pop("_start_dt", None)
    sessions.sort(key=lambda s: s["SessionStart"])

    fieldnames = [
        "Sensor", "ProtectedObject", "TargetNetwork", "Protocol",
        "SessionStart", "SessionEnd", "DurationMin", "EventCount",
        "PeakBW_human", "PeakBW_bps", "SourceLogFile",
    ]
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sessions)

    print(f"\n  CSV exported: {out_file}  ({len(sessions)} rows)")
    dp_print_summary(sessions, len(start_events), len(end_events))


# ══════════════════════════════════════════════════════════════════
#  Arbor log parser
# ══════════════════════════════════════════════════════════════════

def arbor_parse_logs(log_sources: list) -> dict:
    attacks: dict = {}
    pending_ends: dict = {}  # kid -> ts for end events seen before their start
    provisions: list = []    # DFC00712 entries: {ts_dt, policy_name, po_name, net}
    for name, opener in log_sources:
        with opener() as fh:
            for line in fh:
                if not any(c in line for c in ("DFC00701", "DFC00703", "DFC00360", "DFC00361", "DFC00712")):
                    continue
                m_ts = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                ts   = m_ts.group(1) if m_ts else ""

                # ── Attack start (Arbor / External Detector) ──────────────────
                if "DFC00701" in line:
                    if not re.search(r"EXTERNAL_DETECTOR|Arbor", line, re.IGNORECASE):
                        continue
                    m = re.search(
                        r"attack started on network (\S+) protocol (\S+)"
                        r" external ID (\d+).*bandwidth (\d+)\(bps\)", line)
                    if not m:
                        continue
                    net, proto, ext_id, bw = m.group(1), m.group(2), m.group(3), int(m.group(4))
                    m_po = re.search(r"Protected object (\S+): attack started", line)
                    po_name = m_po.group(1) if m_po else ""
                    kid = f"arbor_{ext_id}"
                    if kid not in attacks:
                        attacks[kid] = {
                            "id": kid, "start": ts,
                            "end": pending_ends.pop(kid, ""),
                            "net": net, "proto": proto,
                            "bw_bps": bw, "pps": 0,
                            "po_name": po_name,
                            "up": [], "down": [], "pending": [],
                            "source_file": name,
                        }
                    else:
                        a = attacks[kid]
                        if not a["start"]: a["start"] = ts
                        if bw > a["bw_bps"]: a["bw_bps"] = bw
                        if not a["po_name"] and po_name: a["po_name"] = po_name
                    continue

                # ── Attack end ────────────────────────────────────────────────
                if "DFC00703" in line:
                    m = re.search(r"external ID (\d+)", line, re.IGNORECASE)
                    if m:
                        kid = f"arbor_{m.group(1)}"
                        if kid in attacks:
                            if not attacks[kid]["end"]:
                                attacks[kid]["end"] = ts
                        elif kid not in pending_ends:
                            pending_ends[kid] = ts
                    continue

                # ── Mitigation UP ─────────────────────────────────────────────
                if "DFC00360" in line:
                    m_id  = re.search(r"[Ee]xternal [Aa]ttack [Ii]d (\d+)", line)
                    m_po  = re.search(r"for protected object (\S+)\.", line)
                    m_bw  = re.search(r"bandwidth (\d+) bps", line)
                    m_pps = re.search(r"rate (\d+) pps", line)
                    if m_id:
                        kid = f"arbor_{m_id.group(1)}"
                        if kid in attacks:
                            a = attacks[kid]
                            if m_pps:
                                pps = int(m_pps.group(1))
                                if pps > a["pps"]: a["pps"] = pps
                            if m_bw:
                                bw = int(m_bw.group(1))
                                if bw > a["bw_bps"]: a["bw_bps"] = bw
                            if m_po:
                                po = m_po.group(1)
                                if po not in a["up"]: a["up"].append(po)
                                # USER-CONF workflow = pending manual confirmation
                                if "USER-CONF" in line and po not in a["pending"]:
                                    a["pending"].append(po)
                    continue

                # ── Mitigation DOWN ───────────────────────────────────────────
                if "DFC00361" in line:
                    m_id = re.search(r"[Ee]xternal [Aa]ttack [Ii]d (\d+)", line)
                    m_po = re.search(r"for protected object (\S+)\.", line)
                    if m_id and m_po:
                        kid = f"arbor_{m_id.group(1)}"
                        if kid in attacks:
                            po = m_po.group(1)
                            if po not in attacks[kid]["down"]:
                                attacks[kid]["down"].append(po)

                # ── Policy provisioned ────────────────────────────────────────
                if "DFC00712" in line:
                    m = re.search(
                        r"Provisioned a security policy (\S+)"
                        r" for protected object (\S+)"
                        r" on mitigation device \S+ for networks (\S+)\.", line)
                    if m and ts:
                        try:
                            ts_dt = datetime.strptime(ts, TS_FMT)
                            provisions.append({
                                "ts_dt":       ts_dt,
                                "policy_name": m.group(1),
                                "po_name":     m.group(2),
                                "net":         m.group(3),
                            })
                        except ValueError:
                            pass

    # ── Match each attack to the nearest DFC00712 entry ──────────────────────
    for a in attacks.values():
        if not a["start"]:
            continue
        try:
            atk_dt = datetime.strptime(a["start"], TS_FMT)
        except ValueError:
            continue
        candidates = [
            p for p in provisions
            if p["po_name"] == a["po_name"] and p["net"] == a["net"]
        ]
        if candidates:
            # Prefer the entry closest in time (within 2 hours of attack start)
            best = min(candidates, key=lambda p: abs((p["ts_dt"] - atk_dt).total_seconds()))
            if abs((best["ts_dt"] - atk_dt).total_seconds()) <= 7200:
                a["policy_name"] = best["policy_name"]

    return attacks


def arbor_build_rows(attacks: dict, time_range: TimeRange) -> list:
    rows = []
    for kid in sorted(attacks):
        a = attacks[kid]
        if not time_range.contains_str(a["start"]):
            continue

        dur_min, status = "", "Open"
        if a["start"] and a["end"]:
            try:
                s = datetime.strptime(a["start"], TS_FMT)
                e = datetime.strptime(a["end"],   TS_FMT)
                dur_min = int((e - s).total_seconds() / 60)
                status  = "Completed"
            except ValueError:
                pass

        rows.append({
            "Arbor_ID":           kid,
            "Status":             status,
            "Protected_Object":   a.get("po_name", ""),
            "Policy_Name":        a.get("policy_name", ""),
            "Target_Network":     a["net"],
            "Protocol":           a["proto"],
            "Peak_Bandwidth":     human_bw(a["bw_bps"]) if a["bw_bps"] > 0 else "0 bps",
            "Peak_Bandwidth_bps": a["bw_bps"],
            "Peak_PPS":           human_pps(a["pps"]) if a["pps"] > 0 else "",
            "Peak_PPS_raw":       a["pps"],
            "Attack_Start":       a["start"],
            "Attack_End":         a["end"],
            "Duration_min":       dur_min,
            "Mitigation_UP":      " | ".join(
                f"{po} (Pending)" if po in a.get("pending", []) and po not in a["down"] else po
                for po in a["up"]
            ),
            "Mitigation_DOWN":    " | ".join(a["down"]),
            "Source_Log_File":    a["source_file"],
        })
    return rows


def arbor_print_summary(rows: list) -> None:
    if not rows:
        print("  No attacks matched.")
        return

    completed    = [r for r in rows if r["Status"] == "Completed"]
    open_attacks = [r for r in rows if r["Status"] == "Open"]
    durs         = [r["Duration_min"] for r in rows if isinstance(r["Duration_min"], int)]
    avg_dur      = sum(durs) / len(durs) if durs else 0

    print()
    print("══════════════════════════════════════════════════════")
    print("  ARBOR ATTACK CYCLE SUMMARY")
    print("══════════════════════════════════════════════════════")
    print(f"  Total attacks   : {len(rows)}")
    print(f"  Completed cycles: {len(completed)}")
    print(f"  Open (no end)   : {len(open_attacks)}")
    print(f"  Avg duration    : {avg_dur:.0f} min")

    top5 = sorted(rows, key=lambda r: -(r["Peak_Bandwidth_bps"] or 0))[:5]
    print(f"\n── Top 5 by Bandwidth")
    print(
        f"    {'Arbor_ID':<20}  {'Target_Network':<22}  "
        f"{'Peak_Bandwidth':<15}  {'Attack_Start':<20}  Duration_min"
    )
    print(f"    {_separator('-', 100)}")
    for r in top5:
        print(
            f"    {r['Arbor_ID']:<20}  {r['Target_Network']:<22}  "
            f"{r['Peak_Bandwidth']:<15}  {r['Attack_Start']:<20}  {r['Duration_min']}"
        )


def run_arbor(log_dir: Path, out_file: Path, time_range: TimeRange) -> None:
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          Arbor Attack Cycle Parser            │")
    print("└" + _separator("─", 48) + "┘")
    print(f"  Log directory : {log_dir}")
    print(f"  Output file   : {out_file}")
    print(f"  Time filter   : {time_range.label() if time_range.active else 'none'}")
    print()

    out_file.parent.mkdir(parents=True, exist_ok=True)
    log_sources, zip_handles = _collect_log_sources(log_dir)
    if not log_sources:
        print(f"  ERROR: No logs/alert* files found in {log_dir}", file=sys.stderr)
        return

    print(f"  Found {len(log_sources)} log file(s): {', '.join(n for n, _ in log_sources)}")
    print("  Parsing Arbor events...")

    try:
        attacks = arbor_parse_logs(log_sources)
    finally:
        for _zh in zip_handles:
            _zh.close()
    print(f"  Unique Arbor attack IDs  : {len(attacks)}")

    rows = arbor_build_rows(attacks, time_range)
    if time_range.active:
        print(f"  Attacks within filter     : {len(rows)}")

    fieldnames = [
        "Arbor_ID", "Status", "Protected_Object", "Policy_Name", "Target_Network", "Protocol",
        "Peak_Bandwidth", "Peak_Bandwidth_bps", "Peak_PPS", "Peak_PPS_raw",
        "Attack_Start", "Attack_End", "Duration_min",
        "Mitigation_UP", "Mitigation_DOWN", "Source_Log_File",
    ]
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n  CSV exported: {out_file}  ({len(rows)} rows)")
    arbor_print_summary(rows)


# ══════════════════════════════════════════════════════════════════
#  Weekly HTML report  (reads arbor_attack_cycles_*.csv)
# ══════════════════════════════════════════════════════════════════

def _bw_for_chart(bps: int) -> float:
    return round(bps / 1_000_000_000, 3)


def _month_week_num(dt: datetime) -> int:
    return (dt.day - 1) // 7 + 1


def _month_week_sort_key(dt: datetime) -> str:
    return f"{dt.year:04d}-{dt.month:02d}-W{_month_week_num(dt)}"


def _month_week_label(dt: datetime) -> str:
    wn        = _month_week_num(dt)
    start_day = (wn - 1) * 7 + 1
    last_day  = calendar.monthrange(dt.year, dt.month)[1]
    end_day   = min(start_day + 6, last_day)
    s = dt.replace(day=start_day)
    e = dt.replace(day=end_day)
    return f"{s.strftime('%b')} Wk{wn}  {s.strftime('%b %d')}–{e.strftime('%b %d')}"


def weekly_find_csvs(csv_dir: Path) -> list:
    files = sorted(csv_dir.glob("arbor_attack_cycles_*.csv"), reverse=True)
    if not files:
        print(f"  WARNING: No arbor_attack_cycles_*.csv found in {csv_dir}", file=sys.stderr)
    return files


def weekly_load_attacks(csv_files: list,
                        start: "datetime | None",
                        end:   "datetime | None") -> list:
    seen, attacks, skip_range, skip_dup = set(), [], 0, 0
    for f in csv_files:
        with open(f, encoding="utf-8", newline="", errors="replace") as fh:
            for row in csv.DictReader(fh):
                kid = row.get("Arbor_ID", "").strip()
                s   = row.get("Attack_Start", "").strip()
                dt  = _parse_dt(s) if s else None

                if dt:
                    if start and dt < start:
                        skip_range += 1; continue
                    if end and dt > end:
                        skip_range += 1; continue

                if kid:
                    if kid in seen:
                        skip_dup += 1; continue
                    seen.add(kid)

                row["_dt"] = dt
                attacks.append(row)

    print(f"  Loaded  : {len(attacks):,} unique attacks")
    if skip_range: print(f"  Filtered: {skip_range:,} outside date range")
    if skip_dup:   print(f"  Deduped : {skip_dup:,} duplicates removed")
    return attacks


def weekly_group_by_week(attacks: list) -> dict:
    buckets: dict = {}
    for row in attacks:
        dt = row.get("_dt")
        if dt is None:
            continue
        key   = _month_week_sort_key(dt)
        label = _month_week_label(dt)
        if key not in buckets:
            buckets[key] = {"label": label, "rows": []}
        buckets[key]["rows"].append(row)
    return dict(sorted(buckets.items()))


def weekly_compute_stats(rows: list) -> dict:
    count = len(rows)
    max_bw_bps, max_pps, top_dur_min = 0, 0, 0
    top_dur_ip, top_dur_start = "N/A", ""
    dst_counts: dict = defaultdict(int)

    for r in rows:
        bps = int(r.get("Peak_Bandwidth_bps") or 0)
        pps = int(r.get("Peak_PPS_raw")       or 0)
        dur = int(r.get("Duration_min")        or 0)
        ip  = (r.get("Target_Network") or "").split("/")[0].strip() or "N/A"

        if bps > max_bw_bps: max_bw_bps = bps
        if pps > max_pps:    max_pps    = pps
        if dur > top_dur_min:
            top_dur_min   = dur
            top_dur_ip    = ip
            top_dur_start = r.get("Attack_Start", "")
        dst_counts[ip] += 1

    top_dst_ip, top_dst_cnt = (
        max(dst_counts.items(), key=lambda x: x[1]) if dst_counts else ("N/A", 0)
    )
    return {
        "count":         count,
        "max_bw_bps":    max_bw_bps,
        "max_bw_human":  human_bw(max_bw_bps),
        "max_pps":       max_pps,
        "max_pps_human": human_pps(max_pps),
        "top_dst_ip":    top_dst_ip,
        "top_dst_count": top_dst_cnt,
        "top_dur_ip":    top_dur_ip,
        "top_dur_min":   top_dur_min,
        "top_dur_human": format_duration(top_dur_min),
        "top_dur_start": top_dur_start,
    }


def weekly_generate_html(weeks: dict, start_dt, end_dt, csv_files: list) -> str:
    now_str     = datetime.now().strftime(TS_FMT)
    start_label = start_dt.strftime("%Y-%m-%d") if start_dt else "All time"
    end_label   = end_dt.strftime("%Y-%m-%d")   if end_dt   else "All time"
    range_label = f"{start_label}  →  {end_label}"

    all_rows      = [r for w in weeks.values() for r in w["rows"]]
    total_attacks = len(all_rows)
    total_weeks   = len(weeks)

    global_max_bw  = max((int(r.get("Peak_Bandwidth_bps") or 0) for r in all_rows), default=0)
    global_max_pps = max((int(r.get("Peak_PPS_raw")       or 0) for r in all_rows), default=0)

    global_dst: dict = defaultdict(int)
    for r in all_rows:
        ip = (r.get("Target_Network") or "").split("/")[0].strip()
        if ip:
            global_dst[ip] += 1
    global_top_dst, global_top_dst_cnt = (
        max(global_dst.items(), key=lambda x: x[1]) if global_dst else ("N/A", 0)
    )

    week_stats = {k: weekly_compute_stats(w["rows"]) for k, w in weeks.items()}

    # Find the single attack with peak bandwidth and peak PPS for click-through detail
    peak_bw_row  = max(all_rows, key=lambda r: int(r.get("Peak_Bandwidth_bps") or 0), default={})
    peak_pps_row = max(all_rows, key=lambda r: int(r.get("Peak_PPS_raw")       or 0), default={})

    def _attack_detail_json(r: dict) -> str:
        dur = r.get("Duration_min", "")
        dur_human = format_duration(int(dur)) if str(dur).lstrip("-").isdigit() and int(dur) > 0 else "N/A"
        fields = [
            ("Arbor ID",       r.get("Arbor_ID",       "—")),
            ("Status",          r.get("Status",          "—")),
            ("Target Network",  r.get("Target_Network",  "—")),
            ("Protocol",        r.get("Protocol",        "—")),
            ("Peak Bandwidth",  r.get("Peak_Bandwidth",  "—")),
            ("Peak PPS",        r.get("Peak_PPS",        "") or "N/A"),
            ("Attack Start",    r.get("Attack_Start",    "—")),
            ("Attack End",      r.get("Attack_End",      "") or "Open"),
            ("Duration",        dur_human),
            ("Policy Name",     r.get("Policy_Name", "") or "—"),
        ]
        return json.dumps(dict(fields))

    peak_bw_detail_json  = _attack_detail_json(peak_bw_row)
    peak_pps_detail_json = _attack_detail_json(peak_pps_row)

    chart_labels     = json.dumps([w["label"] for w in weeks.values()])
    chart_counts     = json.dumps([week_stats[k]["count"] for k in weeks])
    chart_bw_gbps    = json.dumps([_bw_for_chart(week_stats[k]["max_bw_bps"]) for k in weeks])
    chart_pps_k      = json.dumps([round(week_stats[k]["max_pps"] / 1000, 1) for k in weeks])
    chart_dst_counts = json.dumps([week_stats[k]["top_dst_count"] for k in weeks])
    chart_dst_ips    = json.dumps([week_stats[k]["top_dst_ip"] for k in weeks])

    table_rows_html = ""
    for i, (key, w) in enumerate(weeks.items()):
        s = week_stats[key]
        row_class = "even" if i % 2 == 0 else "odd"
        table_rows_html += f"""
            <tr class="{row_class}">
                <td class="week-col"><strong>{w["label"]}</strong></td>
                <td class="num-col">{s["count"]:,}</td>
                <td>{s["max_bw_human"]}</td>
                <td>{s["max_pps_human"]}</td>
                <td class="ip-col">{s["top_dst_ip"]}<span class="badge">{s["top_dst_count"]}x</span></td>
                <td class="ip-col">{s["top_dur_ip"]}<br><span class="sub">{s["top_dur_human"]}
                    {(" · " + s["top_dur_start"]) if s["top_dur_start"] else ""}</span></td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Radware Weekly Attack Trends Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5; color: #2c3e50; line-height: 1.6;
        }}
        .container {{
            max-width: 1300px; margin: 0 auto; background: #fff;
            box-shadow: 0 4px 24px rgba(0,0,0,.12); border-radius: 10px; overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #003f7f 0%, #005bb5 60%, #0073e6 100%);
            color: #fff; padding: 36px 40px 28px;
        }}
        .header h1 {{ font-size: 26px; font-weight: 700; letter-spacing: .5px; }}
        .header .subtitle {{ margin-top: 6px; font-size: 14px; opacity: .85; }}
        .header .meta {{ margin-top: 14px; font-size: 12px; opacity: .7; display: flex; gap: 30px; flex-wrap: wrap; }}
        .header .meta span {{ display: flex; align-items: center; gap: 6px; }}
        .content {{ padding: 32px 40px; }}
        .section {{ margin-bottom: 40px; }}
        .section-title {{
            font-size: 17px; font-weight: 700; color: #003f7f;
            border-left: 4px solid #0073e6; padding-left: 12px; margin-bottom: 18px;
        }}
        .stats-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px; margin-bottom: 8px;
        }}
        .stat-card {{
            background: #f7f9fc; border: 1px solid #dde3ef; border-radius: 8px;
            padding: 20px 18px; text-align: center; transition: box-shadow .2s;
        }}
        .stat-card:hover {{ box-shadow: 0 4px 14px rgba(0,63,127,.12); }}
        .stat-value {{ font-size: 26px; font-weight: 800; color: #003f7f; line-height: 1.1; }}
        .stat-value.large-text  {{ font-size: 18px; }}
        .stat-value.xlarge-text {{ font-size: 14px; word-break: break-all; }}
        .stat-label {{ font-size: 12px; color: #6c757d; margin-top: 6px; text-transform: uppercase; letter-spacing: .6px; }}
        .stat-sub   {{ font-size: 11px; color: #999; margin-top: 3px; }}
        .chart-row {{
            display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 8px;
        }}
        @media (max-width: 860px) {{ .chart-row {{ grid-template-columns: 1fr; }} }}
        .chart-box {{
            background: #f7f9fc; border: 1px solid #dde3ef; border-radius: 8px; padding: 20px;
        }}
        .chart-title {{ font-size: 13px; font-weight: 600; color: #003f7f; margin-bottom: 14px; text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        thead tr {{ background: #003f7f; color: #fff; }}
        thead th {{ padding: 11px 14px; text-align: left; font-weight: 600; white-space: nowrap; }}
        tbody tr.even {{ background: #f7f9fc; }}
        tbody tr.odd  {{ background: #fff; }}
        tbody tr:hover {{ background: #e8f0fa; }}
        tbody td {{ padding: 10px 14px; border-bottom: 1px solid #e9ecef; vertical-align: top; }}
        .week-col  {{ font-size: 12px; white-space: nowrap; }}
        .num-col   {{ text-align: right; font-weight: 700; color: #003f7f; }}
        .ip-col    {{ font-family: 'Consolas', monospace; font-size: 12px; }}
        .badge {{
            display: inline-block; background: #0073e6; color: #fff;
            border-radius: 10px; padding: 1px 7px; font-size: 11px;
            margin-left: 6px; font-family: 'Segoe UI', sans-serif;
        }}
        .sub {{ font-size: 11px; color: #888; }}
        .clickable {{
            cursor: pointer; border: 1px solid #b0c8ef !important;
            transition: box-shadow .2s, transform .15s;
        }}
        .clickable:hover {{ box-shadow: 0 6px 20px rgba(0,63,127,.20) !important; transform: translateY(-2px); }}
        /* Modal */
        .modal-backdrop {{
            display: none; position: fixed; inset: 0;
            background: rgba(0,0,0,.45); z-index: 1000;
            align-items: center; justify-content: center;
        }}
        .modal-backdrop.open {{ display: flex; }}
        .modal {{
            background: #fff; border-radius: 10px; width: 480px; max-width: 95vw;
            box-shadow: 0 16px 48px rgba(0,0,0,.28); overflow: hidden;
        }}
        .modal-header {{
            background: linear-gradient(135deg, #003f7f, #0073e6);
            color: #fff; padding: 16px 20px; display: flex; align-items: center; justify-content: space-between;
        }}
        .modal-header h3 {{ font-size: 15px; font-weight: 700; }}
        .modal-close {{
            background: none; border: none; color: #fff; font-size: 22px;
            cursor: pointer; line-height: 1; padding: 0 4px;
        }}
        .modal-body {{ padding: 20px 24px; }}
        .detail-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .detail-table td {{ padding: 7px 10px; border-bottom: 1px solid #eee; }}
        .detail-table td:first-child {{ color: #555; font-weight: 600; width: 42%; white-space: nowrap; }}
        .detail-table td:last-child  {{ font-family: Consolas, monospace; color: #003f7f; }}
        .footer {{
            background: #f0f2f5; border-top: 1px solid #dde3ef;
            padding: 16px 40px; font-size: 11px; color: #888;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Radware Weekly Attack Trends Report</h1>
        <div class="subtitle">DDoS Detection &amp; Mitigation — Weekly Summary</div>
        <div class="meta">
            <span>&#128197; Period: <strong>{range_label}</strong></span>
            <span>&#128344; Generated: {now_str}</span>
        </div>
    </div>

    <div class="content">
        <div class="section">
            <div class="section-title">Overview</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_attacks:,}</div>
                    <div class="stat-label">Total Attacks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_weeks}</div>
                    <div class="stat-label">Weeks Covered</div>
                </div>
                <div class="stat-card clickable" onclick="showAttackDetail('bw')" title="Click for attack details">
                    <div class="stat-value{'  large-text' if len(human_bw(global_max_bw)) > 10 else ''}">{human_bw(global_max_bw)}</div>
                    <div class="stat-label">Peak Bandwidth (single attack)</div>
                    <div class="stat-sub">&#128269; click for details</div>
                </div>
                <div class="stat-card clickable" onclick="showAttackDetail('pps')" title="Click for attack details">
                    <div class="stat-value{'  large-text' if len(human_pps(global_max_pps)) > 10 else ''}">{human_pps(global_max_pps)}</div>
                    <div class="stat-label">Peak PPS (single attack)</div>
                    <div class="stat-sub">&#128269; click for details</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value xlarge-text">{global_top_dst}</div>
                    <div class="stat-label">Most Targeted DST IP</div>
                    <div class="stat-sub">{global_top_dst_cnt:,} attacks</div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Weekly Trends</div>
            <div class="chart-row">
                <div class="chart-box">
                    <div class="chart-title">&#128200; Attack Count per Week</div>
                    <canvas id="chartCount"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">&#9889; Max Peak Bandwidth per Week (Gbps)</div>
                    <canvas id="chartBW"></canvas>
                </div>
            </div>
            <div class="chart-row" style="margin-top:24px">
                <div class="chart-box">
                    <div class="chart-title">&#128246; Max Peak PPS per Week (K pps)</div>
                    <canvas id="chartPPS"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">&#127919; Top DST IP Hit Count per Week</div>
                    <canvas id="chartDST"></canvas>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Weekly Detail</div>
            <div style="overflow-x:auto">
                <table>
                    <thead>
                        <tr>
                            <th>Week</th>
                            <th style="text-align:right">Attacks</th>
                            <th>Max Peak BW</th>
                            <th>Max Peak PPS</th>
                            <th>Top DST IP (count)</th>
                            <th>Longest Attack</th>
                        </tr>
                    </thead>
                    <tbody>{table_rows_html}</tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="footer">
        <span>Radware Weekly Attack Trends Report &mdash; {now_str}</span>
    </div>
</div>

<!-- Attack detail modal -->
<div class="modal-backdrop" id="modalBackdrop" onclick="hideModal(event)">
    <div class="modal">
        <div class="modal-header">
            <h3 id="modalTitle">Attack Detail</h3>
            <button class="modal-close" onclick="closeModal()">&#x2715;</button>
        </div>
        <div class="modal-body">
            <table class="detail-table" id="modalTable"></table>
        </div>
    </div>
</div>

<script>
const LABELS    = {chart_labels};
const COUNTS    = {chart_counts};
const BW_GBPS   = {chart_bw_gbps};
const PPS_K     = {chart_pps_k};
const DST_CNT   = {chart_dst_counts};
const DST_IPS   = {chart_dst_ips};
const PEAK_BW_DETAIL  = {peak_bw_detail_json};
const PEAK_PPS_DETAIL = {peak_pps_detail_json};

function showAttackDetail(type) {{
    const detail = type === 'bw' ? PEAK_BW_DETAIL : PEAK_PPS_DETAIL;
    const title  = type === 'bw' ? '\u26a1 Peak Bandwidth Attack Detail' : '\\u{{1F4E2}} Peak PPS Attack Detail';
    document.getElementById('modalTitle').textContent = title;
    const tbl = document.getElementById('modalTable');
    tbl.innerHTML = Object.entries(detail)
        .map(([k, v]) => `<tr><td>${{k}}</td><td>${{v || '\u2014'}}</td></tr>`)
        .join('');
    document.getElementById('modalBackdrop').classList.add('open');
}}
function closeModal() {{
    document.getElementById('modalBackdrop').classList.remove('open');
}}
function hideModal(e) {{
    if (e.target === document.getElementById('modalBackdrop')) closeModal();
}}
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModal(); }});

const BLUE_PALETTE = [
    'rgba(0,  63,127,0.78)','rgba(0,115,230,0.78)',
    'rgba(0,163,224,0.78)','rgba(0,191,255,0.78)',
    'rgba(0,214,198,0.78)','rgba(0,230,160,0.78)',
];
function barColor(n) {{
    return Array.from({{length: n}}, (_,i) => BLUE_PALETTE[i % BLUE_PALETTE.length]);
}}
const commonOpts = {{
    responsive: true,
    plugins: {{ legend: {{ display: false }}, tooltip: {{ mode:'index', intersect:false }} }},
    scales: {{
        x: {{ ticks: {{ font: {{ size:11 }}, maxRotation:35 }}, grid: {{ color:'rgba(0,0,0,.05)' }} }},
        y: {{ beginAtZero:true, ticks: {{ font: {{ size:11 }} }}, grid: {{ color:'rgba(0,0,0,.05)' }} }},
    }},
}};

new Chart(document.getElementById('chartCount'), {{
    type:'bar', data:{{ labels:LABELS, datasets:[{{ label:'Attacks', data:COUNTS, backgroundColor:barColor(LABELS.length), borderRadius:5 }}] }},
    options: commonOpts,
}});
new Chart(document.getElementById('chartBW'), {{
    type:'bar', data:{{ labels:LABELS, datasets:[{{ label:'Gbps', data:BW_GBPS, backgroundColor:barColor(LABELS.length), borderRadius:5 }}] }},
    options: {{ ...commonOpts, scales: {{ ...commonOpts.scales, y: {{ ...commonOpts.scales.y, ticks: {{ ...commonOpts.scales.y.ticks, callback: v => v.toFixed(1)+' G' }} }} }} }},
}});
new Chart(document.getElementById('chartPPS'), {{
    type:'bar', data:{{ labels:LABELS, datasets:[{{ label:'K pps', data:PPS_K, backgroundColor:barColor(LABELS.length), borderRadius:5 }}] }},
    options: {{ ...commonOpts, scales: {{ ...commonOpts.scales, y: {{ ...commonOpts.scales.y, ticks: {{ ...commonOpts.scales.y.ticks, callback: v => v.toFixed(0)+' K' }} }} }} }},
}});
new Chart(document.getElementById('chartDST'), {{
    type:'bar',
    data:{{ labels:DST_IPS, datasets:[{{ label:'Attacks on top DST IP', data:DST_CNT, backgroundColor:barColor(LABELS.length), borderRadius:5 }}] }},
    options: {{
        ...commonOpts,
        plugins: {{ ...commonOpts.plugins, tooltip: {{ callbacks: {{
            title: (items) => DST_IPS[items[0].dataIndex],
            beforeLabel: (ctx) => 'Week: ' + LABELS[ctx.dataIndex],
            label: (ctx) => 'Hit count: ' + ctx.parsed.y,
        }} }} }},
        scales: {{ ...commonOpts.scales,
            x: {{ ...commonOpts.scales.x, ticks: {{ font:{{ size:11 }}, maxRotation:35 }} }},
            y: {{ ...commonOpts.scales.y, ticks: {{ ...commonOpts.scales.y.ticks, callback: v => Number.isInteger(v) ? v : '' }} }},
        }},
    }},
}});
</script>
</body>
</html>
"""
    return html


def run_weekly_report(time_range: TimeRange,
                      csv_dir: Path,
                      out_path: "Path | None" = None) -> None:
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          Weekly HTML Trend Report              │")
    print("└" + _separator("─", 48) + "┘")

    start_dt, end_dt = time_range.as_tuple()
    print(f"  CSV directory : {csv_dir}")
    print(f"  Time filter   : {time_range.label() if time_range.active else 'none (all records)'}")
    print()

    csv_files = weekly_find_csvs(csv_dir)
    if not csv_files:
        print("  ERROR: No source CSV files found. Run the Arbor parser first.")
        return

    print(f"  Found {len(csv_files)} CSV file(s)")

    attacks = weekly_load_attacks(csv_files, start_dt, end_dt)
    if not attacks:
        print("  ERROR: No attacks matched the specified date range.")
        return

    weeks = weekly_group_by_week(attacks)
    print(f"  Weeks   : {len(weeks)}")

    if out_path is None:
        ts       = datetime.now().strftime(DATETIME_FMT)
        out_path = REPORTS_DIR / f"radware_weekly_report_{ts}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    html = weekly_generate_html(weeks, start_dt, end_dt, csv_files)
    out_path.write_text(html, encoding="utf-8")
    print(f"\n  Report  : {out_path}")


# ══════════════════════════════════════════════════════════════════
#  Main menu
# ══════════════════════════════════════════════════════════════════

def main_menu() -> str:
    """Present the report selection menu.  Returns one of: dp, arbor, both, weekly."""
    print()
    print("╔" + _separator("═", 52) + "╗")
    print("║       Radware Report Tool                        ║")
    print("╚" + _separator("═", 52) + "╝")
    print()
    print("  Select report type:")
    print("    [1] DefensePro   — parse logs → attack session CSV")
    print("    [2] Arbor       — parse logs → attack cycle CSV")
    print("    [3] Both         — run DefensePro + Arbor parsers")
    print("    [4] Weekly HTML  — attack cycle trends (HTML report)")
    print("    [Q] Quit")
    print()

    while True:
        choice = input("  Selection [1/2/3/4/Q]: ").strip().upper()
        if choice in ("1", "2", "3", "4", "Q"):
            break

    if choice == "Q":
        print("  Bye.")
        sys.exit(0)

    return {"1": "dp", "2": "arbor", "3": "both", "4": "weekly"}[choice]


# ══════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Unified Radware Report Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python radware_reports.py\n"
            "  python radware_reports.py --report weekly --start 2026-03-01 --end 2026-03-30\n"
            "  python radware_reports.py --report dp --interactive\n"
            "  python radware_reports.py --report both --config alert_parser.ini\n"
        ),
    )
    p.add_argument("--report", choices=["dp", "arbor", "both", "weekly"],
                   help="Report to run (skips interactive menu).")
    p.add_argument("--interactive", "-i", action="store_true",
                   help="Prompt for time-range filter interactively.")
    p.add_argument("--config", "-c", nargs="?", const=str(DEFAULT_CFG), metavar="FILE",
                   help=f"INI config file (default: {DEFAULT_CFG.name}).")
    p.add_argument("--start", help="Start date (weekly report)  YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    p.add_argument("--end",   help="End date   (weekly report)  YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    p.add_argument("--log-dir",     default="", help="Override log directory (parsers).")
    p.add_argument("--csv-dir",     default="", help="Override CSV directory (weekly report).")
    p.add_argument("--out",         default="", help="Override output file path.")
    p.add_argument("--gap-minutes", type=int, default=0,
                   help="DefensePro session gap in minutes (overrides config, default 10).")
    return p.parse_args()


# ══════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════

def main():
    args    = parse_args()
    now     = datetime.now()
    today   = now.strftime(DATE_FMT)
    now_str = now.strftime(DATETIME_FMT)

    if args.interactive and args.config:
        print("ERROR: --interactive and --config are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────
    cfg = configparser.ConfigParser()
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        cfg.read(config_path, encoding="utf-8")
    elif DEFAULT_CFG.exists():
        cfg.read(DEFAULT_CFG, encoding="utf-8")

    # ── Menu ──────────────────────────────────────────────────────
    report_choice = args.report or main_menu()

    # ── Resolve time range ────────────────────────────────────────
    # CLI --start/--end take priority, then --interactive, then config
    if args.start or args.end:
        start_dt = _parse_dt(args.start) if args.start else None
        end_dt   = None
        if args.end:
            end_dt = _parse_dt(args.end)
            if end_dt and len(args.end.strip()) == 10:
                end_dt = end_dt.replace(hour=23, minute=59, second=59)
        time_range = TimeRange(start_dt, end_dt)
    elif args.interactive:
        time_range = interactive_range()
    elif cfg.sections():
        time_range = range_from_config(cfg)
    else:
        time_range = TimeRange(None, None)

    # ── Resolve paths helper ──────────────────────────────────────
    def _resolve(cli_val: str, cfg_section: str, cfg_key: str, default: str) -> Path:
        raw = cli_val or _cfg_str(cfg, cfg_section, cfg_key) or default
        return (SCRIPT_DIR / raw).resolve()

    # ══════════════════════════════════════════════════════════════
    #  Weekly HTML report
    # ══════════════════════════════════════════════════════════════
    if report_choice == "weekly":
        csv_dir  = Path(args.csv_dir).resolve() if args.csv_dir else REPORTS_DIR
        out_path = Path(args.out).resolve() if args.out else None
        run_weekly_report(time_range, csv_dir, out_path)

    # ══════════════════════════════════════════════════════════════
    #  Parser reports (DefensePro / Arbor / Both)
    # ══════════════════════════════════════════════════════════════
    else:
        do_dp     = report_choice in ("dp",     "both")
        do_arbor = report_choice in ("arbor", "both")

        if do_dp:
            dp_log_dir  = _resolve(args.log_dir, "defensepro", "log_dir", "Input")
            dp_out_str  = (
                args.out if (do_dp and not do_arbor and args.out)
                else _cfg_str(cfg, "defensepro", "out_file")
                or f"Reports/defensepro_attack_sessions_{now_str}.csv"
            )
            dp_out_file = (SCRIPT_DIR / dp_out_str
                           .replace("{datetime}", now_str)
                           .replace("{date}", today)).resolve()
            dp_gap      = args.gap_minutes or _cfg_int(cfg, "defensepro", "gap_minutes", 10)

        if do_arbor:
            k_log_dir  = _resolve(args.log_dir, "arbor", "log_dir", "Input")
            k_out_str  = (
                args.out if (do_arbor and not do_dp and args.out)
                else _cfg_str(cfg, "arbor", "out_file")
                or f"Reports/arbor_attack_cycles_{now_str}.csv"
            )
            k_out_file = (SCRIPT_DIR / k_out_str
                          .replace("{datetime}", now_str)
                          .replace("{date}", today)).resolve()

        if do_dp:
            run_defensepro(dp_log_dir, dp_out_file, time_range, dp_gap)
        if do_arbor:
            run_arbor(k_log_dir, k_out_file, time_range)

    print()
    print("═" * 54)
    print("  All done.")
    print("═" * 54)


if __name__ == "__main__":
    main()
