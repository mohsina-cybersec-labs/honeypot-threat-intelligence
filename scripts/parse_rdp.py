#!/usr/bin/env python3
"""
parse_rdp.py  -  T-Pot RDPHoneypot log parser

Reads every rdphoneypot.json* file (plain + .gz, daily + rotated) from a
T-Pot export, deduplicates on (session, eventid, timestamp), and writes
tidy CSVs for downstream analysis and charting.

Usage:
    python3 parse_rdp.py <log_dir> <out_dir>
"""

import sys, os, json, gzip, glob, collections
import pandas as pd

LOG_DIR = sys.argv[1] if len(sys.argv) > 1 else "data/rdphoneypot/log"
OUT_DIR = sys.argv[2] if len(sys.argv) > 2 else "parsed"
os.makedirs(OUT_DIR, exist_ok=True)


def open_any(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def load(log_dir):
    files = sorted(glob.glob(os.path.join(log_dir, "rdphoneypot.json*")))
    seen = set()
    rows = []
    stats = collections.Counter()
    for path in files:
        n = 0
        with open_any(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed"] += 1
                    continue
                key = (rec.get("session"), rec.get("eventid"), rec.get("timestamp"))
                if key in seen:
                    stats["duplicate"] += 1
                    continue
                seen.add(key)
                rows.append(rec)
                n += 1
        stats["files"] += 1
        print(f"  {os.path.basename(path):42s} {n:>8,} new")
    return rows, stats


print(f"Reading {LOG_DIR} ...")
rows, stats = load(LOG_DIR)
print(f"\nfiles={stats['files']}  unique={len(rows):,}  "
      f"dupes={stats['duplicate']:,}  malformed={stats['malformed']:,}")

df = pd.DataFrame(rows)
df["timestamp"] = pd.to_datetime(
    df["timestamp"].str.replace("Z$", "", regex=True), format="mixed", utc=True
)
df = df.sort_values("timestamp")
df["date"] = df["timestamp"].dt.date
df["hour"] = df["timestamp"].dt.floor("h")

# ---------- outputs ----------
df.groupby(["date", "eventid"]).size().unstack(fill_value=0) \
  .to_csv(f"{OUT_DIR}/rdp_daily_events.csv")

df.groupby(["hour", "eventid"]).size().unstack(fill_value=0) \
  .to_csv(f"{OUT_DIR}/rdp_hourly_events.csv")

df.groupby("src_ip").agg(
    events=("eventid", "size"),
    sessions=("session", "nunique"),
    first_seen=("timestamp", "min"),
    last_seen=("timestamp", "max"),
).sort_values("events", ascending=False).to_csv(f"{OUT_DIR}/rdp_source_ips.csv")

logins = df[df["eventid"] == "rdphoneypot.login"].copy()
if not logins.empty:
    logins.groupby("username").agg(
        attempts=("eventid", "size"),
        unique_src=("src_ip", "nunique"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).sort_values("attempts", ascending=False).to_csv(f"{OUT_DIR}/rdp_usernames.csv")

    logins.groupby(["date", "username"]).size().unstack(fill_value=0) \
        .to_csv(f"{OUT_DIR}/rdp_username_by_day.csv")

    logins[["timestamp", "src_ip", "src_port", "username", "domain",
            "auth_method", "session"]].to_csv(
        f"{OUT_DIR}/rdp_login_attempts.csv", index=False)

# session durations
closed = df[df["eventid"] == "rdphoneypot.session.closed"]
if "duration" in closed.columns:
    closed[["timestamp", "src_ip", "session", "duration"]].to_csv(
        f"{OUT_DIR}/rdp_sessions_closed.csv", index=False)

print(f"\nWindow: {df['timestamp'].min()}  ->  {df['timestamp'].max()}")
print(f"Total events      : {len(df):,}")
print(f"Unique source IPs : {df['src_ip'].nunique():,}")
print(f"Unique sessions   : {df['session'].nunique():,}")
print(f"Login attempts    : {len(logins):,}")
print(f"\nCSVs written to {OUT_DIR}/")
