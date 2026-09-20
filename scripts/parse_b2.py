#!/usr/bin/env python3
"""
parse_b2.py - Sentrypeer (SIP) + Suricata alert parser.

Usage: python3 parse_b2.py <raw_root> <alerts_dir> <out_dir>
"""
import sys, os, json, gzip, glob, collections
import pandas as pd

ROOT = sys.argv[1] if len(sys.argv) > 1 else "b2"
ALERTS = sys.argv[2] if len(sys.argv) > 2 else "b2/suricata-alerts"
OUT = sys.argv[3] if len(sys.argv) > 3 else "parsed3"
os.makedirs(OUT, exist_ok=True)


def open_any(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") \
        else open(p, "r", errors="replace")


def load_ndjson(pattern, key_fn, label):
    files = sorted(glob.glob(pattern))
    seen, rows, bad = set(), [], 0
    for p in files:
        with open_any(p) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                k = key_fn(r)
                if k in seen:
                    continue
                seen.add(k)
                rows.append(r)
    print(f"{label}: {len(files)} files, {len(rows):,} unique, {bad} malformed")
    return rows


# ========================= SENTRYPEER =========================
sp = load_ndjson(f"{ROOT}/*/data/sentrypeer/log/sentrypeer.json*",
                 lambda r: r.get("event_uuid"), "sentrypeer")

if sp:
    s = pd.DataFrame(sp)
    s["timestamp"] = pd.to_datetime(s["event_timestamp"], format="mixed",
                                    errors="coerce", utc=True)
    s = s.dropna(subset=["timestamp"]).sort_values("timestamp")
    s["date"] = s["timestamp"].dt.date
    s["hour"] = s["timestamp"].dt.floor("h")
    # source_ip carries "ip:port"
    s["src_ip"] = s["source_ip"].astype(str).str.rsplit(":", n=1).str[0]

    s.groupby("date").size().to_frame("events").to_csv(f"{OUT}/sip_daily_events.csv")
    s.groupby("hour").size().to_frame("events").to_csv(f"{OUT}/sip_hourly_events.csv")

    s.groupby("src_ip").agg(
        events=("event_uuid", "size"),
        distinct_numbers=("called_number", "nunique"),
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
    ).sort_values("events", ascending=False).to_csv(f"{OUT}/sip_source_ips.csv")

    s.groupby("called_number").agg(
        attempts=("event_uuid", "size"), unique_src=("src_ip", "nunique"),
    ).sort_values("attempts", ascending=False).to_csv(f"{OUT}/sip_called_numbers.csv")

    s.groupby("sip_user_agent").agg(
        events=("event_uuid", "size"), unique_src=("src_ip", "nunique"),
    ).sort_values("events", ascending=False).to_csv(f"{OUT}/sip_user_agents.csv")

    for col in ["sip_method", "transport_type", "collected_method"]:
        if col in s.columns:
            s[col].value_counts().to_frame("count").to_csv(f"{OUT}/sip_{col}.csv")

    print(f"sentrypeer: {s.src_ip.nunique():,} source IPs, "
          f"{s.called_number.nunique():,} distinct dialed numbers")
    print(f"window: {s.timestamp.min()} -> {s.timestamp.max()}")


# ========================== SURICATA ==========================
files = sorted(glob.glob(f"{ALERTS}/*-alerts.json"))
seen, rows, bad = set(), [], 0
for p in files:
    n = 0
    with open(p, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            a = r.get("alert", {})
            k = (r.get("timestamp"), r.get("src_ip"), r.get("dest_ip"),
                 r.get("src_port"), a.get("signature_id"))
            if k in seen:
                continue
            seen.add(k)
            rows.append({
                "timestamp": r.get("timestamp"),
                "src_ip": r.get("src_ip"), "src_port": r.get("src_port"),
                "dest_ip": r.get("dest_ip"), "dest_port": r.get("dest_port"),
                "proto": r.get("proto"),
                "sig_id": a.get("signature_id"),
                "signature": a.get("signature"),
                "category": a.get("category"),
                "severity": a.get("severity"),
                "cve": ",".join(a.get("metadata", {}).get("cve", []))
                       if isinstance(a.get("metadata"), dict) else "",
            })
            n += 1
    print(f"  {os.path.basename(p)}: {n:,} new")

print(f"suricata: {len(files)} files, {len(rows):,} unique alerts, {bad} malformed")

if rows:
    a = pd.DataFrame(rows)
    a["timestamp"] = pd.to_datetime(a["timestamp"], format="mixed",
                                    errors="coerce", utc=True)
    a = a.dropna(subset=["timestamp"]).sort_values("timestamp")
    a["date"] = a["timestamp"].dt.date

    a.groupby("signature").agg(
        count=("sig_id", "size"), unique_src=("src_ip", "nunique"),
        sig_id=("sig_id", "first"), severity=("severity", "first"),
        category=("category", "first"),
    ).sort_values("count", ascending=False).to_csv(f"{OUT}/suricata_signatures.csv")

    a.groupby("category").agg(
        count=("sig_id", "size"), unique_src=("src_ip", "nunique"),
    ).sort_values("count", ascending=False).to_csv(f"{OUT}/suricata_categories.csv")

    a.groupby(["date", "category"]).size().unstack(fill_value=0) \
     .to_csv(f"{OUT}/suricata_daily_by_category.csv")

    a.groupby("src_ip").agg(
        alerts=("sig_id", "size"), distinct_sigs=("signature", "nunique"),
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
    ).sort_values("alerts", ascending=False).to_csv(f"{OUT}/suricata_source_ips.csv")

    # CVE-tagged alerts, the independent check on the scrapbook's claim
    cve = a[a.cve.astype(str).str.len() > 0]
    if not cve.empty:
        cve.to_csv(f"{OUT}/suricata_cve_alerts.csv", index=False)
        print("\nCVE-TAGGED ALERTS:")
        print(cve.groupby("cve").agg(
            count=("sig_id", "size"), unique_src=("src_ip", "nunique"),
            first=("timestamp", "min"), last=("timestamp", "max"),
        ).to_string())
    else:
        print("\nno CVE metadata field; searching signature text instead")
        m = a[a.signature.astype(str).str.contains("CVE", case=False, na=False)]
        if not m.empty:
            m.to_csv(f"{OUT}/suricata_cve_alerts.csv", index=False)
            print(m.groupby("signature").size().to_string())

    a.to_csv(f"{OUT}/suricata_alerts_full.csv", index=False)
    print(f"\nwindow: {a.timestamp.min()} -> {a.timestamp.max()}")
    print(f"unique signatures: {a.signature.nunique()}  "
          f"source IPs: {a.src_ip.nunique():,}")

print(f"\nCSVs in {OUT}/")
