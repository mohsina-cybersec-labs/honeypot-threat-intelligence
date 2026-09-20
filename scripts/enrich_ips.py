#!/usr/bin/env python3
"""
enrich_ips.py - Join honeypot source-IP lists against GeoLite2 ASN + Country.

Rebuilds the enrichment layer that lived inside Elasticsearch, so every ASN and
country figure in the report is computed from raw logs rather than cited from a
dashboard screenshot.

Usage: python3 enrich_ips.py <asn.mmdb> <country.mmdb> <out_dir>
"""
import sys, os, glob
import pandas as pd
import geoip2.database

ASN_DB = sys.argv[1]
CTY_DB = sys.argv[2]
OUT = sys.argv[3] if len(sys.argv) > 3 else "parsed4"
os.makedirs(OUT, exist_ok=True)

asn_r = geoip2.database.Reader(ASN_DB)
cty_r = geoip2.database.Reader(CTY_DB)

_cache = {}


def lookup(ip):
    if ip in _cache:
        return _cache[ip]
    asn = org = country = iso = None
    try:
        a = asn_r.asn(ip)
        asn, org = a.autonomous_system_number, a.autonomous_system_organization
    except Exception:
        pass
    try:
        c = cty_r.country(ip)
        country, iso = c.country.name, c.country.iso_code
    except Exception:
        pass
    _cache[ip] = (asn, org, country, iso)
    return _cache[ip]


# sources: (label, csv path, ip column, weight column)
SOURCES = [
    ("rdp",        "parsed/rdp_source_ips.csv",         "src_ip",    "events"),
    ("cowrie",     "parsed2/cowrie_source_ips.csv",     "src_ip",    "events"),
    ("heralding",  "parsed2/heralding_source_ips.csv",  "source_ip", "attempts"),
    ("sip",        "parsed3/sip_source_ips.csv",        "src_ip",    "events"),
    ("suricata",   "parsed3/suricata_source_ips.csv",   "src_ip",    "alerts"),
]

frames = []
for label, path, ipcol, wcol in SOURCES:
    if not os.path.exists(path):
        print(f"  skip {label}: {path} missing")
        continue
    df = pd.read_csv(path)
    df = df.rename(columns={ipcol: "ip", wcol: "events"})
    df = df[["ip", "events"]].copy()
    df["source"] = label
    frames.append(df)
    print(f"  {label:10s} {len(df):>7,} IPs, {df.events.sum():>12,} events")

all_ips = pd.concat(frames, ignore_index=True)
uniq = all_ips.ip.dropna().astype(str).unique()
print(f"\nresolving {len(uniq):,} distinct IPs ...")

res = {ip: lookup(ip) for ip in uniq}
meta = pd.DataFrame(
    [(ip, *res[ip]) for ip in uniq],
    columns=["ip", "asn", "asn_org", "country", "iso"])
meta.to_csv(f"{OUT}/ip_enrichment.csv", index=False)

hit = meta.asn.notna().sum()
print(f"ASN resolved: {hit:,} of {len(meta):,} ({100*hit/len(meta):.1f}%)")
print(f"Country resolved: {meta.country.notna().sum():,}")

j = all_ips.merge(meta, on="ip", how="left")
j.to_csv(f"{OUT}/source_ips_enriched.csv", index=False)

# ---------- ASN tables ----------
asn_tbl = j.groupby(["asn", "asn_org"], dropna=False).agg(
    events=("events", "sum"), unique_ips=("ip", "nunique"),
    honeypots=("source", "nunique"),
).sort_values("events", ascending=False).reset_index()
total = asn_tbl.events.sum()
asn_tbl["pct_of_total"] = (100 * asn_tbl.events / total).round(2)
asn_tbl.to_csv(f"{OUT}/asn_full_window.csv", index=False)

# per honeypot
j.groupby(["source", "asn_org"], dropna=False).agg(
    events=("events", "sum"), unique_ips=("ip", "nunique")
).sort_values(["source", "events"], ascending=[True, False]) \
 .to_csv(f"{OUT}/asn_by_honeypot.csv")

# ---------- country tables ----------
cty = j.groupby("country", dropna=False).agg(
    events=("events", "sum"), unique_ips=("ip", "nunique")
).sort_values("events", ascending=False).reset_index()
cty["pct_of_total"] = (100 * cty.events / cty.events.sum()).round(2)
cty.to_csv(f"{OUT}/country_full_window.csv", index=False)

j.groupby(["source", "country"], dropna=False).agg(
    events=("events", "sum"), unique_ips=("ip", "nunique")
).sort_values(["source", "events"], ascending=[True, False]) \
 .to_csv(f"{OUT}/country_by_honeypot.csv")

# ---------- research scanner separation ----------
SCANNER_ORGS = ["google", "onyphe", "censys", "shodan", "digitalocean",
                "modat", "internet-measurement", "driftnet", "alpha strike",
                "bitsight", "recyber", "shadowserver", "rapid7", "palo alto",
                "securitytrails", "binaryedge", "stretchoid", "netsystems"]
j["likely_scanner"] = j.asn_org.fillna("").astype(str).str.lower().apply(
    lambda s: any(k in s for k in SCANNER_ORGS))

# Zmap self-identified IPs from Suricata
zmap = set()
sp = "parsed3/suricata_alerts_full.csv"
if os.path.exists(sp):
    sa = pd.read_csv(sp, low_memory=False)
    zmap = set(sa[sa.signature.astype(str).str.contains("Zmap", case=False,
                                                        na=False)].src_ip.dropna())
    print(f"\nZmap self-identified IPs: {len(zmap):,}")
j["zmap_flagged"] = j.ip.isin(zmap)
j["scanner"] = j.likely_scanner | j.zmap_flagged
j.to_csv(f"{OUT}/source_ips_enriched.csv", index=False)

sc = j.groupby("scanner").agg(events=("events", "sum"), ips=("ip", "nunique"))
sc.to_csv(f"{OUT}/scanner_vs_attack.csv")

print("\n=== TOP 15 ASN (full window, all honeypots) ===")
print(asn_tbl.head(15)[["asn", "asn_org", "events", "unique_ips",
                        "pct_of_total"]].to_string(index=False))
print("\n=== TOP 12 COUNTRIES ===")
print(cty.head(12).to_string(index=False))
print("\n=== SCANNER vs ATTACK ===")
print(sc.to_string())

# de-skewed view: drop the single largest ASN
top_asn = asn_tbl.iloc[0]
ds = j[j.asn != top_asn.asn]
print(f"\n=== DE-SKEWED (excluding {top_asn.asn_org}, "
      f"{top_asn.pct_of_total}% of traffic) ===")
dsc = ds.groupby("country").agg(events=("events", "sum")) \
        .sort_values("events", ascending=False)
dsc["pct"] = (100 * dsc.events / dsc.events.sum()).round(2)
dsc.to_csv(f"{OUT}/country_deskewed.csv")
print(dsc.head(10).to_string())

print(f"\nCSVs in {OUT}/")
