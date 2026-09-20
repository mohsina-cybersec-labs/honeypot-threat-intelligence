#!/usr/bin/env python3
"""
parse_b1.py - Cowrie + Heralding parser for T-Pot exports.

Walks every archive directory, dedupes across overlapping exports, and writes
tidy CSVs to parsed/.

Usage: python3 parse_b1.py <raw_root> <out_dir>
"""
import sys, os, json, gzip, glob, csv, io
import pandas as pd

ROOT = sys.argv[1] if len(sys.argv) > 1 else "b1"
OUT = sys.argv[2] if len(sys.argv) > 2 else "parsed"
os.makedirs(OUT, exist_ok=True)


def open_any(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") \
        else open(p, "r", errors="replace")


# ============================ COWRIE ============================
def load_cowrie():
    files = sorted(glob.glob(f"{ROOT}/*/data/cowrie/log/cowrie.json*"))
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
                k = (r.get("session"), r.get("eventid"), r.get("timestamp"),
                     r.get("input", r.get("username", "")))
                if k in seen:
                    continue
                seen.add(k)
                rows.append(r)
    print(f"cowrie: {len(files)} files, {len(rows):,} unique events, {bad} malformed")
    return pd.DataFrame(rows)


cw = load_cowrie()
cw["timestamp"] = pd.to_datetime(cw["timestamp"], format="mixed", utc=True)
cw = cw.sort_values("timestamp")
cw["date"] = cw["timestamp"].dt.date

cw.groupby(["date", "eventid"]).size().unstack(fill_value=0) \
  .to_csv(f"{OUT}/cowrie_daily_events.csv")

# credentials (plaintext, unlike RDP)
logins = cw[cw.eventid.isin(["cowrie.login.failed", "cowrie.login.success"])].copy()
if not logins.empty:
    logins["success"] = logins.eventid.eq("cowrie.login.success")
    logins[["timestamp", "src_ip", "username", "password", "success",
            "protocol", "session"]].to_csv(f"{OUT}/cowrie_credentials.csv", index=False)
    logins.groupby(["username", "password"]).agg(
        attempts=("eventid", "size"),
        successes=("success", "sum"),
        unique_src=("src_ip", "nunique"),
    ).sort_values("attempts", ascending=False).to_csv(f"{OUT}/cowrie_cred_pairs.csv")

# typed commands
cmds = cw[cw.eventid.isin(["cowrie.command.input", "cowrie.command.failed"])].copy()
if not cmds.empty:
    cmds["failed"] = cmds.eventid.eq("cowrie.command.failed")
    cmds[["timestamp", "src_ip", "session", "input", "failed"]] \
        .to_csv(f"{OUT}/cowrie_commands.csv", index=False)

# client tooling fingerprints
ver = cw[cw.eventid == "cowrie.client.version"]
if not ver.empty:
    col = "version" if "version" in ver.columns else "client"
    ver.groupby(col).agg(count=("eventid", "size"),
                         unique_src=("src_ip", "nunique")) \
       .sort_values("count", ascending=False).to_csv(f"{OUT}/cowrie_client_versions.csv")

# download attempts (blocked by egress filter)
dl = cw[cw.eventid.astype(str).str.startswith("cowrie.session.file_download")]
if not dl.empty:
    keep = [c for c in ["timestamp", "src_ip", "session", "url", "outfile",
                        "shasum", "eventid"] if c in dl.columns]
    dl[keep].to_csv(f"{OUT}/cowrie_downloads.csv", index=False)

cw.groupby("src_ip").agg(
    events=("eventid", "size"), sessions=("session", "nunique"),
    first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
).sort_values("events", ascending=False).to_csv(f"{OUT}/cowrie_source_ips.csv")

# sessions that actually got a shell
cmd_sessions = set(cmds.session.dropna()) if not cmds.empty else set()
print(f"cowrie: {cw.session.nunique():,} sessions, "
      f"{len(cmd_sessions):,} with typed commands, "
      f"{int(logins.success.sum()) if not logins.empty else 0} successful logins")


# =========================== HERALDING ===========================
def load_csv_set(pattern):
    files = sorted(glob.glob(pattern))
    frames, hdr = [], None
    for p in files:
        with open_any(p) as fh:
            txt = fh.read()
        if not txt.strip():
            continue
        # rotated files keep the header; fall back to the first file's header
        try:
            df = pd.read_csv(io.StringIO(txt), on_bad_lines="skip")
        except Exception:
            continue
        if "timestamp" not in df.columns and hdr is not None:
            df = pd.read_csv(io.StringIO(txt), names=hdr, on_bad_lines="skip")
        if hdr is None and "timestamp" in df.columns:
            hdr = list(df.columns)
        frames.append(df)
    if not frames:
        return pd.DataFrame()
    out = pd.concat(frames, ignore_index=True)
    print(f"  {os.path.basename(pattern)}: {len(files)} files, {len(out):,} rows")
    return out


print("heralding:")
auth = load_csv_set(f"{ROOT}/*/data/heralding/log/auth.csv*")
sess = load_csv_set(f"{ROOT}/*/data/heralding/log/session.csv*")

if not auth.empty:
    auth = auth.drop_duplicates(subset=["auth_id"])
    auth["timestamp"] = pd.to_datetime(auth["timestamp"], format="mixed",
                                       errors="coerce", utc=True)
    auth = auth.dropna(subset=["timestamp"]).sort_values("timestamp")
    auth["date"] = auth["timestamp"].dt.date

    auth.groupby(["date", "protocol"]).size().unstack(fill_value=0) \
        .to_csv(f"{OUT}/heralding_daily_by_protocol.csv")

    auth.groupby("source_ip").agg(
        attempts=("auth_id", "size"), protocols=("protocol", "nunique"),
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
    ).sort_values("attempts", ascending=False) \
     .to_csv(f"{OUT}/heralding_source_ips.csv")

    # plaintext credentials only; VNC stores challenge/response in password_hash
    cred = auth[auth.username.notna() | auth.password.notna()]
    if not cred.empty:
        cred.groupby(["protocol", "username", "password"], dropna=False) \
            .size().reset_index(name="attempts") \
            .sort_values("attempts", ascending=False) \
            .to_csv(f"{OUT}/heralding_cred_pairs.csv", index=False)

    auth.groupby("protocol").agg(
        attempts=("auth_id", "size"), unique_src=("source_ip", "nunique"),
    ).sort_values("attempts", ascending=False) \
     .to_csv(f"{OUT}/heralding_protocol_summary.csv")

    vnc_cr = auth[auth.password_hash.notna() & auth.password_hash.astype(str).str.contains("challenge")]
    print(f"heralding: {len(auth):,} unique auth attempts, "
          f"{auth.source_ip.nunique():,} source IPs, "
          f"{len(vnc_cr):,} VNC challenge/response captures")
    print(f"window: {auth.timestamp.min()} -> {auth.timestamp.max()}")

if not sess.empty:
    sess = sess.drop_duplicates(subset=["session_id"])
    sess.to_csv(f"{OUT}/heralding_sessions.csv", index=False)
    print(f"heralding: {len(sess):,} unique sessions")

print(f"\nCSVs in {OUT}/")
