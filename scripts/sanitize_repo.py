#!/usr/bin/env python3
"""
sanitize_repo.py - Build the publishable repo from the analysis outputs.

Removes the operator's own IP, drops credential-hash columns, excludes
oversized derived files, and runs a verification pass that fails loudly if any
sensitive term survives.
"""
import os, re, shutil, sys
import pandas as pd

SRC = "/mnt/user-data/outputs/rdp-analysis"
DST = "/mnt/user-data/outputs/honeypot-repo"

# --- terms that must never appear in the published repo ---
# Loaded from .sanitize-terms (gitignored) so the literals are never committed.
# Format: one "label = value" pair per line. Example:
#   operator IP = 203.0.113.7
#   hostname    = example-host
TERMS_FILE = os.path.join(os.path.dirname(__file__), "..", ".sanitize-terms")

FORBIDDEN, REDACT = {}, {}
if os.path.exists(TERMS_FILE):
    for line in open(TERMS_FILE):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        label, value = (x.strip() for x in line.split("=", 1))
        if label.lower().startswith("redact:"):
            REDACT[label.split(":", 1)[1].strip()] = value
        else:
            FORBIDDEN[label] = value
else:
    print("WARNING: no .sanitize-terms file found; nothing will be scrubbed.")

HOME_IP = FORBIDDEN.get("operator IP", "")
SERVER_IP = next(iter(REDACT.values()), "")
REDACT_LABEL = next(iter(REDACT.keys()), "HOST_IP")

# columns carrying crackable authentication material
HASH_COLS = {"hashcat_line", "nt_proof", "nt_response", "challenge",
             "response", "password_hash", "ntlm_hash", "server_challenge"}
# derived files too large or too raw to publish
EXCLUDE = {"heralding_sessions.csv", "source_ips_enriched.csv"}

for sub in ("data", "charts", "scripts", "docs"):
    os.makedirs(f"{DST}/{sub}", exist_ok=True)

# ---------------- data ----------------
removed_rows, dropped_cols, skipped = 0, [], []
for f in sorted(os.listdir(f"{SRC}/data")):
    if f in EXCLUDE:
        skipped.append(f)
        continue
    df = pd.read_csv(f"{SRC}/data/{f}", low_memory=False)
    before = len(df)

    # strip the operator's own IP from any column that holds addresses
    for col in df.columns:
        if col.lower() in ("src_ip", "ip", "source_ip", "dest_ip") and HOME_IP:
            df = df[df[col].astype(str).str.strip() != HOME_IP]
    removed_rows += before - len(df)

    # drop authentication material
    drop = [c for c in df.columns if c.lower() in HASH_COLS]
    if drop:
        df = df.drop(columns=drop)
        dropped_cols.append(f"{f}: {', '.join(drop)}")

    for col in df.columns:
        if not SERVER_IP:
            continue
        try:
            df[col] = df[col].astype(str).str.replace(
                SERVER_IP, REDACT_LABEL, regex=False)
        except Exception:
            pass
    df.to_csv(f"{DST}/data/{f}", index=False)

for f in os.listdir(f"{SRC}/charts"):
    shutil.copy(f"{SRC}/charts/{f}", f"{DST}/charts/{f}")
for f in os.listdir(f"{SRC}/scripts"):
    shutil.copy(f"{SRC}/scripts/{f}", f"{DST}/scripts/{f}")
NOTES = "/mnt/user-data/outputs/working-notes"
os.makedirs(NOTES, exist_ok=True)
for f in os.listdir(SRC):
    if f.startswith("FINDINGS"):
        shutil.copy(f"{SRC}/{f}", f"{NOTES}/{f}")

# ---------------- .gitignore ----------------
with open(f"{DST}/.gitignore", "w") as fh:
    fh.write("""# Never commit credential or key material
*.pem
*.key
*.p12
*.pfx
*.mmdb

# Raw honeypot exports and working directories
raw/
*.tar.gz
*.tar
*.gz
data/elk/
suricata-alerts/

# Large derived files kept local
heralding_sessions.csv
source_ips_enriched.csv
suricata_alerts_full.csv

# Environment
.env
.venv/
__pycache__/
.DS_Store
.ipynb_checkpoints/
""")

# ---------------- verification ----------------
print("=" * 62)
print("SANITIZATION VERIFICATION")
print("=" * 62)
print(f"Rows removed containing operator IP : {removed_rows}")
print(f"Files excluded from publication     : {', '.join(skipped) or 'none'}")
if dropped_cols:
    print("Hash columns dropped:")
    for d in dropped_cols:
        print(f"  {d}")
else:
    print("Hash columns dropped                : none present")

print("\nWord-boundary scan across every published file:")
fail = False
for label, term in FORBIDDEN.items():
    pat = re.compile(r"\b" + re.escape(term) + r"\b")
    hits = []
    for root, _, files in os.walk(DST):
        for f in files:
            p = os.path.join(root, f)
            if f.endswith(".png"):
                continue
            try:
                with open(p, "r", errors="replace") as fh:
                    if pat.search(fh.read()):
                        hits.append(os.path.relpath(p, DST))
            except Exception:
                pass
    status = "CLEAN" if not hits else f"FOUND in {len(hits)} file(s)"
    if hits:
        fail = True
    print(f"  {label:16s} {term:18s} {status}")
    for h in hits[:6]:
        print(f"      {h}")

# server IP is intentional in docs; flag location only
pat = re.compile(r"\b" + re.escape(SERVER_IP) + r"\b")
hits = []
for root, _, files in os.walk(DST):
    for f in files:
        if f.endswith(".png"):
            continue
        p = os.path.join(root, f)
        try:
            with open(p, "r", errors="replace") as fh:
                if pat.search(fh.read()):
                    hits.append(os.path.relpath(p, DST))
        except Exception:
            pass
print(f"\n  redacted host address: "
      f"{'CLEAN (redacted to HONEYPOT_IP)' if not hits else f'FOUND in {len(hits)}'}")
for h in hits[:6]:
    print(f"      {h}")
if hits:
    fail = True

print("\n" + ("VERIFICATION FAILED" if fail else "VERIFICATION PASSED"))
size = sum(os.path.getsize(os.path.join(r, f))
           for r, _, fs in os.walk(DST) for f in fs)
print(f"Repo size: {size/1e6:.1f} MB")
sys.exit(1 if fail else 0)
