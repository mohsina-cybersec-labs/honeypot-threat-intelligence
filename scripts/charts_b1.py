#!/usr/bin/env python3
"""Charts for Cowrie + Heralding. Reads parsed2/*.csv, writes charts2/*.png"""
import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

os.makedirs("charts2", exist_ok=True)
plt.rcParams.update({
    "figure.dpi": 150, "savefig.dpi": 150, "font.size": 9,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": .25, "figure.facecolor": "white",
})
INK, ACC1, ACC2, ACC3 = "#1f2933", "#2f6f9f", "#c2603f", "#7a8b99"

# ---- 1. Heralding VNC: the Contabo campaign lifecycle ----
h = pd.read_csv("parsed2/heralding_daily_by_protocol.csv", parse_dates=["date"])
fig, ax = plt.subplots(figsize=(10, 4.2))
ax.plot(h.date, h["vnc"], color=ACC1, lw=2, marker="o", ms=3.5, label="VNC (5900)")
for p, c in [("socks5", ACC2), ("postgresql", ACC3)]:
    if p in h.columns:
        ax.plot(h.date, h[p], color=c, lw=1.2, label=p)
ax.set_yscale("log")
ax.set_title("Heralding authentication attempts per day, by protocol",
             loc="left", color=INK, fontweight="bold")
ax.set_ylabel("Auth attempts (log scale)")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
ax.legend(frameon=False)
ax.axvspan(pd.Timestamp("2026-08-29"), pd.Timestamp("2026-08-31"), color=ACC1, alpha=.10)
ax.axvspan(pd.Timestamp("2026-09-08"), pd.Timestamp("2026-09-13"), color=ACC1, alpha=.10)
ax.text(pd.Timestamp("2026-08-29"), h["vnc"].max()*1.5, "wave 1\nAug 30-31", fontsize=8, color=INK)
ax.text(pd.Timestamp("2026-09-08"), h["vnc"].max()*1.5, "wave 2\nSep 8-13", fontsize=8, color=INK)
ax.text(pd.Timestamp("2026-09-02"), 400, "dormant Sep 1-7", fontsize=8, color=ACC3)
fig.autofmt_xdate(rotation=45, ha="right")
fig.tight_layout(); fig.savefig("charts2/05_heralding_campaign.png"); plt.close(fig)

# ---- 2. Cowrie funnel ----
cw = pd.read_csv("parsed2/cowrie_daily_events.csv", parse_dates=["date"])
cred = pd.read_csv("parsed2/cowrie_credentials.csv")
cmds = pd.read_csv("parsed2/cowrie_commands.csv")
stages = [
    ("Sessions opened", int(cw["cowrie.session.connect"].sum())),
    ("Login attempted", len(cred)),
    ("Login succeeded", int(cred.success.sum())),
    ("Commands typed", cmds.session.nunique()),
    ("Payload fetched", 14),
]
fig, ax = plt.subplots(figsize=(8.5, 4.2))
labels = [s[0] for s in stages][::-1]
vals = [s[1] for s in stages][::-1]
ax.barh(labels, vals, color=[ACC2 if v < 2000 else ACC1 for v in vals])
ax.set_xscale("log")
ax.set_title("Cowrie attacker funnel, 21-day window", loc="left",
             color=INK, fontweight="bold")
ax.set_xlabel("Count (log scale)")
for y, v in enumerate(vals):
    ax.text(v*1.15, y, f"{v:,}", va="center", fontsize=8, color=INK)
ax.margins(x=.2)
fig.tight_layout(); fig.savefig("charts2/06_cowrie_funnel.png"); plt.close(fig)

# ---- 3. Cowrie client tooling ----
v = pd.read_csv("parsed2/cowrie_client_versions.csv")
v = v.head(6).iloc[::-1]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 3.6), gridspec_kw={"width_ratios": [1.3, 1]})
a1.barh(v.iloc[:, 0].astype(str), v["count"], color=ACC1)
a1.set_xscale("log")
a1.set_title("SSH client version strings", loc="left", color=INK, fontweight="bold")
a1.set_xlabel("Connections (log scale)")
for y, (c, s) in enumerate(zip(v["count"], v["unique_src"])):
    a1.text(c*1.15, y, f"{c:,}  ({s} IPs)", va="center", fontsize=7.5, color=INK)
a1.margins(x=.35)

top = pd.read_csv("parsed2/cowrie_cred_pairs.csv").head(10).iloc[::-1]
lbl = (top.username.astype(str) + " / " + top.password.astype(str)).str.slice(0, 28)
a2.barh(lbl, top.attempts, color=ACC2)
a2.set_title("Top credential pairs", loc="left", color=INK, fontweight="bold")
a2.set_xlabel("Attempts")
fig.tight_layout(); fig.savefig("charts2/07_cowrie_tooling_creds.png"); plt.close(fig)

print("wrote:", *sorted(os.listdir("charts2")), sep="\n  ")
