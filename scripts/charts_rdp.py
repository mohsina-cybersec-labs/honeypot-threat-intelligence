#!/usr/bin/env python3
"""Charts for the RDP honeypot dataset. Reads parsed/*.csv, writes charts/*.png"""
import os, re
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

os.makedirs("charts", exist_ok=True)
plt.rcParams.update({
    "figure.dpi": 150, "savefig.dpi": 150, "font.size": 9,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": .25, "grid.linestyle": "-",
    "figure.facecolor": "white",
})
INK, ACC1, ACC2, ACC3 = "#1f2933", "#2f6f9f", "#c2603f", "#7a8b99"

# ---------- 1. daily volume ----------
d = pd.read_csv("parsed/rdp_daily_events.csv", parse_dates=["date"])
fig, ax = plt.subplots(figsize=(10, 4.2))
ax.bar(d.date, d["rdphoneypot.session.connect"], color=ACC3, label="Session connects (total)", width=.75)
ax.bar(d.date, d["rdphoneypot.login"], color=ACC1, label="of which: NLA login attempts", width=.75)
ax.set_title("RDP honeypot daily activity, 21-day collection window", loc="left", color=INK, fontweight="bold")
ax.set_ylabel("Events per day")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
ax.legend(frameon=False)
ax.annotate("Sep 2-3: 213.177.179.195\n120,226 events in 6h23m",
            xy=(pd.Timestamp("2026-09-02"), 38800), xytext=(pd.Timestamp("2026-09-03 12:00"), 33000),
            fontsize=8, color=INK, arrowprops=dict(arrowstyle="->", color=ACC2, lw=.9))
fig.autofmt_xdate(rotation=45, ha="right")
fig.tight_layout(); fig.savefig("charts/01_rdp_daily_volume.png"); plt.close(fig)

# ---------- 2. top source IPs ----------
ips = pd.read_csv("parsed/rdp_source_ips.csv").head(12).iloc[::-1]
fig, ax = plt.subplots(figsize=(8, 4.6))
ax.barh(ips.src_ip, ips.events, color=ACC1)
ax.set_title("Top 12 source IPs by RDP event volume", loc="left", color=INK, fontweight="bold")
ax.set_xlabel("Events")
for y, v in zip(range(len(ips)), ips.events):
    ax.text(v + 1500, y, f"{v:,}", va="center", fontsize=7.5, color=INK)
ax.margins(x=.14)
fig.tight_layout(); fig.savefig("charts/02_rdp_top_source_ips.png"); plt.close(fig)

# ---------- 3. username signal vs noise ----------
u = pd.read_csv("parsed/rdp_usernames.csv").dropna(subset=["username"])
u["username"] = u.username.astype(str)
pat = re.compile(r"^[\x20-\x7e]+$")
real = u[u.username.map(lambda s: bool(pat.match(s))) & (u.attempts > 1)]
noise_n = len(u) - len(real)
noise_a = u.attempts.sum() - real.attempts.sum()

fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.4),
                             gridspec_kw={"width_ratios": [1, 1.5]})
a1.bar(["Distinct\nstrings", "Attempts"], [noise_n, noise_a], color=ACC3, label="Malformed / non-RDP")
a1.bar(["Distinct\nstrings", "Attempts"], [len(real), real.attempts.sum()],
       bottom=[noise_n, noise_a], color=ACC1, label="Valid usernames")
a1.set_title("Username field: signal vs. noise", loc="left", color=INK, fontweight="bold")
a1.set_ylabel("Count"); a1.legend(frameon=False, fontsize=8)
a1.text(0, noise_n/2, f"{noise_n:,}\n(84.7%)", ha="center", va="center", color="white", fontsize=8)

top = real.head(12).iloc[::-1]
a2.barh(top.username, top.attempts, color=ACC1)
a2.set_title("Top usernames attempted (valid strings only)", loc="left", color=INK, fontweight="bold")
a2.set_xlabel("NLA login attempts"); a2.set_xscale("log")
fig.tight_layout(); fig.savefig("charts/03_rdp_username_quality.png"); plt.close(fig)

# ---------- 4. campaign windows ----------
top_ips = pd.read_csv("parsed/rdp_source_ips.csv").head(10)
top_ips["first_seen"] = pd.to_datetime(top_ips.first_seen)
top_ips["last_seen"] = pd.to_datetime(top_ips.last_seen)
top_ips = top_ips.iloc[::-1].reset_index(drop=True)
fig, ax = plt.subplots(figsize=(10, 4.4))
for i, r in top_ips.iterrows():
    ax.barh(i, r.last_seen - r.first_seen, left=r.first_seen, height=.55,
            color=ACC1 if r.events > 20000 else ACC3, alpha=.9)
    ax.text(r.last_seen, i, f"  {r.events:,}", va="center", fontsize=7.5, color=INK)
ax.set_yticks(range(len(top_ips))); ax.set_yticklabels(top_ips.src_ip, fontsize=8)
ax.set_title("Active window per top-10 source IP", loc="left", color=INK, fontweight="bold")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
ax.margins(x=.10)
fig.autofmt_xdate(rotation=45, ha="right")
fig.tight_layout(); fig.savefig("charts/04_rdp_campaign_windows.png"); plt.close(fig)

print("wrote:", *sorted(os.listdir("charts")), sep="\n  ")
