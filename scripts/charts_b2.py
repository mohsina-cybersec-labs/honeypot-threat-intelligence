#!/usr/bin/env python3
"""Charts for Sentrypeer + Suricata. Reads parsed3/*.csv, writes charts3/*.png"""
import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

os.makedirs("charts3", exist_ok=True)
plt.rcParams.update({
    "figure.dpi": 150, "savefig.dpi": 150, "font.size": 9,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": .25, "figure.facecolor": "white",
})
INK, ACC1, ACC2, ACC3 = "#1f2933", "#2f6f9f", "#c2603f", "#7a8b99"

# ---- 8. SIP daily volume with the Sep 12 burst ----
d = pd.read_csv("parsed3/sip_daily_events.csv", parse_dates=["date"])
fig, ax = plt.subplots(figsize=(10, 4.0))
ax.fill_between(d.date, d.events, color=ACC1, alpha=.25)
ax.plot(d.date, d.events, color=ACC1, lw=1.8, marker="o", ms=3)
ax.set_title("Sentrypeer SIP events per day (port 5060)", loc="left",
             color=INK, fontweight="bold")
ax.set_ylabel("SIP events")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
peak = d.loc[d.events.idxmax()]
ax.annotate(f"{peak.date:%b %d}: {int(peak.events):,}",
            xy=(peak.date, peak.events),
            xytext=(peak.date - pd.Timedelta(days=5), peak.events * .88),
            fontsize=8, color=INK,
            arrowprops=dict(arrowstyle="->", color=ACC2, lw=.9))
fig.autofmt_xdate(rotation=45, ha="right")
fig.tight_layout(); fig.savefig("charts3/08_sip_daily.png"); plt.close(fig)

# ---- 9. SIP methods + user agents ----
m = pd.read_csv("parsed3/sip_sip_method.csv").head(5).iloc[::-1]
ua = pd.read_csv("parsed3/sip_user_agents.csv").head(8).iloc[::-1]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 3.8), gridspec_kw={"width_ratios": [1, 1.3]})
a1.barh(m.iloc[:, 0].astype(str), m["count"], color=ACC1)
a1.set_title("SIP methods observed", loc="left", color=INK, fontweight="bold")
a1.set_xscale("log"); a1.set_xlabel("Events (log scale)")
for y, v in enumerate(m["count"]):
    a1.text(v * 1.15, y, f"{v:,}", va="center", fontsize=7.5, color=INK)
a1.margins(x=.3)
a2.barh(ua.sip_user_agent.astype(str), ua.events, color=ACC2)
a2.set_title("SIP User-Agent strings (spoofed PBX identities)", loc="left",
             color=INK, fontweight="bold")
a2.set_xlabel("Events")
for y, (v, s) in enumerate(zip(ua.events, ua.unique_src)):
    a2.text(v * 1.02, y, f" {v:,} ({s} IPs)", va="center", fontsize=7.5, color=INK)
a2.margins(x=.22)
fig.tight_layout(); fig.savefig("charts3/09_sip_methods_agents.png"); plt.close(fig)

# ---- 10. Suricata: alert categories ----
c = pd.read_csv("parsed3/suricata_categories.csv").head(9).iloc[::-1]
fig, ax = plt.subplots(figsize=(9, 4.0))
ax.barh(c.category.astype(str).str.slice(0, 42), c["count"], color=ACC1)
ax.set_xscale("log")
ax.set_title("Suricata alerts by category, 499,038 total across 21 days",
             loc="left", color=INK, fontweight="bold")
ax.set_xlabel("Alerts (log scale)")
for y, (v, s) in enumerate(zip(c["count"], c.unique_src)):
    ax.text(v * 1.15, y, f"{v:,} ({s:,} IPs)", va="center", fontsize=7.5, color=INK)
ax.margins(x=.3)
fig.tight_layout(); fig.savefig("charts3/10_suricata_categories.png"); plt.close(fig)

# ---- 11. CVE rarity ----
fig, ax = plt.subplots(figsize=(9, 2.9))
bars = [("All Suricata alerts", 499038, ACC3),
        ("Scan-detection alerts", 1450, ACC1),
        ("CVE-2020-11910 (Path MTU, false positive)", 48, ACC2),
        ("CVE-2020-5902 (F5 TMUI RCE, genuine)", 2, ACC2)]
ax.barh([b[0] for b in bars][::-1], [b[1] for b in bars][::-1],
        color=[b[2] for b in bars][::-1])
ax.set_xscale("log")
ax.set_title("CVE-tagged detections against total alert volume", loc="left",
             color=INK, fontweight="bold")
ax.set_xlabel("Count (log scale)")
for y, v in enumerate([b[1] for b in bars][::-1]):
    ax.text(v * 1.2, y, f"{v:,}", va="center", fontsize=8, color=INK)
ax.margins(x=.28)
fig.tight_layout(); fig.savefig("charts3/11_cve_rarity.png"); plt.close(fig)

print("wrote:", *sorted(os.listdir("charts3")), sep="\n  ")
