import os
import pandas as pd, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
os.makedirs("charts4", exist_ok=True)
plt.rcParams.update({"figure.dpi":150,"savefig.dpi":150,"font.size":9,
    "axes.spines.top":False,"axes.spines.right":False,"axes.grid":True,
    "grid.alpha":.25,"figure.facecolor":"white"})
INK,ACC1,ACC2,ACC3="#1f2933","#2f6f9f","#c2603f","#7a8b99"

# 12: ASN concentration
a=pd.read_csv("parsed4/asn_full_window.csv").head(12).iloc[::-1]
fig,ax=plt.subplots(figsize=(9,4.6))
ax.barh(a.asn_org.astype(str).str.slice(0,32),a.events,
        color=[ACC2 if p>10 else ACC1 for p in a.pct_of_total])
ax.set_title("Top 12 ASNs by event volume, full window",loc="left",color=INK,fontweight="bold")
ax.set_xlabel("Events")
for y,(v,p,n) in enumerate(zip(a.events,a.pct_of_total,a.unique_ips)):
    ax.text(v*1.02,y,f" {v:,} ({p}%, {n} IPs)",va="center",fontsize=7.3,color=INK)
ax.margins(x=.32)
fig.tight_layout();fig.savefig("charts4/12_asn_concentration.png");plt.close(fig)

# 13: per-honeypot top ASN - the independence finding
h=pd.read_csv("parsed4/asn_by_honeypot.csv")
order=["heralding","sip","rdp","cowrie","suricata"]
fig,ax=plt.subplots(figsize=(10,4.2))
labels=[];shares=[];orgs=[]
for s in order:
    g=h[h.source==s]; tot=g.events.sum(); t=g.nlargest(1,"events").iloc[0]
    labels.append(s); shares.append(100*t.events/tot); orgs.append(str(t.asn_org)[:26])
bars=ax.bar(labels,shares,color=ACC1,width=.6)
for b,o,s in zip(bars,orgs,shares):
    ax.text(b.get_x()+b.get_width()/2,s+2,f"{o}\n{s:.0f}%",ha="center",fontsize=8,color=INK)
ax.set_ylim(0,105)
ax.set_ylabel("Share of that honeypot's traffic")
ax.set_title("Dominant ASN per honeypot: five different operators, no overlap",
             loc="left",color=INK,fontweight="bold")
fig.tight_layout();fig.savefig("charts4/13_asn_per_honeypot.png");plt.close(fig)

# 14: raw vs de-skewed geography
c=pd.read_csv("parsed4/country_full_window.csv").head(8)
d=pd.read_csv("parsed4/country_deskewed.csv").head(8)
fig,(a1,a2)=plt.subplots(1,2,figsize=(11,4.0),sharey=False)
a1.barh(c.country.astype(str).iloc[::-1],c.pct_of_total.iloc[::-1],color=ACC3)
a1.set_title("Raw geography",loc="left",color=INK,fontweight="bold")
a1.set_xlabel("% of events")
a2.barh(d.country.astype(str).iloc[::-1],d.pct.iloc[::-1],color=ACC1)
a2.set_title("De-skewed (Contabo removed)",loc="left",color=INK,fontweight="bold")
a2.set_xlabel("% of events")
fig.tight_layout();fig.savefig("charts4/14_geo_raw_vs_deskewed.png");plt.close(fig)

# 15: scanner vs attack
s=pd.read_csv("parsed4/scanner_vs_attack.csv")
sc=s[s.scanner==True].iloc[0]; at=s[s.scanner==False].iloc[0]
fig,(a1,a2)=plt.subplots(1,2,figsize=(9,3.4))
for ax,vals,title in [(a1,[at.ips,sc.ips],"Distinct source IPs"),
                      (a2,[at.events,sc.events],"Events")]:
    ax.bar(["Attack traffic","Research scanners"],vals,color=[ACC1,ACC3],width=.55)
    ax.set_title(title,loc="left",color=INK,fontweight="bold")
    tot=sum(vals)
    for i,v in enumerate(vals):
        ax.text(i,v,f"\n{v:,}\n{100*v/tot:.1f}%",ha="center",va="top",
                fontsize=8,color="white" if v/tot>.5 else INK)
fig.tight_layout();fig.savefig("charts4/15_scanner_vs_attack.png");plt.close(fig)
print("wrote:",*sorted(os.listdir("charts4")),sep="\n  ")
