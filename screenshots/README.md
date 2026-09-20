# Collection screenshots

These are Kibana dashboard captures taken at each health checkpoint during the 21-day
collection window, plus the two NVD pages used to verify the CVE findings.

They are here as a record of what the live deployment looked like, not as evidence for the
analysis. Every figure in the report is regenerated in Python from raw logs by the scripts
in [`../scripts/`](../scripts/), which is stronger provenance than a screenshot. Where a
number in a capture disagrees with the report, the report is correct and section 8 explains
why.

**Sanitization.** Browser chrome was cropped from every capture. The honeypot's address was
visible in each URL bar, and two captures included the full desktop. The crop is done by
[`../scripts/sanitize_screenshots.py`](../scripts/sanitize_screenshots.py), which detects
the content region and discards everything outside it. Attacker addresses visible inside
the dashboards are unredacted.

---

## Collection start

| File | What it shows |
|---|---|
| `01-attack-map-first-contact.png` | The attack map minutes after exposure. 31 attacks in the first minute, 155 in the first hour. The live feed shows the first contact source hitting the printer honeypot on port 9100. |
| `02-attack-map-first-hour.png` | Same view a few minutes later, 245 events. RDP traffic has started arriving alongside the printer probes. |

## August 28, 72-hour checkpoint

| File | What it shows |
|---|---|
| `03-dashboard-72h-aug28.png` | 270k events across three days. Honeytrap and Sentrypeer lead; the VNC campaign has not started. |
| `04-tagclouds-aug28.png` | **The panel behind correction 1.** The username and password tagclouds sit side by side and aggregate across every honeypot at once, with no indication of which one produced any given term. |

## August 30, VNC campaign onset

| File | What it shows |
|---|---|
| `05-dashboard-24h-aug30-vnc-onset.png` | 210k in 24 hours, Heralding at 111k. This is the day the VNC campaign peaked. |
| `06-tagclouds-aug30-24h.png` | Port 5900 dominates the destination-port donuts. |
| `07-dashboard-5day-aug30.png` | 575k across five days, showing how fast Heralding overtook everything else. |
| `08-tagclouds-aug30-5day.png` | Five-day credential view, where the vendor-default set is visible. |

## September 5, the checkpoint that produced a wrong conclusion

| File | What it shows |
|---|---|
| `09-dashboard-24h-sep05-vnc-dormant.png` | Heralding down to 7k from 111k. **This 94% drop is what led to the conclusion that the campaign had ended.** It had not; it was dormant and returned three days later at higher volume. |
| `10-tagclouds-sep05-first-cve.png` | First CVE-tagged alert of the window appears in the Suricata CVE panel. |
| `11-dashboard-10day-sep05.png` | One million honeypot events at the ten-day mark. |
| `12-tagclouds-sep05-10day.png` | Ten-day credential and ASN view. |

## September 12, the campaign returns

| File | What it shows |
|---|---|
| `13-dashboard-24h-sep12-vnc-returns.png` | 450k in 24 hours, the highest of the window. Heralding back to 178k. Same provider, same protocol, same port as the August wave. |
| `14-tagclouds-sep12.png` | France back on top, port donut almost entirely 5900. |
| `15-asn-tables-sep12.png` | The ASN table showing the return, alongside a second concurrent SIP campaign. |

## September 12 burst

| File | What it shows |
|---|---|
| `18-sep12-burst-window.png` | The four-hour burst window isolated. 148k events, Sentrypeer 85k. |
| `19-sep12-burst-tagclouds.png` | Credentials seen only during the burst, including a sequential date-pattern wordlist. |
| `20-sep12-burst-asn.png` | 83,902 of 83,961 burst events from a single address. |

## September 15, teardown

| File | What it shows |
|---|---|
| `16-dashboard-full-window-4m.png` | The full 21-day view. 4m honeypot attacks, Heralding and Honeytrap at 1m each. |
| `17-tagclouds-full-window-both-cves.png` | Full-window credential profile, with both CVE-tagged signatures visible in the Suricata CVE panel. |
| `21-attack-map-live-sep15.png` | The attack map on the final day, 182,366 events in 24 hours. |

## CVE verification

| File | What it shows |
|---|---|
| `22-nvd-cve-2020-11910.png` | NVD entry for the Ripple20 Treck ICMPv4 flaw. Note NVD scores it 5.3 MEDIUM while CISA-ADP scores it 9.8 CRITICAL. |
| `23-nvd-cve-2020-5902.png` | NVD entry for the F5 BIG-IP TMUI remote code execution flaw, 9.8 CRITICAL, CISA KEV listed. |
