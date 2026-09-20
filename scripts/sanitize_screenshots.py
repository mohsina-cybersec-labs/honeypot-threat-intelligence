#!/usr/bin/env python3
"""
sanitize_screenshots.py

Crops browser chrome and desktop furniture out of the scrapbook screenshots.
The honeypot's IP address appeared in every URL bar and two captures included
the full macOS desktop, so the content region is detected and everything
outside it is discarded rather than blurred.
"""
import os, glob
import numpy as np
from PIL import Image

SRC = "sb"
OUT = "screenshots_clean"
os.makedirs(OUT, exist_ok=True)

# Kibana and the T-Pot attack map render on a dark background. Browser chrome,
# the macOS menu bar and the dock are light. Find the dark block and keep it.
DARK = 95


def content_box(im, pad=2):
    g = np.array(im.convert("L"), dtype=np.float32)
    rows = g.mean(axis=1)
    cols = g.mean(axis=0)
    dark_rows = np.where(rows < DARK)[0]
    dark_cols = np.where(cols < DARK)[0]
    if len(dark_rows) < 30 or len(dark_cols) < 30:
        return None
    # largest contiguous dark run vertically, so a dark wallpaper strip at the
    # bottom does not drag the box past the dashboard
    runs, start = [], dark_rows[0]
    for a, b in zip(dark_rows, dark_rows[1:]):
        if b - a > 6:
            runs.append((start, a))
            start = b
    runs.append((start, dark_rows[-1]))
    top, bottom = max(runs, key=lambda r: r[1] - r[0])
    left, right = dark_cols[0], dark_cols[-1]
    if bottom - top < 120 or right - left < 200:
        return None
    return (max(0, left - pad), max(0, top - pad),
            min(im.width, right + pad), min(im.height, bottom + pad))


# light-background captures (NVD pages): fixed top crop removes the tab strip
# and address bar, which is where the honeypot URL was visible
LIGHT_CROP_TOP = {"img-021.png": 0.055, "img-022.png": 0.0}

RENAME = {
    "img-000.png": "01-attack-map-first-contact",
    "img-001.png": "02-attack-map-first-hour",
    "img-002.png": "03-dashboard-72h-aug28",
    "img-003.png": "04-tagclouds-aug28",
    "img-004.png": "05-dashboard-24h-aug30-vnc-onset",
    "img-005.png": "06-tagclouds-aug30-24h",
    "img-006.png": "07-dashboard-5day-aug30",
    "img-007.png": "08-tagclouds-aug30-5day",
    "img-008.png": "09-dashboard-24h-sep05-vnc-dormant",
    "img-009.png": "10-tagclouds-sep05-first-cve",
    "img-010.png": "11-dashboard-10day-sep05",
    "img-011.png": "12-tagclouds-sep05-10day",
    "img-012.png": "13-dashboard-24h-sep12-vnc-returns",
    "img-013.png": "14-tagclouds-sep12",
    "img-014.png": "15-asn-tables-sep12",
    "img-015.png": "16-dashboard-full-window-4m",
    "img-016.png": "17-tagclouds-full-window-both-cves",
    "img-017.png": "18-sep12-burst-window",
    "img-018.png": "19-sep12-burst-tagclouds",
    "img-019.png": "20-sep12-burst-asn",
    "img-020.png": "21-attack-map-live-sep15",
    "img-021.png": "22-nvd-cve-2020-11910",
    "img-022.png": "23-nvd-cve-2020-5902",
}

report = []
for f in sorted(glob.glob(f"{SRC}/img-*.png")):
    base = os.path.basename(f)
    im = Image.open(f).convert("RGB")
    before = im.size

    if base in LIGHT_CROP_TOP:
        top = int(im.height * LIGHT_CROP_TOP[base])
        im = im.crop((0, top, im.width, im.height))
        method = f"fixed top crop {LIGHT_CROP_TOP[base]:.1%}"
    else:
        box = content_box(im)
        if box:
            im = im.crop(box)
            method = "content-region detect"
        else:
            method = "NO CROP (review)"

    name = RENAME.get(base, base.replace(".png", "")) + ".png"
    im.save(f"{OUT}/{name}", optimize=True)
    report.append((name, before, im.size, method))

print(f"{'file':44s} {'before':>12s} {'after':>12s}  method")
for n, b, a, m in report:
    print(f"{n:44s} {str(b):>12s} {str(a):>12s}  {m}")
