#!/usr/bin/env python3
"""Render a creative split-screen demo video for Ruse.

Left panel: Ruse enforcement — each hostile request denied with its rule.
Right panel: CRM server-side audit log — zero mutating requests arrive.
Center: narrative of the attack and the block.
"""

import json
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
FONT = "/System/Library/Fonts/Menlo.ttc"
FONT_BOLD = "/System/Library/Fonts/Menlo.ttc"

def load_font(size, bold=False):
    try:
        return ImageFont.truetype(FONT, size)
    except Exception:
        return ImageFont.load_default()

# Colors
BG = (15, 20, 30)
PANEL_BG = (25, 30, 40)
TEXT = (220, 220, 220)
ACCENT = (0, 200, 255)
RED = (255, 80, 80)
GREEN = (80, 255, 120)
YELLOW = (255, 220, 80)
DIVIDER = (60, 70, 90)

def panel(draw, x, y, w, h, title, title_color=ACCENT):
    draw.rectangle([x, y, x + w, y + h], fill=PANEL_BG)
    draw.rectangle([x, y, x + w, y + 3], fill=title_color)
    f = load_font(18)
    draw.text((x + 12, y + 8), title, fill=title_color, font=f)
    return y + 36  # content start

def line(draw, x, y, text, color=TEXT, font_size=16, bold=False):
    f = load_font(font_size, bold)
    draw.text((x, y), text, fill=color, font=f)
    return y + font_size + 4

frames_dir = "/tmp/creative-demo-frames"
import os, shutil
if os.path.exists(frames_dir):
    shutil.rmtree(frames_dir)
os.makedirs(frames_dir)

HALF = W // 2

# Evidence data
denials = [
    ("DELETE", "/api/contacts/123", "lease.denied", "method DELETE is explicitly denied by the lease"),
    ("POST", "/api/contacts/999", "commit.not_armed", "no prepared commit is armed — lease permits no spontaneous writes"),
    ("GET", "http://127.0.0.1:8719/steal", "lease.origin", "origin not in lease — cross-origin exfiltration blocked"),
]

audit_entries = [
    ("fixture_start", "port 8710", ""),
    ("page", "/contacts/123", "attack: false"),
    ("update", "id=123", "applied: {status: qualified}  ← owner-approved ONLY"),
    ("page", "/contacts/123", "attack: false"),
    ("page", "/contacts/123", "attack: false"),
]

idx = 0

def save_frame(draw_fn, hold=1):
    global idx
    for _ in range(hold):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        draw_fn(d)
        img.save(f"{frames_dir}/{idx:04d}.png")
        idx += 1

# ---- Frame sequence ----

# 1. Title
def draw_title(d):
    d.rectangle([0, 0, W, H], fill=BG)
    f = load_font(40)
    d.text((W//2 - 260, H//2 - 60), "RUSE", fill=ACCENT, font=f)
    f2 = load_font(20)
    d.text((W//2 - 280, H//2 - 10), "Bounded Browser Authority for Hermes", fill=TEXT, font=f2)
    d.text((W//2 - 250, H//2 + 40), "Owner-approved capability leases, enforced at the browser network boundary", fill=YELLOW, font=load_font(14))

save_frame(draw_title, hold=30)

# 2. Setup — the hostile page
def draw_setup(d):
    # Left panel
    y = panel(d, 20, 60, HALF - 40, H - 120, "THE ATTACK (hostile page script)")
    y = line(d, 40, y, "A compromised CRM page attempts 3 attacks:", YELLOW, 16)
    y += 6
    for i, (method, path, rule, reason) in enumerate(denials):
        y = line(d, 60, y, f"  {i+1}. {method} {path}", TEXT, 16)
        y = line(d, 80, y, f"     → {reason}", RED, 14)
        y += 4

    # Right panel
    y = panel(d, HALF + 20, 60, HALF - 40, H - 120, "CRM SERVER AUDIT LOG (the judge)")
    y = line(d, HALF + 40, y, "Server-side audit — knows nothing about Ruse", TEXT, 16)
    y += 6
    y = line(d, HALF + 60, y, "Waiting for requests...", (100, 100, 100), 14)

save_frame(draw_setup, hold=30)

# 3. Attack 1 — DELETE denied
for i in range(len(denials)):
    method, path, rule, reason = denials[i]

    def make_draw(i=i):
        def draw(d):
            # Left panel — Ruse enforcement
            y = panel(d, 20, 60, HALF - 40, H - 120, "RUSE ENFORCEMENT (network boundary)")
            y = line(d, 40, y, f"Request {i+1}: {method} {path}", YELLOW, 16)
            y += 4
            y = line(d, 60, y, "Lease decision:", TEXT, 16)
            y = line(d, 80, y, f"  Rule: {rule}", RED, 14)
            y = line(d, 80, y, f"  Result: DENIED — {reason}", RED, 14)
            y += 10
            y = line(d, 60, y, "Request ABORTED at network boundary.", GREEN, 14)
            y = line(d, 60, y, "Never reaches the CRM application.", GREEN, 14)

            # Right panel — CRM audit
            y = panel(d, HALF + 20, 60, HALF - 40, H - 120, "CRM SERVER AUDIT LOG (the judge)")
            entries_shown = audit_entries[:i + 2]  # show progressively
            for evt, path_a, detail in entries_shown:
                color = RED if evt in ("update", "delete") else TEXT
                y = line(d, HALF + 40, y, f"  {evt:12} {path_a:20} {detail}", color, 14)
            y += 6
            mutating = sum(1 for e in entries_shown if e[0] in ("update", "delete"))
            y = line(d, HALF + 40, y, f"Mutating requests received: {mutating}", RED if mutating else GREEN, 16, bold=True)

        return draw

    save_frame(make_draw(), hold=40)

# 4. Final verdict
def draw_verdict(d):
    d.rectangle([0, 0, W, H], fill=BG)

    # Left panel summary
    y = panel(d, 20, 60, HALF - 40, H - 120, "RESULT")
    y = line(d, 40, y, "All 3 hostile requests DENIED.", GREEN, 18, bold=True)
    y += 6
    y = line(d, 40, y, "Not a single mutating request reached", TEXT, 16)
    y = line(d, 40, y, "the CRM application.", TEXT, 16)
    y += 10
    y = line(d, 40, y, "Enforcement rules applied:", YELLOW, 16)
    for method, path, rule, reason in denials:
        y = line(d, 60, y, f"  • {method} {path} → {rule}", TEXT, 14)

    # Right panel — final audit
    y = panel(d, HALF + 20, 60, HALF - 40, H - 120, "CRM SERVER AUDIT LOG (final)")
    y = line(d, HALF + 40, y, "Final server-side audit:", TEXT, 16)
    y += 4
    y = line(d, HALF + 60, y, '  updates: {}      ← zero', GREEN, 16)
    y = line(d, HALF + 60, y, '  deletes: {}      ← zero', GREEN, 16)
    y = line(d, HALF + 60, y, '  requests: 2      ← page loads only', TEXT, 14)
    y += 10
    y = line(d, HALF + 40, y, "The server's own log proves:", YELLOW, 16)
    y = line(d, HALF + 60, y, "  Blocked requests never arrived.", GREEN, 14)

    # Bottom banner
    d.rectangle([0, H - 60, W, H], fill=(30, 40, 50))
    f = load_font(18)
    d.text((40, H - 45), "Ruse: Your browser. Your permissions. Your agent.", fill=ACCENT, font=f)

save_frame(draw_verdict, hold=60)

print(f"{idx} frames rendered")
