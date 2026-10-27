#!/usr/bin/env python3
"""Draw the LGroot app icon and convert it to assets/AppIcon.icns.

Everything is drawn procedurally with signed distance fields, so the script
needs nothing beyond the Python standard library plus the macOS `sips` and
`iconutil` tools that ship with the OS.

    python3 scripts/make_icon.py
"""

import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

SIZE = 1024


def smoothstep(edge0, edge1, x):
    if edge0 == edge1:
        return 0.0 if x < edge0 else 1.0
    t = (x - edge0) / (edge1 - edge0)
    t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)
    return t * t * (3.0 - 2.0 * t)


def sd_round_rect(px, py, cx, cy, hw, hh, r):
    qx = abs(px - cx) - (hw - r)
    qy = abs(py - cy) - (hh - r)
    ax = max(qx, 0.0)
    ay = max(qy, 0.0)
    return math.hypot(ax, ay) + min(max(qx, qy), 0.0) - r


def sd_segment(px, py, ax, ay, bx, by):
    pax, pay = px - ax, py - ay
    bax, bay = bx - ax, by - ay
    denom = bax * bax + bay * bay
    h = 0.0 if denom == 0.0 else (pax * bax + pay * bay) / denom
    h = 0.0 if h < 0.0 else (1.0 if h > 1.0 else h)
    return math.hypot(pax - bax * h, pay - bay * h)


def mix(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(3))


def over(dst, src, alpha):
    """Composite a straight-alpha colour over an opaque RGB destination."""
    return tuple(dst[i] * (1.0 - alpha) + src[i] * alpha for i in range(3))


def render():
    bg_top = (0x1B, 0x21, 0x2C)
    bg_bottom = (0x0E, 0x10, 0x15)
    blue = (0x3E, 0xA6, 0xFF)
    green = (0x4A, 0xDE, 0x80)
    screen_fill = (0x12, 0x16, 0x1C)

    body_hw = SIZE / 2 - 28
    body_hh = SIZE / 2 - 28
    body_r = 190.0

    # TV screen, in icon coordinates.
    scx, scy = SIZE / 2, 470.0
    shw, shh = 300.0, 190.0
    sr = 46.0
    stroke = 26.0

    rows = []
    for y in range(SIZE):
        row = bytearray()
        row.append(0)  # PNG filter: none
        py = y + 0.5
        for x in range(SIZE):
            px = x + 0.5

            body = sd_round_rect(px, py, SIZE / 2, SIZE / 2, body_hw, body_hh, body_r)
            body_a = 1.0 - smoothstep(-1.0, 1.0, body)
            if body_a <= 0.001:
                row.extend(b"\x00\x00\x00\x00")
                continue

            t = y / (SIZE - 1)
            color = mix(bg_top, bg_bottom, t)

            # A soft blue glow rising from the bottom edge.
            glow = smoothstep(0.0, 1.0, (y - SIZE * 0.45) / (SIZE * 0.55))
            color = over(color, blue, 0.10 * glow)

            # Inner hairline border.
            ring = abs(body + 14.0) - 2.0
            color = over(color, blue, 0.35 * (1.0 - smoothstep(-1.0, 1.0, ring)))

            # TV screen: dark fill plus a bright outline.
            screen = sd_round_rect(px, py, scx, scy, shw, shh, sr)
            fill_a = 1.0 - smoothstep(-1.0, 1.0, screen)
            color = over(color, screen_fill, fill_a)

            edge = abs(screen + stroke / 2) - stroke / 2
            color = over(color, blue, 1.0 - smoothstep(-1.2, 1.2, edge))

            # Stand.
            neck = sd_round_rect(px, py, scx, scy + shh + 26, 46.0, 26.0, 10.0)
            color = over(color, blue, 1.0 - smoothstep(-1.0, 1.0, neck))
            base = sd_round_rect(px, py, scx, scy + shh + 62, 132.0, 14.0, 12.0)
            color = over(color, blue, 1.0 - smoothstep(-1.0, 1.0, base))

            # Check mark inside the screen.
            d = min(
                sd_segment(px, py, scx - 108, scy + 4, scx - 28, scy + 84),
                sd_segment(px, py, scx - 28, scy + 84, scx + 116, scy - 78),
            )
            check = d - 25.0
            color = over(color, green, 1.0 - smoothstep(-1.2, 1.2, check))

            r = int(round(min(255.0, max(0.0, color[0]))))
            g = int(round(min(255.0, max(0.0, color[1]))))
            b = int(round(min(255.0, max(0.0, color[2]))))
            a = int(round(255.0 * body_a))
            row.extend(bytes((r, g, b, a)))
        rows.append(bytes(row))
    return b"".join(rows)


def write_png(path, raw, size):
    def chunk(tag, data):
        out = struct.pack(">I", len(data)) + tag + data
        return out + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n")
        fh.write(chunk(b"IHDR", ihdr))
        fh.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        fh.write(chunk(b"IEND", b""))


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "assets", "AppIcon.icns")

    if sys.platform != "darwin":
        print("iconutil is macOS-only; skipping icon build", file=sys.stderr)
        return 1

    work = tempfile.mkdtemp(prefix="lgroot-icon-")
    try:
        master = os.path.join(work, "master.png")
        write_png(master, render(), SIZE)

        iconset = os.path.join(work, "AppIcon.iconset")
        os.makedirs(iconset)
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                px = size * scale
                name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
                subprocess.run(
                    ["sips", "-z", str(px), str(px), master, "--out", os.path.join(iconset, name)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

        subprocess.run(
            ["iconutil", "-c", "icns", iconset, "-o", out],
            check=True,
        )
        print("wrote", out)
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
