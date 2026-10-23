import io
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from .common import Artifact, Snapshot

FONTS = Path(__file__).resolve().parent / "fonts"
PAPER, INK, MUTED, WHITE = "#f9f7f2", "#1b2430", "#5b6472", "#ffffff"
SIZES = {"og.png": (1200, 630), "og-github.png": (1280, 640)}


def _font(weight: str, px: float) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / f"IBMPlexMono-{weight}.ttf"), round(px))


def _hatch(img: Image.Image, box: tuple[int, int, int, int], step: int, width: int) -> None:
    x0, y0, x1, y1 = box
    mask = Image.new("L", (x1 - x0, y1 - y0), 0)
    draw = ImageDraw.Draw(mask)
    h = y1 - y0
    for x in range(-h, x1 - x0, step):
        draw.line((x, h, x + h, 0), fill=255, width=width)
    img.paste(INK, box, mask)


def card(s: Snapshot, size: tuple[int, int]) -> bytes:
    w, h = size
    k = h / 630
    left = (w - 1200 * k) / 2 + 72 * k
    right = w - left
    img = Image.new("RGB", size, PAPER)
    draw = ImageDraw.Draw(img)
    small, body, bold = _font("Regular", 24 * k), _font("Regular", 28 * k), _font("SemiBold", 28 * k)

    y = 48 * k
    draw.text((left, y), "MIRAGE-FEED(7)", font=small, fill=INK)
    draw.text((right, y), "OffSeq Mirage", font=small, fill=INK, anchor="ra")
    chip = _font("SemiBold", 22 * k)
    cx0, cx1 = w / 2 - draw.textlength("TLP:CLEAR", font=chip) / 2, w / 2 + draw.textlength("TLP:CLEAR", font=chip) / 2
    draw.rectangle((cx0 - 12 * k, y - 6 * k, cx1 + 12 * k, y + 30 * k), fill=INK)
    draw.text((w / 2, y), "TLP:CLEAR", font=chip, fill=WHITE, anchor="ma")

    draw.text((left, 118 * k), "NAME", font=bold, fill=INK)
    draw.text((left + 56 * k, 158 * k), "mirage-feed - handshake-verified attacker IPs", font=body, fill=INK)

    pub, obs = s.stats["published"], s.stats["observed"]
    listed, seen = int(pub.get("active_24h", 0)), int(obs.get("ips", 0))
    number, caption = f"{listed:,}", ("in the last 24 h are in the feed", f"of {seen:,} source IPs seen")
    room = right - left - 36 * k - max(draw.textlength(c, font=body) for c in caption)
    px = 150
    while draw.textlength(number, font=_font("SemiBold", px * k)) > room and px > 60:
        px -= 10
    big = _font("SemiBold", px * k)
    draw.text((left, 355 * k), number, font=big, fill=INK, anchor="ls")
    text_x = left + draw.textlength(number, font=big) + 36 * k
    draw.text((text_x, 262 * k), caption[1], font=body, fill=INK)
    draw.text((text_x, 302 * k), caption[0], font=body, fill=INK)

    bar_top, bar_bottom = round(410 * k), round(456 * k)
    x0, x1 = round(left), round(right)
    _hatch(img, (x0, bar_top, x1, bar_bottom), max(8, round(12 * k)), max(1, round(2 * k)))
    if seen:
        fill_x = x0 + round((x1 - x0) * min(listed, seen) / seen)
        draw.rectangle((x0, bar_top, fill_x, bar_bottom), fill=INK)
    draw.rectangle((x0, bar_top, x1, bar_bottom), outline=INK, width=max(2, round(2 * k)))
    draw.text((left, bar_bottom + 14 * k), f"listed {listed:,}", font=small, fill=INK)
    draw.text((right, bar_bottom + 14 * k), f"seen {seen:,}", font=small, fill=MUTED, anchor="ra")

    draw.line((left, 548 * k, right, 548 * k), fill=INK, width=max(1, round(k)))
    draw.text((left, 566 * k), f"feeds.offseq.com · {s.day}", font=small, fill=INK)
    draw.text((right, 566 * k), "MIRAGE-FEED(7)", font=small, fill=INK, anchor="ra")

    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=False, compress_level=9)
    return buf.getvalue()


def render(s: Snapshot) -> list[Artifact]:
    return [Artifact(path, card(s, size), "png", 1, None, ("social",)) for path, size in SIZES.items()]
