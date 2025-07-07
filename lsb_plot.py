import io
import math

from PIL import Image, ImageDraw


BLOCK_SIZE = 8
QR_SIZE    = 51
SPACING_PX = 20


def _estimate_meta_rows(qr_pix: int) -> int:
    """Conservative upper bound – keeps the red-box grid correct."""
    worst_bits = 8 + 64*8 + 16 + 16 + 8 + 640
    return math.ceil(worst_bits / qr_pix)


def plot_blue_lsb_pillow(image_bytes: bytes,
                         block_size: int = BLOCK_SIZE,
                         qr_size: int   = QR_SIZE,
                         spacing_px: int = SPACING_PX) -> bytes:
    """
    Return PNG bytes visualising the blue-channel LSB plane plus red rectangles
    where each QR tile is expected.
    """
    img  = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    W, H = img.size

    # 1) isolate blue-channel LSB as black/white mask
    blue = img.split()[2]
    lsb  = blue.point(lambda p: 0 if p & 1 else 255, mode='L')
    vis  = Image.merge("RGB", (lsb, lsb, lsb))

    draw = ImageDraw.Draw(vis, "RGBA")

    qr_pix    = qr_size * block_size
    meta_rows = _estimate_meta_rows(qr_pix)
    tile_h    = qr_pix + 1 + meta_rows

    # 2) add red rectangles
    row = 0
    while True:
        off_y = int(round(row * (tile_h + spacing_px)))
        if off_y + qr_pix > H:
            break
        col = 0
        while True:
            off_x = int(round(col * (qr_pix + spacing_px)))
            if off_x + qr_pix > W:
                break
            draw.rectangle(
                [off_x, off_y, off_x + qr_pix - 1, off_y + qr_pix - 1],
                outline=(255, 0, 0, 255), width=2
            )
            col += 1
        row += 1

    # 3) encode PNG → bytes
    out = io.BytesIO()
    vis.save(out, format="PNG", optimize=True)
    return out.getvalue()