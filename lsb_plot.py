import io
import math
from typing import List
from PIL import Image, ImageDraw

# --- constants that must match the encoder defaults -----------------------
BLOCK_SIZE = 8
QR_SIZE    = 51
SPACER     = 1
THUMB      = 96
PADDING    = 12

# pessimistic bit budget: dev-ID len byte + 64-byte signature
def _estimate_meta_rows(qr_pix: int) -> int:
    worst_bits = 8 + 64*8 + 16 + 16 + 8 + 640
    return math.ceil(worst_bits / qr_pix)

def plot_blue_lsb_pillow(image_bytes: bytes,
                         block_size: int = BLOCK_SIZE,
                         qr_size:   int = QR_SIZE,
                         include_tiles: bool = True) -> bytes:
    """
    Visualises the blue-channel LSB plane and outlines every tile.
    Returns PNG bytes.
    """
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    W, H = img.size

    # blue-LSB layer
    blue = img.split()[2]
    lsb  = blue.point(lambda p: 0 if p & 1 else 255, mode='L')
    vis  = Image.merge("RGB", (lsb, lsb, lsb))
    draw = ImageDraw.Draw(vis, "RGBA")

    # replicate encoder geometry
    qr_pix_min   = qr_size * block_size
    meta_rows_min = _estimate_meta_rows(qr_pix_min)
    tile_min_w   = qr_pix_min
    tile_min_h   = qr_pix_min + SPACER + meta_rows_min

    tiles_per_row = math.ceil(W / tile_min_w)
    tiles_per_col = math.ceil(H / tile_min_h)

    tile_w = W // tiles_per_row
    tile_h = H // tiles_per_col

    qr_pix = tile_w
    eff_bl = qr_pix // qr_size

    thumbs: List[Image.Image] = []

    for r in range(tiles_per_col):
        off_y = r * tile_h
        for c in range(tiles_per_row):
            off_x = c * tile_w

            # outline full tile
            draw.rectangle(
                [off_x, off_y,
                 off_x + tile_w - 1, off_y + tile_h - 1],
                outline=(255, 0, 0, 255), width=2
            )

            # optional: thumbnail of the QR area only
            if include_tiles:
                qr_crop = vis.crop((off_x, off_y,
                                    off_x + qr_pix, off_y + qr_pix))
                thumbs.append(qr_crop.resize((THUMB, THUMB), Image.NEAREST))

    # combine main image + thumbnails
    if include_tiles and thumbs:
        thumbs_per_row = max(1, W // THUMB)
        rows_needed    = math.ceil(len(thumbs) / thumbs_per_row)
        strip_h        = rows_needed * THUMB + (rows_needed - 1) * PADDING

        canvas = Image.new("RGB", (W, H + PADDING + strip_h), "white")
        canvas.paste(vis, (0, 0))

        for idx, t in enumerate(thumbs):
            r, c = divmod(idx, thumbs_per_row)
            x = c * THUMB
            y = H + PADDING + r * (THUMB + PADDING)
            canvas.paste(t, (x, y))
    else:
        canvas = vis

    out = io.BytesIO()
    canvas.save(out, format="PNG", optimize=True)
    return out.getvalue()