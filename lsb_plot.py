import io, math
from typing import List
from PIL import Image, ImageDraw

BLOCK_SIZE = 8
QR_SIZE    = 51
THUMB      = 96
PADDING    = 12

#  Helper – pessimistic upper bound for metadata rows
def _estimate_meta_rows(qr_pix: int) -> int:
    worst_bits = 8 + 64 * 8 + 16 + 16 + 8 + 640    # devID + 64-byte sig
    return math.ceil(worst_bits / qr_pix)

#  Main public function
def plot_blue_lsb_pillow(image_bytes: bytes,
                         block_size: int = BLOCK_SIZE,
                         qr_size:   int = QR_SIZE,
                         include_tiles: bool = True) -> bytes:
    """
    Returns PNG bytes visualising the blue-channel LSB plane.
    If include_tiles == True, thumbnails of every QR area are appended below.
    Works with the *new* no-spacing layout.
    """
    # original RGB & sizes
    img  = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    W, H = img.size

    # 1) blue-LSB → greyscale → RGB
    blue = img.split()[2]
    lsb  = blue.point(lambda p: 0 if p & 1 else 255, mode='L')
    vis  = Image.merge("RGB", (lsb, lsb, lsb))
    draw = ImageDraw.Draw(vis, "RGBA")

    # 2) derive tile geometry
    qr_pix    = qr_size * block_size
    meta_rows = _estimate_meta_rows(qr_pix)
    tile_h    = qr_pix + 1 + meta_rows

    tiles_per_row = W // qr_pix
    tiles_per_col = H // tile_h

    # 3) walk the rigid grid, draw outlines & collect thumbnails
    thumbs: List[Image.Image] = []

    for row in range(tiles_per_col):
        off_y = row * tile_h
        for col in range(tiles_per_row):
            off_x = col * qr_pix

            # red rectangle = QR region
            draw.rectangle(
                [off_x, off_y,
                 off_x + qr_pix - 1, off_y + tile_h - 1],
                outline=(255, 0, 0, 255), width=2
            )
            # optional blue rectangle = metadata rows
            draw.rectangle(
                [off_x, off_y + qr_pix + 1,
                 off_x + qr_pix - 1, off_y + tile_h - 1],
                outline=(0, 128, 255, 128), width=1
            )

            if include_tiles:
                tile_crop = vis.crop((off_x, off_y,
                                      off_x + qr_pix, off_y + tile_h))
                thumbs.append(
                    tile_crop.resize((THUMB, THUMB), Image.NEAREST)
                )

    # 4) build final canvas (main image + thumb strip)
    if include_tiles and thumbs:
        thumbs_per_row = max(1, W // THUMB)
        rows_needed    = math.ceil(len(thumbs) / thumbs_per_row)
        strip_height   = rows_needed * THUMB + (rows_needed - 1) * PADDING

        canvas = Image.new("RGB",
                           (W, H + PADDING + strip_height),
                           "white")
        canvas.paste(vis, (0, 0))

        for idx, t in enumerate(thumbs):
            r, c = divmod(idx, thumbs_per_row)
            x = c * THUMB
            y = H + PADDING + r * (THUMB + PADDING)
            canvas.paste(t, (x, y))
    else:
        canvas = vis

    # 5) encode PNG → bytes
    out = io.BytesIO()
    canvas.save(out, format="PNG", optimize=True)
    return out.getvalue()