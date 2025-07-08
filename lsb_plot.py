import io
import math
from typing import List
from PIL import Image, ImageDraw

#  Encoder-matching constants

BLOCK_SIZE = 8          # same as `blockSize` you pass to QRSteganography
QR_SIZE    = 51         # fixed‐side QR version
SPACER     = 1          # 1-px gap between QR block and metadata rows
THUMB      = 96         # size of little previews under the main image
PADDING    = 12         # gap between preview rows

WORST_BITS = 8 + 256 + 16 + 16 + 8 + 640   # 944 bits

def _estimate_meta_rows(qr_pix: int) -> int:
    """Return the worst-case row count for the metadata area."""
    return math.ceil(WORST_BITS / qr_pix)

#  Visualiser
def plot_blue_lsb_pillow(image_bytes: bytes,
                         block_size: int = BLOCK_SIZE,
                         qr_size:   int = QR_SIZE,
                         include_tiles: bool = True) -> bytes:
    """
    Render the blue-channel LSB plane, draw every tile rectangle in RED,
    and (optionally) append little thumbnails of each QR block.
    Returns PNG bytes.
    """
    img  = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    W, H = img.size

    # Blue-LSB layer → white=0  black=1 for visibility
    blue = img.split()[2]
    lsb  = blue.point(lambda p: 0 if p & 1 else 255, mode="L")
    vis  = Image.merge("RGB", (lsb, lsb, lsb))
    draw = ImageDraw.Draw(vis, "RGBA")

    # Geometry replicated from the Swift encoder
    qr_pix        = qr_size * block_size
    meta_rows     = _estimate_meta_rows(qr_pix)
    tile_w        = qr_pix
    tile_h        = qr_pix + SPACER + meta_rows

    # Swift uses *integer division* (floor) to decide how many tiles fit
    tiles_per_row = max(1, W // tile_w)
    tiles_per_col = max(1, H // tile_h)

    thumbs: List[Image.Image] = []

    for r in range(tiles_per_col):
        off_y = r * tile_h
        for c in range(tiles_per_row):
            off_x = c * tile_w

            # Outline the full tile
            draw.rectangle(
                [off_x, off_y,
                 off_x + tile_w - 1, off_y + tile_h - 1],
                outline=(255, 0, 0, 255), width=2
            )

            # Collect thumbnail of the QR area
            if include_tiles:
                qr_crop = vis.crop((
                    off_x, off_y,
                    off_x + qr_pix, off_y + qr_pix
                ))
                thumbs.append(qr_crop.resize(
                    (THUMB, THUMB), Image.NEAREST))

    # compose final canvas
    if include_tiles and thumbs:
        thumbs_per_row = max(1, W // THUMB)
        rows_needed    = math.ceil(len(thumbs) / thumbs_per_row)
        strip_h        = rows_needed * THUMB + (rows_needed - 1) * PADDING

        canvas = Image.new("RGB",
                           (W, H + PADDING + strip_h),
                           "white")
        canvas.paste(vis, (0, 0))

        for idx, thumb in enumerate(thumbs):
            r, c = divmod(idx, thumbs_per_row)
            x = c * THUMB
            y = H + PADDING + r * (THUMB + PADDING)
            canvas.paste(thumb, (x, y))
    else:
        canvas = vis

    buf = io.BytesIO()
    canvas.save(buf, format="PNG", optimize=True)
    return buf.getvalue()