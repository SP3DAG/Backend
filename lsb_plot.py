import io, math
from typing import List
from PIL import Image, ImageDraw

BLOCK_SIZE = 8
QR_SIZE    = 51
SPACING_PX = 20
THUMB      = 96      # px per tile thumbnail
PADDING    = 12      # gap between main image and thumbnails


def _estimate_meta_rows(qr_pix: int) -> int:
    worst_bits = 8 + 64*8 + 16 + 16 + 8 + 640
    return math.ceil(worst_bits / qr_pix)


def plot_blue_lsb_pillow(image_bytes: bytes,
                         block_size: int = BLOCK_SIZE,
                         qr_size: int   = QR_SIZE,
                         spacing_px: int = SPACING_PX,
                         include_tiles: bool = True) -> bytes:
    """
    Returns PNG bytes visualising the blue-channel LSB plane.
    If include_tiles == True, thumbnails of every tile are appended below.
    """
    img  = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    W, H = img.size

    # 1) blue-LSB plane → greyscale → RGB (so we can draw in colour)
    blue = img.split()[2]
    lsb  = blue.point(lambda p: 0 if p & 1 else 255, mode='L')
    vis  = Image.merge("RGB", (lsb, lsb, lsb))
    draw = ImageDraw.Draw(vis, "RGBA")

    qr_pix    = qr_size * block_size
    meta_rows = _estimate_meta_rows(qr_pix)
    tile_h    = qr_pix + 1 + meta_rows

    # 2) collect tile thumbnails while drawing rectangles
    thumbs: List[Image.Image] = []

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

            # red outline
            draw.rectangle(
                [off_x, off_y, off_x + qr_pix - 1, off_y + qr_pix - 1],
                outline=(255, 0, 0, 255), width=2
            )

            if include_tiles:
                tile_crop = vis.crop((off_x, off_y,
                                      off_x + qr_pix, off_y + qr_pix))
                thumbs.append(tile_crop.resize((THUMB, THUMB), Image.NEAREST))

            col += 1
        row += 1

    # 3) build final canvas
    if include_tiles and thumbs:
        thumbs_per_row = math.floor(W / THUMB)
        rows_needed    = math.ceil(len(thumbs) / thumbs_per_row)
        strip_height   = rows_needed * THUMB + (rows_needed - 1) * PADDING

        canvas = Image.new("RGB", (W, H + PADDING + strip_height), "white")
        canvas.paste(vis, (0, 0))

        for idx, t in enumerate(thumbs):
            r, c = divmod(idx, thumbs_per_row)
            x = c * THUMB
            y = H + PADDING + r * (THUMB + PADDING)
            canvas.paste(t, (x, y))
    else:
        canvas = vis

    # 4) encode PNG → bytes
    out = io.BytesIO()
    canvas.save(out, format="PNG", optimize=True)
    return out.getvalue()