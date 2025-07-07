import math
import io
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from PIL import Image


def plot_blue_lsb(image_bytes: bytes,
                  block_size: int = 8,
                  qr_size: int = 51,
                  spacing_px: int = 20) -> bytes:
    """
    Takes raw image bytes (PNG or JPEG), returns PNG bytes visualizing:
      - blue-channel LSB
      - red boxes where QR tiles would be embedded
    """
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    px = np.array(img)
    H, W = px.shape[:2]
    blue_lsb = (px[:, :, 2] & 1) * 255

    qr_pix = qr_size * block_size
    meta_rows = 12  # conservative upper bound
    tile_h = qr_pix + 1 + meta_rows

    fig, ax = plt.subplots(figsize=(8, 8))
    ax.imshow(blue_lsb, cmap="gray", interpolation="nearest")
    ax.set_title("Blue LSB Plane with Tile Outlines")
    ax.axis("off")

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
            rect = plt.Rectangle((off_x, off_y), qr_pix, qr_pix,
                                 linewidth=1.5, edgecolor='red', facecolor='none')
            ax.add_patch(rect)
            col += 1
        row += 1

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf.read()