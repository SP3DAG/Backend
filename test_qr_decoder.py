import json
from pathlib import Path
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from decoding.decoding import (
    decode_qr,
    extract_qr_matrix,
    verify_tile,
    QR_PIX
)

IMAGE_PATH = Path("/Users/moritzdenk/Documents/IMG_2201.PNG")
KEYS_PATH  = Path("/Users/moritzdenk/Documents/public_keys.json")

def load_public_keys(p: Path):
    with open(p, "r") as f:
        raw = json.load(f)
    return {k: load_pem_public_key(v.encode()) for k, v in raw.items()}

def show_all_verified_qrs(image_path: Path, keys: dict):
    print("Scanning:", image_path)
    img = Image.open(image_path).convert("RGB")
    px  = np.array(img)
    h, w = px.shape[:2]
    cols = w // QR_PIX
    rows = h // QR_PIX
    verified = 0

    for ty in range(rows):
        for tx in range(cols):
            x0, y0 = tx * QR_PIX, ty * QR_PIX
            tile   = px[y0:y0 + QR_PIX, x0:x0 + QR_PIX]
            try:
                qr_mat  = extract_qr_matrix(px, x0, y0)
                payload = decode_qr(qr_mat)
                device_id = payload["device_id"]
                pubkey = keys[device_id]
                verify_tile(payload, tile, pubkey)
                verified += 1
                print(f"verified tile: {tx} {ty}")
            except Exception as exc:
                print(f"skipped tile: {tx} {ty} – {type(exc).__name__}: {exc}")

    print("verified tiles:", verified)

if __name__ == "__main__":
    keys = load_public_keys(KEYS_PATH)
    show_all_verified_qrs(IMAGE_PATH, keys)