import os, json, hashlib
from typing import List, Dict

import numpy as np
from PIL import Image
import cv2
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# constants
BLOCK_SIZE = 8
MODULES    = 125
QR_PIX     = BLOCK_SIZE * MODULES

PUBLIC_KEY_FOLDER = "/var/data/public_keys"

# public-key helper
def get_public_key(device_id: str):
    path = os.path.join(PUBLIC_KEY_FOLDER, f"{device_id}.pem")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No public key for {device_id}")
    with open(path, "rb") as fh:
        return load_pem_public_key(fh.read())

# QR extraction helpers
def extract_qr_matrix(px: np.ndarray, off_x: int, off_y: int) -> List[List[int]]:
    """Return a MODULES×MODULES matrix of 0/1 bits (blue-channel LSB)."""
    return [
        [
            px[off_y + y * BLOCK_SIZE,
               off_x + x * BLOCK_SIZE, 2] & 1
            for x in range(MODULES)
        ]
        for y in range(MODULES)
    ]

# bigger quiet zone + higher up-scale
def qr_matrix_to_cv(qr: List[List[int]],
                    quiet: int = 8,
                    scale: int = 10) -> np.ndarray:
    """
    Renders the binary matrix to a uint8 OpenCV image:
      • `quiet` white modules on every side
      • `scale`× nearest-neighbour up-scaling for crisp edges
    """
    side = MODULES + 2 * quiet
    img  = np.full((side, side), 255, np.uint8)          # white background
    for y in range(MODULES):
        for x in range(MODULES):
            if qr[y][x]:
                img[y + quiet, x + quiet] = 0
    return cv2.resize(img,
                      (side * scale, side * scale),
                      interpolation=cv2.INTER_NEAREST)

# try detectAndDecodeMulti as fallback
def decode_qr(qr_mat: List[List[int]]) -> str:
    """Decode the QR matrix using OpenCV. Raises ValueError on failure."""
    qr_img = qr_matrix_to_cv(qr_mat)      # bigger, with wide quiet zone
    detector = cv2.QRCodeDetector()

    txt, _, _ = detector.detectAndDecode(qr_img)
    if txt:
        return txt

    # Multi-code fallback (helps sometimes with non-standard sizes)
    ok, texts, _ = detector.detectAndDecodeMulti(qr_img)
    if ok and texts and texts[0]:
        return texts[0]

    raise ValueError("QR decode failed")

# signature + hash verification
def verify_tile(json_payload: dict,
                tile_px: np.ndarray,
                public_key) -> None:
    masked = tile_px & 0xFE
    if hashlib.sha256(masked.tobytes()).hexdigest() != json_payload["hash"]:
        raise ValueError("pixel hash mismatch")

    sig_hex = json_payload.pop("sig")
    try:
        public_key.verify(bytes.fromhex(sig_hex),
                          json.dumps(json_payload, sort_keys=True).encode())
    finally:
        json_payload["sig"] = sig_hex

# main entry point
def decode_all_qr_codes(image_path: str) -> List[Dict]:
    img  = Image.open(image_path).convert("RGB")
    px   = np.array(img)
    H, W = px.shape[:2]
    cols = W // QR_PIX
    rows = H // QR_PIX

    out: List[Dict] = []
    for ty in range(rows):
        for tx in range(cols):
            x0, y0 = tx * QR_PIX, ty * QR_PIX
            tile   = px[y0:y0 + QR_PIX, x0:x0 + QR_PIX]
            try:
                qr   = extract_qr_matrix(px, x0, y0)
                data = json.loads(decode_qr(qr))

                pub  = get_public_key(data["device_id"])
                verify_tile(data, tile, pub)

                out.append({
                    "json":      json.dumps(data),
                    "device_id": data["device_id"],
                    "tile_x":    data["tile_x"],
                    "tile_y":    data["tile_y"]
                })
            except Exception:
                continue
    return out