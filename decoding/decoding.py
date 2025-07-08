import os, json, hashlib
from typing import List, Dict

import numpy as np
from PIL import Image
import cv2
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# Constants (match the Swift embedder)
BLOCK_SIZE = 8
MODULES    = 125
QR_PIX     = BLOCK_SIZE * MODULES


PUBLIC_KEY_FOLDER = "/var/data/public_keys"


# Public-key helper
def get_public_key(device_id: str):
    path = os.path.join(PUBLIC_KEY_FOLDER, f"{device_id}.pem")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No public key for {device_id}")
    with open(path, "rb") as fh:
        return load_pem_public_key(fh.read())


# QR extraction helpers
def extract_qr_matrix(px: np.ndarray, off_x: int, off_y: int) -> List[List[int]]:
    """Reads the blue-channel LSBs inside one tile and returns a MODULES×MODULES matrix."""
    return [
        [
            px[off_y + y * BLOCK_SIZE,
               off_x + x * BLOCK_SIZE, 2] & 1
            for x in range(MODULES)
        ]
        for y in range(MODULES)
    ]


def qr_matrix_to_cv(qr: List[List[int]]) -> np.ndarray:
    """Convert the binary matrix to an OpenCV-compatible image (grayscale)."""
    size = MODULES + 8
    img  = np.full((size, size), 255, np.uint8)
    for y in range(MODULES):
        for x in range(MODULES):
            if qr[y][x]:
                img[y + 4, x + 4] = 0
    return cv2.resize(img, (size * 4, size * 4), interpolation=cv2.INTER_NEAREST)


def decode_qr(qr_mat: List[List[int]]) -> str:
    """Decode QR matrix with OpenCV."""
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(qr_matrix_to_cv(qr_mat))
    if not data:
        raise ValueError("QR decode failed")
    return data


# Signature + hash verification
def verify_tile(json_payload: dict,
                tile_px: np.ndarray,
                public_key) -> None:
    """Raises on any verification failure."""
    # 1) recompute pixel hash (upper 7 bits of RGB)
    masked = tile_px & 0xFE
    calc_hash = hashlib.sha256(masked.tobytes()).hexdigest()
    if calc_hash != json_payload["hash"]:
        raise ValueError("pixel hash mismatch")

    # 2) verify signature
    sig_hex = json_payload.pop("sig")
    sig     = bytes.fromhex(sig_hex)

    canonical = json.dumps(json_payload, sort_keys=True).encode()
    try:
        public_key.verify(sig, canonical)
    finally:
        json_payload["sig"] = sig_hex


# Main entry point
def decode_all_qr_codes(image_path: str) -> List[Dict]:
    """
    Returns a list of verified tiles:

        {
          "json":      <original JSON string>,
          "device_id": <str>,
          "tile_x":    <int>,
          "tile_y":    <int>
        }
    """
    img   = Image.open(image_path).convert("RGB")
    px    = np.array(img)
    H, W  = px.shape[:2]
    cols  = W // QR_PIX
    rows  = H // QR_PIX
    output: List[Dict] = []

    for ty in range(rows):
        for tx in range(cols):
            x0, y0 = tx * QR_PIX, ty * QR_PIX
            tile   = px[y0:y0 + QR_PIX, x0:x0 + QR_PIX]

            try:
                qr_mat = extract_qr_matrix(px, x0, y0)
                json_str = decode_qr(qr_mat)
                payload  = json.loads(json_str)

                device_id = payload["device_id"]
                pubkey    = get_public_key(device_id)

                verify_tile(payload, tile, pubkey)

                output.append({
                    "json":      json_str,
                    "device_id": device_id,
                    "tile_x":    payload["tile_x"],
                    "tile_y":    payload["tile_y"]
                })

            except Exception:
                continue

    return output