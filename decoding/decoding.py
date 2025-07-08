import os, json, hashlib
from typing import List, Dict
import numpy as np
from PIL import Image
import cv2
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes
from qreader import QReader

BLOCK_SIZE = 8
MODULES = 125
QR_PIX = BLOCK_SIZE * MODULES

PUBLIC_KEY_FOLDER = "/var/data/public_keys"
qr_reader = QReader()

def get_public_key(device_id: str):
    path = os.path.join(PUBLIC_KEY_FOLDER, f"{device_id}.pem")
    with open(path, "rb") as fh:
        return load_pem_public_key(fh.read())

def extract_qr_matrix(px: np.ndarray, off_x: int, off_y: int) -> List[List[int]]:
    return [[px[off_y + y * BLOCK_SIZE, off_x + x * BLOCK_SIZE, 2] & 1
             for x in range(MODULES)] for y in range(MODULES)]

def qr_matrix_to_cv(qr: List[List[int]], quiet=4, scale=4) -> np.ndarray:
    size = MODULES + 2 * quiet
    img = np.full((size, size), 255, np.uint8)
    for y in range(MODULES):
        for x in range(MODULES):
            if qr[y][x]:
                img[y + quiet, x + quiet] = 0
    return cv2.resize(img, (size * scale, size * scale), interpolation=cv2.INTER_NEAREST)

def decode_qr(qr_mat: List[List[int]]) -> dict:
    img_rgb = cv2.cvtColor(qr_matrix_to_cv(qr_mat), cv2.COLOR_GRAY2RGB)
    decoded = qr_reader.detect_and_decode(image=img_rgb)
    if not decoded or decoded[0] is None:
        raise ValueError("QReader failed to decode QR")
    return json.loads(decoded[0])

def verify_tile(payload: dict, tile_px: np.ndarray, pubkey, verbose=True) -> None:
    if hashlib.sha256((tile_px & 0xFE).tobytes()).hexdigest() != payload["hash"]:
        raise ValueError("pixel hash mismatch")
    sig_hex = payload.pop("sig")
    try:
        sig = bytes.fromhex(sig_hex)
        cjson = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(sig, cjson)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey.verify(sig, cjson, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("unsupported key type")
        if verbose:
            print("signature OK")
    finally:
        payload["sig"] = sig_hex

def decode_all_qr_codes(image_path: str, public_keys: Dict[str, any]) -> List[Dict]:
    px = np.array(Image.open(image_path).convert("RGB"))
    H, W = px.shape[:2]
    cols, rows = W // QR_PIX, H // QR_PIX
    verified = []
    for ty in range(rows):
        for tx in range(cols):
            x0, y0 = tx * QR_PIX, ty * QR_PIX
            tile = px[y0:y0 + QR_PIX, x0:x0 + QR_PIX]
            try:
                payload = decode_qr(extract_qr_matrix(px, x0, y0))
                pubkey = public_keys[payload["device_id"]]
                verify_tile(payload, tile, pubkey, verbose=False)
                print(f"verified tile: {tx} {ty}")
                verified.append({"device_id": payload["device_id"],
                                 "tile_x": payload["tile_x"],
                                 "tile_y": payload["tile_y"],
                                 "json":   payload})
            except Exception as e:
                print(f"skipped tile: {tx} {ty} – {type(e).__name__}: {e}")
    return verified