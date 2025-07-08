import os
import math
import hashlib
from typing import List, Dict, Tuple

import numpy as np
from PIL import Image
import cv2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PUBLIC_KEY_FOLDER = "/var/data/public_keys"

#  Utility helpers
def bits_to_bytes(bits: List[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def flatten_qr_matrix(qr_matrix: List[List[int]]) -> bytes:
    return bytes(bit for row in qr_matrix for bit in row)

#  Core tile-extraction + signature-input reconstruction
def extract_qr_and_signature_at(
    pixels: np.ndarray,
    offset_x: int,
    offset_y: int,
    block_size: int = 8,
    qr_size: int = 51
) -> Tuple[
        List[List[int]],   # qr_matrix
        bytes,             # sig_input (hash‖deviceID‖totalTiles‖qr_index)
        bytes,             # signature
        str,               # device_id
        int,               # total_tiles (UInt16)
        int                # qr_index   (UInt16, unique per tile)
]:
    """
    Extract one embedded QR tile plus metadata and rebuild the byte-string
    that was signed by the camera app.

        Metadata bit layout (LSB of blue channel, row-major):
          8   bits  device_id_length
          N×8 bits  device_id (UTF-8)
          16  bits  total_tiles
          16  bits  qr_index
          8   bits  signature_length
          S×8 bits  signature (DER or raw)

        The signature covers:
          SHA256(7-MSBs of all RGB pixels in tile) ||
          device_id || total_tiles || qr_index
    """
    qr_pix = qr_size * block_size

    # 1) read the binary QR matrix
    qr_matrix = [
        [pixels[offset_y + y * block_size,
                offset_x + x * block_size, 2] & 1
         for x in range(qr_size)]
        for y in range(qr_size)
    ]

    # 2) collect metadata bits (20 rows is plenty for our payload)
    bits: List[int] = []
    meta_start_y = offset_y + qr_pix + 1
    for r in range(20):
        y = meta_start_y + r
        if y >= pixels.shape[0]:
            break
        for c in range(qr_pix):
            x = offset_x + c
            if x >= pixels.shape[1]:
                break
            bits.append(pixels[y, x, 2] & 1)

    # 3) parse metadata fields
    if len(bits) < 8:
        raise ValueError("metadata truncated (ID length)")

    dev_len = int("".join(map(str, bits[0:8])), 2)
    need = 8 + dev_len * 8 + 16 + 16 + 8
    if len(bits) < need:
        raise ValueError("metadata truncated (deviceID)")

    pos = 8
    dev_bits = bits[pos:pos + dev_len * 8]
    pos += dev_len * 8
    device_id = bytes(
        int("".join(map(str, dev_bits[i:i + 8])), 2)
        for i in range(0, len(dev_bits), 8)
    ).decode()

    total_tiles = int("".join(map(str, bits[pos:pos + 16])), 2)
    pos += 16
    qr_index = int("".join(map(str, bits[pos:pos + 16])), 2)
    pos += 16

    sig_len = int("".join(map(str, bits[pos:pos + 8])), 2)
    pos += 8
    if len(bits) < pos + sig_len * 8:
        raise ValueError("metadata truncated (signature)")
    sig_bits = bits[pos:pos + sig_len * 8]
    signature = bytes(
        int("".join(map(str, sig_bits[i:i + 8])), 2)
        for i in range(0, len(sig_bits), 8)
    )

    # 4) recreate the hash of the 7-MSBs of ALL RGB pixels in this tile
    qr_area = pixels[
        offset_y:offset_y + qr_pix,
        offset_x:offset_x + qr_pix,
        :
    ]
    # mask off LSBs
    masked = qr_area & 0xFE
    hasher = hashlib.sha256()
    hasher.update(masked.tobytes())
    hash_digest = hasher.digest()

    # 5) rebuild sig_input (byte-sequence signed by the camera)
    sig_input = (
        hash_digest +
        device_id.encode() +
        total_tiles.to_bytes(2, "big") +
        qr_index.to_bytes(2, "big")
    )

    return (
        qr_matrix, sig_input, signature,
        device_id, total_tiles, qr_index
    )

#  Public-key retrieval + signature verification helpers
def get_public_key_by_device_id(device_id: str):
    path = os.path.join(PUBLIC_KEY_FOLDER, f"{device_id}.pem")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No public key for device ID '{device_id}'")
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

#  Convenience helpers for QR decoding via OpenCV
def qr_matrix_to_image(qr_matrix: List[List[int]],
                       scale: int = 10,
                       quiet_zone: int = 4) -> Image.Image:
    size = len(qr_matrix)
    total = size + 2 * quiet_zone
    img = Image.new("L", (total, total), 255)
    px = img.load()
    for y in range(size):
        for x in range(size):
            px[x + quiet_zone, y + quiet_zone] = 0 if qr_matrix[y][x] else 255
    return img.resize((total * scale, total * scale), Image.NEAREST)


def decode_qr_image_opencv(qr_img_pil: Image.Image) -> str:
    qr_np = np.array(qr_img_pil.convert("RGB"))
    qr_cv = cv2.cvtColor(qr_np, cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(qr_cv)
    if not data:
        raise ValueError("OpenCV could not decode QR")
    return data

#  Scan entire image for verified QR tiles (gap-free grid)
def decode_all_qr_codes(
    image_path: str,
    block_size: int = 8,
    qr_size: int = 51
) -> List[Dict[str, str]]:
    """
    Returns one dict per *verified* QR tile:

        {
          "payload":   <str>,
          "device_id": <str>,
          "total":     <int>,   # signed totalTiles
          "index":     <int>    # qr_index
        }
    """
    img = Image.open(image_path).convert("RGB")
    px = np.array(img)
    H, W = px.shape[:2]

    qr_pix = qr_size * block_size
    results: List[Dict[str, str]] = []

    # estimate how many metadata rows follow a tile
    try:
        _m, _si, _sig, _dev, _tot, _idx = extract_qr_and_signature_at(
            px, 0, 0, block_size, qr_size
        )
        full_bits = 8 + len(_dev.encode()) * 8 + 16 + 16 + 8 + len(_sig) * 8
        meta_rows = math.ceil(full_bits / qr_pix)
    except Exception:
        meta_rows = 12                                      # safe default

    tile_h = qr_pix + 1 + meta_rows
    tiles_per_row = W // qr_pix
    tiles_per_col = H // tile_h

    # rigid grid scan (no spacing)
    for row in range(tiles_per_col):
        off_y = row * tile_h
        for col in range(tiles_per_row):
            off_x = col * qr_pix

            try:
                (qr_mat, sig_input, signature,
                 device_id, total, idx) = extract_qr_and_signature_at(
                     px, off_x, off_y, block_size, qr_size
                 )

                # cryptographic verification
                pub = get_public_key_by_device_id(device_id)
                verify_signature(sig_input, signature, pub)

                payload = decode_qr_image_opencv(
                    qr_matrix_to_image(qr_mat)
                )

                results.append({
                    "payload":   payload.rstrip("#"),
                    "device_id": device_id,
                    "total":     total,
                    "index":     idx
                })

            except Exception:
                pass

    return results