import os
import math
from typing import List, Dict, Tuple

import numpy as np
from PIL import Image
import cv2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PUBLIC_KEY_FOLDER = "/var/data/public_keys"

def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert list [0,1,0,1,…] to bytes (MSB-first)."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def flatten_qr_matrix(qr_matrix: List[List[int]]) -> bytes:
    """Row-wise flatten of a binary QR matrix to bytes (1 byte per bit)."""
    return bytes(bit for row in qr_matrix for bit in row)

def extract_qr_and_signature_at(
    pixels: np.ndarray,
    offset_x: int,
    offset_y: int,
    block_size: int = 8,
    qr_size: int = 47
) -> Tuple[
        List[List[int]],   # qr_matrix
        bytes,             # sig_input  (bitmap‖device_id‖total‖index)
        bytes,             # signature
        str,               # device_id
        int,               # total_qr_count
        int                # qr_index
]:
    """
    Reads one QR tile plus its metadata.

    Bit stream (all in blue-channel LSBs, row-wise below the QR):

        8  bits  device_id_length
        N  bytes device_id
        8  bits  total_qr_count     (NEW)
        8  bits  qr_index           (NEW)
        8  bits  signature_length
        S  bytes signature

    Signature is ECDSA over:  bitmap || device_id || total || index
    """
    qr_pw = qr_size * block_size

    # QR bitmap
    qr_matrix = [
        [pixels[offset_y + y * block_size,
                offset_x + x * block_size, 2] & 1
         for x in range(qr_size)]
        for y in range(qr_size)
    ]
    bitmap_bytes = flatten_qr_matrix(qr_matrix)

    # Metadata bits
    sig_start_y = offset_y + qr_pw + 1
    bits: List[int] = []

    for row in range(20):
        y = sig_start_y + row
        if y >= pixels.shape[0]:
            break
        for px in range(qr_pw):
            x = offset_x + px
            if x >= pixels.shape[1]:
                break
            bits.append(pixels[y, x, 2] & 1)

    if len(bits) < 8:
        raise ValueError("metadata truncated (device-ID length)")

    device_id_len = int("".join(str(b) for b in bits[:8]), 2)
    need = 8 + device_id_len * 8 + 8
    if len(bits) < need:
        raise ValueError("metadata truncated (device-ID)")

    pos = 8
    device_id_bits = bits[pos:pos + device_id_len * 8]
    device_id = bits_to_bytes(device_id_bits).decode("utf-8")
    pos += device_id_len * 8

    total_qr_count = int("".join(str(b) for b in bits[pos:pos + 8]), 2)
    pos += 8
    qr_index = int("".join(str(b) for b in bits[pos:pos + 8]), 2)
    pos += 8

    if len(bits) < pos + 8:
        raise ValueError("metadata truncated (sig length)")
    sig_len = int("".join(str(b) for b in bits[pos:pos + 8]), 2)
    pos += 8

    if len(bits) < pos + sig_len * 8:
        raise ValueError("metadata truncated (sig body)")
    sig_bits = bits[pos:pos + sig_len * 8]
    signature = bits_to_bytes(sig_bits)

    sig_input = bitmap_bytes + device_id.encode() + bytes([total_qr_count, qr_index])

    return (
        qr_matrix,
        sig_input,
        signature,
        device_id,
        total_qr_count,
        qr_index
    )

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

def decode_all_qr_codes(image_path: str,
                        block_size: int = 8,
                        spacing_px: int = 20,
                        qr_size: int = 47) -> List[Dict[str, str]]:
    """
    Returns a list of dicts, **one per valid QR tile**:

        {
          "payload":   <string>,
          "device_id": <string>,
          "total":     <int>,    # signed total_qr_count
          "index":     <int>     # signed qr_index
        }
    """
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)
    height, width = pixels.shape[:2]

    qr_pw = qr_size * block_size
    qr_ph = qr_pw
    results: List[Dict[str, str]] = []
    seen_signatures: set[bytes] = set()

    # estimate how many rows of metadata we must skip per tile
    try:
        _m, _sig_in, _sig, _dev, _tot, _idx = extract_qr_and_signature_at(
            pixels, 0, 0, block_size, qr_size
        )
        full_bits = 8 + len(_dev.encode()) * 8 + 8 + 8 + 8 + len(_sig) * 8
        sig_rows = math.ceil(full_bits / qr_pw)
    except Exception:
        sig_rows = 10

    total_h_per_qr = qr_ph + sig_rows + 1

    # brute-force grid scan
    row_idx = 0
    while True:
        offset_y = int(round(row_idx * (total_h_per_qr + spacing_px)))
        if offset_y + qr_ph > height:
            break

        col_idx = 0
        while True:
            offset_x = int(round(col_idx * (qr_pw + spacing_px)))
            if offset_x + qr_pw > width:
                break

            try:
                (qr_matrix, sig_input, signature,
                 device_id, total, idx) = extract_qr_and_signature_at(
                    pixels, offset_x, offset_y, block_size, qr_size
                 )

                if signature in seen_signatures:
                    raise ValueError("duplicate signature")

                public_key = get_public_key_by_device_id(device_id)
                verify_signature(sig_input, signature, public_key)

                payload = decode_qr_image_opencv(
                    qr_matrix_to_image(qr_matrix))

                results.append({
                    "payload":   payload,
                    "device_id": device_id,
                    "total":     total,
                    "index":     idx
                })
                seen_signatures.add(signature)

            except Exception:
                pass

            col_idx += 1
        row_idx += 1

    return results