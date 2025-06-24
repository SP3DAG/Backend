from PIL import Image
import numpy as np
import cv2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os
import math
from typing import List, Dict

PUBLIC_KEY_FOLDER = "/var/data/public_keys"

def extract_qr_and_signature_at(pixels: np.ndarray,
                                offset_x: int,
                                offset_y: int,
                                block_size: int = 8,
                                qr_size: int = 47):
    """
    Extracts a QR matrix, flattened data, digital signature, and device ID
    from a given offset within an image's pixel array.

    Args:
        pixels (np.ndarray): The full RGB pixel array from the input image.
        offset_x (int): The x-pixel coordinate of the top-left QR module.
        offset_y (int): The y-pixel coordinate of the top-left QR module.
        block_size (int, optional): Pixel width of one QR module. Defaults to 8.
        qr_size (int, optional): Number of modules per side (should be 47). Defaults to 47.

    Returns:
        Tuple[List[List[int]], bytes, bytes, str]:
            - QR matrix as 2D list
            - Flattened matrix as bytes (for signature verification)
            - Signature bytes
            - Extracted device ID as a string

    Raises:
        ValueError: If metadata (device ID or signature) is incomplete or malformed.
    """
    qr_pw = qr_size * block_size
    qr_ph = qr_pw

    qr_matrix = [
        [pixels[offset_y + y*block_size, offset_x + x*block_size, 2] & 1
         for x in range(qr_size)]
        for y in range(qr_size)
    ]
    data = flatten_qr_matrix(qr_matrix)

    sig_start_y = offset_y + qr_ph + 1
    extracted_bits: List[int] = []

    max_rows = 20
    qr_pw_pixels = qr_pw

    for row in range(max_rows):
        y = sig_start_y + row
        if y >= pixels.shape[0]:
            break
        for px in range(qr_pw_pixels):
            x = offset_x + px
            if x >= pixels.shape[1]:
                break
            extracted_bits.append(pixels[y, x, 2] & 1)

    if len(extracted_bits) < 16:
        raise ValueError("Metadata truncated (no lengths).")

    device_id_len = int(''.join(str(b) for b in extracted_bits[:8]), 2)
    need = 8 + device_id_len*8 + 8        # up to signature length field
    if len(extracted_bits) < need:
        raise ValueError("Metadata truncated (device-ID).")

    device_id_bits = extracted_bits[8:8 + device_id_len * 8]
    device_id_bytes = bytearray()
    for i in range(0, len(device_id_bits), 8):
        byte = 0
        for bit in device_id_bits[i:i+8]:
            byte = (byte << 1) | bit
        device_id_bytes.append(byte)
    device_id = device_id_bytes.decode('utf-8')

    sig_len_start = 8 + device_id_len * 8
    sig_len = int(''.join(str(b) for b in extracted_bits[sig_len_start:
                                                         sig_len_start + 8]), 2)

    total_needed = sig_len_start + 8 + sig_len * 8
    if len(extracted_bits) < total_needed:
        raise ValueError("Metadata truncated (signature).")

    sig_bits_start = sig_len_start + 8
    sig_bits = extracted_bits[sig_bits_start:sig_bits_start + sig_len * 8]
    sig_bytes = bytearray()
    for i in range(0, len(sig_bits), 8):
        byte = 0
        for bit in sig_bits[i:i+8]:
            byte = (byte << 1) | bit
        sig_bytes.append(byte)

    return qr_matrix, data, bytes(sig_bytes), device_id


def decode_all_qr_codes(image_path: str,
                        block_size: int = 8,
                        spacing_px: int = 20,
                        qr_size: int = 47) -> List[Dict[str, str]]:
    """
    Scans an image for all embedded QR codes and their metadata, verifies each,
    and decodes all valid QR payloads.

    Args:
        image_path (str): Path to the carrier image.
        block_size (int, optional): Pixel width/height of one QR module. Defaults to 8.
        spacing_px (int, optional): Pixel spacing between QR blocks. Defaults to 20.
        qr_size (int, optional): Number of modules per QR code (should be 47). Defaults to 47.

    Returns:
        List[Dict[str, str]]: A list of valid results. Each result has:
            - "payload": the decoded QR string
            - "device_id": the verified device ID

    Notes:
        Invalid or duplicate QR codes are ignored.
    """
    
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)
    height, width = pixels.shape[:2]

    qr_pw = qr_size * block_size
    qr_ph = qr_pw
    results: List[Dict[str, str]] = []
    seen_signatures: set[bytes] = set()
    
    try:
        _m, _d, _sig, _dev = extract_qr_and_signature_at(
            pixels, 0, 0, block_size, qr_size)
        full_bits = 8 + len(_dev.encode())*8 + 8 + len(_sig)*8
        sig_rows = math.ceil(full_bits / qr_pw)
    except Exception:
        sig_rows = 10

    total_h_per_qr = qr_ph + sig_rows + 1   # +1 spacer

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
                qr_matrix, data, signature, device_id = \
                    extract_qr_and_signature_at(
                        pixels, offset_x, offset_y, block_size, qr_size)

                if signature in seen_signatures:
                    raise ValueError("duplicate")

                public_key = get_public_key_by_device_id(device_id)
                verify_signature(data, signature, public_key)

                payload = decode_qr_image_opencv(
                    qr_matrix_to_image(qr_matrix))

                results.append(
                    {"payload": payload, "device_id": device_id})
                seen_signatures.add(signature)

            except Exception:
                pass

            col_idx += 1
        row_idx += 1

    return results

def flatten_qr_matrix(qr_matrix):
    """
    Flattens a 2D QR matrix into a byte sequence.

    Args:
        qr_matrix (List[List[int]]): A 2D list of binary values (0 or 1) representing a QR code.

    Returns:
        bytes: Flattened byte representation of the matrix (1 byte per bit).
    """
    return bytes(bit for row in qr_matrix for bit in row)

def qr_matrix_to_image(qr_matrix, scale=10, quiet_zone=4):
    """
    Converts a QR matrix into a PIL image with a quiet zone and scaling applied.

    Args:
        qr_matrix (List[List[int]]): The QR matrix as 0s and 1s.
        scale (int, optional): Scale factor for output image size. Defaults to 10.
        quiet_zone (int, optional): Number of blank border modules. Defaults to 4.

    Returns:
        PIL.Image: The rendered QR code as a grayscale image.
    """
    size = len(qr_matrix)
    total_size = size + 2 * quiet_zone
    img = Image.new('L', (total_size, total_size), 255)
    pixels = img.load()
    for y in range(size):
        for x in range(size):
            pixels[x + quiet_zone, y + quiet_zone] = 0 if qr_matrix[y][x] == 1 else 255
    return img.resize((total_size * scale, total_size * scale), Image.NEAREST)

def decode_qr_image_opencv(qr_img_pil):
    """
    Uses OpenCV to decode a QR code from a PIL image.

    Args:
        qr_img_pil (PIL.Image): A PIL image containing a QR code.

    Returns:
        str: The decoded text from the QR code.

    Raises:
        ValueError: If OpenCV cannot detect or decode the QR code.
    """
    qr_img_np = np.array(qr_img_pil.convert("RGB"))
    qr_img_cv = cv2.cvtColor(qr_img_np, cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(qr_img_cv)
    if not data:
        raise ValueError("Could not decode QR code with OpenCV.")
    return data
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)

    # Extract QR matrix
    qr_matrix = [
        [pixels[y * QR_BLOCK_SIZE, x * QR_BLOCK_SIZE, 2] & 1 for x in range(QR_SIZE)]
        for y in range(QR_SIZE)
    ]

    qr_pixel_h = QR_SIZE * QR_BLOCK_SIZE
    sig_start_y = qr_pixel_h + 1
    extracted_bits = []
    for row in range(10):  # increase to ensure we cover long IDs + signature
        y = sig_start_y + row
        if y >= pixels.shape[0]:
            continue
        for x in range(QR_SIZE * QR_BLOCK_SIZE):
            if x >= pixels.shape[1]:
                continue
            extracted_bits.append(pixels[y, x, 2] & 1)

    # === Decode device ID length ===
    device_id_len_bits = extracted_bits[:8]
    device_id_len = int(''.join(str(b) for b in device_id_len_bits), 2)

    # === Decode device ID ===
    device_id_bits = extracted_bits[8:8 + device_id_len * 8]
    device_id_bytes = bytearray()
    for i in range(0, len(device_id_bits), 8):
        byte = 0
        for bit in device_id_bits[i:i+8]:
            byte = (byte << 1) | bit
        device_id_bytes.append(byte)
    device_id = device_id_bytes.decode('utf-8')

    # === Decode signature length ===
    sig_len_start = 8 + device_id_len * 8
    sig_len_bits = extracted_bits[sig_len_start:sig_len_start + 8]
    sig_len = int(''.join(str(b) for b in sig_len_bits), 2)

    # === Decode signature ===
    sig_bits_start = sig_len_start + 8
    sig_bits = extracted_bits[sig_bits_start:sig_bits_start + sig_len * 8]
    sig_bytes = bytearray()
    for i in range(0, len(sig_bits), 8):
        byte = 0
        for bit in sig_bits[i:i+8]:
            byte = (byte << 1) | bit
        sig_bytes.append(byte)

    return qr_matrix, flatten_qr_matrix(qr_matrix), bytes(sig_bytes), device_id

def get_public_key_by_device_id(device_id):
    """
    Loads a PEM-encoded public key for the given device ID.

    Args:
        device_id (str): The device ID to look up.

    Returns:
        cryptography.PublicKey: The loaded public key.

    Raises:
        FileNotFoundError: If no key file exists for the given device ID.
    """
    path = os.path.join(PUBLIC_KEY_FOLDER, f"{device_id}.pem")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No public key found for device ID: {device_id}")
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())

def verify_signature(data, signature, public_key):
    """
    Verifies an ECDSA signature against given data.

    Args:
        data (bytes): The signed message.
        signature (bytes): The ECDSA signature to verify.
        public_key: The public key to verify with.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False