from PIL import Image
import numpy as np
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import cv2

QR_BLOCK_SIZE = 8
QR_SIZE = 47

def flatten_qr_matrix(qr_matrix):
    flat_bits = [bit for row in qr_matrix for bit in row]
    return bytes(flat_bits)

def extract_qr_and_signature(image_path):
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)

    height, width, _ = pixels.shape
    qr_matrix = []

    for y in range(QR_SIZE):
        row = []
        for x in range(QR_SIZE):
            px = x * QR_BLOCK_SIZE
            py = y * QR_BLOCK_SIZE
            blue = pixels[py, px, 2]
            row.append(blue & 1)
        qr_matrix.append(row)

    qr_pixel_h = QR_SIZE * QR_BLOCK_SIZE
    sig_start_y = qr_pixel_h + 1
    extracted_bits = []

    for row in range(3):
        y = sig_start_y + row
        if y >= height:
            continue
        for x in range(QR_SIZE * QR_BLOCK_SIZE):
            if x >= width:
                continue
            blue = pixels[y, x, 2]
            extracted_bits.append(blue & 1)
            if len(extracted_bits) >= 8 + 72 * 8:
                break

    length_byte_bits = extracted_bits[:8]
    sig_len = int(sum([(bit << (7 - i)) for i, bit in enumerate(length_byte_bits)]))

    if sig_len <= 0 or sig_len > 72:
        raise ValueError(f"Invalid signature length: {sig_len}")

    sig_bits = extracted_bits[8:8 + sig_len * 8]
    sig_bytes = bytearray()
    for i in range(0, len(sig_bits), 8):
        byte = 0
        for bit in sig_bits[i:i+8]:
            byte = (byte << 1) | bit
        sig_bytes.append(byte)

    flattened = flatten_qr_matrix(qr_matrix)
    return flattened, bytes(sig_bytes)

def load_public_key(device_id):
    path = f"public_keys/{device_id}.pem"
    if not os.path.exists(path):
        raise FileNotFoundError(f"No public key found for device: {device_id}")
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())

def decode_qr_image(image_path, device_id):
    try:
        # Step 1: Extract raw QR bits and signature
        raw_data, signature = extract_qr_and_signature(image_path)

        # Step 2: Decode the QR message using OpenCV
        qr_matrix = np.array(list(raw_data)).reshape((QR_SIZE, QR_SIZE)) * 255
        qr_matrix = qr_matrix.astype(np.uint8)
        qr_matrix = np.pad(qr_matrix, pad_width=4, constant_values=255)

        img = Image.fromarray(qr_matrix)
        upscaled = cv2.resize(np.array(img), (470, 470), interpolation=cv2.INTER_NEAREST)

        detector = cv2.QRCodeDetector()
        val, points, _ = detector.detectAndDecode(upscaled)
        if not val or points is None:
            print("QR decoding failed")
            return None

        message = val.strip()
        print(f"Extracted message: {message}")

        # Step 3: Verify signature
        public_key = load_public_key(device_id)
        public_key.verify(
            signature,
            raw_data,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid")
        return message

    except Exception as e:
        print(f"Verification failed: {e}")
        return None