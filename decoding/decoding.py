from PIL import Image
import numpy as np
import cv2
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

QR_BLOCK_SIZE = 8
QR_SIZE = 47
SIGNATURE_BIT_LENGTH = 520 * 8

def extract_qr_from_blue_lsb(image_path, qr_shape=(QR_SIZE, QR_SIZE), block_size=QR_BLOCK_SIZE, top=0, left=0):
    img = Image.open(image_path).convert("RGB")
    np_img = np.array(img)
    h, w = qr_shape

    matrix = np.zeros((h, w), dtype=np.uint8)
    for i in range(h):
        for j in range(w):
            y = top + i * block_size
            x = left + j * block_size
            bits = []
            for dy in range(block_size):
                for dx in range(block_size):
                    yy, xx = y + dy, x + dx
                    if yy >= np_img.shape[0] or xx >= np_img.shape[1]:
                        continue
                    blue = np_img[yy, xx, 2]
                    bits.append(blue & 1)
            matrix[i, j] = 1 if sum(bits) > len(bits) // 2 else 0

    matrix = ((1 - matrix) * 255).astype(np.uint8)
    matrix = np.pad(matrix, pad_width=4, constant_values=255)
    qr_img = Image.fromarray(matrix)
    return qr_img

def extract_signature_from_lsb(img, qr_shape, block_size, sig_bits_length, top=0, left=0):
    sig_bits = []
    qr_height_px = qr_shape[0] * block_size
    qr_width_px = qr_shape[1] * block_size
    np_img = np.array(img.convert("RGB"))

    sig_rows = (sig_bits_length + qr_width_px - 1) // qr_width_px
    sig_start_y = top + qr_height_px + 1

    sig_bit_index = 0
    for row in range(sig_rows):
        for col in range(qr_width_px):
            if sig_bit_index >= sig_bits_length:
                break
            y = sig_start_y + row
            x = left + col
            if y >= np_img.shape[0] or x >= np_img.shape[1]:
                continue
            blue = np_img[y, x, 2]
            sig_bits.append(blue & 1)
            sig_bit_index += 1

    signature_bytes = bytes([
        sum([bit << (7 - i) for i, bit in enumerate(sig_bits[j:j + 8])])
        for j in range(0, len(sig_bits), 8)
    ])
    return signature_bytes

def load_public_key(device_id):
    path = f"public_keys/{device_id}.pem"
    if not os.path.exists(path):
        raise FileNotFoundError(f"No public key found for device: {device_id}")
    with open(path, "rb") as f:
        return load_pem_public_key(f.read())

def decode_qr_image(image_path, device_id, qr_shape=(QR_SIZE, QR_SIZE), block_size=QR_BLOCK_SIZE):
    # Step 1: Extract QR from LSB
    qr_img = extract_qr_from_blue_lsb(image_path, qr_shape, block_size)
    #qr_img.save("debug_extracted_qr.png")  # Optional debug image

    arr = np.array(qr_img)
    upscaled = cv2.resize(arr, (arr.shape[1] * 10, arr.shape[0] * 10), interpolation=cv2.INTER_NEAREST)
    
    detector = cv2.QRCodeDetector()
    val, points, _ = detector.detectAndDecode(upscaled)
    if not val or points is None:
        print("No QR code detected")
        return None

    message = val.strip()
    print(f"Extracted message: {message}")

    # Step 2: Extract signature from LSB region under QR
    signature = extract_signature_from_lsb(
        Image.open(image_path),
        qr_shape=qr_shape,
        block_size=block_size,
        sig_bits_length=SIGNATURE_BIT_LENGTH
    )

    # Step 3: Load public key and verify
    try:
        public_key = load_public_key(device_id)
        public_key.verify(
            signature,
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid")
        return message
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return None