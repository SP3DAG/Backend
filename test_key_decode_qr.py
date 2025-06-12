from PIL import Image
import numpy as np
import hashlib
import cv2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

QR_BLOCK_SIZE = 8
QR_SIZE = 47  # QR code is 47x47 modules

def flatten_qr_matrix(qr_matrix):
    return bytes(bit for row in qr_matrix for bit in row)

def qr_matrix_to_image(qr_matrix, scale=10, quiet_zone=4):
    size = len(qr_matrix)
    total_size = size + 2 * quiet_zone
    img = Image.new('L', (total_size, total_size), 255)
    pixels = img.load()
    for y in range(size):
        for x in range(size):
            pixels[x + quiet_zone, y + quiet_zone] = 0 if qr_matrix[y][x] == 1 else 255
    return img.resize((total_size * scale, total_size * scale), Image.BILINEAR)

def decode_qr_image_opencv(qr_img_pil):
    qr_img_np = np.array(qr_img_pil.convert("RGB"))
    qr_img_cv = cv2.cvtColor(qr_img_np, cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(qr_img_cv)
    if not data:
        raise ValueError("Could not decode QR code with OpenCV.")
    return data

def extract_qr_and_signature(image_path):
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)
    qr_matrix = [
        [pixels[y * QR_BLOCK_SIZE, x * QR_BLOCK_SIZE, 2] & 1 for x in range(QR_SIZE)]
        for y in range(QR_SIZE)
    ]
    qr_pixel_h = QR_SIZE * QR_BLOCK_SIZE
    sig_start_y = qr_pixel_h + 1
    extracted_bits = []
    for row in range(3):
        y = sig_start_y + row
        if y >= pixels.shape[0]:
            continue
        for x in range(QR_SIZE * QR_BLOCK_SIZE):
            if x >= pixels.shape[1]:
                continue
            extracted_bits.append(pixels[y, x, 2] & 1)
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
    return qr_matrix, flatten_qr_matrix(qr_matrix), bytes(sig_bytes)

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

if __name__ == "__main__":
    image_path = "/Users/moritzdenk/Documents/IMG_2007.PNG"
    public_key_path = 'public_keys/my-key.pem'

    with open(public_key_path, 'rb') as f:
        public_key = load_pem_public_key(f.read())

    try:
        qr_matrix, data, signature = extract_qr_and_signature(image_path)
        is_valid = verify_signature(data, signature, public_key)

        qr_img = qr_matrix_to_image(qr_matrix)
        qr_img.save("reconstructed_qr.png")

        qr_message = decode_qr_image_opencv(qr_img)

        print("Signature is VALID" if is_valid else "Signature is INVALID")
        print("Decoded QR message:", qr_message)
    except Exception as e:
        print(f"Verification failed: {e}")