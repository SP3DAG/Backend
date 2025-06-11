from PIL import Image
import numpy as np
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# CONFIGURABLE
QR_BLOCK_SIZE = 8
QR_SIZE = 47  # QR code is 47x47 modules

def flatten_qr_matrix(qr_matrix):
    flat_bits = [bit for row in qr_matrix for bit in row]
    return bytes(flat_bits)

def extract_qr_and_signature(image_path):
    image = Image.open(image_path).convert("RGB")
    pixels = np.array(image)
    
    height, width, _ = pixels.shape

    # Extract QR matrix
    qr_matrix = []
    for y in range(QR_SIZE):
        row = []
        for x in range(QR_SIZE):
            px = x * QR_BLOCK_SIZE
            py = y * QR_BLOCK_SIZE
            blue = pixels[py, px, 2]
            bit = blue & 1

            # Debug: log a few samples
            if y < 2 and x < 5:
                print(f"Pixel at ({px}, {py}) blue={blue} bit={bit}")

            row.append(bit)
        qr_matrix.append(row)

    print("Extracted QR Matrix Preview (first 5 rows):")
    for row in qr_matrix[:5]:
        print("".join(str(bit) for bit in row))

    # Extract signature bits from below the QR code
    qr_pixel_h = QR_SIZE * QR_BLOCK_SIZE
    sig_start_y = qr_pixel_h + 1
    extracted_bits = []

    for row in range(3):  # 3 rows
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

    # Parse signature length
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

    # Print flattened QR matrix bytes for debugging
    print("Flattened QR bytes (first 20):", flattened[:20].hex())

    return flattened, bytes(sig_bytes)

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Verification error: {e}")
        return False


if __name__ == "__main__":
    image_path = "/Users/moritzdenk/Documents/IMG_2007.PNG"
    public_key_path = 'public_keys/my-key.pem'

    with open(public_key_path, 'rb') as f:
        public_key_pem = f.read()

    public_key = load_pem_public_key(public_key_pem)

    try:
        data, signature = extract_qr_and_signature(image_path)

        print("SHA256 of QR content:", hashlib.sha256(data).hexdigest())
        print("Signature length:", len(signature), "bytes")
        print("Signature (first 10 bytes):", signature[:10].hex())

        is_valid = verify_signature(data, signature, public_key)
        print("Signature is VALID" if is_valid else "Signature is INVALID")
    except Exception as e:
        print(f"Verification failed: {e}")