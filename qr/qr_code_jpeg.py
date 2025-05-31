import numpy as np
from PIL import Image
import qrcode
import cv2
import random

BLOCK_SIZE = 8
DCT_POS = (4, 3)  # Robust, mid-frequency
STEP = 5  # Use every Nth block to reduce visual impact
SEED = 42  # To make embedding deterministic (optional)

JPEG_LUMA_QTABLE = np.array([
    [16,11,10,16,24,40,51,61],
    [12,12,14,19,26,58,60,55],
    [14,13,16,24,40,57,69,56],
    [14,17,22,29,51,87,80,62],
    [18,22,37,56,68,109,103,77],
    [24,35,55,64,81,104,113,92],
    [49,64,78,87,103,121,120,101],
    [72,92,95,98,112,100,103,99]
])

def generate_qr_matrix(message, version=2):
    qr = qrcode.QRCode(
        version=version,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=1,
        border=0
    )
    qr.add_data(message)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("L")
    arr = np.array(img)
    return (arr < 128).astype(np.uint8)

def quantize(block, qtable):
    return np.round(block / qtable)

def dequantize(block, qtable):
    return block * qtable

def embed_bit(dct_block, bit):
    coeff = dct_block[DCT_POS]
    coeff_int = int(np.round(coeff))
    if abs(coeff_int) < 5:
        coeff_int = 6 if bit else 5
    if coeff_int % 2 != bit:
        coeff_int += 1 if coeff_int > 0 else -1
    dct_block[DCT_POS] = coeff_int
    return dct_block

def embed_qr_sparse(input_path, message, output_path):
    qr_matrix = generate_qr_matrix(message)
    flat_qr = qr_matrix.flatten()
    img = Image.open(input_path).convert("RGB")
    ycbcr = img.convert("YCbCr")
    y, cb, cr = ycbcr.split()
    y_np = np.array(y, dtype=np.float32)
    h, w = y_np.shape

    block_coords = [
        (by, bx)
        for by in range(0, h - BLOCK_SIZE, BLOCK_SIZE)
        for bx in range(0, w - BLOCK_SIZE, BLOCK_SIZE)
    ]
    random.seed(SEED)
    usable_blocks = block_coords[::STEP]

    if len(flat_qr) > len(usable_blocks):
        raise ValueError("Image too small for QR embedding with this step size.")

    for idx, bit in enumerate(flat_qr):
        by, bx = usable_blocks[idx]
        block = y_np[by:by+BLOCK_SIZE, bx:bx+BLOCK_SIZE] - 128
        dct = cv2.dct(block)
        q = quantize(dct, JPEG_LUMA_QTABLE)
        q = embed_bit(q, bit)
        dct = dequantize(q, JPEG_LUMA_QTABLE)
        idct = cv2.idct(dct) + 128
        y_np[by:by+BLOCK_SIZE, bx:bx+BLOCK_SIZE] = np.clip(idct, 0, 255)

    y_stego = Image.fromarray(y_np.astype(np.uint8))
    final_img = Image.merge("YCbCr", (y_stego, cb, cr)).convert("RGB")
    final_img.save(output_path, "JPEG", quality=95)
    print(f"✅ Embedded QR into: {output_path}")

def extract_qr_sparse(stego_path, qr_shape):
    img = Image.open(stego_path).convert("YCbCr")
    y, _, _ = img.split()
    y_np = np.array(y, dtype=np.float32)
    h, w = y_np.shape

    total_bits = qr_shape[0] * qr_shape[1]
    block_coords = [
        (by, bx)
        for by in range(0, h - BLOCK_SIZE, BLOCK_SIZE)
        for bx in range(0, w - BLOCK_SIZE, BLOCK_SIZE)
    ]
    random.seed(SEED)
    usable_blocks = block_coords[::STEP]

    bits = []
    for idx in range(total_bits):
        by, bx = usable_blocks[idx]
        block = y_np[by:by+BLOCK_SIZE, bx:bx+BLOCK_SIZE] - 128
        dct = cv2.dct(block)
        q = quantize(dct, JPEG_LUMA_QTABLE)
        bit = int(np.round(q[DCT_POS])) % 2
        bits.append(bit)

    arr = np.array(bits).reshape(qr_shape)
    img_qr = (1 - arr) * 255
    padded = np.pad(img_qr, 4, constant_values=255)
    return Image.fromarray(padded.astype(np.uint8)).convert("L")

def decode_qr_image(img):
    arr = np.array(img.convert("L"))
    _, binary = cv2.threshold(arr, 128, 255, cv2.THRESH_BINARY)
    upscaled = cv2.resize(binary, (binary.shape[1]*10, binary.shape[0]*10), interpolation=cv2.INTER_NEAREST)
    cv2.imwrite("qr/output/upscaled_debug.png", upscaled)
    detector = cv2.QRCodeDetector()
    val, _, _ = detector.detectAndDecode(upscaled)
    return val

# Main
if __name__ == "__main__":
    message = "JPEG DCT QR working cleanly!"
    input_img = "qr/test.jpeg"
    output_img = "qr/output/stego_jpeg_dct_sparse.jpg"

    embed_qr_sparse(input_img, message, output_img)

    shape = generate_qr_matrix(message).shape
    extracted = extract_qr_sparse(output_img, shape)
    extracted.save("qr/output/extracted_sparse_qr.png")

    result = decode_qr_image(extracted)
    print("🔍 Decoded message:", result)