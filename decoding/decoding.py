from PIL import Image
import numpy as np
import cv2

def extract_qr_from_blue_lsb(image_path, qr_shape, block_size, top=0, left=0):
    """
    Extract a QR code from the blue channel LSB of an image.
    Assumes block-wise embedding.
    """
    img = np.array(Image.open(image_path).convert("RGB"))
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
                    if yy >= img.shape[0] or xx >= img.shape[1]:
                        continue
                    blue = img[yy, xx, 2]
                    bits.append(blue & 1)
            matrix[i, j] = 1 if np.mean(bits) >= 0.5 else 0

    # Invert and scale to 255 for white/black image
    matrix = ((1 - matrix) * 255).astype(np.uint8)
    matrix = np.pad(matrix, pad_width=4, constant_values=255)
    qr_img = Image.fromarray(matrix)
    return qr_img

def decode_qr_image(img):
    """
    Use OpenCV to decode the QR code from the extracted matrix.
    """
    arr = np.array(img)
    upscaled = cv2.resize(arr, (arr.shape[1]*10, arr.shape[0]*10), interpolation=cv2.INTER_NEAREST)
    detector = cv2.QRCodeDetector()
    val, _, _ = detector.detectAndDecode(upscaled)
    return val

# === Run Example ===
if __name__ == "__main__":
    image_path = "decoding/IMG_1940.PNG"  # Replace with your image path
    qr_img = extract_qr_from_blue_lsb(image_path, qr_shape=(47, 47), block_size=8)
    qr_img.save("qr/output/test_extracted_qr_1.png")  # Optional: visualize extracted QR

    decoded = decode_qr_image(qr_img)
    print(f"Decoded QR content: {decoded}")