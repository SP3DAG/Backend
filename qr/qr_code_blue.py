import numpy as np
from PIL import Image
import qrcode
import cv2
import os

class MultiQRLSBStegoBlueOnly:
    def __init__(self, block_size=8, debug=True):
        self.block_size = block_size
        self.debug = debug

    def _log(self, msg):
        if self.debug:
            print(f"[DEBUG] {msg}")

    def generate_qr_matrix(self, message: str, version=2) -> np.ndarray:
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
        binarized = (arr < 128).astype(np.uint8)
        return binarized

    def embed_multiple_blue(self, cover_image_path, qr_matrix, output_path="qr/output/qr_lsb_multi_blue.png"):
        img = Image.open(cover_image_path).convert("RGB")
        img_arr = np.array(img).copy()

        h, w = qr_matrix.shape
        block = self.block_size
        bh, bw, _ = img_arr.shape

        qrh_pixels = h * block
        qrw_pixels = w * block

        max_rows = bh // qrh_pixels
        max_cols = bw // qrw_pixels

        positions = []

        self._log(f"Embedding {max_rows * max_cols} QR codes ({max_rows} rows × {max_cols} cols)")

        for row in range(max_rows):
            for col in range(max_cols):
                top = row * qrh_pixels
                left = col * qrw_pixels
                positions.append((top, left))
                for i in range(h):
                    for j in range(w):
                        val = qr_matrix[i, j]
                        y = top + i * block
                        x = left + j * block
                        for dy in range(block):
                            for dx in range(block):
                                yy, xx = y + dy, x + dx
                                if yy < bh and xx < bw:
                                    img_arr[yy, xx, 2] = (img_arr[yy, xx, 2] & 0xFE) | val  # Blue only

        Image.fromarray(img_arr).save(output_path)
        self._log(f"Multi-QR stego image saved to {output_path}")
        return output_path, positions, qr_matrix.shape

    def extract_from_position_blue(self, image_path, top, left, qr_shape):
        img = np.array(Image.open(image_path).convert("RGB"))
        h, w = qr_shape
        block = self.block_size

        matrix = np.zeros((h, w), dtype=np.uint8)
        for i in range(h):
            for j in range(w):
                y = top + i * block
                x = left + j * block
                bits = []
                for dy in range(block):
                    for dx in range(block):
                        yy, xx = y + dy, x + dx
                        if yy >= img.shape[0] or xx >= img.shape[1]:
                            continue
                        blue = img[yy, xx, 2]
                        bits.append(blue & 1)
                matrix[i, j] = 1 if np.mean(bits) >= 0.5 else 0

        matrix_padded = np.pad(matrix, pad_width=4, constant_values=0)
        arr = ((1 - matrix_padded) * 255).astype(np.uint8)
        return Image.fromarray(arr)

    def decode_qr_image(self, img: Image.Image):
        arr = np.array(img.convert("L"))
        _, binary = cv2.threshold(arr, 128, 255, cv2.THRESH_BINARY)
        upscaled = cv2.resize(binary, (binary.shape[1]*10, binary.shape[0]*10), interpolation=cv2.INTER_NEAREST)
        detector = cv2.QRCodeDetector()
        val, _, _ = detector.detectAndDecode(upscaled)
        return val

    def test_all_qrs(self, image_path, positions, qr_shape):
        results = []
        for idx, (top, left) in enumerate(positions):
            extracted = self.extract_from_position_blue(image_path, top, left, qr_shape)
            decoded = self.decode_qr_image(extracted)
            results.append((idx, decoded))
            extracted.save(f"qr/extracted_qrs/qr_extracted_blue_{idx}.png")
            self._log(f"QR #{idx} decoded: {decoded}")
        return results
    
if __name__ == "__main__":

    message = "Hidden via blue channel only"
    cover_image = "qr/test.jpeg"  # Replace with your image path

    qr = MultiQRLSBStegoBlueOnly(block_size=8, debug=True)
    qr_matrix = qr.generate_qr_matrix(message, version=2)

    stego_path, positions, shape = qr.embed_multiple_blue(
        cover_image_path=cover_image,
        qr_matrix=qr_matrix,
        output_path="qr/output/multi_qr_blue_only.png"
    )

    results = qr.test_all_qrs(stego_path, positions, shape)

    print("\nDecoded Results:")
    for idx, decoded in results:
        print(f"QR #{idx}: {decoded}")
