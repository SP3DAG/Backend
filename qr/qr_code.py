import numpy as np
from PIL import Image
import qrcode
import cv2
from matplotlib import pyplot as plt
import matplotlib.patches as patches

"""
MultiQRLSBStego: A class for embedding multiple QR codes into an image using LSB steganography.
"""

class MultiQRLSBStego:
    
    def __init__(self, block_size=8, debug=True):
        """
        Initializes the steganography object, setting the size of each QR-pixel block in the cover image and whether to print debug messages.
        """
        self.block_size = block_size
        self.debug = debug


    def _log(self, msg):
        """
        Prints a debug message prefixed with “[DEBUG]” if debugging is enabled.
        """
        if self.debug:
            print(f"[DEBUG] {msg}")


    def generate_qr_matrix(self, message: str, version=2) -> np.ndarray:
        """
        Builds a QR code for the given text, converts it to a binary NumPy array (1 for black, 0 for white), saves a PNG of the raw QR, and returns the binary matrix.
        """
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
        Image.fromarray(arr).save("qr/output/debug_qr_original.png")
        return binarized
    

    def embed_multiple(self, cover_image_path, qr_matrix, output_path="qr_lsb_multi_stego.png"):
        """
        Opens a cover image, tiles qr_matrix across it by embedding each bit into the least significant bit of every pixel in block_size x block_size blocks,
        saves the stego image, and returns the output filename, a list of top-left positions for each embedded QR, and the QR's (height, width).
        """
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
                                    for c in range(3):
                                        img_arr[yy, xx, c] = (img_arr[yy, xx, c] & 0xFE) | val

        Image.fromarray(img_arr).save(output_path)
        self._log(f"Multi-QR stego image saved to {output_path}")
        return output_path, positions, qr_matrix.shape
    

    def extract_from_position(self, image_path, top, left, qr_shape) -> Image.Image:
        """
        Reads the stego image, for the QR at (top,left) reconstructs each QR bit by averaging the LSBs in the corresponding block,
        pads it for quiet zones, inverts & scales to 0-255, and returns it as a PIL image.
        """
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
                        r, g, b = img[yy, xx]
                        bits.extend([r & 1, g & 1, b & 1])
                matrix[i, j] = 1 if np.mean(bits) >= 0.5 else 0

        matrix_padded = np.pad(matrix, pad_width=4, constant_values=0)
        arr = ((1 - matrix_padded) * 255).astype(np.uint8)
        return Image.fromarray(arr)
    

    def decode_qr_image(self, img: Image.Image):
        """
        Converts a extracted QR image to binary, upscales it for reliability, then uses OpenCV's QRCodeDetector to decode and return the embedded message.
        """
        arr = np.array(img.convert("L"))
        _, binary = cv2.threshold(arr, 128, 255, cv2.THRESH_BINARY)
        upscaled = cv2.resize(binary, (binary.shape[1]*10, binary.shape[0]*10), interpolation=cv2.INTER_NEAREST)
        detector = cv2.QRCodeDetector()
        val, _, _ = detector.detectAndDecode(upscaled)
        return val
    

    def test_all_qrs(self, image_path, positions, qr_shape):
        """
        Iterates over all stored positions, calls extract_from_position and decode_qr_image for each, saves each extracted QR as a PNG, 
        logs & collects their decoded texts, and returns a list of (index, decoded_string) tuples.
        """
        results = []
        for idx, (top, left) in enumerate(positions):
            extracted = self.extract_from_position(image_path, top, left, qr_shape)
            decoded = self.decode_qr_image(extracted)
            results.append((idx, decoded))
            extracted.save(f"qr/extracted_qrs/qr_extracted_{idx}.png")
            self._log(f"QR #{idx} decoded: {decoded}")
        return results
    def plot_qr_positions(self, image_path, positions, qr_shape):
        """
        Displays the stego image with red rectangles and labels over each embedded-QR region to visualize where QRs were hidden.
        """
        img = np.array(Image.open(image_path))
        block = self.block_size
        h, w = qr_shape

        fig, ax = plt.subplots(figsize=(10, 10))
        ax.imshow(img)
        for idx, (top, left) in enumerate(positions):
            rect = patches.Rectangle(
                (left, top), w * block, h * block,
                linewidth=2, edgecolor='red', facecolor='none'
            )
            ax.add_patch(rect)
            ax.text(left + 5, top + 15, f"QR#{idx}", color="yellow", fontsize=8, bbox=dict(facecolor='black', alpha=0.5))
        ax.set_title("QR Code Regions (LSB-Embedded)")
        plt.axis('off')
        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    message = "This is a test"
    cover_image = "qr/test.jpeg"  # Replace with your image

    qr = MultiQRLSBStego(block_size=8, debug=True)
    qr_matrix = qr.generate_qr_matrix(message, version=2)

    stego_path, positions, shape = qr.embed_multiple(
        cover_image_path=cover_image,
        qr_matrix=qr_matrix,
        output_path="qr/output/test_with_qr.png"
    )

    results = qr.test_all_qrs(stego_path, positions, shape)

    print("\nDecoding Results:")
    for idx, decoded in results:
        print(f"QR #{idx}: {decoded}")
    
    qr.plot_qr_positions(stego_path, positions, shape)