from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
from qr_code import MultiQRLSBStego  # Adjust path if needed
import cv2
import os

# === SETUP ===
message = "This class is stupid."
cover_image = "test.jpeg"  # Use your original cover image

qr = MultiQRLSBStego(block_size=8, debug=True)

# === 1. Generate QR and Embed ===
qr_matrix = qr.generate_qr_matrix(message)
stego_path, positions, shape = qr.embed_multiple(cover_image, qr_matrix, output_path="qr_lsb_multi_stego.png")

# === 2. Visualize Bit Plane 1 ===
image = Image.open(stego_path).convert("L")
image_array = np.array(image)

bit_plane_1 = (image_array & 1) * 255
enhanced = np.clip((bit_plane_1 - np.min(bit_plane_1)) * (255.0 / (np.max(bit_plane_1) - np.min(bit_plane_1))), 0, 255).astype(np.uint8)

plt.figure(figsize=(6, 6))
plt.imshow(enhanced, cmap='gray')
plt.title("Enhanced Bit Plane 1 (LSB)")
plt.axis('off')
plt.tight_layout()
plt.savefig("bit_plane_1_enhanced.png")
plt.show()

# === 3. Try Decoding from Bit Plane 1 Directly ===
rgb_from_lsb = np.stack([bit_plane_1] * 3, axis=-1).astype(np.uint8)
Image.fromarray(rgb_from_lsb).save("bit_plane_1_rgb.png")

results = qr.test_all_qrs("bit_plane_1_rgb.png", positions, shape)

print("\nDecoded from Bit Plane 1 (Direct):")
for idx, decoded in results:
    print(f"QR #{idx}: {decoded}")