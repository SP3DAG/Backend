from PIL import Image
import numpy as np
import matplotlib.pyplot as plt

# Load and convert image to grayscale
image = Image.open("qr/output/test_with_qr.png").convert("L")  # Replace with your image path
image_array = np.array(image)

# Plot all 8 bit planes
fig, axes = plt.subplots(2, 4, figsize=(16, 8))
fig.suptitle("Bit Planes 1 to 8 (LSB to MSB)")

for bit in range(8):
    # Extract bit plane and scale to 0-255
    bit_plane = ((image_array >> bit) & 1) * 255
    ax = axes[bit // 4, bit % 4]
    ax.imshow(bit_plane, cmap='gray')
    ax.set_title(f"Bit Plane {bit + 1}")
    ax.axis('off')

plt.tight_layout()
plt.savefig("bit_planes.png")
plt.show()