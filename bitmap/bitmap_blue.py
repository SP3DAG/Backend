from PIL import Image
import numpy as np
import matplotlib.pyplot as plt

# Load image and convert to RGB
image = Image.open("/Users/moritzdenk/Documents/IMG_2084.PNG").convert("RGB")
image_array = np.array(image)

# Extract the blue channel (channel index 2)
blue_channel = image_array[:, :, 2]

# Plot all 8 bit planes from the blue channel
fig, axes = plt.subplots(2, 4, figsize=(16, 8))
fig.suptitle("Blue Channel Bit Planes (LSB to MSB)")

for bit in range(8):
    # Extract bit plane and scale to 0-255
    bit_plane = ((blue_channel >> bit) & 1) * 255
    ax = axes[bit // 4, bit % 4]
    ax.imshow(bit_plane, cmap='gray')
    ax.set_title(f"Bit Plane {bit + 1}")
    ax.axis('off')

plt.tight_layout()
plt.savefig("bitmap/blue_channel_bit_planes.png")
plt.show()