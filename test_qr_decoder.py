from cryptography.hazmat.primitives import serialization
from decoding.decoding import decode_qr_image, extract_qr_and_signature, qr_matrix_to_image

def load_public_key(pem_path):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def save_qr_matrix_as_image(image_path, output_path="extracted_qr.png"):
    try:
        qr_matrix, _, _ = extract_qr_and_signature(image_path)
        img = qr_matrix_to_image(qr_matrix)
        img.save(output_path)
        print(f"Extracted QR matrix saved as '{output_path}'")
    except Exception as e:
        print(f"Failed to extract and save QR image: {e}")

def main():
    image_path = "/Users/moritzdenk/Documents/IMG_2084.PNG"
    public_key_path = "public_keys/my-key.pem"

    # Optional: Save QR image for debugging
    save_qr_matrix_as_image(image_path)

    public_key = load_public_key(public_key_path)
    message = decode_qr_image(image_path, public_key)

    if message is not None:
        print("Decoded Message:", message)
    else:
        print("Failed to verify or decode the QR code.")

if __name__ == "__main__":
    main()