from cryptography.hazmat.primitives.serialization import load_pem_public_key
from decoding.decoding import decode_qr_image


if __name__ == "__main__":
    image_path = "/Users/moritzdenk/Documents/IMG_2007.PNG"
    public_key_path = "public_keys/my-key.pem"

    with open(public_key_path, "rb") as f:
        public_key = load_pem_public_key(f.read())

    result = decode_qr_image(image_path, public_key)

    if result:
        print("Decoded message:", result)
    else:
        print("Failed to decode or verify QR code.")