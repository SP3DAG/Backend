# test_decoder.py

from decoding.decoding import decode_qr_image

def test_decode_valid_image():
    image_path = "/Users/moritzdenk/Documents/IMG_2110.PNG"

    try:
        message = decode_qr_image(image_path)
        print("Decoded message:")
        print(message)
    except Exception as e:
        print("Failed to decode image:")
        print(str(e))

if __name__ == "__main__":
    test_decode_valid_image()