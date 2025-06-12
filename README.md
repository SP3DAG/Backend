# GeoCam Backend

This is the backend server for **GeoCam**, a project that facilitates secure device linking and QR code-based authentication using public-key cryptography.

## Overview

The backend is built with **FastAPI** and serves three primary purposes:

1. **Device Pairing via QR Codes**: It generates a QR code containing a secure token and a device UUID, which a client device can scan to initiate linking.
2. **Public Key Registration**: Once a device has scanned the QR code, it completes the pairing process by submitting a public key.
3. **Image Verification**: It verifies signed QR code images by decoding them using the previously registered public key.

---

## Endpoints

### `GET /`

Returns a simple health check message:

```json
{ "message": "GeoCam backend running" }
```

---

### `GET /generate-qr-link`

Generates a QR code PNG image containing a `token` and `uuid`. These are temporarily stored for 10 minutes (600 seconds) in-memory.

**Response**: `image/png` – the QR code image.

---

### `POST /api/complete-link`

Completes the device linking by submitting the token and a PEM-formatted public key.

**Form Data**:
- `token`: the token obtained from the QR code
- `public_key`: the device’s public key in PEM format

**Response**:

```json
{
  "success": true,
  "device_uuid": "GeoCam_1"
}
```

---

### `POST /verify-image/`

Verifies the QR code in an uploaded image by decoding it and checking its cryptographic signature against the device’s registered public key.

**Form Data**:
- `device_uuid`: The ID assigned during QR generation
- `file`: Image file containing a signed QR code

**Response** (on success):

```json
{
  "decoded_message": "<original_signed_message>"
}
```

---

## Public Key Handling

- Public keys are stored in-memory.
- Keys are looked up using the device UUID provided during verification.

---

## Running the Server

To run locally or deploy (e.g., on Render or similar services):

```bash
uvicorn main:app --host 0.0.0.0 --port 10000
```

### Dependencies

- `fastapi`
- `uvicorn`
- `cryptography`
- `qrcode`
- `python-multipart` (for form data handling)
- `Pillow` (for QR code image handling)

Install them with:

```bash
pip install -r requirements.txt
```
---

## Notes

- Tokens expire after 10 minutes to prevent stale link attempts.
- All data is stored in-memory and is not persisted across restarts (except saved public keys).
- Intended to be used in tandem with a client app that can:
  - Scan QR codes
  - Sign QR payloads
  - Upload signed images for verification