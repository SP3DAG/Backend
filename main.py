from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
import secrets, json, io, os, qrcode
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from decoding.decoding import decode_qr_image

# === In-memory token & ID tracking ===
tokens = {}
device_id_counter = 0
public_keys = {}  # In-memory store for public keys by device ID

def generate_device_id():
    global device_id_counter
    device_id_counter += 1
    return f"GeoCam_{device_id_counter}"

def store_token(token, device_id, ttl_seconds=600):
    tokens[token] = {
        "uuid": device_id,
        "expires": datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    }

def get_token(token):
    entry = tokens.get(token)
    if not entry:
        return None
    if datetime.now(timezone.utc) > entry["expires"]:
        del tokens[token]
        return None
    return entry["uuid"]

def delete_token(token):
    tokens.pop(token, None)

# === FastAPI Setup ===
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Helper: Save public key ===
def save_public_key(device_id: str, public_key: str):
    public_keys[device_id] = public_key
    os.makedirs("public_keys", exist_ok=True)
    with open(f"public_keys/{device_id}.pem", "w") as f:
        f.write(public_key)

def get_public_key(device_id: str):
    key_pem = public_keys.get(device_id)
    if not key_pem:
        raise FileNotFoundError(f"No public key found for device: {device_id}")
    return load_pem_public_key(key_pem.encode())

# === Routes ===

@app.get("/")
def home():
    return {"message": "GeoCam backend running"}

@app.get("/api/generate-link-token")
async def generate_link_token():
    device_id = generate_device_id()
    token = secrets.token_urlsafe(16)
    store_token(token, device_id)

    return JSONResponse({
        "token": token,
        "device_uuid": device_id
    })

@app.post("/api/complete-link")
async def complete_link(token: str = Form(...), public_key: str = Form(...)):
    print(f"[DEBUG] Linking attempt with token: {token[:6]}")
    device_id = get_token(token)
    if not device_id:
        print("Token not found or expired.")
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    save_public_key(device_id, public_key)
    delete_token(token)

    return JSONResponse({
        "success": True,
        "device_uuid": device_id
    })

@app.post("/verify-image/")
async def verify_image(device_uuid: str = Form(...), file: UploadFile = File(...)):
    try:
        contents = await file.read()
        with open("temp_uploaded.png", "wb") as f:
            f.write(contents)

        public_key = get_public_key(device_uuid)
        decoded_message = decode_qr_image("temp_uploaded.png", public_key=public_key)
        if not decoded_message:
            raise HTTPException(status_code=422, detail="QR decode or signature invalid.")

        return JSONResponse(content={"decoded_message": decoded_message})
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise  # Preserve 422 and 404
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image processing failed: {str(e)}")

# === Run Locally (or on Render) ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000)