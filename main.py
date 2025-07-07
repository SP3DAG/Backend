from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
import secrets, json, os, io
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from lsb_plot import plot_blue_lsb
from decoding.decoding import decode_all_qr_codes

# === Persistent Storage Setup ===
PERSIST_DIR = os.getenv("PERSIST_DIR", "/var/data")
KEYS_DIR = os.path.join(PERSIST_DIR, "public_keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# === In-memory token & ID tracking ===
tokens = {}
device_id_counter = 0
public_keys = {}

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

def save_public_key(device_id: str, public_key: str):
    public_keys[device_id] = public_key

    # Save PEM file
    pem_path = os.path.join(KEYS_DIR, f"{device_id}.pem")
    with open(pem_path, "w") as f:
        f.write(public_key)

    # Update JSON key registry
    json_path = os.path.join(KEYS_DIR, "public_keys.json")

    try:
        with open(json_path, "r") as f:
            existing = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing = {}

    existing[device_id] = public_key

    with open(json_path, "w") as f:
        json.dump(existing, f, indent=2)

# === FastAPI Setup ===
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
async def verify_image(file: UploadFile = File(...)):
    try:
        # 1) persist the upload
        temp_path = os.path.join(PERSIST_DIR, "temp_uploaded.png")
        contents = await file.read()
        with open(temp_path, "wb") as f:
            f.write(contents)

        # 2) run the decoder   (returns ONLY fully-verified QR tiles)
        #    Each element:  {"payload", "device_id", "total", "index"}
        decoded_results = decode_all_qr_codes(temp_path)

        # no valid signatures at all
        if not decoded_results:
            raise HTTPException(status_code=422,
                                detail="No valid QR/signature pair found.")

        # 3) payload consistency check
        payloads = {r["payload"] for r in decoded_results}
        if len(payloads) != 1:
            raise HTTPException(status_code=422,
                                detail="Inconsistent QR messages found.")
        message = payloads.pop()

        # 4) structural integrity check
        total_expected = decoded_results[0]["total"]      # signed!
        indexes_found  = {r["index"] for r in decoded_results}

        if (len(indexes_found) == total_expected and
                indexes_found == set(range(total_expected))):
            status = "verified"
        else:
            status = "verified_but_image_modified"

        # 5) success JSON
        return JSONResponse(content={
            "status":          status,
            "decoded_message": message,
            "expected_qrs":    total_expected,
            "found_qrs":       len(indexes_found)
        })
    
    # 6) error handling
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"Image processing failed: {str(e)}")
    
@app.get("/api/public-keys", response_class=FileResponse)
async def download_public_keys():
    json_path = os.path.join(KEYS_DIR, "public_keys.json")
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename="public_keys.json"
    )

@app.post("/plot-lsb/")
async def plot_lsb(file: UploadFile = File(...)):
    """
    Upload an image and receive a PNG visualising the blue-channel LSB
    with QR tile bounding boxes.
    """
    try:
        image_bytes = await file.read()
        plot_bytes = plot_blue_lsb(image_bytes)

        return StreamingResponse(
            io.BytesIO(plot_bytes),
            media_type="image/png",
            headers={"Content-Disposition": 'inline; filename="lsb_debug.png"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500,
                            detail=f"LSB plot generation failed: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000)