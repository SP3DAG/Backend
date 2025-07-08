import os, io, json, secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from decoding.decoding import decode_all_qr_codes

# Persistent Storage
PERSIST_DIR = os.getenv("PERSIST_DIR", "/var/data")
KEYS_DIR    = os.path.join(PERSIST_DIR, "public_keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# In-memory token & key tracking
tokens, public_keys = {}, {}
device_id_counter   = 0

def generate_device_id() -> str:
    global device_id_counter
    device_id_counter += 1
    return f"GeoCam_{device_id_counter}"

def store_token(token: str, device_id: str, ttl: int = 600):
    tokens[token] = {
        "uuid":    device_id,
        "expires": datetime.now(timezone.utc) + timedelta(seconds=ttl)
    }

def get_token(token: str):
    entry = tokens.get(token)
    if not entry or datetime.now(timezone.utc) > entry["expires"]:
        tokens.pop(token, None)
        return None
    return entry["uuid"]

def delete_token(token: str): tokens.pop(token, None)

def save_public_key(device_id: str, pem: str):
    public_keys[device_id] = pem
    pem_path = os.path.join(KEYS_DIR, f"{device_id}.pem")
    with open(pem_path, "w") as fh: fh.write(pem)

    registry = {}
    json_path = os.path.join(KEYS_DIR, "public_keys.json")
    if os.path.exists(json_path):
        try:
            with open(json_path) as fh: registry = json.load(fh)
        except json.JSONDecodeError:
            registry = {}
    registry[device_id] = pem
    with open(json_path, "w") as fh: json.dump(registry, fh, indent=2)

# FastAPI setup
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_methods = ["*"],
    allow_headers = ["*"],
    allow_credentials = True
)

# Routes
@app.get("/")
def home(): return {"message": "GeoCam backend running"}

# Device pairing
@app.get("/api/generate-link-token")
async def generate_link_token():
    token     = secrets.token_urlsafe(16)
    device_id = generate_device_id()
    store_token(token, device_id)
    return JSONResponse({"token": token, "device_uuid": device_id})

@app.post("/api/complete-link")
async def complete_link(token: str = Form(...), public_key: str = Form(...)):
    device_id = get_token(token)
    if not device_id:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    save_public_key(device_id, public_key)
    delete_token(token)
    return JSONResponse({"success": True, "device_uuid": device_id})

# Image verification
@app.post("/verify-image/")
async def verify_image(file: UploadFile = File(...)):
    """
    Accepts a PNG/JPEG with tiled-QR steganography.
    Returns 'verified' if every tile is present & authentic,
    else 'verified_but_image_modified' when at least one authentic tile exists.
    """
    try:
        tmp_path = os.path.join(PERSIST_DIR, "temp_uploaded.png")
        with open(tmp_path, "wb") as fh:
            fh.write(await file.read())

        tiles = decode_all_qr_codes(tmp_path)

        if not tiles:
            raise HTTPException(status_code=422,
                                detail="No valid signed QR tiles found.")

        # All tiles must share the same device_id
        dev_ids = {t["device_id"] for t in tiles}
        if len(dev_ids) != 1:
            raise HTTPException(status_code=422,
                                detail="Mixed device IDs in image.")
        device_id = dev_ids.pop()

        # Grid completeness test
        xs = {t["tile_x"] for t in tiles}
        ys = {t["tile_y"] for t in tiles}
        full_grid = (xs == set(range(max(xs)+1)) and
                     ys == set(range(max(ys)+1)))

        status = "verified" if full_grid else "verified_but_image_modified"

        return JSONResponse({
            "status":         status,
            "device_id":      device_id,
            "tiles_verified": len(tiles),
            "grid_cols":      max(xs)+1,
            "grid_rows":      max(ys)+1
        })

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500,
                            detail=f"Image processing failed: {exc}")

# Public-key registry download
@app.get("/api/public-keys", response_class=FileResponse)
async def download_public_keys():
    jpath = os.path.join(KEYS_DIR, "public_keys.json")
    if not os.path.exists(jpath):
        raise HTTPException(status_code=404, detail="Registry not found")
    return FileResponse(jpath, media_type="application/json",
                        filename="public_keys.json")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000)