from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import redis, uuid, secrets, json, io, os, qrcode
from datetime import timedelta
from decoding.decoding import extract_qr_from_blue_lsb, decode_qr_image

# Redis Setup
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# FastAPI Setup
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# Helpers
def save_public_key(device_id: str, public_key: str):
    os.makedirs("public_keys", exist_ok=True)
    with open(f"public_keys/{device_id}.pem", "w") as f:
        f.write(public_key)

# === Routes ===

@app.get("/")
def home():
    return {"message": "GeoCam backend running"}

@app.get("/generate-qr-link")
async def generate_qr_link():
    device_uuid = str(uuid.uuid4())
    token = secrets.token_urlsafe(16)
    redis_client.setex(f"link_token:{token}", timedelta(minutes=10), device_uuid)

    qr_payload = {"token": token, "uuid": device_uuid}
    qr_img = qrcode.make(json.dumps(qr_payload))
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")

@app.post("/api/complete-link")
async def complete_link(token: str = Form(...), public_key: str = Form(...)):
    device_uuid = redis_client.get(f"link_token:{token}")
    if not device_uuid:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    save_public_key(device_uuid, public_key)
    redis_client.delete(f"link_token:{token}")

    return JSONResponse({"success": True, "device_uuid": device_uuid})

@app.post("/verify-image/")
async def verify_image(device_uuid: str = Form(...), file: UploadFile = File(...)):
    try:
        contents = await file.read()
        with open("temp_uploaded.png", "wb") as f:
            f.write(contents)

        decoded_message = decode_qr_image("temp_uploaded.png", device_id=device_uuid)
        if not decoded_message:
            raise HTTPException(status_code=422, detail="QR decode or signature invalid.")

        return JSONResponse(content={"decoded_message": decoded_message})
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image processing failed: {str(e)}")
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000)