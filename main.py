from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import io

# Import your decoding logic
from decoding.decoding import extract_qr_from_blue_lsb, decode_qr_image

app = FastAPI()

# Add CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/verify-image/")
async def verify_image(file: UploadFile = File(...)):
    try:
        contents = await file.read()

        # Extract and decode (with hardcoded shape and block size)
        qr_img = extract_qr_from_blue_lsb(
            image_path=io.BytesIO(contents),
            qr_shape=(47, 47),
            block_size=8
        )
        decoded_message = decode_qr_image(qr_img)

        if not decoded_message:
            raise HTTPException(status_code=422, detail="QR code could not be decoded")

        return JSONResponse(content={"decoded_message": decoded_message})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process image: {str(e)}")