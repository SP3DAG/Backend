from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
import uuid
import io

# Import your decoding logic
from decoding.decoding import extract_qr_from_blue_lsb, decode_qr_image

# === Setup ===
app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="super-secret-session-key")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === OAuth Setup ===
config = Config(environ={
    "GITHUB_CLIENT_ID": "Ov23liP9xQGJp29wZO5s",
    "GITHUB_CLIENT_SECRET": "47c7eefa4acccaf3f9c7044ae7898d2bbc520727"
})

oauth = OAuth(config)
oauth.register(
    name='github',
    client_id=config("GITHUB_CLIENT_ID"),
    client_secret=config("GITHUB_CLIENT_SECRET"),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    userinfo_endpoint='https://api.github.com/user',
    client_kwargs={'scope': 'user:email'},
)

# === In-memory link store ===
linked_devices = {}  # {code: user_id}


# === Routes ===

@app.get("/")
def home():
    return HTMLResponse("<a href='/auth/github'>Login with GitHub</a>")


@app.get("/auth/github")
async def login(request: Request):
    redirect_uri = request.url_for("auth_callback")
    return await oauth.github.authorize_redirect(request, redirect_uri)


@app.get("/auth/github/callback")
async def auth_callback(request: Request):
    token = await oauth.github.authorize_access_token(request)
    userinfo = await oauth.github.get("user", token=token)
    github_user = userinfo.json()
    user_id = github_user["id"]

    # Generate code
    code = uuid.uuid4().hex[:8].upper()
    linked_devices[code] = user_id

    return HTMLResponse(f"""
    <h3>Signed in as {github_user['login']}</h3>
    <p>Your link code: <code>{code}</code></p>
    <p>Enter this code in the GeoCam app to upload your public key.</p>
    """)


@app.post("/api/link-device/")
async def link_device(code: str = Form(...), public_key: str = Form(...)):
    user_id = linked_devices.pop(code, None)
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    # Save the public key to database or file (not implemented here)
    print(f"[✔] Linked device to GitHub user ID: {user_id}")
    print(f"[🔑] Received public key:\n{public_key}")

    return JSONResponse({"success": True, "linked_to": user_id})


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