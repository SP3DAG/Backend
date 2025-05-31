# Backend for Studyproject

This backend is supposed to serve the app for QR code generation and validation of the signed images.

# Setup

## Create venv

```sh
python -m venv venv
```

## Install requirements

```sh
pip install -r requirements.txt
```

# How to run

## To serve the backend
The FastAPI backend serves for decoding and verification of the QR code embedded image from the camera app.

```sh
uvicorn main:app --reload    
```

## Test QR code hiding

```sh
python qr/qr_code.py
```

## Test QR code high for channel *blue*

```sh
python qr/qr_code_blue.py
```

## Decode the image

```sh
python decoding/decoding.py
```

## Plot bitmap for channel blue

```sh
python bitmap/bitmap_blue.py
```