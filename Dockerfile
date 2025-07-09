# base image 
FROM python:3.11-slim

# system deps (zbar
RUN apt-get update \
 && apt-get install -y --no-install-recommends libzbar0 \
 && rm -rf /var/lib/apt/lists/*

# python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# app code
COPY . /app
WORKDIR /app

# run
CMD ["python", "main.py"]