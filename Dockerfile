# Phishing Triage Bot - production-ish demo image
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

# Dependencies pehle copy/install karte hain (Docker layer cache ke liye)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# App code copy
COPY . .

# Non-root user (security best practice) + writable data dir
RUN useradd --create-home --uid 1001 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# waitress = production WSGI server (Flask dev server nahi)
CMD ["waitress-serve", "--listen=0.0.0.0:5000", "app:app"]
