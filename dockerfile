FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ca-certificates is required for TLS verification when connecting to Neon and
# downloading CVE release assets from GitHub.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY load_cves_latest.py ./

# Run as a non-root user. The loader only needs /tmp for downloaded release ZIPs.
RUN useradd --create-home --uid 10001 appuser
USER appuser

ENTRYPOINT ["python", "load_cves_latest.py"]
