# ==============================================================================
# Aegis Zero-Trust MCP Gateway - Container Specification
# ==============================================================================
FROM python:3.11-slim-bullseye

# System dependencies for high-performance networking and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm

# Copy gateway application source code
COPY . .

# Run as non-privileged security user
RUN useradd -m -u 10001 aegisuser && chown -R aegisuser:aegisuser /app
USER aegisuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
