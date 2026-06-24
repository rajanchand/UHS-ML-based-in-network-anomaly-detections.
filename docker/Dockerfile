# =============================================================================
# Aegis ML-IDS - Multi-Stage Container Dockerfile
# =============================================================================

# --- Stage 1: Build Dependencies ---
FROM python:3.11-slim AS builder

WORKDIR /build

# Install system dependencies needed for compiling python wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: Final Production Stage ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Install runtime dependencies (libpq for Postgres, magic for MIME detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder stage
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application source code
COPY app/ app/
COPY wsgi.py .

# Expose default Gunicorn interface port
EXPOSE 5000

# Set environment production flag
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Create execution script
RUN echo '#!/bin/sh\n\
python3 -c "from app import create_app; from app.extensions import db; app = create_app(); with app.app_context(): db.create_all()"\n\
flask db upgrade || true\n\
gunicorn wsgi:app --bind 0.0.0.0:5000 --workers 4 --threads 2 --timeout 60\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Run under entrypoint
CMD ["/entrypoint.sh"]
