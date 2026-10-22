FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    ENV=prod

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY agents ./agents
COPY api ./api
COPY db ./db
COPY docs ./docs
COPY legacy ./legacy
COPY STATUS.md ./STATUS.md

# Run as non-root user in production container
RUN useradd -m -u 10001 atlasuser && chown -R atlasuser:atlasuser /app
USER atlasuser

EXPOSE 8080

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
