# Build context is the repo root (see docker-compose.yml: context: .),
# so this Dockerfile can pull in libs/common alongside backend/ itself.
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY libs/common ./common
COPY backend/ .

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --retries=10 --start-period=10s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
