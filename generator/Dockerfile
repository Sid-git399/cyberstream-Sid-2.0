# Build context is the repo root (see docker-compose.yml: context: .).
FROM python:3.12-slim

WORKDIR /app

COPY generator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY libs/common ./common
COPY generator/ .

ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
