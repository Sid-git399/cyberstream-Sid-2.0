# Build context is the repo root (see docker-compose.yml: context: .).
FROM bitnami/spark:3.5.3

WORKDIR /app

USER root
COPY streaming/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY libs/common ./common
COPY docs/event-schema.json ./docs/event-schema.json
COPY infrastructure/spark/detection_rules.yaml ./infrastructure/spark/detection_rules.yaml
COPY streaming/src ./src

# spark-submit takes a script path, not a `-m module` flag (unlike plain
# python) - so src/main.py's package-qualified imports (`from src.xxx
# import ...`) need /app on PYTHONPATH explicitly, since spark-submit puts
# only the script's own directory (/app/src) on sys.path[0] by default.
ENV PYTHONPATH=/app

CMD ["spark-submit", "--master", "local[*]", "src/main.py"]
