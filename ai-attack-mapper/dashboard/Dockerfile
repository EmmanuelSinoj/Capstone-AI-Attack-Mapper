# Build context is the PROJECT ROOT (see docker-compose.yml's
# `build.context: .`) purely for consistency with the testbed's
# Dockerfile -- this image doesn't actually need anything outside
# dashboard/ baked in. alerts.db and the reports/
# directory are bind-mounted read-only at runtime instead (see
# docker-compose.yml), so a new alert or report file shows up on the
# next poll with no rebuild required.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

COPY dashboard/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/app.py ./app.py
COPY dashboard/static ./static

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
