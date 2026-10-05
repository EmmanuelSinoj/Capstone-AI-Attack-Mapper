# Build context is the PROJECT ROOT (see docker-compose.yml's
# `build.context: .`), not this directory -- that's what lets this
# image also pull in alert_store/ and detection/,
# which live outside testbed/ but are imported by
# app.py at runtime.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

COPY testbed/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY testbed/app.py ./app.py
COPY testbed/system_prompt.txt ./system_prompt.txt
COPY detection ./detection
COPY alert_store ./alert_store

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
