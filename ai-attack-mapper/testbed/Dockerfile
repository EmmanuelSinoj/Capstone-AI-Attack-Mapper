# Build context is the PROJECT ROOT (see docker-compose.yml's
# `build.context: .`), not this directory -- that's what lets this
# image also pull in alert_store/ and live_attack_path/detection/,
# which live outside live_attack_path/testbed/ but are imported by
# app.py at runtime.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

COPY live_attack_path/testbed/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY live_attack_path/testbed/app.py ./app.py
COPY live_attack_path/testbed/system_prompt.txt ./system_prompt.txt
COPY live_attack_path/detection ./detection
COPY alert_store ./alert_store

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
