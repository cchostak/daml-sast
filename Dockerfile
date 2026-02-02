# syntax=docker/dockerfile:1
FROM python:3.13-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt requirements-dev.txt pyproject.toml README.md ./
COPY daml_sast ./daml_sast

RUN pip install --upgrade pip && \
    pip install --no-deps -r requirements.txt && \
    pip install --no-deps .

ENTRYPOINT ["daml-sast"]
CMD ["scan", "--help"]
