FROM python:3.12-slim AS builder

WORKDIR /build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv pip install --system --no-cache -r pyproject.toml

COPY . .
RUN uv pip install --system --no-cache --no-deps .

# -------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

RUN adduser --system --no-create-home clearwing

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

USER clearwing

ENTRYPOINT ["clearwing"]
