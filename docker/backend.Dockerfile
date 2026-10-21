FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 vibeguard
WORKDIR /app

COPY pyproject.toml ./
COPY vibeguard ./vibeguard
COPY alembic.ini ./
COPY alembic ./alembic
RUN pip install --no-cache-dir ".[anthropic,service]"

USER vibeguard
# Fetch Tree-sitter grammars at build time so workers never download at scan time
RUN python -c "from tree_sitter_language_pack import get_parser; [get_parser(l) for l in ('javascript', 'typescript', 'tsx')]"

ENV PYTHONUNBUFFERED=1
