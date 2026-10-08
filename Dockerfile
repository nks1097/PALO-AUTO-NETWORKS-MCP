# Multi-stage build para segurança e imagem enxuta
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --user .

# Imagem final de execução
FROM python:3.12-slim AS runner

WORKDIR /app

# Cria usuário não-root por segurança
RUN groupadd -r mcpuser && useradd -r -g mcpuser -d /app -s /sbin/nologin mcpuser

COPY --from=builder /root/.local /home/mcpuser/.local
COPY src/ ./src/

ENV PATH=/home/mcpuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER mcpuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "from paloalto_mcp.registry import validate_registry; validate_registry()" || exit 1

ENTRYPOINT ["paloalto-mcp"]
