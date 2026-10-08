.PHONY: help install test lint check run docker-build docker-run

help:
	@echo "Comandos disponíveis:"
	@echo "  make install       Instala dependências do projeto"
	@echo "  make test          Executa a suíte de testes unitários"
	@echo "  make test-live     Executa testes de integração contra o firewall configurado"
	@echo "  make lint          Executa validação com ruff"
	@echo "  make check         Executa linter e todos os testes"
	@echo "  make run           Inicia o servidor MCP via stdio"
	@echo "  make docker-build  Gera a imagem Docker de produção"

install:
	pip install -e ".[dev]"

test:
	pytest tests/unit -v

test-live:
	pytest tests/integration/test_live_firewall.py -v

lint:
	ruff check src/ tests/

check: lint test

run:
	python -m paloalto_mcp.server

docker-build:
	docker build -t paloalto-mcp:latest .
