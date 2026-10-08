"""
Configuração do pytest e injeção de dependências para a suíte de testes.
"""

import sys
from pathlib import Path

import pytest

# Adiciona diretório src ao path do Python
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import paloalto_mcp.tools  # noqa: F401, E402
from paloalto_mcp.registry import REGISTERED_TOOLS  # noqa: E402


@pytest.fixture
def registered_tools():
    return REGISTERED_TOOLS
