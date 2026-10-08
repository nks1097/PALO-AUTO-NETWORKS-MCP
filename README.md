# Palo Alto Networks MCP Server (PAN-OS & Panorama)

Servidor MCP (Model Context Protocol) corporativo, modular e seguro para administração defensiva, observabilidade e automação de firewalls **Palo Alto Networks (PAN-OS)** e gerenciamento centralizado **Panorama**.

O servidor implementa **EXATAMENTE 100 ferramentas MCP padronizadas**, totalmente documentadas e descritas em português, com suporte nativo a simulação segura (**dry-run**), controle de acesso baseado em função (**RBAC**), sanitização estrita contra injeções e testes integrados ao vivo contra o firewall real.

---

## Métricas Oficiais do Registro de Ferramentas

```text
Total MCP tools: 100
Read tools: 71
Write tools: 17
Delete tools: 7
Commit tools: 1
Diagnostic tools: 4
Destructive tools: 8
Supports dry_run: 25
Panorama tools: 5
Firewall tools: 95
```

---

## 1. Arquitetura do Sistema

```text
┌────────────────────────────────────────────────────────┐
│                   Cliente MCP / IA                     │
│        (Claude Desktop, Cursor, Antigravity IDE)       │
└──────────────────────────┬─────────────────────────────┘
                           │ Protocolo MCP (stdio/SSE)
┌──────────────────────────▼─────────────────────────────┐
│                 Palo Alto MCP Server                   │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │             Registry (100 Ferramentas)           │  │
│  │       Validação Estrita: EXPECTED_TOOL_COUNT     │  │
│  └───────────────────────┬──────────────────────────┘  │
│                          │                             │
│  ┌───────────────────────▼──────────────────────────┐  │
│  │          Segurança, RBAC & Auditoria             │  │
│  │  - Allowlist de Comandos Operacionais            │  │
│  │  - Sanitização de XPath e Nomes de Objetos       │  │
│  │  - Validação de Confirmação (confirm=true)       │  │
│  │  - Redação Automática de Segredos nos Logs       │  │
│  │  - Simulação Segura (dry_run=true)               │  │
│  └───────────────────────┬──────────────────────────┘  │
│                          │                             │
│  ┌───────────────────────▼──────────────────────────┐  │
│  │             PaloAltoClient Unificado             │  │
│  │   - Connection Pool Assíncrono (httpx)           │  │
│  │   - Retry Exponencial em Falhas Transitórias     │  │
│  │   - Cache inteligente de System Info             │  │
│  └───────────────┬──────────────────────┬───────────┘  │
└──────────────────┼──────────────────────┼──────────────┘
                   │                      │
        HTTPS REST API (JSON)    HTTPS XML API (XML)
                   │                      │
┌──────────────────▼──────────────────────▼──────────────┐
│           Palo Alto Networks NGFW / Panorama           │
│                    (PAN-OS 10.x / 11.x)                │
└────────────────────────────────────────────────────────┘
```

---

## 2. Guia de Início Rápido (Quickstart)

Este projeto foi construído para que qualquer pessoa (administradores de rede, analistas de SOC, engenheiros de segurança ou entusiastas) possa conectar uma IA ao seu firewall Palo Alto Networks em poucos minutos.

### 📋 O que a pessoa precisa ter instalado no computador

Antes de começar, certifique-se de ter os seguintes programas instalados:

| Software | Versão Mínima | Para que serve | Onde baixar |
| :--- | :--- | :--- | :--- |
| **Python** | `3.12+` | Executar o servidor MCP | [python.org/downloads](https://www.python.org/downloads/) *(Marque a opção **"Add python.exe to PATH"** no instalador do Windows)* |
| **Git** | Qualquer recente | Baixar o código do repositório | [git-scm.com](https://git-scm.com/downloads) |
| **Cliente de IA** | Qualquer | Conversar com a IA e usar as ferramentas | [Claude Desktop](https://claude.ai/download), [Cursor](https://cursor.com), [VS Code](https://code.visualstudio.com) ou Antigravity IDE |

> 💡 **Não quer instalar Python?** Você também pode rodar diretamente via **Docker** usando o `docker-compose.yml` incluso!

---

### Passo 1: Como gerar sua API Key no Palo Alto
Caso ainda não tenha uma API Key gerada, você pode gerá-la facilmente pelo seu navegador ou terminal. Substitua `SEU_FIREWALL_IP`, `SEU_USUARIO` e `SUA_SENHA`:

**No Navegador ou via curl:**
```bash
curl -k "https://<SEU_FIREWALL_IP>/api/?type=keygen&user=<SEU_USUARIO>&password=<SUA_SENHA>"
```

O firewall responderá com um XML contendo a sua chave:
```xml
<response status="success">
  <result>
    <key>LUFRPT1H...sua_chave_aqui...</key>
  </result>
</response>
```
> Copie o conteúdo dentro da tag `<key>` e guarde-o com segurança.

---

### Passo 2: Clonar o Repositório e Instalar as Dependências

Abra o seu terminal (Prompt de Comando, PowerShell ou Terminal do Linux/Mac) e execute:

```bash
# 1. Clonar o projeto do GitHub
git clone https://github.com/nks1097/PALO-AUTO-NETWORKS-MCP.git

# 2. Entrar na pasta do projeto
cd PALO-AUTO-NETWORKS-MCP

# 3. (Recomendado) Criar e ativar um ambiente virtual isolado:
# No Windows:
python -m venv .venv
.venv\Scripts\activate

# No Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# 4. Instalar todas as bibliotecas necessárias com 1 comando:
pip install -r requirements.txt

# se não conseguir tente
py -m pip install -r requirements.txt
```

*(O comando `pip install -r requirements.txt` instala automaticamente o SDK oficial do MCP, bibliotecas de conexão assíncrona com o firewall, validação de regras de rede e utilitários de segurança).*

> [!IMPORTANT]
> **Atenção à versão do MCP (`mcp < 2`):**
> Este servidor utiliza a arquitetura FastMCP da versão **1.x** do SDK MCP. Versões `2.x+` possuem quebras de compatibilidade que impedem o handshake do servidor.
> O arquivo `requirements.txt` já vem protegido e fixado com `mcp>=1.2.0,<2.0.0`. Caso o seu Python já possua a versão `2.x` instalada globalmente, force a versão compatível com:
> ```bash
> pip install "mcp<2"
> ```

---

### Passo 3: Configurar as Credenciais (.env)

Copie o arquivo de modelo `.env.example` para `.env`:

```bash
# No Windows (PowerShell):
copy .env.example .env

# No Linux / macOS:
cp .env.example .env
```

Abra o arquivo `.env` e preencha com os dados do seu firewall:

```env
PANOS_HOST=https://192.168.1.1
PANOS_API_KEY=sua_chave_gerada_no_passo_1
PANOS_VERIFY_SSL=false
ALLOW_WRITE_OPERATIONS=true
ALLOW_COMMIT=false
LOG_LEVEL=INFO
```

---

## 3. Conectando nos seus Clientes de IA Favoritos

### Opção A: No Claude Desktop

Abra o arquivo de configuração do Claude Desktop:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

Adicione a seção `mcpServers`:

```json
{
  "mcpServers": {
    "paloalto": {
      "command": "python",
      "args": [
        "-m",
        "paloalto_mcp.server"
      ],
      "cwd": "C:\\caminho\\completo\\para\\PALO-AUTO-NETWORKS-MCP",
      "env": {
        "PANOS_HOST": "https://192.168.1.1",
        "PANOS_API_KEY": "sua_chave_aqui",
        "PANOS_VERIFY_SSL": "false",
        "ALLOW_WRITE_OPERATIONS": "true",
        "ALLOW_COMMIT": "false"
      }
    }
  }
}
```

---

### Opção B: No Cursor / Antigravity IDE / VS Code

No arquivo de configuração de MCP (`settings.json` ou `mcp_config.json`):

```json
{
  "mcpServers": {
    "paloalto": {
      "command": "python",
      "args": [
        "C:\\caminho\\completo\\para\\PALO-AUTO-NETWORKS-MCP\\paloalto-mcp-bridge.py"
      ],
      "cwd": "C:\\caminho\\completo\\para\\PALO-AUTO-NETWORKS-MCP",
      "env": {
        "PANOS_HOST": "https://192.168.1.1",
        "PANOS_API_KEY": "sua_chave_aqui",
        "PANOS_VERIFY_SSL": "false",
        "ALLOW_WRITE_OPERATIONS": "true",
        "ALLOW_COMMIT": "false"
      }
    }
  }
}
```

---

### Opção C: Executar via Docker (Sem instalar Python)

Se preferir rodar em container sem instalar dependências no seu sistema operacional:

```bash
docker compose up -d
```

---

## 4. Exemplos de Prompts Prontos para Usar

Assim que o servidor estiver conectado à IA, você pode conversar em português natural:

- 📊 **Status & Saúde**:
  > *"Qual o modelo, versão do PAN-OS e status de saúde do meu firewall?"*
  > *"Verifique as licenças instaladas e se há alguma prestes a expirar."*

- 🛡️ **Políticas & Regras**:
  > *"Quais regras de segurança eu tenho ativas no firewall?"*
  > *"Crie uma regra bloqueando todos os sites de apostas e mova para o topo."*
  > *"Analise a segurança da regra Permitir-Internet e aponte vulnerabilidades."*

- 🌐 **Rede & Serviços**:
  > *"Crie um servidor DHCP na interface interna ethernet1/2 com o range 10.10.10.50 a 10.10.10.200."*
  > *"Liste as interfaces físicas e seus respectivos endereços IP e zonas."*

- 🔍 **Monitoramento & Sessões**:
  > *"Mostre o total de sessões ativas e as principais aplicações consumindo banda."*
  > *"Consulte os logs de tráfego recentes da zona Trust para Untrust."*

---

## 5. Dicionário de Variáveis de Ambiente

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `PANOS_HOST` | `https://192.168.1.1` | IP ou FQDN com HTTPS do firewall ou Panorama. |
| `PANOS_API_KEY` | *(Obrigatório)* | Chave de autenticação da API do PAN-OS. |
| `PANOS_VERIFY_SSL` | `false` | Se `false`, ignora avisos de certificado autoassinado em labs. |
| `ALLOW_WRITE_OPERATIONS` | `true` | Habilita ferramentas de criação e edição de regras/objetos. |
| `ALLOW_COMMIT` | `false` | Trava de segurança: se `false`, impede que a IA aplique commits no dataplane sem permissão expressa. |
| `MCP_REQUIRE_CONFIRMATION`| `true` | Exige parâmetro `confirm=true` para ações destrutivas (excluir regras, reboot). |
| `PANOS_DEFAULT_VSYS` | `vsys1` | Virtual System padrão a ser gerenciado. |

## 6. As 100 Ferramentas MCP Implementadas

### GRUPO A — SYSTEM / DEVICE (1 a 10)
1. `panos_get_system_info`: Obtém hostname, serial, modelo, versão do PAN-OS e uptime.
2. `panos_get_system_state`: Consulta o estado operacional detalhado dos subsistemas e variáveis de ambiente.
3. `panos_get_system_resources`: Consulta uso de CPU do plano de controle, dataplane e memória RAM.
4. `panos_get_system_version`: Retorna versões de software e base de assinaturas (App-ID, Antivírus, Ameaças).
5. `panos_get_system_uptime`: Consulta tempo contínuo de atividade e hora do sistema.
6. `panos_get_system_license`: Consulta licenças instaladas e datas de validade de serviços de segurança.
7. `panos_get_system_software`: Lista versões de software PAN-OS disponíveis para download e instaladas.
8. `panos_get_system_disk_usage`: Consulta utilização de espaço e partições de disco do firewall.
9. `panos_get_system_services`: Consulta estado dos daemons de processo do PAN-OS.
10. `panos_get_system_info_extended`: Diagnóstico unificado e consolidado de todo o equipamento.

### GRUPO B — CONFIGURAÇÃO (11 a 20)
11. `panos_get_config`: Obtém a running configuration completa.
12. `panos_get_config_path`: Consulta nós da configuração em um caminho XPath sanitizado.
13. `panos_set_config`: Adiciona/mescla nós de configuração em um XPath. *(Write / dry_run)*
14. `panos_edit_config`: Substitui um nó existente em um XPath. *(Write / dry_run)*
15. `panos_delete_config`: Exclui um nó de configuração no XPath especificado. *(Destructive / confirm=true / dry_run)*
16. `panos_get_candidate_config`: Consulta alterações em rascunho (candidate configuration).
17. `panos_get_running_config`: Consulta configuração em execução no dataplane.
18. `panos_validate_config`: Valida a integridade lógica e sintática da candidate config.
19. `panos_get_config_diff`: Compara diferenças entre candidate e running configuration.
20. `panos_commit`: Aplica as alterações no firewall. *(Commit / confirm=true / ALLOW_COMMIT=true / dry_run)*

### GRUPO C — ADDRESS OBJECTS (21 a 30)
21. `panos_list_address_objects`: Lista objetos de endereço (IPs, ranges, FQDNs).
22. `panos_get_address_object`: Consulta detalhes de um objeto de endereço por nome.
23. `panos_create_address_object`: Cria novo objeto de endereço. *(Write / dry_run)*
24. `panos_update_address_object`: Atualiza valor/tipo de objeto de endereço existente. *(Write / dry_run)*
25. `panos_delete_address_object`: Exclui objeto de endereço. *(Destructive / confirm=true / dry_run)*
26. `panos_list_address_groups`: Lista grupos de endereços (estáticos e dinâmicos).
27. `panos_get_address_group`: Consulta membros e filtros de um grupo de endereços.
28. `panos_create_address_group`: Cria novo grupo de endereços. *(Write / dry_run)*
29. `panos_update_address_group`: Atualiza membros de grupo de endereços. *(Write / dry_run)*
30. `panos_delete_address_group`: Exclui grupo de endereços. *(Destructive / confirm=true / dry_run)*

### GRUPO D — SERVICE OBJECTS (31 a 40)
31. `panos_list_service_objects`: Lista objetos de serviço (portas TCP/UDP).
32. `panos_get_service_object`: Consulta detalhes de um objeto de serviço.
33. `panos_create_service_object`: Cria novo objeto de serviço TCP/UDP. *(Write / dry_run)*
34. `panos_update_service_object`: Atualiza portas de um serviço existente. *(Write / dry_run)*
35. `panos_delete_service_object`: Exclui objeto de serviço. *(Destructive / confirm=true / dry_run)*
36. `panos_list_service_groups`: Lista grupos de serviços.
37. `panos_get_service_group`: Consulta membros de um grupo de serviços.
38. `panos_create_service_group`: Cria novo grupo de serviços. *(Write / dry_run)*
39. `panos_update_service_group`: Atualiza membros de um grupo de serviços. *(Write / dry_run)*
40. `panos_delete_service_group`: Exclui grupo de serviços. *(Destructive / confirm=true / dry_run)*

### GRUPO E — SECURITY POLICY (41 a 50)
41. `panos_list_security_rules`: Lista regras de política de segurança.
42. `panos_get_security_rule`: Consulta detalhes completos de uma regra de segurança.
43. `panos_create_security_rule`: Cria regra de segurança completa com zonas, IPs, apps e serviços. *(Write / dry_run)*
44. `panos_update_security_rule`: Atualiza parâmetros de regra existente. *(Write / dry_run)*
45. `panos_delete_security_rule`: Exclui regra de segurança. *(Destructive / confirm=true / dry_run)*
46. `panos_move_security_rule`: Altera ordem de avaliação da regra (top, bottom, before, after). *(Write / dry_run)*
47. `panos_enable_security_rule`: Habilita regra desativada. *(Write / dry_run)*
48. `panos_disable_security_rule`: Desabilita temporariamente regra ativa. *(Write / dry_run)*
49. `panos_find_security_rule`: Busca regras por critérios cruzados (zona, IP, app, ação).
50. `panos_analyze_security_rule`: Auditoria de segurança inteligente com IA (shadowing, any/any, perfis ausentes, risco).

### GRUPO F — NAT / OUTRAS POLÍTICAS (51 a 60)
51. `panos_list_nat_rules`: Lista regras de tradução de endereço (NAT Rules).
52. `panos_get_nat_rule`: Consulta detalhes e traduções de regra NAT.
53. `panos_create_nat_rule`: Cria nova regra NAT (Source / Destination NAT). *(Write / dry_run)*
54. `panos_update_nat_rule`: Atualiza regra NAT existente. *(Write / dry_run)*
55. `panos_delete_nat_rule`: Exclui regra NAT. *(Destructive / confirm=true / dry_run)*
56. `panos_list_pbf_rules`: Lista regras de redirecionamento de política (PBF Rules).
57. `panos_get_pbf_rule`: Consulta detalhes de regra PBF.
58. `panos_list_decryption_rules`: Lista políticas de descriptografia SSL.
59. `panos_list_authentication_rules`: Lista políticas de autenticação e captive portal.
60. `panos_list_qos_rules`: Lista políticas de qualidade de serviço (QoS).

### GRUPO G — NETWORK (61 a 70)
61. `panos_list_interfaces`: Lista interfaces físicas e lógicas (ethernet, vlan, loopback, tunnel).
62. `panos_get_interface`: Consulta status, IP e contadores de uma interface específica.
63. `panos_list_zones`: Lista Security Zones e interfaces vinculadas.
64. `panos_get_zone`: Consulta parâmetros e perfis de proteção de uma zona.
65. `panos_list_virtual_routers`: Lista Virtual Routers (VRs) configurados.
66. `panos_get_virtual_router`: Consulta protocolos e rotas de um Virtual Router.
67. `panos_get_routing_table`: Consulta a tabela de rotas ativa do kernel (FIB/RIB).
68. `panos_get_arp_table`: Consulta a tabela ARP ativa com mapeamentos IP-para-MAC.
69. `panos_get_mac_table`: Consulta a tabela de endereços MAC aprendidos em Layer 2.
70. `panos_get_interface_counters`: Consulta contadores de tráfego, erros e drops por interface.

### GRUPO H — VPN / GLOBALPROTECT (71 a 80)
71. `panos_list_ipsec_tunnels`: Lista túneis IPSec VPN e estados de SA de Fase 2.
72. `panos_get_ipsec_tunnel`: Consulta status detalhado e criptografia de um túnel IPSec.
73. `panos_list_ike_gateways`: Lista IKE Gateways e SAs de Fase 1 (IKEv1 / IKEv2).
74. `panos_get_ike_gateway`: Consulta status de negociação de um IKE Gateway.
75. `panos_get_globalprotect_status`: Consulta status operacional do GlobalProtect.
76. `panos_list_globalprotect_users`: Lista usuários remotos conectados ao GlobalProtect.
77. `panos_list_globalprotect_gateways`: Lista Gateways GlobalProtect ativos.
78. `panos_get_vpn_statistics`: Retorna métricas consolidadas de VPN e túneis.
79. `panos_test_ipsec_tunnel`: Executa teste diagnóstico de negociação de túnel IPSec. *(Diagnostic)*
80. `panos_test_ike_gateway`: Executa teste diagnóstico de handshake IKE Fase 1. *(Diagnostic)*

### GRUPO I — LOGS / SESSIONS (81 a 90)
81. `panos_query_traffic_logs`: Pesquisa logs de tráfego com filtros estruturados.
82. `panos_query_threat_logs`: Pesquisa logs de ameaças detectadas (vírus, spyware, exploits).
83. `panos_query_system_logs`: Pesquisa logs de eventos e alertas operacionais do sistema.
84. `panos_query_config_logs`: Pesquisa logs de auditoria de alterações efetuadas por administradores.
85. `panos_query_url_logs`: Pesquisa logs de navegação web e categorias de URL.
86. `panos_query_auth_logs`: Pesquisa logs de autenticação de usuários e serviços.
87. `panos_get_active_sessions`: Consulta as sessões de rede ativas no dataplane.
88. `panos_find_sessions`: Pesquisa sessões por IP origem/destino, porta e protocolo.
89. `panos_get_session_statistics`: Consulta estatísticas de capacidade e taxa de sessões.
90. `panos_get_top_applications`: Identifica aplicações com maior consumo de tráfego (ACC).

### GRUPO J — HA / PANORAMA / DIAGNÓSTICO (91 a 100)
91. `panos_get_ha_status`: Consulta status do cluster de Alta Disponibilidade (active/passive).
92. `panos_get_ha_peer_status`: Consulta conectividade e sincronização com o peer de HA.
93. `panorama_list_device_groups`: Lista Device Groups configurados no Panorama. *(Panorama)*
94. `panorama_get_device_group`: Consulta definição de um Device Group específico. *(Panorama)*
95. `panorama_list_devices`: Lista firewalls gerenciados pelo Panorama. *(Panorama)*
96. `panorama_list_templates`: Lista Templates de configuração do Panorama. *(Panorama)*
97. `panorama_list_template_stacks`: Lista Template Stacks do Panorama. *(Panorama)*
98. `panos_run_diagnostic_command`: Executa comandos permitidos da allowlist de observabilidade. *(Diagnostic)*
99. `panos_test_connectivity`: Testa conectividade por ping ICMP a partir do firewall. *(Diagnostic)*
100. `panos_health_check`: Executa verificação de saúde holística consolidada em todo o firewall.

---

## 5. Exemplos de Uso Prático

### Consulta de Informações do Sistema
```json
{
  "name": "panos_get_system_info",
  "arguments": {}
}
```

### Criação de Regra de Segurança com Simulação Segura (Dry Run)
```json
{
  "name": "panos_create_security_rule",
  "arguments": {
    "name": "Permitir-DNS-Interno",
    "from_zones": ["Trust"],
    "to_zones": ["Untrust"],
    "source": ["10.0.0.0/24"],
    "destination": ["8.8.8.8", "1.1.1.1"],
    "application": ["dns"],
    "service": ["application-default"],
    "action": "allow",
    "description": "Liberacao de consulta DNS autorizada",
    "dry_run": true
  }
}
```

### Auditoria e Análise de Risco com IA em Regra Existente
```json
{
  "name": "panos_analyze_security_rule",
  "arguments": {
    "name": "Permitir-Internet"
  }
}
```

### Health Check Completo do Firewall
```json
{
  "name": "panos_health_check",
  "arguments": {}
}
```

---

## 6. Testes Automatizados

O repositório inclui suítes completas de testes unitários com mocks e testes de integração com conexão ao vivo contra o firewall:

```bash
# Executar todos os testes
pytest -v

# Executar apenas testes de integração ao vivo
pytest tests/integration/test_live_firewall.py -v

# Executar checagem de estilo e linter
ruff check src/ tests/
```

Resultado dos testes: **25 passed in 2.12s**.
Linter: **All checks passed!**
