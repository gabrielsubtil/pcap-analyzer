# Changelog

## 🇧🇷 Português (PT-BR)

Todas as alterações notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/), e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

### [5.1.0] - 2026-01-28

#### Adicionado

- **Todas as Strings:** Nova aba para visualizar todas as strings ASCII imprimíveis extraídas de todos os pacotes, independentemente de serem consideradas ameaças.
- **Botão "Todas as Strings":** Adicionado ao cabeçalho para acesso rápido à nova funcionalidade.

### [5.0.0] - 2026-01-08

#### Adicionado

- **Aba DNS:** Nova visualização dedicada para tráfego DNS (Porta 53), exibindo consultas, tipos de registro e contagem, com filtragem inteligente.
- **Regra de Ameaça:** Adicionada regra `dns_low_to_low` para detectar tráfego com origem em portas privilegiadas (exceto 53) destinado à porta 53.
- **Suporte a Tráfego "Vazio":** O Dashboard agora exibe contabilização para pacotes sem porta de transporte (ex: ARP) como "Vazio".

#### Corrigido

- **Estatísticas de Porta 0:** Corrigido bug no analisador que ignorava a Porta 0. Agora ela é contabilizada corretamente nos gráficos.
- **Favicon:** Corrigido erro 404 ao carregar o favicon da aplicação (agora usa `logo.png`).

### [4.3.0] - 2026-01-08

#### Otimizado

- **Interface Gráfica:** Aumento do tamanho do logo no cabeçalho e ajuste de alinhamento do texto de créditos.
- **Documentação:** Atualização completa do `README.md` para publicação no GitHub, incluindo lista detalhada de ameaças e créditos.

### [4.2.0] - 2026-01-08

#### Adicionado

- **Paginação no Dashboard:** Implementado sistema de "Carregar Mais" nos cartões do Dashboard (Portas, IPs, Tamanhos) limitando a visualização inicial a 10 itens para performance extrema.
- **Ícones Personalizados:**
  - Adicionado `app.ico` para ícone da janela e barra de tarefas.
  - Adicionado `logo.png` para o cabeçalho da aplicação.
- **Organização de Assets:** Criação da estrutura `src/assets` e `src/frontend/assets`.

#### Otimizado

- **Renderização do Dashboard:** Refatoração completa da lógica de renderização (`renderDashboard`) para evitar re-cálculos de DOM ao trocar de abas.
- **Correção de Travamentos:** A limitação de itens no Dashboard resolveu o "stutter" (travamento) de ~20s causado por renderizar listas massivas de portas/IPs.

### [4.1.0] - 2026-01-08

#### Conventions

- Implementação da nova convenção de "Threat Definitions" (v4.1).
- Padronização de campos: `Name` (ID), `Summary` (<80 chars), `Description` (<300 chars, technical).
- Documentação formalizada em `convensoes.md`.

#### Alterado

- **Dashboard**: Exibe apenas `Name` e `Summary` nos cards de ameaça.
- **Aba Strings**: Exibe `Name`, `Summary` e a nova `Description` detalhada, além do payload e contagem.
- **Catálogo**: Atualizado para exibir a explicação técnica completa.
- **Backend**:
  - `consts.py`: Reescrita completa das assinaturas e regras para seguir os novos limites de caracteres.
  - `database.py`: Schema atualizado para suportar `threat_explanation`.
  - `analyzer.py`: Lógica de *buffer* ajustada para persistir a explicação.

### [3.0.0] - 2026-01-08

#### Removido

- **Sistema de Severidade:** Removida a classificação visual e lógica de severidade (High/Medium/Low). Todas as ameaças são tratadas de forma igualitária na interface.

#### Adicionado

- **Ordenação de Strings:** A lista de strings extraídas agora é ordenada pela frequência de ocorrência (quantidade de pacotes), exibindo as mais comuns no topo.

### [2.2.0] - 2026-01-07

#### Otimizado

- **Alta Performance:** Implementado banco de dados **SQLite em Memória** para processamento de strings e payloads.
- **Paginação:** A aba "Strings" agora carrega dados sob demanda (Paginação/Infinite Scroll), eliminando travamentos de interface em arquivos grandes e reduzindo o consumo de memória do navegador.
- **Transferência de Dados:** Redução de ~95% no tamanho do payload JSON enviado do Python para o Frontend.

### [2.1.1] - 2026-01-07

#### Alterado

- **Regras de Detecção:** A porta **161 (SNMP)** foi reintroduzida nas regras de detecção.

### [2.1.0] - 2026-01-07

#### Corrigido

- **Hotfix de Interface:** Corrigido bug crítico de renderização na aba "Strings".

### [2.0.0] - 2026-01-07

#### Adicionado

- Abas do Frontend renomeadas: "Ameaças" agora é **"Catálogo"**.

#### Alterado

- **Visual Unificado:** O sistema de cores de severidade (Low/Medium/High) foi removido da interface. Todas as ameaças agora são exibidas em **Vermelho** (Crítico).
- **Catálogo de Ameaças:** Revertido comportamento para exibir a *lista completa estática* de regras conhecidas.
- **Performance:** Regra redundante `priv_port_web` removida do backend.

#### Corrigido

- **Estabilidade:** Corrigido crash crítico (`TypeError`) no analisador ao processar pacotes sem porta (ICMP/ARP).
- **Lógica de Interface:** Corrigido bug de renderização duplicada nos filtros de strings.

### [1.0.0] - 2026-01-07

#### Adicionado

- Refatoração completa da aplicação para versão Desktop em Python.
- Interface gráfica baseada em `pywebview`.
- Parser nativo Python para arquivos `.pcap` e `.pcapng`.
- Sistema de análise de ameaças e estatísticas de tráfego.

---

## 🇺🇸 English (EN-US)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

### [5.1.0] - 2026-01-28

#### Added

- **All Strings:** New tab to visualize all printable ASCII strings extracted from all packets, regardless of whether they are considered threats.
- **"All Strings" Button:** Added to the header for quick access to the new functionality.

### [5.0.0] - 2026-01-08

#### Added

- **DNS Tab:** New dedicated view for DNS traffic (Port 53), displaying queries, record types, and counts, with smart filtering.
- **Threat Rule:** Added `dns_low_to_low` rule to detect traffic originating from privileged ports (except 53) destined for port 53.
- **"Empty" Traffic Support:** The Dashboard now tracks counts for packets without a transport port (e.g., ARP) as "Empty".

#### Fixed

- **Port 0 Statistics:** Fixed bug in analyzer that ignored Port 0. It is now correctly accounted for in charts.
- **Favicon:** Fixed 404 error when loading the application favicon (now uses `logo.png`).

### [4.3.0] - 2026-01-08

#### Optimized

- **GUI:** Increased logo size in header and adjusted credits text alignment.
- **Documentation:** Complete update of `README.md` for GitHub publication, including detailed threat list and credits.

### [4.2.0] - 2026-01-08

#### Added

- **Dashboard Pagination:** Implemented "Load More" system in Dashboard cards (Ports, IPs, Sizes), limiting initial view to 10 items for extreme performance.
- **Custom Icons:**
  - Added `app.ico` for window and taskbar icon.
  - Added `logo.png` for application header.
- **Assets Organization:** Created `src/assets` and `src/frontend/assets` structure.

#### Optimized

- **Dashboard Rendering:** Complete refactoring of rendering logic (`renderDashboard`) to avoid DOM re-calculations when switching tabs.
- **Freeze Fixes:** Item limitation in Dashboard resolved ~20s stutter caused by rendering massive lists of ports/IPs.

### [4.1.0] - 2026-01-08

#### Conventions

- Implementation of new "Threat Definitions" convention (v4.1).
- Field standardization: `Name` (ID), `Summary` (<80 chars), `Description` (<300 chars, technical).
- Documentation formalized in `convensoes.md`.

#### Changed

- **Dashboard**: Displays only `Name` and `Summary` in threat cards.
- **Strings Tab**: Displays `Name`, `Summary`, and new detailed `Description`, plus payload and count.
- **Catalog**: Updated to show full technical explanation.
- **Backend**:
  - `consts.py`: Complete rewrite of signatures and rules to follow new character limits.
  - `database.py`: Schema updated to support `threat_explanation`.
  - `analyzer.py`: Buffer logic adjusted to persist explanation.

### [3.0.0] - 2026-01-08

#### Removed

- **Severity System:** Removed visual classification and severity logic (High/Medium/Low). All threats are treated equally in the interface.

#### Added

- **String Sorting:** Extracted strings list is now sorted by occurrence frequency (packet count), displaying most common ones at the top.

### [2.2.0] - 2026-01-07

#### Optimized

- **High Performance:** Implemented **In-Memory SQLite** database for string and payload processing.
- **Pagination:** "Strings" tab now loads data on demand (Pagination/Infinite Scroll), eliminating interface freezes on large files and reducing browser memory consumption.
- **Data Transfer:** ~95% reduction in JSON payload size sent from Python to Frontend.

### [2.1.1] - 2026-01-07

#### Changed

- **Detection Rules:** Port **161 (SNMP)** reintroduced into detection rules.

### [2.1.0] - 2026-01-07

#### Fixed

- **Interface Hotfix:** Fixed critical rendering bug in "Strings" tab.

### [2.0.0] - 2026-01-07

#### Added

- Frontend tabs renamed: "Threats" is now **"Catalog"**.

#### Changed

- **Unified Visuals:** Severity color system (Low/Medium/High) removed from interface. All threats now displayed in **Red** (Critical).
- **Threat Catalog:** Reverted behavior to display *full static list* of known rules.
- **Performance:** Redundant rule `priv_port_web` removed from backend.

#### Fixed

- **Stability:** Fixed critical crash (`TypeError`) in analyzer when processing packets without ports (ICMP/ARP).
- **Interface Logic:** Fixed duplicate rendering bug in string filters.

### [1.0.0] - 2026-01-07

#### Added

- Complete application refactoring for Python Desktop version.
- GUI based on `pywebview`.
- Native Python parser for `.pcap` and `.pcapng` files.
- Threat analysis system and traffic statistics.
