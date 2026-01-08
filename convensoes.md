# Convenções de Projeto v4.1.0

---

## 🇧🇷 Português (PT-BR)

### 1. Definições de Ameaças

Todas as regras de detecção (assinaturas, portas, tráfego) devem seguir estritamente o seguinte padrão de campos para garantir consistência visual e semântica na interface.

#### Campos Obrigatórios

| Campo | Tipo | Limite | Descrição | Uso na Interface |
| :--- | :--- | :--- | :--- | :--- |
| **Name** (ID/Title) | String | - | Identificador técnico curto (ex: "XSS", "Porta 3389"). | Cabeçalho do Card |
| **Summary** (desc) | String | **80 chars** | Resumo direto e não técnico do que foi detectado. | Subtítulo do Card |
| **Description** (explanation) | String | **300 chars** | Explicação técnica detalhada, impacto e contexto. | Corpo Expansível / Detalhes |

#### Regras de Redação

1. **Summary (Resumo)**:
    - Deve caber em uma linha na maioria dos displays.
    - Evite artigos desnecessários (ex: use "Tráfego FTP detectado" em vez de "Um tráfego de FTP foi detectado").
    - **NÃO** use pontuação final se for uma frase nominal curta.

2. **Description (Explicação)**:
    - Deve ser completa e educativa.
    - Explique **O QUE** é, **POR QUE** é perigoso e **O QUE** isso implica.
    - Use terminologia técnica correta (CVEs, nomes de protocolos, tipos de ataques).

### 2. Visualização de Dados

#### Dashboard Principal

- **Exibe**: Apenas `Name` e `Summary`.
- **Objetivo**: Visão rápida de alto nível.

#### Aba de Detalhes (Strings/Pacotes)

- **Exibe**: `Name`, `Summary` e `Description`.
- **Ordenação**: Sempre por **Frequência** (contagem de pacotes), do maior para o menor.
- **Contexto**: Exibe o payload ou dados brutos associados.

#### Catálogo de Ameaças

- **Exibe**: `Name`, `Summary` e `Description`.
- **Objetivo**: Glossário completo de todas as regras ativas no sistema.

### 3. Controle de Versão

- O versionamento segue o padrão SemVer (Major.Minor.Patch).
- Atualizações de convenções ou mudanças visuais significativas incrementam o **Minor** (ex: 4.0 -> 4.1).
- Mudanças no motor de análise ou quebra de compatibilidade incrementam o **Major**.

---

## 🇺🇸 English (EN-US)

### 1. Threat Definitions

All detection rules (signatures, ports, traffic) must strictly follow the field pattern below to ensure visual and semantic consistency in the interface.

#### Mandatory Fields

| Field | Type | Limit | Description | UI Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Name** (ID/Title) | String | - | Short technical identifier (e.g., "XSS", "Port 3389"). | Card Header |
| **Summary** (desc) | String | **80 chars** | Direct, non-technical summary of detection. | Card Subtitle |
| **Description** (explanation) | String | **300 chars** | Detailed technical explanation, impact, and context. | Expandable Body / Details |

#### Style Rules

1. **Summary**:
    - Must fit on one line on most displays.
    - Avoid unnecessary articles (e.g., use "FTP Traffic Detected" instead of "An FTP traffic was detected").
    - **DO NOT** use trailing punctuation if it's a short noun phrase.

2. **Description**:
    - Must be complete and educational.
    - Explain **WHAT** it is, **WHY** it is dangerous, and **WHAT** implies.
    - Use correct technical terminology (CVEs, protocol names, attack types).

### 2. Data Visualization

#### Main Dashboard

- **Displays**: Only `Name` and `Summary`.
- **Goal**: Quick high-level overview.

#### Details Tab (Strings/Packets)

- **Displays**: `Name`, `Summary`, and `Description`.
- **Sorting**: Always by **Frequency** (packet count), descending.
- **Context**: Displays payload or associated raw data.

#### Threat Catalog

- **Displays**: `Name`, `Summary`, and `Description`.
- **Goal**: Complete glossary of all active rules in the system.

### 3. Version Control

- Versioning follows SemVer (Major.Minor.Patch).
- Convention updates or significant visual changes increment **Minor** (e.g., 4.0 -> 4.1).
- Changes to the analysis engine or breaking compatibility increment **Major**.

---
*Document updated on: 01/08/2026 for Release 4.1.0*
