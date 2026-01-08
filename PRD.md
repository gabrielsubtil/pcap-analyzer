# Documento de Requisitos do Produto (PRD)

---

## 🇧🇷 Português (PT-BR)

### 1. Visão Geral

O **PCAP Analyzer** é uma ferramenta desktop standalone para análise de tráfego de rede (arquivos `.pcap` e `.pcapng`). O objetivo é fornecer uma interface visual rica e intuitiva para identificar ameaças, visualizar estatísticas de tráfego e inspecionar payloads, sem a necessidade de instalação complexa ou dependências de sistema (como Node.js ou Java).

### 2. Regras e Convenções

- **Idioma**: Toda a documentação, logs e interface devem estar em **Português do Brasil (pt-BR)** e **Inglês Americano (en-US)**.
- **Versionamento**: Adesão estrita ao [Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/).
- **Changelog**: Manter um arquivo `CHANGELOG.md` seguindo o padrão [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).
- **Código**: Comentários explicativos. Design de código limpo e modular.
- **Tratamento de Erros**: Sistema de erros amigável com feedback visual claro (Toasts ou Banners) na UI.

### 3. Especificações Técnicas

- **Linguagem Core**: Python 3.x.
- **Interface Gráfica**: `pywebview` (renderizando HTML5/CSS3/JS).
- **Independência**: A aplicação não deve depender de subprocessos do sistema.
- **Compatibilidade**: Windows (10/11/7) e Linux.
- **Build**: Preparado para `PyInstaller` (Onefile ou Directory).

### 4. Funcionalidades Principais

- **Parsing**: Suporte a múltiplos arquivos `.pcap` e `.pcapng`.
- **Análise de Ameaças**: Assinaturas de Strings, Portas Suspeitas, Regras de Tráfego.
- **Dashboard**: Cards informativos, Gráficos de Pizza/Barras.
- **Visualização de Strings**: Tabela detalhada com payloads e contagem.
- **Catálogo de Ameaças**: Lista estática de consulta.

### 5. Versões Recentes

- **v5.0.0**: Aba DNS Dedicada, Suporte a Portas 0 e Nulas, Nova Regra de Ameaça (DNS Low-to-Low).
- **v4.2.0**: Paginação de Interface, Assets (Ícones).

### 6. Design e UX

- **Fidelidade**: Réplica exata do layout original (Tailwind CSS, Dark Mode).
- **Interatividade**: Feedback imediato, processamento com barra de progresso.

### 7. Licenciamento

- **Licença**: PolyForm Shield License 1.0.0.
- **Restrição**: Gratuito para uso (incluindo comercial), proibida a revenda autônoma.

---

## 🇺🇸 English (EN-US)

### 1. Overview

**PCAP Analyzer** is a standalone desktop tool for network traffic analysis (`.pcap` and `.pcapng` files). The goal is to provide a rich and intuitive visual interface to identify threats, visualize traffic statistics, and inspect payloads without complex installation or system dependencies (like Node.js or Java).

### 2. Rules and Conventions

- **Language**: All documentation, logs, and interface must be in **Brazilian Portuguese (pt-BR)** and **American English (en-US)**.
- **Versioning**: Strict adherence to [Semantic Versioning 2.0.0](https://semver.org).
- **Changelog**: Maintain a `CHANGELOG.md` file following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
- **Code**: Explanatory comments. Clean and modular code design.
- **Error Handling**: Friendly error system with clear visual feedback (Toasts or Banners) in the UI.

### 3. Technical Specifications

- **Core Language**: Python 3.x.
- **GUI**: `pywebview` (rendering HTML5/CSS3/JS).
- **Independence**: The application must not depend on system subprocesses.
- **Compatibility**: Windows (10/11/7) and Linux.
- **Build**: Prepared for `PyInstaller` (Onefile or Directory).

### 4. Main Features

- **Parsing**: Support for multiple `.pcap` and `.pcapng` files.
- **Threat Analysis**: String Signatures, Suspicious Ports, Traffic Rules.
- **Dashboard**: Info cards, Pie/Bar Charts.
- **String Visualization**: Detailed table with payloads and counts.
- **Threat Catalog**: Static reference list.

### 5. Recent Versions

- **v5.0.0**: Dedicated DNS Tab, Support for Port 0 and Null Ports, New Threat Rule (DNS Low-to-Low).
- **v4.2.0**: Interface Pagination, Assets (Icons).

### 6. Design and UX

- **Fidelity**: Exact replica of original layout (Tailwind CSS, Dark Mode).
- **Interactivity**: Immediate feedback, processing with progress bar.

### 7. Licensing

- **License**: PolyForm Shield License 1.0.0.
- **Restriction**: Free for use (including commercial), standalone resale prohibited.
