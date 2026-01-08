# PCAP & NG Analyzer

Uma ferramenta poderosa e independente para análise de tráfego de rede, projetada para identificar ameaças e visualizar estatísticas de forma intuitiva. Suporta arquivos `.pcap` e `.pcapng`.

> 🚀 **Desenvolvido em colaboração com Google Antigravity e time Gemini.**
> Esta aplicação é **gratuita** graças ao apoio dessas tecnologias.

*A powerful and standalone network traffic analysis tool designed to identify threats and visualize statistics intuitively. Supports `.pcap` and `.pcapng` files.*

> 🚀 **Developed in collaboration with Google Antigravity and the Gemini team.**
> This application is **free** thanks to the support of these technologies.

---

## 🇧🇷 Português (PT-BR)

> [!WARNING]
> **Este software é gratuito para uso, inclusive comercial (prestação de serviços). No entanto, é estritamente proibido vender, licenciar ou comercializar este software ou versões modificadas dele como um produto autônomo.**

### Sobre

O **PCAP Analyzer** elimina a necessidade de ferramentas complexas como Wireshark para análises rápidas e visuais. Focado em segurança e performance, ele oferece um dashboard rico e detecção automática de padrões suspeitos.

**Destaques:**

- 🛡️ **Mitigação de DDoS**: Ideal para verificar volumetrias suspeitas e vetores de amplificação rapidamente.
- 🔒 **100% Offline e Privada**: Aplicação sem intenção de uso de APIs externas. Todo processamento é local.

> ⚠️ **Nota de Transparência:**
>
> - **Requisitos:** Basta ter Windows para rodar o executável.
> - **Internet:** A única dependência de internet é para carregar o visual (CSS e Fontes).
> - **Privacidade:** Aplicação local, **sem uso de APIs externas** e **sem uso de IA para análise em tempo real**. É puro código rodando na sua máquina.
> - **Origem:** Este software foi arquitetado e codificado com auxílio do **Gemini 3.0 High**, mas o produto final é puramente lógica de programação (Python/JS).

### Funcionalidades

- **Multiformato**: Suporte nativo para PCAP e PCAPNG.
- **Análise de Ameaças**: Detecção baseada em assinaturas e comportamento de tráfego.
- **Dashboard Rico**: Visualização clara de volumes, protocolos e top talkers.
- **Inspeção de Payload**: Extração e busca de strings em pacotes suspeitos.
- **Standalone**: Não requer instalação de drivers ou ferramentas externas.

### Pré-requisitos

1. **Python 3.12** (Recomendado)
2. Windows 10/11 (para modo Desktop nativo via .NET).
3. Bibliotecas listadas em `requirements.txt`.

### Ameaças Monitoradas

Inclui diversas regras de detecção pré-configuradas (Scanners, Webshells, Auth Fraca, etc.). Consulte a documentação completa ou o catálogo na aplicação.

### Como Compilar (Build)

1. Instale as dependências: `pip install pyinstaller pywebview scapy`
2. Execute o script de build: `build_exe.bat`
3. O executável será gerado em `dist_windows/PCAP Analyzer.exe`.

### Autor

- **Usuário**: gabrielsubtil
- **GitHub**: [github.com/gabrielsubtil](https://github.com/gabrielsubtil)
- **Contato**: [instagram.com/subtil](https://instagram.com/subtil)

### Licença

**PolyForm Shield License 1.0.0**

---

## 🇺🇸 English (EN-US)

> [!WARNING]
> **This software is free for use, including commercial use (service provision). However, it is strictly prohibited to sell, license, or market this software or modified versions of it as a standalone product.**

### About

**PCAP Analyzer** eliminates the need for complex tools like Wireshark for quick and visual analysis. Focused on security and performance, it offers a rich dashboard and automatic detection of suspicious patterns.

**Highlights:**

- 🛡️ **DDoS Mitigation**: Ideal for quickly verifying suspicious volumetrics and amplification vectors.
- 🔒 **100% Offline & Private**: Application with no intention of using external APIs. All processing is local.

> ⚠️ **Transparency Note:**
>
> - **Requirements:** Only Windows is required to run the executable.
> - **Internet:** The only internet dependency is for loading visuals (CSS and Fonts).
> - **Privacy:** Local application, **no external APIs** and **no AI used for real-time analysis**. It is pure code running on your machine.
> - **Origin:** This software was architected and coded with the help of **Gemini 3.0 High**, but the final product is purely programming logic (Python/JS).

### Features

- **Multi-format**: Native support for PCAP and PCAPNG.
- **Threat Analysis**: Detection based on signatures and traffic behavior.
- **Rich Dashboard**: Clear visualization of volumes, protocols, and top talkers.
- **Payload Inspection**: Extraction and string search in suspicious packets.
- **Standalone**: Does not require installation of drivers or external tools.

### Prerequisites

1. **Python 3.12** (Recommended)
2. Windows 10/11 (for native Desktop mode via .NET).
3. Libraries listed in `requirements.txt`.

### Monitored Threats

Includes several pre-configured detection rules (Scanners, Webshells, Weak Auth, etc.). Refer to the full documentation or the in-app catalog.

### How to Build

1. Install dependencies: `pip install pyinstaller pywebview scapy`
2. Run the build script: `build_exe.bat`
3. The executable will be generated in `dist_windows/PCAP Analyzer.exe`.

### Author

- **User**: gabrielsubtil
- **GitHub**: [github.com/gabrielsubtil](https://github.com/gabrielsubtil)
- **Contato**: [instagram.com/subtil](https://instagram.com/subtil)

### License

**PolyForm Shield License 1.0.0**

---
*Developed with focus on performance and privacy.*
