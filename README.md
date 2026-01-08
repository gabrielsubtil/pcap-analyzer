# PCAP & NG Analyzer

Uma ferramenta poderosa e independente para análise de tráfego de rede, projetada para identificar ameaças e visualizar estatísticas de forma intuitiva. Suporta arquivos `.pcap` e `.pcapng`.

*A powerful and standalone network traffic analysis tool designed to identify threats and visualize statistics intuitively. Supports `.pcap` and `.pcapng` files.*

---

## 🇧🇷 Português (PT-BR)

> [!WARNING]
> **Este software é gratuito para uso, inclusive comercial (prestação de serviços). No entanto, é estritamente proibido vender, licenciar ou comercializar este software ou versões modificadas dele como um produto autônomo.**

### Sobre

O **PCAP Analyzer** elimina a necessidade de ferramentas complexas como Wireshark para análises rápidas e visuais. Focado em segurança e performance, ele oferece um dashboard rico e detecção automática de padrões suspeitos.

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
- **E-mail**: <gabrielsubtil@hotmail.com>

### Licença

**PolyForm Shield License 1.0.0**

---

## 🇺🇸 English (EN-US)

> [!WARNING]
> **This software is free for use, including commercial use (service provision). However, it is strictly prohibited to sell, license, or market this software or modified versions of it as a standalone product.**

### About

**PCAP Analyzer** eliminates the need for complex tools like Wireshark for quick and visual analysis. Focused on security and performance, it offers a rich dashboard and automatic detection of suspicious patterns.

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
- **E-mail**: <gabrielsubtil@hotmail.com>

### License

**PolyForm Shield License 1.0.0**

---
*Developed with focus on performance and privacy.*
