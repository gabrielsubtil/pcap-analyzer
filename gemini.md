# Contexto do Projeto para Gemini/AI

Este arquivo serve como referência para assistentes de IA sobre a estrutura e regras do projeto **PCAP Analyzer**.

## Visão Geral

Aplicação desktop Python para análise de PCAP, usando `pywebview` para UI.
O objetivo é fornecer uma ferramenta de forense de rede leve e visual.

## Estrutura de Arquivos

- `src/boot.py`: Entry point e Bridge API.
- `src/backend/`: Lógica de negócios (Parsing, Análise).
- `src/frontend/`: Interface Web (HTML/CSS/JS).

## Regras Críticas

1. **Idioma**: Sempre responder e documentar em **Português do Brasil**.
2. **Independência**: Nunca usar `subprocess` para chamar ferramentas externas de rede.
3. **Design**: Manter fidelidade visual ao design original (Tailwind Dark Theme).
4. **Licença**: Respeitar a PolyForm Shield 1.0.0.

## Comandos Úteis

- Build (Exemplo): `pyinstaller --onefile --noconsole --name "PCAP Analyzer" src/boot.py`
