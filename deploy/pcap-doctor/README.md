# PCAP Doctor — homologação

Edição Web/Docker do PCAP Doctor. O fluxo upload-first recebe PCAP/PCAPNG, grava o corpo em arquivo temporário por streaming, valida a assinatura e retorna um resultado limitado (formato e quantidade de bytes). Não há paridade com a edição Desktop Python/Windows nesta fase, que permanece intocada.

O limite máximo é **64 MiB**, aplicado pelo `DefaultBodyLimit` do Axum e validado durante a gravação. Jobs e resultados são identificados por UUID aleatório, não usam o nome enviado pelo cliente e expiram em 15 minutos; o arquivo temporário é apagado após sucesso ou falha.

## Requisitos

- Docker Compose v2+ em host ARM64
- Rede Docker externa `proxy`
- Caddy com `http://pcapdoctor.local { reverse_proxy pcap-doctor-web:8080 }`

## Subir

```bash
cd /opt/pcap-doctor
docker compose up -d --build
docker compose ps
```

O serviço não publica portas. O acesso LAN é via `http://pcapdoctor.local`.

## Segurança aplicada

- Processo não-root UID/GID 10001
- Root filesystem somente leitura
- `/tmp` em tmpfs com `noexec,nosuid,nodev`
- Capabilities removidas
- `no-new-privileges`
- Limites de CPU, memória e PIDs
- Rede de jobs interna e sem volumes do host

## Evidência técnica

A implementação segue a documentação do **Axum 0.8.4** consultada via Context7: o extrator `Multipart` é consumido como stream (sem `field.bytes()`), o `DefaultBodyLimit` limita o corpo e o router usa estado compartilhado; os testes de integração exercitam o router com `tower::ServiceExt::oneshot`. Isso fundamenta apenas o slice limitado documentado acima, não suporte completo de parsing.

O healthcheck do Compose consulta `GET /api/health` internamente. O container continua sem porta publicada e sem rede externa para análise.
