# PCAP Doctor — homologação

Infraestrutura inicial da edição Web/Docker. Esta fase publica uma página de homologação; não processa arquivos PCAP nem altera a edição Desktop Python/Windows.

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
