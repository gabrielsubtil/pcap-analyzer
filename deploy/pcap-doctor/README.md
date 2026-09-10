# PCAP Doctor — homologação

Edição Web/Docker do PCAP Doctor. O fluxo upload-first recebe PCAP/PCAPNG, grava o corpo em arquivo temporário por streaming e processa o contêiner com `pcap-parser` 0.17 (`create_reader`) sem reter fatias zero-copy. O resultado JSON versionado (`pcap-doctor.job-result.v1` / `pcap-doctor.metrics.v2`) inclui contêiner e resumo limitado de protocolos: totais de pacotes/bytes, TCP/UDP/ICMP, portas, cardinalidade IP e top 10 talkers/destinos. Não expõe payloads, DNS ou dados em logs; a edição Desktop Python/Windows permanece intocada.

## Limites e contrato

- Upload: **64 MiB**; nome/MIME/extensão do cliente não são confiáveis.
- Parser streaming: buffer circular de **16 MiB**, no máximo **1.000.000** blocos/pacotes, frame de **16 MiB** e prazo de **5 s**.
- Jobs e resultados usam UUID aleatório e expiram em 15 minutos. O temporário é removido em sucesso, captura inválida, erro de multipart, erro de escrita e erro de parsing; timeout aborta o job de parsing e remove o caminho temporário assim que o handler termina.
- Formatos aceitos: PCAP legado little/big-endian, micro/nanosegundos (quatro magics) e PCAPNG com seções/blocos válidos. Formatos desconhecidos ou truncados são rejeitados.
- Linktypes suportados para o resumo: Ethernet II **1** e Linux SLL **113**, com `etherparse` 0.21 e APIs lax (`LaxSlicedPacket::from_ethernet`/`from_ether_type` e `LaxPacketHeaders::from_linux_sll`). IPv4 TCP, UDP e ICMPv4 são contados. VLAN encapsulada segue a capacidade do etherparse; IPv6, ARP, outros transportes e linktypes são não analisados.
- `parsed_packets`, `unparsed_packets` e `truncated_packets` são explícitos. Erros não fatais ficam no fluxo lax e frames malformados não abortam a captura. `unsupported_linktypes` cataloga valores fora de 1/113; nunca são apresentados como analisados.
- Agregações são limitadas a top 10 e distribuições de portas top 10; IPs são mantidos apenas em conjuntos/contadores para a resposta.

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
- Capabilities removidas, `no-new-privileges`, limites de CPU/memória/PIDs
- Rede de jobs interna e sem volumes do host

## Evidência técnica

A implementação segue Axum 0.8.4 consultado via Context7 para o extrator `Multipart`, `DefaultBodyLimit` e router com estado compartilhado. O leitor puro Rust segue a documentação oficial do [pcap-parser 0.17 no docs.rs](https://docs.rs/pcap-parser/0.17.0/pcap_parser/) e do [repositório Rusticata](https://github.com/rusticata/pcap-parser): `create_reader`, consumo/refill streaming, `PcapNGReader`/`LegacyPcapReader` internamente e descarte das fatias antes do próximo refill. A consulta Context7 de etherparse confirma `LaxSlicedPacket::from_ethernet`, `from_ether_type`, `LaxPacketHeaders::from_linux_sll` e `stop_err` para parsing não fatal: [docs.rs/etherparse](https://docs.rs/etherparse/0.21.0/etherparse/).

Os testes geram em memória um PCAP e um PCAPNG válidos, fazem upload pelo router, verificam métricas de pacote e verificam limpeza. Capturas inválidas e truncadas falham com segurança. Não há dados de produção nem deploy no Radxa nesta fase.

O healthcheck do Compose consulta `GET /api/health` internamente. O container continua sem porta publicada e sem rede externa para análise.
