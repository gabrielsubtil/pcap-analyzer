# PCAP Doctor Web — Fase 1

A rota web serve os quatro artefatos Desktop diretamente de `src/frontend/` com `include_bytes!`, sem copiar, editar ou redesenhar o Desktop. Os testes verificam igualdade byte a byte e os tipos MIME.

## Adaptador HTTP

- `GET /pywebview-compat.js` entrega o adaptador de compatibilidade para o browser.
- O adaptador cria `window.pywebview.api`, usa um elemento `input[type=file]` para seleção e nunca expõe caminhos locais.
- As chamadas do objeto são encaminhadas para `POST /api/pywebview/{method}`.
- `get_app_version` e `get_catalog` têm respostas mínimas; `get_dns_records(limit, offset)` usa o `job_id` da última análise agregada e retorna somente `{transactionId, queryName, queryType, count}` paginados (limite 1–100).
- Chamadas DNS antes da análise, para job expirado ou com paginação inválida retornam erro JSON controlado; DNS legado em `/api/jobs/{job_id}/dns` conserva `{name,qtype,count}`.
- Os endpoints existentes `/api/health`, `/api/threat-catalog`, `/api/jobs` e `/api/jobs/{job_id}/dns` permanecem preservados.

O HTML Desktop é servido literalmente, portanto o script compatível é uma rota separada e não foi injetado no `index.html`. Um host Web que precise da bridge deve carregar `/pywebview-compat.js` antes de `/app.js`; o `app.js` original continua carregando sem assumir a existência da bridge.

## Fonte Axum consultada

Context7, biblioteca `/tokio-rs/axum/axum_v0_7_9`, consultada em 2026-09-10: documentação de `Html`/headers, serviços de arquivo/rotas e testes `Router::oneshot` com `tower::ServiceExt`.

## Jornada Desktop no browser

- `pick_files` mantém os `File` reais em um fechamento privado, preserva a ordem do `FileList`, limita a seleção aos primeiros 50 e devolve somente os nomes esperados pelo `app.js`.
- `analyze_files` envia cada `File` selecionado, em ordem, no campo `file` do `POST /api/jobs/aggregate` usando `FormData`; o browser define o boundary multipart.
- Jobs completos são agregados em camelCase para o Dashboard. `topTalkers` e `topDestinations` são pares `[ip, contagem]`, no formato consumido pelo Desktop; `threatStats` expõe somente `{title, description, count}`, derivados do catálogo Desktop.
- A cardinalidade global de origem/destino em múltiplos arquivos é calculada dentro de um único job agregado no backend, por união interna exata. Os valores individuais de IP não são serializados na resposta pública.
- `packetSizeStats` é medido pelo tamanho capturado de cada pacote e agregado entre jobs; não é um campo sintético.
- Jobs ou uploads com falha viram `Error` controlado e chegam ao tratamento de erro existente do Desktop.

## Superfícies de Strings

As três APIs Strings do Desktop têm paridade limitada e somente para o `job_id` da última análise agregada:

- `get_string_filter_types()` retorna os filtros presentes nas entradas de ameaça.
- `get_analysis_strings(limit, offset, filterType)` retorna itens `{threatType, threatDesc, threatExplanation, payload, count}`.
- `get_all_strings(limit, offset)` retorna itens `{payload, count}`.

Os resultados são cópias próprias, paginados com limite 1–100 e limitados a 10.000 entradas e payloads ASCII contíguos de 3–256 bytes. Pacotes sem payload ASCII legível, criptografados ou truncados não são apresentados como strings.

Chamadas antes de uma análise, para job expirado/inexistente ou com aridade/paginação inválida retornam erros JSON controlados.

## TDD registrado

- RED: os contratos DNS novos falharam antes da implementação: bridge sem `job_id`, resposta camelCase/payload DNS e chamada sem análise.
- GREEN: os mesmos contratos passaram após a implementação.
- Suite completa: `cargo test --manifest-path web/Cargo.toml --locked` passou.
- Release: `cargo build --manifest-path web/Cargo.toml --locked --release` passou.

## Próximas superfícies

Whois e demais consultas de enriquecimento ainda retornam `501 method_not_implemented`.
