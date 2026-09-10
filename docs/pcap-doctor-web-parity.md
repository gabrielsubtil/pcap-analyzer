# PCAP Doctor Web — Fase 1

A rota web serve os quatro artefatos Desktop diretamente de `src/frontend/` com `include_bytes!`, sem copiar, editar ou redesenhar o Desktop. Os testes verificam igualdade byte a byte e os tipos MIME.

## Adaptador HTTP

- `GET /pywebview-compat.js` entrega o adaptador de compatibilidade para o browser.
- O adaptador cria `window.pywebview.api`, usa um elemento `input[type=file]` para seleção e nunca expõe caminhos locais.
- As chamadas do objeto são encaminhadas para `POST /api/pywebview/{method}`.
- `get_app_version` e `get_catalog` têm respostas mínimas; métodos sem backend de paridade retornam `501` com `method_not_implemented`.
- Os endpoints existentes `/api/health`, `/api/threat-catalog`, `/api/jobs` e `/api/jobs/{job_id}/dns` permanecem preservados.

O HTML Desktop é servido literalmente, portanto o script compatível é uma rota separada e não foi injetado no `index.html`. Um host Web que precise da bridge deve carregar `/pywebview-compat.js` antes de `/app.js`; o `app.js` original continua carregando sem assumir a existência da bridge.

## Fonte Axum consultada

Context7, biblioteca `/tokio-rs/axum/axum_v0_7_9`, consultada em 2026-09-10: documentação de `Html`/headers, serviços de arquivo/rotas e testes `Router::oneshot` com `tower::ServiceExt`.

## Jornada Desktop no browser

- `pick_files` mantém os `File` reais em um fechamento privado, preserva a ordem do `FileList`, limita a seleção aos primeiros 50 e devolve somente os nomes esperados pelo `app.js`.
- `analyze_files` envia cada `File` selecionado, em ordem, como `file` no `POST /api/jobs` usando `FormData`; o browser define o boundary multipart.
- Jobs completos são agregados em camelCase para o Dashboard. `topTalkers` e `topDestinations` são pares `[ip, contagem]`, no formato consumido pelo Desktop; `threatStats` expõe somente `{title, description, count}`, derivados do catálogo Desktop.
- A cardinalidade global de origem/destino em múltiplos arquivos é calculada pela união dos valores de IP emitidos por cada job, nunca pela soma dos contadores. Esses valores são limitados indiretamente a `MAX_PACKETS` por captura; a análise recusa capturas acima desse limite.
- `packetSizeStats` é medido pelo tamanho capturado de cada pacote e agregado entre jobs; não é um campo sintético.
- Jobs ou uploads com falha viram `Error` controlado e chegam ao tratamento de erro existente do Desktop.

## Superfícies ainda indisponíveis

Strings (`get_string_filter_types`, `get_analysis_strings`, `get_all_strings`), Whois e demais consultas de enriquecimento continuam sem backend de paridade e retornam `501 method_not_implemented`. DNS permanece disponível somente pela API paginada existente; a jornada de análise agora cobre o Dashboard, não essas superfícies.

## TDD registrado

- RED: `cargo test --manifest-path web/Cargo.toml --locked --test bridge_contract` falhou em 4/4 contratos antes da implementação.
- GREEN: o mesmo teste passou 4/4 após a implementação.
- Suite completa: `cargo test --manifest-path web/Cargo.toml --locked` passou após a implementação.
