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

## TDD registrado

- RED: `cargo test --manifest-path web/Cargo.toml --locked --test parity_contract` falhou com 5/5 testes antes da implementação (rotas de artefatos e bridge retornavam 404 e a página ainda era inline).
- GREEN: o mesmo teste passou 5/5 após a implementação.
- Suite completa: `cargo test --manifest-path web/Cargo.toml --locked` passou 15 testes de integração/unidade, mais doctests sem testes.
