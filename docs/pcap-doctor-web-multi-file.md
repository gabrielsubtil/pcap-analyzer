# Jornada web multi-arquivo

`POST /api/jobs/aggregate` recebe múltiplas partes `file` em uma única requisição multipart.

Limites explícitos:

- no máximo 50 arquivos por job;
- no máximo 64 MiB por arquivo;
- no máximo 256 MiB no corpo agregado;
- cada captura é temporária e removida após o parse, inclusive em erro.

O backend Rust agrega as métricas antes de serializar a resposta. Cardinalidades de IP são uniões globais exatas mantidas apenas no backend; `source_ip_values` e `destination_ip_values` não fazem parte do JSON público. A resposta permanece limitada a top talkers, top portas, `packetSizeStats`, contagens e cardinalidades.

O endpoint legado `POST /api/jobs` continua sendo o contrato de arquivo único.
