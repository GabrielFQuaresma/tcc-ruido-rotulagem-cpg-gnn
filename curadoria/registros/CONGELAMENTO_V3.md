# Congelamento da traversal v3

Gravado em **2026-10-05 12:16** por `congelar.py --versao v3 --gravar`, **antes** da rodada da v3.

É a foto da v3, ao lado da da v2 (`CONGELAMENTO.md`, 10/08/2026), que **não** foi
regravada e continua provando que a regra da Etapa 5 veio antes dos 50. O que mudou da
v2 para a v3, por quê, e o que se previu antes de rodar: `TRAVERSAL_V3.md`.

| arquivo | sha256 | bytes |
| --- | --- | --- |
| `curadoria_v3.sc` | `a6d119bd74ae64b918e54964d691f691a33085d3860e246fc9349ac999e2ca22` | 12139 |
| `dados/funcoes_memoria.tsv` | `85297b08107ab18c12eb4ec37fbea90f2df4639928038f841e49bd1ec62594f8` | 1974 |
| `dados/fontes_nao_confiaveis.tsv` | `9e36fd6f71828a418a77a3c958cbf1e1416c1e3d03976a6984fae75ae1af1fc9` | 1024 |
| `regra_veredito.toml` | `485b73c3c71b6b662aa05bfb93435ff2db729352d499885ecf1c7fe8c7a73e4d` | 7661 |

Só o `.sc` muda em relação à v2; as duas tabelas de `dados/` e o `regra_veredito.toml`
têm de ter o mesmo SHA-256 do congelamento da v2. A tabela `identificacao_v3.tsv` não
é regra (traz id de item); o SHA-256 dela está no adendo do `TRAVERSAL_V3.md`.
