# Congelamento das regras da curadoria — Etapa 5, passo 1

Gravado em **2026-08-10** por `congelar.py --gravar`.

A precisão do filtro só vale como medida se a regra tiver sido escrita **antes** de
ver os 50 casos anotados. "Antes" não é uma promessa: é este hash. Daqui em diante,
qualquer edição em qualquer um destes arquivos muda o SHA-256, e a divergência aparece
em `congelar.py --conferir` e no diff do git.

| arquivo | sha256 | bytes |
| --- | --- | --- |
| `curadoria_v2.sc` | `835571171d40b50c4e63fdefcf27564e54e9dd2a0bfecd43167d2b28147bcccf` | 9850 |
| `dados/funcoes_memoria.tsv` | `85297b08107ab18c12eb4ec37fbea90f2df4639928038f841e49bd1ec62594f8` | 1974 |
| `dados/fontes_nao_confiaveis.tsv` | `9e36fd6f71828a418a77a3c958cbf1e1416c1e3d03976a6984fae75ae1af1fc9` | 1024 |
| `regra_veredito.toml` | `485b73c3c71b6b662aa05bfb93435ff2db729352d499885ecf1c7fe8c7a73e4d` | 7661 |

## O que está congelado, e o que não está

Congelado é **regra**: o que decide o veredito. A traversal (`curadoria_v2.sc`), as duas
tabelas de dados que ela consulta, e a `regra_veredito.toml`, que transforma evidência em
veredito. A lista é importada de `rodar_curadoria.py` (`REGRAS`), não copiada — as duas
não podem divergir em silêncio.

**Não** está congelado o `veredito.py`: ele só aplica a regra e precisa poder nomear o
caso de regressão para tirá-lo da estatística. Escriturário, não regra. Também não estão
os runners nem os `.md` de registro.

## O que este congelamento permite fazer, e só agora

Rodar a curadoria nos **50 casos anotados** (`saida/amostra_validacao_revisao.csv`) e
comparar o veredito com os rótulos humanos. Até este arquivo existir, nenhum arquivo dos
50 podia ser lido — é a regra de método que a Etapa 4a e a 4b existiram para respeitar.

Invertida a ordem, o número não vale nada.
