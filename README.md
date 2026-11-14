# Rotulagem e Generalização em Detecção de Vulnerabilidades

Material complementar do artigo *Rotulagem e Generalização em Detecção de Vulnerabilidades:
Uma Abordagem com Code Property Graphs e GNNs*, Trabalho de
Conclusão de Curso de Gabriel Felipe Quaresma de Oliveira, orientado por Pedro Henrique Ramos
Costa (ICEI, PUC Minas, 2026).

Aqui estão o **material complementar do artigo** (`material_complementar/material_complementar.pdf`),
o código do pipeline, os pré-registros e os dados de saída que sustentam os números do texto. O
artigo tem um apêndice curto (A, B e C) com o essencial do método; o material complementar traz o
resto do detalhe, numerado de 1 a 3, sem repetir o que está no apêndice.

## O trabalho em um parágrafo

O BigVul, um *dataset* de funções C/C++ vulneráveis, marca como vulnerável toda função alterada
pelo *commit* que corrigiu a CVE. Parte dessas funções muda só por refatoração ou para acompanhar
o conserto, então o rótulo tem ruído. O trabalho pergunta se **limpar esses rótulos** melhora a
generalização de um detector baseado em grafos. A limpeza é feita por *traversals*, consultas
ao grafo do código que corroboram o rótulo de uma família de CWEs, escritas a partir da definição
delas e congeladas antes de qualquer medição. A comparação é entre o ReVeal treinado no conjunto curado e treinado em controles
aleatórios do mesmo tamanho. Na anotação manual de uma amostra aleatória de 50 funções positivas
do recorte, 57,1% não correspondem ao local da vulnerabilidade. Nessa amostra e numa segunda, sorteada
depois da curadoria, a proporção de rótulos corretos foi maior entre as funções que a curadoria
confirmou (64,7% e 60,0%) do que no conjunto sem filtro (44,2% e 48,8%), mas nenhuma das duas
amostras exclui ganho nulo. O ReVeal treinado no conjunto curado ficou acima dos cinco controles
no teste do BigVul e nas duas arenas externas, o PrimeVul e o VentiVul, o que é evidência a favor
da hipótese, e não prova.

## Vocabulário

| termo | o que é |
|---|---|
| CPG (*Code Property Graph*) | grafo que junta a árvore sintática, o fluxo de controle e as dependências de dados de uma função; gerado pelo Joern |
| *traversal* | consulta escrita sobre o CPG; aqui, a regra de curadoria (`curadoria/curadoria_v3.sc`) |
| recorte | as funções positivas do BigVul de quatro CWEs de erro de memória em *buffer* (CWE-119, 120, 125 e 787) |
| braço | um conjunto de treino; o modelo é o mesmo em todos |
| `M_raw` (bruto) | todos os positivos do recorte com corpo analisável |
| `M_cur` (curado) | só os positivos que a *traversal* confirmou |
| `M_ctrl_g2026` a `g2030` (controles) | cinco sorteios aleatórios do bruto, do mesmo tamanho do curado |
| `_bal` | versão balanceada do braço, com tantos negativos quanto positivos |
| arena | conjunto de avaliação: o teste do BigVul, o PrimeVul, o VentiVul e uma sonda de *use-after-free* (CWE-416) |
| pré-registro | documento que fixa a regra de decisão antes de o resultado existir, com o SHA-256 gravado no momento |

## Mapa do repositório

| pasta | o que tem | parte do artigo |
|---|---|---|
| `material_complementar/` | o PDF do material complementar e os scripts que geram as tabelas e figuras do artigo e dele a partir dos resultados | Apêndices e material complementar |
| `preparacao/` | extração do recorte do BigVul e recuperação do arquivo-fonte de cada função | Seção 3.2, material complementar 3.1 |
| `curadoria/` | a regra (`curadoria_v3.sc`, `regra_veredito.toml`, `dados/`), os scripts, os conjuntos de treino, a partição e as saídas da *traversal* | Seções 3.3 e 3.5, Apêndice B, material complementar 3.2 |
| `curadoria/registros/` | o registro em texto de cada etapa da curadoria | Apêndice B, material complementar 2 |
| `validacao/primeira/` | rubrica, pré-registro, amostra de 50 anotada e concordância entre anotadores | Seções 3.4, 4.1 e 4.2, Apêndice B.2, material complementar 2.2 |
| `validacao/segunda/` | a segunda validação, sorteada depois da curadoria, com chave e anotação congeladas | Seções 3.4 e 4.2, Apêndice B.3 |
| `modelo/` | o ReVeal implementado, os pré-registros da análise, o resultado do teste do BigVul e os históricos de treino de cada braço | Seções 3.5, 3.6 e 4.3, Apêndices A e C, material complementar 1.2 e 3.3 |
| `arenas/` | preparação e deduplicação das arenas externas e o resultado delas | Seção 4.4, material complementar 1.1 |

As saídas da *traversal* sobre todos os positivos e sobre os negativos do teste estão compactadas
em `curadoria/saidas_compactadas/` (um JSON por função).

## Arquivos congelados

São os arquivos da Tabela C.1 do apêndice do artigo. Cada um foi fixado antes de o resultado que ele decide
existir. Para conferir, basta comparar o SHA-256 do arquivo com o da tabela, por exemplo
`sha256sum curadoria/curadoria_v3.sc`.

| arquivo | congelado | SHA-256 |
|---|---|---|
| `curadoria/curadoria_v2.sc` | 10/08/2026, antes da Etapa 5 | `835571171d40b50c4e63fdefcf27564e54e9dd2a0bfecd43167d2b28147bcccf` |
| `curadoria/curadoria_v3.sc` | 05/10/2026, antes da rodada v3 | `a6d119bd74ae64b918e54964d691f691a33085d3860e246fc9349ac999e2ca22` |
| `curadoria/dados/funcoes_memoria.tsv` | 10/08/2026 (igual na v3) | `85297b08107ab18c12eb4ec37fbea90f2df4639928038f841e49bd1ec62594f8` |
| `curadoria/dados/fontes_nao_confiaveis.tsv` | 10/08/2026 (igual na v3) | `9e36fd6f71828a418a77a3c958cbf1e1416c1e3d03976a6984fae75ae1af1fc9` |
| `curadoria/regra_veredito.toml` | 10/08/2026 (igual na v3) | `485b73c3c71b6b662aa05bfb93435ff2db729352d499885ecf1c7fe8c7a73e4d` |
| `modelo/PREREGISTRO_TAMANHO.md` | 10/10/2026, antes do treino | `57c0a26f79cb6b36248f8852ad8ba327ece0742e47a430aafe08afc28826e8ee` |
| `modelo/PREREGISTRO_PRINCIPAL.md` | 12/10/2026, antes de qualquer métrica de teste | `dbb2269cc6f1f76b176c8cedc426b3a85137b924f06b98c06def91e2209ab86c` |
| `modelo/PREREGISTRO_ARENAS.md` | 15/10/2026, antes de qualquer predição nas arenas | `6284d831d490048ad2da33d34e32fc2f8f4d67185ae20bc7f1cce36949a01838` |
| `modelo/resultado_teste_bigvul.json` | 13/10/2026, na abertura | `f8ea66693ceac645cc1d9a7dd16aed5d08b45a4703f661519acc9bad63991402` |
| `arenas/resultado_arenas.json` | 21/10/2026, na correção do piso | `34ff46c06ea6c08631af5b6417fd25b2a7b40162f0bc42ee9ede8ea15e9f92b0` |
| `validacao/segunda/chave/chave_segunda.csv` | 30/10/2026, ao montar a amostra | `013f16819667bf3d8b4225652c031165abc824f9f06f3638d0a5a5e8bcf50afb` |
| `validacao/segunda/anotacao_segunda.csv` | 30/10/2026, antes da abertura da chave | `11a916170d491a5b82bc8c5b38ea38b01f3fdd094b685abec00917751b9a6caa` |
| `validacao/segunda/PRE_REGISTRO_SEGUNDA.md` | 30/10/2026, antes da abertura da chave | `c877d06a3b0c5cfddba56228b3d1061d7f1d5487a028a9e05294491b8ed34066` |

## O que não está aqui

- **O BigVul bruto** (`all_c_cpp_release2.0.csv`, 1,5 GB), distribuído pelos autores do
  *dataset* [Fan et al. 2020, MSR, doi:10.1145/3379597.3387501]. A cópia usada tem SHA-256
  `be96d4133fe4e75a2c5dd3f36eae22939612083cd1f7bcaa3bb5ce782316e0f2`. O índice das funções usadas
  está em `preparacao/saida_final/indice_bigvul.csv.gz`.
- **Os CPGs, os vetores e os modelos treinados**, que somam dezenas de GB e são regenerados pelos
  scripts.
- **Os dados das arenas externas** (PrimeVul e VentiVul), que têm licença própria e são baixados
  pelo `arenas/baixar_dados.sh`.
- **Os scripts de diagnóstico** usados durante o trabalho para investigar falhas, que não produzem
  nenhum número do artigo.

## Ambiente

Ubuntu 24.04 (WSL), Joern 4.0.513 com OpenJDK 21, Python 3.12, PyTorch 2.6 e DGL 2.5. Os scripts
guardam os caminhos absolutos do ambiente original (`/mnt/c/...`, `~/curadoria`) e precisam ser
ajustados para rodar em outra máquina.
