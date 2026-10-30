# Concordancia entre anotadores — ruido de rotulagem do BigVul

- condicao: **cve_oculta**
- repeticoes do modelo: [1]
- anotacao humana: `amostra_validacao_revisao.csv`
- rubrica congelada: `rubrica_v1.md` sha256 `81f9d2495741537a27a189dedfd1d6da767afc8171608b3fbf425d8809567316`
- plano de analise: `pre_registro.md` sha256 `8d96084383cdd6fa899fbcee9402ed93db2b64ea973268fa556daac95f2b4c6c`
- bootstrap: 10000 reamostragens por cluster de commit, semente 42

> Os rotulos do humano sao os primarios. O modelo e verificacao de confiabilidade, nao ground truth. Nenhum rotulo foi alterado aqui; os kappas abaixo sao pre-adjudicacao.

## 1. Distribuicao dos rotulos

| tipo | humano | modelo (voto majoritario) |
| --- | --- | --- |
| A | 7 | 10 |
| B | 12 | 9 |
| C | 9 | 14 |
| D | 21 | 17 |
| ? | 1 | 0 |

| anotador | D (vulneravel) | decididos | acuracia de rotulo | ruido estimado |
| --- | --- | --- | --- | --- |
| humano | 21 | 49 | 42.9% | **57.1%** |
| modelo | 17 | 50 | 34.0% | **66.0%** |

- IC95% da taxa de ruido (humano): [34.2%, 74.2%]
- IC95% da taxa de ruido (modelo): [44.2%, 81.0%]

**A faixa a reportar no TCC e a dos dois anotadores, com o humano como numero principal.**

## 2. Casos sem decisao (`?`)

- humano marcou `?` em 1 caso(s): [7]
- modelo marcou `?` em 0 caso(s): —
- excluidos dos kappas e da taxa de ruido: 1 caso(s) [7]

## 3. Concordancia humano x modelo

### 3.1 Todos os casos decididos por ambos (analise principal)

n = 49 casos | clusters (commits distintos) = 37

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.659** | [0.380, 0.852] | 0.837 | 0.522 |
| 4 categorias (A/B/C/D) | 0.383 | [0.215, 0.563] | 0.551 | 0.272 |

### 3.2 Excluindo o caso pre-preenchido automaticamente ([29])

n = 48 casos | clusters (commits distintos) = 36

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.654** | [0.367, 0.855] | 0.833 | 0.518 |
| 4 categorias (A/B/C/D) | 0.366 | [0.195, 0.545] | 0.542 | 0.277 |

### 3.3 Por commit (primeira linha de cada commit distinto)

n = 37 casos | clusters (commits distintos) = 37

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.572** | [0.300, 0.819] | 0.784 | 0.495 |
| 4 categorias (A/B/C/D) | 0.390 | [0.176, 0.590] | 0.595 | 0.335 |

### 3.4 So casos em que o humano marcou confianca alta

n = 42 casos | clusters (commits distintos) = 32

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.706** | [0.437, 0.901] | 0.857 | 0.514 |
| 4 categorias (A/B/C/D) | 0.447 | [0.286, 0.626] | 0.595 | 0.269 |

## 4. Matriz de confusao (linhas = humano, colunas = modelo)

Todos os casos, sem excluir `?`. Diagnostica **onde** os dois divergem.

| H \ M | A | B | C | D | ? | total |
| --- | --- | --- | --- | --- | --- | --- |
| **A** | **5** | 2 | 0 | 0 | 0 | 7 |
| **B** | 4 | **3** | 5 | 0 | 0 | 12 |
| **C** | 0 | 3 | **4** | 2 | 0 | 9 |
| **D** | 0 | 1 | 5 | **15** | 0 | 21 |
| **?** | 1 | 0 | 0 | 0 | 0 | 1 |
| **total** | 10 | 9 | 14 | 17 | 0 | 50 |

## 5. Auto-consistencia do modelo

_So uma repeticao: nao da para medir. Rode com R>=2 na condicao primaria — um anotador que discorda de si mesmo nao serve como segundo anotador._

## 6. Discordancias

23 de 50 casos. Detalhe em `saida/discordancias_oculta.csv`.

| id | projeto | CVE | H | M | votos M | conf H |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | ImageMagick | CVE-2016-10066 | B | C | C | alta |
| 3 | Chrome | CVE-2013-0917 | B | C | C | baixa |
| 7 | Android | CVE-2016-1621 | ? | A | A | baixa |
| 9 | Chrome | CVE-2012-5157 | B | C | C | alta |
| 10 | Chrome | CVE-2013-2920 | C | D | D | media |
| 11 | libtiff | CVE-2016-9535 | B | C | C | alta |
| 12 | Android | CVE-2016-1621 | A | B | B | alta |
| 16 | Android | CVE-2016-1621 | B | A | A | alta |
| 20 | Android | CVE-2016-1621 | B | A | A | alta |
| 21 | Android | CVE-2016-1621 | C | B | B | alta |
| 23 | yara | CVE-2017-9465 | D | C | C | alta |
| 24 | Android | CVE-2016-1621 | B | A | A | alta |
| 26 | linux | CVE-2017-18222 | D | C | C | alta |
| 27 | busybox | CVE-2019-5747 | D | B | B | media |
| 28 | Android | CVE-2016-1621 | C | B | B | baixa |
| 33 | Android | CVE-2016-1621 | A | B | B | alta |
| 34 | busybox | CVE-2018-20679 | C | D | D | alta |
| 35 | Android | CVE-2016-1621 | B | A | A | alta |
| 36 | libsndfile | CVE-2017-7586 | D | C | C | alta |
| 39 | Chrome | CVE-2015-8126 | B | C | C | alta |
| 41 | Android | CVE-2016-1621 | C | B | B | baixa |
| 49 | FFmpeg | CVE-2013-4263 | D | C | C | alta |
| 50 | ImageMagick | CVE-2019-10714 | D | C | C | alta |

Discordancias que mudam o veredito binario (vulneravel x nao): 8 — [10, 23, 26, 27, 34, 36, 49, 50]. As demais sao divergencia sobre *por que* nao e vulneravel e nao afetam a taxa de ruido.

## 7. O que este relatorio nao diz

- Nao diz quem esta certo. Mede reprodutibilidade, nao acuracia.
- As CVEs da amostra sao publicas e anteriores ao corte de treino do modelo; parte da concordancia pode ser memorizacao. A condicao `cve_oculta` sonda isso.
- n pequeno e linhas nao independentes: leia o IC, nao o ponto.
- Ver `pre_registro.md` para a lista completa de limitacoes declaradas antes da analise.
