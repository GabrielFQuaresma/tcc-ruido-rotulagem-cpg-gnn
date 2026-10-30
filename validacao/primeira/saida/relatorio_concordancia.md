# Concordancia entre anotadores — ruido de rotulagem do BigVul

- condicao: **cve_visivel**
- repeticoes do modelo: [1, 2, 3]
- anotacao humana: `amostra_validacao_revisao.csv`
- rubrica congelada: `rubrica_v1.md` sha256 `81f9d2495741537a27a189dedfd1d6da767afc8171608b3fbf425d8809567316`
- plano de analise: `pre_registro.md` sha256 `8d96084383cdd6fa899fbcee9402ed93db2b64ea973268fa556daac95f2b4c6c`
- bootstrap: 10000 reamostragens por cluster de commit, semente 42

> Os rotulos do humano sao os primarios. O modelo e verificacao de confiabilidade, nao ground truth. Nenhum rotulo foi alterado aqui; os kappas abaixo sao pre-adjudicacao.

## 1. Distribuicao dos rotulos

| tipo | humano | modelo (voto majoritario) |
| --- | --- | --- |
| A | 7 | 10 |
| B | 12 | 15 |
| C | 9 | 8 |
| D | 21 | 17 |
| ? | 1 | 0 |

| anotador | D (vulneravel) | decididos | acuracia de rotulo | ruido estimado |
| --- | --- | --- | --- | --- |
| humano | 21 | 49 | 42.9% | **57.1%** |
| modelo | 17 | 50 | 34.0% | **66.0%** |

- IC95% da taxa de ruido (humano): [34.2%, 74.2%]
- IC95% da taxa de ruido (modelo): [44.7%, 81.0%]

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
| **binario (D x A+B+C)** — primaria | **0.744** | [0.496, 0.915] | 0.878 | 0.522 |
| 4 categorias (A/B/C/D) | 0.520 | [0.339, 0.746] | 0.653 | 0.278 |

### 3.2 Excluindo o caso pre-preenchido automaticamente ([29])

n = 48 casos | clusters (commits distintos) = 36

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.741** | [0.487, 0.913] | 0.875 | 0.518 |
| 4 categorias (A/B/C/D) | 0.506 | [0.330, 0.732] | 0.646 | 0.283 |

### 3.3 Por commit (primeira linha de cada commit distinto)

n = 37 casos | clusters (commits distintos) = 37

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.679** | [0.424, 0.891] | 0.838 | 0.495 |
| 4 categorias (A/B/C/D) | 0.631 | [0.415, 0.818] | 0.757 | 0.340 |

### 3.4 So casos em que o humano marcou confianca alta

n = 42 casos | clusters (commits distintos) = 32

| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |
| --- | --- | --- | --- | --- |
| **binario (D x A+B+C)** — primaria | **0.804** | [0.579, 0.953] | 0.905 | 0.514 |
| 4 categorias (A/B/C/D) | 0.567 | [0.391, 0.786] | 0.690 | 0.286 |

## 4. Matriz de confusao (linhas = humano, colunas = modelo)

Todos os casos, sem excluir `?`. Diagnostica **onde** os dois divergem.

| H \ M | A | B | C | D | ? | total |
| --- | --- | --- | --- | --- | --- | --- |
| **A** | **5** | 2 | 0 | 0 | 0 | 7 |
| **B** | 4 | **7** | 1 | 0 | 0 | 12 |
| **C** | 0 | 4 | **4** | 1 | 0 | 9 |
| **D** | 1 | 1 | 3 | **16** | 0 | 21 |
| **?** | 0 | 1 | 0 | 0 | 0 | 1 |
| **total** | 10 | 15 | 8 | 17 | 0 | 50 |

## 5. Auto-consistencia do modelo

- itens com todas as 3 repeticoes validas: 50
- **kappa de Fleiss entre repeticoes: 0.890** (concordancia media 0.920, esperada 0.272)
- casos em que as 3 repeticoes deram o MESMO rotulo: 44/50 (88.0%)

- casos instaveis entre repeticoes (6): [7, 20, 22, 24, 27, 33]

> Este numero e o teto do kappa humano-modelo: o modelo nao pode concordar com outro anotador mais do que concorda consigo mesmo.

## 6. Discordancias

18 de 50 casos. Detalhe em `saida/discordancias.csv`.

| id | projeto | CVE | H | M | votos M | conf H |
| --- | --- | --- | --- | --- | --- | --- |
| 7 | Android | CVE-2016-1621 | ? | B | ABB | baixa |
| 10 | Chrome | CVE-2013-2920 | C | D | DDD | media |
| 11 | libtiff | CVE-2016-9535 | B | C | CCC | alta |
| 12 | Android | CVE-2016-1621 | A | B | BBB | alta |
| 16 | Android | CVE-2016-1621 | B | A | AAA | alta |
| 20 | Android | CVE-2016-1621 | B | A | AAB | alta |
| 21 | Android | CVE-2016-1621 | C | B | BBB | alta |
| 23 | yara | CVE-2017-9465 | D | C | CCC | alta |
| 24 | Android | CVE-2016-1621 | B | A | AAB | alta |
| 27 | busybox | CVE-2019-5747 | D | A | CAA | media |
| 28 | Android | CVE-2016-1621 | C | B | BBB | baixa |
| 33 | Android | CVE-2016-1621 | A | B | BAB | alta |
| 35 | Android | CVE-2016-1621 | B | A | AAA | alta |
| 36 | libsndfile | CVE-2017-7586 | D | C | CCC | alta |
| 38 | rdesktop | CVE-2018-20182 | D | B | BBB | alta |
| 41 | Android | CVE-2016-1621 | C | B | BBB | baixa |
| 44 | wildmidi | CVE-2017-11664 | D | C | CCC | alta |
| 45 | ImageMagick | CVE-2016-10066 | C | B | BBB | alta |

Discordancias que mudam o veredito binario (vulneravel x nao): 6 — [10, 23, 27, 36, 38, 44]. As demais sao divergencia sobre *por que* nao e vulneravel e nao afetam a taxa de ruido.

## 7. O que este relatorio nao diz

- Nao diz quem esta certo. Mede reprodutibilidade, nao acuracia.
- As CVEs da amostra sao publicas e anteriores ao corte de treino do modelo; parte da concordancia pode ser memorizacao. A condicao `cve_oculta` sonda isso.
- n pequeno e linhas nao independentes: leia o IC, nao o ponto.
- Ver `pre_registro.md` para a lista completa de limitacoes declaradas antes da analise.
