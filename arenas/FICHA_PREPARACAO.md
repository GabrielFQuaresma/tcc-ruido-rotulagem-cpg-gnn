# Ficha de preparação das arenas externas

> Gerada em 16/10/2026 02:52 por `arenas/ficha_preparacao.py`, no fim do passo 3 do §10 do `PREREGISTRO_ARENAS.md` (congelado em 15/10/2026, SHA-256 `6284d831…a01838`). **Nenhuma predição existe; nenhuma foi lida.** Tudo aqui é contagem. Depois de gravada, o SHA-256 desta ficha é registrado e o script de análise o confere antes de abrir as arenas (§10, passo 6).

## Situando

As arenas externas são os conjuntos fora do treino onde se mede se o `M_cur` (o modelo treinado só com os positivos que a traversal confirmou) generaliza melhor que os 5 controles. Esta ficha fecha a preparação: quantas funções cada arena tem no fim, o que saiu e por quê, e o que essas contagens decidem, mecanicamente, sobre o que vai poder ser lido na abertura. O como de cada passo está em `arenas/PREPARACAO_ARENAS.md`.

## 1. Quantas funções cada arena tem no fim (vulneráveis / não vulneráveis)

| arena | candidatas | ficam na deduplicação | **com grafo** | % vulneráveis | veredito? |
| --- | --- | --- | --- | --- | --- |
| Sonda CWE-416 | 330 / 9254 | 323 / 9230 | **258 / 7751** | 3.2% | **sim** |
| VentiVul v3 — família de memória | 50 / 3326 | 50 / 3274 | **48 / 2778** | 1.7% | **sim** |
| PrimeVul v0.1 | 1959 / 52791 | 1025 / 30380 | **843 / 20806** | 3.9% | **sim** |
| VentiVul v3 — inteiro (descritivo) | 263 / 13063 | 248 / 12954 | **229 / 10225** | 2.2% | descritiva (sem veredito) |

**Troca automática da G3 (VentiVul):** a família de memória tem 48 positivos com grafo (≥ 30) → **não dispara**; decide a família de memória.

## 2. O que saiu na deduplicação (Decisão H), por motivo e rótulo

| motivo | Sonda CWE-416 | VentiVul v3 — família de memória | PrimeVul v0.1 | VentiVul v3 — inteiro (descritivo) |
| --- | --- | --- | --- | --- |
| cve | 0 / 0 | 0 / 0 | 900 / 20992 | 0 / 0 |
| commit | 0 / 0 | 0 / 0 | 32 / 650 | 0 / 0 |
| corpo | 2 / 8 | 0 / 52 | 1 / 681 | 1 / 70 |
| duplicata_interna | 0 / 11 | 0 / 0 | 0 / 69 | 0 / 25 |
| duplicata_conflito | 5 / 5 | 0 / 0 | 1 / 1 | 14 / 14 |
| falha_sem_corpo | 0 / 0 | 0 / 0 | 0 / 18 | 0 / 0 |

## 3. O que se perdeu na extração (arquivo, CPG, localização), por motivo e rótulo

| motivo | Sonda CWE-416 | VentiVul v3 — família de memória | PrimeVul v0.1 | VentiVul v3 — inteiro (descritivo) |
| --- | --- | --- | --- | --- |
| ambiguo | 2 / 16 | 0 / 25 | 0 / 58 | 0 / 42 |
| arquivo_codificado_cobertura_zero | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 73 |
| arquivo_codificado_sem_candidato | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 83 |
| arquivo_nao_identificado_no_commit | 0 / 0 | 0 / 0 | 35 / 895 | 0 / 0 |
| no_fora_da_funcao | 0 / 0 | 0 / 0 | 0 / 1 | 0 / 0 |
| sem_arquivo_baixado | 13 / 0 | 0 / 0 | 0 / 270 | 0 / 0 |
| sem_metodo | 50 / 838 | 1 / 470 | 147 / 8234 | 18 / 2522 |
| sem_nome_de_arquivo | 0 / 624 | 0 / 0 | 0 / 0 | 0 / 0 |
| sem_nome_de_funcao | 0 / 1 | 1 / 1 | 0 / 116 | 1 / 9 |
| **perda total** | 20.1% / 16.0% | 4.0% / 15.1% | 17.8% / 31.5% | 7.7% / 21.1% |

A perda é desigual entre rótulos em todas as arenas; os motivos estão em `PREPARACAO_ARENAS.md` (passos 3b–3d).

## 4. Contagem por faixa de tamanho e o que ela decide (Decisão I)

Faixas do `PREREGISTRO_TAMANHO.md` §2 (nós do grafo). Mínimo de 30 (convenção do §3 de lá).

| faixa | Sonda CWE-416 | VentiVul v3 — família de memória | PrimeVul v0.1 | VentiVul v3 — inteiro (descritivo) |
| --- | --- | --- | --- | --- |
| ate 46 | 72 / 4275 | 6 / 1391 | 49 / 7496 | 50 / 5395 |
| 47-131 | 78 / 2331 | 17 / 968 | 158 / 7344 | 81 / 3224 |
| 132-339 | 74 / 893 | 17 / 349 | 275 / 4054 | 70 / 1265 |
| 340+ | 34 / 252 | 8 / 70 | 361 / 1912 | 28 / 341 |

| o que a contagem decide | Sonda CWE-416 | VentiVul v3 — família de memória | PrimeVul v0.1 | VentiVul v3 — inteiro (descritivo) |
| --- | --- | --- | --- | --- |
| F1 e recall por faixa (≥ 30 positivos) | ate 46, 47-131, 132-339, 340+ | nenhuma | ate 46, 47-131, 132-339, 340+ | ate 46, 47-131, 132-339 |
| taxa de falso positivo por faixa (≥ 30 negativos) | ate 46, 47-131, 132-339, 340+ | ate 46, 47-131, 132-339, 340+ | ate 46, 47-131, 132-339, 340+ | ate 46, 47-131, 132-339, 340+ |
| V1 (≥ 30 negativos em até 46 e 340+) | se aplica | se aplica | se aplica | se aplica |
| V2 (≥ 30 positivos em alguma faixa pequena) | se aplica (faixas: ate 46, 47-131, 132-339, 340+) | não se aplica | se aplica (faixas: ate 46, 47-131, 132-339, 340+) | se aplica (faixas: ate 46, 47-131, 132-339) |
| veredito de tamanho | V1 e V2 | só V1 | V1 e V2 | V1 e V2 |

## 5. Tokens fora do vocabulário (Word2Vec do treino, sem ajuste em dado de arena)

| arena | tokens de nó calculados | fora do vocabulário | taxa |
| --- | --- | --- | --- |
| teste do BigVul (referência; o Word2Vec também não o viu) | 5.467.742 | 586.098 | 10,7% |
| Sonda CWE-416 | 3951192 | 479888 | 12.1% |
| VentiVul v3 — família de memória | 1435980 | 263105 | 18.3% |
| PrimeVul v0.1 | 22299437 | 3032248 | 13.6% |
| VentiVul v3 — inteiro (descritivo) | 5138935 | 929451 | 18.1% |

## 6. Arquivos de onde esta ficha saiu

| arquivo | SHA-256 |
| --- | --- |
| `arenas/grafos_primevul.tsv` | `5ecc0b14ceb9edeaf9827c4917a0a6853b42b42ad4ae394bcaaa1464021e68ca` |
| `arenas/grafos_sonda.tsv` | `c24b955b87902f47c0dc81a93d62c12807b3a33367de42467699af35b1b3b7b4` |
| `arenas/grafos_ventivul.tsv` | `f75921ba91ba6925dbf766fe18228585c24497b3fda3b3b8617a1ee6efc83aba` |
| `arenas/indice_primevul.tsv` | `9871794f97019db7c1712ee395dbb0a101c7fd5add70228d3929deda1d369656` |
| `arenas/indice_sonda.tsv` | `5fb46461f3a80e1b02437079bdfa97a78d9420818e68843b84a6bf592b9796d3` |
| `arenas/indice_ventivul_familia.tsv` | `e405f69666aa4338c655cf53ceb38ee4c54db252c5e6d82234bc48da5e89c68b` |
| `arenas/indice_ventivul_inteiro.tsv` | `c58f14bed787550d27ac1d7245e254555b68546366bbfeacc829160648f6d37b` |
| Word2Vec do treino | `20585c12449aa792dd2b040ae4bd7d13cd1fa28677aa88cd237f49533e618392` |

## O que esta ficha NÃO é

- não é resultado: nenhum modelo previu nenhuma função de arena até aqui;
- não traz a traversal pura (passo 4, depois desta ficha) nem as predições (passo 5).
