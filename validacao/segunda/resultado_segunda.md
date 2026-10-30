# Resultado da segunda validacao manual — precisao do filtro

Aberto em 30/10/2026 14:09:03 por `analisar_segunda.py --abrir`. Plano: `PRE_REGISTRO_SEGUNDA.md` (congelado em 30/10/2026, 14:06, depois da anotacao e antes da chave; desvio declarado no topo do pre-registro).

**Situando.** A traversal v3 confirma ou descarta cada positivo do BigVul. O autor anotou 60 funcoes (30 confirmadas + 30 descartadas, misturadas) sem saber o veredito, com a rubrica_v1: so a categoria D (a funcao e o sitio do defeito) e rotulo correto. O `?` fica fora de todo denominador.

## Tabela A/B/C/D/? por estrato

| estrato | A | B | C | D | ? | decididas |
| --- | --- | --- | --- | --- | --- | --- |
| confirmados | 0 | 4 | 8 | 18 | 0 | 30 |
| descartados | 1 | 7 | 9 | 13 | 0 | 30 |

## Medidas principais (secao 7)

| medida | estimativa | IC 95% | contagem |
| --- | --- | --- | --- |
| precisao do filtro (D entre os confirmados) | 60,0% | [41,9; 80,0] | 18 de 30 |
| D entre os descartados | 43,3% | [25,8; 62,1] | 13 de 30 |
| taxa base estimada (ponderada 806 : 1646) | 48,8% | [35,6; 62,8] | — |
| ganho (precisao - taxa base) | +11,2 pontos | [-6,4; +28,8] | — |

Bootstrap estratificado por cluster de commit: 10000 reamostragens validas de 10000, 0 descartadas por estrato vazio; 26 commits entre os confirmados decididos e 26 entre os descartados; `random.Random(7074)`.

**Frase pre-registrada que resulta (secao 7):** continua valendo a frase atual do artigo, agora com esta amostra: compativel com ganho (+11,2 pontos, IC 95% [-6,4; +28,8]), mas nao exclui ganho nulo a 95%.

## Leituras descritivas (secao 7, item 7; sem IC e sem criterio)

- (a) o filtro confirmou 0 das 1 funcoes A e 4 das 11 funcoes B da amostra (na Etapa 5: 0 de 5 e 0 de 10).
- (b) cobertura dos D (fracao dos sitios que o filtro mantem, ponderada pela moldura): 40,4% (na Etapa 5: 11 de 19 = 57,9%).

## Sensibilidades (secao 8; so estimativa pontual e n)

| recorte | precisao | D nos descartados | taxa base | ganho | n confirmados | n descartados |
| --- | --- | --- | --- | --- | --- | --- |
| 8.1 sem commit ja visto | 65,2% | 50,0% | 55,0% | +10,2 | 23 | 18 |
| 8.2 uma linha por commit | 65,4% | 50,0% | 55,1% | +10,3 | 26 | 26 |
| 8.3 so confianca alta | 92,3% | 61,5% | 71,7% | +20,7 | 13 | 13 |

8.4 os `?`: 0 entre os confirmados e 0 entre os descartados (fora de todo denominador).

Nenhuma sensibilidade substitui a analise principal (secao 7).

## Referencia: Etapa 5 (secao 10; as amostras NAO se somam)

- precisao: 64,7% (11 de 17), IC 95% [40,0; 86,7]
- taxa base: 44,2% (19 de 43); na v3, entre 42,9% e 45,2%
- ganho: +20,5 pontos, IC 95% [-1,8; +39,0]

## Entradas (SHA-256)

- `PRE_REGISTRO_SEGUNDA.md` `c877d06a3b0c5cfddba56228b3d1061d7f1d5487a028a9e05294491b8ed34066`
- `anotacao_segunda.csv` `11a916170d491a5b82bc8c5b38ea38b01f3fdd094b685abec00917751b9a6caa`
- `chave/chave_segunda.csv` `013f16819667bf3d8b4225652c031165abc824f9f06f3638d0a5a5e8bcf50afb`
