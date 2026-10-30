# Quantos negativos de fato viram exemplo de treino

Fechado em **21/09/2026**. Script: `_cruzar_cpg_negativos.py`.

Continua o `NEGATIVOS.md`, do mesmo dia. Aquele respondeu "o BigVul sabe dizer qual função é";
este responde "e o CPG dela existe?". As duas juntas dão o **n final do lado negativo**.

## Situando: onde estamos e o que isto destrava

O modelo (ReVeal) consome **um grafo por função**. Montar o dataset é, para cada função, achar
o grafo dela. Isso precisa de duas coisas, e só agora as duas existem:

1. **saber o que procurar** — nome da função e em qual arquivo. Fechado no `NEGATIVOS.md`:
   28.578 dos 32.479 negativos do split têm os dois.
2. **ter onde procurar** — o `cpg.bin` do arquivo. É o que se mede aqui.

Sem isto o pipeline de treino não pode ser montado, porque não se sabe quantos exemplos
negativos existem por partição.

## O ponto que confunde: os CPGs não estão indexados por arquivo

Estão por **item positivo**. `~/curadoria/completa` tem uma pasta `NNNN__projeto` por item do
`relatorio_extracao.csv`, e dentro dela o `cpg.bin` do **arquivo inteiro** daquele item (o CPG
é do arquivo e não da função — é a §4.3, e é o motivo de existir a decisão de recorte do
`RECORTE_SUBGRAFO.md`).

Então um negativo do commit `C` no arquivo `A` é alcançável se **algum** item positivo tiver o
mesmo par `(commit, arquivo)` e a pasta dele tiver `cpg.bin`. Vários itens positivos caem no
mesmo par — é o fan-out de novo, aqui a favor —, e por isso 2911 pastas dão só 1486 pares.

| | n |
| --- | --- |
| pastas de item em `~/curadoria/completa` | 2911 |
| ...com `cpg.bin` | **2911** (100%) |
| itens no `relatorio_extracao.csv` | 2957 |
| pares `(commit, arquivo)` distintos com CPG | **1486** |

Os 2911 contra 2957 são as perdas de download já declaradas (2912 baixados, 45 perdidos); a
diferença de 1 entre baixado e pasta não foi investigada e é irrelevante na escala aqui.

## O resultado

| | n | % dos 32.479 |
| --- | --- | --- |
| negativos do split | 32.479 | 100% |
| usáveis (têm nome e `file_name`) | 28.578 | 88,0% |
| **alcançáveis** (o arquivo tem CPG) | **26.914** | **82,9%** |
| **montáveis** (depois do desempate por corpo) | **26.907** | **82,8%** |

Os alcançáveis são 94,2% dos usáveis — ou seja, **a perda desta etapa é pequena**: quase todo
negativo que o BigVul sabe nomear está num arquivo que já foi grafado. A perda dominante
continua sendo o `file_name` vazio (11,9%), registrada no `NEGATIVOS.md` como recuperável.

Dentro dos 26.914 alcançáveis: 25.070 sem ambiguidade nenhuma, 1844 com nome repetido dentro do
arquivo, dos quais **1837 o `sha1_corpo` desempata** e 7 são linhas duplicadas do próprio
BigVul (mesmo corpo, mesmo grafo — entram uma vez só). É o mesmo mecanismo do `NEGATIVOS.md`.

| partição | split | usáveis | **montáveis** | % do split |
| --- | --- | --- | --- | --- |
| treino | 20.061 | 17.647 | **16.347** | 81,5% |
| validação | 5004 | 4450 | **4237** | 84,7% |
| teste | 7414 | 6481 | **6323** | 85,3% |

**Bate com a medida de 15/08.** O `_negativos_reaproveitaveis.py` tinha dado 26.962, casando só
por arquivo, antes de existir nome de função. Aqui deu 26.914 casando por `(commit, arquivo)` e
já com nome. A diferença de 48 (0,2%) é o esperado de uma chave mais estrita; as duas medidas
se corroboram em vez de se contradizer.

## O que isto obriga a corrigir: as razões da Decisão 5

A Decisão 5 (05/09, `documentos-orientação/resposta_treinamentos_bigvul.md`) fixou "pool de
negativos cheio, idêntico em todos os braços" e declarou as razões **negativo : positivo** como
**11,1:1** no `M_raw` e **37,6:1** no `M_cur` e nos cinco `M_ctrl`. Esses dois números foram
calculados sobre os **20.061 negativos brutos** da partição de treino — antes de saber quantos
dariam grafo.

O pool real é **16.347**. Então:

| braço | positivos (treino) | razão declarada em 05/09 | **razão real** |
| --- | --- | --- | --- |
| `M_raw` | 1806 | 11,1:1 | **9,1:1** |
| `M_cur` | 533 | 37,6:1 | **30,7:1** |
| `M_ctrl` (cada um dos 5) | 533 | 37,6:1 | **30,7:1** |

**A decisão em si não muda, e o argumento que a sustenta também não:** `M_cur` e os cinco
`M_ctrl` têm 533 positivos e o **mesmo** pool, logo a mesma razão dos dois lados — o
desbalanceamento continua sendo idêntico e continua não podendo explicar diferença entre eles.
Quem é afetado é só a leitura do `M_raw`, que já era "referência de escala superior".

O que muda são **os dois números escritos no registro**, e eles não podem entrar no artigo como
estão. Corrigir na `resposta_treinamentos_bigvul.md` e em qualquer lugar do `main.tex` que os
repita.

## O que isto NÃO é

- **Não é "os 26.907 grafos existem".** É "o arquivo deles foi grafado". Achar a função **dentro**
  do CPG por `nameExact` + desempate por corpo ainda não foi executado, e vai ter perda própria
  — nome que o extrator leu da assinatura pode não bater com o nome que o Joern dá ao método
  (macros, `<duplicate>`, C++ com namespace). **Medir isso é a próxima etapa, não uma suposição.**
- **Não toca rótulo, conjunto de teste, nem regra congelada.** É contagem de arquivo em disco e
  cruzamento de chave. Nenhum veredito foi lido.
- **Não é o mesmo que a colisão de nome dos positivos** (`COLISAO_NOME.md`). Lá a decisão é
  *declarar* e a evidência da curadoria continua calculada sobre a união dos homônimos. Aqui é
  montagem de dataset, que é posterior e não é regra — e onde o corpo desempata.

## O que muda a partir daqui

O lado negativo do dataset tem número final por partição: **16.347 / 4237 / 6323**. Somado aos
positivos já congelados (`conjuntos_treino/`: `M_raw` 1806, `M_cur` 533, 5 × `M_ctrl` 533), o
tamanho de cada um dos 7 braços está definido e o pipeline de treino pode ser dimensionado.

Próximo passo: **executar a localização de verdade** — para uma amostra, abrir o `cpg.bin` e
tentar achar a função por nome + `sha1_corpo`, medindo a taxa de acerto. É o número que falta
antes de gerar os ~28 mil subgrafos, porque ele decide se 26.907 é o n real ou só o teto.
