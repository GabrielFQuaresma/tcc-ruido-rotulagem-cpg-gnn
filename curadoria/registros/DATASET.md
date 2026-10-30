# O dataset de grafos: montado, conferido, e um problema que apareceu no fim

> **06/10/2026 — este é o dataset da v2, mantido como registro** (`~/curadoria/dataset`,
> `dataset_indice.tsv`). O da traversal v3 foi remontado à parte (`~/curadoria/dataset_v3`,
> `dataset_indice_v3.tsv`, 25.829 grafos): positivos com hash, colisões no método certo, grupos que
> misturavam arquivos de mesmo nome separados. A perda assimétrica descrita abaixo **sumiu** na v3
> (`M_cur` e `M_ctrl` com 100% de grafo). Registro: `TRAVERSAL_V3.md`, Fase 5.

Fechado em **21/09/2026**. Scripts: `montar_dataset.py`, `exportar_grafos.sc`,
`_conferir_dataset.py`, `_conferir_bracos.py`.

Último passo antes de treinar. Até aqui havia CPG **por arquivo** e listas de quais funções
entram; o ReVeal consome **um grafo por função**. Este registro é a montagem.

## O que foi produzido

**25.670 grafos**, em `~/curadoria/dataset/grupos/` (fora do repositório — são ~1 GB; o
repositório fica com `dataset_indice.tsv`, que é de onde se escreve).

| partição | positivos | negativos | total |
| --- | --- | --- | --- |
| treino | 1647 | **14.390** | 16.037 |
| validação | 249 | 3674 | 3923 |
| teste | 470 | 5240 | 5710 |

Tamanho dos grafos: mínimo 4 nós, **mediana 58**, p95 511, máximo 11.903. Total de 3.676.986
nós — `CALL` 1.234 mil, `IDENTIFIER` 1.025 mil, `LITERAL` 284 mil.

**1501 execuções de Joern, uma por arquivo, ~6,6 s cada.** Não uma por função: o CPG do arquivo
serve todas as funções dele, positivas e negativas juntas.

### A estimativa contra a contagem

O `LOCALIZACAO.md` projetou o lado negativo a partir de uma amostra de 80 arquivos. Agora há
contagem:

| partição | estimado | **contado** | erro |
| --- | --- | --- | --- |
| treino | 14.133 | **14.390** | +1,8% |
| validação | 2765 | **3674** | +32,9% |
| teste | 5892 | **5240** | −11,1% |

O treino — que é o que importa — bateu com 1,8% de erro. A validação errou muito, e o registro
já avisava por quê: eram **95 funções em poucos arquivos**, a linha menos confiável da tabela.
**A partir daqui valem as contagens; as estimativas são história.**

## O recorte, e o que agora é teste em vez de afirmação

Implementado em `exportar_grafos.sc`, conforme o `RECORTE_SUBGRAFO.md`: subgrafo induzido por
`method.ast`, **não seguir `CALL`**, **tipo como atributo de nó**.

O `_conferir_dataset.py` roda quatro invariantes sobre o dataset inteiro:

| invariante | resultado |
| --- | --- |
| nós fora da faixa de linhas da função (**vazamento de rótulo**) | **0** de 3.676.986 |
| arestas apontando para nó inexistente | 0 |
| ids duplicados | 0 |
| id em mais de uma partição | 0 |

**A primeira era só um raciocínio e virou teste.** E o teste pegou uma falha real: **1 nó** em
3,7 milhões, num arquivo onde a função é definida pela macro `PHP_FUNCTION` — o Joern gera
métodos homônimos e a fronteira entre eles sai borrada, e um nó da função **anterior** entrou na
AST da seguinte. Um exemplo foi descartado.

A regra do descarte é **estrutural e uniforme** (`fora_da_funcao` em `montar_dataset.py`): grafo
com nó fora da faixa de linhas sai, porque não dá para garantir que o nó é da própria função.
Não menciona projeto, CVE nem nome de função — é teste automatizado, não intenção. E descartar
é omissão, que pela regra do projeto é de graça.

## Dois defeitos encontrados durante a montagem

**1. `"nan"` como nome de arquivo.** O `file_name` do BigVul passa pelo pandas e um valor ausente
chega como a **string** `"nan"`, que passa em qualquer teste de "tem valor". Resultado: 248
positivos com arquivo `"nan"`, e em 34 commits **2+ itens caíam no mesmo grupo** — e um grupo usa
**um** `cpg.bin`. Itens seriam procurados no CPG do arquivo errado; havendo homônimo lá, sairia
**o grafo errado com o rótulo certo**. Corrupção silenciosa, invisível na métrica.

*Corrigido* lendo o nome do arquivo **do disco** (`arquivo__<nome>` na pasta do item). Conferido
antes de trocar: **2686 concordam com o relatório, 0 divergem**, e o disco ainda resolve 225
casos de `"nan"`. Efeito: 1471 → **1501 arquivos**.

**2. Saída desatualizada em silêncio.** Grupos gravados antes da correção ficariam com a lista de
alvos antiga, e o `--retomar` os pularia. Foi criada uma **reconciliação**: se o número de alvos
de um grupo mudou, a saída dele é descartada e refeita. Ela agiu, descartando 20 grupos.

## 🔴 O problema que apareceu no fim: a perda é assimétrica entre os braços

Os sete braços são listas de itens, fixadas em `conjuntos_treino/` desde 05/09. Só entra no
dataset o item cuja função foi localizada no CPG. Então o n de cada braço é a **interseção**:

| braço | na lista | **com grafo** | % mantido |
| --- | --- | --- | --- |
| `M_cur` | 533 | **513** | **96,2%** |
| `M_ctrl_s2026` | 533 | 482 | 90,4% |
| `M_ctrl_s2027` | 533 | 487 | 91,4% |
| `M_ctrl_s2028` | 533 | 483 | 90,6% |
| `M_ctrl_s2029` | 533 | 486 | 91,2% |
| `M_ctrl_s2030` | 533 | 489 | 91,7% |
| `M_raw` | 1806 | 1647 | 91,2% |

**`M_cur` mantém 96,2%; os `M_ctrl` mantêm 91,1% em média. Diferença de +5,2 pontos.**

### Por que acontece — e a explicação fecha numericamente

> ⚠️ **CORREÇÃO DE 03/10/2026 — a explicação abaixo está ERRADA. Ver `PERDA_BRACOS.md`.**
> Medido item a item: 157 dos 159 positivos perdidos são **homônimos com corpo sem hash para
> desempatar** (os positivos entraram na montagem com `shas: []`), não cegueira do `#ifdef`. Os
> cegos já estavam fora do `M_raw` desde 11/08 (são os indeterminados). A assimetria vem de a
> curadoria confirmar pouco os itens com colisão (12,1% contra 31,2%). A decisão de resortear
> continua valendo. O texto original fica abaixo como registro.

Não é acaso nem bug. É **consequência direta da cegueira do `#ifdef`** medida no `PARSE_IFDEF.md`.

Para a traversal **confirmar** um item, ela precisa ver evidência; para ver evidência, o corpo da
função precisa estar parseado. Logo **`M_cur` não pode conter item cego — por construção**. Já o
`M_ctrl` é sorteio aleatório dos positivos do treino, e **pode** conter os cegos.

A conta fecha: a cegueira medida na população foi **8,2%**. O `M_ctrl` perde 8,9%; o `M_cur`
perde 3,8%. A diferença (~5 pontos) é da ordem da cegueira, e o resíduo de 3,8% é a perda comum
aos dois (nome que não casa etc.).

### Por que isto importa, dito sem suavizar

O `M_ctrl` existe para garantir que **a única diferença entre ele e o `M_cur` seja o rótulo**.
Agora há duas: o rótulo **e** o tamanho (513 contra ~485), e mais importante, **a composição** —
o `M_ctrl` carrega funções que o `M_cur` não podia carregar.

Isso abre uma explicação alternativa para qualquer resultado: *o `M_cur` foi melhor porque os
rótulos estão mais limpos, ou porque as funções dele são mais bem parseadas e têm grafo mais
rico?* Enquanto essa pergunta estiver em aberto, o resultado central não é limpo.

**Nada foi alterado.** Corrigir isto mexe no `M_ctrl`, que é a peça de controle do experimento, e
não é decisão de script.

### RESOLVIDO em 21/09/2026: os `M_ctrl` foram resorteados dentro de quem tem grafo

**Decisão do autor.** Novos arquivos `conjuntos_treino/M_ctrl_g<semente>.tsv`, sementes 2026–2030,
**513 itens cada** — o mesmo N do `M_cur` com grafo.

É a aplicação da **mesma** definição ("sorteio aleatório de mesmo N, do bruto do treino") no
estágio certo: o sorteio de 05/09 foi feito antes de se saber quais itens teriam grafo.

**Os `M_ctrl_s*.tsv` de 05/09 não foram tocados** — são o registro daquela decisão.

Uma correção de enquadramento que vale registrar: as opções que este documento listou como (a) e
(c) **não eram alternativas** — (a) contém (c). A cadeia é *tem grafo* ⟹ *tem corpo parseado* ⟹
*não é cego*. Resortear dentro de quem tem grafo já garante que todo item do controle tem corpo,
que era o que (c) pretendia.

## 🔴 O que sobrou, e é maior: `M_cur` e `M_ctrl` diferem em TAMANHO

Medido em `_conferir_composicao.py`, sobre os positivos de treino **que têm grafo**:

| | densidade de parse (nós/linha) | **tamanho (mediana de nós)** |
| --- | --- | --- |
| `M_cur` | 3,76 | **316** |
| `M_ctrl` (os cinco) | 3,42 | **126–152** |
| `M_raw` | 3,43 | 139 |

**A densidade de parse quase não difere (+10%)** — ou seja, o resorteio acima de fato resolveu o
que era para resolver. **O tamanho difere por mais de 2×**, e a diferença atravessa a distribuição
inteira (p25 do `M_cur` é 139; a mediana do `M_ctrl` é ~139).

**Por que acontece:** a regra de curadoria exige camada 1 **E** camada 2, com mínimo 1 em cada.
Função maior tem mais chamadas, mais acessos indexados e mais fluxos — logo mais chance de
satisfazer as duas. **A regra é mecanicamente enviesada para função grande.**

**Isto não é efeito do `#ifdef` e existiria com parse perfeito.** É confundimento de verdade: se
o `M_cur` vencer, não há como separar *"os rótulos estão mais limpos"* de *"os grafos são maiores"*
— e tamanho de grafo afeta GNN por conta própria.

**E não estava registrado em lugar nenhum do projeto.** Foi conferido: nenhum `.md` menciona
balanço de tamanho ou complexidade entre os braços.

### Parear o tamanho **não é viável**, e isso é informação, não fracasso

Tentativa de montar um `M_ctrl` com a mesma distribuição de tamanho do `M_cur`, em 5 faixas de
quantil, sorteando do bruto **fora** do `M_cur` (pool de 1134):

| faixa | tamanho (nós) | precisa | disponível | |
| --- | --- | --- | --- | --- |
| 0 | 0–107 | 102 | 621 | |
| 1 | 108–227 | 103 | 238 | |
| 2 | 228–414 | 102 | 133 | |
| 3 | 415–841 | 103 | 97 | **faltam 6** |
| 4 | 842–6541 | 103 | 45 | **faltam 58** |

**O `M_cur` já levou as funções grandes e não sobra equivalente no resto do bruto.**

A leitura é o ponto: isso **não** é falha de amostragem, é **propriedade do conjunto**. "Curado" e
"grande" estão amarrados neste dataset, e o experimento **não consegue separar os dois pela
amostragem**. Forçar o pareamento exigiria reamostrar com reposição ou afrouxar as faixas — as
duas coisas mudam o que o controle é.

### A saída é controlar na análise, não na amostragem

Como o pareamento não é viável, o desconfundimento tem de acontecer **depois**, na leitura dos
resultados: comparar `M_cur` × `M_ctrl` **dentro de faixas de tamanho** e reportar se o efeito
sobrevive em cada faixa. Se sobreviver, não é tamanho. Se só aparecer nas faixas grandes, é.

Isto tem de entrar no desenho **antes** de treinar, porque decide o que se mede — e vai declarado
nas Ameaças à Validade de qualquer jeito.

## O que muda a partir daqui

O dataset existe, está conferido e é reprodutível; os controles foram realinhados. O que falta
antes de treinar:

1. **Decidir como o tamanho entra na análise** (estratificação na leitura dos resultados).
2. **Extração de features** — tokenização e embedding de nó. Não precisa reabrir CPG nenhum: o
   grafo já guarda o código de cada nó.
