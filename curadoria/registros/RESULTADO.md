# Etapa 5 — a precisão do filtro de curadoria, medida nos 50 casos anotados

Fechada em **10/08/2026**. Este é o número que o card dos traversals existia para produzir.

## Onde estamos, para quem chegou agora

O TCC pergunta se **limpar os rótulos do BigVul melhora a generalização de uma GNN**. A limpeza
é feita por um **filtro de curadoria**: uma consulta ao grafo de propriedades de código (CPG) que
olha cada função que o BigVul marcou como vulnerável e diz se o padrão da família de erro de
buffer está mesmo ali. Quem o filtro **confirma** entra no `M_cur` (o conjunto de treino curado);
quem ele **descarta** apenas fica de fora — o silêncio nunca inverte rótulo.

Para isso valer alguma coisa, é preciso saber **quanto o filtro acerta**. Essa é a *precisão do
filtro*: entre as funções que ele confirmou, quantas eram de fato o sítio da vulnerabilidade.
A Etapa 5 mede exatamente isso, e é a única medida honesta de precisão que o trabalho tem.

O que aconteceu antes: a regra foi escrita na Etapa 4a olhando só o **tamanho** do conjunto
resultante (nunca acurácia), conferida na Etapa 4b contra um **dev set** de 30 casos anotados
pelo modelo, e só então — aqui — congelada e medida contra os **50 casos anotados pelo autor**.

## Passo 1 — o congelamento (o que dá valor ao número)

`congelar.py --gravar`, 10/08/2026. SHA-256 dos quatro arquivos que decidem o veredito:

| arquivo | sha256 (16 primeiros) |
| --- | --- |
| `curadoria_v2.sc` | `835571171d40b50c…` |
| `dados/funcoes_memoria.tsv` | `85297b08107ab18c…` |
| `dados/fontes_nao_confiaveis.tsv` | `9e36fd6f71828a41…` |
| `regra_veredito.toml` | `485b73c3c71b6b66…` |

Os hashes completos estão em `CONGELAMENTO.md` e `congelamento.tsv`. O `etapa_5.py` **recusa
rodar** se algum divergir — é o mesmo mecanismo do `comparar.py`, que recusa rodar sem o
pré-registro. Nenhum arquivo dos 50 foi lido antes desta gravação.

## Passo 2 — a rodada

`montar_teste_50.py` reconstruiu o conjunto de teste e o mapa `caso_NN ↔ NNNN__projeto`. A
conferência aqui é mais forte que a do dev: como o `revisar_validacao.py build` grava `id = i+1`
na ordem exata de `df.sample(n=50, random_state=42)`, o casamento foi conferido **elemento a
elemento** — commit, CVE e projeto das 50 linhas — e não por multiconjunto. 50/50 bateram.

`rodar_curadoria.py --lista teste_50.tsv --saida saida_50`: 50 itens, **556 s**, 1 falha
(`0103__busybox`, função `udhcp_get_option32` não encontrada no CPG — mesma família das falhas
de `nome_da_funcao` já vistas no lote da Etapa 3). A regressão do `BASELINE_libgd.md` passou
dentro da rodada.

**49 itens com evidência**, dos quais 5 `indeterminado` (a ferramenta não conseguiu olhar) →
44 olháveis, **17 confirmados = 38,6% do `M_raw` olhável**. Terceira amostra independente na
mesma ordem de grandeza: 48,1% no dev (n=27) e 39,5% no lote da Etapa 3 (n=43).

O balde **"só camada 2" deu 0 pela terceira vez** — 0 de 49 itens com evidência aqui, contra os
0 de 27 registrados no `ETAPA_4A.md` (dev) e 0 de 44 no `LOTE_50.md`. Três amostras, zero
exceções: o achado estrutural do `LOTE_50.md` (camada 2 ⊆ camada 1) está confirmado.

## Passo 3 — O NÚMERO

Rótulos do anotador humano (o autor), rubrica `rubrica_v1.md` congelada. **n = 43 comparáveis**:
49 com evidência, menos 5 indeterminados, menos 1 rótulo `?`.

Lembrete da rubrica: **D** = a função é o sítio da vulnerabilidade (o filtro *deveria* confirmar).
**A** = mudança sem efeito semântico; **B** = mudou por motivo não relacionado à CVE; **C** =
mudou como parte do conserto, mas o defeito não está nela. A, B e C são todos "não vulnerável"
(o filtro *deveria* descartar), por motivos diferentes.

| | A | B | C | D | n |
| --- | --- | --- | --- | --- | --- |
| **confirmado** | 0 | 0 | 6 | **11** | 17 |
| **descartado** | 5 | 10 | 3 | 8 | 26 |

- **taxa base** (proporção de D entre os 43 comparáveis, isto é, quanto o BigVul acerta sozinho):
  **19/43 = 44,2%**
- **precisão do filtro** (proporção de D entre os 17 que ele confirmou): **11/17 = 64,7%**
- **ganho: +20,5 pontos** (44,2% → 64,7%)
- **IC 95%**, bootstrap com reamostragem por **cluster de commit** (33 clusters, 10.000
  reamostragens, semente 42 — a mesma convenção do `pre_registro.md`):
  **precisão [40,0% ; 86,7%]**, **ganho [−1,8 ; +39,0] pontos**.

### A frase honesta sobre este número

**A estimativa pontual replica o dev quase exatamente (+20,5 aqui contra +21,1 lá), e o
intervalo de confiança do ganho encosta no zero.** As duas coisas são verdade e as duas têm que
ir para o texto.

O que se pode escrever: *"o filtro eleva a proporção de rótulos corretos de 44,2% para 64,7%
(n=43); o IC 95% agrupado por commit é [40,0; 86,7] para a precisão e [−1,8; +39,0] para o
ganho — a amostra é compatível com um ganho substancial, mas não exclui ganho nulo a 95%."*

O que **não** se pode escrever: *"o filtro melhora significativamente a qualidade do rótulo"*.
Com 33 clusters de commit, esta amostra não tem poder para essa frase, e a frase não é
necessária — a curadoria nunca dependeu dela (ver "O que isto não é", abaixo).

## Os outros três recortes, fixados antes de ver a tabela

| recorte | n | taxa base | precisão | ganho |
| --- | --- | --- | --- | --- |
| **os 50 completos** | 43 | 44,2% | **11/17 = 64,7%** | +20,5 |
| sem o caso de regressão (`1217__libgd`) | 42 | 42,9% | 10/16 = 62,5% | +19,6 |
| por commit (1ª linha de cada commit distinto) | 31 | 61,3% | 11/15 = 73,3% | +12,0 |
| rótulo do **modelo** (sensibilidade) | 44 | 36,4% | 10/17 = 58,8% | +22,5 |

**Por que "sem o caso de regressão":** o `1217__libgd` é o caso do artigo, contra o qual a
traversal vem sendo conferida desde a Etapa 0 — ele **está dentro da amostra dos 50** e não é
cego. Tirá-lo derruba a precisão de 64,7% para 62,5%. A contaminação existe e é de 1 linha em 43.

**Por que "por commit":** 43 linhas comparáveis vêm de 33 commits, e 14 linhas dos 50 são a mesma
CVE. As linhas não são observações independentes; o `pre_registro.md` já exigia esta leitura.

**Por que o rótulo do modelo é só sensibilidade:** o modelo não é ground truth, mede
reprodutibilidade da rubrica. Nas 48 linhas com os dois rótulos, humano e modelo concordam em
**89,6% no binário D contra A/B/C** (43/48) e em 66,7% na categoria exata (32/48). O IC do ganho
sob rótulo do modelo é [+0,7 ; +41,7] — exclui zero por pouco, ao contrário do humano. Duas
leituras da mesma coisa, com rótulos de qualidades diferentes: não escolher a que sai melhor.

## Três leituras qualitativas que valem mais que a precisão

### 1. O filtro nunca confirmou um A nem um B — e isso é o mecanismo alegado

Taxa de confirmação por rótulo, sobre os 43 comparáveis:

| rótulo | confirmados / total |
| --- | --- |
| A (sem mudança semântica) | **0 / 5** |
| B (mudou por outro motivo, veio de carona no commit) | **0 / 10** |
| C (mudou no conserto, mas não é o sítio) | 6 / 9 |
| D (é o sítio) | 11 / 19 |

**Os 15 casos de A e B foram todos descartados. Todos os 6 erros do filtro são C.** Isso importa
porque A e B são exatamente o ruído que o mecanismo do fan-out produz — o commit toca N funções e
o BigVul marca todas — e é esse ruído que a curadoria alega remover. O C é a categoria dura: a
função mudou *dentro do conserto*, tem o padrão de acesso a buffer no corpo, e distingui-la do
sítio real exige entender a intenção do patch. Errar só em C é o modo de falha mais defensável
que havia disponível.

### 2. O cluster de fan-out alto: 11 de 11 corretamente removidos

A CVE-2016-1621 (libvpx/Android) ocupa 14 das 50 linhas. Entre as 12 comparáveis do cluster:
**nenhuma é D** — nenhuma daquelas 14 funções é o sítio da vulnerabilidade. O filtro descartou
**11 de 11** dos que julgou e confirmou 1 (rótulo C).

É a ilustração mais limpa do mecanismo em todo o trabalho: dentro de um commit de fan-out alto, o
filtro separou a função com o defeito das que vieram junto — e como aqui *nenhuma* tinha defeito,
ele removeu quase o cluster inteiro.

**Ressalva que anda junto:** tirando esse cluster, sobram 31 comparáveis com taxa base 61,3% e
precisão 68,8% (11/16) — ganho de **+7,5 pontos**, bem menor que os +20,5 do total. Ou seja:
**boa parte do ganho vem de onde está o ruído**, que é o que a hipótese causal prevê, mas também
significa que em linhas de fan-out baixo o ganho medido é modesto. As duas leituras vão para o
texto.

### 3. Os 8 D descartados são perda de recall, e a camada 2 é quem cobra

Os 8 casos em que a função era o sítio e o filtro descartou: `0536__linux`, `2467__Android`,
`0930__yara`, `1437__linux`, `1685__tcpdump`, `1578__rdesktop`, `0299__FFmpeg`,
`1753__ImageMagick`. **Todos os 8 têm camada 2 = 0** (o fluxo não fecha); 5 deles têm camada 1 > 0
(a presença estava lá). O conector `E` é o que custa esse recall, e o custo é de graça por
desenho: o silêncio não inverte rótulo, a função só não entra no `M_cur`.

Cobertura dos D (recall): 11/19 = 57,9%. **Não é critério**, e está aqui por transparência.

## O que este número **não** é

1. **Não é a segunda validação manual da §4.7.** Aquela é outra coisa: uma amostra **nova**,
   estratificada pelo veredito do filtro (confirmados × descartados), sorteada depois da rodada
   completa nos 2957 positivos. Esta aqui reusa os 50 casos que já existiam, que são uma amostra
   dos positivos **brutos**. Confundir as duas é o erro que a página raiz do TCC já lista como
   correção pendente do artigo.
2. **Não é medida de qualidade do `M_cur` final.** O `M_cur` sai da rodada completa; isto é uma
   amostra de 43 linhas comparáveis dela.
3. **Não é "o filtro tem 64,7% de precisão" como fato.** É uma estimativa com IC [40,0; 86,7].
   Reportar o ponto sem o intervalo, com este n, é escolher o número.
4. **Não é resultado do experimento.** O resultado do TCC é a diferença de F1/recall entre
   `M_raw`, `M_cur` e `M_ctrl` fora da distribuição de treino. A precisão do filtro é a
   **premissa** que torna esse experimento interpretável — se o filtro não elevasse a taxa base,
   o `M_cur` seria só um `M_ctrl` com outro nome.

## ⚠️ Ameaça à validade: o IC não cobre erro de rotulagem

> **Decidir se isto entra no texto do artigo, e onde.** É uma afirmação que enfraquece o próprio
> número por uma margem desconhecida. Pode ser honestidade necessária ou tiro no pé, dependendo
> de como a §4.7 ficar redigida. **Não escrever no automático** — está aqui registrado porque
> é verdade, não porque já foi decidido que vai para o artigo.

O bootstrap reamostra os 33 clusters de commit **com os rótulos que eles já têm**. Ele responde
*"e se eu tivesse sorteado outros commits do BigVul?"*. Ele **não** responde *"e se alguns dos
meus rótulos estiverem errados?"*.

A diferença importa porque as duas fontes de incerteza se comportam de maneira oposta. Erro de
amostragem é aleatório e o bootstrap o captura. Erro de rotulagem é **sistemático**: se um `C`
era na verdade um `D`, as 10.000 reamostragens erram todas na mesma direção, e o intervalo
reporta com toda a confiança um número deslocado.

| fonte de incerteza | está quantificada? |
| --- | --- |
| qual amostra foi sorteada (amostragem) | sim — IC [40,0 ; 86,7] |
| quão bons são os rótulos (rotulagem) | **não**, e não dá neste desenho |

Consequência: **a incerteza real em torno de 64,7% é maior que [40,0 ; 86,7]**, por uma margem
que este trabalho não consegue medir — exigiria um terceiro anotador independente.

O que existe hoje no lugar disso: **89,6% de concordância (43/48)** entre o autor e o segundo
anotador na pergunta binária `D` contra `A/B/C`. É evidência de que os rótulos não são ruído.
**Não é uma barra de erro**, e não pode ser apresentada como se fosse.

Nota de escopo: a página raiz já declara "o modelo como segundo anotador não é ground truth" e
"a anotação humana tem anotador único". Isto aqui é uma terceira coisa, mais específica e ainda
não registrada em nenhum outro lugar: **o intervalo reportado tem um limite que não é óbvio pelo
número.**

## Por que o IC encostar no zero não bloqueia o experimento

A curadoria nunca dependeu de significância neste teste. A regra foi escolhida por
rastreabilidade até a definição da CWE e por tamanho do `M_cur` — dois eixos que não vazam a
resposta — e o dev set existiu para absorver os olhares. Os 50 são um **guarda-corpo de
qualidade**, não a hipótese sendo testada: eles respondem "o filtro está fazendo algo parecido
com o que promete?", e a resposta é sim, em três amostras independentes, na mesma direção e na
mesma ordem de grandeza (+21,1 no dev, +20,5 aqui, +22,5 sob rótulo do modelo).

O poder para a pergunta do TCC vem do treino sobre ~1200–1400 funções curadas, não de 43 linhas.

## Arquivos desta etapa

| arquivo | o que é |
| --- | --- |
| `congelar.py` | congela e confere os 4 arquivos de regra por SHA-256 |
| `CONGELAMENTO.md` / `congelamento.tsv` | os hashes, gravados antes de tocar nos 50 |
| `montar_teste_50.py` | conjunto de teste + mapa caso ↔ item, conferido elemento a elemento |
| `teste_50.tsv` / `mapa_caso_item_50.csv` | os 50 itens e o mapa |
| `saida_50/*.json` | evidência dos 49 (+ `_falhas.tsv`) |
| `saida_50/_etapa5.tsv` | veredito × rótulo humano × rótulo do modelo, por item |
| `etapa_5.py` | a medida; recusa rodar com o congelamento quebrado |

## O que muda a partir daqui

O card dos traversals fecha: existe traversal versionada, regra congelada e precisão medida
contra o único conjunto de teste honesto do trabalho. **Destrava a rodada completa nos 2957
positivos** (montar `M_raw`, `M_cur` e `M_ctrl`), que é o próximo P0.

Duas coisas ficam anotadas para o artigo, além dos números:

- a §4.5 precisa da reescrita já registrada (o `OU` entre camadas é idêntico à camada 1 sozinha);
- a §4.7 precisa separar as duas validações manuais, e agora a primeira delas tem número.

E um item novo para as Ameaças à Validade: **o caso de regressão do artigo está dentro da amostra
dos 50** (1 linha em 43, custo medido: 2,2 pontos de precisão).
