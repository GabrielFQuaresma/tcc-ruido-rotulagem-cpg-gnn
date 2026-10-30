# Pré-registro da checagem de tamanho

> **Congelado em 10/10/2026, antes de qualquer treino de braço.** Aprovado pelo autor item a item
> em 09–10/10/2026 (revisão do `PLANO_TREINO.md` §4). Este arquivo **não é editado** depois do
> congelamento: o SHA-256 dele está em `PLANO_TREINO.md` §4 e nas `Notas` do cartão do Notion
> (que guarda o histórico com data). Se algo precisar mudar, o caminho honesto é um arquivo novo,
> com hash novo, registrando o que mudou e por quê. O que não é defensável é mudar e não contar.

## Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3), o dataset de
grafos (dataset v3, 25.829 grafos, um por função) e o modelo (ReVeal). Este arquivo é da terceira
parte e foi escrito **antes** de qualquer modelo ser treinado.

**O que ele responde.** O `M_cur` (os 523 positivos de treino que a traversal confirmou) tem
funções maiores que os `M_ctrl_g` (cada um, 523 positivos sorteados sem curadoria, semente g):
mediana de 323 nós contra 116–136 (n = 523 em cada braço, treino; `traversal/TRAVERSAL_V3.md`
§10). Um modelo treinado no `M_cur` pode aprender o atalho "função grande = vulnerável". Esta
checagem diz, depois do treino, se o ganho do `M_cur` (se houver) sobrevive quando se comparam
funções de tamanho parecido. Fixar a forma dela **antes** de ver resultado é o que impede de
escolher, depois, a forma que favorece o resultado — a mesma lógica do congelamento da regra antes
dos 50 casos.

**O que ele NÃO é.**
- não é a análise principal (`M_cur` contra os controles no teste inteiro); é um recorte
  complementar dela, a mesma comparação repetida dentro de faixas de tamanho;
- não é resultado: quando foi congelado, nenhum braço tinha sido treinado e nenhuma predição
  existia;
- não inclui classificador "só de tamanho" — proposto no rascunho de 08/10 e retirado pelo autor
  (a checagem combinada com o orientador é a análise por faixas).

## 0. Escopo

A checagem, com veredito (V1 e V2), vale para os dois desenhos que têm **cinco controles**:
- **desenho principal:** `M_cur` contra os 5 `M_ctrl_g` (g = 2026 a 2030), cada um com os 14.394
  negativos de treino;
- **par balanceado:** `M_cur` balanceado contra os 5 `M_ctrl_g` balanceados, todos com os mesmos
  523 negativos (sorteados uma vez, semente 5050) — `PLANO_TREINO.md` §5.1, D7.

O `M_raw` (todos os 1776 positivos de treino) aparece nas tabelas por faixa como referência, mas
não entra no veredito. Arenas: toda arena que tiver a contagem exigida na 3 (abaixo).

## 1. Tamanho

Número de nós do grafo da função: coluna `n_nos` de `traversal/dataset_indice_v3.tsv`.

## 2. Faixas

Quatro, cortadas nos quartis do tamanho dos 1776 positivos de treino com grafo (o `M_raw`):

**até 46 nós | 47 a 131 | 132 a 339 | 340 ou mais**

Quartis por interpolação linear, **arredondados para cima**; o valor do quartil fica na faixa de
baixo. Conferido em 09/10 no `dataset_indice_v3.tsv` (rótulo 1, partição treino, n = 1776):
quartis 45,75 / 130,5 / 338,25; positivos de treino por faixa 452 / 439 / 442 / 443.

*Por que estes cortes:* vêm do treino, não do teste; são neutros entre braços (o `M_raw` contém os
positivos de todos — cortar nos quartis do `M_cur` puxaria as faixas para o lado dele); e
acompanham o tamanho dos positivos, para cada faixa do teste ter positivos. *Contra, declarado:* os
negativos são menores (mediana de 58 nós no dataset inteiro), então a faixa de 340 ou mais tem
relativamente poucos negativos — daí o mínimo de negativos na 3.

## 3. Quando uma faixa entra

Uma faixa de uma arena entra com métrica se tiver **pelo menos 30 positivos** (para F1 e recall) e
**pelo menos 30 negativos** (para a taxa de falso positivo); abaixo disso, aquela métrica aparece
só com a contagem. O 30 é **convenção** (o mínimo usual para uma proporção não ser dominada por um
ou dois casos), não valor derivado. Contar quantas funções caem em cada faixa não é ver resultado.

## 4. Métricas, em cada faixa

- **F1** e **recall** (as métricas primárias do TCC);
- **taxa de falso positivo**: das funções não vulneráveis da faixa, quantas o modelo acusou.

**Limiar de decisão: o do ReVeal** — a classe mais provável das duas que a Fase II devolve,
equivalente a 0,5 (código oficial: `models.py:34`, `LogSoftmax` de duas classes; `trainer.py:104`,
`argmax`). O mesmo para todos os braços, sem ajuste na validação (`PLANO_TREINO.md`, D12; vale
também para a análise principal).

O **recall por faixa é descritivo**: aparece na tabela, não entra em V1 nem em V2.

## 5. Comparação

Para cada braço e cada faixa: em cada uma das 30 repetições da Fase II calcula-se a métrica
naquela faixa; o valor do braço na faixa é a **mediana dessas 30**. O `M_cur` é comparado com a
**faixa dos controles** do seu desenho — do menor ao maior valor entre as medianas dos 5
`M_ctrl_g`. Se o desenho passar a ter mais controles **antes de qualquer resultado**, a régua
acompanha.

**O que a régua permite dizer.** Se a curadoria não fizesse diferença nenhuma, o `M_cur` seria,
para efeito de resultado, um sexto controle; entre seis valores trocáveis, cada um tem a mesma
chance de ser o maior. Então ficar **acima do maior dos 5** aconteceria **por acaso 1 vez em 6**
(~17%), e ficar **fora da faixa**, nos dois sentidos, 1 vez em 3. As 30 repetições estabilizam o
valor de cada braço (o ruído da Fase II), mas **não aumentam o número de controles**, que é o que
dá a largura da régua (a variação de quais 523 positivos foram sorteados). Para o texto:
- **pode:** "o `M_cur` ficou acima dos cinco controles — o que, sem efeito nenhum, aconteceria
  1 vez em 6";
- **não pode:** "a curadoria melhorou significativamente", "prova", ou qualquer linguagem de teste
  estatístico.

## 6. O que conta como viés de tamanho

- **V1, o atalho.** A **inclinação** do `M_cur` fica **acima da maior inclinação** entre os 5
  controles. Inclinação = taxa de falso positivo na faixa de 340 nós ou mais **menos** a da faixa
  de até 46: quanto o modelo acusa a mais as funções grandes do que as pequenas. Calculada em cada
  uma das 30 repetições; o valor do braço é a mediana das 30. Os negativos do teste são os mesmos
  para todos os braços, então acusar mais os negativos grandes só pode vir do que o modelo
  aprendeu. Se uma das duas faixas não tiver 30 negativos numa arena (3), o V1 não se aplica nela.
- **V2, ganho só nas grandes.** O F1 do `M_cur` fica acima da faixa dos controles em **pelo menos
  uma** das faixas grandes (132–339 ou 340 ou mais) e em **nenhuma** das pequenas (até 46 e
  47–131). Só contam as faixas com 30 positivos naquela arena (3).

**Veredito.** Nenhum dos dois → "sem evidência de viés de tamanho": uma frase no texto e a tabela
no apêndice. V1 ou V2 → "evidência de viés de tamanho": no corpo do texto e na conclusão
(`PLANO_TREINO.md`, D5 — falta o orientador concordar com relatar sempre).

*Os critérios foram desenhados para errar no sentido de acusar viés, que enfraquece a conclusão a
favor do `M_cur`, nunca no de escondê-lo.*

*Limitação declarada:* com 5 controles, cada comparação "acima do maior" sai por acaso 1 vez em 6
(5).

## 7. O que esta checagem NÃO cobre

Função maior também dá à GGNN mais estrutura para aprender. Isso não é atalho: é parte do que a
curadoria escolhe. A checagem separa "aprendeu o atalho do tamanho" de "aprendeu outra coisa"; não
separa "rótulo mais limpo" de "função mais rica". Na forma como o TCC está escrito ("limpar os
rótulos *utilizando traversals*"), o tratamento é a curadoria inteira, e a riqueza é parte dele.

## Histórico antes do congelamento (09–10/10/2026, sem nenhum resultado existente)

Mudanças em relação ao rascunho de 08/10, todas feitas na revisão com o autor:
- **Limiar:** o rascunho dizia "o mesmo da análise principal", que não estava definido em lugar
  nenhum; fixado como o do ReVeal (4).
- **Régua:** o rascunho dizia que a mediana de 30 repetições compensava a régua de 5 controles;
  não compensa — corrigido e explicado (5).
- **V1:** olhava só a faixa de 340 ou mais e não separava "acusa mais as grandes" de "acusa mais
  tudo"; passou a ser a inclinação (6).
- **V2:** exigia as duas faixas grandes, de modo que "acima só na maior" caía em "sem evidência";
  passou a "pelo menos uma grande e nenhuma pequena" (6).
- **Mínimo de negativos** acrescentado na 3; **regra de arredondamento** escrita na 2.
- **Classificador só de tamanho** retirado.
- **Par balanceado** passou de 1 para 5 controles (D7), o que permite aplicar a régua a ele (0).
