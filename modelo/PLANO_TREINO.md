# Plano de treino do ReVeal — decisões, implementação e pré-registro da checagem de tamanho

> **Rascunho de 08/10/2026, revisado com o autor em 09–10/10.** As §3.3, §4 e §5 foram revisadas
> item a item e fechadas (D7, D9–D12). A §4 (pré-registro) foi **congelada em 10/10** em arquivo
> próprio, `PREREGISTRO_TAMANHO.md`, antes de qualquer treino. O artigo do TCC (`Tex/main.tex`)
> **não foi tocado**.

## 0. Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3, concluída em
06/10), o dataset de grafos (dataset v3, 25.829 grafos, um por função) e o modelo. Este arquivo
é da terceira parte.

**O que ele responde:** como o ReVeal vai ser treinado nos braços (`M_raw`, `M_cur` e os cinco
`M_ctrl_g`, cada um com seus positivos e os mesmos 14.394 negativos de treino), e como o tamanho
das funções vai ser checado **depois** do treino.

**O que ele NÃO é:**
- não é a ficha do ReVeal — essa é `PIPELINE_REVEAL.md`, que compara artigo e código linha a
  linha e de onde vêm as fontes citadas aqui;
- não é resultado: nenhum braço foi treinado;
- não é texto do artigo do TCC.

---

## 1. O que já está decidido

| # | decisão | quando | quem | onde está registrada |
| --- | --- | --- | --- | --- |
| D1 | O tamanho das funções **não bloqueia** o treino: treinar sem esperar | 08/10 | orientador + autor | Pauta, item 2 |
| D2 | A checagem por **faixas de tamanho será feita**, sobre as predições, depois do treino | 08/10 | autor convenceu o orientador | Pauta, item 2 |
| D3 | O ReVeal segue o **artigo** onde a mudança for trivial; onde não for, o código, declarando a diferença | 08/10 | orientador + autor | Pauta, item 6 |
| D4 | Cada braço treina o ReVeal **do zero** (não há modelo pré-treinado no ReVeal) | 07/10 | esclarecimento | Dicionário do TCC, item 6 |
| D5 | **Relatar sempre** a checagem: sem viés, uma frase no texto e a tabela no apêndice; com viés, no corpo e na conclusão | 08/10 | autor (aceitou a proposta) | **falta o orientador** — ele preferia mostrar só se houver viés |
| D6 | **Repetições:** a GGNN treina uma vez por braço; só a Fase II se repete 30 vezes | 08/10 | autor (aceitou a proposta) | este arquivo |
| D7 | **Par balanceado:** `M_cur` balanceado contra **os 5** `M_ctrl_g` balanceados (1:1, os mesmos 523 negativos, semente 5050), no lugar do `M_raw` (detalhes na §5.1). Em 09/10 era contra **um** `M_ctrl`; passou a 5 em 10/10 | 09/10, revisada 10/10 | autor — **não passou pelo orientador**; informar na próxima reunião | Pauta, item 3 |
| D8 | A interseção entre `M_cur` e `M_ctrl` **fica** como está (motivo na §5.2) | 09/10 | autor perguntou; explicação na §5.2 | este arquivo |
| D9 | **Sem corte de tamanho**: nenhuma função sai por ser grande, em nenhuma partição (§3.3 a) | 09/10 | autor | este arquivo |
| D10 | **Vetor de nó = one-hot dos 18 rótulos do Joern + média Word2Vec do código do nó**, como no ReVeal; sem nome da operação, sem tipo de dado (§3.3 b) | 09/10 | autor | este arquivo |
| D11 | **"Iteração" da GGNN = época**: no máximo 500 épocas; validação ao fim de cada época; para se o F1 na validação não melhorar em 50 épocas seguidas (§3.3 c) | 09/10 | autor | este arquivo |
| D12 | **Limiar de decisão = o do ReVeal** (classe mais provável, equivalente a 0,5), igual para todos os braços, sem ajuste na validação — vale para a análise principal **e** para a §4 | 09/10 | autor | este arquivo |

*Não confundir* os números D1–D10 desta tabela com a "decisão 10" do projeto (o tamanho maior das
funções do `M_cur`, `TRAVERSAL_V3.md`), citada na §3.3. A D10 daqui é sobre o vetor de nó.

*Sobre D5 e D6:* registradas a partir do "pode ser assim mesmo" do autor em 08/10, que respondia
às duas propostas. Se a leitura estiver errada, corrigir aqui.

---

## 2. Qual "artigo"

**O artigo do ReVeal é:** Saikat Chakraborty, Rahul Krishna, Yangruibo Ding e Baishakhi Ray,
*"Deep Learning Based Vulnerability Detection: Are We There Yet?"*.

Existem duas versões, e elas não são iguais (detalhe em `PIPELINE_REVEAL.md`, §0):

| versão | onde | o que tem que a outra não tem |
| --- | --- | --- |
| **preprint** — arXiv 2009.07235 v1, 03/09/2020 | arxiv.org/abs/2009.07235 | a **tabela de hiperparâmetros** (Tabela 2) |
| **publicada** — IEEE TSE vol. 48, n. 9, pp. 3280–3296, set. 2022, DOI 10.1109/TSE.2021.3087402 | `Trabalhos Relacionados/toRead/ReVeal.pdf`; é a que o `main.tex` cita | as **estatísticas do dataset** (Tabela 2: máx. 499 nós por função); divisão corrigida para 70/10/20 |

Então "seguir o artigo" quer dizer: **hiperparâmetros do preprint** (é o único lugar onde estão),
**procedimento das duas versões** (iguais na §5.1).

**O Lu & Lagaisse (2025, *From Lab to Reality*) não é "o artigo".** É um trabalho de terceiros que
treinou o ReVeal no BigVul. Entra como precedente — dizem ter usado *"the recommended
hyperparameters from the original papers"* — e como ordem de grandeza para o `M_raw` (F1 23,58 no
BigVul). Na conversa de 08/10 o autor entendia "o artigo" como este; a direção é a mesma, mas
falta confirmar com o orientador (nota no item 6 da Pauta).

---

## 3. Como o ReVeal vai ser implementado

Regra (D3): artigo onde for trivial; código onde não for; toda diferença declarada.

### 3.1 Segue o artigo (mudança trivial)

| o quê | artigo | código oficial |
| --- | --- | --- |
| passos de propagação da GGNN | 8 | 6 |
| qual versão da GGNN guardar | melhor F1 na **validação**, paciência 50 | melhor acurácia em lotes de **treino**, paciência 100 |
| validação da Fase II | o conjunto de validação | 10% sorteados do treino |
| divisão | fixa (no TCC: o split congelado, agrupado por commit↔CVE) | junta tudo e redivide ao acaso a cada repetição — **vaza o teste** |
| Word2Vec | janela 10, 100 números | janela padrão da biblioteca |
| distância da triplet loss | 1 − \|cosseno\| | 1 − cosseno |

No TCC, a validação de tudo é a partição de validação do split (255 positivos, 3674 negativos), e o
Word2Vec é treinado só no código da partição de treino, uma vez, igual para todos os braços.

### 3.2 Fica o código, declarado (não trivial)

| o quê | por quê |
| --- | --- |
| **SMOTE: usado**, na versão do código, que só cria positivos sintéticos | o SMOTE faz parte do ReVeal e fica. O que o artigo deixa vago é só a *variante*: descreve também reduzir negativos, mas não diz quantos (o Algoritmo 3 não dá valor); e a versão publicada diz usar *"off-the-shelf SMOTE"*, que é exatamente a chamada do código (`imblearn`, `random_state=1000`) |
| **tipos de nó**: os 18 rótulos do Joern atual | os 69 tipos do Joern antigo não existem no nosso grafo |
| **biblioteca**: DGL 2.5 | o artigo diz TensorFlow 1.15, mas esse código não foi publicado; a biblioteca não muda o modelo |
| **30 repetições** sem redividir | o split é congelado; ver D6 e §5 |

### 3.3 Decisões do autor (fechadas em 09/10: D9, D10, D11)

**(a) Corte de tamanho.** O código descarta função com 500 nós ou mais, e a Tabela 2 da versão
publicada mostra que o dataset do artigo teve esse corte (máx. 499). Mas lá "nó" é **comando**;
aqui é todo nó da árvore sintática. Opções, com o que cada uma tira de cada braço (dado de treino,
`_tamanho_bracos_v3.py`):

| opção | tira do `M_cur` | tira de cada `M_ctrl_g` | a favor | contra |
| --- | --- | --- | --- | --- |
| **sem corte** | 0 | 0 | o artigo não enuncia a regra; D1 diz que tamanho não bloqueia | não reproduz o recorte do dataset do artigo |
| **corte em linhas, > 915** (a maior função do dataset do ReVeal) | 12 (2,3%) | 2–7 (0,4–1,3%) | traduz o recorte do artigo numa unidade que os dois têm; quase não mexe nos braços | é interpretação: 915 é o máximo deles, não uma regra |
| **corte em 500 dos nossos nós** | 180 (34,4%) | 70–91 (13,4–17,4%) | é o número do código | unidade errada; tira o dobro do `M_cur` — é a decisão 10 entrando pela porta dos fundos |

**Decidido em 09/10 (D9): sem corte.** Motivos: o artigo não enuncia a regra; a diferença prática
para o corte em 915 linhas é de 2 a 12 funções por braço; e qualquer corte abriria uma segunda
decisão (aplicar só no treino, ou também na validação e no teste). Nenhuma função sai por tamanho,
em nenhuma partição.

*O modelo aguenta função grande?* Sim: a GGNN não tem tamanho máximo de entrada — troca mensagens
entre vizinhos, quantos nós houver, e a soma dos nós dá sempre um vetor de 200 números. O 500 do
código é filtro do dado, não limite da arquitetura (o código não diz por que existe). O limite
real é **memória da GPU** (RTX 2050, 4 GB). Tamanho do dataset v3 inteiro, sem olhar rótulo nem
partição (09/10, `dataset_indice_v3.tsv`, n = 25.829): mediana 58 nós, 99% das funções até 1437,
123 com 2000 ou mais, a maior com 11.903 nós; a que tem mais arestas, 82.960. Se um lote com uma
dessas não couber, a saída é no **lote**, não no dado: dividir o lote em pedaços e somar os
gradientes antes de atualizar (acumulação de gradiente). Com a perda somada (`reduction='sum'`) e
sem normalização por lote no `GGNNSum`, isso dá a mesma conta que o lote inteiro. Conferir no teste
de fumaça (§7, passo 3).

*Duas propriedades do modelo que pesam mais nas funções grandes* (iguais em todos os braços; não
são motivo para corte, mas explicam por que a §4 existe): (1) o vetor da função é a **soma** dos
vetores dos nós, então cresce com o número de nós — o tamanho chega pronto à Fase II, e o atalho
"grande = vulnerável" fica fácil de aprender; (2) com 8 passos de propagação, cada nó só recebe
informação de até 8 arestas de distância — numa função de milhares de nós, partes distantes não se
"enxergam".

**(b) Que informação vai em cada nó.** O vetor inicial de cada nó, no ReVeal, é o one-hot do tipo
do nó (um vetor de zeros com um 1 na posição do tipo) mais a média dos vetores Word2Vec dos tokens
do código do nó. A questão era o que usar como "tipo".

*Correção de 09/10.* A versão de 08/10 desta linha dizia que o ReVeal "sabia o tipo da operação
pelo tipo do nó (`AssignmentExpression`, `ArrayIndexing`…)". Muito provavelmente não sabia: a
representação de 169 números **só aceita nós de comando** — `create_ggnn_data.py:302` descarta todo
nó que não é de CFG; a chamada que gera essa representação passa `cfg_only=False`, que, ao contrário
do que o nome sugere, é o caso que filtra (linhas 411-412). `AssignmentExpression` e `ArrayIndexing`
são pedaços **dentro** de um comando, não comandos; os tipos que entravam eram do nível do comando
(`ExpressionStatement`, `Condition`, `IdentifierDeclStatement`, `ReturnStatement`…). A Tabela 2 de
[A2] confirma a granularidade: mediana de 18 nós para mediana de 15 linhas, cerca de um nó por
linha. *Inferência, não conferida no dado deles:* a lista exata de tipos que eram nós de comando no
Joern antigo. Consequência: no ReVeal a operação (`=`, `[`) já chegava **pelo Word2Vec**, diluída na
média dos tokens do comando — não pelo tipo.

Exemplo, `x = buf[i];`: no ReVeal, 1 nó de tipo `ExpressionStatement`, Word2Vec de `x = buf [ i ]`.
No nosso grafo, 5 nós (a atribuição, `x`, a indexação `buf[i]`, `buf`, `i`), de tipo `CALL` ou
`IDENTIFIER`, cada um com o Word2Vec do seu próprio código — o `=` e o `[` entram pelo Word2Vec, como
lá.

Opções que estavam em aberto: (i) os 18 rótulos + Word2Vec do código do nó; (ii) exportar também o
nome da operação (`<operator>.assignment`, `memcpy`), que o `exportar_grafos.sc` hoje não exporta —
informação que o ReVeal **não** tinha no tipo, e que exigiria rodar de novo a exportação a partir dos
18.072 `cpg.bin` salvos (a da v2 foram 1501 execuções de ~6,6 s, umas 2h45) e conferir que saem os
mesmos 25.829 grafos.

**Decidido em 09/10 (D10): opção (i)**, "baseado no ReVeal mesmo". É a tradução direta de "tipo do
nó + tokens do código" e não reabre etapa fechada. O campo `tipo` que já exportamos (tipo de dado,
`int`, `char*`; 78,3% dos nós) **não entra** — o ReVeal não usava. Limitação a declarar: `CALL` é
1,24 mi dos 3,71 mi nós do dataset v3 (33%); para esse terço, quem distingue a operação é só o
Word2Vec. Como vale igual para todos os braços, mexe no nível do F1, não na comparação
`M_cur` × `M_ctrl`.

**(c) "Máximo de 500 iterações" da GGNN** ([A] §5.1): o artigo não diz se iteração é passo ou
época. Texto ([A2] §5.1, p. 3287): *"For the GGNN, maximum iteration number is set to be 500. For
the representation learner maximum iteration is 100. We stop the training procedure if F1-score on
validation set does not increase in for 50 consecutive training iteration for GGNN and 5 for
Representation Learning."* A unidade escolhida vale para o máximo **e** para a paciência.

- *Passo* (um lote de 128): 500 passos são ~4 passadas pelo treino do `M_cur` (14.917 funções,
  ~117 lotes por época); e paciência 50 exigiria validar (3929 funções) depois de cada lote, ou a
  cada k passos, que o artigo não dá.
- *Época* (uma passada pelo treino inteiro): a mesma frase usa a mesma palavra para a Fase II, e
  lá os 100 e os 5 do código são épocas, com validação ao fim de cada uma
  ([R] `representation_learning_api.py:16`, `representation_learning/trainer.py:24,53`,
  `api_test.py:81`). O código da GGNN conta em passos (1.000.000, avaliação a cada 128), mas esses
  números não batem com os 500 do artigo e não ajudam a interpretar.

**Decidido em 09/10 (D11): época** — a leitura coerente com o próprio artigo.

*A conferir no teste de fumaça (não é decisão):* a GGNN treina sem rebalanceamento (o SMOTE é da
Fase II; o carregador do [D] não reequilibra — conferido em `data_loader/dataset.py`, só
`shuffle=True`). No `M_cur` e nos `M_ctrl_g` são 3,5% de positivos (523 de 14.917). Se a GGNN
começar dizendo "não vulnerável" para tudo, o F1 na validação fica em zero, nunca "melhora", e a
paciência encerra o treino na época 50 com um modelo que não aprendeu. Se acontecer, volta ao autor.

### 3.4 O que nós escrevemos (não existe no código oficial)

- ler os grafos do dataset v3 e montar o vetor de cada nó;
- treinar o Word2Vec;
- o passo que entrega o vetor de cada função da GGNN para a Fase II (`--save_after_ggnn` não
  existe);
- caber na memória: vetores pré-calculados em disco (3,7 milhões de nós; 7,8 GB de RAM no WSL);
- gravar a predição de cada função **com o id**, que a §4 precisa.

O que decide o resultado — a GGNN (`GGNNSum`), a rede da Fase II com a triplet loss
(`MetricLearningModel`) e a chamada do SMOTE — vem do código oficial, que tem licença MIT.

---

## 4. Pré-registro da checagem de tamanho — CONGELADO em 10/10/2026

**Mudou de lugar.** O texto aprovado está em **`modelo/PREREGISTRO_TAMANHO.md`**, que não é mais
editado. Foi tirado daqui para que as edições que o resto deste plano ainda vai sofrer não mexam
no que está congelado.

| arquivo | SHA-256 | bytes | congelado em |
| --- | --- | --- | --- |
| `PREREGISTRO_TAMANHO.md` | `57c0a26f79cb6b36248f8852ad8ba327ece0742e47a430aafe08afc28826e8ee` | 8725 | 10/10/2026, antes de qualquer treino de braço |
| `PREREGISTRO_PRINCIPAL.md` | `dbb2269cc6f1f76b176c8cedc426b3a85137b924f06b98c06def91e2209ab86c` | 24706 | 12/10/2026, 13:05, depois do treino dos 13 braços e antes de qualquer métrica no teste |
| `PREREGISTRO_ARENAS.md` | `6284d831d490048ad2da33d34e32fc2f8f4d67185ae20bc7f1cce36949a01838` | 63373 | 15/10/2026, 09:06, depois de abrir o teste do BigVul e antes de qualquer modelo prever qualquer função de arena externa |

Conferir: `sha256sum PREREGISTRO_TAMANHO.md PREREGISTRO_PRINCIPAL.md PREREGISTRO_ARENAS.md` (no
WSL) tem de dar os valores acima. O `PREREGISTRO_ARENAS.md` é o adendo das arenas externas
(PrimeVul, VentiVul v3, sonda CWE-416): quais funções entram, deduplicação, mínimo por arena, regra
de piso, traversal pura, síntese ("acima em todas") e a ordem de preparação e abertura (§10). O `PREREGISTRO_PRINCIPAL.md` fixa a análise principal (`M_cur` contra a faixa dos 5
controles: só o F1 decide; no BigVul, leitura como concordância com o rótulo; nas arenas
externas, decide o F1 lá), a ligação com a checagem de tamanho (o veredito do desenho principal,
por arena, vai lado a lado com o resultado) e a ordem de abertura do teste. O mesmo hash está
nas `Notas` do cartão do Notion, cujo histórico registra a data por fora do repositório.

**Resumo, para quem chega aqui** (o que vale é o arquivo): quatro faixas de tamanho cortadas nos
quartis dos positivos de treino (até 46 | 47–131 | 132–339 | 340 ou mais nós); em cada faixa, F1,
recall (descritivo) e taxa de falso positivo, no limiar do ReVeal (D12); o `M_cur` comparado com a
faixa dos 5 controles, no desenho principal e no par balanceado; "evidência de viés de tamanho" se
a inclinação do falso positivo (grandes menos pequenas) do `M_cur` passar a de todos os controles
(V1), ou se o ganho de F1 aparecer em alguma faixa grande e em nenhuma pequena (V2). Com 5
controles, "acima de todos" sai por acaso 1 vez em 6 — indício, não prova.

---

## 5. Repetições e sementes — aprovado pelo autor em 10/10 ("pode congelar e treinar")

- **GGNN:** uma por braço, semente 1000 (a do código oficial, `[D] main.py:18-19`). São **13
  treinos**: os 7 do desenho principal (`M_raw`, `M_cur`, 5 `M_ctrl_g`) e os 6 do par balanceado
  (`M_cur` e 5 `M_ctrl_g`, balanceados).
- **Fase II:** 30 repetições por braço, sementes 1000 a 1029; reporta mediana e IQR (a faixa onde
  cai a metade central dos resultados), como o artigo. A Fase II é uma rede pequena sobre vetores
  de 200 números: barata.
- **O que isto mede e o que não:** a variação da Fase II e, pelos 5 `M_ctrl_g`, a do sorteio do
  controle. Não mede a variação do treino da GGNN — declarado.

### 5.1 O par balanceado (D7) — fechado em 10/10

- **Proporção 1:1:** 523 positivos e 523 negativos em cada braço do par.
- **Os mesmos 523 negativos em todos os braços do par**, sorteados **uma vez** dos 14.394 negativos
  de treino, com a semente **5050** (não coincide com nenhuma semente já usada no projeto: 42, 7,
  909, 2026–2030, 101, 303, 404, 1000–1029). Assim os braços do par diferem só nos positivos.
- **Controles: os 5** (`M_ctrl_g2026` a `g2030`, com os positivos que já existem em
  `conjuntos_treino_v3/`). Decidido em 10/10 no lugar de um controle só (a versão de 09/10 previa
  só o `g2026`): com um controle, o `M_cur` ficaria acima dele por acaso 1 vez em 2 — cara ou
  coroa, tanto na conclusão do próprio par quanto na checagem de tamanho. Com 5, o par tem a mesma
  régua do desenho principal (1 em 6) e entra no pré-registro (`PREREGISTRO_TAMANHO.md` §0).
- **Consequência que vale saber:** com o treino já em 1:1, o SMOTE não tem o que sintetizar — no
  par, ele fica inativo na prática. É justamente a pergunta de sensibilidade: o padrão do desenho
  principal se mantém sem depender do rebalanceamento?
- **Custo:** 6 treinos de GGNN pequenos (1046 funções cada, contra 14.917 de um braço principal;
  uma época custa algo entre 1/7 e 1/14 de uma época de braço principal, conforme o peso da
  validação, que é a mesma para todos) + 6 × 30 da Fase II. Os 4 controles a mais somam menos que
  um treino de braço principal.

### 5.2 A interseção entre `M_cur` e `M_ctrl` (D8) — por que fica

Cada `M_ctrl_g` é um sorteio de 523 dos 1776 positivos de treino com grafo. Como o `M_cur` é 29,4%
desses positivos (523 de 1776), um sorteio cai **por acaso** em itens do `M_cur` mais ou menos nessa
proporção. Medido em 09/10 (`conjuntos_treino_v3/`): **140 a 152 de 523 (26,8% a 29,1%)** em cada
um dos cinco — o esperado pelo acaso seria uns 154.

**Não é defeito, é o que o controle tem de ser.** O `M_ctrl` responde "o que se teria escolhendo
523 positivos **sem** curadoria?". Sem curadoria, uns 29% dos escolhidos seriam funções que a
traversal confirmaria. Tirar a interseção (sortear o controle só de fora do `M_cur`) mudaria a
pergunta: o controle viraria "as funções que a traversal **rejeitou**", e a comparação passaria a
ser confirmadas contra rejeitadas — um contraste exagerado, que não é o efeito de curar. E pioraria
o tamanho: as funções de fora do `M_cur` são ainda menores.

**O efeito da interseção erra no sentido seguro:** como ~28% do controle já é "curado", os dois
braços ficam mais parecidos, e isso torna **mais difícil**, não mais fácil, encontrar diferença
entre eles. Não pode fabricar um ganho do `M_cur`. Declarar com os números acima.

---

## 6. Ainda em aberto

- §3.3 fechada em 09/10: (a) sem corte (D9), (b) 18 rótulos + Word2Vec (D10), (c) época (D11);
- §4 congelada em 10/10 (`PREREGISTRO_TAMANHO.md`); §5 e §5.1 fechadas em 10/10 (D7 com 5
  controles);
- **opção futura, não adotada (autor, 09/10, por prazo):** aumentar os controles para 19, o que
  baixaria o "acima de todos por acaso" de 1 em 6 para 1 em 20 (5%, o nível usual) — teste de
  Monte Carlo por posto. Custo: 14 sorteios, 14 GGNN e 14 × 30 Fases II. Mexe no desenho principal,
  não só na §4;
- **vale para a análise principal também:** o `main.tex` (cenário esperado, linha 767) compara o
  `M_cur` com "a faixa ocupada pelos cinco controles" — a mesma régua de 1 em 6
  (`PREREGISTRO_TAMANHO.md` §5). Quando o texto for mexido, a limitação tem de entrar lá, e a
  linguagem tem de ser a de indício, não de prova;
- D5 — falta o orientador concordar com relatar sempre;
- confirmar com o orientador que "o artigo" é o do ReVeal (Pauta, item 6);
- informar o orientador da troca do `M_raw` pelos `M_ctrl` balanceados no par (D7, agora com 5);
- item 4 da Pauta (o que se decidiu em 09/09) — não discutido. O item 1 foi aceito pelo orientador
  em 08/10.

## 7. Próximo passo

1. ~~O autor revisa a §3.3 e a §4.~~ Feito em 09–10/10.
2. ~~A §4 é congelada.~~ Feito em 10/10 (`PREREGISTRO_TAMANHO.md`, hash na §4).
3. ~~Implementar conforme a §3 e rodar o teste de fumaça numa amostra do treino, sem braço.~~
   Feito em 10/10 — `IMPLEMENTACAO.md` (scripts, diferenças declaradas, vetorização, teste de
   fumaça e tempo projetado).
4. ~~Treinar os 13 braços (§5).~~ **Terminado em 12/10, 09:35** — `IMPLEMENTACAO.md` §6 (épocas
   de cada GGNN, conferência das saídas, interrupções). Nenhuma GGNN terminou sem melhora.
5. Depois dos 13: abrir resultados (análise principal + `PREREGISTRO_TAMANHO.md`), num passo
   próprio. **Em 12/10 a análise principal foi pré-registrada e congelada**
   (`PREREGISTRO_PRINCIPAL.md`, hash na §4). A abertura segue a ordem do §6 de lá: refazer a Fase
   II salvando os modelos → traversal nos negativos do teste → script de análise → ensaio na
   validação → teste, uma vez.
