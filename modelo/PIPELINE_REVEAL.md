# Ficha do ReVeal: o que o código oficial e o artigo dizem

Registro de **06/10/2026**. Cartão do Notion: "Definir e reproduzir o pipeline de treino do ReVeal".

## 0. Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3, concluída em
06/10), o dataset de grafos (dataset v3, 25.829 grafos, um por função) e o modelo. Este arquivo é
o primeiro passo da terceira parte.

**O que este arquivo responde:** *o que exatamente é o ReVeal*, segundo as fontes primárias —
para que os braços (`M_raw`, `M_cur`, os `M_ctrl`) sejam treinados com arquitetura e
hiperparâmetros fixados **antes**, e não ajustados no nosso dado.

**O que este arquivo NÃO é:**
- não é a decisão de como implementar (rodar o código original ou portá-lo — item 3 da conversa de
  06/10, **em aberto**, decisão do autor);
- não é resultado de nada: nenhum modelo foi treinado, nenhum grafo do dataset foi vetorizado;
- os números publicados do ReVeal (§6) **não são alvo**: foram medidos em outros datasets
  (Chromium+Debian e FFmpeg+Qemu), contra os rótulos daqueles datasets.

**Fontes, todas lidas em 06/10/2026:**

| sigla | fonte | onde está |
| --- | --- | --- |
| **[R]** | repositório oficial `github.com/VulDetProject/ReVeal`, commit `ca31b78` (12/05/2021) | `~/reveal_oficial` no WSL |
| **[D]** | repositório `github.com/saikat107/Devign`, commit `be2f831` (31/01/2021) — o GGNN que o README do ReVeal manda clonar | `~/devign_saikat` no WSL |
| **[A]** | artigo, **preprint** arXiv 2009.07235 **v1** (03/09/2020, a única versão no arXiv; cabeçalho "IEEE Transactions on Software Engineering, vol. TBD, 2020"), lidas as páginas 5–14 | — |
| **[A2]** | artigo, **versão publicada**: IEEE TSE, vol. 48, n. 9, pp. 3280–3296, set. 2022, DOI 10.1109/TSE.2021.3087402 — é a que o `main.tex` cita (`chakraborty:2022`); lida inteira (17 páginas) em 08/10/2026 | `Trabalhos Relacionados/toRead/ReVeal.pdf` |

Citações de código vêm como `[R] arquivo:linha`; do artigo, como `[A] §seção` ou `[A] Tabela n`.

**As duas versões do artigo diferem, e isso importa (conferido em 08/10/2026):**

| | preprint [A] | publicada [A2] |
| --- | --- | --- |
| Tabela 2 | **hiperparâmetros** (Word2Vec, GGNN, modelo de representação) | **estatísticas do dataset** do ReVeal — "# of nodes": mín. 2, mediana 18, **máx. 499**; "# of lines of code": mediana 15, máx. 915 |
| tabela de hiperparâmetros | existe (Tabela 2) | **não existe** em nenhuma das 17 páginas |
| divisão (§5.3) | "80%, 10%, and 20%" (soma 110%) | **70, 10 e 20** |
| §5.1 (TensorFlow 1.15 para a GGNN; 500 / 100 iterações; paciência 50 / 5) | igual | igual |
| números do ReVeal (F1 41,25 e 64,42) | Tabela 5 | iguais (§6.3) |

Consequência: **os hiperparâmetros só podem ser citados do preprint** [A]. E o máximo de 499 nós da
Tabela 2 de [A2] mostra que o corte de 500 do código foi aplicado no dataset do artigo (ver §2.2).

---

## 1. O ReVeal em uma página

Duas fases ([A] §4, Figura 6):

**Fase I — de código a vetor.**
1. Gera-se o CPG da função (o grafo do Joern que junta árvore sintática, fluxo de controle e
   fluxo de dados).
2. Cada nó vira um vetor: **one-hot do tipo do nó** (um vetor de zeros com um 1 na posição do
   tipo) concatenado com a **média dos vetores Word2Vec dos tokens do código do nó** (Word2Vec é
   um modelo que aprende um vetor por palavra a partir do contexto em que ela aparece).
3. Uma **GGNN** (Gated Graph Neural Network) atualiza o vetor de cada nó trocando mensagens com
   os vizinhos por alguns passos, com uma GRU (célula recorrente com "portões").
4. Os vetores dos nós são **somados**: isso é o vetor da função inteira, `x_g`.
5. A GGNN é **treinada primeiro, no próprio dado**, com uma camada de classificação provisória em
   cima, como no Devign; depois a camada é descartada e a GGNN só produz os vetores. O artigo chama
   isso de *pre-train* ([A] §4.1, p. 6), mas **não é modelo pré-treinado baixado de fora**: o
   ReVeal treina do zero em cada dataset. *(Esclarecido em 07/10: a palavra "pré-treinada" nesta
   ficha levou o autor a entender que o ReVeal exigia modelo pronto.)*

**Fase II — treino sobre os vetores de função.**
6. **SMOTE** rebalanceia as classes no espaço dos vetores de função, criando positivos sintéticos
   por interpolação entre positivos vizinhos ([A] §4.2.1).
7. Uma **MLP** (rede de camadas densas) projeta `x_g` num espaço latente, treinada com uma perda
   que soma classificação + **triplet loss** (aproxima exemplos da mesma classe, afasta os de
   classe diferente) + regularização ([A] §4.2.2).

---

## 2. Ficha de hiperparâmetros: artigo × código

Legenda da última coluna: **=** artigo e código batem; **≠** divergem; **?** não dá para conferir.

### 2.1 Vetor inicial dos nós e Word2Vec

| parâmetro | artigo | código | |
| --- | --- | --- | --- |
| dimensão do vetor de nó | 169 ([A] Tabela 2) | 69 tipos (one-hot) + 100 (Word2Vec) = 169 ([R] `data_processing/create_ggnn_data.py:225-242, 321-322`) | = |
| tipos de nó | "vertex type", ex. `ArithmeticExpression` ([A] §4.1) | 69 tipos do **Joern antigo** (fuzzyc), lista fixa (`create_ggnn_data.py:225-241`) | = |
| tokenização do código do nó | não diz | `nltk.word_tokenize`; token fora do vocabulário vira vetor zero; média simples (`create_ggnn_data.py:309-320`) | ? |
| Word2Vec: dimensão | 100 ([A] Tabela 2) | o modelo carregado é `raw_code_deb_chro.100` (`create_ggnn_data.py:386`); o script de treino tem padrão 300 (`Vuld_SySe/word2vec_train.py:32`) | = (pelo nome do arquivo) |
| Word2Vec: janela | 10 ([A] Tabela 2) | o script **não passa** `window`, logo vale o padrão do gensim 3.8 (`word2vec_train.py:15`) | ≠ ou ? — o modelo treinado não está no repositório |
| Word2Vec: corpus | não diz | padrão do script: `code_train.json` **e** `code_test.json` (`word2vec_train.py:27`) | ? |

### 2.2 Grafo de entrada

| parâmetro | artigo | código | |
| --- | --- | --- | --- |
| quais nós entram | todos os vértices do CPG ([A] Algoritmo 2) | **só nós de CFG** (comandos); nós de expressão ficam de fora (`create_ggnn_data.py:301-303`) | ≠ |
| nós sem aresta | — | descartados (`create_ggnn_data.py:344-346`) | ? |
| tipos de aresta | não lista | 12 do Joern antigo: `IS_AST_PARENT`, `FLOWS_TO`, `REACHES`, `CONTROLS`, `DOM`, `POST_DOM`, `DEF`, `USE`, `DECLARES`, `IS_CLASS_OF`, `IS_FUNCTION_OF_AST/CFG` (`create_ggnn_data.py:244-257`) | ? |
| **filtro de tamanho** | não é enunciado como regra, **mas a Tabela 2 da versão publicada [A2] dá máximo de 499 nós** no dataset do ReVeal — o corte foi aplicado (corrigido em 08/10; antes esta linha dizia "não encontrei menção", lendo só o preprint) | **função com 500 nós ou mais é descartada** (`create_ggnn_data.py:326-327`; a contagem é só dos nós que sobraram depois da linha 302, ou seja, só comandos) | = no dado, ≠ no texto |

**Existe uma segunda representação no repositório**, incompatível com a primeira: grafo **por
linha** de código, vetor de 100 dimensões (só Word2Vec, sem tipo), 4 tipos de aresta (dependência
de controle e de dados, cada uma nos dois sentidos), sem filtro de tamanho
([R] `data_processing/full_data_prep_script.ipynb`, célula 13; `chrome_deb_line_level_graph_for_ggnn.ipynb`,
célula 7). O padrão do GGNN público é 100 dimensões ([D] `main.py:29`), o que casa com esta; a
Tabela 2 do artigo diz 169, o que casa com a primeira. **O repositório não registra qual das duas
gerou os números publicados.** A de 169 é a que bate com o artigo.

### 2.3 GGNN (Fase I)

| parâmetro | artigo | código | |
| --- | --- | --- | --- |
| implementação | "**For GGNN, we use tensorflow 1.15**" ([A] §5.1) | PyTorch + DGL ([D] `modules/model.py:2`) | ≠ — o código público **não é** o que o artigo diz ter usado |
| modelo | GGNN + soma dos nós ([A] §4.1) | `GGNNSum`: `GatedGraphConv` → soma → `Linear(200→1)` → sigmoide ([D] `modules/model.py:64-82`); o padrão do script é **outro modelo**, `devign` ([D] `main.py:21-22`) | = (se escolher `--model_type ggnn`) |
| dimensão oculta | 200 ([A] Tabela 2) | 200 ([D] `main.py:30`) | = |
| passos de propagação | 8 ("Number of Graph layers", [A] Tabela 2) | **6** ([D] `main.py:31`; a classe tem padrão 8, mas o script passa 6) | ≠ |
| função de ativação | tanh ([A] Tabela 2) | nenhuma explícita; a GRU do `GatedGraphConv` usa tanh por dentro | ? |
| otimizador | não diz (só a taxa) | Adam, `lr=0.0001`, `weight_decay=0.001` ([D] `main.py:72`) | = na taxa |
| perda | — | `BCELoss(reduction='sum')` ([D] `main.py:71`) | ? |
| lote | não diz | 128 ([D] `main.py:32`) | ? |
| máximo de iterações | 500 ([A] §5.1) | 1.000.000 passos, avaliação a cada 128 ([D] `main.py:73`) | ≠ |
| parada antecipada | "F1 na **validação** não sobe por 50 iterações" ([A] §5.1) | avalia em lotes **de treino**, pelo critério **acurácia**, paciência 100 ([D] `trainer.py:84-100`; `evaluate_loss` devolve acurácia, `trainer.py:33`) | ≠ (**grave**, ver §4) |
| semente | — | `torch` e `numpy` = 1000 ([D] `main.py:18-19`) | ? |
| saída para a Fase II | — | o README manda usar `--save_after_ggnn` ([R] `README.md`, "Running GGNN", passo 3); **essa opção não existe** em nenhum commit do [D] (`git log --all -p`, 0 ocorrências) | **ausente** |

### 2.4 SMOTE e modelo de representação (Fase II)

| parâmetro | artigo | código | |
| --- | --- | --- | --- |
| SMOTE | **reduz** a classe majoritária **e** sintetiza a minoritária até empatar ([A] §4.2.1, Algoritmo 3) | `SMOTE(random_state=1000).fit_resample` do imbalanced-learn, que **só sintetiza** a minoritária; vizinhos = padrão da biblioteca ([R] `Vuld_SySe/representation_learning/graph_dataset.py:53-54`) | ≠ |
| camadas | 3, tamanhos 256, 128, 256, ReLU ([A] Tabela 2) | `entrada→256`, depois `256→128→256`, ReLU e dropout entre elas ([R] `models.py:18-30`, `num_layers=1`) | = |
| dropout | 0,2 | 0,2 ([R] `representation_learning_api.py:15`) | = |
| perda | `L = L_CE + α·L_p + β·L_reg` ([A] eq. 2) | igual ([R] `models.py:64-77`) | = |
| `L_p` (triplet) | `|D(a,p) − D(a,n) + γ|` — **valor absoluto**, não o `max(0, ·)` usual ([A] eq. 4) | `torch.abs(...)` ([R] `models.py:73`) | = |
| distância `D` | `1 − |cosseno|` ([A] eq. 5) | `1 − cosseno`, sem o módulo ([R] `models.py:71-72`) | ≠ (pequeno) |
| γ (margem) / α / β | 0,5 / 0,5 / 0,001 ([A] Tabela 2) | `alpha=0.5`, `lambda1=0.5`, `lambda2=0.001` ([R] `api_test.py:16-17`; os nomes trocam: o γ do artigo é o `alpha` do código) | = |
| otimizador | Adam, `lr=0.001` ([A] Tabela 2) | `Adam(params)` com padrão 0,001 ([R] `representation_learning_api.py:46`) | = |
| lote | não diz | 128 ([R] `api_test.py:81`; o padrão da classe é 64) | ? |
| épocas / paciência | 100 / 5 ([A] §5.1) | 100 / 5 ([R] `representation_learning_api.py:16`; `api_test.py:81`) | = |
| validação interna | — | 10% sorteados do treino, sem semente fixa ([R] `representation_learning_api.py:50-54`) | ? |
| exemplos do triplet | da mesma classe / da outra ([A] Algoritmo 4) | sorteio aleatório no treino ([R] `graph_dataset.py:178-200`) | = |

### 2.5 Avaliação

| ponto | artigo | código | |
| --- | --- | --- | --- |
| repetições | 30, reporta mediana e IQR (intervalo interquartil, a distância entre o 1º e o 3º quartil) ([A] §5.3) | 30 ([R] `api_test.py:74`) | = |
| divisão | "80%, 10%, and 20%" no preprint ([A] §5.3, soma 110%); **70/10/20** na versão publicada ([A2] §5.3) | junta treino+validação+teste do GGNN num conjunto só e redivide 80/20 a cada repetição ([R] `api_test.py:62-75`) | ≠ (**grave**, ver §4) |
| semente | — | `numpy.random.rand(1000)`, que **gera** números em vez de fixar a semente ([R] `api_test.py:22`) | defeito |

### 2.6 Ambiente oficial

Python 3.6 ([D] `README.md`), PyTorch 1.4.0 com CUDA 10.1 ([A] §5.1; [R] `Vuld_SySe/requirements.txt`),
gensim 3.8.0, numpy 1.16.3, DGL sem versão fixada, TensorFlow 1.15 para o GGNN ([A] §5.1). GPU do
artigo: GTX 1080 Ti.

*Inferência, **não verificada**:* os binários do PyTorch 1.4 com CUDA 10.1 não trazem código para
GPUs da arquitetura Ampere (a RTX 2050 daqui é Ampere, *compute capability* 8.6, medida em 15/08).
Rodar o ambiente oficial nesta máquina provavelmente seria só em CPU.

---

## 3. O nosso dataset, comparado

Contagem estrutural do dataset v3 inteiro (06/10/2026, `modelo/_vocabulario_v3.py`):
**25.829 grafos, 3.710.493 nós** — os mesmos totais do `_conferir_dataset.py` (`TRAVERSAL_V3.md`
§10, Fase 5). Não lê rótulo, partição nem braço.

| | ReVeal (Joern antigo) | dataset v3 (Joern atual) |
| --- | --- | --- |
| tipos de nó | 69 | **18** (`CALL` 1,24 mi, `IDENTIFIER` 1,04 mi, `LITERAL` 287 mil, …) |
| quais nós | só comandos (nós de CFG) | **todo nó da árvore sintática** da função (decidido em 16/08, `RECORTE_SUBGRAFO.md`) |
| tipos de aresta | 12 | **18** (`REACHING_DEF` 9,1 mi, `AST` 3,7 mi, `CONTAINS`, `CFG`, `DOMINATE`, `POST_DOMINATE`, `CDG`, `ARGUMENT`, `REF`, …) |
| tipo de dado do nó | não usado | `tipo` preenchido em 2.906.024 nós (78,3%) |

Três consequências, nenhuma decidida aqui:

1. **O one-hot de 69 tipos não pode ser reproduzido como está.** O Joern antigo distingue
   operações no próprio tipo do nó (`AssignmentExpression`, `ArrayIndexing`, `CallExpression`…).
   No Joern atual elas são todas `CALL`, e a operação fica no nome do método chamado
   (`<operator>.assignment`, `<operator>.indirectIndexAccess`) — **campo que o
   `exportar_grafos.sc` hoje não exporta**. ~~Os 18 rótulos sozinhos carregam bem menos informação
   que os 69 tipos.~~ *Correção de 09/10:* essa última frase supunha que os tipos de operação
   chegavam ao modelo. Na representação de 169 números só entram nós de comando
   (`create_ggnn_data.py:302`; chamada com `cfg_only=False`, linhas 411-412, que é o caso que
   filtra), então os tipos usados na prática eram do nível do comando (`ExpressionStatement`,
   `Condition`…), e a operação chegava pelo Word2Vec dos tokens. A Tabela 2 de [A2] confirma a
   granularidade (mediana de 18 nós para 15 linhas). Decisão tomada a partir disso: `PLANO_TREINO.md`
   §3.3 (b), D10 — 18 rótulos + Word2Vec, sem o nome da operação.
2. **Os nossos grafos são de outra granularidade.** Nó de expressão, identificador e literal
   entram; no ReVeal (versão de 169 dimensões), só comandos. O mesmo número de nós não quer dizer
   o mesmo tamanho de função.
3. **O filtro de 500 nós cruza com a decisão 10.** O `M_cur` tem mediana de 323 nós contra 116–136
   nos `M_ctrl_g` (n=523 em cada braço, treino; `TRAVERSAL_V3.md` §10). Um corte por número de nós
   tiraria do `M_cur` uma fração bem maior que dos controles. Aplicar ou não esse filtro **não é
   escolha técnica de implementação: é a decisão 10 entrando por outro caminho**, e espera a
   reunião com o orientador. Pela descrição do dado de treino (`modelo/_tamanho_bracos_v3.py`,
   07–08/10): **500 nós ou mais = 180 funções do `M_cur` (34,4%)** contra **70–91 em cada
   `M_ctrl_g` (13,4–17,4%)**. Mas 500 nós nossos não são 500 nós do ReVeal (lá a unidade é
   comando). Na unidade que os dois têm, linhas, a maior função do dataset do ReVeal tem 915
   ([A2] Tabela 2): passar de 915 linhas atinge **12 do `M_cur` (2,3%)** e **2–7 por `M_ctrl_g`
   (0,4–1,3%)**. *Correção de 07/10:* na versão de 06/10 este parágrafo
   dizia que essa contagem "não deve ser feita antes da decisão". Era restrição demais: o que a
   decisão 10 proíbe antes de ser tomada é olhar **resultado de modelo**; descrever o dado de
   treino é o que as medianas sempre fizeram.

---

## 4. Os dois defeitos que importam

Lidos no código, não deduzidos.

**4.1 A GGNN escolhe o melhor modelo olhando o treino.** Em [D] `trainer.py:85-86`, a avaliação
periódica usa `dataset.get_next_train_batch` — lotes **de treino** —, e o critério é acurácia
(apesar de a variável se chamar `valid_f1`). O "Test Accuracy" impresso no fim também sai de
lotes de treino (`trainer.py:110-112`). O artigo diz outra coisa: F1 na **validação** ([A] §5.1).
Copiar o código ao pé da letra seria escolher o modelo pelo quanto ele decorou o treino.

**4.2 A Fase II redivide os dados ao acaso, e o teste dela vaza.** [R] `api_test.py` junta os
vetores de treino, validação e teste produzidos pela GGNN, e a cada uma das 30 repetições sorteia
80/20 de novo. A GGNN foi treinada na parte `train` original. Então funções que a GGNN **viu com
rótulo** durante o treino caem no teste da Fase II. No TCC isso destruiria duas coisas: o split
agrupado por commit↔CVE (`SPLIT.md`), que existe justamente para impedir vazamento, e a
partição de teste como medida honesta.

Os dois defeitos são do código público. **Não dá para saber, só pelo repositório, se foi com
eles que os números da §6 foram produzidos** — o próprio artigo diz que o GGNN foi feito em
TensorFlow 1.15, e esse código não está publicado.

---

## 5. O que não está no repositório

- O passo que transforma a saída da GGNN nos vetores que a Fase II lê (`--save_after_ggnn`).
- O GGNN em TensorFlow 1.15 que o artigo diz ter usado.
- Os modelos Word2Vec treinados (são baixados de um Google Drive por `data/get_data.sh` e
  `models/get_models.sh`; não baixados nem conferidos).
- Qual das duas representações de grafo (§2.2) gerou os números publicados.
- `Vuld_SySe/graph_network/` traz um terceiro GGNN, que não roda como está (`ggnn_dataset.py`
  usa `copy` sem importar e uma classe `GG` que não existe) e que nenhum script chama.

O próprio README do [D] avisa, sobre o Devign: "*We could NOT recreate the result in the original
paper though.*"

---

## 6. Números publicados do ReVeal (referência, não alvo)

[A] Tabela 5, "ReVeal with GGNN", mediana (IQR) de 30 execuções:

| dataset | n funções | % vulneráveis | acurácia | precisão | recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| Chromium+Debian ("ReVeal dataset") | 18.169 | 9,16% | 84,37 (1,73) | 30,91 (2,76) | 60,91 (7,89) | **41,25 (2,28)** |
| FFmpeg+Qemu | 22.361 | 45,02% | 62,51 (0,90) | 56,85 (1,54) | 74,61 (4,31) | **64,42 (1,33)** |

n e % vulneráveis: [A] Tabela 1. **Não são comparáveis com nada do TCC:** outros dados, outros
rótulos, e a divisão é a do §4.2.

### 6.1 O ReVeal treinado no BigVul, por terceiros — Lu & Lagaisse (2025)

Fonte: `Trabalhos Relacionados/readen/LabToReality.pdf` (arXiv 2512.10485v1), lido em 06/10/2026.
É o `lu:2025` do `main.tex`, que o TCC usa como motivação central e de onde vêm o VentiVul e as
arenas.

O que eles dizem ter feito (§3.2, RQ2): *"training two representative models, LineVul and ReVeal,
from scratch [...] using the recommended hyperparameters from the original papers"*; *"strict
train–test splits and filtered out duplicate functions"*; *"we fixed the test sets across all
datasets"*. Ou seja: hiperparâmetros **do artigo**, divisão própria e estrita — não a redivisão
do `api_test.py` (§4.2). O código deles está em
`github.com/Chaomeng-Lu/A-Practical-Evaluation-of-Deep-Learning-Models-and-LLMs-for-Vulnerability-Detection`
(**não lido**).

ReVeal treinado no BigVul, testado em cada arena (Tabela 4 e Tabela 6, *whole-file*):

| testado em | acurácia | precisão | recall | F1 |
| --- | --- | --- | --- | --- |
| BigVul (mesma base) | 87,45 | 17,87 | 34,67 | **23,58** |
| ICVul | 58,89 | 33,33 | 0,41 | **0,81** |
| VentiVul (*whole-file*) | 89,06 | 1,49 | 4 | **2,17** |

**Por que isto também não é alvo:** eles usaram o BigVul inteiro (todas as CWEs) e a divisão
deles; o TCC usa o recorte de erros de memória (CWE-119/120/125/787) e o split agrupado por
commit↔CVE. Serve como **ordem de grandeza para o `M_raw`** na avaliação final — se o nosso
`M_raw` der F1 de 90 ou de 0 no teste do BigVul, algo está quebrado no pipeline —, nunca como
teste da hipótese, que é `M_cur` × `M_ctrl`. (Os testes de fumaça não tocam a partição de teste;
esta comparação só acontece quando ela for aberta para valer.)

---

## 7. Ambiente instalado neste passo (06/10/2026)

Com `pip install --user --break-system-packages`, como o torch em 15/08. Simulado antes com
`--dry-run`; **numpy 2.5.1, pandas 3.0.5, pyarrow 25.0.0 e torch 2.6.0+cu124 não mudaram**
(conferido antes e depois), e o pipeline antigo continua importando.

| pacote | versão | para quê |
| --- | --- | --- |
| gensim | 4.4.0 | Word2Vec |
| scikit-learn | 1.9.1 | métricas, divisão |
| imbalanced-learn | 0.14.2 | SMOTE |
| scipy | 1.18.1 | dependência dos três acima |
| tqdm | 4.70.1 | barra de progresso |
| nltk | 3.10.3 + dado `punkt_tab` em `~/nltk_data` (15 MB) | tokenização do código do nó, como o oficial |
| dgl | 2.5.0+cu124 | o `GatedGraphConv` que o código oficial usa |

O DGL veio de `data.dgl.ai/wheels/torch-2.6/cu124/` (no PyPI a versão mais nova é a 2.1.0, que
não é a compilada para este torch), baixado para `~/curadoria/wheels/` (229.432.772 bytes,
SHA-256 `ce4798260ecc4908484ecdf557e75078053de2c43b9a7632b18dd275eb56d96c`). Dependências que ele
trouxe: pydantic 2.13.5, pydantic_core 2.46.5, psutil 7.2.2, packaging 26.3, typing_extensions
4.16.0, annotated-types 0.8.0, typing-inspection 0.4.4.

**Teste da biblioteca, não do modelo:** `GatedGraphConv(169 → 200, 8 passos, 2 tipos de aresta)`
num grafo de 4 nós, na GPU — saída 4×200, finita, gradiente chegando em todos os parâmetros.

Reverter: `pip uninstall` dos pacotes acima e `rm -rf ~/nltk_data ~/curadoria/wheels`. Os clones
`~/reveal_oficial` e `~/devign_saikat` são só leitura e podem ser apagados sem efeito.

---

## 8. O que muda a partir daqui

A decisão de implementação (item 3) fica com o autor, agora com fatos: o código oficial está
incompleto (§5), diverge do artigo em pontos que mexem no resultado (§2), e tem dois defeitos
que, copiados, quebrariam garantias do TCC (§4). Até ela ser tomada, nada é implementado.
Depois dela, o próximo passo é vetorizar o dataset v3 — o que exige antes resolver o ponto 1 da
§3 (que informação de nó exportar) e **não** pode resolver o ponto 3 (filtro de tamanho) antes da
reunião.
