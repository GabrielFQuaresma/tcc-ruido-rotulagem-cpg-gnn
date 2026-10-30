# Implementação do ReVeal no TCC — o que foi escrito, de onde veio cada peça, e o teste de fumaça

Registro de **10/10/2026**. Cartão do Notion: "Definir e reproduzir o pipeline de treino do ReVeal".

## 0. Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3), o dataset de
grafos (dataset v3, 25.829 grafos, um por função) e o modelo (ReVeal). Este arquivo é da terceira
parte e vem **depois** do congelamento do pré-registro (`PREREGISTRO_TAMANHO.md`, 10/10).

**O que ele responde:** como o ReVeal foi implementado — quais peças vêm do código oficial e quais
foram escritas aqui, toda diferença em relação ao artigo e ao código, e o que o teste de fumaça
mostrou antes de treinar os braços.

**O que ele NÃO é:**
- não é o plano (decisões e porquês: `PLANO_TREINO.md`) nem a ficha do ReVeal
  (`PIPELINE_REVEAL.md`);
- não é resultado: o teste de fumaça usa só uma amostra da partição de **treino**, sem braço, e
  não toca validação nem teste.

## 1. Os scripts

Todos em `Dataset/bigvul/modelo/`; a saída vai para `~/curadoria/modelo/` (fora do repositório).
Rodam no WSL, em primeiro plano, por `bash rodar.sh <script> [args]` (log em
`~/curadoria/modelo/logs/`). Todos são retomáveis: se caírem, rodar de novo continua.

| script | o que faz | saída |
| --- | --- | --- |
| `reveal_comum.py` | caminhos, hiperparâmetros (cada um com a fonte), braços, e os dois modelos copiados do oficial | — |
| `vetorizar.py` | treina o Word2Vec e calcula o vetor de cada nó (uma vez, igual para todos os braços) | `vetores/` |
| `treinar_ggnn.py` | Fase I de um braço: treina a GGNN, grava x_g de cada função | `ggnn/<braço>/` |
| `treinar_fase2.py` | Fase II de um braço: SMOTE + triplet loss, 30 sementes, grava a predição de cada função com o id | `fase2/<braço>/` |
| `rodar_todos.sh` | os 13 braços em sequência | — |

**Nenhum script calcula métrica no teste.** A GGNN só grava o vetor das funções de teste e a
Fase II só grava a predição de cada uma; abrir resultado é um passo próprio, depois dos 13 braços,
seguindo o `PREREGISTRO_TAMANHO.md` para a checagem de tamanho.

## 2. De onde vem cada peça

**Copiado do código oficial (licença MIT), sem mudar a conta:**
- `GGNNSum` — [D] `modules/model.py:64-82`. Só a interface de entrada mudou (recebe o grafo DGL
  em lote em vez do objeto de lote do Devign); a soma dos nós é a mesma.
- `MetricLearningModel` — [R] `representation_learning/models.py`. Uma mudança de conta, do
  plano: distância da triplet loss `1 − |cosseno|`, como no artigo (§3.1 do plano).
- A chamada do SMOTE: `SMOTE(random_state=1000).fit_resample` ([R] `graph_dataset.py:53-54`).

**Escrito aqui** (não existe no oficial, `PLANO_TREINO.md` §3.4): leitura dos grafos do dataset
v3, o vetor de cada nó, o treino do Word2Vec, o passo que entrega x_g da GGNN para a Fase II, o
processamento do lote em pedaços para caber na memória, e a gravação da predição com o id.

## 3. Diferenças declaradas, além das já decididas no plano

As do plano (D9–D12, §3.1, §3.2) estão lá. Estas apareceram ao escrever o código:

| ponto | oficial | aqui | por quê |
| --- | --- | --- | --- |
| tokenização do Word2Vec | treina com `code.split()` (espaços) e tokeniza o nó com `nltk.word_tokenize` | `nltk.word_tokenize` nos dois | os dois do oficial não casam: "buf[i]" é um token num e quatro no outro, e o token do nó vira vetor zero |
| corpus do Word2Vec | código de treino **e teste** | só as 16.170 funções da partição de treino (§3.1) | o oficial vaza o teste para o Word2Vec |
| texto da função no corpus | — | recortado do arquivo-fonte pelas linhas da função, conferido contra o início do `code` do METHOD | o Joern trunca o `code` em 1000 caracteres |
| tipos de aresta | os 12 do Joern antigo (conjunto "full") | os 18 rótulos de aresta do grafo exportado, cada um um tipo, na direção exportada | é o análogo do "full": todos os tipos que o Joern dá |
| lote da GGNN | 128 grafos de uma vez | 128 grafos, processados em pedaços de no máximo 100.000 arestas, gradientes somados antes do passo | memória (4 GB, §5); com perda somada e sem normalização por lote é a mesma conta |
| melhor modelo da Fase II | só restaurado se a paciência estoura; em 100 épocas fica o último | restaurado sempre | o artigo manda parar pela validação, o que implica ficar com o melhor |
| lotes da Fase II | `np.arange(0, total − 1)`: perde o último exemplo de cada conjunto | todos entram | defeito do oficial |
| sorteio da triplet loss | laço Python, converte o conjunto em lista a cada exemplo | o mesmo sorteio (uniforme na classe, fora do lote), em numpy | velocidade; a distribuição é a mesma |
| ordem dos lotes da GGNN | `shuffle` sem semente por época | permutação com semente 1000 + época | permite retomar o treino de um checkpoint com a mesma sequência |

## 4. Vetorização (rodada em 10/10/2026, 242 s)

`vetorizar.py`, saída em `~/curadoria/modelo/vetores/` (`relatorio.json`):

| | |
| --- | --- |
| grafos / nós / arestas | 25.829 / 3.710.493 / 31.853.004 (batem com `dataset_indice_v3.tsv`, conferido grafo a grafo) |
| rótulos de nó / de aresta | 18 / 18 |
| corpus do Word2Vec | 16.170 funções da partição de treino; **15.998 (98,9%) com o texto recortado do fonte e conferido**, 172 caíram no `code` truncado do METHOD; 3.843.905 tokens |
| vocabulário do Word2Vec | 138.596 tokens |
| tokens de nó fora do vocabulário | 964.617 de 20.682.431 calculados (4,7%) — contam como vetor zero na média, como no oficial |
| SHA-256 do `word2vec.model` | `20585c12449aa792dd2b040ae4bd7d13cd1fa28677aa88cd237f49533e618392` |

*Conserto registrado:* a primeira gravação do Word2Vec separou as matrizes em arquivos com prefixo
`.tmp` e o rename quebrava o `load`. Os arquivos foram renomeados, o modelo carregado e regravado
em arquivo único, e os vetores conferidos idênticos (`array_equal`). O script já grava em arquivo
único.

## 5. Teste de fumaça (10/10/2026)

**O que é:** uma rodada curta do pipeline inteiro numa **amostra da partição de treino**, sem
braço, para achar defeito antes de gastar horas. **Não é resultado:** não toca validação nem
teste. Amostra de 600 funções do treino (semente 6060, não usada antes): 590 sorteadas + os 10
maiores grafos do treino, de propósito, para exercitar a memória; 480 viram pseudo-treino (55
positivos) e 120 pseudo-validação (11 positivos). GGNN por 3 épocas; Fase II com 2 sementes.

**O que ele achou e o que mudou por causa disso:**

1. **Memória (achado real).** Com o lote dividido em pedaços de até 60.000 **nós**, o pico foi de
   **8,96 GB numa placa de 4 GB**: no WSL, o driver do Windows deixa a GPU emprestar RAM do sistema
   em vez de dar erro, e tudo fica lento (85 s por época para 480 funções). Quem ocupa memória são
   as **arestas** (média de 1233 por função; o GatedGraphConv guarda uma mensagem de 200 números
   por aresta em cada um dos 8 passos). Conserto: pedaços de até **100.000 arestas** e a GPU
   travada em 85% da memória real (faltar memória vira erro, e o lote é refeito com metade do
   orçamento). Resultado: pico de **2,44 GB**, **9 s por época**.
   *Conferência de que os pedaços não mudam a conta:* as perdas das 3 épocas saíram **idênticas**
   nas duas rodadas (4567,3 / 2247,7 / 1953,3), com pedaços de tamanhos diferentes.
2. **Defeito de código na Fase II** (passava um array numpy onde o modelo espera tensor) —
   corrigido.
3. **TF32** (multiplicação de matriz em precisão reduzida das placas Ampere) foi medido como
   opção de velocidade: 29,7 s contra 32,2 s no total, uns 8%, dentro do ruído entre épocas. **Não
   adotado**; fica FP32.

**O que funcionou:** a Fase II leva o pseudo-treino de 480 a 850 com SMOTE (425 positivos), treina,
para pela validação (10 e 12 épocas), restaura a melhor e grava a predição das 120 funções com o
id. A GGNN grava `vetores.npz` com x_g de 200 números por função.

**O que o teste de fumaça NÃO conseguiu responder:** se a GGNN aprende com 3,5% de positivos. Na
amostra, o F1 na pseudo-validação ficou em 0 nas 3 épocas, o que com 480 funções e 3 épocas não
diz nada. Só o `M_cur` de verdade responde. O treino foi preparado para isso: se uma GGNN termina
sem nunca passar de F1 0 (`sem_melhora`), o script sai com erro e o `rodar_todos.sh` **para**,
esperando o autor (`PLANO_TREINO.md` §3.3 c).

**Tempo projetado** (pela taxa de arestas por segundo do teste, FP32): uma época custa uns
**3 min no `M_cur`** e em cada `M_ctrl_g` (14.917 funções, 16,9 milhões de arestas), uns **4 min
no `M_raw`** (16.170, 19,0 milhões) e ~1 min em cada braço do par balanceado (1046 funções, mas
a validação inteira roda a cada época). Com a paciência de 50, cada braço roda **no mínimo 51
épocas**: ~2,7 h por braço principal. O total depende de quando cada GGNN para de melhorar, e só
se sabe rodando; no pior caso (500 épocas) seriam ~27 h por braço principal.

## 6. Treino dos 13 braços (10/10/2026, 19:45 → 12/10/2026, 09:35)

**Terminado.** Todos os 13 braços têm a GGNN treinada e as 30 sementes da Fase II gravadas.
Conferido em 12/10 (`conferir_saidas.py`, só contagens, **nenhuma métrica de teste**): em cada
braço, 30 arquivos de predição, cada um com as 3929 funções de validação e as 5730 de teste, e o
**mesmo conjunto de ids de teste em todos os 390 arquivos**. Nenhuma GGNN terminou `sem_melhora`.

| braço | épocas da GGNN | melhor época | positivos / total no treino |
| --- | --- | --- | --- |
| `M_raw` | 76 | 25 | 1776 / 16.170 |
| `M_cur` | 158 | 107 | 523 / 14.917 |
| `M_ctrl_g2026` | 61 | 10 | 523 / 14.917 |
| `M_ctrl_g2027` | 70 | 19 | 523 / 14.917 |
| `M_ctrl_g2028` | 78 | 27 | 523 / 14.917 |
| `M_ctrl_g2029` | 58 | 7 | 523 / 14.917 |
| `M_ctrl_g2030` | 109 | 58 | 523 / 14.917 |
| `M_cur_bal` | 80 | 29 | 523 / 1046 |
| `M_ctrl_g2026_bal` | 58 | 7 | 523 / 1046 |
| `M_ctrl_g2027_bal` | 77 | 26 | 523 / 1046 |
| `M_ctrl_g2028_bal` | 56 | 5 | 523 / 1046 |
| `M_ctrl_g2029_bal` | 76 | 25 | 523 / 1046 |
| `M_ctrl_g2030_bal` | 52 | **1** | 523 / 1046 |

**O que a tabela NÃO é:** não é resultado. As épocas e a "melhor época" vêm da regra de parada
(melhor F1 de validação da camada provisória da GGNN; para 50 épocas depois do último recorde),
que é a mesma para todos os braços. O F1 de validação pula muito entre épocas (o modelo acusa
poucas funções — de 20 a 180 das 3929 nos braços principais), então o número de épocas é em parte
acaso: uma época de sorte reinicia a contagem. O `M_cur` rodou mais (recordes nas épocas 33, 66 e
107) e cada época dele custa ~10% mais, porque os positivos dele têm em média 5664 arestas contra
2528–3074 nos controles. **A comparação entre braços se faz no teste**, pela análise principal e
pelo `PREREGISTRO_TAMANHO.md`.

**A anotar para a análise:** no `M_ctrl_g2030_bal` a melhor época da GGNN foi a **1** — a versão
guardada é uma GGNN quase sem treino. A regra foi seguida (é a mesma para todos); é o controle
balanceado que menos treinou.

**No par balanceado o SMOTE ficou inativo**, como previsto (`PLANO_TREINO.md` §5.1): 1046 → 1046
funções. Nos braços principais, 14.917 (ou 16.170) → 28.788, com 14.394 positivos.

**Interrupções (nenhuma por erro do treino).** O ambiente de execução encerra processos em segundo plano
quando a RAM do Windows fica crítica com a sessão ociosa. Aconteceu 4 vezes, mais uma pausa pedida
pelo autor (11/10, para usar o computador). Cada vez o treino retomou do checkpoint da última
época completa — perde-se no máximo a época em andamento. Em 11/10 foi criado
`C:\Users\kntpr\.wslconfig` (`memory=6GB`, `autoMemoryReclaim=gradual`) e fechados Discord e
Steam; depois disso houve uma queda (WSL a 4,4 GB, host a 3,7 GB livres), resolvida reiniciando o
WSL. Para desfazer a configuração: apagar o arquivo e rodar `wsl --shutdown`.

**Tempo de relógio:** ~38 h do início ao fim, incluindo as paradas.

## 7. Fase II refeita com os modelos salvos (12/10/2026, 13:09 → 13:45)

**Por quê.** A rodada da §6 gravou só as predições da Fase II, não os modelos. Para avaliar as
arenas externas seria preciso treiná-la de novo, e, como a GPU não garante resultado idêntico, o
BigVul poderia ganhar uma segunda versão de predições depois de aberto. O
`PREREGISTRO_PRINCIPAL.md` (congelado em 12/10, §6 passo 2 e §8) mandou refazer a Fase II **antes
de abrir o teste**, salvando os modelos, e fixou que o conjunto novo é o oficial em qualquer caso.

**O que mudou no código:** só a gravação. `treinar_fase2.py` ganhou `--pasta` (padrão `fase2`, a
rodada original) e, com outra pasta, grava `modelo_<s>.pt` (o `state_dict` da melhor época) antes
da predição; a retomada passa a exigir o modelo também. Nenhuma conta mudou. Rodado por
`rodar_fase2_v2.sh` (os 13 braços, saída só para o log) e conferido por `conferir_fase2_v2.py`
(só contagem de ids e SHA-256 dos arquivos; não lê rótulo, não calcula métrica, não imprime
predição).

**Resultado da conferência:**
- 390 arquivos em `~/curadoria/modelo/fase2_v2/`, cada um com os 3929 ids de validação e os 5730
  de teste do `dataset_indice_v3.tsv`, sem repetição; 390 modelos gravados; 287 MB no total;
- **os 390 arquivos de predição saíram idênticos byte a byte aos da rodada original** (`fase2/`).
  A Fase II é reprodutível nesta máquina: mesmas sementes, mesmos números. Na prática, o conjunto
  oficial (`fase2_v2/`) e o original são o mesmo; a diferença é que agora os modelos existem para
  prever as arenas externas.
- Tempo: ~36 min para os 13 braços (4–6 min por braço principal, ~30 s por braço do par).

**O que isto NÃO é:** não é resultado. Nenhuma métrica foi calculada, e a única comparação feita
entre as duas rodadas foi de identidade de arquivo.

## 8. O script de análise e o ensaio na validação (13/10/2026)

**O que é.** `analisar_resultados.py` é o passo 4 da ordem de abertura (`PREREGISTRO_PRINCIPAL.md`
§6): calcula as tabelas que os dois pré-registros fixaram, e nada além. Antes de calcular, confere o
SHA-256 dos dois pré-registros e o congelamento da traversal v3; se algo não bater, não roda. No
teste, só roda com `--abrir-teste`; se o resultado do teste já existir, só roda de novo com
`--refazer "motivo"`, e a versão anterior fica guardada (passo 7).

**O ensaio (passo 5)** rodou só na partição de validação. A saída ficou **fora do repositório**
(`~/curadoria/modelo/analise/ensaio_validacao.md`), porque o ensaio não é resultado: a validação já
foi usada para escolher a época da GGNN e da Fase II. Ele serviu para estas conferências, todas
passaram:
- **(a)** o F1 que o script calcula em cada repetição é igual ao F1 de validação gravado no treino
  em **390 de 390** repetições (maior diferença 0) — confere a junção por id, o alinhamento dos
  rótulos e a conta do F1;
- **(b)** a contagem por faixa de tamanho bate com a medida em 12/10;
- **(c)** o veredito da traversal, recalculado pelo script para os 2031 positivos de treino e
  validação, é igual ao de `traversal/conjuntos_v3/M_raw.tsv` em todos (0 diferenças), e os
  confirmados de treino dão 523, o `M_cur`. Os positivos de teste ficaram de fora desta conferência;
- **(d)** as 5241 evidências das negativas do teste têm a estrutura que o veredito lê (só estrutura,
  sem aplicar o veredito).

**Os caminhos que só valem no teste** foram testados sem tocar no teste: a trava (sem
`--abrir-teste` o script recusa e não grava nada); o veredito das negativas, com evidências
sintéticas copiadas de 40 positivos de treino (igual ao dos positivos em 40 de 40; falha e ausência
de evidência contam como "não acusa"); e a contagem de acertos e erros num exemplo feito à mão.

**Ordem de grandeza (não é resultado):** na validação, o F1 de todos os braços ficou entre 0,14 e
0,23 (mediana das 30), compatível com o ReVeal publicado no BigVul (F1 23,58, Lu & Lagaisse) — o
pipeline não está quebrado. Nenhum número do ensaio vai para o texto.

**Próximo passo (6):** `python3 analisar_resultados.py --particao teste --abrir-teste`, uma vez,
com o autor presente.

## 9. Abertura do teste do BigVul (13/10/2026, 10:21)

Aberto uma vez, com o ok do autor ("pode abrir o teste"), por
`analisar_resultados.py --particao teste --abrir-teste`. As conferências passaram (hashes dos dois
pré-registros e da traversal; contagens por faixa; veredito dos positivos de treino e validação;
estrutura das negativas).

| arquivo | SHA-256 |
| --- | --- |
| `resultado_teste_bigvul.md` | `39296fad703b850a0db4bc75e50617bd383e294978178ebdeba7d7185480cf1c` |
| `resultado_teste_bigvul.json` | `f8ea66693ceac645cc1d9a7dd16aed5d08b45a4703f661519acc9bad63991402` |

**O que os pré-registros mandam ler** (BigVul: concordância com o rótulo do BigVul, não detecção):
- **Comparação que decide (§3), desenho principal:** F1 do `M_cur` 0,262 (mediana das 30) contra a
  faixa dos 5 controles 0,206–0,242 → **acima** (por acaso, 1 vez em 6). Par balanceado
  (sensibilidade): 0,287 contra 0,255–0,272 → também acima.
- **Checagem de tamanho:** desenho principal **sem evidência de viés de tamanho** (V1 não dispara:
  inclinação 0,362 contra 0,253–0,479; V2 não dispara: o `M_cur` não fica acima em nenhuma faixa).
  Par balanceado: **evidência** (V1 dispara: 0,775 contra 0,648–0,762) — fica no apêndice, não
  qualifica a conclusão (E2).
- **Traversal pura (descritiva):** F1 0,270 (TP 230, FP 983, FN 259, TN 4258), contra 0,262 do
  `M_cur`.

**Observações descritivas, pós hoc** (calculadas depois de abrir, a partir do `.json`; não mudam
nenhum veredito, mas pesam na redação — a discutir com o autor):
- o ganho do `M_cur` no F1 geral **não aparece dentro de nenhuma faixa de tamanho**. Ele vem de
  acusar muito menos funções pequenas: medianas das 30, falsos positivos nas faixas até 46 / 47–131
  = 5 / 76 no `M_cur`, contra 73 / 141 no controle de perfil mais parecido (`M_ctrl_g2030`), com
  acertos totais parecidos (136 contra 141);
- na PR-AUC, que não depende do limiar, o `M_cur` (0,176) fica **dentro** da faixa dos controles
  (0,153–0,189);
- o `M_cur` supera o F1 da traversal pura em 7 das 30 repetições; fica acima da maior mediana dos
  controles em 26 das 30.

**Decisão do autor (13/10):** a observação pós hoc do tamanho (o ganho não aparece dentro de
nenhuma faixa) vai **no corpo do texto**, ao lado do resultado do BigVul, declarada como pós hoc —
não só no apêndice. *Também registrado:* o V1 mede **diferença** de taxas de falso positivo, e por
isso não acusa um modelo que acusa pouco em todas as faixas, mesmo muito desigual em proporção
(o `M_cur` acusa ~150× mais as não vulneráveis grandes que as pequenas; os controles, 6–10×). Essa
fraqueza era visível antes do congelamento e não foi levantada; o veredito pré-registrado fica
como está.

**Pós hoc, pedido pelo autor (13/10): sobreposição com a regra** (`posthoc_sobreposicao.py` →
`posthoc_sobreposicao.md`). A regra confirma 1213 das 5730 funções do teste (21,2%). Das
acusações do `M_cur`, **54,5%** a regra também confirma, contra 34,1–39,5% nos 5 controles. A
diferença sobrevive dentro das faixas de tamanho (na de 47–131 nós: 36,3% contra 19,0–20,7%, com
a regra confirmando 18,3% das funções da faixa), então não é só tamanho. Mas o `M_cur` não é só a
regra: 45 dos seus 136 acertos (um terço) são vulneráveis que a regra **não** confirma, e ele
acusa só 25,3% do que a regra confirma. Leitura: o `M_cur` aprendeu em parte o padrão da regra,
não apenas ele, e no BigVul não ficou melhor que ela (F1 0,262 contra 0,270).

**Os 50 anotados no dataset v3:** 9 no teste (9 commits e 9 CVEs distintos), 34 no treino, 7 sem
grafo, nenhum na validação. A sonda qualitativa (PREREGISTRO_PRINCIPAL §9) só pode usar os 9.

**Sonda qualitativa dos 9, pedida pelo autor (13/10)** (`posthoc_50_teste.py` →
`posthoc_50_teste.md`). Segundo uso dos 50, declarado. O script lê do CSV de anotação só id, commit,
CVE e `tipo_ruido` (o arquivo traz o patch com autores; nada disso é lido nem impresso); o `id` da
anotação é o número do caso, conferido por commit e CVE em 50 de 50. Composição: 4 **D** (sítio) e 5
de rótulo indevido (1 A, 1 B, 3 C). Média de repetições (de 30) em que cada braço acusa:

| grupo | `M_cur` | `M_raw` | 5 controles | `M_cur_bal` |
| --- | --- | --- | --- | --- |
| D (n = 4) | 11,5 | 20,5 | 0,8 a 21,2 | 22,0 |
| A/B/C (n = 5) | 7,4 | 16,2 | 12,8 a 19,6 | 14,4 |

Leitura, só qualitativa (n = 9, sem métrica): o `M_cur` acusa menos tudo, como no teste inteiro.
Nos 5 de rótulo indevido acusa menos que todos os controles, e poupa dois casos que a maioria dos
controles acusa (caso 45, C: 3 de 30 contra 21–30; caso 9, B: 0 contra até 30). Mas também acusa
pouco dois dos 4 sítios verdadeiros (caso 46: 0; caso 8: 3). A preferência relativa por D sobre
ruído é maior no `M_cur` (~1,5×) que na maioria dos controles (~0,9–1,1×) — compatível com a
hipótese, mas com 9 casos é ilustração, não evidência.
