# Pré-registro da análise principal — `M_cur` contra a faixa dos 5 controles

> **Congelado em 12/10/2026, depois do treino dos 13 braços e antes de qualquer métrica no
> teste.** Aprovado pelo autor item a item em 12/10/2026 (Histórico, no fim). Para redigi-lo,
> nenhum arquivo de predição foi aberto: as únicas coisas consultadas foram o código
> (`treinar_fase2.py`, `reveal_comum.py`, `treinar_ggnn.py`), contagens de
> `traversal/dataset_indice_v3.tsv` (que o `PREREGISTRO_TAMANHO.md` §3 diz não ser ver resultado)
> e a data de gravação dos arquivos da Fase II, sem abri-los.
>
> Este arquivo **não é editado** depois do congelamento: o SHA-256 dele está em `PLANO_TREINO.md`
> §4 e nas `Notas` do cartão do Notion. Se algo precisar mudar, o caminho honesto é um arquivo
> novo, com hash novo, registrando o que mudou e por quê — como no `PREREGISTRO_TAMANHO.md`.

## Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3 — a consulta do
Joern que confirma ou descarta cada função que o BigVul marca como vulnerável), o dataset de
grafos (dataset v3, 25.829 grafos, um por função) e o modelo (ReVeal). Os 13 braços terminaram de
treinar em 12/10/2026 (`IMPLEMENTACAO.md` §6). O próximo passo é calcular, pela primeira vez, as
métricas no teste.

**O que este arquivo responde.** *Como* o `M_cur` (os 523 positivos de treino que a traversal
confirmou) vai ser comparado com os 5 `M_ctrl_g` (cada um, 523 positivos sorteados sem curadoria,
semente g = 2026 a 2030), e *o que se pode escrever* para cada resultado possível. Fixar isso antes
de ver o número é o que impede de escolher, depois, a comparação que favorece o número.

**O que ele NÃO é.**
- não é a checagem de tamanho — essa é o `PREREGISTRO_TAMANHO.md`, congelado em 10/10, que **não é
  editado**; este arquivo só a conecta à análise principal e decide o que ela deixou em silêncio
  (§5), sem mudar nada do que ela diz;
- não é resultado: quando foi escrito, nenhuma métrica de teste existia;
- não é o protocolo completo das arenas externas (ICVul, VentiVul, sonda CWE-416), que ainda não
  existem; fixa só a quantidade que decide nelas (§8), porque essa escolha não pode esperar o
  BigVul ser aberto.

## Resumo das 4 decisões do autor

| | pergunta | decisão | onde |
| --- | --- | --- | --- |
| A | Qual métrica decide? | **fechada (12/10):** só o F1; recall e precisão ao lado, descritivas | §3 |
| B | O veredito de tamanho vale por desenho e arena, ou para o trabalho inteiro? | **fechada (12/10):** por desenho e arena; só o do principal qualifica | §5 |
| C | Nas arenas externas, decide o F1 lá ou a queda de F1 do BigVul para lá? | **fechada (12/10):** o F1 lá; a queda ao lado, descritiva | §8 |
| D | A linha "traversal pura" fica? (exige rodar a regra nos negativos do teste) | **fechada (12/10):** fica; roda antes de abrir o teste | §7 |

---

## 0. O que já estava decidido e só é reunido aqui

Nada desta tabela é decisão nova; está aqui para a análise poder ser executada lendo um arquivo só.

| o quê | decidido em |
| --- | --- |
| Limiar: a classe mais provável das duas (prob ≥ 0,5), igual para todos, sem ajuste | `PLANO_TREINO.md` D12 |
| Fase II (a segunda etapa do ReVeal: SMOTE + rede com *triplet loss*) repetida 30 vezes por braço, sementes 1000–1029; reporta mediana e IQR (o intervalo onde cai a metade central das 30) | `PLANO_TREINO.md` §5 |
| F1 e recall primárias; PR-AUC e MCC secundárias; sem acurácia | `main.tex`, Protocolo de avaliação |
| No BigVul, a métrica mede "concordância com o rótulo do BigVul", não detecção | `main.tex`, Protocolo de avaliação (l. 494) |
| Régua = faixa das medianas dos 5 controles; ficar acima de todos acontece por acaso 1 vez em 6 | `PREREGISTRO_TAMANHO.md` §5; `main.tex` l. 767 |
| `M_raw` é referência de escala e não entra em veredito | `main.tex` Tabela de braços; `PREREGISTRO_TAMANHO.md` §0 |
| Par balanceado (1:1, 523 negativos, semente 5050) é sensibilidade | `PLANO_TREINO.md` §5.1, D7 |

## 1. Os dados da análise

- **Arena BigVul (dentro da distribuição):** a partição de teste do split congelado, **5730
  funções, 489 positivas e 5241 negativas** (`dataset_indice_v3.tsv`, partição `teste`). Na
  rodada original, os 390 arquivos de predição tinham o mesmo conjunto de ids de teste
  (`IMPLEMENTACAO.md` §6); a mesma conferência (só contagem de ids) é refeita em `fase2_v2/`.
- **Predição usada:** a coluna `predicao` de `fase2_v2/<braço>/semente_<s>.tsv` — a rodada da
  Fase II refeita **com os modelos salvos** (§6, passo 2; §8) —, que é `prob_vulneravel ≥ 0,5`
  (`treinar_fase2.py:159`). A rodada original, `fase2/`, fica como registro e não é usada. A
  `prob_vulneravel` é a probabilidade de verdade (exponencial da saída `LogSoftmax`,
  `reveal_comum.py:185`), então "≥ 0,5" é a classe mais provável do D12. Ela só é usada para a
  PR-AUC.
- **A partição de validação** (3929 funções) já serviu para escolher a época da GGNN e da Fase II.
  Não entra em nenhum número reportado como resultado; serve só para o ensaio do script (§6).

## 2. O valor de um braço

- Para cada braço e cada métrica: calcula-se a métrica em cada uma das 30 repetições da Fase II;
  **o valor do braço é a mediana das 30**, reportada com o IQR.
- **Nenhum braço e nenhuma repetição saem da análise**, por motivo nenhum descoberto depois de
  abrir o teste. Isso inclui o `M_ctrl_g2030_bal`, cuja GGNN teve a melhor época = 1
  (`IMPLEMENTACAO.md` §6), e qualquer repetição da Fase II que tenha terminado sem melhora.
  *Por quê:* a regra de treino foi a mesma para todos; tirar um controle depois de ver onde ele
  caiu é escolher a régua pelo resultado. *O que isso faz, declarado:* um controle quase sem
  treino tende a puxar para baixo o **piso** da faixa do par balanceado — o que torna mais difícil
  o `M_cur_bal` ficar *abaixo* da faixa, e não muda nada em ficar *acima*.

## 3. A comparação que decide

**Uma comparação por arena:** o F1 do `M_cur` contra a faixa dos controles, **no desenho
principal** (`M_cur` e os 5 `M_ctrl_g`, cada um com os 14.394 negativos de treino).

- **Faixa dos controles** = do menor ao maior valor entre as 5 medianas dos `M_ctrl_g`.
- **Três resultados possíveis:** *acima* (maior que o maior dos 5), *dentro*, *abaixo* (menor que
  o menor dos 5). **Empate conta como *dentro*.**
- **O que o acaso faz:** se a curadoria não fizesse diferença nenhuma, o `M_cur` seria um sexto
  controle, e cada uma das seis posições seria igualmente provável: *acima* por acaso 1 vez em 6
  (~17%), *abaixo* 1 vez em 6, *dentro* 4 vezes em 6.
- **Pode:** "o `M_cur` ficou acima dos cinco controles — o que, sem efeito nenhum, aconteceria 1
  vez em 6". **Não pode:** "significativamente", "prova", ou qualquer linguagem de teste
  estatístico.

**Qual métrica decide (DECISÃO A, fechada pelo autor em 12/10): só o F1.** Recall e precisão
aparecem ao lado, descritivos, para mostrar de onde o F1 veio. O `main.tex` tinha duas métricas
primárias (F1 e recall) e nenhuma regra para quando discordassem; no texto, passa a constar
"primária para o veredito: F1".
*Por quê:* uma comparação só, então o "1 em 6" vale exatamente como escrito; o F1 é a métrica da
frase central do `main.tex` (l. 767) e a que o ReVeal publicado reporta. O recall sozinho premia
acusar mais — um modelo que acusa as 5730 funções do teste tem recall de 100%, precisão de 8,5%
(489/5730) e F1 de ~15,7% —, e acusar mais é o que um atalho de tamanho faria.
*Alternativas descartadas:* exigir F1 **e** recall do mesmo lado (a chance por acaso deixa de ser
calculável sem simular, porque os dois andam juntos); aceitar qualquer um dos dois (duas chances
de 1 em 6, até perto de 1 em 3 por acaso).

## 4. O que se escreve para cada resultado, no BigVul

O teste do BigVul tem os rótulos originais: na amostra de 50 positivos brutos, **57,1% não eram o
sítio da vulnerabilidade** segundo o anotador humano (28 de 49 decididas, IC 95% 34,2–74,2;
`validacao_cega/saida/resumo_para_o_artigo.md`). Por isso cada resultado tem uma leitura limitada.

| resultado (F1, desenho principal) | pode escrever | não pode escrever |
| --- | --- | --- |
| **acima** | "o `M_cur` concordou mais com o rótulo do BigVul do que os cinco controles (1 vez em 6 por acaso)" — **e só depois do veredito de tamanho** do mesmo desenho e arena (§5) | "a curadoria melhora a detecção"; a régua é o rótulo ruidoso |
| **dentro** | "no BigVul, o `M_cur` não se distingue dos controles"; é o cenário que a hipótese prevê dentro da distribuição (`main.tex` l. 767) | que isso é evidência contra (ou a favor) da hipótese, que é sobre as arenas externas |
| **abaixo** | as **duas** leituras, sem escolher: (i) a curadoria piorou o modelo; (ii) o `M_cur` aprendeu um alvo diferente do rótulo ruidoso e é cobrado por ele. O BigVul sozinho não separa as duas | só uma das duas leituras |

Isto fecha a Decisão 3 de 05/09 (`documentos-orientação/resposta_treinamentos_bigvul.md`) na
combinação que já era a inclinação registrada: relatar o BigVul como concordância com o rótulo
(a) e apoiar a conclusão nas arenas externas (c); os anotados que caíram no teste, só como
evidência qualitativa (d).

## 5. A ligação com o `PREREGISTRO_TAMANHO.md` — e o que ele deixou em silêncio

O texto congelado vale como está. Abaixo, só pontos que ele **não** decide; nenhum contradiz o que
ele diz. Foram escritos antes de qualquer resultado.

**Contagens do teste por faixa** (o §3 de lá permite contar):

| faixa (nós do grafo) | positivos | negativos | % de positivos na faixa |
| --- | --- | --- | --- |
| até 46 | 37 | 2096 | 1,7% |
| 47 a 131 | 129 | 1732 | 6,9% |
| 132 a 339 | 135 | 968 | 12,2% |
| 340 ou mais | 188 | 445 | 29,7% |
| total | 489 | 5241 | 8,5% |

As quatro faixas passam do mínimo de 30 positivos e 30 negativos — a mais apertada é a de até 46
nós, com 37 positivos. Então, **no BigVul, V1 e V2 se aplicam integralmente**, nos dois desenhos
(o par balanceado usa o mesmo teste). *E a tabela mostra por que a checagem importa aqui:* no
teste, a proporção de positivos sobe de 1,7% nas funções pequenas para 29,7% nas grandes. Um modelo
que aprendesse só "grande = vulnerável" seria **recompensado** por este teste.

**Esclarecimentos:**

- **E1 — Como o resultado principal é qualificado (aprovado pelo autor em 12/10).** **O resultado
  geral decide a frase principal**: a comparação do §3, no teste inteiro da arena. A checagem de
  tamanho não muda essa frase; quando dispara, **acrescenta uma segunda, lado a lado**, no corpo
  do texto e na conclusão (como o §6 de lá manda), dizendo qual critério disparou e o que ele
  significa. Vale o veredito do desenho principal na mesma arena (E2).

  | resultado (§3) | checagem de tamanho | o texto diz |
  | --- | --- | --- |
  | acima | sem evidência | "ganho sem sinal de atalho de tamanho", com a ressalva do §7 de lá (função maior também é função mais rica, e a checagem não separa as duas coisas) |
  | acima | evidência (V1 ou V2) | "ganho **e** evidência de atalho de tamanho", qual critério disparou e o que ele significa; o ganho não é atribuído só à limpeza dos rótulos |
  | dentro ou abaixo | evidência | relata: o modelo pegou o atalho e não lucrou com ele |
  | dentro ou abaixo | sem evidência | nada a acrescentar |

  *O que cada critério significa, para a frase:* o **V1** (acusar funções grandes não vulneráveis
  mais que todos os controles) é a marca mais direta do atalho; o **V2** (ganho só nas faixas
  grandes) tem duas leituras que a checagem não separa — atalho, ou competência concentrada nas
  funções grandes, que é como são os positivos do `M_cur` (mediana de 323 nós, contra 116–136 nos
  controles; treino, n = 523 cada) e que o §7 de lá trata como parte do tratamento.
  *Por que lado a lado e não "inconclusivo":* os dois são indícios do mesmo tipo — o ganho sai
  por acaso 1 vez em 6, e algum critério de viés ~31% das vezes por arena (E2). Rebaixar um por
  causa do outro trataria um indício como prova. O ganho nunca é escrito sem a ressalva quando
  ela existe, e nunca é chamado de prova.
  *Alternativas descartadas:* chamar o ganho de inconclusivo sempre que houver evidência; ou só
  quando o V2 disparar (proposta intermediária de 12/10, retirada porque o V2 sozinho não separa
  atalho de competência).

- **E2 — A que se aplica o veredito (DECISÃO B, fechada pelo autor em 12/10).** O §0 de lá estende
  a checagem aos dois desenhos e a todas as arenas; o §6 dá um veredito sem dizer se é um por
  desenho e arena ou um para o trabalho inteiro. O texto congelado admitia as duas leituras.
  **Fica: um veredito por desenho e por arena, e só o do desenho principal qualifica a
  conclusão (E1), arena por arena.** O veredito do par balanceado continua sendo calculado, como o
  §0 de lá manda, e aparece na tabela do apêndice, mas não qualifica conclusão nenhuma. Assim nada
  do texto congelado muda.
  *Por quê:* cada checagem disparada por acaso soma alarme falso. Juntar tudo num veredito só —
  2 desenhos × 2 critérios, só no BigVul — levaria a chance de **nenhuma** disparar por acaso a
  (5/6)⁴ ≈ 48% (conta simplificada: 1 em 6 cada, independentes), e menos ainda com as arenas
  externas. Mesmo restrito ao principal, cada arena tem 2 critérios: algum dispara por acaso
  ~31% das vezes (1 − (5/6)²) — por isso o veredito é tratado como indício (E1).
  *Alternativa descartada:* tirar o veredito do par (mudaria o §0 congelado, com o mesmo efeito no
  texto).

- **E3 — "Não deu para verificar" não é "sem evidência".** Se, numa arena, nem V1 nem V2 puderem ser
  aplicados por falta de contagem (§3 de lá), o veredito é **"não verificável"**, não "sem
  evidência". E o V2 exige pelo menos uma faixa pequena (até 46 ou 47–131) com 30 positivos; sem
  nenhuma, "em nenhuma das pequenas" seria verdade por vacuidade, e o V2 passa a "não se aplica".
  No BigVul isso não acontece (tabela acima); importa nas arenas externas e na sonda.

- **E4 — Empate.** "Acima do maior" é estritamente maior; empate conta como dentro — vale para V1,
  V2 e o §3 deste arquivo.

- **E5 — Tamanho nas arenas externas.** O §1 de lá mede o tamanho pela coluna `n_nos` de um arquivo
  que só tem o BigVul. Nas arenas externas, o tamanho será contado do mesmo jeito (grafo exportado
  pelo mesmo `exportar_grafos.sc`, mesmo recorte de função), e as faixas continuam as do BigVul
  (até 46 | 47–131 | 132–339 | 340 ou mais), que são números fixos.

## 6. Ordem de abertura

1. **Congelar este arquivo** (SHA-256 no `PLANO_TREINO.md` §4 e no Notion).
2. **Refazer a Fase II dos 13 braços salvando os 390 modelos** (§8), em `fase2_v2/`, com as
   mesmas sementes e a mesma GGNN. A única mudança no código é gravar o modelo; nenhuma conta muda.
   Os arquivos de predição novos são comparados com os de `fase2/` **só por SHA-256, arquivo a
   arquivo**, sem ler o conteúdo, e registra-se quantos dos 390 saíram idênticos. **Em qualquer
   caso, o conjunto oficial é o novo** — o único cujos modelos também vão prever as arenas
   externas. Decidido aqui, antes de qualquer resultado. Custo: ~40 min (pela data de gravação dos
   arquivos da rodada original: 4–6 min por braço principal, menos de 1 min por braço do par) e
   ~180 MB (~118 mil parâmetros por modelo).
3. **Rodar a traversal v3 congelada nos 5241 negativos do teste** (§7, traversal pura), primeiro
   num ensaio pequeno e depois em todos.
4. **Escrever o script de análise** seguindo os dois pré-registros. Ele confere o SHA-256 dos dois e
   **se recusa a rodar** se algum não bater — como o `comparar.py` da validação cega.
5. **Ensaiar o script só na partição de validação**, para achar defeito de código antes de gastar o
   teste. Nada do ensaio vira resultado nem entra no texto.
6. **Rodar no teste uma vez**, todas as tabelas juntas: principal, par balanceado, tamanho e
   descritivas (§7).
7. **Defeito encontrado depois de abrir o teste:** corrige, roda de novo e reporta **as duas
   versões**, dizendo que foi refeito. Mudar braço, hiperparâmetro, limiar ou regra depois de abrir
   o teste é análise *post hoc* e vai declarada como tal.

## 7. O que se reporta sem veredito

- **Para todos os braços:** F1, recall, precisão, PR-AUC (área sob a curva de precisão × recall em
  todos os limiares; calculada como *average precision*, `sklearn.metrics.average_precision_score`,
  sobre `prob_vulneravel`) e MCC (coeficiente de Matthews, que usa as quatro casas da matriz de
  confusão), cada um com mediana e IQR das 30.
- **`M_raw`:** referência de escala. Comparado em ordem de grandeza com o ReVeal treinado no BigVul
  por Lu & Lagaisse (F1 23,58 no teste do próprio BigVul; `PIPELINE_REVEAL.md` §6, transcrito das
  tabelas deles — conferir no PDF antes de pôr no texto). **Não há critério de aceite:** o número
  deles serve para notar um pipeline quebrado (F1 perto de 0 ou de 90), não para ajustar nada.
- **Par balanceado:** a mesma regra do §3, reportada como sensibilidade (o padrão se mantém sem o
  SMOTE, que no par fica inativo?). Se discordar do desenho principal, as duas aparecem e o texto
  diz que discordam; a conclusão se apoia no desenho principal.
- **Traversal pura (DECISÃO D, fechada pelo autor em 12/10): fica, e roda antes de abrir o
  teste.** A Tabela de braços do `main.tex` e o cartão "Testar se a GNN aprendeu mais do que a
  regra da traversal" preveem a regra congelada como classificador no teste. Isso responde a
  pergunta do orientador de 05/09: "a rede aprendeu só o que o Joern já faz?". Se o `M_cur` não
  supera a regra, é achado, não fracasso.
  - **O que falta:** a traversal v3 só rodou nos 2957 positivos (`TRAVERSAL_V3.md`, Fase 4); os
    5241 negativos do teste não têm veredito. A regra v3 congelada roda neles **antes de abrir o
    teste**, sem nenhuma alteração da regra. Os positivos do teste usam os vereditos que já existem
    da rodada v3.
  - **Classificador:** *confirmado* = acusa; *descartado*, *indeterminado* ou falha da ferramenta =
    não acusa (o silêncio da traversal nunca vira acusação).
  - **Comparação:** o F1 do `M_cur` (mediana das 30) contra o F1 da traversal (um valor só — a
    regra é determinística). Descritiva, sem a régua de 1 em 6. Recall e precisão da traversal ao
    lado.
  - **Problemas técnicos da rodada nos negativos** (função que não se localiza, adaptação de
    script) são resolvidos e registrados **antes** de abrir o teste, sem nenhum resultado de
    modelo à vista. Custo projetado: ~13 h (5241 itens × ~9 s, a taxa da rodada v3 — projeção, não
    medida); um ensaio em poucos negativos vem antes, para conferir viabilidade e custo.
  - *Alternativa descartada:* tirar a linha e declarar (custo zero, mas a pergunta do orientador
    ficaria sem resposta). *Também descartado:* rodar depois de abrir o teste (pouparia a espera,
    mas qualquer remendo técnico seria decidido já sabendo o resultado dos modelos).

## 8. Arenas externas — a quantidade que decide, fixada agora

**Por que agora.** Depois de ver o BigVul, escolher entre "F1 na arena externa" e "queda de F1 do
BigVul para a arena externa" seria escolher sabendo qual das duas favorece o `M_cur`. Por exemplo:
se o `M_cur` sair abaixo no BigVul, a queda dele fica menor automaticamente.

**O que decide nas arenas externas (DECISÃO C, fechada pelo autor em 12/10): o F1 na arena
externa**, com a mesma régua do §3 e a mesma métrica (DECISÃO A), uma comparação por arena. A
queda de F1 (BigVul − arena) aparece ao lado, descritiva, calculada por repetição — a mesma
semente da Fase II prevê as duas arenas — e depois a mediana.
*Por quê:* mede direto o que a hipótese afirma (o curado detecta melhor fora da distribuição) e
não depende do rótulo ruidoso do teste do BigVul. A queda, como critério, premiaria quem foi pior
no BigVul: o ReVeal treinado no BigVul por Lu & Lagaisse deu F1 23,58 no próprio BigVul, **0,81 no
ICVul e 2,17 no VentiVul** (`PIPELINE_REVEAL.md` §6); se as nossas arenas também ficarem perto de
zero para todos os braços, a queda vira praticamente o F1 do BigVul, e "queda menor" passa a querer
dizer "pior no BigVul" — que é justamente o que o `M_cur` pode ser, por ser cobrado pelo rótulo
sujo (§4).
*Consequência para o texto:* o `main.tex` (l. 767) promete a queda; muda quando for mexido.
*Fraqueza declarada, que vale também para esta opção:* rótulos externos têm ruído próprio, não
medido; e com todos perto de zero, uma ou duas funções decidem a posição — daí a regra de piso do
adendo (abaixo).
*Alternativa descartada:* a queda de F1 como critério (é o que o `main.tex` promete hoje).

**Fica para um adendo, congelado antes de rodar as arenas externas:** quais funções entram,
deduplicação por CVE (já prevista no `main.tex`), contagem por faixa de tamanho, e uma regra de
**piso** — o que se escreve se todos os braços ficarem perto de zero, como os números de Lu &
Lagaisse sugerem.

**Execução — os mesmos modelos nas duas arenas.** A GGNN de cada braço foi salva
(`ggnn/<braço>/melhor.pt`), mas na rodada original **os modelos da Fase II não foram**: o
`treinar_fase2.py` gravava só as predições. Como o script não força determinismo na GPU, refazer
a Fase II só na hora das arenas externas poderia dar predições do BigVul diferentes das já
abertas, e seria preciso escolher entre duas versões sabendo o resultado. Por isso a Fase II é
refeita **antes de abrir o teste**, salvando os 390 modelos (§6, passo 2; ideia do autor, 12/10):
os mesmos modelos preveem o teste do BigVul e, depois, as arenas externas, e a queda descritiva
sai pareada por modelo.

## 9. O que este pré-registro não cobre

- a sonda dos anotados: os positivos dos 50 que caíram no teste entram só como evidência
  qualitativa, e é o **segundo uso** desse conjunto, declarado como tal (`main.tex`, Cronograma);
- a sonda CWE-416 e o resto do protocolo das arenas externas (§8, adendo);
- a segunda validação manual (amostra estratificada pelo veredito do filtro), que é outra coisa.

## Pendências fora deste arquivo (não bloqueiam a abertura do teste)

- `PLANO_TREINO.md` D5: o orientador ainda não concordou com relatar sempre a checagem de tamanho;
  isso muda *onde* ela aparece no texto, não *como* é calculada.
- O cartão do Notion "Treinar os braços…" ainda descreve, no corpo de 05/09, "3 sementes, média ±
  desvio" e uma tabela de 3 linhas; vale o `PLANO_TREINO.md` §5 (30 repetições, mediana e IQR).
- O `main.tex` (Treinamento dos modelos, l. 483) diz que cada braço é repetido com várias sementes
  de inicialização; na execução, a GGNN treinou uma vez por braço e só a Fase II se repete (D6).

## Histórico

- **12/10/2026** — rascunho redigido pelo Claude a pedido do autor, depois do treino dos 13 braços.
  Nenhuma métrica de teste calculada; nenhum arquivo de predição aberto. Fontes consultadas:
  `PREREGISTRO_TAMANHO.md` (SHA-256 conferido: `57c0a26f…26e8ee`, 8725 bytes, intacto),
  `PLANO_TREINO.md`, `IMPLEMENTACAO.md`, `PIPELINE_REVEAL.md` §6, `main.tex` (metodologia e
  síntese), `resposta_treinamentos_bigvul.md` (Decisão 3), o código dos três scripts citados e as
  contagens do §5.
- **12/10/2026, mesma sessão** — o autor fechou, uma por vez: **E3** (aceitou "não verificável" e
  "o V2 não se aplica"); **B** (veredito por desenho e arena; só o do principal qualifica; o do par
  segue calculado, para não mudar o congelado); **E1** (resultado geral decide a frase; a
  checagem de tamanho vai lado a lado — a proposta intermediária "V2 → inconclusivo" foi retirada
  porque o V2 sozinho não separa atalho de competência nas funções grandes); **A** (só o F1
  decide); **C** (F1 na arena externa decide; queda descritiva); **D** (traversal pura fica e
  roda nos negativos do teste antes de abrir). Por proposta do autor, a Fase II é refeita antes de
  abrir o teste salvando os modelos, e o conjunto novo é o oficial (§6, passo 2; §8). O autor
  aprovou o restante do arquivo (itens não discutidos: E4, E5, §2, §4, §6, §7, §8). Nenhuma
  métrica de teste existia em nenhum desses momentos.
- **12/10/2026 — congelado**, com a autorização do autor ("sim pode fazer tudo").
