# Adendo ao pré-registro — arenas externas (PrimeVul, VentiVul e sonda CWE-416)

> **Nota de 14/10:** o rascunho nasceu com o ICVul na vaga *cross-dataset*; o autor o trocou pelo
> PrimeVul (Decisão G0). As seções sobre o ICVul ficam como registro do que foi analisado.

> **Congelado em 15/10/2026, antes de qualquer modelo prever qualquer função de arena externa.**
> Redigido pelo Claude a pedido do autor (13–14/10), com todas as decisões fechadas pelo autor
> (Resumo, abaixo), revisado numa sessão nova em 15/10 e aprovado pelo autor (Histórico, no fim).
>
> Este arquivo **não é editado** depois do congelamento: o SHA-256 dele está no `PLANO_TREINO.md`
> §4 e nas `Notas` do cartão do Notion. Se algo precisar mudar — inclusive se a preparação
> encontrar nos dados algo que o contradiga (§10, passo 2) —, o caminho é um arquivo novo, com hash
> novo, dizendo o que mudou e por quê.

## Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3 — a consulta do
Joern que confirma ou descarta cada função que o BigVul marca como vulnerável), o dataset de grafos
(dataset v3, um grafo por função) e o modelo (ReVeal, 13 braços treinados). O teste do BigVul foi
aberto em 13/10/2026 (`IMPLEMENTACAO.md` §9). O próximo passo são as **arenas externas**: conjuntos
de avaliação que não vêm do BigVul, onde mora a pergunta do TCC — o modelo treinado com rótulos
curados (`M_cur`) generaliza melhor **fora** da distribuição de treino do que os controles sem
curadoria (`M_ctrl_g`, cinco sorteios do mesmo tamanho)? No BigVul a métrica só mede concordância
com o rótulo ruidoso do próprio BigVul (`PREREGISTRO_PRINCIPAL.md` §4); a conclusão se apoia nas
arenas externas (`main.tex`, Protocolo de avaliação).

**O que este arquivo responde.** O `PREREGISTRO_PRINCIPAL.md` (congelado em 12/10) já fixou **o que
decide** em cada arena externa: o F1 lá, contra a faixa dos 5 controles (§8, Decisão C). Ele deixou
para este adendo: quais funções entram, a deduplicação, a contagem por faixa de tamanho e a regra de
piso (§8); e a sonda CWE-416 (§9). As `Notas` do cartão "Preparar ICVul e VentiVul" acrescentaram a
traversal pura. Ao redigir apareceram mais dois pontos que nenhum texto congelado decide: **qual
versão do VentiVul** (existem duas, §1) e **como as arenas se juntam na conclusão** (Decisão M). E,
em 14/10, a arena *cross-dataset* trocou do ICVul para o **PrimeVul** (Decisão G0).

**O que ele NÃO é.**
- não muda nada dos dois pré-registros congelados; onde interpreta um texto congelado, diz (§0);
- não é resultado: nenhuma predição existe e nenhum modelo tocou arena externa. O que se contou foi
  só metadado (rótulo, CWE, commit, CVE, nome de arquivo): a CWE-416 no índice do BigVul (13/10), o
  PrimeVul lido de espelhos (14/10) e o VentiVul lido do Figshare oficial (15/10), sem guardar os
  dados (§1);
- não é o registro da preparação (download, grafos, contagens por faixa). Esse é a **ficha de
  preparação**, escrita depois, antes de abrir (§10).

**Escrito DEPOIS de abrir o BigVul — o que já se sabia, declarado.** Os dois pré-registros
anteriores foram escritos sem nenhum resultado. Este não: quando foi redigido, já se sabia que, no
teste do BigVul (5730 funções, 489 positivas; mediana das 30 repetições):
1. o `M_cur` ficou **acima** dos controles (F1 0,262 contra 0,206–0,242);
2. o `M_cur` **acusa muito menos**: taxa de falso positivo 0,082 contra 0,100–0,246 nos controles
   — então é plausível que, nas arenas externas, ele acuse quase nada;
3. a **traversal pura** (a regra congelada usada como detector) teve F1 0,270, **acima** do `M_cur`;
4. pós hoc: o ganho do `M_cur` **não aparece dentro de nenhuma faixa de tamanho**.

Cada decisão abaixo tem uma linha *"O que o BigVul poderia puxar"*, dizendo se esse conhecimento
podia inclinar a escolha e como a recomendação se protege disso.

## Resumo das decisões

| | pergunta | recomendação | status |
| --- | --- | --- | --- |
| F | Qual versão do VentiVul? | a v3 (200 CVEs, Linux + Chromium) | **fechada (13/10): v3** |
| G0 | Qual conjunto é a arena *cross-dataset*: ICVul, PrimeVul, os dois ou nenhum? | o PrimeVul no lugar do ICVul (quais partições: G4) | **fechada (14/10): PrimeVul** |
| G1 | No ICVul, quais CWEs? | só a família de memória (CWE-119/120/125/787) | **não se aplica** (G0) |
| G2 | No ICVul, quem é o negativo? | as outras funções do mesmo arquivo, como no BigVul | **não se aplica** (G0) |
| G4 | No PrimeVul, quais funções entram? | v0.1 inteiro (proposta do autor); família de memória; negativos dos mesmos commits; dedup estrita (1027 / 31.149) | **fechada (14/10): v0.1 inteiro** |
| G3 | No VentiVul, quais CWEs (e quem é o negativo)? | decide a família de memória (50 positivos, §1); o VentiVul inteiro sai ao lado; negativo = versões consertadas + funções não relacionadas das CVEs da família, como publicado | **fechada (14/10)**; negativo conferido nos dados em 15/10 |
| H | Deduplicação contra o quê, por qual chave? | treino + validação; CVE, commit e corpo da função; no PrimeVul, contra o BigVul inteiro | **fechada (14/10)**; a exceção do PrimeVul (dedup estrita) fechou junto com a G4 |
| I | Contagem por faixa e mínimo por arena | contar antes de abrir; arena com < 30 positivos ou < 30 negativos não tem veredito | **fechada (14/10)** |
| J | Regra de piso | piso = nenhum dos seis braços do desenho principal acerta mais que o acaso por mais de 2 funções; o excesso de cada braço vai para o arquivo de resultado | **fechada (14/10)**; escala declarada e excesso no resultado em 15/10 |
| K | A traversal pura entra? | sim, nas três arenas | **fechada (13/10): sim, nas três** |
| L | De onde vem a sonda CWE-416? | do próprio BigVul (330 positivas, 0 sobreposição com o treino) | **fechada (14/10)** |
| M | Como as arenas se juntam na conclusão? | "acima" só se for acima em todas as arenas com veredito | **fechada (14/10): acima em todas** |

---

## 0. O que já está fixado e só é aplicado aqui

Nada desta tabela é decisão nova.

| o quê | onde foi fixado |
| --- | --- |
| Decide o **F1**, uma comparação por arena, no desenho principal (`M_cur` contra os 5 `M_ctrl_g`) | `PREREGISTRO_PRINCIPAL.md` §3, §8 (Decisões A e C) |
| Régua: do menor ao maior dos 5 controles (mediana das 30 repetições); *acima* / *dentro* / *abaixo*; empate = dentro; *acima* por acaso 1 vez em 6 | §3, E4 |
| A **queda** de F1 (BigVul − arena), por repetição e depois a mediana, é descritiva | §8 |
| Recall, precisão, PR-AUC, MCC ao lado, mediana e IQR; `M_raw` como escala; par balanceado como sensibilidade | §7 |
| Limiar 0,5 (a classe mais provável), igual para todos | `PLANO_TREINO.md` D12 |
| Os modelos: a GGNN de cada braço (`ggnn/<braço>/melhor.pt`) e os 390 da Fase II (`fase2_v2/<braço>/modelo_<s>.pt`). **Nada é retreinado e nada é ajustado em dado de arena** — nem o Word2Vec (o modelo que transforma cada token em vetor; treinado só no treino do BigVul). Token fora do vocabulário vira vetor zero, como no BigVul (4,7% lá) | §8; `IMPLEMENTACAO.md` §4, §7 |
| Tamanho = `n_nos` do grafo exportado pelo mesmo `exportar_grafos.sc`; faixas do BigVul (até 46 \| 47–131 \| 132–339 \| 340+); mínimo de 30 positivos e 30 negativos por faixa; V1 e V2; "não verificável" e "não se aplica"; um veredito por desenho e arena, só o do principal qualifica, lado a lado com o resultado | `PREREGISTRO_TAMANHO.md` §2–§6; `PREREGISTRO_PRINCIPAL.md` E1–E5 |

**Onde este adendo interpreta ou muda um texto congelado ou o `main.tex`** (seis pontos; os textos
congelados não são editados, a mudança fica declarada aqui):
- O `main.tex` (Protocolo de avaliação) diz que a deduplicação remove das arenas "toda CVE presente
  na **partição de treino**". A Decisão H usa treino **e validação**, por CVE, commit e corpo — e,
  no PrimeVul, o BigVul inteiro. É mais conservador e muda a frase do texto.
- O §8 do principal cita, de Lu & Lagaisse, F1 **0,81 no ICVul e 2,17 no VentiVul**. São números da
  versão 1 do artigo. O 0,81 continua igual na versão 3; o 2,17 é do VentiVul v1 e, no VentiVul v3,
  o número equivalente é 8,65 (§1). O argumento do §8 (todos perto de zero → uma ou duas funções
  decidem) não muda; a citação no texto do TCC tem de dizer de qual versão é. O ICVul saiu das
  arenas (G0); o 0,81 continua valendo só como ilustração do colapso.
- O `main.tex` nomeia o **ICVul** como arena *cross-dataset* (resumo, objetivos, figura, Protocolo
  de avaliação), e o `PREREGISTRO_PRINCIPAL.md` também ("O que ele NÃO é"; §8). Pela Decisão G0, a
  vaga passa ao **PrimeVul** — muda o texto e vai para a "Pauta para o orientador". As regras do
  principal valem para a arena *cross-dataset* qualquer que seja o conjunto que a ocupa.
- O §8 do principal manda reportar a **queda** de F1 (BigVul − arena), descritiva. Ela compara o F1
  de arenas com proporções de vulneráveis diferentes (8,5% no teste do BigVul; ~1,5–3,4% nas arenas,
  Decisão M), e parte dela vem só dessa diferença. A queda é reportada como manda o principal, e o
  texto diz isso ao lado dela.
- O **mínimo por arena** (Decisão I: menos de 30 positivos ou de 30 negativos → "abaixo do mínimo",
  sem veredito) é um estado que o principal não previu: o §8 dele delegou a este adendo quais
  funções entram, a deduplicação, a contagem por faixa e o piso, não um mínimo. É a convenção de 30
  do `PREREGISTRO_TAMANHO.md` §3 estendida da faixa para a arena.

## 1. O que se sabe das fontes

Fatos, com fonte. Nada aqui é resultado do TCC.

### ICVul (registro — saiu das arenas na Decisão G0)

Lu, Li, Dehaene & Lagaisse, MSR 2025 (arXiv 2505.08503v1, lido em 13/10/2026).
- **O que é:** CVEs da NVD coletadas em 13/11/2024, só as ligadas a commit de correção no GitHub.
  807 repositórios, 146 CWEs, 4327 commits de correção, 6862 arquivos, **15.396 funções, das quais
  6276 vulneráveis (41%)** (Tabela I).
- **Só entram funções que o commit de correção alterou** — *"by only collecting functions with
  changes in the commits to ensure label accuracy, the dataset achieves a much better balance ratio
  of 41%"* (§III). Cada função é guardada nas versões antes e depois do conserto (§II-c; campo
  `before_change` da tabela `function_info`). **Consequência:** o "não vulnerável" do ICVul **não é**
  outra função do arquivo, como no BigVul; ao que tudo indica, é a versão **consertada** da própria
  função vulnerável (mais funções acrescentadas pelo conserto). *A confirmar nos dados* — §10,
  passo 2.
- **O arquivo inteiro vem junto:** `file_info.code_before` e `code_after`, e cada função tem
  `start_line` e `end_line`. Dá para gerar o CPG com o contexto do arquivo sem baixar nada.
- **ESC** (*Eliminate Suspicious Commit*, o filtro de commits do ICVul): tira, entre outros, commits
  ligados a **mais de uma CWE** e commits com 100 ou mais funções vulneráveis (§II-d). Então cada
  função tem uma CWE só.
- **Qualidade do rótulo:** 92% de rótulos corretos — Lu & Lagaisse checaram à mão **50 funções
  vulneráveis sorteadas** (From Lab to Reality, Tabela 1). É a checagem deles, n = 50.
- **Tamanho da família de memória:** funções vulneráveis por CWE (Fig. 3 do artigo do ICVul):
  CWE-125 685, CWE-119 500, CWE-787 460; a CWE-120 não está entre as cinco maiores. Então
  **~1645 funções vulneráveis** antes de qualquer filtro do TCC.
- **Referência publicada:** o ReVeal treinado no BigVul por Lu & Lagaisse deu **F1 0,81** no ICVul
  (precisão 33,33, recall 0,41, acurácia 58,89) — no ICVul inteiro (todas as CWEs), com o rótulo
  como publicado, na partição de teste deles. Igual nas versões 1 e 3 do artigo.

### VentiVul — existem duas versões

**Achado desta redação:** o VentiVul que o TCC conhece (o do PDF em
`Trabalhos Relacionados/readen/LabToReality.pdf`) é a versão 1 do artigo; o artigo foi revisado
duas vezes, e a versão 3 traz outro VentiVul, dez vezes maior.

| | **v1** (arXiv 2512.10485v1, 11/12/2025) | **v3** (arXiv 2512.10485v3, 17/08/2026) |
| --- | --- | --- |
| CVEs | 20, kernel Linux, divulgadas em maio/2025 | 200 (100 Linux + 100 Chromium), divulgadas a partir de 01/05/2025 |
| funções vulneráveis | 25 (pares antes/depois do conserto) | 263 pares (147 Chromium + 116 Linux) |
| funções no total | 25 + 835 não relacionadas, de 21 arquivos | 13.326 (Chromium 7095, Linux 6231) |
| CWEs | não informado por CVE | 39 (27 no Linux, 20 no Chromium); CVE sem CWE não entra |
| negativo | funções dos mesmos arquivos não relacionadas ao conserto | a **versão consertada** de cada vulnerável (263) **+** as funções dos mesmos arquivos não relacionadas ao conserto (12.800) |
| ReVeal treinado no BigVul, arquivo inteiro | F1 **2,17** (precisão 1,49, recall 4 = 1 de 25) | F1 **8,65** (precisão 5,25, recall 24,43) |
| dados | repositório do artigo | Figshare, doi 10.6084/m9.figshare.33263469 |

Proporção de vulneráveis na v3: 263 / 13.326 ≈ **2,0%** (bate com a precisão de 1,97 de quem acusa
quase tudo na Tabela da v3). *A coluna v3 foi transcrita da versão HTML do arXiv em 13/10/2026 por
ferramenta de leitura, não do PDF — conferir no PDF antes de pôr qualquer número no texto.* A
página do Figshare recusou a leitura automática (HTTP 403), mas a API dele responde: o artigo
33263469 traz `ventivul.csv` (11,8 MB, licença CC BY 4.0, publicado em 15/08/2026).

**Quem é o negativo do VentiVul v3 — conferido em 15/10/2026 no texto e nos dados.** No artigo (v3,
§3.2, HTML): *"The before-fix version was labeled as vulnerable, while the after-fix version was
labeled as non-vulnerable. [...] We additionally extracted functions from the same affected source
files that were unrelated to the fix and labeled them as non-vulnerable."* Na avaliação "arquivo
inteiro" (Tabela 3 da v3), as funções alteradas pelo conserto entram *"using their before-fix and
patched status"*, isto é, **a versão consertada entra como negativo**, como no PrimeVul. O README
do repositório do artigo diz o mesmo. Nos dados (`ventivul.csv`, lido em fluxo, só metadados;
scripts `estrutura_ventivul.sh` e `contar_ventivul.py` em `modelo/contagens_arenas/`):
- 13.326 linhas: **263 vulneráveis** (rótulo 1, com `pair_id`), **263 versões consertadas** (rótulo 0,
  com `pair_id`) e **12.800 não relacionadas** (rótulo 0, `pair_id = none`). Então o 263/13.326 da
  proporção já conta as consertadas no denominador;
- só as funções com par trazem CVE, CWE e `link` (o commit em `git.kernel.org` ou a revisão em
  `chromium-review`/`dawn-review.googlesource.com`). **As não relacionadas não trazem CVE**: ligam-se
  a ela pelo nome do arquivo, que codifica a CVE (`cve202523142.c` é a CVE-2025-23142;
  `cve202523142_1.c`, o segundo arquivo dela; `cve202523156_202523157.c`, um arquivo de duas CVEs).
  Os 199 nomes seguem esse padrão; 1 CVE lida de um nome não aparece nos pares, e 7 CVEs dos pares
  não têm nenhuma função não relacionada;
- **o arquivo inteiro não vem nos dados** (só as funções): para o CPG, busca-se pelo commit do
  `link` (§10). 37 dos 263 pares estão sem nome de arquivo;
- uma CWE por célula; 12 vulneráveis com `NVD-CWE-noinfo` (o artigo diz que CVE sem CWE não entra);
- 13 corpos repetidos dentro do conjunto, 10 deles com rótulos diferentes (a regra de duplicata
  interna da Decisão H os tira).

**Família de memória pela regra da G3** (negativo como na G4: rótulo 0 ligado a uma CVE que tem
positivo da família): **50 positivos** (CWE-125 26, CWE-787 19, CWE-120 5; 25 Linux e 25 Chromium;
37 CVEs) e **3326 negativos** (50 versões consertadas + 3276 não relacionadas; 850 destas estão em
arquivos compartilhados com uma CVE de fora da família). Proporção: **1,5%**. Ficam fora 10
vulneráveis CWE-122 (*heap overflow*, filha da CWE-787 na hierarquia; regra comum do §3: o treino não
teve filhas).

**O VentiVul testa o tempo, não o projeto:** Linux e Chrome também são projetos do BigVul.

### PrimeVul — a arena *cross-dataset* desde 14/10 (Decisões G0 e G4)

Ding et al., *Vulnerability Detection with Code Language Models: How Far Are We?*, ICSE 2025
(arXiv 2403.18624v2; é o `ding:2024` já citado no `main.tex`). *Lido na versão HTML por ferramenta
de leitura em 14/10/2026, não no PDF — conferir no PDF antes de pôr número no texto.*
- **Contém o BigVul:** junta os commits de segurança e as funções alteradas do **BigVul, CrossVul,
  CVEfixes e DiverseVul**, e deduplica (MD5 do corpo sem espaços, tabulações e quebras de linha).
- **Rótulo por duas regras** (é uma limpeza de rótulo independente da nossa, sem Joern):
  *OneFunc* — vulnerável se for a **única** função alterada pelo commit de segurança; *NVDCheck* —
  vulnerável se a descrição da NVD cita o nome da função, ou cita o arquivo e ela é a única
  alterada naquele arquivo.
- **Negativo:** a versão **consertada** de cada vulnerável **e todas as outras funções não
  alteradas** nos mesmos commits. É o negativo do BigVul mais as irmãs consertadas.
- **Qualidade do rótulo** (checagem manual deles, 50 funções por conjunto, Tabela I): OneFunc 86%,
  NVDCheck 92%; **BigVul 25%** pelo mesmo protocolo.
- **Tamanho:** 6968 vulneráveis e 228.800 não vulneráveis, 755 projetos, 6827 commits, 140 CWEs.
- **Partição por data do commit:** os 80% mais antigos são treino, 10% validação, os **10% mais
  recentes são teste** — 695 vulneráveis e 25.216 não vulneráveis (todas as CWEs).
- **Referência:** um modelo de linguagem de 7B parâmetros teve F1 68,26% no BigVul e 3,09% no
  PrimeVul. **Nenhum modelo de grafo** (ReVeal, Devign) foi avaliado no artigo — não há número de
  referência para o ReVeal.
- **Dados:** github.com/DLVulDet/PrimeVul (MIT). Segundo o README, a versão v0.1 traz, além de
  `primevul_test.jsonl` etc., os campos `commit_id`, `cwe`, `cve`, `file_name` e uma pasta
  `file_contents/` com cópia dos arquivos-fonte — *a conferir nos dados* (de que versão do arquivo é
  a cópia, antes ou depois do conserto).

**Contado em 14/10/2026 — só metadados** (rótulo, CWE, commit, CVE; nenhum modelo, nenhuma
predição), lidos de **espelhos públicos no Hugging Face** (`starsofchance/PrimeVul` = v0.1;
`Code-TREAT/PrimeVul_original` = teste da versão do artigo), sem guardar os dados: a v0.1 é lida em
fluxo; o teste da versão do artigo (parquet) é baixado em `/tmp` e apagado em seguida (scripts em
`modelo/contagens_arenas/`: `contar_primevul.sh`, `contar_primevul_original.sh`,
`comparar_versoes_primevul.sh`, `contar_primevul_estrito.sh`; rodam no WSL e releem os espelhos;
conferidos de novo em 15/10, todos os números abaixo reproduzem). *A refazer nos arquivos oficiais
na preparação.*
Família de memória pela regra da G4; deduplicação só por CVE e commit contra treino + validação do
BigVul (a chave do corpo não foi calculada). *Precisão:* essa referência veio das partições do
split (`traversal/split/`, 767 commits); a da Decisão H é o dataset v3, que tem 701 commits em
treino + validação (as funções sem grafo não entraram). Refeita contra o dataset v3 na preparação, a
coluna "ficam" só pode crescer. A dedup estrita (contra o BigVul inteiro) não muda.

| | vulneráveis (todas as CWEs) | não vulneráveis | **família de memória: vulneráveis / não vulneráveis dos mesmos commits** | saem por CVE / commit (vuln.) | **ficam (vuln. / não vuln.)** |
| --- | --- | --- | --- | --- | --- |
| teste, versão do artigo | 695 | 25.216 | **8 / 126** — o campo `cwe` está vazio em 659 das 695 vulneráveis | 0 / 1 | 7 / 110 |
| teste, v0.1 | 549 | 24.239 | **177 / 4935** (CWE-787 90, CWE-125 59, CWE-119 21, CWE-120 7) | 4 / 0 | **173 / 4867** |
| validação, v0.1 | 593 | 23.355 | 207 / 6190 | 3 / 0 | 204 / 5818 |
| treino, v0.1 | 4862 | 170.935 | 1575 / 41.666 | 644 / 30 | 901 / 26.401 (236 / 4867 vêm do **teste** do BigVul) |

- **As duas versões não são o mesmo conjunto.** No teste, os commits da v0.1 são um subconjunto dos
  da versão do artigo: os 534 commits com vulnerável do teste da v0.1 estão todos entre os 678 do
  teste original; os outros 144 só existem no original. Por função não se sabe: o hash de função
  das duas versões só coincide em 510 casos, provavelmente porque o algoritmo é outro. E **a versão
  do artigo não tem CWE** para 659 das 695 vulneráveis do teste (641 sem valor + 18 vazias; nem
  campo de CVE): o filtro da família de memória só é aplicável na v0.1.
- **O treino do PrimeVul é onde o BigVul mora:** 674 das 1575 vulneráveis da família (43%) saem por
  CVE ou commit, e das que ficam, 236 vêm de commits do teste do BigVul. O teste da v0.1 quase não
  encosta no BigVul (4 de 177).
- Nenhuma função da família tem CWE misturada com outra classe (a regra "todas no recorte" da G4 não
  tirou nada).

**Deduplicação estrita — contada em 14/10/2026, a partir da proposta do autor** (mesmas condições:
espelho v0.1, só metadados, só CVE e commit): tirar do PrimeVul tudo cuja CVE ou commit aparece em
**qualquer linha do BigVul** (`saida_final/indice_bigvul.csv`: 4058 commits, 3540 CVEs, todas as
CWEs e partições), e não só no treino + validação do recorte (767 commits).

| família de memória, v0.1 | vulneráveis: contra treino + validação / **contra o BigVul inteiro** | não vulneráveis: idem |
| --- | --- | --- |
| teste | 173 / **172** | 4867 / **4866** |
| validação | 204 / **203** | 5818 / **5762** |
| treino | 901 / **652** | 26.401 / **20.521** |
| **total** | 1278 / **1027** | 37.086 / **31.149** |

Com a dedup estrita, o que sobra do treino do PrimeVul são commits que **não estão no BigVul**
(610 commits com vulnerável da família) — vieram do CrossVul, do CVEfixes ou do DiverseVul.

### Sonda CWE-416 — o que o BigVul tem

Contado em 13/10/2026 em `saida_final/indice_bigvul.csv` (só metadados; script
`modelo/contagens_arenas/contar_cwe416.py`, que recebe a pasta `Dataset/bigvul`):
- **330 funções CWE-416 com `vul = 1`**, em 140 commits e 135 CVEs; **9254 com `vul = 0`** nesses
  mesmos 140 commits (o critério do `SPLIT.md` para os negativos do recorte: `vul == 0` em commit
  que tem positivo). Positivos por projeto: Chrome 137, linux 120, os outros 73.
- **Sobreposição com o recorte de memória** (os 1027 commits e 949 CVEs dos 2957 positivos,
  `traversal/split/positivos.tsv` — este 1027 é coincidência com as 1027 vulneráveis do PrimeVul da
  G4; não têm relação): **0 commits e 0 CVEs**, tanto nos positivos quanto nos
  negativos. Nenhuma CVE CWE-416 aparece no BigVul com outra CWE.
- **O rótulo é o do BigVul**, com o ruído do mesmo processo (no recorte de memória, 57,1% dos
  positivos brutos não eram o sítio da vulnerabilidade: 28 de 49 decididos, IC 95% 34,2–74,2). Para a
  CWE-416 não há medida.

---

## 2. Decisão F — qual VentiVul (fechada pelo autor em 13/10: a v3)

**Recomendação, aceita: a v3.**
- *Por quê:* 263 funções vulneráveis contra 25. Com 25, cada função muda o recall em 4 pontos e a
  arena fica abaixo do mínimo de 30 positivos da Decisão I — sem veredito, só descritiva. É também a
  versão atual do artigo.
- *Contra:* traz o Chromium, que é C++ (o Joern lê C++; o BigVul também tem Chrome). E o número de
  referência do §8 do principal (2,17) passa a ser outro (8,65), o que só muda a citação.
- *Se a v3 não puder ser obtida:* usa-se a v1, declarada, e ela cai na Decisão I.
- *Alternativa:* a v1 (a do PDF que o TCC já leu e cita).
- *O que o BigVul poderia puxar:* nada direto — a escolha é pelo tamanho, que se conhece sem
  modelo.

## 2b. Decisão G0 — qual conjunto é a arena *cross-dataset* (fechada pelo autor em 14/10: PrimeVul)

**As quatro arenas do `main.tex`:** (1) teste do BigVul, dentro da distribuição; (2) ICVul,
*cross-dataset*; (3) VentiVul, temporal; (4) sonda CWE-416, entre classes. As duas externas são a 2
e a 3; a 1 e a 4 vêm do próprio BigVul. Esta decisão é sobre a vaga 2.

**O que a vaga 2 precisa entregar:** (i) rótulo melhor que o do BigVul, para medir detecção e não
concordância com ruído; (ii) funções que os modelos não viram (depois da Decisão H); (iii) a mesma
tarefa do treino — achar a função vulnerável entre as funções do arquivo/commit; (iv) pelo menos 30
positivos da família de memória depois das perdas (Decisão I).

| | **ICVul** | **PrimeVul** (partição de teste) |
| --- | --- | --- |
| rótulo, checagem manual (n = 50) | 92% (Lu & Lagaisse) | 86% OneFunc / 92% NVDCheck (Ding et al.; BigVul 25% no mesmo protocolo) |
| como o rótulo foi limpo | filtro de commits suspeitos (ESC) | só função única do commit ou citada na NVD |
| negativo como publicado | só a irmã consertada → tarefa diferente do treino (§3, G2) | irmã consertada **+ todas as não alteradas do commit** → quase a tarefa do treino |
| usar como publicado? | não serve (G2 a); exige negativo montado pelo TCC (G2 b) | sim |
| sobreposição com o BigVul | parcial (mesmas CVEs antigas no GitHub) | **estrutural** (o BigVul é uma das fontes); o teste é a fatia mais recente, onde deve haver menos — a deduplicação (H) mede |
| contexto do arquivo | `code_before` incluído | `file_contents/` (a conferir) |
| número de referência do ReVeal | 0,81 (na montagem deles) | nenhum |
| já está no `main.tex` | como arena (resumo, objetivos, figura) | só na fundamentação |

**Recomendação, aceita: (b) o PrimeVul no lugar do ICVul** — como publicado, filtrado à família de
memória e deduplicado pela Decisão H. *(A recomendação inicial era só a partição de teste; a G4
fechou o v0.1 inteiro com deduplicação estrita. A tabela acima e os contras abaixo foram escritos
pensando no teste; a mudança está na G4.)*
- *Por quê:* é o único dos dois que serve **sem montagem nossa** — o negativo dele já inclui as
  funções não alteradas do commit, como no BigVul; a limpeza de rótulo é documentada, independente
  da traversal e checada à mão; e o teste dele é a fatia mais recente, o que reduz a sobreposição com
  o BigVul.
- *Contra:* (1) o BigVul está dentro dele — a remoção pela Decisão H pode ser grande, e o número
  removido vai para o texto; (2) as irmãs consertadas entram como negativo, o que deixa a arena um
  pouco mais difícil que o treino (são no máximo tantas quantas as vulneráveis, contra ~36 não
  alteradas por vulnerável no teste inteiro: 25.216 / 695); (3) a regra OneFunc escolhe commits que
  tocam uma função só — exatamente onde o BigVul tem menos ruído —, então os positivos do PrimeVul
  são os casos "fáceis de rotular"; (4) não há número publicado do ReVeal; (5) troca a arena nomeada
  no resumo, nos objetivos e na figura do `main.tex`, e convém avisar o orientador (item para a
  "Pauta para o orientador").
- *Alternativas:* (a) o ICVul com o negativo montado como no BigVul (G2 b); (c) os dois — pela
  Decisão M, mais uma arena só torna o "acima em todas" mais difícil, nunca mais fácil, mas soma
  preparação e Joern; (d) nenhuma — só o VentiVul decide, e o texto passa a ter três arenas.
- *Se o PrimeVul ficar:* G1 e G2 deixam de existir; a regra de CWE da família de memória (§3,
  regras comuns) vale para ele pelo campo `cwe`.
- *O que o BigVul poderia puxar:* nada previsível — a escolha é pela definição do negativo, pela
  checagem do rótulo e pela disponibilidade, que não dependem de qual braço ganhou.

## 3. Decisão G — quais funções entram

**Regras comuns (consequência do treino, não decisão):** a família de memória é a do recorte do
BigVul — **os mesmos 4 identificadores** (CWE-119, CWE-120, CWE-125, CWE-787), sem filhos da
hierarquia da CWE (CWE-121, CWE-122…), porque o treino não teve filhos; a CWE vem do metadado do
próprio conjunto (PrimeVul: campo `cwe`; VentiVul: coluna `cwe_id`); o positivo é a versão
**antes** do conserto; cada função é extraída do arquivo inteiro na versão a que pertence (antes do
conserto para as vulneráveis e as não alteradas; depois, para as irmãs consertadas do PrimeVul e do
VentiVul), com o mesmo recorte de função do dataset v3.

**Ordem das operações (vale para as três arenas):** o negativo é definido pelo rótulo publicado,
**antes** de qualquer perda. "Commit (ou CVE) que tem positivo da arena" conta os positivos antes
da deduplicação e das falhas de extração; se um positivo sai depois (pela chave do corpo, por
duplicata interna ou por falha), os negativos do commit dele ficam. É o que o BigVul fez: no dataset
v3 ficaram 665 negativos em 39 commits cujo positivo se perdeu.

### G4 — PrimeVul: quais funções entram (fechada pelo autor em 14/10: v0.1 inteiro, dedup estrita)

**O que ficou decidido:**
- **Versão: a v0.1** (a mais recente, dos mesmos autores). Uma redação anterior dizia "a versão do
  artigo"; a contagem do §1 mostrou que ela **não tem CWE** para 659 das 695 vulneráveis do teste,
  então o filtro da família de memória não se aplica a ela. A relação entre as duas é declarada
  só no que foi visto: no teste, os 534 commits com vulnerável da v0.1 estão todos entre os 678 da
  do artigo; por função não se sabe (§1).
- **Partições: as três** (`primevul_train.jsonl`, `primevul_valid.jsonl`, `primevul_test.jsonl`) —
  proposta do autor; o TCC não treina no PrimeVul, então a partição dele não importa. A
  recomendação anterior era só o teste, por medo de que a parte antiga do PrimeVul fosse o próprio
  BigVul rerrotulado; a **deduplicação estrita** da Decisão H (contra o BigVul inteiro) resolve isso:
  sai tudo que tem CVE, commit ou corpo no BigVul.
- **Positivo:** função com `target = 1` cuja CWE está entre os 4 identificadores. Se o campo listar
  mais de uma CWE, entra só se **todas** estiverem entre os 4 (mistura de classes não entra, e é
  contada) — o mesmo espírito do ESC do ICVul e da sonda separada.
- **Negativo:** toda função com `target = 0` de um commit que tem pelo menos um positivo da arena —
  o critério do `SPLIT.md` para os negativos do recorte. Isso traz junto, como no PrimeVul publicado,
  as irmãs consertadas e as não alteradas.
- **Arquivo-fonte:** da própria v0.1; se não vier, busca-se pelo commit, como no BigVul
  (`buscar_arquivo.py`); se nem assim, é falha contada (§10).
- **Não se usam** os arquivos `*_paired.jsonl` (avaliação por pares, fora do escopo — §11).
- **Quanto dá** (§1, antes da chave do corpo e das falhas de extração): **1027 vulneráveis e 31.149
  não vulneráveis** (3,2% de vulneráveis), quase 6× o teste sozinho.
- *Por quê:* mais vulneráveis deixam o F1 de cada braço mais estável (menos peso de cada função) e
  aumentam a chance de as quatro faixas de tamanho terem 30 positivos, o que deixa o V1 e o V2
  aplicáveis (Decisão I).
- *Contra:* custo — ~65 h de traversal pura (Decisão K) e uma extração de grafos do tamanho da do
  BigVul (~32 mil funções). E a arena mistura épocas: a parte antiga é da mesma época do BigVul,
  então ela mede "outro conjunto", não "outro tempo" — o tempo é a pergunta do VentiVul.
- *Alternativas, com os números do §1:*

  | opção (dedup estrita) | vulneráveis / não vulneráveis que ficam | traversal pura |
  | --- | --- | --- |
  | só o teste | 172 / 4866 | ~10 h |
  | teste + validação | 375 / 10.628 | ~22 h |
  | **inteiro (recomendada, proposta do autor)** | **1027 / 31.149** | **~65 h** |

  Sem a dedup estrita (só contra treino + validação), o inteiro daria 1278 / 37.086, mas 238 / 4924
  delas viriam do teste do BigVul. Tirar as irmãs consertadas dos negativos continua sendo outra
  alternativa (tarefa igual à do treino, mas deixa de ser o PrimeVul como publicado).
- *O que o BigVul poderia puxar:* nada direto.

### G1 — ICVul: quais CWEs (não se aplica desde 14/10 — registro)

**Recomendação: só a família de memória.** O `main.tex` descreve o ICVul como "outra amostra do
**mesmo problema**". O treino só viu erros de memória; avaliar em 146 CWEs misturaria a pergunta
desta arena com a da sonda (transferência entre classes).
- *Contra:* o número não se compara com o 0,81 de Lu & Lagaisse (eles usaram todas as CWEs).
- *Alternativa:* o ICVul inteiro.
- *O que o BigVul poderia puxar:* nada direto.

### G2 — ICVul: quem é o negativo (não se aplica desde 14/10 — registro)

É a decisão que mais muda o significado da arena (e o motivo de o ICVul ter sido trocado).

- **(a) Como o ICVul publica:** negativo = a versão consertada da função (e as funções acrescentadas
  pelo conserto). O F1 passa a medir se o modelo **distingue a função vulnerável da irmã
  consertada** — tarefa que o treino nunca pediu (no BigVul do TCC o negativo é outra função do
  arquivo) e em que os modelos de aprendizado profundo quase não acertam: no VentiVul v1, o ReVeal
  treinado no BigVul diferenciou **0 de 25 pares** (Lu & Lagaisse, Tabela 7). Espera-se o piso
  (Decisão J) para todos os braços.
- **(b) Como no BigVul (recomendada):** negativo = as **outras funções do mesmo arquivo**, que o
  conserto não tocou, tiradas do `code_before` — um método do CPG do arquivo cujo intervalo de
  linhas não cruza o de nenhuma função alterada por aquele commit naquele arquivo. É a mesma regra
  do BigVul e do VentiVul "arquivo inteiro". As três arenas passam a medir **a mesma tarefa que o
  treino ensinou** — achar a função vulnerável entre as do arquivo —, e o ICVul contribui o que tem
  de melhor: positivos com rótulo checado e filtrado pelo ESC.
  - *Contra:* é uma montagem do TCC **sobre** o ICVul, não o ICVul como publicado — o número não se
    compara com o de ninguém; e o negativo herda a suposição do BigVul ("não tocada pelo conserto =
    não vulnerável"). Custo: muito mais funções (Decisão K).
- *O que o BigVul poderia puxar:* nada direto; a escolha não depende de qual braço acusa mais.

### G3 — VentiVul: quais CWEs e quais funções entram (CWEs fechadas pelo autor em 14/10: a recomendada, c; negativo conferido nos dados em 15/10)

- **(a)** o VentiVul inteiro decide (todas as CWEs) — compara com o 8,65 publicado, mas mistura o
  tempo com a troca de classe, que é a pergunta da sonda;
- **(b)** só a família de memória decide, e o resto não é calculado;
- **(c) recomendada:** **decide a família de memória**; o VentiVul inteiro aparece ao lado, só
  descritivo, para conferir a ordem de grandeza contra o 8,65 (o `M_raw` é o braço comparável).
  **Troca automática, fixada agora:** se a família de memória tiver menos de 30 positivos depois da
  deduplicação e das falhas (Decisão I), o veredito passa para o VentiVul inteiro, e a frase do
  texto diz que ali tempo e classe estão misturados. O número de positivos por CWE se conhece na
  preparação, sem modelo nenhum.
- **Quais funções entram** (estrutura conferida nos dados em 15/10, §1):
  - **positivo:** função com rótulo 1 cuja `cwe_id` está entre os 4 identificadores;
  - **negativo:** toda função com rótulo 0 ligada a uma CVE que tem pelo menos um positivo da
    família: a versão consertada de cada vulnerável (mesmo `pair_id`) e as funções não relacionadas
    dos arquivos daquela CVE (ligadas pelo nome do arquivo, §1). Arquivo de mais de uma CVE entra se
    uma delas for da família. É a regra da G4 com "CVE" no lugar de "commit" (no VentiVul os
    arquivos são organizados por CVE), e é o VentiVul como publicado na avaliação "arquivo inteiro";
  - **o VentiVul inteiro** (ao lado, ou com veredito se a troca automática disparar): todas as
    13.326 funções, 263 positivas e 13.063 negativas;
  - **arquivo-fonte:** não vem nos dados; busca-se pelo commit indicado em `link` (o dos pares da
    CVE), e cada função é localizada no CPG do arquivo como no BigVul; falha é contada (§10).
- **Consequência:** as duas arenas da síntese (Decisão M) têm o mesmo tipo de negativo: a irmã
  consertada mais as funções do mesmo arquivo que o conserto não tocou.
- **Quanto dá** (§1, antes da deduplicação e das falhas): 50 positivos e 3326 negativos (1,5%). A
  troca automática só dispara se mais de 20 dos 50 positivos se perderem.
- *O que o BigVul poderia puxar:* nada direto.

## 4. Decisão H — deduplicação (fechada pelo autor em 14/10)

**Por que existe.** BigVul, PrimeVul e VentiVul saem todos de commits de correção e podem conter a
mesma vulnerabilidade, o mesmo commit ou o mesmo corpo de função. Se o modelo viu a função no treino,
acertá-la na arena não é generalizar. E **importa para a comparação**, não só para o número: os
braços diferem nos positivos de treino, então um positivo de treino que reaparece na arena ajuda os
braços que o tinham e não os outros. (Os negativos de treino são os mesmos 14.394 em todos os
braços do desenho principal.)

**Recomendação:**
- **Referência = tudo o que os modelos tocaram:** as funções das partições de **treino** (ajustou os
  pesos e o Word2Vec) e **validação** (escolheu a época) do dataset v3, positivas e negativas. O
  teste do BigVul não entra: nenhum modelo o viu.
- **Três chaves, aplicadas nesta ordem:**
  1. **CVE** — sai da arena toda função de uma CVE que aparece na referência;
  2. **commit** — sai toda função de um commit que aparece na referência (o mesmo conserto com outro
     número de CVE);
  3. **corpo** — sai toda função da arena cujo corpo normalizado é igual ao de alguma função da
     referência (positiva ou negativa). Normalização: a do `traversal/normalizar_corpo.py`
     (`hash_corpo`: comentários removidos, espaços colapsados), o mesmo módulo que já gerou os
     hashes do BigVul.
- **Exceção do PrimeVul — dedup estrita (14/10, a partir da proposta do autor na G4):** como o
  PrimeVul foi montado **a partir** do BigVul, nele a referência das três chaves é o **BigVul
  inteiro** (todas as linhas do `indice_bigvul.csv`, todas as CWEs e partições; o corpo pelo
  `func_before` do `all_c_cpp_release2.0.csv`), não só treino + validação. Assim a arena
  *cross-dataset* não contém nada que tenha vindo do BigVul — nem do teste dele, que nenhum modelo
  viu. No VentiVul e na sonda vale a referência de treino + validação (o VentiVul só tem CVEs
  divulgadas a partir de maio de 2025; a sonda **é** o BigVul).
- **Direção:** sai sempre a função da arena. **Nada muda no treino** — mexer nele mudaria o `M_cur`
  depois de medido.
- **Duplicata dentro da mesma arena** (mesmo corpo normalizado mais de uma vez): mesmo rótulo →
  fica uma cópia (a de menor identificador); rótulos diferentes → saem todas (o rótulo daquele corpo
  é indefinido).
- **Entre arenas não se deduplica:** nenhuma treina nada.
- **Reporta-se**, por arena: quantas saíram por CVE, por commit, por corpo e por duplicata interna,
  separado em positivas e negativas. É número para o artigo (`main.tex`, Cronograma, etapa 5).

*O que esperar (não medido):* o VentiVul só tem CVEs divulgadas a partir de maio de 2025, então CVE
e commit não podem coincidir com o BigVul; só o corpo (funções antigas do Linux e do Chrome que não
mudaram). Dentro dele há 13 corpos repetidos, 10 com rótulos diferentes (§1), que a regra de
duplicata interna tira. O PrimeVul **contém o
BigVul**, e a remoção se concentra no treino dele: com a dedup estrita, saem 932 das 1959
vulneráveis da família e 21.642 das 52.791 não vulneráveis, por CVE e commit (§1; a chave do corpo
ainda não foi calculada). A sonda tem 0 por CVE e por commit (§1); só o corpo pode tirar alguma coisa.

- *Alternativas:* só a CVE (o que o `main.tex` diz hoje); só a partição de treino; aplicar a chave do
  corpo só aos positivos.
- *O que o BigVul poderia puxar:* nada — a deduplicação é aplicada antes de qualquer modelo e não
  olha braço.

## 5. Decisão I — contagem por faixa e mínimo por arena (fechada pelo autor em 14/10)

**O que já está fixado (§0):** as faixas, o mínimo de 30 por faixa, "não verificável" e "não se
aplica" (E3). Contar quantas funções caem em cada faixa não é ver resultado
(`PREREGISTRO_TAMANHO.md` §3).

**Recomendação:**
- **Quando:** depois das Decisões G e H e dos grafos exportados, **antes de qualquer modelo prever
  qualquer função da arena**. As contagens (positivas e negativas por faixa, por arena) vão para a
  ficha de preparação (§10), com o SHA-256 dela.
- **O que a contagem decide, mecanicamente** (nada aqui é escolha depois de contar):

  | se a arena tiver… | então… |
  | --- | --- |
  | ≥ 30 positivos numa faixa | F1 e recall daquela faixa entram na tabela |
  | ≥ 30 negativos numa faixa | taxa de falso positivo daquela faixa entra |
  | ≥ 30 negativos nas faixas até 46 **e** 340+ | o V1 (o atalho) se aplica |
  | ≥ 30 positivos em pelo menos uma faixa pequena (até 46 ou 47–131) | o V2 se aplica, contando só as faixas com 30 |
  | nem V1 nem V2 aplicáveis | veredito de tamanho "não verificável" (E3) |

- **Novo — mínimo por arena:** a arena inteira só tem veredito (o *acima / dentro / abaixo* do §3
  do principal) se tiver **pelo menos 30 positivos e 30 negativos** depois da deduplicação e das falhas. Abaixo
  disso, entra com as métricas e a contagem, como **"abaixo do mínimo"**, sem veredito. É a mesma
  convenção de 30 do `PREREGISTRO_TAMANHO.md` §3 (convenção, não valor derivado), estendida da faixa
  para a arena.
- *Expectativa (não medida por faixa):* a sonda (330 positivos) e o PrimeVul (1027 depois da dedup
  estrita por CVE e commit, §1) passam do mínimo por arena e devem ter faixas com 30. A família de
  memória do VentiVul tem 50 positivos antes das perdas (§1): passa do mínimo com margem de 20, mas no
  máximo uma faixa pode chegar a 30 (30 + 30 > 50). Se for uma das grandes, o V2 "não se aplica" lá
  (E3).
- *O que o BigVul poderia puxar:* nada — é contagem.

## 6. Decisão J — regra de piso (fechada pelo autor em 14/10)

**O problema.** Lu & Lagaisse mostram o ReVeal treinado no BigVul quase cego fora dele (F1 0,81 no
ICVul; 2,17 no VentiVul v1). Se todos os braços ficarem perto de zero, uma ou duas funções decidem
quem fica "acima" (§8 do principal), e escrever "o curado generaliza melhor" seria ler ruído.
*Ressalva:* esses dois números são do ICVul (que saiu das arenas, G0) e do VentiVul v1. No VentiVul
v3, que esta arena usa, o mesmo artigo dá F1 8,65 (precisão 5,25%, recall 24,43%, arquivo inteiro).
Pela conta do excesso, abaixo, isso é ~64 vulneráveis acertadas contra ~24 esperadas do acaso: sinal,
não colapso (conta feita aqui a partir dos números publicados, lidos no HTML). O piso existe para o
caso de colapso, que pode ou não acontecer.

**A ideia: comparar cada braço com o acaso.** Um braço que acusa *A* funções numa arena com *P*
vulneráveis entre *N* funções acertaria, sorteando, *A × P / N* vulneráveis em média. O
**excesso sobre o acaso** é quantas vulneráveis ele acertou **a mais** que esse sorteio:

> excesso = VP − A × P / N  (VP = verdadeiros positivos; calculado em cada uma das 30 repetições; o
> valor do braço é a mediana)

Quem acusa **tudo** tem excesso zero (acerta todas as vulneráveis, mas o sorteio de *N* também);
quem acusa **nada** também tem excesso zero.

**Recomendação:**
- **Uma arena está no piso** quando **nenhum dos seis braços do desenho principal** (`M_cur` e os 5
  controles) tem excesso mediano **maior que 2 funções**. O "2" vem da própria frase congelada do §8
  do principal ("uma ou duas funções decidem a posição"); é convenção, como o 30.
- **Escala, declarada (15/10).** O "2" é um número absoluto, e a sorte cresce com a arena. Conta
  ilustrativa, não dado (supõe que os braços acusem ~10% das funções, como no BigVul): na família
  de memória do VentiVul (50 vulneráveis em 3376 funções), um braço que acusasse ~340 funções **ao
  acaso** acertaria 5 ± 2, e aí o "2" é uma barreira de verdade. No PrimeVul (1027 em ~32 mil), um
  braço que acusasse ~3 mil ao acaso acertaria 96 ± 9: passar de 2 acima do acaso é comum só por
  sorte, e com seis braços quase sempre algum passa. **No PrimeVul o piso dificilmente dispara,
  mesmo com os seis braços cegos;** lá, quem protege a leitura é a régua de 1 em 6 (§3 do principal). E
  como o F1 de quem acusa ao acaso cresce com o número de acusações, um colapso no PrimeVul tende a
  pôr *abaixo* o braço que menos acusa (no BigVul, o `M_cur`).
- **O excesso mediano de cada braço** (os seis e o `M_raw`) vai para o arquivo de resultado, ao lado
  das métricas descritivas do §7 do principal. Não decide nada: mostra se um *abaixo* veio de
  detectar menos ou só de acusar menos. O script já o calcula para o piso.
- **O piso não muda a posição; muda o que se escreve.** A posição do §3 do principal é calculada e
  aparece na tabela. O texto diz: *"na arena X, nenhum dos seis braços acertou mais que o acaso por mais de
  duas funções; a posição do `M_cur` não é lida como evidência a favor nem contra a hipótese"* — e o
  colapso em si é relatado como achado (como o de Lu & Lagaisse no ICVul e no VentiVul v1).
- **Não pode:** "o `M_cur` generaliza melhor" ou "pior" numa arena no piso.
- **Checagem de tamanho no piso:** calculada e relatada como na linha "dentro ou abaixo" do E1 (se
  houver evidência: "pegou o atalho e não lucrou com ele").
- **A arena no piso não conta na síntese** (Decisão M).

**Por que o excesso, e não uma regra mais simples** — exemplo inventado, uma arena com 100
vulneráveis entre 5000 funções (2%):

| cenário | P1: "todo braço acerta ≤ 2" | P2: "maior F1 abaixo do F1 de acusar tudo (3,9%)" | **excesso** |
| --- | --- | --- | --- |
| todos acusam quase nada (VP 0–1) | piso ✔ | piso ✔ | piso ✔ |
| o `M_cur` acusa as 5000 (VP 100, F1 3,9%); os controles acusam ~10 com VP 0–1 (F1 ≤ 1,8%) | **não é piso** → "`M_cur` acima" ✘ | **não é piso** (3,9% não é *abaixo* de 3,9%) → "acima" ✘ | excesso do `M_cur` = 100 − 5000 × 2% = 0 → piso ✔ |
| um controle acusa 200 com VP 20 (excesso 16) | não é piso ✔ | não é piso ✔ | não é piso ✔ — a posição é lida normalmente |

O segundo cenário é o que importa: **acusar tudo não é detectar**, e só o excesso enxerga isso.

- *Alternativas:* P1; P2; nenhuma regra de piso (vale o §3 do principal como está, e empate conta
  como dentro); uma barreira que cresça com a arena (não adotada na revisão de 15/10: seria um
  número novo sem frase congelada que o justifique).
- *O que o BigVul poderia puxar:* **este é o ponto mais sensível.** No BigVul o `M_cur` acusa bem
  menos que os controles; então é plausível que, nas arenas, ele fique perto de zero — e uma regra
  de piso pode parecer feita para protegê-lo de um "abaixo". **Na forma**, ela é simétrica: bloqueia
  "abaixo" e "acima" do mesmo jeito, e só dispara quando **os seis** estão sem sinal. Se algum
  controle tiver sinal e o `M_cur` não, não é piso, e o "abaixo" vale. **No efeito**, depende do
  tamanho da arena (Escala, acima): nas pequenas, ela pode impedir um *abaixo* do `M_cur` que viria
  só de acusar menos; no PrimeVul quase não dispara, e não protege ninguém.

## 7. Decisão K — a traversal pura entra? (fechada pelo autor em 13/10: sim, nas três)

**O que é.** A regra congelada da traversal v3 usada como detector: *confirmado* = acusa;
*descartado*, *indeterminado* ou falha da ferramenta = não acusa (§7 do principal). Responde a
pergunta do orientador de 05/09: "a rede aprendeu só o que o Joern já faz?". Comparação descritiva:
F1 do `M_cur` (mediana das 30) contra o F1 da regra (um valor só; ela é determinística), sem régua.

**Recomendação: sim, nas três arenas**, no conjunto que tem veredito em cada uma.
- **Como:** a regra congelada, sem nenhuma alteração (hash dos 4 arquivos conferido antes de rodar),
  pelo mesmo executador da rodada nas negativas do BigVul (`rodar_traversal_negativos.py`, adaptado
  só no caminho dos arquivos), no mesmo método de onde sai o grafo. Grava só a **evidência**; o
  veredito é aplicado pelo script de análise, na abertura (como no BigVul).
- **Quando:** antes de qualquer modelo prever a arena. Problema técnico é resolvido e registrado
  antes.
- **Custo** (projeção, não medida: mediana de 7,3 s por função na rodada das 5241 negativas do
  BigVul, `TRAVERSAL_NEGATIVOS_TESTE.md` — ~2 h por mil funções):

  | arena | funções (antes das perdas) | projeção |
  | --- | --- | --- |
  | sonda CWE-416 | 330 + 9254 | ~19 h |
  | VentiVul v3, família de memória | 50 + 3326 (§1) | ~7 h (~27 h se a troca automática da G3 levar ao inteiro) |
  | PrimeVul v0.1 inteiro, família de memória, dedup estrita | 1027 + 31.149 (§1, depois de CVE e commit) | ~65 h |

  O total fica em **~3,8 dias de Joern** (~4,6 se a troca automática da G3 disparar), rodado em
  primeiro plano com `--retomar` (o processo em segundo plano morre quando o WSL desliga —
  `CLAUDE.md`, Ambiente).
- *Por que nas três:* a pergunta do orientador é a mesma em toda arena; escolher arena por arena
  seria escolher já sabendo como a regra foi no BigVul.
- *Alternativas:* (b) só as duas arenas externas — na sonda a regra é de erro de buffer, e o que ela mede
  em use-after-free é se o padrão de buffer dispara ali (é a mesma pergunta de transferência, mas
  custa ~19 h); (c) nenhuma, declarado.
- *O que o BigVul poderia puxar:* **sensível.** No BigVul a regra ficou acima do `M_cur` (0,270
  contra 0,262). Tirá-la agora pareceria esconder uma comparação desfavorável; mantê-la nas três é a
  escolha que não depende de ela ser favorável ou não.

## 8. Decisão L — a sonda CWE-416 (fechada pelo autor em 14/10)

**O que é.** *Use-after-free* (CWE-416, uso de memória depois de liberada) ficou de fora do treino
de propósito: a base de consultas do Joern não tem traversal confiável para ela (`main.tex`,
Definição das classes). A sonda mede se um modelo treinado em erros de **buffer** acusa uma classe
que nunca viu. O `main.tex` prevê desempenho baixo para todos.

**Recomendação: (a) a CWE-416 do próprio BigVul.**
- **Funções:** as 330 com `vul = 1` e as 9254 com `vul = 0` nos mesmos commits (§1) — o mesmo
  critério dos negativos do recorte. Extraídas pelo **mesmo caminho que gerou o dataset v3**
  (arquivo no commit pai, CPG, localização da função, exportação do grafo), sem regra nova; falha
  sai e é contada (§10).
- **Por quê:** a construção é idêntica à do treino; a única coisa que muda é a classe. É o que o
  `main.tex` descreve ("amostras de use-after-free deliberadamente excluídas do treino"), e a
  sobreposição com o recorte é zero por CVE e por commit.
- **Deduplicação:** a da Decisão H (na prática, só o corpo).
- **Leitura:** a régua do §3 do principal, o piso da Decisão J e o mínimo da Decisão I. **O rótulo é o do
  BigVul**, então vale para a sonda a leitura do §4 do principal: mede **concordância com o rótulo
  do BigVul** em use-after-free, não detecção; um *abaixo* tem as duas leituras de lá.
- **A sonda não entra na síntese das arenas externas** (Decisão M): ela responde outra pergunta
  (transferência entre classes, não generalização da mesma classe).
- *Contra:* rótulo ruidoso; 137 dos 330 positivos são do Chrome e 120 do Linux, então a sonda é
  quase só dois projetos.
- *Alternativa:* (b) a CWE-416 do PrimeVul ou do VentiVul — rótulos melhores, mas mistura troca de
  conjunto com troca de classe.
- *O que o BigVul poderia puxar:* como o rótulo é o do BigVul, o que levou o `M_cur` a "acima" no
  teste do BigVul (concordar mais com esse rótulo) pode se repetir aqui — por isso a leitura é a do
  §4 do principal (concordância), não a de detecção.

## 9. Decisão M — como as arenas se juntam na conclusão (fechada pelo autor em 14/10: acima em todas)

**O buraco.** Os textos congelados dão um veredito **por arena**, mas não dizem o que a conclusão do
TCC afirma quando as duas arenas externas (na redação original, ICVul e VentiVul; desde a G0,
PrimeVul e VentiVul) discordam. Com duas arenas, a chance de *acima* em **pelo
menos uma** por puro acaso fica entre 1 em 6 (se as duas arenas sempre ordenassem os braços igual) e
~31% (se fossem independentes: 1 − (5/6)²). Os mesmos modelos preveem as duas, então a dependência
real fica no meio e não se conhece.

**Recomendação:**
- **Entram na síntese** o PrimeVul e o VentiVul que tiverem veredito (nem "abaixo do mínimo", nem piso).
  O BigVul não (mede concordância com rótulo ruidoso), nem a sonda (outra pergunta).
- **"Evidência a favor da hipótese" só se o `M_cur` ficar *acima* em TODAS as arenas da síntese.**
  Chance disso por acaso: **no máximo 1 em 6**, qualquer que seja a dependência entre as arenas
  (ficar acima nas duas nunca é mais provável que ficar acima numa) e 1 em 36 se fossem
  independentes. Nunca "prova".
- **O que se escreve em cada caso:**

  | arenas da síntese | o texto diz |
  | --- | --- |
  | todas *acima* | evidência a favor (com a chance acima e o veredito de tamanho de cada arena, E1) |
  | algumas *acima*, as outras *dentro* | resultado misto, arena por arena; a hipótese não se confirma de forma consistente |
  | todas *dentro* | a curadoria não se distinguiu dos controles fora da distribuição — a resposta que o `main.tex` já prevê como publicável ("reduziu o conjunto sem limpá-lo de forma útil") |
  | alguma *abaixo* | relatada; se houver *acima* em outra, o texto diz que as arenas se contradizem |
  | nenhuma com veredito | as arenas externas não permitiram avaliar a hipótese; o colapso é relatado como achado |

- **Não pode:** comparar o F1 de uma arena com o de outra como se fosse a mesma escala — a proporção
  de vulneráveis muda (~1,5% na família de memória do VentiVul, ~2% no VentiVul inteiro, ~3,4% na
  sonda e ~3,2% no PrimeVul, antes das perdas; 8,5% no teste do BigVul), e o F1 muda junto. A queda
  de F1 do §8 do principal (BigVul − arena) é reportada como ele manda, mas é justamente essa
  comparação: o texto diz, ao lado dela, que parte da queda vem só da proporção (§0).
- *Contra:* exigir todas é exigente — um efeito real que apareça só numa arena vira "misto".
- *Alternativa (descartada):* fixar agora **uma arena primária** (por exemplo o PrimeVul: maior e
  com rótulo checado) e a outra como secundária. Mantém o 1 em 6 exato com uma comparação só, mas a escolha
  da primária tem de ser justificada sem olhar nada.
- *O que o BigVul poderia puxar:* nada direto; a regra vale igual para *acima* e *abaixo*.

## 10. Ordem de preparação e de abertura

1. **Congelar este adendo** (SHA-256 no `PLANO_TREINO.md` §4 e no Notion).
2. **Obter os dados e confirmar a estrutura.** PrimeVul v0.1 (Google Drive do repositório oficial —
   as contagens do §1 vieram de espelhos e são refeitas nos arquivos oficiais; diferença é
   registrada e vale o oficial), VentiVul v3 (Figshare) e a CWE-416 do índice do BigVul. Conferir
   nos dados o que §1 supõe — em especial: no PrimeVul, a definição do negativo e de que versão é o
   arquivo em `file_contents/`; no VentiVul (estrutura já vista em 15/10, §1), o arquivo inteiro,
   que não vem nos dados e se busca pelo commit do `link`, e a correspondência entre as funções do
   `ventivul.csv` e as do CPG do arquivo. **Se algo contradisser este adendo, parar** e escrever um
   adendo novo antes de seguir.
3. **Montar as arenas** — filtros da Decisão G, deduplicação (H), arquivo, CPG, grafo — e escrever a
   **ficha de preparação**: contagens por arena e por faixa (I), removidas por motivo e rótulo, falhas
   por motivo e rótulo, taxa de tokens fora do vocabulário. Falha técnica (arquivo que não se obtém,
   parse que quebra, função que não se localiza) tira a função e é contada; tudo se resolve **antes**
   de qualquer modelo tocar a arena. SHA-256 da ficha registrado.
4. **Rodar a traversal pura** (Decisão K) — só evidência, sem veredito.
5. **Script de inferência** (GGNN + Fase II nas arenas). Conferência de reprodução: rodado nos
   grafos do **teste do BigVul** (já aberto), ele tem de reproduzir as predições gravadas em
   `fase2_v2/` — a Fase II já se mostrou reprodutível byte a byte (`IMPLEMENTACAO.md` §7). Só então
   grava as predições das arenas, sem ler nem calcular nada.
6. **Script de análise estendido:** confere o hash dos dois pré-registros, deste adendo, da regra
   da traversal e da ficha; recusa rodar se algum não bater. Ensaio na partição de validação do
   BigVul e em predições sintéticas, como em 13/10.
7. **Abrir as três arenas juntas, uma vez**, com o autor presente. Juntas para que o resultado de
   uma não influa na preparação da outra.
8. **Defeito encontrado depois de abrir:** corrige, roda de novo e reporta as duas versões, como no
   §6.7 do principal.

## 11. O que este adendo não cobre

- a avaliação por pares do VentiVul (as métricas de pares da v3); não é calculada;
- os LLMs de Lu & Lagaisse;
- a segunda validação manual (amostra estratificada pelo veredito do filtro), que é outra coisa;
- a redação do `main.tex`, que fica para depois de fechar todo o processo (decisão do autor, 13/10).

## Histórico

- **13/10/2026** — rascunho redigido pelo Claude a pedido do autor, depois da abertura do teste do
  BigVul. Lidos: `PREREGISTRO_PRINCIPAL.md` (§8, §9 e o resto), `PREREGISTRO_TAMANHO.md`,
  `IMPLEMENTACAO.md`, `resultado_teste_bigvul.md`, `SPLIT.md`, `TRAVERSAL_NEGATIVOS_TESTE.md`,
  `main.tex` (Protocolo de avaliação, Definição das classes, Síntese), as `Notas` dos cartões
  "Preparar ICVul e VentiVul" e "Deduplicação por CVE"; o artigo do ICVul (arXiv 2505.08503v1, PDF) e
  o de Lu & Lagaisse (v1 em PDF; v3 em HTML). Contado: a CWE-416 no `indice_bigvul.csv` e a
  sobreposição com `split/positivos.tsv`. Nenhum dado de arena externa baixado; nenhuma predição.
- **13/10/2026, mesma sessão** — o autor fechou **F** (VentiVul v3) e **K** (traversal pura nas
  três arenas). **G2 adiada:** antes, analisar se o ICVul faz sentido como arena. **J:** o autor
  perguntou se o "acaso" é um sorteio 50/50 por função — não é (é sortear o mesmo número de funções
  que o braço acusou); explicação pendente de confirmação. **M:** inclinação do autor a favor de
  testar a generalização sobretudo em conjuntos realistas; regra "acima em todas" ainda não
  confirmada.
- **14/10/2026** — o autor fechou **M** ("acima em todas"). Pediu para considerar o **PrimeVul**:
  lido o artigo (HTML do arXiv v2) e o README; aberta a **Decisão G0** (qual conjunto ocupa a vaga
  *cross-dataset*), com recomendação de trocar o ICVul pelo PrimeVul. **J:** feito o exemplo pedido
  pelo autor (100 acusadas, 3 acertos no VentiVul v3 → excesso 1,03, sem sinal); aprovação pendente.
- **14/10/2026, mesma sessão** — o autor aprovou **J** e fechou **G0 = PrimeVul** (G1 e G2 deixam de
  se aplicar). Consequência redigida: **G4** (quais funções do PrimeVul entram), a decidir; ICVul
  trocado por PrimeVul em H, I, K, M e §10. Faltam G3, G4, H, I e L.
- **14/10/2026, mesma sessão** — o autor aprovou **G3** (escreveu "g5"; era o segundo item da lista,
  o VentiVul — a confirmar), **H**, **I** e **L**. Na G4 perguntou quantas funções dá: contados os
  metadados do PrimeVul em espelhos do Hugging Face (§1). Achado: a versão do artigo não tem CWE para
  659 das 695 vulneráveis do teste; a G4 passou a recomendar o teste da **v0.1** (173 vulneráveis e
  4867 não vulneráveis da família, depois de CVE e commit). Falta só a G4.
- **14/10/2026, mesma sessão** — o autor propôs, na G4, o **PrimeVul inteiro** deduplicado contra o
  BigVul e com grafo só das CWEs do recorte ("teríamos mais área" de avaliação). Contado (§1): com a
  dedup contra o BigVul **inteiro**, sobram 1027 vulneráveis e 31.149 não vulneráveis da família. A
  recomendação passou a ser a proposta do autor, com a dedup estrita como exceção da H para o
  PrimeVul. A confirmar pelo autor, com o custo (~65 h de traversal pura).
- **14/10/2026, mesma sessão** — o autor fechou **G4** (PrimeVul v0.1 inteiro, dedup estrita) e
  mandou pôr a troca ICVul → PrimeVul na "Pauta para o orientador" (feito: item 10). Perguntou o que
  era o "g5": não existe G5; a resposta dele tinha sido lida como aprovação da **G3**, que fica
  pendente de confirmação explícita.
- **14/10/2026, mesma sessão** — o autor confirmou a **G3**. Com isso, **todas as decisões estão
  fechadas**. O autor pediu para **revisar o arquivo numa sessão nova antes de congelar**. Os scripts
  das contagens foram copiados do scratchpad para `modelo/contagens_arenas/` (caminhos ajustados) e
  conferidos: reproduzem os números da CWE-416 e do teste do PrimeVul (`conferir_scripts.sh`).
  **Não congelado.**
- **15/10/2026, sessão nova (revisão antes de congelar)** — o Claude revisou o arquivo a pedido do
  autor, contra ele mesmo, os dois pré-registros congelados e as fontes. **Números:** os quatro
  scripts do PrimeVul e o da CWE-416 rodaram de novo e reproduzem todos os números do §1, e as contas
  derivadas (H, G4, K, M) batem; os números do BigVul citados batem com `resultado_teste_bigvul.md`.
  **Negativo do VentiVul**, que a G3 não fixava: descoberto no artigo (v3, §3.2 e Tabela 3), no
  README e nos dados (`ventivul.csv` do Figshare, lido em fluxo, só metadados; scripts
  `estrutura_ventivul.sh` e `contar_ventivul.py`). É a versão consertada mais as funções não
  relacionadas dos mesmos arquivos, a mesma estrutura do PrimeVul. A regra da G4 foi transposta
  (CVE no lugar de commit): família de memória com 50 positivos e 3326 negativos; K e I atualizadas.
  **Piso (J):** o autor deixou com o Claude a decisão de reportar o excesso; ficou "escala declarada
  + excesso no arquivo de resultado", sem barreira nova. **Ordem das operações** do negativo
  escrita como o BigVul fez (antes das perdas). **Redação:** três pontos novos no §0 (o ICVul no
  principal, a queda, o mínimo por arena); referências "§3/§4/§8" ambíguas passaram a dizer "do
  principal"; Resumo (G3, H, I, J) alinhado ao corpo; a frase "v0.1 é subconjunto" restrita ao que
  foi visto; aviso sobre os dois "1027"; referência da dedup do §1 (split, não dataset v3) declarada;
  "VentiVul de 2025" → CVEs a partir de maio de 2025 (há CVEs de 2026). Nenhuma decisão do autor
  mudou de sentido.
- **15/10/2026 — congelado**, com a autorização do autor ("estou satisfeito, pode congelar e começar
  a preparação das arenas"). Nenhum modelo previu nenhuma função de arena externa até aqui.
