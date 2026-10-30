# Pré-registro da segunda validação manual — a precisão do filtro de curadoria

> **CONGELADO em 30/10/2026, 14:06 — depois da anotação e antes da abertura da chave.**
>
> **Desvio do §12, declarado.** O §12 mandava congelar antes de anotar. O autor anotou antes de
> congelar. A ordem real foi esta:
>
> 1. 30/10, 12:12 — última modificação do texto do plano (registro das três decisões da §9 e dos
>    números da amostra 30 + 30). O SHA-256 do arquivo nesse estado, calculado às 14:06 sobre o
>    arquivo ainda intocado, é `349b982b2aa2b7ac510493a7290a43c8ac9c08e00b33cd324b630acb70c8a442`.
> 2. 30/10, 13:54 — última gravação da planilha anotada (`anotacao_segunda.csv`).
> 3. 30/10, 14:06 — congelamento. Nenhuma linha do plano mudou entre 1 e 3. Só este aviso foi
>    trocado, e o SHA-256 do arquivo congelado está em `congelamento_segunda.tsv`.
>
> O que sustenta o plano mesmo assim: a chave continuou lacrada durante todo o processo (SHA-256
> igual ao da geração, conferido pelo `montar_segunda.py --conferir` às 14h), então ninguém sabia
> o veredito de nenhum caso quando o plano foi escrito nem quando foi congelado. As datas do item 1
> e 2 são datas de arquivo, prova mais fraca que um SHA-256 gravado na hora. A frase do artigo é
> "o plano foi escrito antes da anotação e congelado antes da abertura da chave".
>
> **Decisões do autor depois de anotar e antes de abrir a chave (30/10, ~14h):** a planilha fica
> como foi preenchida. Não relê os D justificados pela estrutura do commit (casos 1, 2, 34, 36 e
> 45). O caso 8, que o autor marcou D anotando que a CVE do BigVul estaria errada, fica D. As 31
> observações vazias ficam vazias. O SHA-256 da planilha anotada também está em
> `congelamento_segunda.tsv`.
>
> *Aviso original (21/10):* proposta não congelada; congelar antes de anotar; mudar este plano
> depois de ver qualquer rótulo desta amostra invalida o número — a mesma regra do
> `../pre_registro.md` da primeira validação.

---

## 0. Situando

**Onde estamos no pipeline.** A curadoria do TCC já rodou (traversal v3, outubro de 2026). A
*traversal* é a consulta do Joern — a ferramenta que transforma o código em um grafo de
propriedades de código, o CPG — que olha cada função que o BigVul marcou como vulnerável e dá um
**veredito**: `confirmado` (o padrão de erro de memória em buffer está na função; ela entra no
`M_cur`, o conjunto de treino curado) ou `descartado` (o padrão não aparece; a função só fica de
fora do `M_cur` — o silêncio da traversal nunca inverte rótulo). Esse filtro é a intervenção do
experimento.

**Para que esta validação existe.** Para responder, numa amostra feita para isso: **quando o
filtro confirma uma função, com que frequência ela é de fato o sítio da vulnerabilidade?** *Sítio*
é a função em cujo corpo está o defeito explorável — a categoria **D** da rubrica. Essa fração é a
**precisão do filtro**. Ela é a premissa que torna o experimento interpretável: se o filtro não
elevasse a proporção de rótulos corretos, o `M_cur` seria só um sorteio com outro nome.

**O que esta validação NÃO é.**

- **Não é a primeira validação manual.** A primeira (julho–agosto de 2026) sorteou 50 positivos
  *brutos*, antes de qualquer filtro (semente 42), e mediu o ruído de rótulo do BigVul. Esta
  sorteia *depois* do filtro, separando confirmados e descartados.
- **Não reusa os 50**, nem os 30 do dev set: eles saem da moldura (§3).
- **Não mede o ruído do BigVul bruto.** Mede o filtro. A taxa base que aparece aqui (§7) é uma
  estimativa derivada, necessária para calcular o ganho; não substitui a da primeira validação.
- **Não é a Etapa 5.** A Etapa 5 (10/08/2026) cruzou os vereditos do filtro com os rótulos que o
  autor já tinha dado aos 50 — só 17 deles eram confirmados. Esta é a medida desenhada para a
  pergunta (§10).

---

## 1. Perguntas

| | pergunta | nome da medida |
| --- | --- | --- |
| principal | entre as funções que o filtro **confirmou**, quantas são o sítio (D)? | precisão do filtro |
| secundária | entre as funções que o filtro **descartou**, quantas são o sítio? | taxa de D entre os descartados (o sítio que o filtro deixou de fora) |
| derivada | qual a proporção de D entre todos os positivos com veredito, e quanto o filtro a eleva? | taxa base estimada e ganho |

---

## 2. Moldura e contagens

*Moldura* é a lista de funções das quais a amostra é sorteada.

- **Fonte:** `traversal/conjuntos_v3/M_raw.tsv`, os positivos do BigVul que têm veredito na
  traversal v3: **2521** = 2957 positivos − 32 excluídos (a função rotulada não pôde ser
  identificada no grafo) − 169 falhas da ferramenta − 235 indeterminados (corpo não parseado: a
  ferramenta não conseguiu olhar). Parcelas: `traversal/TRAVERSAL_V3.md`, §10.
- **Vereditos no `M_raw`:** 836 confirmados e 1685 descartados (conferido pelo script).
- **Depois das exclusões da §3:** **806 confirmados + 1646 descartados = 2452 funções**, de 882
  commits distintos.

Consequência: o resultado vale para funções **com veredito**. As indeterminadas, as falhas e as
excluídas não estão representadas — e também não entram em nenhum braço do experimento.

---

## 3. Exclusões

| conjunto | por que sai | quantos estão no `M_raw` | confirmados | descartados |
| --- | --- | --- | --- | --- |
| os 50 da primeira validação (`traversal/mapa_caso_item_50.csv`) | já anotados pelo autor e usados na Etapa 5; anotá-los de novo contaria a mesma função duas vezes, com o rótulo antigo na memória | 43 de 50 | 17 | 26 |
| os 30 do dev set (`traversal/dev_set.tsv`; 30 positivos, semente 7, anotados pelo modelo) | absorveram os olhares durante a escrita da regra de curadoria | 26 de 30 | 13 | 13 |

Os 7 dos 50 e os 4 do dev que não estão no `M_raw` ficaram sem veredito (indeterminados, falha ou
excluídos pela v3); não há o que tirar.

**Não se exclui** quem só divide o *commit* com os 50 ou com o dev: marca-se (§5).

---

## 4. Estratos, n, sementes e o sorteio aninhado

*Estrato* é cada um dos dois grupos em que a moldura é dividida antes de sortear: confirmados e
descartados. Sorteia-se separadamente dentro de cada um, com um n fixado por estrato, para garantir
confirmados suficientes para a pergunta principal — sorteando das 2452 sem estratificar, só cerca
de 1 em 3 (806/2452 = 32,9%) seria confirmado.

| estrato | tamanho na moldura | n (decidido em 30/10/2026, §9.1) | semente da permutação |
| --- | --- | --- | --- |
| confirmados | 806 | **30** | **7071** |
| descartados | 1646 | **30** | **7072** |
| ordem de apresentação dos 60 | — | — | **7073** |
| bootstrap da análise (§7) | — | — | **7074** |

**Sorteio aninhado.** Em cada estrato, a moldura em ordem crescente de `id_parquet` (o número da
linha da função em `saida/bigvul_memoria_positivos.parquet`, contado a partir de 1) é permutada
por `numpy.random.RandomState(semente).permutation` — o gerador legado do numpy, cuja sequência é
congelada entre versões — e a amostra são os **n primeiros** da permutação. Se o n aumentar,
entram só os próximos da mesma permutação; os que já estavam continuam. Conferido em 21/10/2026:
com 40 + 30, os 30 + 20 de então são os primeiros de cada estrato; com 25 + 25, ficam os 25
primeiros confirmados e os 20 descartados de então, mais 5. Por isso a amostra 30 + 30 de
30/10/2026 contém a 30 + 20 de 21/10 e acrescenta os 10 descartados seguintes da permutação.

**Ordem de apresentação.** Os 60 sorteados, em ordem crescente de `id_parquet`, são permutados com
a semente 7073 e numerados de 01 a 60: confirmados e descartados misturados, sem bloco.

**Por que estas sementes.** A proposta inicial era 7070/7071/7072. A busca de 21/10/2026 nos
scripts e registros do TCC (`.py`, `.sh`, `.sc`, `.ps1`, `.toml`, `.md`, `.txt`, `.tex`) mostrou
que a **7070 já foi usada**: ensaio da traversal nas funções não vulneráveis, 12/10/2026
(`traversal/rodar_traversal_negativos.py`, `traversal/TRAVERSAL_NEGATIVOS_TESTE.md`). O bloco foi
deslocado uma unidade **antes de qualquer sorteio**. Sementes já usadas no projeto: 7, 42, 101,
202, 303, 404, 909, 1000–1029, 2026–2030, 5050, 6060, 7070, 8080, 9090. A 7074 do bootstrap é
nova — e não a 42, convenção do bootstrap das análises anteriores — para que nenhum número desta
validação se confunda com os da primeira.

**A amostra sorteada** (só totais; a §5 explica por quê): 60 casos, **48 commits** distintos,
47 CVEs (o identificador público de cada vulnerabilidade), 21 projetos; 8 commits têm 2 ou mais
casos (20 casos ao todo). **1** caso veio pré-marcado como A (§6). *(Na versão 30 + 20 de
21/10/2026 eram 50 casos, 42 commits, 41 CVEs, 20 projetos, 5 commits com 2 ou mais casos.)*

---

## 5. Cegueira e chave lacrada

*Cegueira* quer dizer que o anotador não sabe, enquanto anota, o veredito do filtro em nenhum
caso. É o ponto mais importante do desenho: quem sabe que o filtro confirmou tende, sem perceber,
a achar o defeito.

- **O caderno (`caderno_segunda.md`) e a planilha (`anotacao_segunda.csv`) não contêm veredito,
  estrato, as contagens das camadas da traversal (camada 1 = presença do padrão, camada 2 = fluxo
  até ele), nenhuma outra evidência do Joern, nem o identificador do item (`NNNN__projeto`, o nome
  da função no pipeline) ou o `id_parquet`.** O script confere antes de gravar (as palavras
  "confirmado", "descartado", "camada", "estrato" e o padrão `NNNN__`), e uma busca independente
  (ripgrep) nos dois arquivos deu zero ocorrência em 21/10/2026.
- **A chave** (`chave/chave_segunda.csv`) é a única ligação caso → item → veredito. Colunas:
  `caso`, `item`, `id_parquet`, `veredito` (o estrato), `ordem_no_estrato` (a posição na
  permutação do estrato), `particao` (treino/validação/teste, de `traversal/split/positivos.tsv`),
  `commit`, `commit_na_primeira`, `commit_visto_em`, `cve_na_primeira`. Fica lacrada até a
  planilha estar completa; o SHA-256 dela está na §13.
- **Exposição prévia — marcada, não excluída.** `commit_na_primeira = sim` quando o commit da
  função aparece entre os 50 da primeira validação **ou** no dev set: o autor já estudou esses
  commits. `commit_visto_em` diz onde (`primeira`, `dev` ou `primeira+dev`); `cve_na_primeira` faz
  o mesmo pela CVE. Na moldura, **655 das 2452 funções (26,7%)** dividem commit com os 50 ou com o
  dev, em 40 commits — 319 delas vêm dos dois commits da CVE-2016-1621 (libvpx, Android), o
  agrupamento de *fan-out* alto (um commit que altera muitas funções, todas marcadas como
  vulneráveis pelo BigVul) que ocupava 14 dos 50. Na amostra: **19 dos 60 casos**, de 10 commits;
  7 desses casos são da CVE-2016-1621. (Contagem do `montar_segunda.py`, refeita em 30/10/2026
  sem abrir a chave, a partir dos commits do `mapa_caso_item_50.csv` e do dev set.)
- **Nada por estrato do que o anotador vê é divulgado antes do fim** — nem quantos pré-marcados,
  nem quantos commits já vistos, nem projetos, por estrato. Uma contagem dessas, cruzada com o que
  aparece no caderno, já sugeriria o veredito de casos específicos.
- **Compromissos do anotador enquanto anota:** não abrir `chave/`; não consultar
  `traversal/conjuntos_v3/`, `traversal/saida_completa_v3/` nem rodar a traversal nesses commits;
  não reabrir a planilha ou o caderno da primeira validação para ver o que disse de outra função do
  mesmo commit; não perguntar a um assistente o veredito de um caso (e quem conversa com o
  anotador não informa).

---

## 6. Rubrica e evidência

- **Rubrica:** `../rubrica_v1.md`, congelada, a mesma da primeira validação — categorias A, B, C,
  D e `?`, e só o D conta como rótulo correto. SHA-256
  `81f9d2495741537a27a189dedfd1d6da767afc8171608b3fbf425d8809567316` (é o `81f9d249…` já
  registrado no cartão do Notion). Se a rubrica mudar, a comparação com a primeira validação e com
  a Etapa 5 deixa de valer.
- **Evidência de cada caso idêntica à da primeira validação.** O `montar_segunda.py` importa as
  funções do `revisar_validacao.py` (o script que gerou o caderno da primeira) e monta cada caso
  com o mesmo cabeçalho (projeto | CVE | CWE do BigVul — a CWE é a categoria do defeito, como
  CWE-119, erro de buffer), os links do commit e do diff bruto, o `commit_id`, a mensagem do
  commit, o resumo da CVE (cortado em 1200 caracteres), o diff da função `func_before` ×
  `func_after` (cortado em 8000) e a pré-marcação de A quando as duas versões são iguais depois de
  normalizar o espaço em branco. **Conferido em 21/10/2026:** rodando o `cmd_build` original do
  `revisar_validacao.py` sobre as mesmas 50 linhas da versão 30 + 20, na mesma ordem, a planilha
  sai idêntica byte a byte e os 50 blocos de caso também. A versão 30 + 30 sai do mesmo código,
  sem alteração no `montar_segunda.py`. Nenhum diff e nenhum resumo passou do corte nos 60 casos.
- **O que difere do caderno da primeira** (nada disso é evidência): o cabeçalho lembra a rubrica
  em uma linha por categoria e traz a lista dos 60 casos; e o script avisaria embaixo de um diff
  ou resumo cortado (não aconteceu).
- **Pré-marcado:** 1 caso (o 43 na numeração de 30/10/2026; era o 32 na de 21/10), A com
  confiança alta e observação "(auto)". Conta como não-D,
  como na primeira. O autor pode trocá-lo se discordar, dizendo por quê na observação.

---

## 7. O que se calcula depois (análise principal)

Notação: em cada estrato, A, B, C e D são as contagens de cada categoria; o `?` fica fora de todo
denominador. N_c = 806 e N_d = 1646 são os tamanhos dos estratos na moldura.

1. **Precisão do filtro** = D / (A + B + C + D) entre os **confirmados**.
2. **Taxa de D entre os descartados** = D / (A + B + C + D) entre os **descartados**. É o sítio
   que o filtro deixou de fora: perda de recall (a fração de sítios reais que o filtro não
   mantém), aceita por desenho — o silêncio não inverte rótulo —, mas medida.
3. **Taxa base estimada** = (N_c × precisão + N_d × taxa dos descartados) / (N_c + N_d): a média
   das duas taxas ponderada pelo tamanho dos estratos na moldura. É a proporção de D que se veria
   sorteando da moldura inteira, sem filtro. Sem a ponderação, a amostra 30 + 30 (50% de
   confirmados, contra 32,9% na moldura) puxaria a taxa base na direção da precisão.
4. **Ganho** = precisão − taxa base, em pontos percentuais.
5. **Intervalos de confiança de 95% (IC)** para as quatro medidas, por *bootstrap* (reamostragem
   com reposição, que simula outros sorteios possíveis) **estratificado e por cluster de commit**:
   dentro de cada estrato, sorteiam-se com reposição tantos commits quantos o estrato tem entre as
   linhas com A, B, C ou D, levando todas as linhas de cada commit sorteado; as medidas são
   recalculadas com as duas metades. 10.000 reamostragens, `random.Random(7074)`, percentis 2,5 e
   97,5 (o mesmo cálculo de percentil do `traversal/etapa_5.py`). Reamostragens em que um estrato
   fique sem linha decidida são contadas e reportadas, não escondidas. Por commit e não por linha
   porque funções do mesmo commit não são independentes; dentro de cada estrato porque os estratos
   foram sorteados separadamente (um commit com funções nos dois estratos é reamostrado em cada
   um, de forma independente).
6. **Tabela completa** A/B/C/D/`?` × estrato, como a da Etapa 5.
7. **Duas leituras descritivas, sem IC e sem critério:** (a) quantos A e quantos B o filtro
   confirmou — na Etapa 5 foram 0 de 5 e 0 de 10, e o artigo se apoia nisso; (b) a cobertura dos
   D = N_c × precisão / (N_c × precisão + N_d × taxa dos descartados), a fração dos sítios que o
   filtro mantém (Etapa 5: 11 de 19 = 57,9%, também só por transparência).

**Como o resultado vira frase** (fixado agora para não ser escolhido depois):

- se o limite inferior do IC 95% do ganho for **maior que zero**: "na amostra estratificada, o
  filtro eleva a proporção de rótulos corretos de [taxa base] para [precisão] (IC 95% [...]; ganho
  de [...] pontos, IC [...])";
- se **não** for: continua valendo a frase atual do artigo — a amostra é compatível com ganho, mas
  não exclui ganho nulo a 95% —, agora com o n desta amostra;
- em qualquer caso, a análise principal é esta; as sensibilidades da §8 vão junto, e nenhuma
  substitui a principal por ter saído melhor.

---

## 8. Sensibilidades pré-fixadas

Cada uma recalcula as medidas 1 a 4 (estimativa pontual e n; IC só na análise principal):

1. **Sem os casos com `commit_na_primeira = sim`** (19 casos, somando os dois estratos): mede o
   quanto a exposição prévia do anotador a esses commits pesa.
2. **Uma linha por commit:** dentro de cada estrato, fica só a linha de menor `ordem_no_estrato`
   de cada commit (a que o sorteio pegou primeiro).
3. **Só confiança alta:** só as linhas com `confianca = alta` (grafias normalizadas como no
   `revisar_validacao.py tally`).
4. **Os `?`:** contados por estrato e reportados à parte; não entram em nenhum denominador.

---

## 9. Decisões do autor (antes de congelar)

**Decididas pelo autor em 30/10/2026, antes de qualquer anotação:** 9.1 → **30 + 30**;
9.2 → **(a) manter e marcar**; 9.3 → **(a) por função**. O texto abaixo fica como estava na
proposta, para registrar o que foi pesado em cada decisão.

### 9.1 O n e a proporção

**Decidido: 30 + 30.** Motivo: quem decide a frase do resultado (§7) é o IC do ganho, e o ganho
depende quase por igual dos dois estratos, porque os descartados são 2 em cada 3 funções da
moldura e dominam a taxa base. Das três opções, só a 30 + 30 muda a chance de o IC do ganho
excluir o zero (~71% → ~80%, nas contas de planejamento abaixo), ao custo de 10 casos.
Remontado com `python3 montar_segunda.py --n-confirmados 30 --n-descartados 30` em 30/10/2026,
com a planilha ainda virgem (SHA-256 `5b3fef7a…` conferido antes de remontar).

*Texto da proposta (21/10/2026):* a amostra gravada é 30 + 20, a proposta. Como o sorteio é
aninhado, mudar é rodar `python3 montar_segunda.py --n-confirmados X --n-descartados Y` **antes de
anotar** e atualizar a §4, a §5 e a §13.

Para ajudar a escolher: a meia-largura aproximada do IC 95%, em pontos percentuais, de cada medida.
**São contas de planejamento, não previsões:** aproximação normal, **sem** o efeito de agrupamento
por commit (que alarga os intervalos reais), supondo que as taxas verdadeiras sejam as da Etapa 5
— precisão de 64,7% (11 de 17 confirmados eram D) e D em 30,8% dos descartados (8 de 26), ambas
sob a traversal v2 — e com os pesos da moldura (806 e 1646). Com essas taxas, o ganho esperado é
de cerca de 22,8 pontos; a penúltima coluna é a chance aproximada de o IC do ganho excluir o zero
(o "poder").

| proposta | ± precisão | ± D nos descartados | ± taxa base | ± ganho | IC do ganho exclui zero | casos a ler |
| --- | --- | --- | --- | --- | --- | --- |
| **30 + 20** | 17,1 | 20,2 | 14,7 | 17,8 | ~71% | 50 |
| 25 + 25 | 18,7 | 18,1 | 13,6 | 17,5 | ~72% | 50 |
| 30 + 30 | 17,1 | 16,5 | 12,4 | 16,0 | ~80% | 60 |

Leitura: 30 + 20 favorece a pergunta principal (a precisão); 25 + 25 dá praticamente o mesmo IC do
ganho com a precisão um pouco mais larga; 30 + 30 melhora o ganho ao custo de 10 casos a mais
(uns 30 a 50 minutos de leitura).

### 9.2 Os casos de commit já visto (15 na versão 30 + 20; 19 na 30 + 30)

**Decidido: (a) manter e marcar.** O custo de (a) é medido pela sensibilidade 8.1; o de (b) muda
a população e não se mede.

- **(a) Manter e marcar** — a proposta. A amostra continua representando a moldura inteira, e a
  sensibilidade 8.1 mede o efeito da exposição.
- **(b) Pular na permutação** — tirar da moldura as 655 funções de commit já visto e completar com
  os próximos de cada permutação (o aninhamento se mantém). Custo: a medida passa a valer só para
  73,3% da moldura, e o que sai é justamente fan-out alto (319 das 655 são da CVE-2016-1621), onde
  está o ruído que o filtro alega remover; a precisão medida tenderia a se afastar da do `M_cur`
  real.

### 9.3 Sortear por função ou por commit

**Decidido: (a) por função.** É o que estima a precisão do `M_cur`; a visão por commit entra como
conferência na sensibilidade 8.2.

O cartão do Notion sugere considerar estratificar também por commit, porque o fan-out põe funções
irmãs na mesma amostra (aqui, 48 commits em 60 casos).

- **(a) Por função** — a proposta. A unidade do `M_cur` é a função, e o treino usa funções:
  sortear funções estima a precisão do conjunto que de fato vai para o treino. A dependência entre
  irmãs entra no IC (bootstrap por commit) e na sensibilidade 8.2.
- **(b) No máximo uma função por commit** — mais independência, mas a medida muda: vira precisão
  "por commit", que dá o mesmo peso a um commit de 1 função e a um de 200 e, sem reponderação, já
  não estima a precisão do `M_cur`.

---

## 10. Ligação com a Etapa 5 — só comparação, sem juntar as amostras

A Etapa 5 (`traversal/RESULTADO.md`, 10/08/2026) cruzou os vereditos do filtro com os rótulos do
autor nos 50 da primeira validação: **precisão de 64,7%** (11 dos 17 confirmados eram D), IC 95%
[40,0; 86,7]; **taxa base de 44,2%** (19 D entre as 43 linhas comparáveis); ganho de +20,5 pontos,
IC [−1,8; +39,0] (bootstrap por commit, 33 clusters, 10.000 reamostragens, semente 42). Na
traversal v3, a precisão continua 11/17, e a taxa base fica entre 42,9% (18/42) e 45,2% (19/42),
conforme o rótulo do único item que a v3 tirou dos 50, que não foi aberto
(`traversal/TRAVERSAL_V3.md`, previsão P4).

Os números das duas medidas entram lado a lado no texto; as amostras **não se somam**: os desenhos
são diferentes (amostra bruta × amostra estratificada pelo veredito), os 50 estão fora desta
moldura por construção, e o anotador estava em outra condição (na primeira, o filtro ainda não
existia; agora ele o conhece — §11).

---

## 11. Limitações declaradas de antemão

1. **O anotador conhece a regra.** Quem anota escreveu o filtro e sabe o que ele procura; lendo o
   código, pode adivinhar o veredito. A cegueira impede *saber* o veredito, não *inferi-lo*. Se
   houver viés, ele aproxima a anotação do filtro e infla a precisão. Não é mensurável neste
   desenho.
2. **Anotador único.** Não há segundo anotador nesta rodada; o IC do bootstrap cobre o acaso do
   sorteio, não o erro de rotulagem (a mesma ressalva do `traversal/RESULTADO.md`).
3. **Exposição prévia** a 10 dos 48 commits da amostra (19 casos, §5) — sensibilidade 8.1.
4. **População:** só funções com veredito (a moldura de 2452); indeterminadas, falhas e excluídas
   não estão representadas.
5. **n pequeno e dependência:** 60 casos em 48 commits; os IC serão largos (§9.1).
6. **Evidência limitada:** diff da função, mensagem do commit e resumo da CVE, mais o link — o
   mesmo pacote da primeira validação.
7. **Deriva do critério:** a rubrica é a mesma, mas a primeira anotação foi há quase três meses, e
   o critério interno do anotador pode ter mudado. Medir isso exigiria reanotar casos antigos, o
   que este desenho não faz.

---

## 12. Como congelar e o que vem depois

1. Decidir a §9. Se o n, a proporção ou o tratamento dos commits já vistos mudar, rodar de novo o
   `montar_segunda.py` com os parâmetros novos **antes de abrir o caderno**, e atualizar a §4, a
   §5 e a §13 com a saída dele.
2. Trocar o aviso do topo por "CONGELADO em DD/MM/AAAA, HH:MM" e registrar na §9 o que foi
   decidido.
3. Calcular o SHA-256 deste arquivo (`sha256sum PRE_REGISTRO_SEGUNDA.md`, no WSL) e gravá-lo
   **fora dele**: num arquivo novo, `congelamento_segunda.tsv`, nesta pasta (arquivo, SHA-256, data
   e hora), e nas Notas do cartão do Notion.
4. Só então anotar (o passo a passo está no `LEIA_ME.md`).
5. O script de análise (`analisar_segunda.py`) será escrito **depois** do congelamento e **recusará
   rodar** se: o SHA-256 deste pré-registro divergir do gravado em `congelamento_segunda.tsv`; o
   SHA-256 da chave divergir do da §13; o `montar_segunda.py --conferir` falhar (caderno ou colunas
   de identificação da planilha alterados); ou alguma linha da planilha estiver sem `tipo_ruido`.

---

## 13. Arquivos e impressões (SHA-256, 30/10/2026 — amostra 30 + 30)

| arquivo | SHA-256 |
| --- | --- |
| `chave/chave_segunda.csv` | `013f16819667bf3d8b4225652c031165abc824f9f06f3638d0a5a5e8bcf50afb` |
| `caderno_segunda.md` | `82de2a9f5ab0cccf78685ff9df3b8735b212a417ea2fb1003ea82211abf34ff8` |
| `anotacao_segunda.csv` (virgem, antes de anotar) | `5e3af8bc18bbc841e2f9bf55f8945bb0f33863019232cc6c8676df49f7260cf8` |
| `../rubrica_v1.md` | `81f9d2495741537a27a189dedfd1d6da767afc8171608b3fbf425d8809567316` |
| `montar_segunda.py` (inalterado desde 21/10) | `468e764fa01502ae7a87094cec73fd8461e0fb0143bc669b2c8d89f06b75e783` |

Em 30/10/2026, depois de remontar: `montar_segunda.py --conferir` deu "OK" (n por estrato lido da
chave: 30 + 30; caderno, chave e colunas de identificação da planilha iguais) e uma busca
independente (grep) por "confirmad", "descartad", "camada", "estrato" e pelo padrão `NNNN__` no
caderno e na planilha deu zero ocorrência. Caderno: 120.777 caracteres; bloco por caso com mínimo
de 980, mediana de 1.580 e máximo de 6.127 caracteres; 3 blocos passam de 4.000.

*Versão 30 + 20 de 21/10/2026, substituída antes de qualquer anotação:* chave `eff7b0fc…a6cf51`,
caderno `d1705e2b…284b4c`, planilha virgem `5b3fef7a…12af0f`. Os parágrafos abaixo são dela.

Determinismo conferido: três execuções seguidas deram os mesmos SHA-256, e
`montar_segunda.py --conferir` (refaz tudo em memória e compara com o disco) deu "OK". O script
ganhou depois uma linha (`sys.dont_write_bytecode = True`, para importar o `revisar_validacao.py`
sem deixar `__pycache__` na pasta de cima) e por isso tem o SHA-256 acima; com ele, o `--conferir`
de 21/10/2026, ~17h, deu de novo "OK": caderno, chave e planilha iguais byte a byte aos de antes.
Conferências de entrada do script, todas passaram: o item `NNNN__projeto` é a linha NNNN (contada
a partir de 1) do parquet de positivos — commit, CVE e projeto batem nos 50 casos do
`mapa_caso_item_50.csv`, projeto e CVE nos 30 do dev, e projeto, CWE e commit (contra o split) nos
2521 itens do `M_raw`. Ambiente: WSL Ubuntu 24.04, Python 3.12.3, numpy 2.5.1, pandas 3.0.5.
