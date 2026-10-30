# Por que o `M_ctrl` perdeu mais itens que o `M_cur` na montagem — a causa medida

> **Correção de 05/10/2026:** os 4 itens classificados abaixo como "nome não existe no CPG"
> (`2317/2318__Chrome`, `1304/1305__neomutt`) **existem** — foram procurados no CPG de OUTRO
> arquivo, porque o `montar_dataset.py` agrupava por nome-base do arquivo e o commit mexia em dois
> arquivos de mesmo nome (P6 do `HANDOFF_2026-10-04.md`, §8.3). Corrigido na remontagem da v3.
> E a "v1 × v2" deste arquivo é a **v2 × v3** do `TRAVERSAL_V3.md`. Desfecho: a perda assimétrica
> sumiu na v3.

Fechado em **03/10/2026**. Scripts: `_diagnosticar_perda_bracos.py`, `_contar_homonimos.sc`.
Saída item a item: `_perda_bracos.tsv`.

**Corrige o `DATASET.md`**, que atribuía a perda assimétrica à cegueira do `#ifdef`. Essa
explicação não se sustenta, e a causa real é outra.

## Situando

Na montagem do dataset de grafos (21–22/09), cada item das listas de braço só entrava se a
função dele fosse localizada no CPG do arquivo. A perda foi assimétrica (`DATASET.md`):

| braço | na lista | com grafo | perdidos |
| --- | --- | --- | --- |
| `M_cur` | 533 | 513 | 20 (3,8%) |
| `M_ctrl_s2026…s2030` | 533 cada | 482–489 | 44–51 (8,3–9,6%) |
| `M_raw` | 1806 | 1647 | 159 (8,8%) |

O `DATASET.md` explicou a diferença pela cegueira do `#ifdef` (função sem corpo no grafo): o
`M_cur` não pode conter item cego, o `M_ctrl` pode, e a taxa de cegueira medida (8,2%) "fechava a
conta". O motivo por item **não tinha sido gravado** — o `montar_dataset.py` só guarda contagens
por arquivo no `.meta.json` —, então a explicação era uma coincidência de taxas, não uma medida.

## Por que a explicação registrada não se sustenta

Os 7 positivos cegos da amostra de 85 (`PARSE_IFDEF.md`, semente 404) são **todos indeterminados
de 11/08**: nenhum está em `conjuntos/M_raw.tsv`, nenhum está em `_falhas_motivo.tsv`. Os
indeterminados já tinham saído dos três braços em 11/08 (`RODADA_COMPLETA.md`), então o `M_ctrl`,
sorteado do `M_raw`, **não podia conter os cegos**. E a montagem usa praticamente o mesmo critério
de corpo (`exportar_grafos.sc`, linha 80: só vira candidato método interno com bloco não vazio).

## A medida

`_diagnosticar_perda_bracos.py` refaz a lista de alvos com o **próprio** `carregar_alvos()` do
`montar_dataset.py` (importado, não copiado), identifica os 159 positivos de braço sem grafo, e
abre o CPG dos 34 arquivos onde eles estão para contar, por nome, quantos métodos existem e quantos
têm corpo — o mesmo filtro do `exportar_grafos.sc`. Com isso o `escolher()` fica reproduzível.

Os totais batem exatamente com o `DATASET.md` (20, 51, 46, 50, 47, 44, 159). Nenhum item caiu
antes do Joern.

| motivo | `M_cur` | s2026 | s2027 | s2028 | s2029 | s2030 | `M_raw` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **homônimo com corpo, sem hash para desempatar** | **19** | 50 | 45 | 49 | 46 | 44 | **157** |
| nome não existe no CPG | 1 | 1 | 1 | 1 | 1 | 0 | 2 |
| **total** | 20 | 51 | 46 | 50 | 47 | 44 | 159 |

**A causa é colisão de nome, não `#ifdef`.** 157 dos 159 itens estão em arquivos onde o nome da
função tem **duas ou mais definições com corpo**.

## O mecanismo

O `escolher()` do `montar_dataset.py` resolve homônimos pelo hash do corpo. **Os negativos entram
com hash; os positivos entram com `shas: []`** (`carregar_alvos()`, linha 187). Então todo
positivo com 2+ homônimos com corpo cai em `ambiguo` e sai, sem aviso.

Isso **contraria o que o `NEGATIVOS.md` (21/09) planejou**: lá ficou escrito que "o mesmo
desempate por hash de corpo pode resolver a colisão dos positivos na montagem do dataset". O
desempate foi implementado só para os negativos.

## Por que a perda pesa mais no `M_ctrl`

Porque a curadoria **confirma pouco** os itens com colisão: **19 de 157 (12,1%)**, contra
**514 de 1649 (31,2%)** entre os demais itens do `M_raw` de treino. O `M_ctrl` é sorteio aleatório
do `M_raw` e herda a proporção de itens com colisão; o `M_cur` tem bem menos.

A conta fecha sem coincidência: se a perda fosse a taxa do `M_raw` (159/1806), um braço de 533
perderia **~47** — os cinco controles perderam 44–51. O `M_cur` perdeu 20.

## Onde se concentra

- **159 itens em 34 arquivos.** Um só arquivo responde por **88**: `mkvparser.cpp` do Android,
  commit `04839626ed85` — um commit que marcou ~88 funções do mesmo arquivo como vulneráveis. Só
  13 delas foram confirmadas. É fan-out em estado puro, o mecanismo de ruído que o trabalho estuda.
- **Por projeto:** Android 118, Chrome 20, php-src 20, php-radius 1.
- **Por linguagem:** `.cpp` 106, `.cc` 30, `.c` 23 — **136 de 159 são C++.** Hipótese, não
  conferida: em C++ o `name` do método no Joern é o nome curto, e métodos de classes diferentes
  (`A::Parse`, `B::Parse`) colidem; o `fullName` os distinguiria.

## O que isto muda e o que não muda

**Não muda a decisão 9** (resortear os `M_ctrl` só entre quem tem grafo). O resorteio condiciona
direto em "virou grafo", qualquer que seja o motivo. Como os itens com colisão não viram grafo,
**hoje os três braços de treino excluem igualmente os positivos com colisão** — o que, por
acidente, é a opção (b) que o `COLISAO_NOME.md` recomendou e a Decisão 2 de 05/09 não adotou
(decidiu-se "(a) declarar").

**Muda a explicação**, que não pode ir para o artigo como estava no `DATASET.md`.

**Abre uma decisão (do autor):** implementar o hash para os positivos, como o `NEGATIVOS.md`
planejou, recuperaria até 157 positivos de treino. Mas 19 deles voltariam para o `M_cur` com
evidência calculada sobre a **união** de homônimos (`COLISAO_NOME.md`) — confirmados,
possivelmente, por padrão da função vizinha. Hoje eles estão fora por acidente. Recuperar dado e
manter fora a evidência possivelmente emprestada puxam para lados opostos.

**Não medido aqui:** o mesmo mecanismo vale para os positivos de validação e teste, que também
entraram sem hash.

## Medida 2 — o hash recuperaria? E a evidência dos que estão no `M_cur` é própria? (03/10)

Script `_recuperabilidade_hash.py` (+ `_tamanho_homonimos.sc`), saída `_recuperabilidade_hash.tsv`.
Não altera nada; não toca regra congelada, veredito nem os 50.

**Recuperabilidade.** Para cada um dos 157, o hash do `func_before` do BigVul (mesmo cálculo e
mesmo módulo dos negativos) comparado ao hash de cada homônimo recortado do arquivo-fonte:

| | todos | dos que estão no `M_cur` |
| --- | --- | --- |
| casa com exatamente 1 homônimo (**recuperável**) | **153** | 18 |
| não casa com nenhum | 4 | 1 |
| empate | 0 | 0 |

O hash resolve **153 de 157 (97,5%)**. Tecnicamente, o conserto funciona.

**A hipótese de C++ se confirma.** O `fullName` dos homônimos mostra classes diferentes com o mesmo
nome curto: `Track.EOSBlock.GetBlock`, `SimpleBlock.GetBlock`, `BlockGroup.GetBlock`,
`Cues.GetBlock`, `Segment.GetBlock` — cinco métodos `GetBlock` no mesmo `mkvparser.cpp`.

**Evidência emprestada nos 18 do `M_cur`.** A traversal congelada contou a evidência sobre a
**união** dos homônimos (`COLISAO_NOME.md`). Proxy medido: fração dos nós AST da união que
pertence à função rotulada (a que o hash identifica). **É tamanho, não evidência** — não re-roda a
traversal.

| fração própria | itens | quais |
| --- | --- | --- |
| ≤ 0,30 | **10** | os 10 do `mkvparser.cpp` com menor fração; os três `GetBlock` de 4,0–4,5% |
| 0,56–0,71 | 2 | `Segment.GetNext`, `Segment.GetBlock` |
| ≥ 0,91 | 6 | `MPEG4Extractor.parseChunk` ×2, `BnOMX.onTransact` ×4 |

**O caso que resume:** `2629__Android` está no `M_cur`. A função rotulada é
`Track::EOSBlock::GetBlock() const { return NULL; }` — 8 nós AST, nenhuma operação de memória. A
evidência gravada (1 acesso indexado, 2 fluxos até índice) foi contada sobre 214 nós de cinco
`GetBlock`. **Ela foi confirmada pela função vizinha.** O commit é o `04839626ed85`, CVE-2016-1621
(`saida_final/itens/2629__Android/meta.json`).

**Consequência para a decisão:** dar hash aos positivos devolveria ao `M_cur` 18 itens, dos quais
pelo menos 10 têm a maior parte da evidência vinda de outra função. O braço tratado receberia
justamente o tipo de positivo que a curadoria existe para tirar. Hoje eles estão fora — por
acidente, e de forma simétrica nos três braços.

## Medida 3 — validação e teste (04/10)

Mesmo diagnóstico (`_diagnosticar_perda_bracos.py --avaliacao`, `_recuperabilidade_hash.py
--avaliacao`) sobre os positivos **sadios** de validação e teste (`conjuntos/M_raw.tsv` × partição
do `split/positivos.tsv`). Saídas: `_perda_avaliacao.tsv`, `_recuperabilidade_hash_avaliacao.tsv`.

| partição | sadios | com grafo | perdidos | homônimo sem hash | nome inexistente |
| --- | --- | --- | --- | --- | --- |
| validação | 257 | 249 | 8 | 8 | 0 |
| teste | 490 | 470 | 20 | 18 | 2 |

Os "com grafo" batem com o `DATASET.md`. **O hash recuperaria 23 dos 26** com colisão (3 não
casam). Na avaliação o rótulo usado é o do BigVul, não o veredito da curadoria — então lá **não
existe** a questão da evidência emprestada; o hash só deixaria a montagem achar o grafo certo.

## A regra é monotônica na seleção do método — consequência para uma correção da traversal (04/10)

Conferido no `regra_veredito.toml` e no `curadoria_v2.sc`: o veredito é **confirmado se e só se
camada 1 ≥ 1 E camada 2 ≥ 1**, e todas as contagens são tomadas sobre `alvoM`
(`cpg.method.nameExact(alvo)`, linha 85) — chamadas de memória, acessos indexados, parâmetros
(fontes), sinks. Restringir `alvoM` da **união** dos homônimos para **a função certa** só pode
manter ou **diminuir** cada contagem (subconjunto de nós, de fontes e de sinks).

Logo uma traversal corrigida (que escolhe o método certo por hash quando há 2+ definições com
corpo) **só pode mudar veredito no sentido confirmado → descartado**, nunca o contrário. Ressalva:
o motor de fluxo pode estourar (`-1` → indeterminado); conferir empiricamente.

**Consequência para a Etapa 5:** os 4 itens com colisão entre os 50 foram todos **descartados** na
v1 (`COLISAO_NOME.md`, medida 2). Pela monotonicidade, continuam descartados numa v2, e os 17
confirmados (nenhum com colisão) não mudam. **A precisão 11/17 e a taxa base 19/43 ficam
idênticas** — e isso se verifica comparando os **vereditos** v1 × v2 nos 50, sem abrir rótulo
humano nenhum.

## O que este registro NÃO é

- Não é falha do `#ifdef`. A cegueira existe (`PARSE_IFDEF.md`) e custou os 235 indeterminados de
  11/08, mas não explica a perda de 22/09.
- Não toca rótulo, veredito nem regra congelada. É contagem de métodos em grafo.
