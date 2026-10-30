# Rodada completa da curadoria — `M_raw`, `M_cur` e `M_ctrl`

> **06/10/2026 — os números abaixo são da traversal v2 e ficam como histórico.** A traversal foi
> corrigida (v3: avalia só a função rotulada, sem somar homônimas). Números atuais: `M_raw`
> 2521, `M_cur` 836 (33,2%, IC95 [31,4; 35,0]), em `conjuntos_v3/`. Registro: `TRAVERSAL_V3.md`.

Fechada em **11/08/2026**. É a primeira vez que a curadoria roda sobre o conjunto inteiro; até
aqui só havia amostras de 27 a 50 itens.

## Onde estamos, para quem chegou agora

A **curadoria** é o filtro que olha cada função que o BigVul marcou como vulnerável e diz se o
padrão da família de erro de buffer está mesmo ali. A Etapa 5 mediu quanto ele acerta (precisão
de 64,7% contra taxa base de 44,2%, `RESULTADO.md`). Esta etapa **aplica** esse filtro aos 2957
positivos e produz os três conjuntos de treino do experimento.

## A rodada

`_rodar_completa.sh` e depois `_rodar_falta.sh`, com a regra **congelada** (`CONGELAMENTO.md`,
hashes conferidos antes e depois). **2957 de 2957 itens processados**, ~11 s por item, em cinco
lançamentos — o processo de background é morto pelo ambiente de execução a cada poucas horas, sem erro no
log, e o `--retomar` é idempotente. Nenhum item ficou de fora.

| | n | % dos 2957 |
| --- | --- | --- |
| com evidência | 2788 | 94,3% |
| falha (sem evidência) | 169 | 5,7% |

### As 169 falhas, por motivo

Apuração final sobre o log completo (`_falhas_motivo.tsv`, um motivo por item):

| motivo | n | % das falhas | o que é |
| --- | --- | --- | --- |
| **função alvo não encontrada no CPG** | **110** | 65,1% | o `nome_da_funcao` devolve uma chamada em vez da definição, ou a função não está no arquivo baixado |
| `sem_arquivo_de_contexto` | **45** | 26,6% | **exatamente** as 45 perdas de download já declaradas |
| `sem_evidencia` (outro) | 11 | 6,5% | a investigar se for citado no artigo |
| `timeout_joern` | 2 | 1,2% | |
| `sem_nome_de_funcao` | 1 | 0,6% | |

Duas leituras:

- **As 45 perdas de download batem exatamente** com o número declarado desde 02/08 (2912 de
  2957 com contexto). Nenhuma perda nova apareceu, e nenhuma foi recuperada.
- **As 110 do tipo "função não encontrada" são novidade de escala.** No lote de 50 foram 2 em
  51 (3,9%); aqui são 110 em 2957 (3,7%) — a taxa bate, mas o `LOTE_50.md` tinha deixado o
  número em aberto ("medir de novo na rodada completa"), e agora está medido.

É **perda de cobertura, não erro de rótulo**: o item simplesmente não entra em nenhum dos três
conjuntos. Vale investigar se é recuperável — se for o `nome_da_funcao` casando declaração em
vez de definição, uma segunda passada recuperaria parte dos 110 e parte dos 34 indeterminados
de assinatura só. Não é bloqueante e não muda nenhum resultado já medido.

## Os três conjuntos

| conjunto | n | o que é |
| --- | --- | --- |
| **`M_raw`** | **2553** | positivos de corpo sadio, rótulo original do BigVul, sem filtro |
| **`M_cur`** | **847** | os que a traversal confirmou (regra v1: camada 1 **E** camada 2) |
| **`M_ctrl`** | **847** | amostra aleatória do `M_raw`, mesmo N do `M_cur`, semente **2026** |

**`M_cur` = 33,2% do `M_raw`**, IC95 [31,4; 35,0].

Arquivos em `conjuntos/`. São o **lado positivo apenas** — as amostras negativas são as mesmas
nos três e entram na montagem do dataset de treino, que é o card do pipeline do ReVeal.

**Os 235 indeterminados ficam fora dos três conjuntos, não só do `M_cur`.** Se ficassem fora
apenas do curado, a diferença entre `M_cur` e `M_ctrl` passaria a incluir "a ferramenta
conseguiu olhar", que não é a variável de interesse.

**A sobreposição de 265 itens (31,3%) entre `M_cur` e `M_ctrl` é esperada e correta.** O
`M_ctrl` é sorteado do bruto inteiro, que inclui os confirmados. Sortear só entre os
descartados faria dele o *complemento* do `M_cur` — outra coisa, e um controle enviesado.

## O `M_cur` saiu abaixo da faixa que eu tinha anunciado — e o erro foi meu

Antes de rodar, ficou registrado no card que se esperava `M_cur` entre **38,6% e 48,1%**, e que
sair fora disso era motivo para **investigar antes de seguir, nunca para ajustar a regra**.
Saiu **33,2%**. A investigação (`_conferir_completa.py`):

| amostra | `M_cur` | IC95 |
| --- | --- | --- |
| dev set (semente 7) | 13/27 = 48,1% | [30,7; 66,0] |
| lote da Etapa 3 | 17/43 = 39,5% | [26,4; 54,4] |
| os 50 do teste | 17/44 = 38,6% | [25,7; 53,4] |
| **as três juntas** | 47/114 = 41,2% | **[32,6; 50,4]** |
| **população (2553)** | **847 = 33,2%** | [31,4; 35,0] |

**33,2% cai dentro do IC de cada uma das três amostras e dentro do IC das três juntas.** Não há
sinal de que as amostras não fossem representativas: é ruído de amostragem, com n de 27 a 44.

O erro foi na **anunciação da faixa**: eu tratei o intervalo entre três estimativas pontuais
(38,6% a 48,1%) como se fosse uma faixa de expectativa. Com n dessa ordem, os intervalos vão de
25% a 66% — a faixa honesta era larga demais para 33,2% surpreender. É exatamente o que a regra
do projeto manda evitar: *reportar o IC, nunca o ponto*.

**Nada foi ajustado.** A regra continua com o hash de 10/08.

### Consequência prática: 847 positivos

O critério de veto da Etapa 4a era `M_cur` nem tão pequeno que o `M_ctrl` perca poder, nem tão
grande que `M_cur ≈ M_raw`. 847 contra 2553 satisfaz o segundo com folga. O primeiro é uma
questão a reavaliar no card do treino: 847 positivos é menos que os ~1200–1400 projetados, e
quem decide se basta é o desenho do treino, não este arquivo.

## Três compromissos do `.toml` cobrados, e as respostas

O `regra_veredito.toml` deixou decisões explicitamente em aberto "para a rodada completa".
`_conferir_compromissos.py` cobrou as três:

1. **`acessos_indexados_diretos` (desligado "por prudência")** — deu **0 em todos os 2788
   itens**. Ligar ou desligar não mudaria veredito nenhum. A decisão continua vazia; nada a
   reabrir.
2. **Guarda de fluxo estourado no motor de dataflow** — **0 ocorrências em 2788**. A guarda
   nunca precisou disparar.
3. **"Só camada 2"** — **0 em 2788**. Somado às três amostras anteriores, são **0 exceções em
   toda a população**. A afirmação estrutural (`camada2 ⊆ camada1`, logo `c1 OU c2 ≡ c1`) deixa
   de ser inferência sobre amostra e passa a ser fato verificado no conjunto inteiro. **É o
   argumento mais forte que a reescrita da §4.5 pode carregar.**

Curva de encolhimento em escala (2788 itens): só camada 1 **429 (15,4%)**, só camada 2
**0 (0,0%)**, ambas **847 (30,4%)**, nenhuma **1512 (54,2%)**.

## ⚠️ Um achado registrado que NÃO se sustenta na população

> **Isto precisa ser corrigido no `LOTE_50.md` e não pode ir para o artigo como está.**

O achado 3 do `LOTE_50.md` justificou a classificação "não consegui olhar" dizendo que havia um
**sinal duro, sem zona cinzenta**: em 48 itens, os de corpo parseado ficavam entre 1,7 e 287,8
nós AST por linha e os quebrados todos em 0,1.

Na população inteira **os dois grupos se sobrepõem**: entre os de corpo ausente a densidade
chega a 30,0 nós/linha, e entre os de corpo sadio desce a 0,29. Há **2518 itens sadios dentro
da faixa ocupada pelos quebrados**. A separação por densidade era artefato de n=48.

**O que isso muda e o que não muda:**

- **Não muda veredito nenhum.** A regra nunca usou densidade: ela usa o critério discreto
  `blocos == 0 E chamadas_total == 0`. A densidade era só a *evidência* oferecida para dizer
  que o critério era duro.
- **Muda a frase.** Não dá para escrever "não há zona cinzenta, é classificação e não heurística
  de limiar". A frase defensável é que o critério é discreto (contagem zero, não limiar
  contínuo), e que 21 itens com corpo estão a uma unidade da fronteira.

### O que são, então, os 235 indeterminados

| | n | % |
| --- | --- | --- |
| span > 20 linhas — corpo grande, o parse falhou mesmo | 151 | 64,3% |
| span = 0 — sem intervalo de linhas | 45 | 19,1% |
| span 4–20 | 33 | 14,0% |
| span 1–3 — cara de protótipo/declaração | 6 | 2,6% |

34 deles (14,5%) têm ≤ 5 nós AST, isto é, só a assinatura — provavelmente **declaração casada no
lugar da definição**, a mesma família de bug das falhas "função não encontrada no CPG". Não muda
o tratamento (sai do `M_cur` e não conta como rótulo suspeito, que é o correto nos dois casos),
mas muda como descrevê-los.

### Concentração das perdas

Os 235 indeterminados **não** são uniformes entre projetos: `php` perde 13 de 16 itens (81,2%),
`OpenSC` 10 de 26 (38,5%), `libtiff` 10 de 40 (25,0%), `savannah` 11 de 45 (24,4%), contra
2,2% no `Android` e 4,6% no `linux`. Por CWE a diferença é menor mas existe: **CWE-125 perde
12,2%** contra 7,5% da CWE-119 e 7,0% da CWE-787.

Isso é material para as Ameaças à Validade: a perda de cobertura é **seletiva por projeto**, e
projetos com muitos itens perdidos ficam sub-representados nos três conjuntos igualmente — o que
preserva a comparação `M_cur` × `M_ctrl`, mas afeta a leitura de "quais vulnerabilidades o
modelo aprendeu".

## A causa da perda de cobertura, identificada e quantificada

*Investigado em 11/08, depois da rodada. Scripts: `_diagnosticar_falhas.py`, `_listar_metodos.sc`,
`_testar_macro.sh`, `_medir_alcance_macro.py`.*

### O mecanismo

Das 110 falhas "função alvo não encontrada no CPG", **93,6% não são erro do extrator de nome**:
o alvo *está* definido no arquivo de contexto e mesmo assim o `c2cpg` não produziu o método.

A causa é **macro de atributo na assinatura**. Em `0103__busybox`:

```c
uint8_t* FAST_FUNC udhcp_get_option32(struct dhcp_packet *packet, int code)
```

Sem o header que define `FAST_FUNC`, o parser vê dois identificadores entre o tipo de retorno e
o nome e não reconhece a definição de função. **Teste que confirma** (`_testar_macro.sh`):
removendo apenas esse token de uma cópia do arquivo, o mesmo `.c` passou de **3 para 74 métodos**
e o alvo apareceu.

Não é flakiness de ferramenta: é uma limitação estrutural de analisar C sem os headers do
projeto, e ela recai sobre os projetos que usam essa convenção — `PNGAPI` (654 assinaturas),
`RD_BOOL`, `XMLCDECL`, `KRB5_CALLCONV`, `FAST_FUNC`.

### O que isso afeta — e, principalmente, o que NÃO afeta

| | com macro detectada | sem macro |
| --- | --- | --- |
| itens | 183 (6,3%) | 2729 |
| **indeterminados** | **43/172 = 25,0%** | 192/2616 = **7,3%** |
| **`M_cur` (taxa de confirmação)** | **43/129 = 33,3%** | 804/2424 = **33,2%** |

**A leitura que importa: o problema custa COBERTURA, não enviesa o VEREDITO.** Itens com macro
de atributo têm 3,4× mais chance de virar indeterminado — mas, entre os que conseguem ser
analisados, a taxa de confirmação é **estatisticamente idêntica** (33,3% contra 33,2%).

Isso descarta a hipótese preocupante que motivou a investigação: a de que um CPG empobrecido
faria a camada 2 contar menos fluxos e empurraria o `M_cur` para baixo. Não empurra.

**Limite desta verificação:** ela só compara itens que **produziram evidência**. Se os itens
perdidos por completo tivessem taxa de confirmação diferente, isso não apareceria aqui. É um
argumento forte, não uma prova.

### Por que NÃO recuperar — decisão de 11/08

A tentação é escrever um passo de pré-processamento que remova tokens `ALL_CAPS` da assinatura.
**Não vale a pena, por quatro razões, nesta ordem:**

1. **Não moveria o resultado.** A taxa de confirmação é a mesma nos dois grupos. Recuperar
   ~144 itens acrescentaria ~48 positivos ao `M_cur` — +5,7% sobre 847, irrelevante para o
   treino, e nenhuma mudança na proporção.
2. **O "conserto" apagaria tipos de retorno.** Entre os tokens `ALL_CAPS` mais frequentes nas
   assinaturas estão `CLASS`, `WORD32`, `EAS_RESULT`, `OMX_ERRORTYPE` — que são **tipos**, não
   atributos. Uma heurística que os remova corrompe o código analisado, e distinguir tipo de
   atributo sem os headers é o mesmo problema original.
3. **Modificar o fonte analisado é passivo metodológico maior que a perda.** Hoje a limitação é
   "o parser não viu 13,7%"; com o hack passaria a ser "os resultados vêm de código que nós
   editamos por heurística".
4. **Obrigaria a refazer a medida da Etapa 5.** Uma das 50 (`0103__busybox`) é justamente uma
   dessas falhas, e 5 são indeterminadas. Mexer no pipeline muda a evidência do conjunto de
   teste e força re-medir a precisão — legítimo, mas caro para ganho nulo.

**O ganho real desta investigação não é dado recuperado, é uma frase defensável:** a perda de
cobertura tem mecanismo nomeado, teste que o demonstra (3 → 74 métodos), e evidência de que ela
não contamina a medida principal. Isso vale mais na banca que 48 funções a mais.

## O que muda a partir daqui

O card "Rodar a curadoria no conjunto inteiro" fecha. **Destrava o treino dos três modelos**,
que depende do card do pipeline do ReVeal — hoje o próximo gargalo real, e ainda sem PyTorch
instalado no WSL.

Três coisas entram na fila do artigo por causa desta rodada:

1. corrigir o achado 3 do `LOTE_50.md` (a zona cinzenta existe);
2. a §4.5 agora pode afirmar `c1 OU c2 ≡ c1` sobre a população inteira, não sobre amostra;
3. declarar a perda de cobertura seletiva por projeto (169 falhas + 235 indeterminados = **404
   de 2957, 13,7%**).
