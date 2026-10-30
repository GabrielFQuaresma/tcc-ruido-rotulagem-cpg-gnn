# Preparação das arenas externas — registro

## Situando

**Onde estamos.** O pipeline do TCC tem três partes: a curadoria (traversal v3), o dataset de
grafos (dataset v3) e o modelo (ReVeal, 13 braços treinados). O teste do BigVul foi aberto em
13/10/2026. Agora vêm as **arenas externas**: conjuntos fora do treino onde se mede se o `M_cur`
(o modelo treinado só com os 523 positivos que a traversal confirmou) generaliza melhor que os 5
controles (`M_ctrl_g`, sorteios do mesmo tamanho sem curadoria). As regras estão no
`modelo/PREREGISTRO_ARENAS.md`, **congelado em 15/10/2026, 09:06** (SHA-256 `6284d831…a01838`, no
`PLANO_TREINO.md` §4 e no cartão do Notion).

**O que este arquivo é.** O diário dos passos 2 e 3 do §10 do adendo: obter os dados, conferir a
estrutura e montar as arenas (filtro de CWE, deduplicação, arquivo, CPG, grafo). No fim do passo 3
sai a **ficha de preparação**, com as contagens por arena e por faixa de tamanho e o SHA-256 dela.

**O que ele NÃO é.** Não é resultado: nenhum modelo prevê nenhuma função de arena até o passo 5, e
nada aqui olha predição. Contar funções, ler metadados e montar grafos não é ver resultado
(`PREREGISTRO_TAMANHO.md` §3). Não é a ficha de preparação (ela é escrita no fim do passo 3).
*Exceção, desde 18/10/2026:* a seção "Passo 7" registra a abertura das arenas — essa sim é
resultado; as tabelas completas estão em `resultado_arenas.md`.

Scripts em `Dataset/bigvul/arenas/`; dados em `~/curadoria/arenas/` no WSL (fora do repositório).

## Passo 2 — obter os dados e conferir a estrutura (15/10/2026)

### Os dados

`baixar_dados.sh` (idempotente). SHA-256 de cada arquivo também em `~/curadoria/arenas/arquivos.sha256`.

| arquivo | origem | bytes | SHA-256 |
| --- | --- | --- | --- |
| `primevul/primevul_train.jsonl` | Google Drive do README oficial (pasta v0.1) | 470.918.175 | `5cadee7f3383124cc26ef6e67c8dd76c321e5461c94bef399a2f03a28767e6f5` |
| `primevul/primevul_valid.jsonl` | idem | 63.564.497 | `7f0b4d05b063c20d5cf57478128538b8c0c36354e8def7f2d4febe6773b9dc7c` |
| `primevul/primevul_test.jsonl` | idem | 66.064.689 | `c9dcab5ee897da36eccf0dbb3b510de2dab66a7dec681af29a7a28c8a53331c4` |
| `primevul/file_info.json` | idem | 56.460.581 | `bd7ccc141a22af2d4f7f9d1884f825aea5683198f0be37297b9e9f2eea3d4fda` |
| `ventivul/ventivul.csv` | Figshare, artigo 33263469 | 11.817.193 | `20126b84f19a0c6659171515b46b5b4e3cb19f3b6fe2ee27f8707783088d556c` |

Os `*_paired.jsonl` não foram baixados: avaliação por pares está fora do escopo (adendo §11). A pasta `file_contents/` do PrimeVul (os arquivos-fonte
inteiros, uma subpasta por projeto) é obtida no passo 3, só para os arquivos da arena.

### O que se conferiu (o que o §10, passo 2, manda) — nada contradiz o adendo

**PrimeVul: oficial = espelho.** Os três `.jsonl` oficiais são **idênticos byte a byte** aos do
espelho do Hugging Face usado nas contagens do adendo (`comparar_espelho.sh`). Todas as contagens do
§1 do adendo valem para os dados oficiais sem refazer.

**PrimeVul: de onde vem o arquivo inteiro** (`estrutura_file_info.py`, `estrutura_primevul.py`). O
`file_info.json` liga cada função (pelo `func_hash`) a um arquivo (`file_contents/<projeto>/
<file_hash>.txt`), com o caminho no projeto e as linhas de início e fim. Na arena da G4 (antes da
chave do corpo: 1027 vulneráveis, 31.149 não vulneráveis, 977 commits):
- **têm arquivo no `file_info`:** 856 das 1027 vulneráveis e 25.779 das 31.149 não vulneráveis; 804
  dos 977 commits têm todas as funções cobertas. O resto é buscado pelo commit (regra da G4), e
  falha é contada;
- **as duas versões do arquivo estão lá:** no mesmo commit e caminho, em geral há dois `file_hash`
  (648 de 963 pares commit–caminho). A vulnerável aponta para o arquivo **antes** do conserto; a
  versão consertada aponta para outro, o **depois** — em 695 dos 839 pares com vulnerável há negativo
  num arquivo diferente do da vulnerável. **Confirma o negativo do adendo** (irmã consertada + não
  alteradas);
- **achado:** as funções **não alteradas** apontam, quase sempre, para o arquivo **depois** do
  conserto (só em 44 dos 839 pares alguma delas aponta para o arquivo da vulnerável). O adendo manda
  extraí-las da versão **antes** (§3, regras comuns). **Não é contradição:** uma função não alterada
  tem, por definição, o mesmo corpo nas duas versões; ela é localizada no CPG do arquivo antes (o da
  vulnerável) pelo mesmo critério do BigVul (nome único no arquivo, ou hash do corpo quando há
  homônimo). Onde o arquivo antes não vier, busca-se pelo commit;
- 1632 arquivos distintos em 225 projetos a obter de `file_contents/`;
- o `func_hash` não é o MD5 do texto da função (0 de 900 testados) — não importa: a conferência do
  arquivo obtido é pelo corpo da função, com `normalizar_corpo.py`;
- hosts dos commits (para o que faltar): `github.com` 22.979 funções, `git.kernel.org` 4857,
  `git.php.net` 750, `git.gnome.org` 740, `gitlab.freedesktop.org` 637, `gitlab.com` 564, outros.

**VentiVul.** O MD5 do arquivo baixado é o publicado pelo Figshare (`e1a78082…`). A estrutura é a
que o adendo descreve no §1 (conferida em 15/10, antes do congelamento). Os `link`: no Linux, o
commit no `git.kernel.org` (árvore *stable*; o `buscar_arquivo.py` já lê essa família); no Chromium,
a revisão no Gerrit (`chromium-review`/`dawn-review.googlesource.com/c/<projeto>/+/<mudança>/
<patchset>/<caminho>`), com o caminho do arquivo — o que resolve os 37 pares sem nome de arquivo.
211 links distintos; 11 CVEs têm mais de um.

**Sonda CWE-416.** Os metadados estão no `saida_final/indice_bigvul.csv` (330 + 9254, adendo §1). Os
arquivos **não** existem: a extração original (`saida_final/relatorio_extracao.csv`) baixou só os
arquivos dos 2957 positivos do recorte. São buscados pelo `buscar_arquivo.py`, no commit pai, como no
BigVul.

## Passo 3a — deduplicação das três arenas (15/10/2026) — FEITA

**O que é.** A Decisão H do adendo: tirar da arena toda função que os modelos podem ter visto, para
que acertá-la não conte como generalizar. Três chaves, nesta ordem — **CVE, commit, corpo** (texto
da função sem comentários e com espaços colapsados, `hash_corpo` do `normalizar_corpo.py`) — e
depois a **duplicata interna** (mesmo corpo duas vezes na arena: mesmo rótulo, fica a de menor
identificador; rótulos diferentes, saem todas). Função sem corpo não pode ser comparada nem
localizada e sai como falha, contada. Feita **antes** dos grafos, como manda o §10 do adendo.

**Referências** (`deduplicar_arenas.py`):
- **treino + validação do dataset v3** (VentiVul e sonda): 20.099 funções, 641 CVEs, 701 commits,
  19.955 corpos distintos — é tudo o que os modelos tocaram;
- **BigVul inteiro** (PrimeVul, dedup estrita): 188.636 linhas, 3543 CVEs, 4058 commits, 185.953
  corpos distintos. Os corpos foram calculados nesta etapa (`hash_bigvul_inteiro.py`, 76 s; saída em
  `~/curadoria/arenas/bigvul_hash_sc.tsv`, SHA-256 `220dd7b1…5efd63`); **conferência:** nas 32.479
  linhas que já tinham hash (os negativos do split), o recalculado é idêntico em 32.479.

**Conferências.**
- Antes da chave do corpo, as quatro arenas têm **exatamente** o tamanho que o adendo registra:
  sonda 330 + 9254; VentiVul família 50 + 3326; VentiVul inteiro 263 + 13.063; PrimeVul 1027 +
  31.149 depois de CVE e commit. O script para sem gravar se não bater.
- Na sonda, nenhuma linha `vul = 0` desses commits tem outra CWE (0): o negativo é o mesmo com ou sem
  o filtro de CWE.
- **CVE em célula múltipla:** 3 células de CVE do BigVul trazem mais de uma CVE (101 linhas; ex.
  "CVE-2014-3176, CVE-2014-3177"). Pela regra (sai toda função de uma CVE que aparece na
  referência), cada uma conta; o script as separa. **Não mudou nenhum número** (as CVEs extras não
  tocam nenhuma função do PrimeVul). Os scripts de contagem do adendo não separavam; o "3540 CVEs"
  do §1 do adendo inclui também 1 valor vazio (13.440 linhas do BigVul não têm CVE; elas continuam
  cobertas pela chave do commit).

**Resultado** (`dedup_resumo.tsv`; vulneráveis / não vulneráveis):

| motivo | sonda CWE-416 | VentiVul família | VentiVul inteiro | PrimeVul |
| --- | --- | --- | --- | --- |
| candidatas | 330 / 9254 | 50 / 3326 | 263 / 13.063 | 1959 / 52.791 |
| sai por CVE | 0 / 0 | 0 / 0 | 0 / 0 | 900 / 20.992 |
| sai por commit | 0 / 0 | 0 / 0 | 0 / 0 | 32 / 650 |
| sai por corpo | 2 / 8 | 0 / 52 | 1 / 70 | 1 / 681 |
| duplicata interna (mesmo rótulo) | 0 / 11 | 0 / 0 | 0 / 25 | 0 / 69 |
| duplicata com rótulos diferentes | 5 / 5 | 0 / 0 | 14 / 14 | 1 / 1 |
| falha: sem corpo | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 18 |
| **fica** | **323 / 9230** | **50 / 3274** | **248 / 12.954** | **1025 / 30.380** |
| proporção de vulneráveis | 3,4% | 1,5% | 1,9% | 3,3% |

**Leitura.**
- As três arenas com veredito passam do **mínimo de 30 positivos** (Decisão I) com folga: sonda 323,
  VentiVul família 50, PrimeVul 1025. A família do VentiVul não perdeu nenhum positivo; a troca
  automática da G3 só dispara se mais de 20 dos 50 se perderem na extração.
- **PrimeVul:** quase toda a sobreposição com o BigVul saiu por CVE e commit (já contado no adendo);
  a chave do corpo tirou só 682 funções a mais. **VentiVul:** como o adendo previa, CVE e commit não
  tiram nada (CVEs de 2025–2026); o corpo tirou 52 não vulneráveis da família — funções antigas do
  Linux e do Chromium que não mudaram e estão no treino. **Sonda:** 10 funções saem porque o próprio
  BigVul rotula o mesmo corpo como vulnerável numa linha e não vulnerável noutra.
- **Economia de Joern:** pouca. A traversal pura (~7,3 s por função) cai de ~91 h para **~90 h**
  (sonda 9553 + VentiVul família 3324 + PrimeVul 31.405 funções); o CPG é por arquivo e só deixa de
  ser feito quando o arquivo inteiro sai.

**Arquivos** (no repositório; uma linha por função candidata, `motivo` vazio = fica):

| arquivo | linhas | SHA-256 |
| --- | --- | --- |
| `indice_sonda.tsv` | 9584 | `5fb46461f3a80e1b02437079bdfa97a78d9420818e68843b84a6bf592b9796d3` |
| `indice_ventivul_familia.tsv` | 3376 | `e405f69666aa4338c655cf53ceb38ee4c54db252c5e6d82234bc48da5e89c68b` |
| `indice_ventivul_inteiro.tsv` | 13.326 | `c58f14bed787550d27ac1d7245e254555b68546366bbfeacc829160648f6d37b` |
| `indice_primevul.tsv` | 54.750 | `9871794f97019db7c1712ee395dbb0a101c7fd5add70228d3929deda1d369656` |
| `dedup_resumo.tsv` | — | `04b9974714f57a658e91aec94c0d535c1dc9fb58344a8d93f6433dbba4f7e166` |

O identificador é `bv<linha_indice>` (sonda), `vv<linha do CSV>` (VentiVul) e `pv<idx>` (PrimeVul),
o que liga cada função de volta à fonte para a extração do grafo.

**O que isto NÃO é.** Não é resultado: nenhum modelo tocou arena. Não é a ficha de preparação:
ainda faltam as perdas da extração (arquivo, parse, localização) e a contagem por faixa de tamanho,
que só existem depois dos grafos.

## Passo 3b — grafos da sonda CWE-416 (15/10/2026) — FEITOS

**O que é.** Para cada função da sonda que ficou na deduplicação (323 vulneráveis + 9230 não
vulneráveis), o grafo pelo **mesmo caminho do dataset v3**, como manda a Decisão L ("sem regra
nova; falha sai e é contada"). `montar_sonda.py` **importa** as peças do v3 em vez de copiá-las:
`buscar_arquivos_do_commit` (arquivo no commit pai), `c2cpg.sh <arquivo> --output cpg.bin` (um CPG
por arquivo), `nome_da_funcao` (nome tirado do `func_before`), `montar_dataset.escolher` (nome
único no arquivo; havendo homônimo, os dois hashes do corpo), `exportar_grafos.sc` e o filtro
`montar_dataset.fora_da_funcao`. Positivo sem nome de arquivo no BigVul tem o arquivo achado pelo
patch; negativo sem nome de arquivo sai — as duas regras do v3.

**Conferência de alinhamento:** o texto, o rótulo e o commit tirados do CSV completo batem com o
`indice_sonda.tsv` em 9553 de 9553 (commit, rótulo e hash do corpo: 0 diferenças).

**Downloads:** 230 pedidos (um por arquivo de commit, mais um por positivo sem nome de arquivo):
227 ok; 2 sem caminho no patch (exempi, `cgit.freedesktop.org`); 1 arquivo que não existe no commit
pai (Chromium, `app_controller_service.cc`, provavelmente criado pelo próprio commit). 217 arquivos
viraram CPG.

**Resultado** (`grafos_sonda.tsv`, uma linha por função; vulneráveis / não vulneráveis):

| status | vuln. | não vuln. | o que é |
| --- | --- | --- | --- |
| **grafo** | **258** | **7751** | localizado e exportado |
| `sem_metodo` | 50 | 838 | nenhum método com aquele nome **e com corpo** no CPG |
| `sem_nome_de_arquivo` | 0 | 624 | negativo sem `file_name` no BigVul (regra do v3) |
| `sem_arquivo_baixado` | 13 | 0 | os 3 downloads que falharam (2 + 11 funções) |
| `ambiguo` | 2 | 16 | homônimos que o hash do corpo não desempatou |
| `sem_nome_de_funcao` | 0 | 1 | o extrator não achou nome |

**O `sem_metodo` é o comportamento do caminho do v3, não erro novo.** Em todas as 888 o nome
aparece no texto do arquivo; o que falta é o método com corpo no CPG. Causas vistas: funções
definidas por macro (`PHP_FUNCTION(...)`, `PHP_METHOD(...)` — o extrator devolve o nome da macro),
arquivos C++ que o `c2cpg` não parseia (ex.: `shell_surface.cc`, 0 de 59) e funções que somem do
CPG em arquivos com muita macro. No BigVul, a amostra do `LOCALIZACAO.md` (1302 negativos) deu
2,7% sem método + 9,8% com método sem corpo = **12,5%**; na sonda, entre as que chegaram à
localização, **10,0%** (888 de 8916). Nada foi consertado só aqui: seria uma regra que o treino não
teve.

**Perda desigual entre rótulos, declarada:** perdem-se 20,1% das vulneráveis (65 de 323) e 16,0%
das não vulneráveis (1479 de 9230). Os negativos perdem sozinhos os 624 sem nome de arquivo; os
positivos perdem mais no `sem_metodo` (16,1% contra 9,7% das que chegaram à localização) —
macros do PHP e arquivos C++ do Chromium concentram positivos.

**Invariantes** (`conferir_grafos.py sonda`): nó fora da faixa de linhas da função 0; aresta para
nó inexistente 0; id repetido 0; contagem de nós/arestas inconsistente 0; grafo de função que não
ficou na deduplicação 0.

**Contagem por faixa de tamanho** (Decisão I; vulneráveis / não vulneráveis):

| faixa (nós) | vuln. | não vuln. | % vuln. |
| --- | --- | --- | --- |
| até 46 | 72 | 4275 | 1,7% |
| 47–131 | 78 | 2331 | 3,2% |
| 132–339 | 74 | 893 | 7,7% |
| 340+ | 34 | 252 | 11,9% |
| **total** | **258** | **7751** | 3,2% |

As quatro faixas passam de 30 positivos e 30 negativos: na sonda, **V1 e V2 se aplicam
integralmente**, e a arena passa do mínimo por arena (258 ≥ 30).

**Arquivos.** `grafos_sonda.tsv` (no repositório, SHA-256
`c24b955b87902f47c0dc81a93d62c12807b3a33367de42467699af35b1b3b7b4`); os grafos em
`~/curadoria/arenas/sonda/grafos/` (191 MB, um `.jsonl` por arquivo, no mesmo formato do dataset
v3) e os arquivos-fonte e CPGs em `~/curadoria/arenas/sonda/arquivos/`.

**Falta da sonda, para a ficha:** a taxa de tokens fora do vocabulário (sai na vetorização, com o
Word2Vec do treino) e a traversal pura (passo 4).

## Passo 3c — grafos do VentiVul (15/10/2026) — FEITOS

**O que é.** Grafos de todas as funções do VentiVul que ficaram na deduplicação em alguma das duas
arenas (família de memória, que decide; inteiro, descritivo): 13.202 funções. `montar_ventivul.py`;
a exportação (CPG → localização → grafo) é a do `comum_grafos.py`, o mesmo código da sonda.
*Refatoração conferida:* a sonda passou a usar o `comum_grafos.py`; rodada de novo, pulou os 217
grupos (mesma assinatura) e o `grafos_sonda.tsv` saiu com o mesmo SHA-256.

**Qual arquivo e qual versão** (adendo §3 e G3). O arquivo inteiro não vem nos dados; busca-se pelo
`link`: no Linux, o commit no `git.kernel.org` (antes = `<sha>^`, depois = `<sha>`); no Chromium (e
v8, angle, libvpx, dawn, vboot), a revisão no Gerrit (depois = o arquivo naquela revisão; antes = o
mesmo com `?parent=1`). Vulnerável e não relacionada → arquivo **antes**; versão consertada →
arquivo **depois**. 216 caminhos × 2 versões = **432 arquivos, todos baixados**.

**As não relacionadas e o arquivo codificado.** O nome do arquivo delas codifica a CVE, não o
caminho. Para cada arquivo codificado, os candidatos são os arquivos **antes** dos pares daquela(s)
CVE(s); fica o candidato onde aparece a maior fração dos nomes de função do arquivo codificado
(cobertura). **197 dos 199** arquivos codificados foram ligados (cobertura mediana 1,0, mínima
0,825; só 2 abaixo de 0,9); 1 é de uma CVE que não existe nos pares (83 funções) e 1 não tem nenhum
nome em comum com o candidato (73 funções) — saem como falha. A ligação está em
`ventivul_mapa_codificados.json` e a resolução dos pares em `ventivul_pares.json` (no repositório).

**Dois defeitos achados e corrigidos durante a montagem** (registrados porque mexem no que roda):
1. O caminho do único par do Linux sem nome de arquivo era resolvido consultando o patch no
   `git.kernel.org` **a cada execução**; o patch falha de forma intermitente e uma execução quebrou.
   Agora a resolução é gravada uma vez (`pares.json`) e, se faltar, procura-se primeiro nos arquivos
   já baixados daquele commit; as fases seguintes se recusam a rodar sem ela.
2. Numa execução em que essa consulta falhou, o mapa dos arquivos codificados foi **regravado
   degradado** (196 ligados em vez de 197) e 55 grupos foram exportados com ele. Corrigido: o mapa só
   é gravado com todos os pares resolvidos; com o mapa restaurado (de novo 197), os grupos cujo pedido
   mudou foram refeitos sozinhos (a assinatura do grupo muda). O resultado final não depende dessa
   execução.

**Resultado** (`grafos_ventivul.tsv`; vulneráveis / não vulneráveis):

| status | família de memória | VentiVul inteiro |
| --- | --- | --- |
| ficaram na deduplicação | 50 / 3274 | 248 / 12.954 |
| **grafo** | **48 / 2778** | **229 / 10.225** |
| `sem_metodo` | 1 / 470 | 18 / 2522 |
| `ambiguo` | 0 / 25 | 0 / 42 |
| arquivo codificado não ligado | 0 / 0 | 0 / 156 |
| `sem_nome_de_funcao` | 1 / 1 | 1 / 9 |

**O `sem_metodo` alto nas não relacionadas (~20%) não é ligação errada.** Em 2529 das 2540, o nome
**e** o corpo da função aparecem no próprio arquivo usado — arquivo e versão estão certos; falta o
método com corpo no CPG. Duas causas vistas: (1) parte das "funções não relacionadas" do VentiVul não
é função — há trechos que começam no cabeçalho do arquivo (`// SPDX-License-Identifier…`) e corpos de
classe C++ inteiros (`class … final {`), que o extrator de nome não tem como casar com um método;
(2) as falhas de parse do Joern em C do kernel e em C++, as mesmas da sonda e do BigVul. Por isso a
perda cai mais nas não relacionadas (Linux 17%, Chromium 22%) que nas vulneráveis (7%). Pela regra
congelada, saem e são contadas; nada foi consertado só aqui.

**Perda desigual entre rótulos, declarada:** família 4% das vulneráveis (2 de 50) contra 15% das
não vulneráveis (496 de 3274); inteiro 8% contra 21%.

**Invariantes** (`conferir_grafos.py ventivul_familia ventivul` e `… ventivul_inteiro ventivul`):
todas 0 nas duas arenas.

**Contagem por faixa de tamanho** (vulneráveis / não vulneráveis):

| faixa (nós) | família | inteiro |
| --- | --- | --- |
| até 46 | 6 / 1391 | 50 / 5395 |
| 47–131 | 17 / 968 | 81 / 3224 |
| 132–339 | 17 / 349 | 70 / 1265 |
| 340+ | 8 / 70 | 28 / 341 |
| **total** | **48 / 2778** (1,7%) | **229 / 10.225** (2,2%) |

**O que a contagem decide, mecanicamente (Decisão I):**
- **família:** 48 positivos ≥ 30 → **tem veredito** (a troca automática da G3 não dispara: perdeu 2
  de 50). Nenhuma faixa chega a 30 positivos → F1 e recall por faixa só com a contagem, e o **V2
  "não se aplica"** (nenhuma faixa pequena com 30). As faixas até 46 e 340+ têm ≥ 30 negativos (1391
  e 70) → o **V1 se aplica**. O veredito de tamanho na família sai só do V1;
- **inteiro** (descritivo): 340+ fica com 28 positivos, abaixo de 30; as outras três passam.

**Arquivos.** `grafos_ventivul.tsv` (SHA-256 `f75921ba91ba6925dbf766fe18228585c24497b3fda3b3b8617a1ee6efc83aba`),
`ventivul_mapa_codificados.json` (`a0b6eb8b…1be27f`), `ventivul_pares.json` (`4723fada…a9e33`);
grafos em `~/curadoria/arenas/ventivul/grafos/` (245 MB), arquivos e CPGs em
`~/curadoria/arenas/ventivul/arquivos/` (103 MB).

## Vetorização e tokens fora do vocabulário (15/10/2026)

**O que é.** O ReVeal dá a cada nó o rótulo do nó mais a média dos vetores Word2Vec dos tokens do
`code` do nó (`modelo/vetorizar.py`, passo C). Nas arenas nada é ajustado em dado de arena (adendo
§0): `vetorizar_arena.py` usa o **Word2Vec do treino** (`~/curadoria/modelo/vetores/word2vec.model`,
SHA-256 `20585c12…618392`) e os índices de rótulo de nó e de aresta do treino; token fora do
vocabulário conta como vetor zero. **Conferência:** vetorizados com este script, os 500 primeiros
grafos do dataset v3 saem **idênticos** aos vetores gravados no treino (500 de 500) — o laço é o
mesmo do treino, não uma reimplementação aproximada.

**Taxa de tokens fora do vocabulário** (tokens de nó cujo vetor é zero porque o Word2Vec do treino
não os viu; a ficha de preparação pede este número):

| conjunto | tokens calculados | fora do vocabulário | taxa |
| --- | --- | --- | --- |
| dataset v3 inteiro (registro do treino; inclui o próprio corpus do Word2Vec) | 20.682.431 | 964.617 | 4,7% |
| **teste do BigVul** (o Word2Vec não o viu — a comparação justa) | 5.467.742 | 586.098 | **10,7%** |
| sonda CWE-416 | 3.951.192 | 479.888 | **12,1%** |
| VentiVul (família + inteiro, mesma pasta) | 5.138.935 | 929.451 | **18,1%** |
| PrimeVul | 22.299.437 | 3.032.248 | **13,6%** |

Leitura: a sonda fica perto do teste do BigVul (mesmo conjunto, outros commits); o VentiVul, código
de 2025, fica acima. Vetores em `~/curadoria/arenas/<arena>/vetores/`, com os mesmos nomes de
arquivo do treino.

## Passo 3d — grafos do PrimeVul (15/10/2026) — EM ANDAMENTO

**O que é.** Grafos das 1025 vulneráveis + 30.380 não vulneráveis que ficaram na deduplicação
estrita. `montar_primevul.py`; a exportação é a do `comum_grafos.py` (o mesmo código da sonda e do
VentiVul).

**Quem é irmã consertada e quem é não alterada.** O adendo manda a irmã para o arquivo **depois** e
a não alterada para o **antes** (§3), mas o PrimeVul não marca qual é qual. Pela construção dele, de
cada commit só ficam a vulnerável, a versão consertada dela e as não alteradas (as outras funções
alteradas são descartadas); então a irmã é a não vulnerável com o **mesmo nome** de uma vulnerável
do mesmo commit e do mesmo arquivo. Conferência: das 946 irmãs assim classificadas (entre as
candidatas), só **3** apontam no `file_info` para o mesmo arquivo da vulnerável — o resto aponta
para o arquivo depois, como deve.

**De onde vem cada arquivo** (G4: "da própria v0.1; se não vier, busca-se pelo commit"). O
`file_contents/` do PrimeVul é lido do Google Drive (listagem pública da pasta de cada projeto; os
nomes dos arquivos são os do `local_file_path` do `file_info`; GIMP e udev não estão lá). O
**antes** de um (commit, caminho) é o arquivo das vulneráveis daquele caminho; o **depois**, o das
irmãs. Quando o `file_contents` não tem, vai pelo commit: antes pelo `buscar_arquivos_do_commit`
(commit pai), depois pela mesma URL sem o `^` (com o mesmo espelho do GitHub para host extinto).

**Planejamento** (`montar_primevul.py planejar`; só conta, nada baixado):

| tipo | versão | arquivo do `file_contents` | arquivo pelo commit |
| --- | --- | --- | --- |
| vulnerável | antes | 855 | 170 |
| irmã consertada | depois | 747 | 184 |
| não alterada | antes | 21.454 | 7995 |

1882 arquivos a obter (antes: 839 do `file_contents` + 291 pelo commit; depois: 618 + 134). As não
alteradas que vão pelo commit são, em geral, as de arquivos do commit sem vulnerável: delas o
`file_contents` só guarda o arquivo depois, e o adendo pede o antes.

**Downloads** (`montar_primevul.py baixar`, ~1,8 s por arquivo): **1789 de 1882 obtidos** — 1456 do
`file_contents` e 333 pelo commit (GitHub, espelho no GitHub, gitweb, cgit). **93 falharam (4,9%)**
e saem como falha contada: 30 de servidor que o buscador não conhece (GitLab e outros), 30 "depois"
cujo "antes" também falhou (não há caminho de onde herdar), 17 sem caminho no patch, 16 de arquivo
que não baixou do commit pai. *Defeito achado e corrigido:* quando a função não tem `file_info` nem
nome de arquivo, o pedido "depois" não aproveitava o caminho que o "antes" do mesmo commit
descobrira pelo patch — 134 pedidos falharam por isso na primeira passada; corrigido, a passada de
novas tentativas (`--refazer-falhas`) recuperou 104 das 197 falhas.

**Primeira exportação (15–16/10)** — 1789 grupos, em três execuções (duas encerradas por falta de
memória no Windows com a sessão ociosa, uma pelo desligamento do computador; a exportação é
retomável e pulou o que já estava pronto). Resultado: 840 vulneráveis + 19.528 não vulneráveis com
grafo; `sem_metodo` 151 / 9680; arquivo não baixado 34 / 997; sem nome 0 / 116; `ambiguo` 0 / 58;
nó fora da função 0 / 1. Invariantes todas 0.

**Diagnóstico do `sem_metodo` alto (32% das não vulneráveis)** — o mesmo teste do VentiVul: o corpo
da função aparece no arquivo usado?
- **~7490 (76%) sim** → arquivo certo, o CPG não tem o método: bibliotecas só de cabeçalho que o
  Joern não parseia (`CImg.h`: 2622 funções, 0 grafos; `stb`: 219, 0), macros (`TEST(...)`,
  `PJ_DEF(...)`), `operator`, C++ com templates (`fmt`). Limitação do caminho do v3: sai e é contada.
- **~2340 (24%) não** → **defeito meu**: quase todas são não alteradas **sem `file_info` e sem nome
  de arquivo**. Todas as desse tipo de um commit iam para UM pedido, que baixava UM arquivo (o da
  primeira função); as dos outros arquivos do commit ficavam sem o arquivo certo. São 5486 funções
  sem caminho, em 173 commits (2299 delas tinham grafo só porque o nome casou no arquivo que veio).

**Correção (16/10): fase `resolver`.** Para cada um dos 173 commits, os arquivos de código do patch
são baixados na versão antes e cada função vai para o arquivo cujo texto contém o **corpo** dela
(sem espaços; vários → o que contém o corpo inteiro); a irmã vai para o caminho da vulnerável de
mesmo nome. Quem não é achado sai como falha "arquivo não identificado no commit" — em vez de ficar
preso a um arquivo qualquer (G4: "se nem assim, é falha contada"). Antes de usar, um teste de
regressão: o planejamento refatorado, sem a resolução, reproduz **idêntico** o plano anterior
(31.405 funções, 1882 pedidos). Commits em que nenhum arquivo baixou (o `git.kernel.org` falha de
forma intermitente) são tentados de novo (`resolver --refazer-falhas`).

**Resultado da busca pelo commit (16/10):** das 5486 funções sem caminho, 4402 foram ligadas ao
arquivo pelo corpo, 154 irmãs herdaram o caminho da vulnerável, 921 não foram achadas e 9 ficaram
ambíguas (→ 930 "não identificadas", das quais 35 vulneráveis). Quase todas as não achadas estão em
commits dos quais nenhum arquivo veio: servidores que o buscador do BigVul não cobre (GitLab:
`gitlab.com`, `gitlab.freedesktop.org`, `gitlab.gnome.org`, `git.lysator.liu.se`; `bitbucket.org`) ou
que saíram do ar (`git.gnome.org`, que migrou para o GitLab) ou não responderam (savannah, gnunet,
cyrusimap, samba, linuxtv). A nova tentativa nos commits sem arquivo não recuperou nenhum. *Opção em
aberto, para o autor:* acrescentar a família GitLab ao buscador recuperaria ~24 vulneráveis e ~570
não vulneráveis; não foi feito (a arena tem folga: >800 vulneráveis contra o mínimo de 30; o adendo
trata isso como falha contada). Replanejado (1861 pedidos), baixados os 285 novos (todos ok),
re-exportados 304 grupos; os 241 grupos que deixaram de existir (os pedidos únicos "sem caminho")
foram **movidos** para `grafos_obsoletos/` (fase `limpar`), para nada ser contado duas vezes.

**Resultado final do PrimeVul** (`grafos_primevul.tsv`; vulneráveis / não vulneráveis):

| status | vuln. | não vuln. |
| --- | --- | --- |
| ficaram na deduplicação | 1025 | 30.380 |
| **grafo** | **843** | **20.806** |
| `sem_metodo` | 147 | 8234 |
| arquivo não identificado no commit | 35 | 895 |
| arquivo não baixado | 0 | 270 |
| `sem_nome_de_funcao` | 0 | 116 |
| `ambiguo` | 0 | 58 |
| nó fora da função | 0 | 1 |

Do `sem_metodo` que sobrou, **95,5% têm o corpo no arquivo usado** (arquivo certo, limite de parse:
CImg, stb, macros, templates C++); o resto (379) é residual. Invariantes todas 0 (sem id repetido
depois da limpeza). Por faixa de tamanho: 49 / 7496 · 158 / 7344 · 275 / 4054 · 361 / 1912 — as
quatro com ≥ 30 positivos. Tokens fora do vocabulário: **13,6%** (3.032.248 de 22.299.437). Perda
desigual, declarada: 18% das vulneráveis, 32% das não vulneráveis (concentrada em projetos só de
cabeçalho, quase todos negativos). *Conferência do vetorizador alterado:* a sonda, revetorizada,
sai com os mesmos SHA-256 nos cinco arquivos.

**Outros dois defeitos meus, achados e corrigidos na mesma noite:**
- `comum_grafos.ler_resultados` guardava na memória os grafos inteiros (nós e arestas) só para montar
  o índice; com os 20 mil grafos do PrimeVul estourou a memória e **derrubou o WSL** duas vezes
  ("falha catastrófica", `E_UNEXPECTED`). Agora guarda só os campos leves; nenhum arquivo gerado muda.
- `vetorizar_arena.py` juntava os vetores de todos os grafos numa lista antes de gravar (~2 GB de
  pico no PrimeVul). Passou a gravar direto em arquivo mapeado, em duas passadas, como o
  `vetorizar.py` do treino.

## Fim do passo 3 — ficha de preparação gravada (16/10/2026, 02:52)

`arenas/FICHA_PREPARACAO.md`, gerada por `ficha_preparacao.py` só com contagens (nenhuma predição
existe). **SHA-256 `e5ead1350a014d70851e9fcc1e546071e916f0a7afcb3ff483d5324ce18b842e`**, registrado
também no `analisar_arenas.py` (que se recusa a abrir se a ficha mudar) e no cartão do Notion. O que
ela fixa: as três arenas com veredito passam do mínimo (sonda 258 / 7751; VentiVul família 48 / 2778;
PrimeVul 843 / 20.806); a troca automática da G3 não dispara; checagem de tamanho com V1 e V2 na sonda
e no PrimeVul, só V1 na família do VentiVul (nenhuma faixa com 30 positivos). Se algo da preparação
precisar mudar depois disto (por exemplo, a opção GitLab do PrimeVul), sai uma ficha nova, com hash
novo e o motivo.

## Passo 4 — traversal pura (16/10/2026) — EM ANDAMENTO

**Ensaio** (`rodar_traversal_arena.py --arena todas --ensaio 20`; semente 8080, nunca usada antes; 17
sorteadas + 3 homônimas por arena): congelamento dos 4 arquivos de regra confere; **60 de 60 funções
com evidência**, nenhuma falha; ~7,4 s por função na sonda, ~8 s no VentiVul, ~7,5 s no PrimeVul.
Filas: sonda 8009 funções (314 homônimas, com a linha do método), VentiVul família 2826 (219),
PrimeVul 21.649 (523). **Rodada completa iniciada em 16/10/2026, ~03:10** (`--arena todas
--retomar`, em segundo plano; retomável): 32.484 funções, ~69 h projetadas (~2,9 dias). Grava só a
evidência; nenhum veredito é aplicado antes da abertura.

**Interrupções.** Três vezes, entre a madrugada e as 11h de 16/10, o ambiente de execução encerrou o processo
em segundo plano por pouca memória livre no Windows. Cada vez a rodada foi retomada com `--retomar`.
Nada se perde: cada função grava o seu JSON ao terminar, e a que estava no meio é refeita. Custo:
~30 min de parede no total, medido nas horas em que saíram ~400 funções em vez das ~490 de costume.

**Desvio de execução declarado: duas fatias em paralelo (16/10/2026, ~17h, decisão do autor).**
- *O que o adendo dizia.* Decisão K: "pelo mesmo executador da rodada nas negativas do BigVul
  (`rodar_traversal_negativos.py`, adaptado só no caminho dos arquivos)".
- *O que mudou.* O executador ganhou a opção `--fatia k/n`, e rodam duas cópias ao mesmo tempo
  (`--fatia 0/2` e `--fatia 1/2`, ambas com `--arena todas --retomar`). Cada cópia pega só as funções
  cujo id cai na sua fatia (SHA-1 do id, módulo 2), que é uma divisão fixa, independente da ordem e
  do que já foi feito. Cada cópia usa a sua própria pasta de trabalho do Joern
  (`~/curadoria/_trabalho_trav_arenas_f0` e `_f1`): o `chamar()` apaga `workspace/` ao fim de cada
  função, e duas cópias na mesma pasta apagariam o trabalho uma da outra.
- *O que não mudou.* A regra (conferência do hash dos 4 arquivos antes de rodar), a chamada ao
  Joern, a leitura da evidência e a pasta de saída. Cada função continua julgada sozinha, numa
  chamada própria do Joern, e a ordem não importa.
- *Por quê.* Para encurtar a rodada. Faltavam 25.750 funções no momento da troca (sonda 1315,
  VentiVul família 2806, PrimeVul 21.629).
- *Conferência* (`_conferir_fatias.py`). Foram rodadas de novo, pelas duas fatias **ao mesmo
  tempo**, 20 funções da sonda que já tinham saída: as primeiras de cada fatia na ordem da fila (8
  sem homônimo + 2 com linha por fatia), sem sorteio. A pasta de saída era à parte. Resultado: **20
  de 20 com evidência idêntica** à da rodada sequencial, comparando os campos `evidencia`, `falha`,
  `linha` e `linha_por_trava`.
- *Ganho real, menor que o estimado.* As mesmas 20 funções somaram 166 s na rodada sequencial e
  levaram 132 s de parede em paralelo, ou seja, **~1,26× mais rápido**, e não ~2×. Cada chamada do
  Joern passou de 8,3 s para 13,2 s em média. O motivo é o processador: um i5-12450H tem 4 núcleos
  de desempenho (8 threads) e 4 de eficiência, e com duas cópias a CPU do WSL ficou 63% ocupada em
  média (30 s medidos), sem espera de disco. A largada da máquina Java usa várias threads, e duas
  largadas juntas disputam os núcleos rápidos. Projeção: ~43 h em vez de ~54 h.
- *Divisão do que faltava:* sonda 628 / 687, VentiVul família 1378 / 1428, PrimeVul 10.988 /
  10.641 (fatia 0 / fatia 1).
- *Ritmo real nas primeiras ~5,3 h (17h–22h30 de 16/10).* Saíram 3603 funções: o resto da sonda
  (1315) e 2288 do VentiVul família. Isso dá ~5,3 s de parede por função, contra ~7,5 s da rodada
  sequencial, ou seja, **~1,4×**, um pouco melhor que o ~1,26× da conferência de 20 funções. Às
  ~22h30 as duas cópias foram encerradas juntas por pouca memória no Windows e retomadas às 22h40
  com `--retomar`.
- **Sonda terminada:** 8009 de 8009 com saída, 8008 com evidência e 1 `timeout_joern`, que fica
  para a passada final `--retentar-timeout`.
- **VentiVul família terminado** (16/10, 23h41): 2826 de 2826 com evidência, nenhuma falha.

**Memória do WSL (17/10): dois problemas de execução, achados e contornados sem tocar na regra nem
no executador.**
1. *Cache de arquivos.* O `vmmemWSL` (a memória que o Windows vê o WSL usando) subiu de 0,76 GB
   (16/10, 22h38) para 4,4 GB (17/10, 11h25), mas os processos somavam só ~1,1 GB; o resto era cache
   de arquivos do Linux. O `autoMemoryReclaim=gradual` do `.wslconfig` só devolve essa memória
   com a VM ociosa, e com a traversal rodando ela nunca fica. **Contorno:** soltar o cache como root
   (`sync; echo 1 > /proc/sys/vm/drop_caches`, só páginas limpas, sem perder dado). Medido: o WSL
   caiu de 4405 para 2633 MB, e o Windows ganhou +1,0 GB livre.
2. *Java órfão do Joern no timeout (vazamento).* Às 13h09 de 17/10 o WSL estava com 85 MB
   disponíveis, e havia três máquinas Java grandes (~1,7 GB cada) num arquivo do PrimeVul
   (`651a0d3ef458__antes__jsiEval.c`). Uma delas tinha 436 s de idade, com timeout de 300 s.
   **Causa:** no `chamar()` (do executador do BigVul, importado sem alteração), o
   `subprocess.run(..., timeout=300)` mata só o processo filho direto, que é o script `joern`. As
   duas máquinas Java que ele abriu (o lançador e o Joern de fato) ficam órfãs, adotadas pelo
   processo inicial da sessão do WSL, e seguem rodando sem que ninguém leia a saída delas.
   **Contorno:** um vigia (`vigia.sh`, como root, lançado à parte; log em
   `~/curadoria/vigia_traversal.log`) que a cada 15 s mata toda máquina Java com mais de 330 s de
   idade. Nenhuma chamada viva passa de 300 s, então todo Java acima disso é órfão. O mesmo vigia
   solta o cache a cada 45 min.
   - *O que o vigia NÃO faz:* não mata chamada viva, não muda o resultado de nenhuma função e não
     toca no executador. A chamada que estourou o tempo já foi gravada como `timeout_joern` antes
     de o órfão ser morto.
   - *Possível efeito no resultado, e como fica neutralizado.* Um órfão disputa memória e
     processador com as chamadas seguintes. Isso pode transformar em timeout uma função que, com a
     máquina livre, terminaria a tempo. Na traversal pura, timeout é falha da ferramenta e conta
     como "não acusa". Por isso a **passada final `--retentar-timeout` vai rodar com uma cópia só,
     sem fatia, com o vigia ligado**: cada função que estourou o tempo é refeita sozinha, na mesma
     condição da rodada sequencial. Timeouts até aqui: 1 na sonda e 1 no PrimeVul (`pv520459`,
     `jsiVarDeref`, nesse mesmo `jsiEval.c`).
3. *Defeito meu no vigia v1, que estragou uma saída.* A v1 media a idade com `ps etimes`, que
   depende do relógio de parede. Às 17h08m45 de 17/10 o relógio do WSL deu um salto, e um Java
   recém-nascido apareceu com 4.123.168.608 s de idade. O vigia o matou, e a chamada viva da função
   `pv372066` (`h2s_frt_make_resp_data`, PrimeVul) saiu com a falha "No java installations was
   detected". Foi a única: o log do vigia v1 tem 3 mortes, das quais as outras 2 eram os órfãos de
   verdade das 13h13.
   - **Correção (vigia v2):** a idade passa a ser medida pelo relógio desde o boot
     (`/proc/uptime` contra o campo 22 de `/proc/<pid>/stat`), que nunca anda para trás. Também
     ganhou uma trava: só mata entre 330 s e 100.000 s de idade.
   - **A saída estragada** foi movida, sem apagar, para
     `~/curadoria/arenas/primevul/traversal_invalidadas/`, junto com um `MOTIVO.txt`, e é refeita
     pelo `--retomar`.

**Execução destacada do terminal (17/10, 22h02).** Às ~22h as duas cópias foram encerradas de novo
pelo ambiente de execução por pouca memória no Windows. Na retomada, as duas fatias e o vigia passaram a
rodar como processos `wsl.exe` destacados (`Start-Process -WindowStyle Hidden`), fora do
encerramento automático do ambiente de execução. Cada fatia roda num laço de retomada
(`rodar_fatia.sh`: `--retomar`, até 20 tentativas, 60 s entre elas) com log em
`~/curadoria/trav_f0.log` e `trav_f1.log`. Nesse momento, o PrimeVul tinha 14.829 de 21.649
funções com saída.

**Fim da rodada (18/10).** A fatia 1 terminou às 8h02 e a fatia 0 às 8h32, ambas sem nenhuma
retomada depois de destacadas do terminal. O vigia matou mais 3 órfãos, às 5h29, 6h37 e 7h02, um
para cada timeout novo.

**Passada final** (`--retentar-timeout`, uma cópia só, sem fatia, com o vigia ligado; 18/10,
9h08–9h42; a parte do PrimeVul foi relançada às 9h20, destacada do terminal, depois de uma queda por
memória). Foram refeitas, sozinhas, as 6 funções que tinham estourado o limite de 300 s, e **as 6
estouraram de novo**:

| arena | id | função | arquivo |
| --- | --- | --- | --- |
| sonda | bv64238 | `dirsection` | `core.c` |
| PrimeVul | pv520459 | `jsiVarDeref` | `jsiEval.c` (antes) |
| PrimeVul | pv520634 | `jsi_evalcode_sub` | `jsiEval.c` (antes) |
| PrimeVul | pv233147 | `ndpi_set_proto_defaults` | `ndpi_main.c` (antes) |
| PrimeVul | pv216804 | `enhanced_recursion` | `term.c` (antes) |
| PrimeVul | pv506600 | `enhanced_recursion` | `term.c` (depois) |

Os timeouts, portanto, não foram efeito do paralelo nem dos órfãos: com a máquina livre, a regra
também não termina essas funções em 300 s. Elas ficam como falha da ferramenta, que conta como
"não acusa" (PREREGISTRO_PRINCIPAL.md §7).

**Traversal pura COMPLETA nas três arenas (18/10/2026, 9h42):**

| arena (conjunto com veredito) | funções | com evidência | falha (timeout do Joern) |
| --- | --- | --- | --- |
| Sonda CWE-416 | 8009 | 8008 | 1 |
| VentiVul v3, família de memória | 2826 | 2826 | 0 |
| PrimeVul v0.1 | 21.649 | 21.644 | 5 |
| **total** | **32.484** | **32.478** | **6** (0,02%) |

Tempo de Joern somado: 18,2 h (sonda) + 8,5 h (VentiVul) + 65,4 h (PrimeVul) = 92,1 h. Em parede,
foram ~55 h, de 16/10 às 3h10 a 18/10 às 9h42, contando as quedas e a troca para duas fatias. O
adendo projetava ~3,8 dias (~91 h) de Joern, e a soma bateu por coincidência de dois efeitos
opostos. Havia menos funções que na projeção (32.484 contra ~45 mil antes das perdas). Em compensação,
cada chamada ficou mais lenta com duas cópias disputando o processador: mediana de 10,8 s no
PrimeVul, contra os 7,3 s projetados. Em parede, as duas fatias encurtaram a rodada.
Nenhum veredito foi aplicado: ele sai na abertura. Com isso, a trava da Decisão K está cumprida, e
o passo 5 (predições) pode rodar.

## Passo 5 — predições gravadas (18/10/2026, 9h44–10h23) — FEITO

`inferir_arena.py --arena sonda | ventivul | primevul`, em sequência, lançado destacado do terminal
(`prever_arenas.sh`; log em `~/curadoria/inferir_arenas.log`). O caminho de inferência é o mesmo
que reproduziu o teste do BigVul na conferência de 16/10, com 0 predições diferentes em 2.234.700.
Nada foi retreinado nem ajustado; só se gravou id, probabilidade e predição (limiar 0,5).

| arena | braços | arquivos (braço × semente) | funções por arquivo | tempo |
| --- | --- | --- | --- | --- |
| Sonda CWE-416 | 13 | 390 | 8009 | ~5 min |
| VentiVul v3 inteiro (contém a família) | 13 | 390 | 10.454 | ~6 min |
| PrimeVul v0.1 | 13 | 390 | 21.649 | ~28 min |

Nenhum erro no log. A conferência foi só de contagem: número de arquivos e de linhas por arquivo.
**Nenhum valor de predição foi aberto, e nenhuma métrica foi calculada.** Quem lê é o
`analisar_arenas.py --abrir`, na abertura com o autor presente (§10 passo 7).

**Decisão do autor (18/10/2026, antes de abrir): GitLab no PrimeVul NÃO será feito.** Era a opção
de acrescentar ao buscador os projetos hospedados no GitLab (~24 vulneráveis e ~570 não
vulneráveis recuperáveis). Fica declarado como perda por arquivo que não se obtém. O PrimeVul segue
com o que está na ficha (843 / 20.806). A decisão foi tomada antes de qualquer resultado das arenas
existir.

**Aviso: o `--ensaio-sintetico` NÃO pode ser repetido antes da abertura.** As predições dele são
aleatórias, mas ele passa à análise a evidência REAL da traversal e os rótulos REAIS das arenas. Em
16/10 isso só exercitava o código, porque a traversal tinha apenas as 20 funções do ensaio por arena.
Com a traversal completa, ele calcularia o resultado real da traversal pura (Decisão K) antes da
abertura. O passo 6 já foi cumprido em 16/10: ensaio na validação do BigVul (390 de 390 iguais) e
ensaio sintético. Desde então nada mudou no que a análise lê. O `analisar_arenas.py` não importa o
`rodar_traversal_arena.py`, o único script alterado depois disso, por causa das fatias. A conferência
dos hashes (os pré-registros, o adendo, a regra da traversal e a ficha) roda de novo no início do
`--abrir` e recusa seguir se algum não bater.

## Passo 7 — abertura das três arenas (18/10/2026, 14:26) — FEITA

**Situando.** É o passo 7 do §10 do adendo: as três arenas abertas juntas, uma vez, com o autor
presente. É aqui que se mede a pergunta do TCC: o `M_cur` (o ReVeal treinado só com os 523
positivos que a traversal confirmou) generaliza melhor fora do BigVul que os 5 `M_ctrl_g` (mesmo
tamanho, 523 positivos sorteados sem curadoria)? Pedido do autor nesta sessão: *"Vamos fazer a
abertura das arenas (passo 7 do modelo/PREREGISTRO_ARENAS.md) [...] Rode analisar_arenas.py
--abrir no WSL"*. O `--ensaio-sintetico` não foi repetido.

**Execução.** `python3 analisar_arenas.py --abrir`, das 14:26:32 às 14:27:38 (66 s), código de
saída 0; log em `~/curadoria/abrir_arenas.log`. Conferências do próprio script: os três
pré-registros e os 4 arquivos de regra da traversal v3 conferem; a ficha de preparação confere.
Conferido depois, sem nada a corrigir (nenhum defeito do §10, passo 8): as contagens de vulneráveis
e não vulneráveis, no total e por faixa de tamanho, são as da ficha nas quatro arenas; a traversal
pura não tem nenhuma função sem saída nas três arenas com veredito.

| arquivo | SHA-256 |
| --- | --- |
| `resultado_arenas.md` | `ec698b72535b24514f6f245b1185e082c395dc1c82a4517cce6740eb20a3ec41` |
| `resultado_arenas.json` | `f45efc4115efeea6fe8ab75949b7c4290ef31f576b035714a4baf721c5d1c6f2` |

**O que os pré-registros mandam ler.** Decide só o F1 (média harmônica entre precisão e recall) do
`M_cur` contra a faixa das medianas dos 5 controles; cada braço é a mediana das 30 repetições da
Fase II. *Acima* = maior que o maior dos 5, o que, sem efeito nenhum, aconteceria 1 vez em 6.

| arena | papel | vuln. / não vuln. | F1 `M_cur` | faixa dos 5 controles | posição | piso? | checagem de tamanho (desenho principal) | frase do E1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PrimeVul v0.1 | síntese (*cross-dataset*) | 843 / 20.806 | 0,164 | 0,123 a 0,135 | **acima** | não | sem evidência (V1 e V2 não disparam) | ganho sem sinal de atalho de tamanho |
| VentiVul v3, família de memória | síntese (temporal) | 48 / 2778 | 0,0702 | 0,0576 a 0,0687 | **acima** | não | sem evidência (só o V1 se aplica; não dispara) | ganho sem sinal de atalho de tamanho |
| Sonda CWE-416 | concordância com o rótulo do BigVul; fora da síntese | 258 / 7751 | 0,078 | 0,069 a 0,094 | dentro | não | **evidência** (V2 dispara: acima só na faixa de 340+ nós) | pegou o atalho e não lucrou com ele |
| VentiVul v3 inteiro | descritiva | 229 / 10.225 | 0,062 | 0,062 a 0,075 | dentro | não | sem evidência | — |

- **Síntese (Decisão M): "todas acima".** O texto diz: *evidência a favor da hipótese* — o `M_cur`
  ficou acima dos cinco controles nas duas arenas externas, o que, sem efeito nenhum, aconteceria
  no máximo 1 vez em 6 (qualquer que seja a dependência entre as arenas; 1 em 36 se fossem
  independentes). Nunca "prova", nunca "significativamente". Ao lado, o veredito de tamanho de cada
  arena (E1): nas duas, "ganho sem sinal de atalho de tamanho", com a ressalva do §7 do
  `PREREGISTRO_TAMANHO.md` (função maior também é função mais rica, e a checagem não separa as duas
  coisas).
- **Par balanceado** (sensibilidade: cada braço treinado com 1 negativo por positivo): acima no
  PrimeVul (0,158 contra 0,132–0,141) e no VentiVul família (0,099 contra 0,075–0,084); dentro na
  sonda e no VentiVul inteiro. Concorda com o desenho principal nas duas arenas da síntese. A
  checagem de tamanho do par dispara no PrimeVul (V2): vai para o apêndice e não qualifica a
  conclusão (E2).
- **Piso (Decisão J): não disparou em nenhuma arena.** Excesso sobre o acaso (VP − A × P / N:
  quantas vulneráveis o braço acertou a mais do que acertaria acusando ao acaso o mesmo número de
  funções), mediana das 30 — *valores da versão de 18/10, com o defeito na conta; os corrigidos
  estão em "Achado na escrita do artigo", logo depois deste passo*: PrimeVul `M_cur` 150,4 contra 117,5–192,3 nos controles; VentiVul
  família 2,9 contra 3,8–10,4; sonda 11,1 contra 9,2–28,5; VentiVul inteiro 9,5 contra 11,7–40,3.
- **Traversal pura** (Decisão K; descritiva — a regra congelada da curadoria usada sozinha como
  detector): PrimeVul F1 0,155 (VP 429, FP 4276) contra 0,164 do `M_cur`; VentiVul família 0,122 (VP
  19, FP 244) contra 0,070; sonda 0,084 (VP 41, FP 680) contra 0,078. No BigVul a regra tinha
  ficado acima do `M_cur` (0,270 contra 0,262); nas arenas, fica abaixo no PrimeVul e acima no
  VentiVul e na sonda. No VentiVul família, a regra passa os 13 braços (o maior é o `M_cur_bal`,
  0,099).
- **Queda de F1** (BigVul − arena, por repetição, depois a mediana; descritiva): PrimeVul `M_cur`
  0,093 contra 0,083–0,116; VentiVul família 0,191 contra 0,143–0,187 (a maior); sonda 0,183 contra
  0,119–0,173 (a maior). Ressalvas que vão ao lado dela: parte da queda vem só da proporção de
  vulneráveis (8,5% no teste do BigVul; 3,9% no PrimeVul; 1,7% no VentiVul família); e a queda pune
  quem foi melhor no BigVul, que foi o `M_cur` (0,262) — o motivo de ela não decidir
  (`PREREGISTRO_PRINCIPAL.md` §8, Decisão C). O orientador ainda não confirmou essa escolha (Pauta,
  item 9), e o `main.tex` (l. 767) ainda promete a queda.
- **VentiVul inteiro, ordem de grandeza (G3):** o `M_raw` (o braço comparável) deu F1 0,071; o ReVeal
  treinado no BigVul por Lu & Lagaisse deu 8,65% (0,0865) no VentiVul v3, arquivo inteiro — número
  lido do HTML do arXiv, a conferir no PDF antes do texto. Mesma ordem de grandeza: o pipeline não
  está quebrado.

**Observações descritivas, pós hoc** (calculadas depois de abrir por `arenas/posthoc_arenas.py`, que
só lê o `.json` da abertura e não recalcula métrica; não mudam nenhum veredito, mas pesam na
redação — a discutir com o autor):

1. **As duas "acima" não têm o mesmo peso.**
   - *PrimeVul, folgado.* O F1 do `M_cur` passa a maior mediana dos controles em **30 das 30**
     repetições; o primeiro quartil dele (0,160) fica acima do terceiro quartil de todos os
     controles (no máximo 0,142). O MCC (coeficiente de Matthews) também fica acima de todos (0,129
     contra 0,090–0,115).
   - *VentiVul família, por um fio.* A margem é de 0,0015 de F1. Na mediana, o `M_cur` acerta **4
     das 48** vulneráveis, com 62 alarmes falsos; nessa escala, cada vulnerável acertada a mais ou a
     menos move o F1 dele em ~0,018 — a margem é menos de um décimo de uma função. Com 3 acertos e
     as mesmas 66 acusações, o F1 seria 0,053, abaixo de todos os controles. O `M_cur` passa a maior
     mediana dos controles em **16 das 30** repetições (no BigVul, 26 de 30). Nas métricas
     descritivas fica no fundo: PR-AUC 0,026, a menor dos seis (controles 0,029–0,044); excesso 2,9,
     o menor; MCC 0,052, no nível do menor controle. É o cenário que a Decisão J descreve ("uma ou
     duas funções decidem a posição"); o piso, como foi escrito, não dispara porque os controles têm
     sinal. O veredito pré-registrado fica: mudar a regra agora seria escolher a análise pelo
     resultado.
2. **No PrimeVul, o ganho tem o formato do BigVul: errar menos, não acertar mais.** Medianas das
   30: o `M_cur` acerta quase tantas vulneráveis quanto o controle de perfil mais parecido, o
   `M_ctrl_g2030` (222,5 contra 210,5 — mais nas funções de 340+ nós, 162,5 contra 124,5, e menos
   nas pequenas), com bem menos alarmes falsos nas duas faixas pequenas (46,5 + 331,5 contra
   185 + 653,5). Não fica acima dos controles dentro de **nenhuma** das 4 faixas de tamanho; a
   PR-AUC (área sob a curva precisão × recall, que não depende do limiar 0,5) fica dentro da faixa
   (0,083 contra 0,079–0,094); e o excesso sobre o acaso também (150,4 contra 117,5–192,3).
3. **A fraqueza do V1 notada em 13/10 se repete** (Pauta, item 8). Razão entre a taxa de falso
   positivo nas funções de 340+ nós e nas de até 46 (medianas): `M_cur` 54× no PrimeVul, 298× no
   VentiVul família e 141× na sonda, contra 5× a 11× nos controles. Pela diferença das duas taxas,
   que é o que o V1 mede, o `M_cur` fica no meio dos controles, e o V1 não dispara.

**Decisões pendentes, do autor:** (1) como a fragilidade do VentiVul família entra no texto — no
corpo ou no apêndice —, o análogo da decisão de 13/10 sobre a observação de tamanho do BigVul; (2)
se o resultado vai para a Pauta para o orientador, junto com os itens 7 a 9 ainda abertos — o 9
(decide o F1 na arena, não a queda) passa a pesar, porque pela queda o VentiVul leria contra.

**O que muda a partir daqui.** Todas as análises pré-registradas estão abertas: o teste do BigVul
em 13/10 e as arenas em 18/10. Não sobra nenhum passo do §10 do adendo. O que resta é a redação
(o `main.tex`, intocado por decisão do autor até o processo fechar) e a conversa com o orientador.

### Achado na escrita do artigo (20/10/2026): defeito na conta do excesso sobre o acaso

**Situando.** O *excesso sobre o acaso* é a conta da regra de piso (Decisão J do adendo): quantas
vulneráveis um braço acertou a mais do que acertaria acusando ao acaso o mesmo número de funções.
O piso existe para não ler uma arena em que todos os braços estão cegos. O adendo define o acaso
como A × P / N, com **N = todas as funções da arena** ("*P* vulneráveis entre *N* funções"; e "quem
acusa tudo tem excesso zero", o que só vale com N total). O `analisar_arenas.py` (função
`analisar`, `P, N = int(y.sum()), int((y == 0).sum())`) passou para a conta **N = só as não
vulneráveis**. Achado ao conferir no JSON os números do artigo, depois da abertura.

**Conferido em 20/10, só lendo o `resultado_arenas.json`** (`arenas/diagnostico_excesso.py`, que não
grava nada; nenhum arquivo de resultado foi tocado): o excesso gravado é exatamente VP − A × P / N com N
= não vulneráveis (diferença 0 nas 30 repetições de cada braço), e a conta pré-registrada subtrai um
acaso menor, por um fator (P + N) / N: 1,0405 no PrimeVul, 1,0173 no VentiVul família, 1,0333 na
sonda e 1,0224 no VentiVul inteiro.

| arena | `M_cur`: gravado → pré-registrado | 5 controles: gravado → pré-registrado | piso nas duas contas |
| --- | --- | --- | --- |
| PrimeVul | 150,45 → 153,19 | 117,53–192,34 → 121,54–201,32 | não |
| VentiVul família | 2,86 → 2,88 | 3,81–10,38 → 3,84–10,58 | não |
| sonda | 11,09 → 11,27 | 9,19–28,46 → 9,40–29,86 | não |
| VentiVul inteiro | 9,47 → 9,61 | 11,65–40,30 → 11,94–41,08 | não |

**O que muda: nenhum veredito.** Nenhuma arena fica no piso em nenhuma das duas contas, e as
posições relativas que o Passo 7 cita se mantêm (no VentiVul família o `M_cur` segue com o menor
excesso; no PrimeVul, dentro da faixa dos controles). Mudam só os valores da tabela "Excesso sobre o
acaso" do `resultado_arenas.md` e as frases que os citam.

**O que o adendo manda (§10, passo 8):** corrigir, rodar de novo e reportar as duas versões, dizendo
que foi refeito.

**Feito em 21/10/2026, com o ok do autor** ("pode corrigir o piso"). Uma linha mudou no
`analisar_arenas.py` (função `excesso`: a divisão passou de `N` para `P + N`; a linha antiga está no
docstring da função). A abertura foi refeita com `python3 analisar_arenas.py --abrir --refazer
"<motivo>"`, às 12:34–12:35 (código de saída 0; log em `~/curadoria/refazer_arenas.log`; as
conferências do script passaram: pré-registros, regra da traversal e ficha). O script guardou a
versão de 18/10 ao lado, renomeada, e as impressões digitais dela são as registradas no Passo 7:

| arquivo | SHA-256 |
| --- | --- |
| `resultado_arenas_anterior_20261021_123410.md` (a de 18/10) | `ec698b72535b24514f6f245b1185e082c395dc1c82a4517cce6740eb20a3ec41` |
| `resultado_arenas_anterior_20261021_123410.json` (a de 18/10) | `f45efc4115efeea6fe8ab75949b7c4290ef31f576b035714a4baf721c5d1c6f2` |
| `resultado_arenas.md` (refeito, **vale este**) | `bf173e893843da671e28afd6f5205f4d135bdca1ad00fa4b86cd2a2c153c2c9b` |
| `resultado_arenas.json` (refeito, **vale este**) | `34ff46c06ea6c08631af5b6417fd25b2a7b40162f0bc42ee9ede8ea15e9f92b0` |

**Conferido que só o excesso mudou** (`arenas/comparar_refeito.py`, que compara os dois JSON campo a
campo): 0 diferença fora dos campos de excesso e da data; no `.md`, só a linha do cabeçalho (com o
**Refeito** e o motivo) e as quatro linhas da tabela de excesso. Os valores novos são exatamente os
da conta pré-registrada da tabela acima. Piso: "não" nas quatro arenas, nas duas versões; síntese:
"todas acima", nas duas. O artigo reporta as duas versões (Seção 4.4 e Apêndice A).

## Passos 4 a 6 — scripts prontos, conferidos sem tocar em nenhuma arena (16/10/2026)

- **Passo 4, traversal pura** — `rodar_traversal_arena.py`. Importa o executador da rodada nas
  negativas do BigVul (`rodar_traversal_negativos.py`: a conferência do congelamento dos 4 arquivos
  de regra e a chamada ao Joern) e muda só o caminho dos arquivos (o CPG da pasta do grupo da arena;
  a fila vem dos grafos exportados, com a linha do método só para homônimos). Grava só a evidência;
  o veredito é aplicado na abertura.
- **Passo 5, inferência** — `inferir_arena.py`. Importa o caminho do treino (`treinar_ggnn.Treino.
  prever` com os pesos de `melhor.pt` e o orçamento final de arestas de cada braço;
  `treinar_fase2.probs` com os 390 `modelo_<s>.pt`). **Trava da Decisão K:** recusa prever uma arena
  enquanto a traversal pura dela não estiver completa. Grava id, probabilidade e predição, sem ler
  nem calcular nada. **Conferência de reprodução (§10 passo 5; 16/10), no teste do BigVul (já
  aberto): 0 predições diferentes em 2.234.700** (13 braços × 30 sementes × 5730 funções) — o
  script reproduz as predições gravadas em `fase2_v2/`. Declarado: as probabilidades não saem bit a
  bit iguais (maior diferença 0,0004; 5,3% diferem na 6ª casa) porque o x_g da GGNN tem ruído de
  ponto flutuante da GPU (a soma por aresta não é determinística, e no treino a GGNN viu outra
  composição de lotes: treino + validação + teste numa passada só); maior diferença no x_g: 3,4,
  num vetor que é soma sobre todos os nós do grafo. Nenhuma predição muda.
- **Passo 6, análise** — `analisar_arenas.py`. Reaproveita do `analisar_resultados.py` (o que abriu
  o BigVul) as métricas, a mediana das 30, a posição na faixa dos controles e a checagem de tamanho;
  acrescenta o mínimo por arena, o piso pelo excesso, a traversal pura, a queda descritiva e a
  síntese "acima em todas". Confere os hashes dos três pré-registros, do congelamento da regra e da
  ficha; abre só com `--abrir`, uma vez. **Ensaio na validação do BigVul (16/10): o F1 calculado bate
  com o gravado no treino em 390 de 390 repetições**, e a contagem por faixa bate com a de 12/10.
  **Ensaio sintético (16/10)** — predições aleatórias nas três arenas (semente 9090), o código
  inteiro exercitado, fora do repositório: com predição ao acaso o excesso fica perto de zero em
  todos os braços e o piso dispara nas quatro arenas; a síntese cai em "nenhuma com veredito"; o V2
  da família do VentiVul sai "não se aplica", como na ficha. Achou **dois defeitos**, corrigidos: (1)
  o próprio ensaio gerava as predições sintéticas do VentiVul só com os ids da família (as duas
  arenas dividem a pasta; a inferência real prevê a pasta inteira); (2) numa arena no piso, a frase
  do E1 usava a posição bruta, e a Decisão J manda relatar a checagem "como na linha 'dentro ou
  abaixo' do E1".

## Passo 3 — plano (a executar)

**Primeiro a deduplicação, depois os grafos** — é a ordem do adendo (§10, passo 3: "filtros da
Decisão G, deduplicação (H), arquivo, CPG, grafo"). *Correção de 15/10:* a primeira redação deste
plano punha a deduplicação depois dos grafos, o que gastaria Joern em funções que saem. As três
chaves dispensam o grafo: CVE e commit são metadado (no PrimeVul já aplicadas nas contagens do
adendo), e o corpo é o texto da função normalizado pelo `normalizar_corpo.py` (`hash_corpo`, sem
comentários e com espaços colapsados), que as três arenas trazem — PrimeVul no campo `func`,
VentiVul na coluna `Function`, sonda no `func_before` do `all_c_cpp_release2.0.csv`. O lado do
BigVul já tem esses hashes, calculados do mesmo jeito a partir do texto (`split/positivos_hash.tsv`,
`split/negativos_hash_sc.tsv`, coluna `sha1_corpo_sc`); o BigVul inteiro (referência do PrimeVul)
sai do `func_before`. A duplicata interna também é por corpo. A regra de ordem do adendo (§3: o
negativo é definido pelo rótulo publicado, antes de qualquer perda) não muda nada aqui: quem é
negativo é decidido antes, e a deduplicação só tira funções.

1. **Deduplicação das três arenas** (minutos, sem Joern): sai o tamanho real de cada arena antes de
   gastar uma hora de Joern, com as removidas por chave e rótulo para a ficha. **Feita em 15/10
   (passo 3a, acima).**
2. **Grafos**, só das funções que ficaram, pelo mesmo caminho do dataset v3: **arquivo inteiro →
   CPG do Joern (um por arquivo) → localização da função (nome único no arquivo; hash do corpo onde
   há homônimo) → `exportar_grafos.sc`** (subgrafo da AST da função, sem seguir `CALL`). Ordem, da
   que reaproveita mais código para a que exige mais código novo:
   - **Sonda CWE-416** — é o próprio BigVul: `buscar_arquivo.py` + os scripts do dataset v3, com
     outra lista de itens. **Feitos em 15/10 (passo 3b, acima): 258 + 7751 grafos.**
   - **VentiVul** — Linux pelo `buscar_arquivo.py` (cgit); Chromium por um buscador novo no Gerrit.
     A vulnerável e as não relacionadas no arquivo antes; a consertada no arquivo depois. **Feitos em
     15/10 (passo 3c, acima): família 48 + 2778, inteiro 229 + 10.225 grafos.**
   - **PrimeVul** — `file_contents/` (Google Drive, só os arquivos da arena) e, onde faltar, o
     commit (`buscar_arquivo.py`, que precisará da família GitLab).
3. Contagem por faixa (I), taxa de tokens fora do vocabulário e a ficha.

Falha técnica (arquivo que não se obtém, parse que quebra, função que não se localiza) tira a função
e é contada por motivo e rótulo; tudo antes de qualquer modelo tocar a arena.
