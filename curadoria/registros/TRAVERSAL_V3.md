# Traversal v3 — pré-registro (Fase 0)

Escrito em **05/10/2026, antes de qualquer código da v3.** Origem das decisões: §8 do
`HANDOFF_2026-10-04.md`. Os números vêm dos scripts `_revisao_*.py` desta pasta (só leem).

---

## 0. Situando

**Onde estamos.** Na curadoria: a etapa em que a *traversal* (a consulta do Joern ao grafo do
código) olha cada função que o BigVul marcou como vulnerável e decide se o padrão de erro de
buffer está nela. Quem passa entra no `M_cur`, o braço curado do experimento.

**O que este arquivo é.** Um pré-registro: diz, **antes de rodar**, o que vai mudar, por quê e o
que se espera ver. Serve ao mesmo propósito do congelamento: provar que nada foi ajustado
depois de ver o resultado. Se uma previsão da §5 falhar, a execução **para**, investiga-se, e o
desvio é registrado aqui antes de seguir.

**O que a v3 corrige, em uma frase.** A v2 procura a função **pelo nome** e conta a evidência de
todos os métodos com aquele nome; às vezes isso inclui funções vizinhas, e às vezes nem inclui a
função rotulada. A v3 **só avalia um item se conseguir apontar no grafo o método que é a função
rotulada — e avalia só ele.** Se não conseguir, o item sai dos três braços.

**O que este arquivo NÃO é:**
- Não é uma regra de veredito nova: `regra_veredito.toml` (regra **v1**) não muda.
- Não é uma nova medida da Etapa 5: a precisão nos 50 não é recalculada com rótulo (§5, P4).
- Não conserta o `#ifdef` nem o extrator de nome dos destrutores — decisões separadas (§7).

---

## 1. Nomes, para não embolar

| nome | o que é | situação |
| --- | --- | --- |
| **traversal v2** | `curadoria_v2.sc`, congelada em 10/08/2026 | usada em toda a evidência até hoje, inclusive na Etapa 5 |
| **traversal v3** | `curadoria_v3.sc`, a criar na Fase 3 | a correção descrita aqui |
| **regra de veredito v1** | `regra_veredito.toml` (camada 1 E camada 2) | **inalterada** |

O `PERDA_BRACOS.md` chama a mesma comparação de "v1 × v2"; aqui e daqui em diante é **v2 × v3**.

---

## 2. A foto da v2 — segunda cópia

O congelamento de 10/08 (gravado às 12:42, antes da evidência dos 50, gerada entre 12:44 e 12:56)
fica **intocado** em `congelamento.tsv` e `CONGELAMENTO.md`. A pasta não está em git, então as
impressões vão copiadas aqui:

| arquivo | SHA-256 |
| --- | --- |
| `curadoria_v2.sc` | `835571171d40b50c4e63fdefcf27564e54e9dd2a0bfecd43167d2b28147bcccf` |
| `dados/funcoes_memoria.tsv` | `85297b08107ab18c12eb4ec37fbea90f2df4639928038f841e49bd1ec62594f8` |
| `dados/fontes_nao_confiaveis.tsv` | `9e36fd6f71828a418a77a3c958cbf1e1416c1e3d03976a6984fae75ae1af1fc9` |
| `regra_veredito.toml` | `485b73c3c71b6b662aa05bfb93435ff2db729352d499885ecf1c7fe8c7a73e4d` |

**Conferido em 05/10/2026** (`congelar.py` e `sha256sum`): os quatro arquivos de hoje têm
exatamente essas impressões. Ambiente: Joern `4.0.513` em `/opt/joern`, WSL Ubuntu 24.04.

---

## 3. O que muda — uma correção só: avaliar a função rotulada, e só ela

### 3.1 A regra de identificação (decidida pelo autor em 05/10)

Para cada positivo, conta-se no grafo do próprio arquivo quantos métodos têm o nome procurado
**e corpo** (filtro `!isExternal && block.astChildren.size > 0`, o mesmo do `exportar_grafos.sc`):

| definições com corpo | como se identifica a função rotulada | se não identificar |
| --- | --- | --- |
| 0 | — (a v2 já dava "indeterminado: corpo não parseado") | igual à v2 |
| 1 | **teste de posição:** a 1ª linha não vazia do `func_before`, com espaços colapsados, é igual a uma linha do arquivo dentro de [início − 3, fim] do método (folga `FOLGA_LINHA` = 3 do `montar_dataset.py`) | **exclui** |
| 2 ou mais | **hash:** o hash do `func_before` (com e sem comentários, `normalizar_corpo`) é igual ao hash do texto de **exatamente um** homônimo, recortado do arquivo por quebra de linha `\n` | **exclui** |

**Por que dois testes.** O hash prova texto idêntico, mas falha em 653 funções legítimas de
definição única (estilo GNU: o BigVul corta a linha do tipo de retorno); por isso não serve para
*conferir* quem tem uma definição só. O teste de posição é ambíguo entre homônimos (em 35 dos 183
casos de colisão, sobrecargas de C++ têm a mesma 1ª linha); por isso não serve para *escolher*.

### 3.2 O que muda no `curadoria_v3.sc` (cópia da v2)

1. **Parâmetro opcional `linha`.** Com ele, `alvoM` passa a ser só o método com aquele nome que
   começa naquela linha. Se isso não der **exatamente um** método, o script sai com erro (código
   próprio) e não grava evidência.
2. **Trava.** Sem `linha`, se houver 2 ou mais métodos com o nome e corpo, o script **se recusa**
   (código de erro próprio) em vez de somar. Sem `linha` e com 0 ou 1 definição, o código é
   **exatamente o da v2**.
3. **Nada mais.** Contagens, fontes, sinks e formato do JSON ficam idênticos.

### 3.3 O que muda fora do `.sc`

- **Tabela de identificação** (Fase 2): item → {avaliar / avaliar com `linha` X / excluir +
  motivo}. Montada de arquivos já existentes (`dataset_indice.tsv`, grupos do dataset,
  `_perda_*.tsv`, `_recuperabilidade_hash*.tsv`); Joern só nos 5 itens do problema de chave de
  grupo (`1265`, `1304`, `1305`, `2317`, `2318`). Ela **não é** arquivo de regra (contém ids de
  item, que trazem nome de projeto); o SHA-256 dela vai para a §9 antes de rodar.
- **Runner:** lê a tabela; não roda os excluídos e grava o motivo num arquivo à parte; passa
  `linha` aos itens com colisão.
- **Inalterados:** `regra_veredito.toml`, `veredito.py`, as duas tabelas de `dados/`.
- **Congelamento por versão:** `congelamento_v3.tsv` novo; lista de arquivos de regra por versão;
  `etapa_5.py` continua conferindo a v2, a montagem dos braços passa a conferir a v3.
- **Rodada:** os 2957 itens, `--trabalho ~/curadoria/completa_v3` (não toca no
  `~/curadoria/completa`, de onde o dataset lê), saída em `saida_completa_v3/`.

---

## 4. Por que é defensável mexer numa traversal congelada

1. **O defeito foi medido sem rótulo nenhum** — é contagem de métodos e comparação de texto.
2. **Antes de qualquer treino:** não há resultado do experimento sendo perseguido.
3. **Propósito único:** identificar a função; nada na lógica da evidência ou do veredito muda.
4. **Direção do efeito conhecida antes:** quem é excluído só sai; quem é avaliado só em parte da
   união tem contagens iguais ou menores (monotonicidade), então um veredito só pode ir de
   confirmado para descartado, nunca o contrário.
5. **Compromisso:** a v3 é adotada **qualquer que seja o tamanho do `M_cur` resultante.**

Frase para o artigo (a ajustar com os números finais): *a traversal foi corrigida (v2 → v3) após a
Etapa 5, por um defeito de identificação da função detectado sem consulta a rótulos, e congelada
de novo antes de rodar; nos 50 casos a v3 apenas exclui um item que já era descartado, e a
precisão medida não se altera.* A regra de veredito continua "verificada" contra o dev (Etapa 4b);
"refinada" não se aplica, porque ela não muda.

---

## 5. Previsões — se alguma falhar, parar

**P1 — sem colisão, idêntico.** Os itens com evidência que não têm colisão e não são excluídos
(≈ 2579, incluindo os 235 indeterminados) produzem JSON **idêntico** ao da v2. Base: 126 de 126
itens reexecutados pela v2 em datas diferentes deram evidência idêntica.

**P2 — com colisão, só para baixo.** Os 176 itens com colisão avaliados com `linha` têm cada
contagem ≤ à da v2, **exceto** `linha_inicio`, `linha_fim` e `saude.span` (na v2 vinham do
primeiro homônimo e podem crescer). Veredito: só de confirmado para descartado.

**P3 — exclusões.** Saem **exatamente** os 33 itens da §6. Única diferença admitida: o `1265`
pode deixar a lista se, no censo do próprio arquivo, passar no teste de posição (hoje ele falha
porque foi medido no arquivo errado).

**P4 — os 50.** Só o `2805__Android` muda: descartado → excluído. Os 17 confirmados ficam com
evidência idêntica, logo a **precisão 11/17 se mantém**. A taxa base (19/43) muda no máximo 1,3
ponto se o `2805` estiver no denominador; reporta-se como faixa, **sem abrir o rótulo**.

**P5 — o dev.** Só o `2229__Chrome` muda: descartado → excluído. Precisão do dev 9/13 mantida;
`M_cur` do dev 13/27 → 13/26.

**P6 — a trava não dispara.** Nenhum item recusado por "2+ definições sem `linha`". Se disparar,
o censo esqueceu alguém.

**P7 — falhas e estouros.** As 169 falhas da v2 (sem evidência) se repetem com o mesmo motivo,
exceto possivelmente as 2 de `timeout_joern`. Nenhum fluxo `-1` (estouro do motor), como na v2.

**P8 — números (consequência de P1–P7; "até 18/21" são os confirmados com colisão que podem
virar descartados).**

| | v2 | v3 previsto |
| --- | --- | --- |
| `M_raw` treino | 1806 | 1776 (1777 se o `1265` sair da lista) |
| `M_cur` treino | 533 | entre 512 e 530 |
| `M_raw` população | 2553 | 2520 (ou 2521) |
| `M_cur` população | 847 | entre 822 e 843 |
| `M_raw` validação / teste | 257 / 490 | 255 / 489 |
| `M_cur` de treino com grafo (o N dos `M_ctrl`) | 513 | entre 511 e 530 |

---

## 6. As 33 exclusões previstas

Gerado por `_revisao_lista_exclusoes.py` em 05/10/2026. "Veredito v2" é o que a v2 deu; nenhum
rótulo humano foi lido.

| item | causa | partição | veredito v2 | nota |
| --- | --- | --- | --- | --- |
| `0032__poppler` | colisão, hash não casa | validação | confirmado | |
| `0360__php-src` | colisão, hash não casa | treino | descartado | |
| `1213__php-src` | colisão, hash não casa | validação | descartado | |
| `1993__Chrome` | colisão, hash não casa | teste | descartado | |
| `2194__Chrome` | colisão, hash não casa | treino | descartado | destrutor |
| `2661__Android` | colisão, hash não casa | treino | confirmado | no `M_cur` |
| `2803__Android` | colisão, hash não casa | treino | descartado | destrutor |
| `1265__texlive-source` | função única não é a rotulada | treino | descartado | reconferir (P3) |
| `1882__Chrome` | função única não é a rotulada | treino | descartado | destrutor |
| `1946__Chrome` | função única não é a rotulada | treino | descartado | |
| `1947__Chrome` | função única não é a rotulada | treino | descartado | |
| `2107__Chrome` | função única não é a rotulada | treino | descartado | destrutor |
| `2134__Chrome` | função única não é a rotulada | treino | descartado | destrutor |
| `2179__Chrome` | função única não é a rotulada | treino | descartado | destrutor |
| `2199__Chrome` | função única não é a rotulada | treino | descartado | destrutor |
| `2229__Chrome` | função única não é a rotulada | treino | descartado | **no dev** |
| `2800__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2801__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2802__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2804__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2805__Android` | função única não é a rotulada | treino | descartado | destrutor, **nos 50** |
| `2806__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2807__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2808__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2810__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2813__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2814__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2815__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2816__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2817__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2818__Android` | função única não é a rotulada | treino | descartado | destrutor |
| `2932__Android` | função única não é a rotulada | treino | confirmado | no `M_cur` |
| `2933__Android` | função única não é a rotulada | treino | confirmado | no `M_cur` |

Totais: 33 itens — 7 por colisão sem casamento de hash, 26 por função única errada (20 deles
destrutores, cujo `~` o extrator de nome joga fora). Por partição: 30 treino, 2 validação, 1
teste. Confirmados na v2: 4 (`0032`, `2661`, `2932`, `2933`).

---

## 7. O que este pré-registro NÃO cobre

- **Consertar o extrator de nome dos destrutores** (manter o `~`): reavaliaria na função certa e
  poderia virar descartado em confirmado — não é monotônico e tocaria um item dos 50. Decisão
  separada.
- **`#ifdef`** (decisão 8): separado, como já estava.
- **Dataset de grafos** (chave de grupo por caminho completo, hash dos positivos, cópia do
  `dataset_indice.tsv`): é a Fase 5 e não decide veredito. Os números com grafo da §5 são
  indicativos.
- **Confundimento de tamanho** (decisão 10): será medido de novo depois da v3, sem previsão aqui.
- **Par balanceado** (decisão 13): continua em aberto.

---

## 8. Fontes

`HANDOFF_2026-10-04.md` §8 (decisões e problemas); `_revisao_conferencias.py` (determinismo,
censo, os 4 dos 50, dev); `_revisao_vereditos_colisao.py` (vereditos dos 183);
`_revisao_identificacao.py` e `_revisao_posicao.py` (hash × posição, 1687/653/26);
`_revisao_26.py`, `_revisao_destrutores.py`, `_revisao_lista_exclusoes.py` (os 33).

---

## 9. Adendo de congelamento da v3 — a preencher na Fase 3, ANTES de rodar

- **Data e hora:** 05/10/2026, 12:16 (−03:00), por `congelar.py --versao v3 --gravar`
  (`congelamento_v3.tsv`, `CONGELAMENTO_V3.md`). Nenhum item do BigVul tinha rodado na v3.
- **SHA-256 de `curadoria_v3.sc`:**
  `a6d119bd74ae64b918e54964d691f691a33085d3860e246fc9349ac999e2ca22` (12139 bytes)
- **Duas tabelas de `dados/` e `regra_veredito.toml`:** idênticas às da §2 (conferido pelo
  `congelar.py` nas duas versões, ambas "ok").
- **SHA-256 da tabela de identificação** (`identificacao_v3.tsv`, 2957 linhas):
  `5b07f03610c0cb62288ae082b632f760a27dcf38920e985a5534949758232f01`
- **SHA-256 de `split/positivos_hash.tsv`** (Fase 1, entrada da tabela):
  `357286d43067f10ef0180c32e10e120e07c402616eda2fb9ba31169fd667cb07`
- **Desvios em relação a este pré-registro:**
  1. *Exclusões: 32, não 33.* O `1265__texlive-source`, medido no CPG do próprio arquivo, tem 1
     definição e passa no teste de posição — exatamente a exceção admitida em P3.
  2. *Códigos de saída 4 e 5 da §3.2.* O `System.exit` do script não atravessa o lançador do
     Joern, que devolve 1 nos dois casos (teste em arquivo sintético). As duas recusas são
     distinguidas pela **mensagem** (`ERRO_V3_COLISAO_SEM_LINHA`, `ERRO_V3_LINHA`), que é o que o
     runner lê. Comportamento igual ao previsto; muda só o sinal usado.
  3. *Teste antes da foto.* O `.sc` foi exercitado num arquivo C++ **sintético** (não é item do
     BigVul) antes de congelar: função única v2 = v3 byte a byte; homônimo sem linha → recusa;
     homônimo com linha → só o método certo (13 nós cada, contra 26 da soma na v2); linha sem
     método → recusa.

---

## 10. Registro da execução

*As seções 0–9 acima são o pré-registro e não se editam depois de escritas (exceto o adendo da
§9). O que foi feito vai aqui, por fase e com data.*

### Fase 0 — pré-registro (05/10/2026)

Escrito este arquivo; o autor aprovou as seis escolhas de detalhe feitas na redação (método
único na `linha` ou erro; tabela de identificação fora da foto, com impressão no adendo; exceção
do `1265`; os 2 `timeout_joern`; taxa base dos 50 como faixa; "corrigida" × "verificada").

### Fase 1 — hash dos positivos (05/10/2026)

*O que era:* pôr o cálculo do hash num lugar só, já com o recorte de linhas certo, e calcular o
hash de todos os positivos — eles entravam na montagem do dataset sem hash (`shas: []`).

*O que mudou no código:*
- `normalizar_corpo.py` ganhou `hashes_do_texto` (os dois hashes: só espaço normalizado, e sem
  comentário) e `recortar_linhas` (corta **só** em `\n`, como o Joern conta).
- `montar_dataset.hashes_do_metodo` passou a usar essas duas funções. **Mudança de
  comportamento decidida (8.1, decisão 9):** antes recortava com `splitlines()`, que desloca as
  linhas em arquivo com *form feed*. Só se manifesta quando o dataset for remontado (Fase 5).
- `_recuperabilidade_hash.py` passou a importar `hashes_do_texto` em vez da cópia local.
  (Os `_revisao_*.py` mantêm cópia própria de propósito: são o registro da revisão de 05/10.)
- Novo `extrair_hash_positivos.py` → `split/positivos_hash.tsv` (item, `sha1_corpo`,
  `sha1_corpo_sc` — as mesmas colunas do lado negativo), lido de `func_before.c`, o mesmo texto
  de onde a curadoria tira o nome.

*Conferências (todas passaram):*
- Autoteste: o recorte não abre linha no *form feed*; `hashes_do_texto` devolve exatamente os
  dois hashes gravados.
- Cobertura: 2957 de 2957 positivos com `func_before.c` e hash.
- Com o TSV novo e as funções centralizadas (`--conferir`): nos 183 com colisão, 176 o hash aponta
  um homônimo e 7 nenhum, **com a mesma faixa de linhas da revisão em 183 de 183**; nos 2366
  positivos de definição única com grafo, o hash casa em **1687** — os números da revisão.
- `_diagnosticar_perda_bracos.py` e `_recuperabilidade_hash.py` (ambos os modos) reexecutados
  depois das mudanças: as quatro TSVs saíram **idênticas** às de 03–04/10.

*O que destrava:* a Fase 2 (montar a tabela de identificação).

### Fase 2 — tabela de identificação (05/10/2026)

*O que era:* decidir, antes de rodar, como a v3 trata cada um dos 2957 positivos.

`montar_identificacao_v3.py` → `identificacao_v3.tsv`. Fontes: grafo da v2 (2365 itens de
definição única), colisões (183, faixas do cache de 03/10), indeterminados da v2 (235), falhas
da v2 (169, rodam de novo como na v2) e **censo no CPG do próprio arquivo** para os 5 itens que o
`montar_dataset` tinha procurado no arquivo errado (P6) — o único uso do Joern na fase.

| ação | n |
| --- | --- |
| avaliar (como a v2) | 2749 |
| avaliar na linha escolhida pelo hash | 176 |
| excluir | **32** (7 colisões sem casamento de hash + 25 funções únicas que não são a rotulada) |

Conferências embutidas: exclusões = as 33 previstas menos o `1265` (a exceção admitida em P3: no
próprio arquivo ele tem 1 definição e passa no teste de posição); as 176 linhas = as faixas da
revisão. Os outros 4 itens do P6 (`1304`, `1305`, `2317`, `2318`) têm 1 definição e passam.

### Fase 3 — `curadoria_v3.sc`, runner e congelamento (05/10/2026)

- `curadoria_v3.sc` = cópia da v2 + parâmetro `linha` + a trava (`diff` contra a v2: só isso e
  comentários). Testado num **arquivo sintético** antes da foto (ver §9, desvio 3).
- `rodar_curadoria.py`: `--versao` (padrão v2, para as rodadas antigas continuarem
  reproduzíveis), `--identificacao`, `--pular-falhas`; excluídos vão para `_exclusoes.tsv`; as
  duas recusas da v3 viram motivo próprio. Listas de regras por versão (`REGRAS_POR_VERSAO`).
- `congelar.py`: um congelamento por versão. **Testado:** tentar regravar a v2 com `--forcar` é
  recusado, e `congelamento.tsv`/`CONGELAMENTO.md` ficaram byte a byte iguais.
- Foto da v3 tirada às 12:16 (§9). Teste de generalidade da v3: ok.
- **Piloto pós-foto** (11 itens, pasta descartável `~/curadoria/piloto_v3`): P1–P7 ok no que
  dava para checar. O `2629__Android` passou de confirmado a descartado (o `GetBlock` que é só
  `return NULL;`); o `2444__Android` (92% dos nós são da própria função) continuou confirmado.

### Fase 4 — rodada nos 2957 (em andamento)

Lançada em 05/10/2026 12:20 (`_rodar_completa_v3.sh`, log em `~/curadoria/completa_v3.log`),
~9 s/item. Conferência ao fim: `_conferir_v3.py --v3 saida_completa_v3 --completo`.

*Interrupção 1:* as Fases 4 e 5, rodando em paralelo, foram encerradas pelo ambiente de execução por falta
de memória no Windows (2,2 GB livres de 15,8). Pararam no item 227/2957 (216 JSONs) e no grupo
261/1503. Conferido depois: nenhum arquivo pela metade (todos os JSONs legíveis, todo `.jsonl`
com seu `.meta.json`). Os dois scripts retomam de onde pararam.

*Interrupção 2* (mesma causa, ~17:20): item 1128/2957, grupo 1499/1503; de novo nada pela metade.
Daí em diante a rodada foi feita **em primeiro plano, em fatias de ~270 s** (`_rodar_v3_fatia.sh`,
opção nova `--parar-apos` do runner: para de forma limpa antes de começar um item novo). 64
fatias, de 05/10 19:20 a 06/10 ~01:00, + passada final retentando os dois timeouts.

*Defeito meu no runner, corrigido:* uma fatia que parava no meio da fila (a passada final)
regravava o `_falhas.tsv` só com as falhas vistas até ali — 10 sumiram do registro. Corrigido no
`rodar_curadoria.py` (com `--retomar` o `_falhas.tsv` passa a ser registro acumulado) e o arquivo
foi reconstruído a partir do log da rodada, que guarda toda falha (cópia do anterior em
`~/curadoria/_falhas_v3_antes_da_reconstrucao.tsv`). Não afeta evidência nem veredito.

**Resultado da conferência (`_conferir_v3.py --completo`, 06/10):**

| previsão | resultado |
| --- | --- |
| P1 sem colisão, JSON idêntico à v2 | **2578 de 2580 — FALHOU em 2** (ver desvio abaixo); veredito idêntico em 2580 de 2580 |
| P2 com colisão (176) | ok — nenhuma contagem cresceu; vereditos: 155 descartado→descartado, 14 confirmado→confirmado, **7 confirmado→descartado**, nenhum no sentido proibido |
| P3 exclusões | ok — as 32 da tabela |
| P4 os 50 | ok — só o `2805__Android` mudou (descartado → excluído); os 17 confirmados com evidência idêntica → **precisão 11/17 mantida** |
| P5 o dev | ok — só o `2229__Chrome` mudou (descartado → excluído) |
| P6 trava | ok — nenhuma recusa da v3 |
| P7 falhas | ok — as mesmas **169** da v2 (incluindo os 2 timeouts do wireshark, que estouraram de novo, inclusive na retentativa); nenhum fluxo `-1` |
| P8 números | ok — tabela abaixo |
| cobertura | ok — todo item da tabela rodou, foi excluído ou falhou |

| | v2 | v3 | previsto |
| --- | --- | --- | --- |
| `M_raw` treino | 1806 | **1777** | 1776–1777 |
| `M_cur` treino | 533 | **523** | 512–530 |
| `M_raw` população | 2553 | **2521** | 2520–2521 |
| `M_cur` população | 847 | **836** | 822–843 |
| `M_raw` validação / teste | 257 / 490 | **255 / 489** | 255 / 489 |

**Desvio em P1 — registrado antes de seguir.** Os 2 itens são `1243__stb` e `1244__stb`, duas
funções do mesmo arquivo de 5449 linhas (`stb_vorbis.c`). Só uma contagem difere,
`fluxos_indice_de_parametro`: 34 → 35 e 63 → 52. Os dois continuam **confirmados**. Isolado
(`~/curadoria/_isolar_124*`): rodando de novo agora, v2 e v3, sobre o CPG de agosto e sobre o
regerado, dão **sempre 63** (8 execuções) para o `1244` e **sempre 35** (4 execuções) para o
`1243`. Ou seja: o 52 da rodada não se reproduz, e o 34 da v2 de agosto também não. A causa é
**variação do motor de fluxo do Joern na contagem de caminhos** em funções grandes, em
execuções isoladas — não a v3 (o código é o mesmo da v2 nesses itens) nem o CPG. **Decisão:** os
JSONs ficam como a rodada produziu (não se reexecuta para fazer a previsão passar); a frase de
determinismo (8.2: "126 de 126") vale para o **veredito**, não para toda contagem de fluxo.

### Fase 5 — dataset e braços (em andamento)

- `montar_dataset.py --versao v3` (`_montar_dataset_v3.sh`, lançado em paralelo à Fase 4 — não
  depende da evidência da v3, só da tabela de identificação): saída **nova** em
  `~/curadoria/dataset_v3` e `dataset_indice_v3.tsv`; o dataset da v2 não é tocado. Mudanças: os
  32 excluídos não viram alvo; os 176 com colisão levam a `linha` e o grafo sai do mesmo método
  que a v3 avaliou; todo positivo leva hash; P6 corrigido; motivo por item no `.meta.json`;
  reconciliação por assinatura (ids, hashes, linhas), não só pelo número de alvos.
  Checagem a seco: 32 excluídos, 176 com linha, 3 grupos separados (51 alvos movidos + 9
  negativos sem CPG do próprio arquivo = os 60 do P6). Teste com Joern em 3 grupos: o `2629`
  agora tem grafo de 8 nós; o `1265` vem do próprio arquivo.
- Scripts de braços e conferência com pasta por parâmetro (P5): `montar_conjuntos.py` e
  `montar_conjuntos_treino.py` (`--versao`), `montar_ctrl_com_grafo.py` (`--conjuntos`,
  `--grupos`), `_conferir_bracos.py`, `_conferir_composicao.py`, `_conferir_dataset.py`.
  **Desvio do plano:** o `_diagnosticar_perda_bracos.py` não foi parametrizado — com o motivo por
  item gravado no dataset, a perda da v3 se lê direto (`_comparar_dataset_v3.py`); ele fica
  como registro da v2.
- **Dataset v3 concluído** (05/10, 19:21, depois de duas interrupções por memória e retomadas
  sem perda): **25.829 grafos** em 1503 grupos (v2: 25.670).

  | partição | positivos v2 → v3 | negativos v2 → v3 |
  | --- | --- | --- |
  | treino | 1647 → **1776** | 14.390 → 14.394 |
  | validação | 249 → **255** | 3674 → 3674 |
  | teste | 470 → **489** | 5240 → 5241 |

  `_conferir_dataset.py`: as quatro invariantes passaram (0 nó fora da faixa da função em
  3.710.493; 0 aresta inválida; 0 duplicata; 0 id em duas partições).
  `_comparar_dataset_v3.py` (v2 × v3, mesmos CPGs de agosto): **25.607 grafos idênticos**; as
  diferenças, todas com causa esperada — saíram 25 positivos excluídos e 5 negativos do P6;
  entraram 175 positivos com colisão (grafo do método escolhido), 4 positivos e 10 negativos do
  P6; mudaram 1 positivo (`1265`, agora do próprio arquivo) e 32 negativos do P6. **Diferença sem
  causa: 0.** O conserto do `splitlines` não mudou nenhum negativo.
  Positivos avaliáveis sem grafo: 235 sem corpo (os indeterminados), 169 sem evidência na v2 e
  1 com nó fora da função (filtro estrutural já existente).
- **Braços da v3** (06/10), em pastas novas — `conjuntos_v3/` (população) e
  `conjuntos_treino_v3/` (treino); `conjuntos/` e `conjuntos_treino/` da v2 intocados. Os dois
  montadores conferiram o congelamento **v3** antes de rodar.
  - População: `M_raw` 2521, `M_cur` **836 = 33,2%, IC95 [31,4; 35,0]** (v2: 847/2553, mesma
    proporção e mesmo IC); `M_ctrl` (semente 2026) 836, 280 em comum com o `M_cur`.
  - Treino: `M_raw` 1777, `M_cur` **523 = 29,4%, IC95 [27,4; 31,6]** (v2: 533/1806 = 29,5%).
    Os cinco `M_ctrl_s` (sementes 2026–2030) pegam, por acaso, 26,8% a 30,6% de itens que a
    traversal confirmaria (v2: 25,9–30,8%).
  - `M_ctrl_g` (resorteio entre quem tem grafo, `montar_ctrl_com_grafo.py`): N = 523.
  - **Braços × dataset (`_conferir_bracos.py`):** `M_cur` e todos os `M_ctrl` com **100%** dos
    itens com grafo (523/523); `M_raw` 1776/1777. **A perda assimétrica da v2 (96,2% × ~91%)
    desapareceu** — era a colisão de nome sem hash (`PERDA_BRACOS.md`). Razão negativo:positivo
    no treino: 14.394 negativos → **27,5:1** para `M_cur` e `M_ctrl`; 8,1:1 para o `M_raw`.
  - **Confundimento de tamanho (decisão 10) continua:** mediana de nós `M_cur` **323** × `M_ctrl_g`
    116–136 (v2: 316 × 126–152); densidade de parse +12,3% (v2: ~+10%). Parear por tamanho
    continua inviável (faltam 6 + 62 funções nas duas faixas de cima). Saída continua sendo
    controlar na análise.

### Fase 6 — registros (06/10/2026)

- Ponteiros para este arquivo no topo de `RODADA_COMPLETA.md`, `DATASET.md`, `COLISAO_NOME.md` e
  `PERDA_BRACOS.md` (este com a correção dos 4 "nome não existe no CPG", que eram o P6). O split
  não muda (é sobre os 2957 positivos, independe de veredito).
- Revisão da Decisão 2 registrada em `documentos-orientação/resposta_treinamentos_bigvul.md`.
- **Não feito, por ser decisão do autor:** editar o artigo; levar a revisão ao orientador; mudar
  o cartão "Declarar a colisão de nome nas Ameaças à Validade".

**Números que mudam no texto (v3 no texto, v2 como histórico):**

| o quê | v2 | v3 |
| --- | --- | --- |
| `M_raw` população | 2553 | 2521 |
| `M_cur` população | 847 (33,2% [31,4; 35,0]) | 836 (33,2% [31,4; 35,0]) |
| `M_raw` / `M_cur` treino | 1806 / 533 | 1777 / 523 |
| `M_cur` de treino com grafo (N dos `M_ctrl`) | 513 | 523 |
| positivos de treino com grafo | 1647 | 1776 |
| positivos com grafo validação / teste | 249 / 470 | 255 / 489 |
| razão neg:pos dos braços (treino) | 28,0:1 (14.390/513) | 27,5:1 (14.394/523) |
| faixa dos cinco controles (confirmados por acaso) | 25,9–30,8% | 26,8–30,6% |
| mediana de nós `M_cur` × `M_ctrl` | 316 × 126–152 | 323 × 116–136 |
| grafos no dataset | 25.670 | 25.829 |
| Etapa 5 (precisão 11/17, taxa base 19/43) | — | **igual** (só o `2805`, descartado, sai; taxa base muda no máx. 1,3 ponto) |
| Etapa 4b (dev, 9/13) | — | **igual** (só o `2229`, descartado, sai) |

**Frase para as Ameaças à Validade (rascunho):** *32 dos 2957 positivos (1,1%) não puderam ter a
função rotulada identificada no grafo e saíram dos três braços: 7 por colisão de nome sem
casamento de texto e 25 porque o único método com aquele nome era outra função — 20 deles
destrutores de C++, cujo nome o extrator de nome perde o `~`.*
