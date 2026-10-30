# Lote de 50 — o número que a §4.5 estava esperando

Rodado em **07/08/2026**. `rodar_curadoria.py --limite 50 --seed 7`, 51 itens (o caso de
regressão entra sempre), **48 com evidência**, 3 falhas. A regressão do `BASELINE_libgd.md`
passou dentro do lote.

Este arquivo responde à pergunta do card *"Entender o problema descrito na 4.5"*. Não fixa regra
nenhuma — isso é a Etapa 4a.

## Achado 1 — o `OU` da §4.5 é matematicamente igual à camada 1 sozinha

O balde **"só camada 2" deu 0, e isso não é acaso amostral: é estrutural.** Os sinks da camada 2
são argumentos exatamente das construções que a camada 1 conta — argumento de chamada a função de
memória, e índice de acesso indexado. Se a camada 1 está em silêncio, a camada 2 não tem onde
ancorar sink. Por construção:

```
camada2  ⊆  camada1        →        (camada1 OU camada2)  ≡  camada1
```

A §4.5 chama a camada 2 de "mais precisa"; a página raiz do TCC chama de "a que dá precisão". Com
a regra escrita como está, **ela não participa do veredito**. Não contribui pouco: contribui zero.
É mais forte que a suspeita original do card, e é o argumento que a reescrita da §4.5 precisa
carregar.

## Achado 2 — o medo original estava superestimado; o problema é a atribuição

A hipótese do card era que a camada 1 dispararia em quase tudo e o `M_cur` sairia do tamanho do
`M_raw`. Não é o caso. Entre os 44 itens cujo corpo o CPG conseguiu parsear:

| balde | n | % |
| --- | --- | --- |
| só camada 1 | 9 | 20,5% |
| só camada 2 | **0** | **0,0%** |
| ambas | 18 | 40,9% |
| nenhuma | 17 | 38,6% |

| regra entre camadas | `M_cur` / `M_raw` |
| --- | --- |
| `OU` (a §4.5 como está) | 61,4% |
| `E` (as duas exigidas) | 40,9% |

O contraste central do TCC **não está morto** — nas duas regras há separação suficiente para o
`M_ctrl` ser um controle com sentido. O que está errado na §4.5 não é o tamanho do corte, é a
**atribuição**: todo o corte vem da camada de presença, e o texto credita a camada de fluxo.

## Achado 3 — o CPG separa "não achei" de "não consegui olhar", e o sinal é duro

Sondado em 07/08 com `_diagnostico_saude.sc`. Método cujo corpo não foi parseado tem o nó do
método presente (`externo=false`) mas **`blocos=0` e `chamadas=0`**:

| item | linguagem | span | nós AST | nós/linha |
| --- | --- | --- | --- | --- |
| `2079__Chrome` (`pngrutil.c`) | C | 141 | 9 | 0,1 |
| `0483__php-src` (`gd.c`) | C | 90 | 10 | 0,1 |
| `0741__tcpdump` (`print-isakmp.c`) | C | 0 | 21 | — |
| `1187__tor` (`<empty>`) | ? | 0 | 5 | — |

Densidade no lote inteiro: **parseados de 1,7 a 287,8 nós/linha (mediana 3,9); ausentes, todos em
0,1.** Não há zona cinzenta — é classificação, não heurística de limiar.

São **4 de 48 (8,3%)**. Os outros 17 `nenhuma` têm corpo sadio e são ausência genuína de padrão do
ponto de vista das tabelas.

**Consequência de desenho, já implementada:** a evidência passou a carregar um bloco `saude`
(`span`, `nos_ast`, `blocos`, `locais`, `chamadas_total`, `chamadas_nao_operador`,
`estruturas_total`, `externo`). Números crus — quem decide o que conta como degradado é o
`regra_veredito.toml`, não a traversal. Sem isso, o silêncio por falha de ferramenta viraria
"rótulo suspeito", e a regra de ouro do TCC (o silêncio remove do curado) puniria o item errado.

## Achado 4 — há um terceiro caso, e esse o CPG *não* sinaliza

`0546__ImageMagick` (`GetDrawInfo`) tem 542 nós AST e 204 chamadas — perfeitamente sadio — e ainda
assim caiu em `nenhuma`. Motivo: chama `ResetMagickMemory`, `AcquireString`, `CloneString`. É
`memset` embrulhado em nome de projeto.

Do ponto de vista do CPG a ausência é **real**: não há `memset` naquela função. A cegueira está
nas tabelas, por decisão declarada. É o mesmo fenômeno do `gdGetBuf` do libgd — agora com um
segundo exemplo independente, o que fortalece a ameaça à validade em vez de enfraquecê-la:
não é uma idiossincrasia do libgd, é um padrão de projetos C maduros.

Resumo dos três silêncios:

| caso | o CPG distingue? |
| --- | --- |
| não consegui olhar (corpo ausente) | **sim, sinal duro** (`blocos=0`) |
| não achei (corpo sadio, sem padrão) | sim, é o complemento |
| achei mas não reconheci (wrapper de projeto) | **não**, e nem tem como |

## Achado 5 — C++ é efeito real, mas menor do que parecia

**Correção de um erro de leitura:** a primeira versão deste arquivo atribuiu o balde `nenhuma` a
C++ agrupando por **nome de projeto**, e o nome de projeto mente. `2079__Chrome` é `pngrutil.c`
(libpng), `2339`/`2340__Chrome` são `transform.c` — C puro. Agrupando pela **extensão real do
arquivo que o c2cpg leu**, entre os 44 de corpo parseado:

| linguagem | itens | camada 1 dispara | `nenhuma` |
| --- | --- | --- | --- |
| C | 31 | 22 (71%) | 9 |
| C++ | 13 | 5 (38%) | 8 |

C++ é 30% do lote e 47% dos `nenhuma` — efeito real (71% contra 38%), porque `operator[]` de
container e cópia por template de `std::` não viram `<operator>.indirectIndexAccess` nem nome de
libc. Mas **a maioria dos `nenhuma` continua sendo arquivo C**, e essa parte não tem explicação de
ferramenta: é ausência genuína, e é exatamente o que a curadoria deveria remover.

## Falhas (3 de 51)

| item | motivo |
| --- | --- |
| `0154__gnupg` | sem arquivo de contexto |
| `0287__linux` | função alvo (`qeth_snmp_command`) não encontrada no CPG |
| `0915__FFmpeg` | função alvo (`xpm_decode_close`) não encontrada no CPG |

As duas últimas são provavelmente `nome_da_funcao` devolvendo uma chamada em vez da definição —
mesma família do `1187__tor`, que entrou como `<empty>`. Medir de novo na rodada completa.

## Limites deste número

- **n = 48, semente única.** É um lote para provar que o motor escala e dimensionar a ordem de
  grandeza, não uma estimativa. Não reportar percentual sem as contagens à vista.
- **Não é medida de qualidade do filtro.** Nenhum rótulo foi consultado aqui — nada foi comparado
  com anotação humana ou do modelo. Isso é a Etapa 4b (dev set) e depois a Etapa 5 (os 50).
- **A distribuição depende das tabelas de `dados/`**, que são revisáveis. Trocar a tabela muda
  estes números, e é por isso que elas ficam fora do código.
