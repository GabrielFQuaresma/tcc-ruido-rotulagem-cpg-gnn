# Etapa 4a — dev set e fixação da regra de veredito

Fechada em **09/08/2026**. Este arquivo é o registro do que foi olhado e do que **não** foi
olhado para escrever a `regra_veredito.toml`.

A afirmação que este arquivo precisa sustentar na banca não é "não houve escolha" — houve. É que
**a escolha foi feita num eixo que não consegue vazar a resposta**. Ninguém prevê a queda de F1
in-dist→OOD olhando quantas funções sobraram no conjunto.

## O dev set

`montar_dev_set.py` → `dev_set.tsv`. 30 positivos, `df.sample(n=30, random_state=7)` sobre
`saida/bigvul_memoria_positivos.parquet`. Os 50 do teste são `random_state=42` sobre o mesmo
parquet, e o script **falha em vez de continuar** se a interseção não for vazia.

O `id` da pasta `saida_final/itens/NNNN__proj` é a posição 1-based da linha no parquet (o
`preparar_bigvul.py` rodou sem `--shuffle`). O script não confia nisso: confere contra
`1217__libgd`/`fb0e0cc…` antes de usar o mapeamento.

**Interseção por função: vazia.** É o que o protocolo pedia.

### A ressalva que o protocolo não pedia, e que importa mais

**Disjunção por função não é disjunção por commit.** 6 dos 30 itens do dev vêm de commits que
também aparecem nos 50 — e **5 deles são a mesma CVE-2016-1621** (libvpx/Android), o cluster que
já ocupa 14 das 50 linhas do teste.

Isso é consequência direta do fan-out medido em 02/08 (55,9% das funções positivas vêm de 103
commits): amostrar por função de um conjunto com fan-out alto **coloca funções irmãs nos dois
lados**, e funções irmãs compartilham contexto.

Não reamostrei. Mexer na amostra depois de ver a sobreposição é a mesma doença que o dev set
existe para evitar — e a semente foi declarada antes. Fica declarado, e tem duas consequências:

- **Na Etapa 4b:** conferir o número com e sem os 6 irmãos. Se a leitura mudar, vale a versão
  sem eles.
- **Nas Ameaças à Validade:** dev e teste não são independentes por commit. Como 4a não olha
  rótulo, isso **não afeta a escolha da regra** — afeta só o guarda-corpo de 4b.

## A rodada

```
python3 rodar_curadoria.py --lista dev_set.tsv --saida saida_dev --trabalho ~/curadoria/dev --retomar
```

(o `--lista` é novo: sortear de novo aqui daria um conjunto diferente do que foi provado disjunto)

31 itens na fila (o caso de regressão entra sempre), **356 s no total**, 2 falhas:

| item | motivo |
| --- | --- |
| `0122__savannah` | sem arquivo de contexto — é uma das 45 perdas de download já declaradas |
| `1443__curl` | idem |

A regressão do `BASELINE_libgd.md` passou dentro da rodada. **O `1217__libgd` está na amostra dos
50** e por isso entra na fila só como teste de motor: sai de toda estatística do dev
(`veredito.py --excluir`, ligado por padrão).

Sobram **28 itens de dev com evidência**, dos quais **27 de corpo sadio**.

## Saúde do CPG — o sinal duro se manteve

Um único item não parseado: `0774__tcpdump`, `span=0 nos_ast=21 blocos=0 chamadas=0`. Todo o
resto tem entre **1,9 e 25,0 nós AST por linha**; o quebrado não tem denominador. Não há zona
cinzenta — segunda amostra independente confirmando o achado 3 do `LOTE_50.md`.

## A curva de encolhimento

Este é o insumo inteiro da escolha. Nenhum rótulo foi lido para produzi-lo
(`_curva_encolhimento.py`, sobre os 27 de corpo sadio):

| regra candidata | `M_cur` | % `M_raw` | por que sim / por que não |
| --- | --- | --- | --- |
| sem filtro | 27 | 100,0% | — |
| camada 1 **com** alocação | 16 | 59,3% | alocar não é acessar; e `malloc` dispara em quase tudo |
| camada 1 sozinha | 16 | 59,3% | **rejeitada** — a camada 2 contribuiria zero |
| **camada 1 E camada 2** | **13** | **48,1%** | **escolhida** |
| c1 E fluxo só de memória | 9 | 33,3% | rejeitada — privilegia uma forma de acesso |
| c1 E fluxo só de índice | 10 | 37,0% | rejeitada — idem |
| c1 E (memória **E** índice) | 6 | 22,2% | rejeitada — conjunção sem respaldo na definição |
| c1 E fluxo ≥ 2 | 13 | 48,1% | rejeitada — parâmetro livre |
| c1 E fluxo ≥ 5 | 11 | 40,7% | rejeitada — parâmetro livre |
| c1 E fluxo ≥ 10 | 8 | 29,6% | rejeitada — parâmetro livre |

No lote de 50 da Etapa 3 (n=43 olháveis, excluído o libgd) a regra escolhida dá **39,5%**, contra
os 48,1% do dev. Duas amostras independentes, mesma ordem de grandeza — nem colapso, nem
`M_cur ≈ M_raw`.

### Os dois eixos que decidiram

**1. Rastreabilidade até a definição da família.** A família CWE-119/120/125/787 se reduz a
quatro ingredientes: (i) um acesso a buffer, (ii) um índice ou tamanho que flui até ele, (iii)
vindo de fora do controle da função, (iv) sem checagem que domine o acesso.

- (i) é a camada 1 — e a definição **não privilegia** índice sobre API de memória, então as
  variantes "só fluxo de memória", "só fluxo de índice" e "os dois" caem: são recortes que a
  definição não faz.
- (ii)+(iii) são a camada 2, e a definição pede **a existência** de um fluxo, não uma quantidade.
  É isso que elimina os limiares ≥2/≥5/≥10: "cinco fluxos" não está em CWE nenhuma. São
  parâmetros livres, e parâmetro livre calibrado na amostra é precisamente o que a Etapa 4a
  existe para não fazer.
- (iv) **não foi implementado, de propósito.** Exigir prova de ausência de checagem inverteria a
  regra de ouro do desenho: o silêncio não confirma nada, só remove do curado. As
  `guardas.condicoes` seguem na evidência como apoio à leitura e não entram no veredito.

Sobra exatamente uma regra sem parâmetro livre: **camada 1 E camada 2**.

**2. Tamanho do `M_cur`, como veto — não como alvo.** O tamanho não foi mirado; foi conferido
depois, contra dois testes grosseiros: pequeno demais tira poder do `M_ctrl` (que é dimensionado
por ele), grande demais faz `M_cur ≈ M_raw` e o contraste central evapora. Extrapolando para os
2957 positivos, 40–48% dá algo entre **~1200 e ~1400 funções** no `M_cur` — folgado nos dois
lados.

**O que deliberadamente não foi usado como alvo:** a taxa base de ~43% (anotador humano) /
~34% (modelo). Seria tentador dizer "escolhi a regra que chega perto da taxa base", e é
justamente o que não pode ser feito: essa taxa é um agregado derivado dos 50, e mirar nela
transformaria o conjunto de teste em régua de calibração pela porta dos fundos. Ela aparece aqui
como leitura *a posteriori* — 48,1% e 39,5% caem na vizinhança de 43% — e nada mais.

## Por que o conector é `E` e não o `OU` da §4.5

Porque com `OU` a camada 2 **não participa**: `camada2 ⊆ camada1` por construção (os sinks da
camada 2 são argumentos exatamente das construções que a camada 1 conta), logo
`(camada1 OU camada2) ≡ camada1`. O balde "só camada 2" deu 0 de 44 no lote e 0 de 27 no dev —
77 itens, duas amostras, zero exceções. O erro da §4.5 não é o tamanho do corte, é a atribuição.

## Três vereditos, não dois

`veredito.py` emite `confirmado` / `descartado` / `indeterminado`. A terceira casa não é
burocracia: sem ela, falha de ferramenta viraria "rótulo suspeito" e a curadoria puniria o item
errado. `indeterminado` fica fora do `M_cur` **e** fora da conta de ruído.

Dois gatilhos: corpo não parseado (1 no dev, 4 no lote) e fluxo que estourou no motor de dataflow
(`-1` no JSON; **nenhuma ocorrência em 77 itens** — a guarda existe para a rodada completa).

## O que ficou de fora desta etapa

- **Anotar o dev com o `anotar_modelo.ps1`** (R=1, `cve_visivel`, ~US$ 11). É insumo da 4b, não
  da 4a — e rodar antes não adianta nada, porque 4a não pode olhar rótulo. Fica como o primeiro
  passo da 4b.
- **Congelar os hashes.** É a Etapa 5, e só depois dela os 50 podem ser tocados.

## Arquivos desta etapa

| arquivo | o que é |
| --- | --- |
| `montar_dev_set.py` | monta o dev set e **prova** a disjunção; falha se não houver |
| `dev_set.tsv` | os 30 itens, com a coluna `irmao_de_commit_do_teste` |
| `saida_dev/*.json` | evidência dos 28 (+ o libgd de regressão) |
| `saida_dev/_veredito_dev.tsv` | veredito por item sob a regra v1 |
| `_curva_encolhimento.py` | a tabela acima; não lê rótulo |
| `regra_veredito.toml` | **a regra**, com a justificativa linha a linha |
| `veredito.py` | aplica a regra à evidência |
