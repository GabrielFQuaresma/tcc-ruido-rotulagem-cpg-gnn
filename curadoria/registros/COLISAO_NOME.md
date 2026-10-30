# Colisão de nome de função — medição e consequências

> **06/10/2026 — a colisão foi CORRIGIDA, não só declarada** (traversal v3, `TRAVERSAL_V3.md`).
> A objeção da opção (c) abaixo ("não há chave confiável para desambiguar") caiu: o hash do
> `func_before` aponta exatamente um homônimo em 176 de 183 casos; os 7 restantes saíram dos três
> braços. A conclusão sobre a Etapa 5 continua valendo e foi confirmada na rodada da v3.

Medido em **05/09/2026**. Scripts: `_medir_colisao.sc`, `_medir_colisao.py`.

## Situando: o que é a colisão

A traversal localiza a função a examinar por **nome**:

```scala
def alvoM = cpg.method.nameExact(alvo)
```

`nameExact` devolve **todos** os métodos do arquivo que se chamam assim, não um. E o
`curadoria_v2.sc` conta a evidência inteira sobre esse conjunto — `alvoM.call`, `alvoM.ast`,
`alvoM.parameter`, os fluxos da camada 2 — enquanto `linha_inicio` e `linha_fim` saem de
`alvoM.head`, de **um** só.

Consequência: quando o arquivo tem duas funções com o mesmo nome, a evidência gravada descreve a
**união** das duas, e as linhas descrevem só a primeira. Um item pode ter sido confirmado por
padrão que está na função vizinha homônima, não na função rotulada.

**Isto não é ruído de rótulo nem erro de regra.** É a ferramenta olhando o alvo errado — a mesma
família de problema das 110 falhas "função alvo não encontrada", só que silenciosa: ela não
produz erro, produz um número.

O `RECORTE_SUBGRAFO.md` (16/08) já tinha registrado o sintoma — em `0001__php` o CPG traz
`PHP_FUNCTION<duplicate>1` e `<duplicate>4` — mas apenas como bloqueio para **montar o
dataset**. O que se mede aqui é maior: se o problema também contamina a evidência já gravada.

## O que distingue colisão inofensiva de colisão real

Um método **sem corpo** (declaração, protótipo, stub externo) não tem chamada, nó AST nem
parâmetro: casar com ele não move contagem nenhuma. Só colisão entre **duas definições com
corpo** soma evidência de função errada. Todos os números abaixo usam esse critério.

## Medida 1 — amostra aleatória da população

**n = 120**, semente **202** (declarada; não é 42 dos 50, 7 do dev set, 2026 do `M_ctrl`, 101 do
subgrafo nem 909 do split). 10,1 s por item, 0 falhas.

| métodos que casam | itens | % |
| --- | --- | --- |
| 1 | 92 | 76,7% |
| 2 | 18 | 15,0% |
| 4–20 | 10 | 8,3% |

| definições **com corpo** | itens | % |
| --- | --- | --- |
| 0 (corpo não parseado) | 10 | 8,3% |
| 1 | 104 | 86,7% |
| **2 ou mais** | **6** | **5,0%** |

**A taxa de colisão real é 5,0% (6 em 120).** Os 15,0% que casam com 2 métodos são, na quase
totalidade, declaração + definição — inofensivo.

Os seis, com quanto de evidência foi emprestado:

| item | definições | nós AST da função | nós AST contados | veredito |
| --- | --- | --- | --- | --- |
| `2031__Chrome` | 13 | 21 | **686** | descartado |
| `2444__Android` | 2 | 1641 | 1788 | **confirmado** |
| `2642__Android` | 3 | 8 | 39 | descartado |
| `2679__Android` | 2 | 10 | 36 | descartado |
| `2735__Android` | 5 | 41 | 234 | descartado |
| `2747__Android` | 15 | 447 | **3791** | descartado |

Em `2747__Android` a traversal contou **8,5×** mais estrutura do que a função rotulada tem.

**A colisão inflou confirmação?** Não há sinal disso: 1/6 (16,7%) entre os itens com colisão
contra 34/104 (32,7%) entre os sem. E o único confirmado, `2444__Android`, tomou emprestado
apenas 9% dos nós (1641 de 1788) — ele se sustenta sozinho. Mas **n=6 não decide nada**: é
sinal para saber se vale medir na população, não estimativa para o artigo.

## Medida 2 — os 50 casos da Etapa 5, e é esta que importa

Conferência **dirigida**, sem sorteio: exatamente os itens de `mapa_caso_item_50.csv`. Dos 50,
**49 têm evidência** (o que falta é `0103__busybox`, a falha de macro já declarada).

Isto é medição estrutural — conta métodos num grafo. **Não lê rótulo humano, não recalibra nada
e não gasta o conjunto de teste.** É conferência de sanidade de um número já publicado.

| definições com corpo | itens | % |
| --- | --- | --- |
| 0 | 5 | 10,2% |
| 1 | 40 | 81,6% |
| **2 ou mais** | **4** | **8,2%** |

| item | definições | nós AST da função | nós AST contados | veredito |
| --- | --- | --- | --- | --- |
| `2666__Android` | 4 | 43 | 280 | descartado |
| `2739__Android` | 3 | 65 | 970 | descartado |
| `2867__Android` | 2 | 18 | 57 | descartado |
| `2901__Android` | 2 | 33 | 66 | descartado |

### A conclusão que este arquivo existe para registrar

**Os quatro itens com colisão foram todos DESCARTADOS. Nenhum está entre os 17 confirmados.**

A precisão do filtro medida na Etapa 5 é **11/17 = 64,7%** — numerador e denominador saem
exclusivamente dos confirmados. Como nenhum confirmado tem colisão, **a precisão não está
contaminada**. E a taxa base de **19/43 = 44,2%** não depende da traversal em nada: é a
proporção de rótulos corretos do BigVul.

Conferência cruzada que fecha: entre os 40 sem colisão, 17 são confirmados — exatamente os 17 do
`RESULTADO.md`.

**O que a colisão pode ter causado é descarte indevido**, não confirmação indevida. Pela regra de
método do projeto, o silêncio da traversal nunca inverte rótulo e errar por omissão é de graça:
o item apenas não entra no `M_cur`. Isso é perda de cobertura, da mesma família dos 235
indeterminados e das 169 falhas.

## Concentração

Dos 10 itens com colisão encontrados nas duas medidas, **9 são `Android` e 1 é `Chrome`**.
Ambos são bases enormes, com muitos `static` de nome genérico e código gerado por macro no
mesmo arquivo. É a mesma assinatura da perda de cobertura por macro de atributo: o problema
recai sobre projetos com certas convenções, o que o torna **seletivo por projeto** e material
para as Ameaças à Validade.

## O que fazer — três saídas, e a recomendada

**(a) Declarar e não mexer.** Ameaça à validade: em ~5% dos itens a evidência descreve uma união
de funções homônimas. Custo zero, e o resultado da Etapa 5 já está demonstrado limpo.

**(b) Excluir os itens com colisão dos três braços, como já se faz com os indeterminados.**
Não toca a regra congelada — é exclusão aplicada depois, exatamente o tratamento que os 235
indeterminados já recebem, e pelo mesmo motivo: se o item saísse só do `M_cur`, a diferença
entre `M_cur` e `M_ctrl` passaria a incluir "a ferramenta conseguiu olhar". Custo: exige rodar
`_medir_colisao.sc` na população inteira — 2788 itens × 10,1 s ≈ **7,8 horas** de Joern, em
lançamentos com `--retomar`.

**(c) Corrigir o `.sc` para desambiguar e refazer tudo.** Mudaria um arquivo de regra congelado,
forçando novo congelamento e **nova medida da Etapa 5**. É o mais caro e o menos defensável: o
`linha_inicio` gravado vem do `.head`, que nos itens com colisão pode ser a função errada, então
nem existe chave confiável para desambiguar sem voltar ao BigVul.

**Recomendação: (b)**, com (a) como piso se o tempo não permitir. A Etapa 5 fica como publicada
nas duas.

## Consequência separada: a chave para montar o dataset

Independente do veredito, montar o dataset de grafos **por nome** pega a função errada nesses
~5%. A chave tem de ser `nome + linha_inicio` — mas **o `linha_inicio` gravado não serve como
desempate nos itens com colisão**, porque ele próprio veio do `.head`. Para esses, a saída
honesta é a mesma da opção (b): marcar e deixar de fora, em vez de adivinhar.

Isso resolve o "EM ABERTO" registrado no card do pipeline do ReVeal em 16/08, e o resolve para
baixo: não é um desempate melhor, é uma exclusão declarada.
