# Identificar os negativos para o dataset de grafos

Fechado em **21/09/2026**. Scripts: `extrair_nomes_negativos.py`, `_conferir_nomes_negativos.py`.

## Situando: por que isto era um problema

O ReVeal consome **um grafo por função**. Para recortar a função de dentro do CPG do arquivo, é
preciso localizá-la no grafo, e a busca do Joern é **por nome** (`cpg.method.nameExact`).

Para os positivos o nome já existia, no `relatorio_extracao.csv`. Para os negativos, não — e a
descoberta que travava isto é que **o BigVul não tem coluna de nome de função**. São 36 colunas
no `all_c_cpp_release2.0.csv` e nenhuma traz o nome. O que existe é `func_before`: o
código-fonte da função inteira.

## A decisão

**Os negativos são exatamente as linhas que o BigVul rotulou com `vul==0`**, e o nome sai da
assinatura dentro do `func_before`.

A alternativa era usar como negativos todos os métodos vizinhos do arquivo, o que dispensaria
esta etapa inteira — mas trocaria o conjunto por outro que inclui funções que o BigVul nunca
rotulou, enfraquecendo a comparação com os números publicados do ReVeal.

**O extrator é o mesmo dos positivos** (`nome_da_funcao` do `buscar_arquivo.py`), importado e
não copiado. Se os dois lados usassem extratores diferentes, uma diferença de resultado entre
positivos e negativos poderia vir da extração em vez do modelo.

## A extração

Uma passada pelo ZIP de 1,4 GB, em blocos de 1000 linhas e só 3 colunas, com escrita incremental
no disco. **57 segundos, sem SIGKILL** — o `_extrair_indice.py` registra que varrer esse arquivo
matou o processo três vezes, e o que mudou foi não acumular nada em memória.

**Os 32.479 negativos do split foram todos encontrados.** Isso valida a premissa da chave: o
`linha_indice` gravado pelo `montar_split.py` é o número da linha no `indice_bigvul.csv`, e ele
casa com o número da linha no CSV completo porque o `_extrair_indice.py` gravou em blocos
sequenciais. Se a ordem tivesse divergido, itens teriam ficado sem resposta.

Saída em `split/negativos_nomes.tsv`: `linha_indice`, `nome`, `linhas_corpo`, `sha1_corpo`.

O `sha1_corpo` é o hash do corpo com espaços normalizados. Não era necessário para a extração —
foi gravado de propósito para o que vem a seguir.

## Quanto sobra, e o que se perde

| | n | % dos 32.479 |
| --- | --- | --- |
| sem nome extraído | 49 | 0,2% |
| **sem `file_name` no BigVul** | **3853** | **11,9%** |
| usáveis (têm nome e arquivo) | **28.578** | **88,0%** |

Sem um dos dois não dá para saber em qual CPG procurar, então o item sai do dataset. É perda de
cobertura da mesma natureza já declarada nos positivos (as 404 de 2957), e pelo mesmo princípio:
errar por omissão é de graça.

**A perda dominante não é o extrator de nome — é `file_name` vazio.** Nos positivos esse mesmo
buraco foi contornado resolvendo o arquivo pelo `codeLink` (`buscar_arquivo.py`); aqui não foi
tentado, e fica registrado como recuperável se 11,9% vier a pesar.

## A ambiguidade, e o que a resolve

Nome repetido no dataset inteiro não atrapalha: `main` aparece 38 vezes, mas em 38 projetos com
CPGs diferentes. O que atrapalha é nome repetido **dentro do mesmo arquivo**, onde `nameExact`
devolve vários métodos e não há como saber qual é o rotulado. É a mesma família do problema
medido em `COLISAO_NOME.md` para os positivos, agora do lado negativo.

| | n | % dos usáveis |
| --- | --- | --- |
| grupos ambíguos (mesmo commit + arquivo + nome) | 748 | — |
| negativos envolvidos | 2105 | 7,4% |

**E o corpo resolve 99,7% deles.** Dos 2105, em **2098** todos os corpos do grupo são distintos,
então o `sha1_corpo` desempata sem chute: compara-se o corpo que o BigVul guarda com o corpo do
método no CPG. Sobram **7** casos em que dois corpos são idênticos — e esses não são ambiguidade
de verdade, são linhas duplicadas do próprio BigVul: qualquer escolha dá o mesmo grafo, só não
pode entrar duas vezes no dataset.

Os grupos maiores são a assinatura já conhecida do macro: `Data` 45× em
`InspectorTraceEvents.cpp`, `SPL_METHOD` 24× em `spl_observer.c`, `PHP_FUNCTION` 23× em
`radius.c`, `DECLAREcpFunc` 17× em `tiffcp.c`.

**Aproveitamento final: 28.571 de 32.479 (88,0%)** — 26.473 sem precisar de desempate nenhum,
mais 2098 recuperados pelo corpo.

| partição | negativos limpos | do total | % |
| --- | --- | --- | --- |
| treino | 16.092 | 20.061 | 80,2% |
| validação | 4159 | 5004 | 83,1% |
| teste | 6222 | 7414 | 83,9% |

*(A tabela conta só os que não precisam de desempate; com o corpo, cada partição sobe.)*

## O achado que vale para os positivos também

O `RECORTE_SUBGRAFO.md` (16/08) deixou em aberto: *"montar o dataset por nome pode pegar a
função errada; precisa de chave melhor (nome + linha de início)"*. E o `COLISAO_NOME.md` (05/09)
mostrou que **`linha_inicio` não serve**, porque ele próprio veio do `.head` e nos itens com
colisão pode ser da função errada.

**A chave que serve é o corpo.** O BigVul guarda o `func_before` de todo item, positivo
inclusive. Então o mesmo desempate por hash de corpo pode resolver a colisão dos positivos na
montagem do dataset — os ~5% medidos em `COLISAO_NOME.md`.

**Isto não reabre a Decisão 2 e não mexe em nada congelado.** São duas coisas distintas:

- **A evidência da curadoria** foi calculada sobre a união dos métodos homônimos, está congelada
  desde 10/08, e a decisão continua sendo **declarar**. Não muda.
- **A montagem do dataset** é posterior e não é regra. Ali o corpo desempata, e os itens com
  colisão podem entrar no treino com o grafo certo em vez de ficarem de fora.

## O que muda a partir daqui

O lado negativo do dataset tem nome, chave e número: 28.571 funções localizáveis. O próximo
passo é cruzar isso com quais `cpg.bin` existem em disco — um negativo só entra se o CPG do
arquivo dele já foi gerado (eram 26.962 pela medida de 15/08, que casava por arquivo). Desse
cruzamento sai o **n final de exemplos negativos por partição**, e com ele o dataset pode ser
montado de verdade.
