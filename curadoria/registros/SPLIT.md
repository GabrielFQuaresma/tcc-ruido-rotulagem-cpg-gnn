# Split agrupado e os cinco controles

Fechado em **05/09/2026**, a partir do acordo com o orientador registrado em
`documentos-orientação/resposta_treinamentos_bigvul.md`.

## Situando: por que o split vem antes de tudo

O TCC compara três conjuntos de treino — `M_raw` (bruto), `M_cur` (curado pela traversal) e
`M_ctrl` (controle sujo do mesmo tamanho) — que diferem **só em quais positivos entram**. Para
a comparação valer, os três têm de ser avaliados no **mesmo** conjunto de teste, e esse conjunto
tem de ser definido **antes** de a curadoria filtrar qualquer coisa. Splitar depois daria a cada
braço um teste diferente, e não haveria comparação nenhuma.

Isto **não** é a amostra dos 50 anotados nem o dev set de 30. Aqueles são instrumentos da
curadoria (medir a precisão do filtro e calibrar a regra). Este é o split do **modelo**.

## A unidade de agrupamento: nem commit, nem CVE

Vazamento aqui não é hipotético. Um commit de correção do BigVul toca várias funções (o
*fan-out*): um deles toca 230 positivos, e os negativos são em geral funções do mesmo arquivo
que o commit tocou. Split aleatório por função poria irmãs do mesmo commit dos dois lados.

**Agrupar por `commit_id` também não basta.** Medido em `_explorar_split.py`: **59 CVEs
aparecem em mais de um commit** (CVE-2016-7514 em 4, CVE-2015-8958 em 4, CVE-2016-3861 em 4).
Agrupar por commit deixaria funções da mesma CVE dos dois lados.

A unidade adotada é o **componente conexo do grafo commit ↔ CVE**: dois itens caem no mesmo
grupo se compartilham commit, ou CVE, ou uma cadeia dos dois. Deu **949 grupos**.

O maior é a CVE-2016-1621, com **365 positivos** espalhados por 3 commits — **12,3%** dos 2957.
O script recusa rodar se algum grupo passar de 20%, porque aí um teste de 20% ou exclui o grupo
(e perde o fenômeno de fan-out que ele representa) ou é dominado por ele.

## O que foi particionado

| | n | fonte |
| --- | --- | --- |
| positivos | **2957** | `saida_final/relatorio_extracao.csv` — todas, inclusive as que a curadoria depois marcou indeterminadas ou que falharam |
| negativos | **32.479** | `saida_final/indice_bigvul.csv`, linhas `vul==0` em commit que tem positivo nosso |

Os 32.479 são mais que os **26.962** já registrados no card do ReVeal, e a diferença é de
critério, não de dado novo: aquele número casava por **arquivo** (negativos cujo `cpg.bin` já
existe) e este casa por **commit** (negativos que herdam a partição do grupo). O split é
anterior a qualquer filtro de disponibilidade, então usa o critério mais largo.

## Balanceamento: por positivos, estratificado por CWE

**Por positivos** (decisão de 05/09): os negativos são ~92% do total e dominariam o
balanceamento, e o teste poderia acabar com poucos positivos — justamente a classe cuja
detecção o trabalho mede. A razão negativo:positivo sai diferente entre partições, de propósito.

**Estratificado por CWE**: o guloso simples, só pelo total, punha **27,9% de CWE-125 no teste
contra 21,1% na população**. Isso importa porque a CWE-125 é a que mais perde cobertura na
curadoria (12,2% de indeterminados contra 7,5% da CWE-119) — um teste enriquecido na CWE que a
ferramenta enxerga pior distorceria a leitura dos três braços. O critério adotado é o do
`StratifiedGroupKFold`: para cada grupo, escolher a partição que deixa o menor desvio-padrão
entre as razões de preenchimento de todos os pares (partição, CWE).

Estratificar por CWE **não é vazamento**: CWE é metadado do dataset, não o rótulo que o modelo
prediz. O split continua sem olhar veredito, sem olhar anotação humana e sem saber quem são
os 50.

## Resultado

| partição | positivos | % | negativos | % | razão |
| --- | --- | --- | --- | --- | --- |
| treino | 2091 | 70,7% | 20.061 | 61,8% | 9,6:1 |
| validação | 292 | 9,9% | 5.004 | 15,4% | 17,1:1 |
| teste | **574** | 19,4% | **7.414** | 22,8% | 12,9:1 |

Composição por CWE, contra a população (71,9 / 0,2 / 21,1 / 6,7):

| partição | CWE-119 | CWE-120 | CWE-125 | CWE-787 |
| --- | --- | --- | --- | --- |
| treino | 72,2% | 0,2% | 20,9% | 6,7% |
| validação | 71,6% | 0,3% | 21,6% | 6,5% |
| teste | 71,3% | 0,2% | 21,8% | 6,8% |

**Conferências de vazamento, todas em 0:** grupos em mais de uma partição, commits em mais de
uma partição, CVEs em mais de uma partição.

**Semente 909**, declarada, diferente de 42 (os 50), 7 (o dev set), 2026 (o `M_ctrl` original) e
101 (a medida de subgrafo).

Congelado por SHA-256 em `split/congelamento_split.tsv`, incluindo os **dois insumos** além das
saídas — o id de cada negativo é o número da linha no índice, então se o índice mudar os ids
mudam junto.

## Onde caíram os 50 anotados

**39 no treino, 0 na validação, 11 no teste.** O split não olhou quem eram; isto é relato
posterior, conforme a decisão de 05/09 ("deixar cair onde cair").

Consequência prática: a sonda dos rejeitados (card *"Testar se a GNN aprendeu mais do que a
regra da traversal"*) só pode usar os **11** que caíram no teste. É pouco, e é o preço de não
enviesar o split. A alternativa — forçar os grupos dos 50 para o teste — foi descartada porque
14 dos 50 são CVE-2016-1621, cujo grupo tem 365 positivos e sozinho ocuparia ~64% de um teste
de 574.

## Os cinco controles

`montar_conjuntos_treino.py`, gravando em `conjuntos_treino/`.

**O `montar_conjuntos.py` antigo não foi alterado e `conjuntos/` não foi sobrescrita.** Aquela
pasta é o registro do que foi medido em `RODADA_COMPLETA.md`; apagar artefato já registrado para
produzir outro com o mesmo nome é o tipo de coisa que torna um resultado indefensável.

| conjunto | n | o que é |
| --- | --- | --- |
| `M_raw` | **1806** | positivos de corpo sadio na partição de treino |
| `M_cur` | **533** | os que a traversal confirmou — 29,5% do `M_raw` |
| `M_ctrl_s2026…s2030` | **533** cada | cinco sorteios do `M_raw`, mesmo N do `M_cur` |

**O `M_cur` de treino é 533, não 847.** Os 847 eram a população inteira; 314 deles caíram na
validação ou no teste e não podem treinar nada. Isto reabre com força a questão já registrada no
card do ReVeal: 533 positivos é bem menos que os ~1200–1400 projetados na Etapa 4a. **Quem
decide se basta é o desenho do treino, não este arquivo** — e a saída, se não bastar, não é
afrouxar a regra congelada.

### Por que cinco, e o que os cinco mostraram

O orientador objetou que o controle "depende completamente de quais 847 são selecionadas". A
objeção procede: um sorteio é uma amostra de tamanho 1, e se o `M_cur` ganhar por alguma margem
não dá para separar "a curadoria fez efeito" de "esse sorteio saiu bom ou ruim". A resposta não é
apagar o braço — é sortear cinco e comparar o `M_cur` contra a **distribuição**.

| semente | confirmados dentro do controle |
| --- | --- |
| 2026 | 150 (28,1%) |
| 2027 | 138 (25,9%) |
| 2028 | 152 (28,5%) |
| 2029 | 148 (27,8%) |
| 2030 | **164 (30,8%)** |

**A objeção está quantificada: entre sorteios a fração de itens "que a traversal teria
confirmado" varia de 25,9% a 30,8%, quase 5 pontos.** É essa faixa que define o que é normal
para um controle. Comparar o `M_cur` contra um sorteio só seria comparar contra um ponto tirado
de uma distribuição com essa largura.

A sobreposição entre cada controle e o `M_cur` é a mesma coluna (150, 138, 152, 148, 164), o que
é esperado: o controle é sorteado do bruto inteiro, que inclui os confirmados. Sortear só entre
os descartados faria dele o *complemento* do `M_cur` — outra coisa, e um controle enviesado.

A primeira semente é 2026, a mesma do sorteio único de 11/08, para a linhagem ficar rastreável.
As outras quatro são sequenciais e foram fixadas **antes** de qualquer treino.

## Débito conhecido

Os cinco controles foram gerados **antes** da reunião de 09/09/2026. Se o desenho mudar lá,
parte disto pode virar trabalho jogado fora. Custo aceito de propósito, porque a alternativa era
chegar na reunião sem nada rodado.

## O que muda a partir daqui

O split existe e está congelado, então a montagem do dataset de grafos pode começar: cada função
extraída herda a partição do grupo do seu commit, e nenhuma decisão de treino precisa mais
esperar. Fica pendente para o texto: declarar a razão negativo:positivo desigual entre partições
(9,6:1 no treino contra 12,9:1 no teste) nas Ameaças à Validade.
