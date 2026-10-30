# Recorte do subgrafo da função — medição

*Registrado em 16/08/2026, no card "Definir e reproduzir o pipeline de treino do ReVeal".*

## Situando: por que existe uma decisão de recorte

A §4.3 manda gerar o CPG (*Code Property Graph*, o grafo que o Joern produz) do **arquivo
inteiro**, não da função isolada — sem os tipos, structs e funções vizinhas o motor de fluxo
de dados não resolve nada, e foi esse justamente o bloqueio que travou o projeto até 28/07.

Mas o ReVeal consome **um grafo por função**: cada exemplo de treino é um grafo. Então há um
descasamento entre o que existe em disco (1519 grafos de arquivo, em `~/curadoria/completa`)
e o que o modelo come (um grafo por função). Alguém tem de recortar a função de dentro do
arquivo, e **como se recorta muda o resultado** — o próprio card já avisava que a banca vai
perguntar.

Três consequências fazem disso uma decisão e não um detalhe:

1. **Vazamento de rótulo.** Se o recorte trouxer vizinhança, o grafo de uma função
   **negativa** pode conter os nós da função **vulnerável** do mesmo arquivo. Isso deixou de
   ser hipotético: 26.962 das funções negativas do BigVul estão em arquivos cujo `cpg.bin` já
   existe, ou seja, dividem arquivo com um positivo. O modelo aprenderia "arquivo que contém
   vulnerabilidade" em vez de "função vulnerável".
2. **Coerência com a curadoria.** A camada 2 da traversal (a de fluxo de dados) só funcionou
   porque o arquivo inteiro estava presente. Se o corte descartar o fluxo que atravessa a
   fronteira da função, o modelo vê menos do que a curadoria viu para confirmar o rótulo.
3. **Comparabilidade com o ReVeal publicado.** A arquitetura foi escolhida para permitir
   comparação direta com números publicados; quanto mais o grafo divergir, mais fraca fica a
   comparação.

## O que foi medido

`_medir_subgrafo.sc` mede, para o **subgrafo induzido** pela função (o conjunto de nós da AST
dela, e nada mais), quantas arestas ficam dentro e quantas atravessam a fronteira, por tipo e
nos dois sentidos. `_medir_subgrafo_lote.py` roda isso em lote e agrega.

**Amostra: n = 40 itens**, sorteados dos que têm veredito e `cpg.bin` em disco, com **semente
101** — declarada, e diferente de 42 (os 50 anotados), 7 (o dev set) e 2026 (o `M_ctrl`),
para não correlacionar com nenhum conjunto que já tem papel no desenho. 360 s de execução,
0 falhas.

**Isto não toca rótulo nenhum.** É medição de estrutura de grafo: não lê veredito, não lê
anotação humana, não entra em conta de precisão. Não é amostra de validação e não gasta
nenhum conjunto de teste.

## Resultado

| | arestas | % das incidentes |
|---|---|---|
| internas (ficam no recorte) | 113.746 | 88,2% |
| saindo (do subgrafo para fora) | 14.929 | 11,6% |
| entrando (de fora para o subgrafo) | 338 | 0,3% |

**Internas, por tipo:** REACHING_DEF 32.951, AST 12.605, CFG 11.561, CONTAINS 11.513,
CDG 11.371, POST_DOMINATE 10.695, DOMINATE 10.676, ARGUMENT 8.094, REF 3.552, CONDITION 362,
PARAMETER_LINK 157, RECEIVER 98, FOR_* 108, CALL 3.

**Saindo:** EVAL_TYPE 10.633 (71,2%), CALL 4.176 (28,0%), REF 77, SOURCE_FILE 43.

**Entrando:** REF 101, CALL 76, REACHING_DEF 67, AST 51, CONTAINS 43.
Por item: mínimo 2, mediana 5, máximo 59; 19 dos 40 itens têm mais de 5.

**Tamanho:** nós do subgrafo por item — mínimo 5, mediana 136, máximo 1956.
Outros métodos internos no mesmo arquivo — mínimo 1, mediana 28, máximo 240; soma 2.073 nos
40 itens. São os candidatos a exemplo negativo que já estão grafados.

## Leitura

**O vazamento não acontece por construção, e isso não depende dos números acima.** O conjunto
de nós do subgrafo induzido é `method.ast` — só descendentes do nó da função alvo. Nenhum nó
de outra função entra, qualquer que seja a contagem de arestas. As arestas que atravessam a
fronteira medem outra coisa: **quanta informação se perde ao cortar**, não quanto vaza.

O que se perde, em ordem de tamanho:

- **EVAL_TYPE (71% do que sai)** aponta para o nó de *tipo* de cada expressão, e tipos moram
  no nível do arquivo. Isso é provavelmente recuperável sem seguir a aresta: a extração de
  features do ReVeal guarda tipo como **atributo do nó**, não como aresta. A conferir na
  implementação, não assumido.
- **CALL (28% do que sai)** aponta para a função chamada. **É a aresta perigosa:** segui-la é
  o que traria função vizinha para dentro do grafo, e é por aí que o vazamento entraria se a
  decisão fosse outra. Não seguir.
- **Fluxo de dados interprocedural é desprezível.** REACHING_DEF entrando são 67 contra
  32.951 internas — **0,20%**. Ou seja, o recorte induzido preserva praticamente todo o fluxo
  de dados que a curadoria usou para confirmar rótulo. Esta é a frase que responde à
  consequência 2 acima.

## Decisão proposta

**Subgrafo induzido pela função; não seguir `CALL`; preservar tipo como atributo de nó em vez
de aresta.**

Apoiada em medida, não em preferência: preserva 88,2% das arestas incidentes e 99,8% do fluxo
de dados, e torna o vazamento impossível por construção em vez de improvável por sorte.

## Atualização de 21/09/2026 — os três itens abertos fecharam

**1. A recuperação do tipo como atributo era hipótese. CONFERIDA, e está certa.** `typeFullName`
é **propriedade do nó** e sai sem seguir aresta nenhuma. Medido em `gnutls_session_get_data`:
63 dos 85 nós carregam tipo. Os 22 sem tipo são `BLOCK`, `RETURN`, `CONTROL_STRUCTURE`,
`METHOD` e `FIELD_IDENTIFIER` — que **não têm tipo por natureza**, não por falha. No dataset
inteiro a proporção sem tipo fica em ~26%, pela mesma razão.
Ressalva honesta: nós `CALL` frequentemente saem com `ANY`, porque sem os headers o Joern não
resolve o tipo de retorno. É a mesma família do problema do `PARSE_IFDEF.md`.

**2. A colisão de nome foi resolvida** — não por `linha_inicio`, que este registro sugeria e que
o `COLISAO_NOME.md` mostrou não servir (veio do `.head`), e sim por **hash do corpo**. Critério
final em `LOCALIZACAO.md`: candidato único ⇒ é ele; havendo homônimo, só o hash decide.

**3. O vazamento deixou de ser argumento e virou teste.** O `_conferir_dataset.py` verifica, em
cada grafo exportado, que **toda linha de nó cai dentro da faixa `[linha_inicio, linha_fim]` da
função**. Se o recorte trouxesse vizinhança, apareceria aqui. Na conferência inicial:
**0 nós fora da faixa em 18.423**. A frase "impossível por construção" agora tem verificação
automatizada por trás, e não só o raciocínio.

Implementação do recorte: `exportar_grafos.sc`, orquestrado por `montar_dataset.py`.

## O que ficava em aberto (16/08) — ver a atualização acima

- **Colisão de nome de função dentro do mesmo arquivo.** `cpg.method.nameExact(alvo)` casa
  por nome, e há arquivos com nomes repetidos — em `0001__php` o CPG traz
  `PHP_FUNCTION<duplicate>1` e `PHP_FUNCTION<duplicate>4`. Enquanto isso não for resolvido,
  montar o dataset por nome pode pegar a função errada, ou várias. Precisa de chave melhor
  (nome + linha de início, que os JSONs de veredito já guardam em `linha_inicio`).
- **A recuperação do tipo como atributo é hipótese**, não medida. Conferir na extração de
  features antes de escrever no artigo.
- **n = 40.** A mediana de arestas entrando é 5, mas a cauda vai a 59. Nada disso muda a
  conclusão (o vazamento é impossível por construção), mas se a perda de contexto virar
  argumento no texto, o n precisa crescer.
