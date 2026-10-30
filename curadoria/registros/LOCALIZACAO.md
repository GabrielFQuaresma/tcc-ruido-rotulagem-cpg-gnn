# Achar a função dentro do CPG: quanto do teto é real

Fechado em **21/09/2026**. Scripts: `_medir_localizacao.py`, `_medir_localizacao.sc`,
`_diag_hash.py`, `normalizar_corpo.py`, `extrair_hash_sem_comentario.py`.

Terceiro e último registro da sequência de 21/09. `NEGATIVOS.md` respondeu *"o BigVul sabe
dizer qual função é?"*; `NEGATIVOS_CPG.md` respondeu *"o CPG do arquivo dela existe?"*; este
responde a que faltava: **aberto o CPG, a função está lá?**

## Situando: por que 26.907 era teto e não número

O modelo consome um grafo por função. Localizar a função dentro do CPG é por **nome**
(`cpg.method.nameExact`). O nome dos negativos foi lido da assinatura do `func_before` pelo
extrator do projeto; o **Joern batiza o método pela regra dele** — macro vira
`PHP_FUNCTION<duplicate>4`, C++ carrega namespace. Os dois podem não coincidir. E mesmo
coincidindo, pode haver homônimo no mesmo arquivo, e aí é preciso o corpo para saber qual é.

Nada disso tinha sido executado. Os 26.907 do `NEGATIVOS_CPG.md` eram *"o arquivo foi grafado"*,
não *"a função foi encontrada"*.

## Desenho da medição

| | |
| --- | --- |
| unidade sorteada | **arquivo** (par commit+arquivo), não função |
| n | **80 arquivos, 1302 funções** |
| semente | **303** — declarada; não é 42 (os 50), 7 (o dev), 2026–2030 (os `M_ctrl`), 101 (o subgrafo), 202 (a colisão) nem 909 (o split) |
| teto por arquivo | 40 negativos, para um arquivo gigante não dominar |
| tempo | ~6,3 s por arquivo, 0 falhas |

**Por que por arquivo:** um `cpg.bin` serve todos os negativos do mesmo arquivo, e abrir o CPG é
o que custa. Uma amostra de funções soltas viraria uma abertura por função.

**A consequência tem de ser declarada:** os negativos de um mesmo arquivo **não são
independentes** — se o extrator erra com o estilo de macro daquele projeto, erra em todos
juntos. É o mesmo fan-out já medido no ruído. Por isso o resultado sai nos dois níveis, e o de
arquivo é o conservador.

**Não toca rótulo, veredito, anotação nem conjunto de teste.** É estrutura de grafo, da mesma
natureza do `RECORTE_SUBGRAFO.md`.

## Dois artefatos que a primeira rodada mediu errado — e o que eram

A primeira rodada deu **44,1%**, com o modo de falha dominante sendo *"o nome casou, exatamente
um método, e só o corpo não bate"* (43,1%). Isso não fazia sentido: se o nome casou e só há um
método, é a função. Investigado em `_diag_hash.py`, eram **dois artefatos, nenhum deles dado**:

**1. O `m.code` do Joern vem truncado em 1000 caracteres**, com `" ..."` no fim. Os textos batem
byte a byte até o corte. Comparar hash de texto truncado reprova toda função com mais de ~1000
caracteres. *Corrigido* recortando o corpo do **arquivo-fonte** pelas linhas do método, em vez
de usar o `m.code`. Subiu para 55,1%.

**2. O `func_before` do BigVul vem sem comentário de linha (`//`)**; o arquivo baixado tem.
Comparar um com o outro reprova toda função comentada. *Corrigido* removendo comentário dos
**dois** lados, com o módulo `normalizar_corpo.py` — importado pelos dois, não copiado, pelo
mesmo motivo que o extrator de nome já era compartilhado: se os dois lados normalizassem
diferente, a diferença viria da normalização e não do dado. Subiu para 64,6%.

Remover comentário é normalização **simétrica**, não afrouxamento: comentário não é código e não
faz parte da identidade da função. O que se compara continua sendo texto exato, hash contra hash.

> O removedor de comentário tem autoteste (6 casos, incluindo `"http://x"` e `'/'`, que uma
> troca ingênua por regex erraria). Ele roda antes da extração e aborta se falhar.

**O `negativos_nomes.tsv` não foi sobrescrito** — é o artefato registrado no `NEGATIVOS.md`. O
segundo hash foi para arquivo próprio, `split/negativos_hash_sc.tsv` (32.479 linhas, 52 s).

## O resultado

| classe | n | % | o que é |
| --- | --- | --- | --- |
| `hash_bate_1` | 799 | 61,4% | localizado; um só método com aquele nome |
| `hash_desempata` | 42 | 3,2% | localizado; o hash do corpo escolheu entre homônimos |
| `sem_hash_1` | 299 | 23,0% | um método casou o nome, corpo não bate |
| `so_declaracao` | 127 | 9,8% | casou, mas o método **não tem corpo** no CPG |
| `sem_metodo` | 35 | 2,7% | `nameExact` devolveu zero |

**Critério estrito — exige hash do corpo: 841 de 1302 = 64,6%.**

**Critério alternativo — 87,6%.** Conta também `sem_hash_1`. A justificativa: o hash existe para
escolher **entre** homônimos; onde o arquivo tem um único método com aquele nome e com corpo,
não há o que escolher — nome + arquivo já identificam. E o diagnóstico por tamanho apoia: **96,0%
dos 299 têm span de linhas compatível** com o `linhas_corpo` do BigVul, ou seja, é a mesma
função. Isto é a pergunta *"há ambiguidade?"* respondida pela estrutura do arquivo, não pelo
resultado — mas **qual critério adotar é decisão de desenho e está em aberto** (ver abaixo).

### Por arquivo, que é a unidade sorteada

- 100% localizado: **34 de 80** (42,5%)
- 0% localizado: **18 de 80** (22,5%)
- mediana da taxa por arquivo: **90,9%**

A distância entre 64,6% (por função) e 90,9% (mediana por arquivo) **é o agrupamento**: o arquivo
típico vai quase todo bem, e uns poucos arquivos grandes que falham inteiros puxam a taxa por
função para baixo. Os zerados são concentrados e reconhecíveis — `sel1.c`, `fc.c`, `keys.c`,
`pngwutil.c`, `tif_write.c`, `rdpdr.c`, `archive_read_support_format_lha.c`.

### Saúde dos CPGs — um achado que não era a pergunta

**2603 de 3059 métodos internos (85,1%) têm corpo parseado**; mediana por arquivo 91,7%; **7 dos
80 arquivos têm menos de 50% dos corpos**. O caso que disparou a investigação: em
`1164__ImageMagick/tiff.c`, `ReadTIFFImage` **está** no CPG, com o nome certo e nas linhas certas
(1074–2121) — e com `blocos=0`. Só 4 dos 38 métodos internos daquele arquivo têm corpo.

**Isto não é erro de nome.** O Joern acha a assinatura e não fecha o bloco (macro,
preprocessador). O método existe no grafo e não tem AST: **não vira exemplo de treino de jeito
nenhum**, com nome certo ou errado. É a fonte dos 9,8% de `so_declaracao`.

> **Pergunta que isto abre e que este registro NÃO responde:** se 15% dos métodos não têm corpo,
> parte dos positivos que a curadoria deixou de confirmar pode ter sido falha de parse e não
> ausência de evidência. Isso é **medição, não conclusão**, e mexe em território congelado —
> está listado como próximo passo, não foi feito aqui, e **nada foi alterado por causa disso**.

### n projetado por partição

| partição | taxa estrita | taxa alternativa | montáveis | **n estrito** | **n alternativo** |
| --- | --- | --- | --- | --- | --- |
| treino | 458/694 = 66,0% | 600/694 = 86,5% | 16.347 | **10.788** | **14.133** |
| validação | 48/95 = 50,5% | 62/95 = 65,3% | 4237 | **2141** | **2765** |
| teste | 335/513 = 65,3% | 478/513 = 93,2% | 6323 | **4129** | **5892** |

**São estimativas de amostra, não contagens.** Para virar número de artigo têm de sair da
montagem de verdade. E **a validação tem n=95 funções em poucos arquivos** — é a linha menos
confiável da tabela, e a variação entre as três partições (50,5% a 66,0%) é compatível com o
agrupamento por arquivo, não com diferença real entre partições.

### Efeito nas razões negativo:positivo

Terceira revisão do mesmo número na mesma sessão. Sobre a partição de treino:

| braço | 05/09 (20.061 brutos) | `NEGATIVOS_CPG` (16.347) | **estrito (10.788)** | **alternativo (14.133)** |
| --- | --- | --- | --- | --- |
| `M_raw` (1806) | 11,1:1 | 9,1:1 | **6,0:1** | **7,8:1** |
| `M_cur` / `M_ctrl` (533) | 37,6:1 | 30,7:1 | **20,2:1** | **26,5:1** |

**A Decisão 5 continua valendo e o argumento não muda:** `M_cur` e os cinco `M_ctrl` têm 533
positivos e o mesmo pool, logo a mesma razão dos dois lados. O desbalanceamento é idêntico e
continua não podendo explicar diferença entre eles.

## DECIDIDO em 21/09/2026: critério **alternativo**

**Decisão do autor.** O pool de treino do lado negativo passa a ser **14.133**, não 10.788.
Fixado em código em `_medir_localizacao.py`, constante `CLASSES_LOCALIZADO` — um lugar só,
importado pelos outros scripts e não copiado.

**O que a decisão diz, em uma frase:** onde o arquivo tem **um único** método com aquele nome e
com corpo, o item conta como localizado mesmo sem o hash do corpo bater.

**Por que é defensável:** o hash existe para escolher **entre** homônimos. Onde não há homônimo,
não há o que escolher — nome + arquivo já identificam a função. A condição é **estrutural** ("há
outro método com esse nome neste arquivo?"), respondida pelo arquivo, não pelo resultado.

**O que a decisão NÃO afrouxa:** onde **há** homônimo (`hash_desempata`, `sem_hash_varios`), o
hash continua obrigatório e continua sendo a única coisa que decide. Nada entra por semelhança,
nem por span de linhas. O critério alternativo não toca o caso ambíguo, que é o caso de risco.

**Por que isto não viola a regra de "não ajustar depois de ver o número":** aquela regra é sobre
**regra de curadoria**, e montagem de dataset é posterior e já está declarada fora do congelado
(`NEGATIVOS.md`). Ainda assim, **os dois números continuam no artigo**, lado a lado, com a
justificativa acima — não se troca um pelo outro em silêncio.

## O que muda a partir daqui

O lado negativo passou de "teto" a **número medido**: entre 10.788 e 14.133 exemplos de treino,
conforme o critério. Com os positivos já congelados (`M_raw` 1806, `M_cur` 533, 5 × `M_ctrl` 533),
os sete braços têm tamanho definido dos dois lados.

Próximos passos, em ordem:

1. ~~Decidir o critério~~ — **feito, alternativo** (seção acima).
2. ~~Medir a saúde de parse nos positivos~~ — **feito**, em `PARSE_IFDEF.md`.
3. **Montar o dataset de verdade** e substituir as estimativas pelas contagens.

A causa das falhas que sobram foi investigada e está em **`PARSE_IFDEF.md`**: não é nome errado
nem função ausente, é o `#ifdef` sem header. Leia-o antes de tentar recuperar os 12,4%.
