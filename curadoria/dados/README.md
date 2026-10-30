# Tabelas de dados da traversal

Estas tabelas existem **fora do código** por um motivo só: elas são o lugar onde o viés pode
entrar, e por isso precisam ser auditáveis linha a linha. A regra do card é *preferir construção
de linguagem a lista de nomes* — indexação, aritmética de ponteiro e parâmetro de função são
propriedades do C e não têm como enviesar para projeto; lista de biblioteca é escolha humana.

## Invariante (vira teste no runner)

**Nenhum arquivo em `traversal/` pode conter identificador de projeto, id de CVE ou nome de função
de aplicação.** Só nomes de libc/POSIX e construções da linguagem. O `gdGetBuf` do libgd é o
contraexemplo canônico: incluí-lo faria a §4.6 "bater", e seria exatamente o overfitting em n=1
que o `BASELINE_libgd.md` proíbe.

## Convenções

- Posições de argumento são **0-indexadas**, no mesmo padrão do `BASELINE_libgd.md`
  (`memcpy dest=0 src=1 size=2`).
- `-` significa "não se aplica" ou "não rastreável por posição" (caso das variádicas).
- `ret` na coluna `saida` significa que a fonte é o **valor de retorno**, não um argumento.

## A coluna `fonte`

| valor | o que significa |
| --- | --- |
| `li2018` | nomeada explicitamente no conjunto de chamadas de biblioteca associadas a erro de buffer de Li et al. (2018) |
| `libc` | mesma família por assinatura do C padrão / POSIX; derivada da definição, não da amostra |
| `estrutural` | não é nome de função — é propriedade da linguagem |

**Sobre o `li2018`:** o artigo relaciona **124** chamadas de biblioteca a erro de buffer
(CWE-119), mas a lista completa não está no corpo do paper. Esta tabela é um **subconjunto**
montado a partir dos nomes citados no texto mais a família por assinatura. Cada linha carrega sua
própria fonte justamente para essa distinção ficar auditável.

**E uma ressalva de enquadramento que importa para a §4.5:** em Li et al. (2018) essas chamadas
são **pontos de partida para fatiar o código** (slicing para trás a partir de cada chamada), e
quem decide se há vulnerabilidade é uma BiLSTM treinada. Elas nunca foram, no trabalho de origem,
veredito de nada. Aqui elas entram como **camada 1, de presença** — e é precisamente por isso que
a camada 1 sozinha não pode confirmar rótulo.

## `funcoes_memoria.tsv` — sinks

Colunas: `nome`, `categoria`, `dest`, `src`, `size`, `fonte`, `nota`.

O `src` está aqui porque o baseline adotado inclui o **ponteiro de origem** entre os sinks, e não
só destino e tamanho. Justificativa: a família declarada cobre CWE-125 (leitura fora de limites),
e numa leitura fora de limites o acesso indevido está na origem. Não é ajuste para bater com o
"12" do artigo — é consequência do escopo declarado. (Ver `BASELINE_libgd.md`, seção *Baseline
adotado*.)

### Sobre a categoria `alocacao`

`malloc`/`calloc`/`realloc`/`alloca` estão na tabela mas são **o caso mais perigoso para o tamanho
do `M_cur`**: quase toda função em C não trivial aloca memória. Se a camada 1 contar alocação como
presença, ela dispara em praticamente tudo.

Por isso o `.sc` emite as contagens **por categoria**, nunca somadas, e cabe à
`regra_veredito.toml` decidir quais categorias contam. É o mesmo princípio do card: o script emite
evidência, a config emite veredito.

## `fontes_nao_confiaveis.tsv` — sources

Colunas: `nome`, `tipo`, `saida`, `fonte`, `nota`.

A primeira linha é a **regra estrutural**: todo parâmetro da função é fonte não confiável, porque
a função não controla quem a chama. É a regra mais ampla e a mais defensável, e é a única que
sobra em projetos que embrulham I/O em abstração própria.

**Ameaça à validade que sai daqui:** projetos com wrapper próprio de I/O (o `gdGetBuf` do libgd é
o exemplo) não disparam a regra por nome de libc, e a contagem de fluxos sai menor. Isso não é
bug — é o preço de não colocar nome de projeto na traversal. Já está declarado na página raiz do
TCC.

## Sobreposição entre as duas tabelas

`read`, `recv`, `fread`, `fgets` e `gets` aparecem nas duas: são sinks de escrita em buffer **e**
fontes de dado não confiável. Isso é correto e proposital. O `.sc` conta os dois papéis
separadamente; nenhum número é somado com o outro.
