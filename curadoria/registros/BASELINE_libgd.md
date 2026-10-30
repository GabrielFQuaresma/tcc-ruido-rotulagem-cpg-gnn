# Baseline de regressão — CVE-2016-6906 / `read_image_tga` (libgd)

Reproduzido localmente em **03/08/2026**. Este arquivo, e não a §4.6 do artigo, é a
referência de regressão da traversal. Se a traversal mudar e estes números mudarem, é
regressão. **Nunca ajustar a traversal para bater com o texto do artigo** — seria
overfitting em n=1.

## Insumo

| item | valor |
| --- | --- |
| caso | `Dataset/bigvul/saida_final/itens/1217__libgd/` |
| arquivo de contexto | `arquivo__gd_tga.c` — 351 linhas, 8.893 bytes |
| função alvo | `read_image_tga`, assinatura `int(gdIOCtx*,oTga*)` |
| linhas da função | **206–336** (bate com a §4.6) |
| Joern | `/opt/joern`, Java 21 (OpenJDK 21.0.10) |
| geração do CPG | `c2cpg.sh gd_tga.c --output gd_tga.cpg.bin` |
| tempo real | **2,7 s** (a figura `step2_cpg.svg` alega "~30 s") |
| tamanho do CPG | **73 KB** (a figura alega "74K" — bate) |

## Camada 1 — presença

| medida | valor | §4.6 |
| --- | --- | --- |
| chamadas a `memcpy` | **2** | 2 ✅ |
| acessos indexados (`<operator>.indirectIndexAccess`) | **7** | 7 ✅ |

Outras chamadas na função: `gdFree` (11), `gdMalloc` (4), `overflow2` (3), `gdGetBuf` (2),
`gd_error` (2). Nenhuma outra função de memória insegura da libc.

## Guardas — condições

`controlStructure` na função: 21 no total — 13 `IF`, 3 `WHILE`, 2 `BREAK`, 1 `FOR`,
1 `ELSE`, 1 `SWITCH`.

**Condições = 13 + 3 + 1 + 1 = 18** (só as estruturas que têm condição; `BREAK` e `ELSE`
não têm). Bate com os "dezoito condições" da §4.6. ✅

Registrado como apoio à leitura, **nunca como critério de decisão**.

## Camada 2 — fluxo

Aqui os números do artigo **não são reproduzíveis com uma configuração única**. Matriz
completa medida:

### Sink = memória

| fonte | sink | fluxos |
| --- | --- | --- |
| parâmetros | `dest` + `size` | **8** |
| parâmetros + `gdGetBuf` | `dest` + `size` | 8 |
| parâmetros | **todos os args** (`dest`,`src`,`size`) | **12** |
| parâmetros + `gdGetBuf` | todos os args | 12 |

### Sink = índice de `a[i]`

| fonte | fluxos |
| --- | --- |
| parâmetros | **14** |
| `gdGetBuf` só | 4 |
| parâmetros + `gdGetBuf` | **18** |

### O que isso revela sobre a §4.6

Os dois números do artigo (12 e 18) **existem**, mas vêm de **configurações diferentes e
incompatíveis entre si**:

- o **12** exige incluir o argumento `src` do `memcpy` — o que contradiz a prosa da própria
  §4.6, que diz "argumento de **tamanho ou destino**". Só tamanho e destino dá **8**.
- o **18** exige somar `gdGetBuf` às fontes — um nome de função **específico do libgd**.
  Só com a regra estrutural (parâmetros) dá **14**.

Ou seja, o exemplo do artigo foi montado com duas queries distintas, e uma delas depende de
um identificador de projeto. É exatamente o tipo de coisa que a traversal versionada não pode
fazer.

## Baseline adotado

Configuração única e generalista, que é a que a traversal implementa:

- **fonte:** parâmetros da função (regra estrutural) + funções de I/O da libc (tabela).
- **sink de memória:** argumentos de ponteiro (origem **e** destino) e de tamanho. Incluir a
  origem é justificado: a família declarada cobre CWE-125 (leitura fora de limites), e numa
  leitura fora de limites o acesso indevido está no ponteiro de **origem**. Não é ajuste para
  bater com o 12 — é consequência do escopo declarado.
- **sink de índice:** argumento 2 de `<operator>.indirectIndexAccess`.

| medida | baseline |
| --- | --- |
| `memcpy` | 2 |
| acessos indexados | 7 |
| condições | 18 |
| fluxo → argumento de memória | **12** |
| fluxo → índice | **14** |

## Consequências

1. **§4.6 do artigo:** o "18 fluxos até o índice" tem que virar **14**. Os demais números
   ficam. A prosa do sink de memória tem que dizer "ponteiro (origem ou destino) ou tamanho".
2. **Figuras `step2_cpg.svg` e `step3_query.svg`:** são desenhos em SVG com aparência de
   captura de terminal, e o `step3_query.svg` mostra a saída de um `curadoria_v2.sc` que não
   existia. Trocar por captura real.
3. **Ameaça à validade (nova):** projetos que embrulham I/O em abstração própria — como o
   `gdGetBuf` do libgd — não disparam a regra de fonte baseada em nomes da libc. Nesses casos
   só a regra estrutural (parâmetros) atua, e a contagem de fluxos sai menor. Isso não é bug:
   é o preço de não colocar nome de projeto na traversal. Declarar.

## Armadilha técnica registrada

Traversal do Joern é **iterador de uso único**. Reusar um `val` de traversal devolve vazio na
segunda leitura, sem erro — a primeira versão deste diagnóstico "mediu" 0 fluxos por isso.
No `.sc`, tudo que for traversal é `def`, nunca `val`.

O Joern também cria um diretório `workspace/` no **cwd**. Rodar sempre com o cwd num diretório
de trabalho, senão ele suja a pasta do dataset.
