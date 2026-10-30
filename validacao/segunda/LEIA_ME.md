# LEIA-ME — segunda validação manual (a precisão do filtro)

Comece por aqui. Este guia diz o que é esta pasta, para que ela serve no artigo e o que fazer, na
ordem. O método inteiro está no `PRE_REGISTRO_SEGUNDA.md`.

## Em uma frase

Você vai ler 60 funções do BigVul **sem saber o que o filtro de curadoria fez com cada uma** e
dizer, para cada uma, se ela é o sítio da vulnerabilidade; depois, uma chave lacrada revela o que
o filtro fez, e do cruzamento sai a precisão do filtro.

## Onde estamos e para que serve

**No pipeline.** A curadoria já rodou, com a *traversal* v3 (a consulta do Joern que olha cada
função marcada como vulnerável pelo BigVul e procura o padrão de erro de memória em buffer). O
treino e as arenas também já rodaram. Esta é a etapa 7 do cronograma, a única que sobrou.

**No artigo.** Dois trechos em vermelho (`\aescrever`) esperam por ela:

- **Seção 3.4 (Validações manuais):** "como a segunda validação foi feita" — sai do pré-registro;
- **Seção 4.2, fim do primeiro parágrafo:** "a precisão do filtro medida na segunda validação
  manual" — sai da análise, depois que você anotar.

Hoje a única medida da precisão é a da Etapa 5: **64,7%** — das 17 funções que o filtro confirmou
entre os 50 casos da primeira validação, 11 eram de fato o sítio —, com intervalo de confiança de
95% de 40,0% a 86,7%. É largo porque são só 17. Esta validação mede a mesma coisa numa amostra
desenhada para a pergunta: 30 funções que o filtro confirmou e 30 que ele descartou, misturadas.

## Os termos

| termo | o que é |
| --- | --- |
| **BigVul** | o dataset: funções em C/C++ marcadas como vulneráveis porque foram alteradas por um commit que corrige uma CVE |
| **CVE / CWE** | CVE é o identificador público de uma vulnerabilidade (ex.: CVE-2016-1621); CWE é a categoria do defeito (ex.: CWE-119, erro de buffer) |
| **traversal** | a consulta do Joern (ferramenta que transforma o código num grafo, o CPG) que procura o padrão de erro de memória em cada função |
| **veredito** | o que a traversal diz de cada função: `confirmado` (o padrão está lá; a função entra no `M_cur`, o conjunto de treino curado) ou `descartado` (não está; a função só fica de fora — o rótulo nunca é invertido) |
| **sítio** | a função em cujo corpo está o defeito explorável. É a categoria **D** da rubrica, e é o único rótulo que conta como correto |
| **precisão do filtro** | das funções que o filtro confirmou, a fração que é sítio |
| **estrato** | cada um dos dois grupos de onde se sorteou separadamente: confirmados (30 casos) e descartados (30) |
| **cegueira** | você não sabe, enquanto anota, o veredito de nenhum caso — saber puxa o julgamento na direção do filtro |
| **chave lacrada** | `chave/chave_segunda.csv`, o único arquivo que liga cada caso ao veredito; só se abre no fim |
| **taxa base** | a proporção de sítios entre todos os positivos, sem filtro: quanto o BigVul acerta sozinho |
| **ganho** | precisão menos taxa base: quanto o filtro melhora a proporção de rótulos corretos |
| **os 50** | a amostra da primeira validação (semente 42), que você anotou em julho e agosto |
| **dev set** | 30 positivos (semente 7), anotados pelo modelo, usados para conferir a regra antes de olhar os 50 |
| **SHA-256** | a impressão digital de um arquivo: muda se um único caractere mudar |

## O que esta validação NÃO é

- **Não é a primeira validação.** A primeira mediu o ruído do BigVul bruto, antes do filtro. Esta
  mede o filtro, com 50 funções novas: nenhuma dos 50 antigos, nenhuma do dev set.
- **Não é a Etapa 5.** A Etapa 5 reaproveitou os rótulos dos 50 antigos para estimar a precisão
  (64,7%, com só 17 confirmados). Esta é a medida feita para isso.
- **Não é uma disputa entre você e o filtro.** A rubrica decide cada caso; a chave só diz o que o
  filtro fez.

## Os passos, na ordem

### 1. Reler o pré-registro e congelar (uns 15 minutos)

Os três pontos da §9 foram **decididos em 30/10/2026**:

1. **o n e a proporção:** 30 + 30 (era a proposta 30 + 20; a amostra foi remontada antes de
   qualquer anotação);
2. **os 19 casos cujo commit você já viu** (nos 50 ou no dev): manter e marcar;
3. **sortear por função ou por commit:** por função.

O `PRE_REGISTRO_SEGUNDA.md` ainda está marcado como **PROPOSTA NÃO CONGELADA**. Releia e congele
(§12 do pré-registro): troque o aviso do topo, grave o SHA-256 do arquivo em
`congelamento_segunda.tsv` e no cartão do Notion. **Não abra o caderno antes disso.**

### 2. Anotar (de 3h a 5h, em três sessões)

Abra `caderno_segunda.md` e, ao lado, `anotacao_segunda.csv`. Para cada caso, leia, decida e
preencha a linha de mesmo número (coluna `id`). **Não abra a pasta `chave/`.**

### 3. Só então pedir a análise

Com as 60 linhas preenchidas, peça a análise. O script de análise ainda não existe, de propósito:
ele é escrito depois do congelamento e confere os SHA-256 antes de rodar. Só aí a chave é aberta.

## Como preencher cada coluna

As sete primeiras colunas (`id` até `commit_patch`) já vêm preenchidas: **não mexa nelas** — a
análise confere que continuam iguais.

| coluna | o que pôr (da `../rubrica_v1.md`) |
| --- | --- |
| `tipo_ruido` | **A** = sem mudança semântica na função (só espaço em branco, formatação ou comentário) — não vulnerável. **B** = a função mudou, mas a mudança não tem relação com a CVE (refatoração, funcionalidade não relacionada, alteração em outro subsistema que veio junto no commit) — não vulnerável. **C** = a função mudou como parte do conserto, mas não é o sítio do bug (ajuste de parâmetros, reset de contador, hardening de apoio, propagação de um novo argumento); a mudança é ligada à correção, mas o defeito explorável não está nela — não vulnerável. **D** = a função é o sítio, reconhecível aqui: o acesso de memória indevido, a falta de checagem de limite, o overflow de inteiro que alimenta o tamanho — o defeito está no corpo dela — vulnerável. **?** = não deu para decidir com a evidência disponível (não chute para evitar o `?`). |
| `confianca` | exatamente um de: `alta` (a evidência decide o caso), `media` (a leitura mais provável é essa, mas há outra plausível) ou `baixa` (chute informado: falta contexto, conhecimento do subsistema, ou a evidência é ambígua) |
| `cwe_correta` | **só nos D**, no formato `CWE-NNN`: se a CWE do BigVul estiver certa, repita-a; se não houver CWE aplicável ou não der para determinar, deixe vazio. Nos A, B e C, vazio |
| `observacao` | uma ou duas frases justificando; nos D, diga se reconheceu o bug só com a função ou se precisou do commit inteiro |

O caso **43** já vem marcado como A (as duas versões da função só diferem em espaço em branco). Se
discordar, troque e diga por quê na observação.

Dá para editar no VS Code, no LibreOffice ou no Excel; se o Excel regravar com `;` ou mudar a
codificação, tudo bem. O que não pode é mexer nas sete primeiras colunas.

## Quanto tempo

O caderno tem 121 mil caracteres, contra 97 mil do caderno da primeira validação, que tinha 50
casos. Metade dos casos tem até uns 1.580 caracteres no total (links, mensagem do commit, resumo
da CVE e um diff curto); 3 passam de 4.000; 1 é o A já marcado. Se você lembra quanto levou a
primeira, conte com isso mais um quinto. Se não: de 3 a 5 minutos por caso, **de 3h a 5h** ao
todo, melhor em três sessões de 20 casos — o cansaço muda o critério.

## Enquanto anota, não

- abrir a pasta `chave/`;
- consultar `traversal/conjuntos_v3/` (o `M_raw.tsv` e o `M_cur.tsv` dizem o veredito),
  `traversal/saida_completa_v3/`, nem rodar a traversal nesses commits;
- reabrir a planilha ou o caderno da primeira validação para ver o que você disse de outra função
  do mesmo commit: são funções diferentes e podem ter rótulos diferentes. Dos 60 casos, 19 têm um
  commit que você já viu — 7 deles são da CVE-2016-1621, o commit da libvpx que ocupava 14 dos 50.
  Julgue a função que está na sua frente;
- perguntar a um assistente o veredito de um caso.

**Nota para quem conversa com o anotador:** não informar veredito, estrato,
nem nenhuma contagem por estrato (pré-marcados, commits já vistos, projetos) até a planilha estar
completa e o pré-registro congelado.

## Arquivos desta pasta

| arquivo | o que é |
| --- | --- |
| `LEIA_ME.md` | este guia |
| `PRE_REGISTRO_SEGUNDA.md` | o plano da validação; proposta até você congelar |
| `caderno_segunda.md` | o que você lê: os 60 casos, com a rubrica resumida no topo |
| `anotacao_segunda.csv` | o que você preenche |
| `montar_segunda.py` | o script que sorteou e montou tudo; recusa sobrescrever a planilha se ela já tiver qualquer anotação sua |
| `chave/` | a chave lacrada e um aviso — **não abrir antes de terminar** |

SHA-256 da chave (`chave/chave_segunda.csv`, amostra 30 + 30 de 30/10/2026):
`013f16819667bf3d8b4225652c031165abc824f9f06f3638d0a5a5e8bcf50afb`. O mesmo valor está na §13 do
pré-registro; se a chave mudar, a análise não roda.

## O que muda depois

Com a planilha completa e a análise rodada, os dois trechos vermelhos do artigo (Seções 3.4 e 4.2)
podem ser escritos, e a etapa 7 — a última do cronograma — fecha. O cartão "Segunda validacao
manual" no Notion sai de "A fazer". O próximo passo concreto é o passo 1 acima: reler o
pré-registro e congelar.
