# Validacao cega — segundo anotador para a validacao manual do BigVul

Mede se a taxa de ruido de rotulagem estimada na validacao manual
(`../saida/amostra_validacao_revisao.csv`, n=50, anotador unico: o autor) e
reproduzivel por um segundo anotador independente e cego.

O segundo anotador e um modelo. **Ele nao e ground truth.** O que se mede aqui e
*confiabilidade* — reprodutibilidade do julgamento sob a mesma rubrica — nao
acuracia. O numero que isso protege e o `~57% de ruido`, que hoje depende de uma
unica pessoa, que por sinal e a pessoa cuja hipotese ganha se o ruido for alto.

## Nao usa a Messages API

Nao ha `ANTHROPIC_API_KEY` envolvida. O anotador roda via `claude -p`, o modo
headless do CLI do Claude Code, que consome a assinatura / creditos de uso extra
ja existentes. Creditos de uso extra do Claude Code e creditos do console da
Anthropic sao contas separadas: os primeiros nao pagam chamadas a
`api.anthropic.com`. Por isso o caminho aqui e o CLI.

Consequencia: o runner roda no **PowerShell do Windows** (o CLI esta instalado
la; o WSL nao tem node). Os dois scripts de dados rodam no **WSL**, como o resto
do pipeline.

## Ordem de execucao

```powershell
# 1. Pacotes de evidencia cegos  (WSL)
wsl -d Ubuntu-24.04 -- bash -c "cd /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/validacao_cega && \
  python3 preparar_pacotes.py --positivos ../saida/bigvul_memoria_positivos.parquet \
    --outdir . --sample-size 50 --seed 42 --condicao cve_visivel \
    --conferir ../saida/amostra_validacao_revisao.csv"

# 2. Anotacao pelo modelo  (PowerShell)
.\anotar_modelo.ps1 -Condicao cve_visivel -Repeticoes 3 -Simular   # estimativa
.\anotar_modelo.ps1 -Condicao cve_visivel -Repeticoes 3            # pra valer

# 3. Consolidacao  (WSL)
wsl ... python3 consolidar_brutos.py --condicao cve_visivel

# 4. Comparacao  (WSL)
wsl ... python3 comparar.py --condicao cve_visivel
```

Condicao secundaria (sonda de memorizacao), mesma sequencia com
`--condicao cve_oculta` / `-Condicao cve_oculta`, `-Repeticoes 1`, e
`comparar.py --condicao cve_oculta --sufixo _oculta`.

O passo 2 e **resumivel**: chamadas que ja gravaram bruto sao puladas. Se algo
falhar no meio, rode de novo.

## Arquivos

| arquivo | o que e |
| --- | --- |
| `rubrica_v1.md` | Taxonomia A/B/C/D congelada + contrato de saida. **Nao editar apos a anotacao.** O hash e verificado. |
| `pre_registro.md` | Plano de analise escrito antes de ver qualquer discordancia. `comparar.py` recusa rodar sem ele. |
| `preparar_pacotes.py` | Monta um pacote de evidencia por caso. Nunca le os rotulos do humano. |
| `anotar_modelo.ps1` | Roda o modelo, um caso por chamada, sem ferramentas, sem historico compartilhado. |
| `consolidar_brutos.py` | Brutos JSON -> planilha tabular, com normalizacao e contagem de parses sujos. |
| `comparar.py` | Kappas, matriz de confusao, auto-consistencia, bootstrap por cluster, relatorio. |
| `pacotes/<condicao>/caso_NN.md` | O prompt exato enviado. Reproduzivel; serve de apendice. |
| `brutos/<condicao>/` | Resposta crua de cada chamada, com metadados de uso. |
| `saida/` | Planilha do modelo, relatorio, discordancias, log. |

## O que garante a cegueira

1. `preparar_pacotes.py` nao abre a coluna `tipo_ruido` do CSV do humano. O modo
   `--conferir` le apenas `id/project/commit_id/cve_id`, para provar que a
   amostra foi reproduzida (mesmo `seed=42`, mesmo `n=50`), e falha se nao bater.
2. O runner passa `--disallowed-tools` com todas as ferramentas de arquivo, shell
   e web. Sem isso o anotador poderia sair lendo o CSV do humano no disco.
3. Uma chamada por caso, em processo separado: o caso N nao ve o caso N-1.

## Casamento de evidencia

O pacote reproduz o bloco que o humano leu no `caderno_revisao.md` (mensagem de
commit, resumo da CVE truncado em 1200 chars, diff da funcao truncado em 8000
chars, mesma funcao `difflib`) e acrescenta o **diff do commit inteiro**,
tirado da coluna `files_changed` do proprio BigVul — nao ha download por HTTP,
o que tambem elimina o problema de rate limit do googlesource.

Cinco casos (**15, 27, 29, 34, 47**) nao tem `files_changed` no BigVul, porque
essa coluna veio da API do GitHub e esses commits estao em cgit/gitweb. Nesses o
pacote declara a ausencia em vez de fingir. Um deles, o **27**, e justamente
aquele onde o humano anotou "nao fui atras por estar sem internet" — ali a
assimetria de evidencia e nula por acidente.

## Limitacoes conhecidas (todas declaradas em `pre_registro.md`)

- **Memorizacao.** As CVEs sao publicas e de 2009-2019. A condicao `cve_oculta`
  sonda mas nao elimina.
- **Sem `temperature`.** O parametro e rejeitado pela familia Claude 5. A
  variabilidade e *medida* pelas repeticoes, nao suprimida — por isso a
  auto-consistencia (kappa de Fleiss entre repeticoes) e obrigatoria no relatorio:
  ela e o teto do kappa humano-modelo.
- **Prompt de sistema do harness.** O `claude -p` antepoe o prompt do Claude Code
  ao pacote. O pacote e integralmente reproduzivel; o prompt do harness nao e
  versionado por nos.
- **Cegueira parcial na condicao `cve_oculta`.** CVE, resumo, mensagem de commit,
  URLs e hash saem, mas caminhos de arquivo e estilo de codigo ainda denunciam
  projetos conhecidos.
- **n pequeno e linhas dependentes.** 50 linhas, 37 commits, 14 linhas da mesma
  CVE-2016-1621. Por isso todo IC sai de bootstrap por cluster de commit, e todo
  kappa e reportado tambem restrito a um caso por commit.
- **`id=29` foi pre-preenchido** automaticamente como A pelo `revisar_validacao.py`
  (funcoes identicas apos normalizar espaco em branco). O humano nao julgou do
  zero; o modelo sim. O relatorio reporta os kappas com e sem essa linha.

## Custo

Cada chamada manda o pacote inteiro (mediana ~24 mil chars, maximo ~134 mil) e
nao ha reuso de cache entre casos, porque cada pacote e unico. Medido no teste de
fumaca: **~US$ 0,16 por chamada com `claude-opus-5`** (valor nocional de API; na
assinatura sai do uso do plano).

- condicao primaria, 50 casos x 3 repeticoes = 150 chamadas ≈ US$ 24
- condicao secundaria, 50 casos x 1 repeticao = 50 chamadas ≈ US$ 8

Para cortar: `-Repeticoes 2` (perde resolucao na auto-consistencia, mas ainda da
para medi-la) ou `-Modelo claude-sonnet-5` (mais barato; como anotador e uma
escolha pior, e vira uma limitacao a declarar).

Rode `-Simular` antes para ver a conta.
