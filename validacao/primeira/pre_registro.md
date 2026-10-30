# Pre-registro da analise de concordancia entre anotadores

> **Escrito antes de olhar qualquer discordancia.** O script `comparar.py`
> recusa rodar sem este arquivo e grava o hash SHA-256 dele no relatorio. Se
> voce mudar este plano depois de ver os resultados, o hash muda e a mudanca
> fica visivel no diff.

## Pergunta

A estimativa de ruido de rotulagem do BigVul obtida na validacao manual
(`saida/amostra_validacao_revisao.csv`, n=50, anotador unico: o autor) e
reproduzivel por um segundo anotador independente e cego?

## Anotadores

- **H** (humano): o autor. Anotacao ja concluida em 31/07/2026.
- **M** (modelo): Claude Opus 5 via `claude -p`, sem acesso aos rotulos de H,
  sem ferramentas, um caso por chamada, cada chamada em processo separado e sem
  historico compartilhado entre casos.

M **nao** e ground truth. Esta analise mede **confiabilidade** (reprodutibilidade
do julgamento sob a mesma rubrica), nao acuracia.

## Condicoes

- **Condicao primaria — `cve_visivel`**: M recebe o mesmo conjunto de evidencias
  que H tinha disponivel (mensagem de commit, resumo da CVE, diff da funcao,
  contexto do commit). Todas as analises abaixo sao rodadas nesta condicao.
- **Condicao secundaria — `cve_oculta`**: identificadores de CVE, resumo e
  mensagem de commit removidos, para sondar o quanto a concordancia depende de
  memorizacao das CVEs publicas. Reportada apenas como sensibilidade.

## Repeticoes

M anota cada caso `R` vezes de forma independente (padrao R=3) na condicao
primaria. O rotulo de M usado nas analises principais e o **voto majoritario**
entre as R repeticoes; empate resolve para `?`.

## Metricas — declaradas antes de ver os dados

1. **Primaria: kappa de Cohen binario** — `D` contra `A+B+C`. E a metrica que
   sustenta a taxa de ruido, que e o numero reportado no TCC.
2. **Secundaria: kappa de Cohen de 4 categorias** — A/B/C/D sem colapso.
   Diagnostica *onde* os anotadores divergem.
3. **Matriz de confusao 5x5** (A/B/C/D/?), sem colapso, para leitura qualitativa.
4. **Auto-consistencia de M**: kappa de Fleiss entre as R repeticoes, mais a
   fracao de casos em que as R repeticoes concordam integralmente. Um anotador
   que discorda de si mesmo nao serve como segundo anotador; este numero deve
   ser reportado junto com o kappa H-M.
5. **Taxa de ruido por anotador**: `1 - D/(total - ?)`, calculada
   independentemente para H e para M, reportada como faixa.

## Tratamento dos `?`

Casos em que qualquer um dos anotadores marcou `?` sao **excluidos** de todos os
calculos de kappa e da taxa de ruido, e reportados a parte com a contagem por
anotador. O `?` nao e uma quinta categoria substantiva; e ausencia de decisao.

## Nao-independencia das linhas

As 50 linhas nao sao observacoes independentes: ha 37 commits distintos e 14
linhas pertencem a mesma CVE (CVE-2016-1621, libvpx). Portanto:

- Todo kappa e reportado tambem em uma **analise por commit**, restrita a
  primeira linha de cada commit distinto (n=37).
- Os intervalos de confianca de 95% para os kappas e para as taxas de ruido sao
  obtidos por **bootstrap com reamostragem por cluster de commit** (10.000
  reamostragens, clusters = `commit_id`, semente 42). Bootstrap por linha
  subestimaria a incerteza.

## Caso pre-preenchido

A linha `id=29` teve `tipo_ruido=A` **pre-preenchido automaticamente** pelo
`revisar_validacao.py` (funcoes identicas apos normalizar espaco em branco); H
nao a julgou do zero, M sim. O relatorio reporta todos os kappas duas vezes:
com e sem essa linha.

## Adjudicacao

**Os rotulos de H permanecem os primarios.** Nenhum rotulo de H e alterado em
funcao de uma discordancia de M dentro desta analise. As discordancias sao
exportadas para `saida/discordancias.csv` para leitura, mas:

- se houver adjudicacao posterior, ela deve ser registrada em um arquivo novo,
  e o kappa **pre-adjudicacao** calculado aqui continua sendo reportado no TCC;
- a taxa de ruido no texto vai como faixa (valor de H, valor de M), com H como
  numero principal.

Revisar seletivamente so os casos que M contestou, e mudar de ideia neles,
transformaria a opiniao de M em rotulo de H sem passar por nenhuma medida — e o
que este paragrafo existe para impedir.

## Limitacoes declaradas de antemao

1. **Memorizacao**: as CVEs da amostra sao publicas e de 2009-2019, dentro do
   corte de treino do modelo. M pode estar recuperando a CVE em vez de julgar o
   codigo. A condicao `cve_oculta` sonda isso mas nao o elimina (o codigo de
   projetos conhecidos tambem e memorizavel).
2. **Determinismo**: nao ha `temperature` disponivel — o parametro e rejeitado
   pelos modelos da familia Claude 5. A variabilidade e medida pelas R
   repeticoes em vez de suprimida.
3. **Prompt de sistema do harness**: as chamadas passam pelo `claude -p`, que
   antepoe o prompt de sistema do Claude Code ao pacote de evidencias. O pacote
   e integralmente reproduzivel; o prompt do harness nao e versionado por nos.
4. **n pequeno**: com n=50 (37 clusters) o IC do kappa e largo. Isto e uma
   verificacao de sensibilidade, nao um estudo de concordancia com poder.
5. **Evidencia levemente super-conjunto**: o caderno que H leu trazia diff da
   funcao, mensagem de commit e resumo da CVE; H abriu o commit completo em
   parte dos casos (e no `id=27` registrou nao ter conseguido, por estar sem
   internet). O pacote de M inclui o contexto do commit em todos os casos onde
   o BigVul o tem. A assimetria residual e por caso e nao e observavel.
