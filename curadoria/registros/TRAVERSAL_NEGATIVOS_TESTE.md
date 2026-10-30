# A traversal v3 nas funções não vulneráveis do teste (a linha "traversal pura")

Registro de **12–13/10/2026**. Cartão do Notion: "Treinar os braços do experimento e montar as
tabelas de resultados".

## Situando

**Onde estamos.** Os 13 braços do ReVeal estão treinados, e o teste ainda não foi aberto. Antes de
abri-lo, o `modelo/PREREGISTRO_PRINCIPAL.md` (congelado em 12/10, §6 passo 3 e §7) mandou rodar a
regra da curadoria nas funções **não vulneráveis** do teste. É o que falta para a linha "traversal
pura" da tabela de resultados: a regra congelada usada como detector ("confirmado" = acusa),
comparada com o `M_cur`. Essa linha responde a pergunta do orientador de 05/09: "a rede aprendeu só
o que o Joern já faz?".

**Por que precisou rodar.** A traversal v3 só tinha rodado nos 2957 **positivos** (é uma curadoria
de positivos; `TRAVERSAL_V3.md`, Fase 4). As 5241 negativas do teste nunca tinham passado por ela,
e sem elas não existe F1 da regra.

**O que este registro NÃO é.** Não é resultado: o executador grava só a **evidência** (as
contagens da camada 1, da camada 2 e de saúde do parse), sem veredito. Contar agora quantas
negativas a regra confirma já seria ver parte do resultado da "traversal pura" no teste. O
veredito (`veredito.py` + `regra_veredito.toml`) é aplicado pelo script de análise, na abertura.

## Como rodou

- **Executador novo:** `rodar_traversal_negativos.py`. Mesma regra e mesma chamada dos positivos
  da v3 (`curadoria_v3.sc` + `dados/`); antes de rodar, `congelar.py --versao v3` confere o hash
  dos 4 arquivos de regra (conferiu em todos os lançamentos).
- **Alvo de cada função:** pasta do CPG e nome vêm de `montar_dataset.carregar_alvos("v3")`, a
  mesma montagem que gerou o dataset v3 — a regra olha o mesmo método de onde saiu o grafo.
- **Linha de início:** passada só nas **118** negativas com homônimo no arquivo (motivo `hash` no
  `dataset_indice_v3.tsv`), como nos positivos (decisão do autor, 12/10). As outras 5123 vão sem
  linha.
- **Diferenças declaradas em relação aos positivos:** o CPG é o já guardado em
  `~/curadoria/completa` (mesmo c2cpg, mesmo arquivo), em vez de regerado item a item; e, se a
  regra recusasse uma função por achar 2+ métodos com o mesmo nome, rodaria de novo com a linha do
  grafo — **não aconteceu nenhuma vez**.
- **Saída:** `saida_negativos_teste_v3/<id>.json`, um por função, escrita atômica.

## O que aconteceu

| quando | o quê |
| --- | --- |
| 12/10, ~19:05 | ensaio em 20 negativas (17 sorteadas com semente 7070 + 3 homônimas): 20/20 com evidência, 7,6 s de mediana |
| 12/10, 19:07 | rodada inteira lançada destacada do terminal (`_rodar_negativos_v3.sh`, `Start-Process` oculto no Windows) |
| 12/10, 21:52 | o PC entrou em suspensão (Windows: "Application API" — um programa pediu). O `/mnt/c` deu erro de E/S e a rodada parou com **1374** funções feitas, todas íntegras |
| 13/10, 01:06 | relançada depois de conferir as 1374 saídas uma a uma; o laço passou a esperar 60 s entre tentativas |
| 13/10, 08:49 | **fim** |

## Resultado técnico (sem veredito)

- **5241 de 5241** negativas do teste com evidência; **0 falhas**; 0 refeitas pela trava de
  homônimo;
- tempo por função: mediana 7,3 s, p90 8,0 s, máximo 13,2 s; soma 10,5 h de processamento.

## O que muda a partir daqui

A linha "traversal pura" passa a ser calculável. Os positivos do teste já tinham veredito da
rodada v3 (`saida_completa_v3/`); as negativas agora têm evidência. O próximo passo da ordem de
abertura (`PREREGISTRO_PRINCIPAL.md` §6) é o 4: o script de análise, que confere o hash dos dois
pré-registros, aplica o veredito às negativas e calcula todas as tabelas — ensaiado primeiro só
na validação, e só depois rodado no teste, uma vez.
