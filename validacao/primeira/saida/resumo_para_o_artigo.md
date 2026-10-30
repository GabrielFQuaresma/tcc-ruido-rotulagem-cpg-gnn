# Validacao do ruido de rotulagem do BigVul — resumo consolidado

Fechado em 02/08/2026. Este arquivo e o destilado dos tres relatorios
(`relatorio_concordancia.md`, `relatorio_concordancia_oculta.md`, saida do
`comparar_condicoes.py`) mais o tally por commit. **E daqui que se escreve o
artigo** — os relatorios completos ficam como apendice/repositorio.

---

## 1. O numero principal

Amostra de 50 funcoes que o BigVul marca como vulneraveis (`vul=1`), sorteadas
com semente 42 do conjunto de 2957 positivos da familia de erro de memoria.

| | funcoes que sao mesmo o sitio da vulnerabilidade | ruido |
| --- | --- | --- |
| **anotador humano** (primario) | 21 de 49 decididas (42,9%) | **57,1%** [IC95% 34,2–74,2] |
| anotador modelo (verificacao) | 17 de 50 (34,0%) | 66,0% [IC95% 44,7–81,0] |
| so os casos de confianca alta (humano) | 19 de 42 (45,2%) | 54,8% |

**Como escrever:** "cerca de 57% das funcoes que o BigVul rotula como
vulneraveis nao sao o sitio da vulnerabilidade; um segundo anotador
independente chegou a 66%." O intervalo e largo porque n=50 — citar o intervalo,
nunca so o ponto.

---

## 2. O mecanismo do ruido (o achado mais forte, e o mais barato de explicar)

O BigVul marca `vul=1` em **toda** funcao tocada pelo commit que corrige a CVE.
Se essa heuristica e a fonte do ruido, o ruido tem que crescer com o numero de
funcoes que o commit toca. Cresce:

| o commit de correcao toca | funcoes amostradas | sao o sitio | ruido |
| --- | --- | --- | --- |
| 1 funcao | 7 | 5 | 28,6% |
| 2 a 4 funcoes | 15 | 10 | 33,3% |
| **5 ou mais funcoes** | 27 | 6 | **77,8%** |

Sem o cluster CVE-2016-1621 (13 das 49 linhas, mesma CVE do Android) o bucket
`5+` vai a 57,1% de ruido — cai, mas continua o dobro dos outros dois. O efeito
nao e artefato do cluster.

E isso vale para a maior parte do dataset, nao para um canto dele:

- 2957 funcoes positivas em 1027 commits — media 2,88 funcoes/commit, **maximo 237**.
- **55,9% de todas as funcoes positivas vem de apenas 103 commits** (os de 5+ funcoes).
- So 22,7% vem de commits que tocaram uma unica funcao.

**Por que isso importa para o TCC:** e a justificativa causal da curadoria. O
rotulo nao e ruidoso "em geral" — ele e ruidoso de um jeito previsivel, e o
traversal do Joern e exatamente o filtro que separa, dentro de um commit de
fan-out alto, a funcao que tem o defeito das que so vieram junto.

Reproduzir: `python3 tally_por_commit.py --positivos saida/bigvul_memoria_positivos.parquet --csv saida/amostra_validacao_revisao.csv`

**Cuidado ao escrever:** n por bucket e pequeno (7/15/27) e as linhas do mesmo
commit nao sao independentes. Reportar como evidencia do mecanismo com as
contagens a vista, nunca como estimativa pontual por estrato.

---

## 3. A anotacao e reproduzivel? (a parte do kappa, em portugues)

Um segundo anotador (Opus 5, mesma rubrica congelada, sem ver a anotacao humana)
julgou os mesmos 50 casos, 3 vezes cada.

- Os dois deram o mesmo veredito (vulneravel x nao) em **43 de 49 casos (87,8%)**.
- Descontando a parte da concordancia que sairia de graca por sorte, sobra
  **kappa = 0,744**. Na escala usual (Landis & Koch) isso e "concordancia
  substancial"; acima de 0,80 seria "quase perfeita".
- Intervalo: [0,496–0,915]. Largo por causa do n. **A leitura honesta e "de
  moderada a quase perfeita, provavelmente substancial"**, nao "0,744".
- Nos casos em que o humano marcou confianca alta, sobe para 0,804.

**Kappa em uma frase, se precisar explicar na banca:** "concordancia bruta
menos a concordancia que dois anotadores teriam por acaso, normalizada. 0 =
nada alem do acaso, 1 = concordancia total."

**O que isso compra:** o direito de dizer que os 57% nao sao a opiniao de uma
pessoa so. E o unico proposito desta parte. Nao e um resultado do TCC.

---

## 4. A sonda de memorizacao — o que ela realmente mostrou

Rodou-se de novo os 50 casos com o id da CVE, o resumo e a mensagem de commit
**removidos** do pacote. O kappa caiu de 0,744 para 0,659 — mas os intervalos se
sobrepoem quase todos e **essa comparacao nao decide nada**.

O que decide e o teste pareado dentro do proprio modelo:

| | mudancas de veredito em 50 casos |
| --- | --- |
| mesmo insumo, perguntado 3x (piso de ruido do modelo) | **0** |
| escondendo a CVE | **6** |

O modelo nunca muda de ideia sozinho no veredito binario. Escondendo a CVE,
muda 6 vezes. Logo o efeito e real: parte do julgamento do modelo vinha dos
metadados da CVE, nao do codigo.

**Duas armadilhas para nao escrever isso errado:**

1. **Nao chamar de "memorizacao".** Esconder a CVE removeu tambem **evidencia
   legitima** — o humano tinha essa evidencia ao anotar. Parte da queda e
   assimetria de insumo que nos mesmos introduzimos. O pre-registro ja declarava
   isso como limitacao 1.
2. **Nao escrever "a estimativa e robusta a esconder a CVE".** O modelo marcou
   D=17 e ruido 66,0% nas duas condicoes, mas o **conjunto** de casos difere:
   14 em comum, sairam [26, 49, 50], entraram [34, 38, 44]. A contagem bater e
   coincidencia.

**Consequencia pratica:** o numero primario do artigo e o do humano (57,1%). O
modelo entra como verificacao de reprodutibilidade da rubrica, com esta
limitacao declarada.

---

## 5. Quanto disso vai para o corpo do texto

O contribuicao do TCC e a curadoria por traversal, nao esta validacao. Ela e
uma verificacao de sanidade da premissa. Proporcao sugerida:

- **Corpo (~1 pagina):** a tabela da secao 1, a tabela da secao 2, uma frase
  sobre a concordancia com o segundo anotador (o 0,744 e o "substancial"), e
  duas frases sobre a sonda com a ressalva 1 acima.
- **Apendice / repositorio:** os quatro recortes de sensibilidade (3.1–3.4 dos
  relatorios), a matriz de confusao, o Fleiss de auto-consistencia (0,890), a
  lista de discordancias, o pre-registro e a rubrica congelada.

Custo total da validacao cega: 200 chamadas, US$ 74,23 nocionais, 0 falhas.

## 6. O que esta validacao nao diz

- Nao diz quem esta certo — mede reprodutibilidade, nao acuracia.
- n=50 com apenas 37 commits distintos; as linhas nao sao independentes.
- Ela mede o ruido do **BigVul bruto**. NAO mede a precisao do filtro de
  curadoria (confirmados x descartados) — essa e uma segunda validacao manual,
  que ainda nao existe e depende do script de traversal.
