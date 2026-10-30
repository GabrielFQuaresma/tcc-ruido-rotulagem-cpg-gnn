# Etapa 4b — a regra conferida contra os rótulos do dev

Fechada em **09/08/2026**, depois da 4a e sem alterar nada do que a 4a decidiu.

**A regra não foi mexida.** É o que permite ao artigo escrever *"calibrada por tamanho e
**verificada** contra um dev set independente"*. Se tivesse sido mexida, teria de escrever
*"refinada"*, e a volta para a 4a viraria linha nas Ameaças à Validade. O que não é defensável é
fazer a segunda e escrever a primeira.

## A anotação

`preparar_pacotes.py --outdir dev --sample-size 30 --seed 7 --condicao cve_visivel`, depois
`anotar_modelo.ps1 -Repeticoes 1 -Raiz validacao_cega/dev`.

- **30 chamadas, 0 falhas, 8m30s, US$ 8,61 nocionais** (a estimativa era ~US$ 11).
- `consolidar_brutos.py --raiz dev`: 30 linhas válidas, **0 parse sujo**.
- **Rubrica idêntica à dos 50** — sha256 `81f9d2495741537a27a189dedfd1d6da767afc8171608b3fbf425d8809567316`.
  Se fosse outra, a anotação do dev não seria comparável com nada. `conferir_pacotes_dev.py`
  falha em vez de continuar se divergir.
- R=1, então **não há auto-consistência medível aqui** — compatível com o pré-registro, que exige
  R≥2 só na condição primária dos 50.
- Tudo em `validacao_cega/dev/`, fora do diretório dos 50. Nenhum arquivo dos 50 foi tocado.

O join `caso_NN ↔ NNNN__projeto` está em `dev/mapa_caso_item.csv`, conferido por **multiconjunto**
`(commit, cve)` — casar por par simples não bastaria, porque o cluster CVE-2016-1621 tem 5 itens
com o mesmo par.

`etapa_4b.py` foi escrito **antes de os rótulos existirem**, com as duas leituras possíveis já
fixadas no docstring. Não dava para escolher a medida depois de ver os números.

## O número

n = 27 comparáveis: 30 do dev, menos 2 sem evidência (`0122__savannah` e `1443__curl`, falha de
download — das 45 perdas já declaradas), menos 1 indeterminado (`0774__tcpdump`, corpo não
parseado). Nenhum rótulo `?`.

| | A | B | C | D | n |
| --- | --- | --- | --- | --- | --- |
| confirmado | 1 | 1 | 2 | **9** | 13 |
| descartado | 1 | 6 | 3 | 4 | 14 |

- taxa base do dev (D/comparáveis): **13/27 = 48,1%**
- **precisão do filtro (D/confirmados): 9/13 = 69,2%**
- entre os descartados, eram D: 4/14 = 28,6%

**Sem os 6 irmãos de commit do teste** (n=21): taxa base 61,9%, precisão **9/11 = 81,8%**.

As duas leituras contam a mesma história — **+21,1 e +19,9 pontos** sobre a respectiva taxa base.
Essa concordância era a condição declarada na 4a para a leitura valer. O critério do plano
("precisão plausivelmente acima da taxa base → segue para a Etapa 5") está satisfeito nas duas.

## Quatro coisas que este número **não** é

1. **Não é resultado.** Não entra em tabela nem no resumo. A precisão do filtro é uma coisa só: a
   medida nos 50, depois do congelamento. Este é guarda-corpo.
2. **Não tem precisão de estimativa.** 13 confirmados. O intervalo em torno de 9/13 é largo o
   bastante para engolir vários pontos percentuais, e mexer no limiar para ganhar 3 pontos aqui
   seria perseguir ruído.
3. **A taxa base do dev não é a taxa base do BigVul.** 48,1% aqui contra os ~34% que a taxa de
   ruído do modelo nos 50 (66,0%) faria esperar. Esta amostra de 30 é menos ruidosa que aquela de
   50 — o que interessa é o **delta** (+21 pontos), não os níveis absolutos.
4. **Os rótulos vêm do modelo, não do autor.** Guarda-corpo grosso.

## Duas leituras que valem a pena registrar

**O mecanismo do fan-out apareceu.** Dos 5 itens do cluster CVE-2016-1621 (o commit de fan-out
alto que já domina os 50), **4 foram descartados** e os 4 estão rotulados A/B — funções que só
vieram junto no commit. O único confirmado do cluster (`2824__Android`) está rotulado B, e é um
falso positivo do filtro. É exatamente o mecanismo que a curadoria alega: separar, dentro de um
commit de fan-out alto, a função com o defeito das que vieram de carona. n minúsculo — vale como
ilustração do mecanismo, não como medida.

**Os 4 D descartados são perda de recall, e ela é de graça por desenho** (`0173__qemu`,
`0650__krb5`, `0856__tcpdump`, `1907__Chrome`). O silêncio não inverte rótulo: a função só deixa
de entrar no `M_cur`. A traversal pode errar por omissão à vontade; o único limite é o `M_cur`
não ficar pequeno demais, e não ficou.

## O que vem

**Etapa 5**, e a ordem é o que dá valor ao número: congelar `curadoria_v2.sc`, as duas tabelas de
`dados/` e a `regra_veredito.toml` com SHA-256 de cada um, **e só então** rodar nos 50 e reportar
precisão contra os rótulos humanos (D = deveria confirmar; A/B/C = deveria descartar).

Até lá, nenhum arquivo dos 50 pode ser lido. Continua valendo.
