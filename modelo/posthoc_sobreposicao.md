# POS HOC — o M_cur acusa as mesmas funcoes que a regra?

> Analise pedida pelo autor em 13/10/2026, **depois** de abrir o teste. Nao pre-registrada; nao muda nenhum veredito. Medianas das 30 repeticoes; teste do BigVul, 5730 funcoes.

A regra (traversal v3, confirmado = acusa) acusa **1213** funcoes do teste (21.2%), das quais 230 sao vulneraveis pelo rotulo do BigVul. Se um modelo acusasse ao acaso, 21.2% das acusacoes dele cairiam nas da regra.

## Sobreposicao geral

| braco | funcoes acusadas | das acusacoes, % que a regra tambem confirma | das confirmacoes da regra, % que o braco acusa | acertos dentro da regra | acertos FORA da regra |
| --- | --- | --- | --- | --- | --- |
| M_raw | 1489 | 37.1% | 44.9% | 143 | 102 |
| M_cur | 573 | 54.5% | 25.3% | 90 | 45 |
| M_ctrl_g2026 | 1501 | 34.1% | 41.1% | 119 | 90 |
| M_ctrl_g2027 | 817 | 39.5% | 27.6% | 97 | 55 |
| M_ctrl_g2028 | 1487 | 35.0% | 44.3% | 140 | 101 |
| M_ctrl_g2029 | 1339 | 35.6% | 39.4% | 128 | 92 |
| M_ctrl_g2030 | 673 | 39.2% | 21.3% | 85 | 56 |

## Das acusacoes de cada braco, % que a regra tambem confirma, por faixa de tamanho

Dentro de uma faixa o tamanho e parecido; se o M_cur coincidir mais com a regra que os controles mesmo assim, a coincidencia nao e so tamanho.

| braco | ate 46 | 47-131 | 132-339 | 340+ |
| --- | --- | --- | --- | --- |
| M_raw | 7.6% | 22.7% | 40.0% | 60.6% |
| M_cur | 0.0% | 36.3% | 48.7% | 67.1% |
| M_ctrl_g2026 | 6.6% | 20.7% | 39.6% | 60.8% |
| M_ctrl_g2027 | 5.4% | 20.7% | 43.3% | 63.5% |
| M_ctrl_g2028 | 4.4% | 21.1% | 41.1% | 60.4% |
| M_ctrl_g2029 | 7.0% | 20.2% | 40.0% | 60.4% |
| M_ctrl_g2030 | 3.9% | 19.0% | 41.4% | 62.1% |

| regra: % das funcoes da faixa que ela confirma | 4.6% | 18.3% | 37.6% | 56.7% |
