# POS HOC / QUALITATIVO — os anotados que cairam no teste

> 13/10/2026, depois de abrir o teste. Segundo uso dos 50 casos anotados (o primeiro foi a Etapa 5), previsto no PREREGISTRO_PRINCIPAL.md §9 como evidencia qualitativa. 9 casos, sem metrica. Cada celula de braco = em quantas das 30 repeticoes ele ACUSOU a funcao.

Categoria (anotacao do autor): **D** = e o sitio da vulnerabilidade; A, B, C = rotulo indevido.

| caso | item | CVE | categoria | nos (faixa) | regra | M_cur | M_raw | M_ctrl_g2026 | M_ctrl_g2027 | M_ctrl_g2028 | M_ctrl_g2029 | M_ctrl_g2030 | M_cur_bal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 8 | 2467__Android | CVE-2016-0835 | **D** | 443 (340+) | descartado | 3 | 5 | 5 | 9 | 26 | 4 | 0 | 26 |
| 14 | 1226__miniupnp | CVE-2016-3178 | **D** | 1104 (340+) | confirmado | 30 | 28 | 30 | 29 | 30 | 30 | 3 | 30 |
| 46 | 0322__linux | CVE-2013-1860 | **D** | 154 (132-339) | confirmado | 0 | 19 | 0 | 1 | 0 | 1 | 0 | 2 |
| 47 | 0046__gstreamer | CVE-2009-0397 | **D** | 955 (340+) | confirmado | 13 | 30 | 28 | 15 | 29 | 30 | 0 | 30 |
| 9 | 1996__Chrome | CVE-2012-5157 | **B** | 354 (340+) | descartado | 0 | 4 | 30 | 0 | 16 | 27 | 0 | 5 |
| 10 | 1892__Chrome | CVE-2013-2920 | **C** | 94 (47-131) | confirmado | 4 | 16 | 2 | 7 | 28 | 0 | 10 | 8 |
| 31 | 1722__ImageMagick | CVE-2016-7526 | **C** | 1844 (340+) | confirmado | 30 | 30 | 24 | 30 | 29 | 30 | 25 | 30 |
| 45 | 1094__ImageMagick | CVE-2016-10066 | **C** | 3283 (340+) | confirmado | 3 | 30 | 21 | 30 | 25 | 30 | 29 | 29 |
| 48 | 1785__Chrome | CVE-2011-2806 | **A** | 115 (47-131) | descartado | 0 | 1 | 1 | 6 | 0 | 1 | 0 | 0 |

## Resumo descritivo (media de repeticoes que acusam, por grupo)

| grupo | n | M_cur | M_raw | M_ctrl_g2026 | M_ctrl_g2027 | M_ctrl_g2028 | M_ctrl_g2029 | M_ctrl_g2030 | M_cur_bal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D (sitio) | 4 | 11.5 | 20.5 | 15.8 | 13.5 | 21.2 | 16.2 | 0.8 | 22.0 |
| A/B/C (rotulo indevido) | 5 | 7.4 | 16.2 | 15.6 | 14.6 | 19.6 | 17.6 | 12.8 | 14.4 |
