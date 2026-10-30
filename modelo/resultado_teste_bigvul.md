# Resultado no teste do BigVul (dentro da distribuicao)

> Gerado em 13/10/2026 10:21 por `analisar_resultados.py --particao teste --abrir-teste`, seguindo o PREREGISTRO_PRINCIPAL.md e o PREREGISTRO_TAMANHO.md (hashes conferidos). No BigVul a metrica mede concordancia com o rotulo do BigVul (§4 do pre-registro).

## Conferencias

- os dois pre-registros e os 4 arquivos de regra da traversal v3 conferem
- (b) contagem por faixa (positivos, negativos) BATE com o medido em 12/10: [(37, 2096), (129, 1732), (135, 968), (188, 445)]
- (c) veredito recalculado de 2031 positivos de treino+validacao: 0 diferem de conjuntos_v3/M_raw.tsv; confirmados de treino = 523 (M_cur = 523)
- (d) evidencias das negativas do teste com a estrutura que o veredito le: 5241 de 5241 (so estrutura, sem veredito)

Particao: teste — 5730 funcoes, 489 positivas, 5241 negativas.

## Comparacao que decide (§3): F1, mediana das 30 repeticoes

| desenho | M_cur | faixa dos 5 controles | posicao |
| --- | --- | --- | --- |
| principal | 0.262 | 0.206 a 0.242 | **acima** |
| par balanceado | 0.287 | 0.255 a 0.272 | **acima** |

Leitura (§3): acima ou abaixo por acaso 1 vez em 6 cada; dentro 4 vezes em 6. Desenho principal decide; par balanceado e sensibilidade (§7).

## Checagem de tamanho (PREREGISTRO_TAMANHO §6; E1-E4)

| desenho | V1 (inclinacao do FPR) | V2 (ganho so nas grandes) | veredito |
| --- | --- | --- | --- |
| principal | nao dispara (M_cur 0.362; controles 0.253 a 0.479) | nao dispara (acima em: nenhuma) | **sem evidencia de vies de tamanho** |
| par balanceado | DISPARA (M_cur 0.775; controles 0.648 a 0.762) | nao dispara (acima em: nenhuma) | **evidencia de vies de tamanho** |

Qualifica a conclusao so o veredito do desenho principal (E2). Ele vai lado a lado com o resultado do §3, nunca o rebaixa a inconclusivo (E1).

## Contagem por faixa de tamanho

| faixa (nos) | positivos | negativos |
| --- | --- | --- |
| ate 46 | 37 | 2096 |
| 47-131 | 129 | 1732 |
| 132-339 | 135 | 968 |
| 340+ | 188 | 445 |

## Todas as metricas, por braco (mediana [Q1–Q3] das 30 repeticoes; descritivas)

| braco | F1 | recall | precisao | PR-AUC | MCC | FPR |
| --- | --- | --- | --- | --- | --- | --- |
| M_raw | 0.245 [0.232–0.262] | 0.499 [0.432–0.567] | 0.171 [0.152–0.179] | 0.217 [0.202–0.243] | 0.166 [0.152–0.186] | 0.240 [0.180–0.282] |
| M_cur | 0.262 [0.257–0.268] | 0.279 [0.260–0.303] | 0.249 [0.233–0.258] | 0.176 [0.166–0.192] | 0.189 [0.184–0.199] | 0.082 [0.071–0.089] |
| M_ctrl_g2026 | 0.206 [0.198–0.219] | 0.429 [0.348–0.492] | 0.140 [0.135–0.146] | 0.153 [0.144–0.174] | 0.110 [0.102–0.128] | 0.246 [0.182–0.299] |
| M_ctrl_g2027 | 0.217 [0.205–0.229] | 0.308 [0.211–0.465] | 0.175 [0.146–0.196] | 0.164 [0.145–0.187] | 0.132 [0.122–0.148] | 0.127 [0.071–0.249] |
| M_ctrl_g2028 | 0.242 [0.232–0.254] | 0.498 [0.458–0.593] | 0.161 [0.150–0.179] | 0.182 [0.166–0.206] | 0.169 [0.150–0.180] | 0.238 [0.201–0.328] |
| M_ctrl_g2029 | 0.234 [0.221–0.239] | 0.452 [0.376–0.510] | 0.159 [0.150–0.169] | 0.189 [0.166–0.206] | 0.149 [0.137–0.156] | 0.212 [0.176–0.276] |
| M_ctrl_g2030 | 0.242 [0.232–0.253] | 0.288 [0.238–0.324] | 0.214 [0.201–0.234] | 0.172 [0.164–0.182] | 0.167 [0.157–0.177] | 0.100 [0.073–0.113] |
| M_cur_bal | 0.287 [0.277–0.293] | 0.570 [0.556–0.603] | 0.191 [0.182–0.198] | 0.260 [0.252–0.272] | 0.223 [0.214–0.231] | 0.230 [0.207–0.249] |
| M_ctrl_g2026_bal | 0.259 [0.249–0.267] | 0.599 [0.569–0.629] | 0.166 [0.159–0.174] | 0.265 [0.248–0.271] | 0.194 [0.184–0.201] | 0.277 [0.256–0.311] |
| M_ctrl_g2027_bal | 0.255 [0.249–0.267] | 0.548 [0.516–0.587] | 0.166 [0.159–0.178] | 0.247 [0.240–0.263] | 0.182 [0.175–0.197] | 0.249 [0.230–0.276] |
| M_ctrl_g2028_bal | 0.255 [0.250–0.259] | 0.598 [0.546–0.634] | 0.163 [0.157–0.167] | 0.241 [0.228–0.260] | 0.186 [0.178–0.193] | 0.285 [0.258–0.305] |
| M_ctrl_g2029_bal | 0.272 [0.266–0.276] | 0.566 [0.548–0.611] | 0.177 [0.173–0.182] | 0.267 [0.255–0.274] | 0.205 [0.197–0.211] | 0.244 [0.233–0.273] |
| M_ctrl_g2030_bal | 0.263 [0.254–0.275] | 0.615 [0.576–0.662] | 0.168 [0.157–0.179] | 0.261 [0.251–0.271] | 0.201 [0.189–0.211] | 0.277 [0.253–0.330] |

## F1 por faixa de tamanho (mediana das 30)

| braco | ate 46 | 47-131 | 132-339 | 340+ |
| --- | --- | --- | --- | --- |
| M_raw | 0.035 | 0.128 | 0.224 | 0.462 |
| M_cur | 0.000 | 0.065 | 0.186 | 0.437 |
| M_ctrl_g2026 | 0.038 | 0.117 | 0.207 | 0.409 |
| M_ctrl_g2027 | 0.032 | 0.087 | 0.195 | 0.411 |
| M_ctrl_g2028 | 0.065 | 0.116 | 0.238 | 0.463 |
| M_ctrl_g2029 | 0.018 | 0.117 | 0.216 | 0.449 |
| M_ctrl_g2030 | 0.043 | 0.097 | 0.189 | 0.446 |
| M_cur_bal | 0.000 | 0.132 | 0.233 | 0.470 |
| M_ctrl_g2026_bal | 0.030 | 0.136 | 0.228 | 0.469 |
| M_ctrl_g2027_bal | 0.029 | 0.118 | 0.226 | 0.465 |
| M_ctrl_g2028_bal | 0.030 | 0.131 | 0.228 | 0.467 |
| M_ctrl_g2029_bal | 0.019 | 0.134 | 0.233 | 0.485 |
| M_ctrl_g2030_bal | 0.018 | 0.125 | 0.228 | 0.468 |

## recall (descritivo) por faixa de tamanho (mediana das 30)

| braco | ate 46 | 47-131 | 132-339 | 340+ |
| --- | --- | --- | --- | --- |
| M_raw | 0.081 | 0.283 | 0.526 | 0.731 |
| M_cur | 0.000 | 0.054 | 0.226 | 0.516 |
| M_ctrl_g2026 | 0.108 | 0.283 | 0.474 | 0.529 |
| M_ctrl_g2027 | 0.054 | 0.136 | 0.315 | 0.468 |
| M_ctrl_g2028 | 0.216 | 0.264 | 0.574 | 0.689 |
| M_ctrl_g2029 | 0.054 | 0.264 | 0.470 | 0.620 |
| M_ctrl_g2030 | 0.054 | 0.101 | 0.237 | 0.495 |
| M_cur_bal | 0.000 | 0.240 | 0.648 | 0.878 |
| M_ctrl_g2026_bal | 0.054 | 0.353 | 0.637 | 0.843 |
| M_ctrl_g2027_bal | 0.054 | 0.264 | 0.600 | 0.809 |
| M_ctrl_g2028_bal | 0.068 | 0.349 | 0.652 | 0.819 |
| M_ctrl_g2029_bal | 0.027 | 0.298 | 0.585 | 0.827 |
| M_ctrl_g2030_bal | 0.027 | 0.333 | 0.689 | 0.896 |

## taxa de falso positivo por faixa de tamanho (mediana das 30)

| braco | ate 46 | 47-131 | 132-339 | 340+ |
| --- | --- | --- | --- | --- |
| M_raw | 0.062 | 0.241 | 0.432 | 0.610 |
| M_cur | 0.002 | 0.044 | 0.178 | 0.365 |
| M_ctrl_g2026 | 0.083 | 0.265 | 0.436 | 0.487 |
| M_ctrl_g2027 | 0.036 | 0.119 | 0.229 | 0.378 |
| M_ctrl_g2028 | 0.081 | 0.239 | 0.462 | 0.536 |
| M_ctrl_g2029 | 0.057 | 0.228 | 0.398 | 0.509 |
| M_ctrl_g2030 | 0.035 | 0.081 | 0.181 | 0.292 |
| M_cur_bal | 0.010 | 0.178 | 0.542 | 0.785 |
| M_ctrl_g2026_bal | 0.043 | 0.283 | 0.547 | 0.747 |
| M_ctrl_g2027_bal | 0.042 | 0.251 | 0.505 | 0.702 |
| M_ctrl_g2028_bal | 0.047 | 0.290 | 0.562 | 0.738 |
| M_ctrl_g2029_bal | 0.040 | 0.248 | 0.488 | 0.692 |
| M_ctrl_g2030_bal | 0.030 | 0.271 | 0.584 | 0.788 |

## Traversal pura (§7; descritiva)

| classificador | F1 | recall | precisao | FPR |
| --- | --- | --- | --- | --- |
| traversal v3 (confirmado = acusa) | 0.270 | 0.470 | 0.190 | 0.188 |
| M_cur (mediana das 30) | 0.262 | 0.279 | 0.249 | 0.082 |

