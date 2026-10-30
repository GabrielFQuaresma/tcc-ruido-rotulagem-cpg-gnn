#!/bin/bash
# Refaz a Fase II dos 13 bracos GRAVANDO OS MODELOS, em ~/curadoria/modelo/fase2_v2/
# (PREREGISTRO_PRINCIPAL.md §6, passo 2). Mesmas sementes, mesma GGNN (le ggnn/<braco>/vetores.npz);
# a unica mudanca e gravar modelo_<s>.pt. Retomavel: rodar de novo continua de onde parou.
# Nao calcula metrica no teste. A saida de cada braco vai so para o log
# (~/curadoria/modelo/logs/); aqui imprime apenas o fim de cada braco.
AQUI="$(cd "$(dirname "$0")" && pwd)"
for b in M_cur M_ctrl_g2026 M_ctrl_g2027 M_ctrl_g2028 M_ctrl_g2029 M_ctrl_g2030 M_raw \
         M_cur_bal M_ctrl_g2026_bal M_ctrl_g2027_bal M_ctrl_g2028_bal M_ctrl_g2029_bal M_ctrl_g2030_bal; do
  bash "$AQUI/rodar.sh" treinar_fase2.py --braco "$b" --pasta fase2_v2 > /dev/null || { echo "FALHOU $b"; exit 1; }
  echo "$(date '+%F %T') pronto $b"
done
echo "=== FASE II V2: 13 BRACOS TERMINADOS $(date '+%F %T')"
