#!/bin/bash
# Treina os 13 bracos (PLANO_TREINO.md §5): GGNN e depois Fase II de cada um, em sequencia.
# Cada passo e retomavel; se cair, rodar este script de novo continua de onde parou.
# Ordem: desenho principal primeiro (M_cur, os 5 controles, M_raw), depois o par balanceado.
AQUI="$(cd "$(dirname "$0")" && pwd)"
for b in M_cur M_ctrl_g2026 M_ctrl_g2027 M_ctrl_g2028 M_ctrl_g2029 M_ctrl_g2030 M_raw \
         M_cur_bal M_ctrl_g2026_bal M_ctrl_g2027_bal M_ctrl_g2028_bal M_ctrl_g2029_bal M_ctrl_g2030_bal; do
  bash "$AQUI/rodar.sh" treinar_ggnn.py --braco "$b" || exit 1
  bash "$AQUI/rodar.sh" treinar_fase2.py --braco "$b" || exit 1
done
echo "=== TODOS OS 13 BRACOS TERMINADOS $(date '+%F %T')"
