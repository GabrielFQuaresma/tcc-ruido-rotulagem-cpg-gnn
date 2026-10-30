#!/bin/bash
# Roda um passo do ReVeal em PRIMEIRO PLANO, com log em ~/curadoria/modelo/logs/.
#   bash rodar.sh vetorizar.py
#   bash rodar.sh treinar_ggnn.py --braco M_cur
# Primeiro plano de proposito: `setsid nohup` nao sobrevive ao desligamento da VM do WSL
# Todo passo e idempotente / retomavel; se cair, rodar de novo.
set -o pipefail
AQUI="$(cd "$(dirname "$0")" && pwd)"
mkdir -p ~/curadoria/modelo/logs
nome="$(basename "$1" .py)"
shift_args="${*:2}"
log=~/curadoria/modelo/logs/"${nome}${shift_args:+_${shift_args// /_}}".log
echo "=== $(date '+%F %T') $*" >> "$log"
# o DGL repete um aviso de API obsoleta do PyTorch a cada operacao (lazyInitCUDA); filtrado
python3 -u "$AQUI/$1" "${@:2}" 2>&1 | grep --line-buffered -v "lazyInitCUDA" | tee -a "$log"
