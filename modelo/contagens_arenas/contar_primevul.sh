#!/bin/bash
# Le cada particao do espelho do PrimeVul (v0.1) em fluxo, sem gravar em disco, e conta metadados.
S="$(cd "$(dirname "$0")" && pwd)"
SPLIT=/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/traversal/split
BASE=https://huggingface.co/datasets/starsofchance/PrimeVul/resolve/main
for p in ${1:-test valid train}; do
  curl -sL --fail "$BASE/primevul_$p.jsonl" | python3 "$S/contar_primevul.py" "$p" "$SPLIT" || echo "[$p] falhou"
done
