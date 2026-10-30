#!/bin/bash
# Le as 3 particoes do espelho v0.1 em fluxo (prefixando a particao) e conta. Nada fica no disco.
S="$(cd "$(dirname "$0")" && pwd)"
BV=/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul
BASE=https://huggingface.co/datasets/starsofchance/PrimeVul/resolve/main
for p in test valid train; do
  curl -sL --fail "$BASE/primevul_$p.jsonl" | sed "s/^/$p\t/"
done | python3 "$S/contar_primevul_estrito.py" "$BV"
