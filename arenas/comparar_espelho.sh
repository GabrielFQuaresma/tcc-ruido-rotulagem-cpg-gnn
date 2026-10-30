#!/bin/bash
# Os arquivos OFICIAIS do PrimeVul v0.1 (Google Drive) sao identicos aos do espelho do Hugging Face
# usado nas contagens do adendo (§1)? Compara SHA-256, arquivo a arquivo. So hash; nada e lido.
BASE=https://huggingface.co/datasets/starsofchance/PrimeVul/resolve/main
for p in test valid train; do
  esp=$(curl -sL --fail "$BASE/primevul_$p.jsonl" | sha256sum | cut -d' ' -f1)
  ofi=$(sha256sum "$HOME/curadoria/arenas/primevul/primevul_$p.jsonl" | cut -d' ' -f1)
  [ "$esp" = "$ofi" ] && r="IDENTICO" || r="DIFERENTE"
  echo "$p: oficial $ofi | espelho $esp | $r"
done
