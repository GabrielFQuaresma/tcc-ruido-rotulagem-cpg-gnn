#!/bin/bash
# Teste da versao ORIGINAL do PrimeVul (espelho Code-TREAT, parquet): baixa em /tmp, converte para
# jsonl em fluxo, conta os mesmos metadados e apaga. Nenhum modelo.
S="$(cd "$(dirname "$0")" && pwd)"
SPLIT=/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/traversal/split
F=/tmp/primevul_original_test.parquet
curl -sL --fail -o "$F" https://huggingface.co/datasets/Code-TREAT/PrimeVul_original/resolve/main/test.parquet || { echo falhou download; exit 1; }
python3 - "$F" <<'EOF' | python3 "$S/contar_primevul.py" original_test "$SPLIT"
import sys, json, pandas as pd
df = pd.read_parquet(sys.argv[1])
print(json.dumps({"_colunas": list(df.columns), "_n": len(df)}), file=sys.stderr)
for rec in df.to_dict(orient="records"):
    for k, v in list(rec.items()):
        if hasattr(v, "tolist"): rec[k] = v.tolist()
    print(json.dumps(rec, default=str))
EOF
rm -f "$F"
