#!/bin/bash
# Compara o teste ORIGINAL (artigo) com o teste v0.1 do PrimeVul: so metadados. Nenhum modelo.
F=/tmp/pv_orig.parquet
G=/tmp/pv_v01_test.jsonl
curl -sL --fail -o "$F" https://huggingface.co/datasets/Code-TREAT/PrimeVul_original/resolve/main/test.parquet || exit 1
curl -sL --fail -o "$G" https://huggingface.co/datasets/starsofchance/PrimeVul/resolve/main/primevul_test.jsonl || exit 1
python3 - "$F" "$G" <<'EOF'
import sys, json, collections, pandas as pd
o = pd.read_parquet(sys.argv[1])
print("original: n", len(o), "| colunas", list(o.columns))
cw = o["cwe"].astype(str)
print("original: cwe vazia ou sem valor nos vulneraveis:", int((o["cwe"].isna() | cw.isin(["", "None", "[]", "nan"]))[o.target == 1].sum()), "de", int((o.target == 1).sum()))
print("original: valores de cwe mais comuns (vulneraveis):", collections.Counter(cw[o.target == 1]).most_common(8))
print("original: campo dataset (vulneraveis):", collections.Counter(o["dataset"].astype(str)[o.target == 1]).most_common())
v = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
vc_pos = {d["commit_id"] for d in v if d["target"] == 1}
oc_pos = set(o.commit_id[o.target == 1].astype(str))
print("commits com vulneravel: original", len(oc_pos), "| v0.1", len(vc_pos), "| em comum", len(oc_pos & vc_pos))
# mesma funcao? compara o hash do corpo como cada versao grava
vh = {str(d.get("func_hash")) for d in v}
oh = set(o["hash"].astype(str))
print("hash de funcao em comum (se for o mesmo algoritmo):", len(vh & oh), "de", len(oh), "(original) /", len(vh), "(v0.1)")
EOF
rm -f "$F" "$G"
