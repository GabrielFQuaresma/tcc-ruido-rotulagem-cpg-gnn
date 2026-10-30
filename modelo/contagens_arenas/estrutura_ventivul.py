# Estrutura do VentiVul v3 (Figshare, ventivul.csv), lido do stdin: so METADADOS.
# Nenhum modelo, nenhuma predicao. Colunas de texto longo (codigo) mostram so o tamanho, nunca o conteudo.
# Uso: curl -sL https://ndownloader.figshare.com/files/67579809 | python3 estrutura_ventivul.py
import sys, collections
import pandas as pd

df = pd.read_csv(sys.stdin)
print(f"linhas: {len(df)} | colunas: {list(df.columns)}")
for c in df.columns:
    s = df[c]
    comp = s.astype(str).str.len()
    if comp.max() > 120:
        print(f"- {c}: texto longo (tamanho mediano {int(comp.median())}); conteudo nao impresso")
    else:
        print(f"- {c}: {s.nunique(dropna=False)} valores distintos; mais comuns {s.value_counts(dropna=False).head(6).to_dict()}")
