# VentiVul v3 (Figshare, ventivul.csv), lido do stdin: quem sao os negativos e quanto da a familia de memoria.
# So METADADOS (rotulo, par, CVE, CWE, arquivo); o codigo da funcao so entra num hash, nunca e impresso.
# Nenhum modelo, nenhuma predicao.
# Uso: bash estrutura_ventivul.sh contar_ventivul.py
import sys, collections, hashlib, re
from urllib.parse import urlparse
import pandas as pd

FAM = {"CWE-119", "CWE-120", "CWE-125", "CWE-787"}
df = pd.read_csv(sys.stdin)
par = df["pair_id"].astype(str) != "none"
v = df["Vulnerable"]

print("== quem e quem")
print(f"com par (vulneravel ou sua versao consertada): {par.sum()} | rotulo 1: {(par & (v == 1)).sum()}, rotulo 0: {(par & (v == 0)).sum()}")
print(f"sem par ('none', nao relacionadas ao conserto): {(~par).sum()} | rotulo 1: {(~par & (v == 1)).sum()}, rotulo 0: {(~par & (v == 0)).sum()}")
print(f"cve_id preenchido: com par {df.loc[par, 'cve_id'].notna().sum()} de {par.sum()}; sem par {df.loc[~par, 'cve_id'].notna().sum()} de {(~par).sum()}")
print(f"link preenchido: com par {df.loc[par, 'link'].notna().sum()}; sem par {df.loc[~par, 'link'].notna().sum()}")
print(f"dominios do link: {collections.Counter(urlparse(str(x)).netloc for x in df['link'].dropna()).most_common(5)}")

# a versao consertada fica no mesmo arquivo (nome) que a vulneravel do mesmo par?
chave = df.loc[par].assign(pid=lambda d: d["project"] + ":" + d["pair_id"].astype(str))
mesmo = chave.groupby("pid")["file_name_ori"].nunique(dropna=False)
print(f"pares: {mesmo.size}; com vulneravel e consertada no mesmo nome de arquivo: {(mesmo == 1).sum()}")

print("== CWE (so as vulneraveis)")
cw = df.loc[v == 1, "cwe_id"].astype(str)
print(f"valores com mais de uma CWE na celula: {sum(bool(re.search(r'[,;|\\[]', x)) for x in cw)}")
print(f"vulneraveis por CWE: {collections.Counter(cw).most_common(12)}")

print("== arquivos")
# as funcoes com par guardam o caminho original (root/...); as nao relacionadas, um nome codificado pela CVE:
# cve202523142.c (CVE-2025-23142), cve202523142_1.c (2o arquivo dela), cve202523156_202523157.c (duas CVEs)
print(f"funcoes com par sem nome de arquivo: {df.loc[par, 'file_name_ori'].isna().sum()}")
print(f"nomes: com par {df.loc[par, 'file_name_ori'].nunique()} | sem par {df.loc[~par, 'file_name_ori'].nunique()} | em comum {len(set(df.loc[par, 'file_name_ori'].dropna()) & set(df.loc[~par, 'file_name_ori']))}")

def cves_do_nome(nome):
    m = re.fullmatch(r"cve(\d{4})(\d+)((?:_\d+)*)", str(nome).rsplit(".", 1)[0])
    if not m:
        return None
    out = [f"CVE-{m.group(1)}-{m.group(2)}"]
    for t in m.group(3).split("_")[1:]:
        if len(t) >= 8 and t.startswith("20"):  # outra CVE; senao e o indice do arquivo (_1, _2...)
            out.append(f"CVE-{t[:4]}-{t[4:]}")
    return out

df["cves_arq"] = None
df.loc[~par, "cves_arq"] = df.loc[~par, "file_name_ori"].map(cves_do_nome)
cves_par = set(df.loc[par, "cve_id"])
sem_parse = df.loc[~par & df["cves_arq"].isna(), "file_name_ori"].unique()
ligadas = {c for l in df.loc[~par, "cves_arq"].dropna() for c in l}
print(f"nomes sem par que nao seguem o padrao: {len(sem_parse)} {list(sem_parse)[:5]}")
print(f"CVEs lidas dos nomes: {len(ligadas)} | que nao existem nos pares: {len(ligadas - cves_par)} | CVEs dos pares sem nenhuma nao relacionada: {len(cves_par - ligadas)}")
print(f"arquivos ligados a mais de uma CVE: {sum(1 for l in df.loc[~par, 'cves_arq'].dropna().map(tuple).unique() if len(l) > 1)}")

print("== familia de memoria (G4 aplicada ao VentiVul: rotulo 0 ligado a uma CVE com positivo da familia)")
pos = df[(v == 1) & df["cwe_id"].isin(FAM)]
cves_fam = set(pos["cve_id"])
cons = df[par & (v == 0) & df["cve_id"].isin(cves_fam)]
nrel = df[~par & df["cves_arq"].map(lambda l: bool(l) and bool(set(l) & cves_fam))]
print(f"positivos: {len(pos)} em {len(cves_fam)} CVEs | por CWE {pos['cwe_id'].value_counts().to_dict()} | por projeto {pos['project'].value_counts().to_dict()}")
print(f"negativos: {len(cons) + len(nrel)} = consertadas {len(cons)} + nao relacionadas {len(nrel)}")
print(f"  das nao relacionadas, em arquivo compartilhado com CVE de fora da familia: "
      f"{df.loc[nrel.index, 'cves_arq'].map(lambda l: bool(set(l) - cves_fam)).sum()}")
print(f"proporcao de positivos: {len(pos) / (len(pos) + len(cons) + len(nrel)):.2%}")
print(f"ficaram fora por serem filhas na hierarquia (CWE-121/122): {df.loc[v == 1, 'cwe_id'].isin(['CWE-121', 'CWE-122']).sum()}; "
      f"sem CWE informada (NVD-CWE-noinfo/Other): {df.loc[v == 1, 'cwe_id'].isin(['NVD-CWE-noinfo', 'NVD-CWE-Other']).sum()}")

print("== corpos repetidos dentro do VentiVul (espacos colapsados; so contagem)")
h = df["Function"].astype(str).map(lambda s: hashlib.md5(" ".join(s.split()).encode()).hexdigest())
g = df.assign(h=h).groupby("h")["Vulnerable"].agg(["size", "nunique"])
print(f"corpos distintos: {len(g)} de {len(df)} | repetidos: {(g['size'] > 1).sum()} corpos | com rotulos conflitantes: {(g['nunique'] > 1).sum()}")
