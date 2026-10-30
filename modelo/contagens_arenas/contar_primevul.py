# Contagem de METADADOS do PrimeVul (rotulo, CWE, commit, CVE), lido do stdin (jsonl).
# Nenhum modelo, nenhuma predicao. Serve para dimensionar a Decisao G4 do adendo.
# Uso: curl -sL <url> | python3 contar_primevul.py <nome_particao> <pasta_split_do_bigvul>
import sys, json, csv, collections

nome, split_dir = sys.argv[1], sys.argv[2]
FAM = {"CWE-119", "CWE-120", "CWE-125", "CWE-787"}

# referencia: commits e CVEs das particoes treino+validacao do split congelado; e os do teste (ficam)
ref_com, ref_cve, tst_com, tst_cve = set(), set(), set(), set()
for arq in ("positivos.tsv", "negativos.tsv"):
    for r in csv.DictReader(open(f"{split_dir}/{arq}", encoding="utf-8"), delimiter="\t"):
        if r["particao"] in ("treino", "validacao"):
            ref_com.add(r["commit"]); ref_cve.add(r["cve"])
        elif r["particao"] == "teste":
            tst_com.add(r["commit"]); tst_cve.add(r["cve"])

def lista(v):
    if v is None: return []
    if isinstance(v, list): return [str(x) for x in v]
    return [str(v)]

linhas = []
primeira = True
for l in sys.stdin:
    l = l.strip()
    if not l: continue
    d = json.loads(l)
    if primeira:
        print(f"[{nome}] campos do registro: {sorted(d.keys())}")
        print(f"[{nome}] exemplo cwe={d.get('cwe')!r} cve={d.get('cve')!r} target={d.get('target')!r}")
        primeira = False
    linhas.append((int(d.get("target")), lista(d.get("cwe")), lista(d.get("cve")),
                   str(d.get("commit_id")), str(d.get("project")), str(d.get("commit_date", ""))))

tot = collections.Counter(t for t, *_ in linhas)
print(f"[{nome}] total: vulneraveis {tot[1]}, nao vulneraveis {tot[0]}")
pos_fam = [x for x in linhas if x[0] == 1 and x[1] and set(x[1]) <= FAM]
pos_mist = [x for x in linhas if x[0] == 1 and set(x[1]) & FAM and not set(x[1]) <= FAM]
com_fam = {x[3] for x in pos_fam}
neg_fam = [x for x in linhas if x[0] == 0 and x[3] in com_fam]
print(f"[{nome}] familia de memoria: vulneraveis {len(pos_fam)} (em {len(com_fam)} commits); "
      f"com CWE misturada (ficam fora) {len(pos_mist)}; nao vulneraveis dos mesmos commits {len(neg_fam)}")
print(f"[{nome}] CWEs dos vulneraveis da familia: {collections.Counter(c for x in pos_fam for c in x[1]).most_common()}")

def sai(x):
    if set(x[2]) & ref_cve: return "cve"
    if x[3] in ref_com: return "commit"
    return None
for rot, conj in (("vulneraveis", pos_fam), ("nao vulneraveis", neg_fam)):
    motivo = collections.Counter(sai(x) for x in conj)
    fica = motivo[None]
    teste_bv = sum(1 for x in conj if sai(x) is None and (x[3] in tst_com or set(x[2]) & tst_cve))
    print(f"[{nome}] {rot}: saem por CVE {motivo['cve']}, por commit {motivo['commit']}; "
          f"ficam {fica} (dos quais {teste_bv} de commits/CVEs do TESTE do BigVul)")
print(f"[{nome}] projetos dos vulneraveis da familia: {collections.Counter(x[4] for x in pos_fam).most_common(8)}")
datas = sorted(x[5] for x in pos_fam if x[5])
if datas:
    print(f"[{nome}] datas de commit dos vulneraveis da familia: {datas[0]} .. {datas[-1]}")
