# Contagem para dimensionar a sonda CWE-416 (so metadados do BigVul; nenhum modelo, nenhuma predicao).
import csv, collections, sys
BASE = sys.argv[1]
idx = BASE + "/saida_final/indice_bigvul.csv"
pos_split = BASE + "/traversal/split/positivos.tsv"

rows = list(csv.DictReader(open(idx, encoding="utf-8", newline="")))
uaf = [r for r in rows if r["CWE ID"] == "CWE-416"]
pos = [r for r in uaf if r["vul"] == "1"]
neg = [r for r in uaf if r["vul"] == "0"]
print("linhas CWE-416:", len(uaf), "| vul=1:", len(pos), "| vul=0:", len(neg))
print("commits CWE-416:", len({r["commit_id"] for r in uaf}), "| CVEs:", len({r["CVE ID"] for r in uaf}))
print("commits com vul=1:", len({r["commit_id"] for r in pos}), "| CVEs com vul=1:", len({r["CVE ID"] for r in pos}))
print("por linguagem (vul=1):", collections.Counter(r["lang"] for r in pos).most_common())
print("projetos (vul=1, top 10):", collections.Counter(r["project"] for r in pos).most_common(10))

# sobreposicao com o recorte de erros de memoria (2957 positivos; commits e CVEs com a particao)
com_rec, cve_rec = {}, {}
for r in csv.DictReader(open(pos_split, encoding="utf-8"), delimiter="\t"):
    com_rec[r["commit"]] = r["particao"]
    cve_rec[r["cve"]] = r["particao"]
print("recorte: commits", len(com_rec), "| CVEs", len(cve_rec))
for nome, conj in (("vul=1", pos), ("vul=0", neg)):
    qualquer = [r for r in conj if r["commit_id"] in com_rec or r["CVE ID"] in cve_rec]
    part = collections.Counter(com_rec.get(r["commit_id"]) or cve_rec.get(r["CVE ID"]) for r in qualquer)
    print(f"{nome}: compartilham commit {sum(r['commit_id'] in com_rec for r in conj)}, "
          f"CVE {sum(r['CVE ID'] in cve_rec for r in conj)}, algum dos dois {len(qualquer)}; particao: {dict(part)}")
# mesma CVE em mais de uma CWE no BigVul inteiro? (CWE e por linha)
cwes_por_cve = collections.defaultdict(set)
for r in rows:
    cwes_por_cve[r["CVE ID"]].add(r["CWE ID"])
print("CVEs CWE-416 que no BigVul tambem aparecem com outra CWE:",
      sum(1 for c in {r["CVE ID"] for r in uaf} if len(cwes_por_cve[c]) > 1))

# negativos so em commit que tem positivo CWE-416 (o mesmo criterio do SPLIT.md para o recorte)
com_pos = {r["commit_id"] for r in pos}
neg_cp = [r for r in neg if r["commit_id"] in com_pos]
print("vul=0 em commit com vul=1:", len(neg_cp), "| projetos:", collections.Counter(r["project"] for r in neg_cp).most_common(5))
