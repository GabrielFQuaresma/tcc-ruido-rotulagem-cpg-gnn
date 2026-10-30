# PrimeVul v0.1 inteiro (as 3 particoes, lidas do stdin em sequencia, cada linha prefixada pela particao),
# familia de memoria, e quanto sobra com duas deduplicacoes por CVE/commit:
#   (a) contra treino+validacao do recorte (a Decisao H aprovada)
#   (b) contra o BigVul INTEIRO (todas as linhas do indice, todas as CWEs, todas as particoes)
# So metadados. Nenhum modelo.
import sys, json, csv, collections
BV = sys.argv[1]  # pasta Dataset/bigvul
FAM = {"CWE-119", "CWE-120", "CWE-125", "CWE-787"}

tv_com, tv_cve = set(), set()
for arq in ("positivos.tsv", "negativos.tsv"):
    for r in csv.DictReader(open(f"{BV}/traversal/split/{arq}", encoding="utf-8"), delimiter="\t"):
        if r["particao"] in ("treino", "validacao"):
            tv_com.add(r["commit"]); tv_cve.add(r["cve"])
bv_com, bv_cve = set(), set()
for r in csv.DictReader(open(f"{BV}/saida_final/indice_bigvul.csv", encoding="utf-8", newline="")):
    bv_com.add(r["commit_id"]); bv_cve.add(r["CVE ID"])
print(f"BigVul inteiro: {len(bv_com)} commits, {len(bv_cve)} CVEs | treino+validacao do recorte: {len(tv_com)} commits")

def lista(v):
    if v is None: return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]

reg = collections.defaultdict(list)
for l in sys.stdin:
    part, _, js = l.partition("\t")
    if not js.strip(): continue
    d = json.loads(js)
    reg[part].append((int(d["target"]), lista(d.get("cwe")), lista(d.get("cve")), str(d["commit_id"])))

tot = collections.Counter()
for part in ("test", "valid", "train"):
    L = reg[part]
    pos = [x for x in L if x[0] == 1 and x[1] and set(x[1]) <= FAM]
    com = {x[3] for x in pos}
    neg = [x for x in L if x[0] == 0 and x[3] in com]
    for rot, conj in (("vuln", pos), ("nao_vuln", neg)):
        fica_a = [x for x in conj if not (set(x[2]) & tv_cve or x[3] in tv_com)]
        fica_b = [x for x in conj if not (set(x[2]) & bv_cve or x[3] in bv_com)]
        tot[(rot, "familia")] += len(conj); tot[(rot, "a")] += len(fica_a); tot[(rot, "b")] += len(fica_b)
        print(f"[{part}] {rot}: familia {len(conj)} | ficam (a) treino+val {len(fica_a)} | ficam (b) BigVul inteiro {len(fica_b)}")
    print(f"[{part}] commits com vulneravel da familia que sobram em (b): "
          f"{len({x[3] for x in pos if not (set(x[2]) & bv_cve or x[3] in bv_com)})}")
for rot in ("vuln", "nao_vuln"):
    print(f"[TOTAL] {rot}: familia {tot[(rot,'familia')]} | (a) {tot[(rot,'a')]} | (b) {tot[(rot,'b')]}")
