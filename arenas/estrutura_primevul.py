# PrimeVul v0.1 oficial, arena da G4 (familia de memoria, negativos dos mesmos commits, dedup estrita
# por CVE e commit contra o BigVul inteiro): o que o §10 do adendo manda conferir nos dados.
#  (1) quantas funções da arena tem arquivo inteiro no file_info.json;
#  (2) de que versao e o arquivo (antes ou depois do conserto) e se as irmas consertadas estao entre
#      os negativos;
#  (3) como o func_hash/file_hash sao calculados (para conferir arquivo baixado por outro caminho);
#  (4) de onde viriam os arquivos que faltam (host do commit).
# So metadados; o codigo das funcoes entra so em hash. Nenhum modelo.
import csv, json, os, hashlib, collections, itertools
from urllib.parse import urlparse

H = os.path.expanduser("~/curadoria/arenas/primevul")
BV = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul"
FAM = {"CWE-119", "CWE-120", "CWE-125", "CWE-787"}

bv_com, bv_cve = set(), set()
for r in csv.DictReader(open(f"{BV}/saida_final/indice_bigvul.csv", encoding="utf-8", newline="")):
    bv_com.add(r["commit_id"]); bv_cve.add(r["CVE ID"])
info = json.load(open(f"{H}/file_info.json", encoding="utf-8"))

def lista(v):
    if v is None: return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]

arena = []
md5_ok = md5_tot = 0
for part in ("test", "valid", "train"):
    L = [json.loads(l) for l in open(f"{H}/primevul_{part}.jsonl", encoding="utf-8") if l.strip()]
    for d in L[:300]:  # (3) hipotese: func_hash = md5 do texto da funcao, como inteiro
        md5_tot += 1
        md5_ok += int(hashlib.md5(d["func"].encode()).hexdigest(), 16) == int(d["func_hash"])
    pos = [d for d in L if d["target"] == 1 and lista(d.get("cwe")) and set(lista(d.get("cwe"))) <= FAM]
    com = {d["commit_id"] for d in pos}
    neg = [d for d in L if d["target"] == 0 and d["commit_id"] in com]
    for d in pos + neg:
        if set(lista(d.get("cve"))) & bv_cve or d["commit_id"] in bv_com:
            continue  # dedup estrita por CVE/commit (a chave do corpo vem depois)
        d["_part"] = part
        arena.append(d)

print(f"(3) func_hash == int(md5(func)): {md5_ok} de {md5_tot}")
pos = [d for d in arena if d["target"] == 1]; neg = [d for d in arena if d["target"] == 0]
print(f"arena (antes da chave do corpo): {len(pos)} vulneraveis, {len(neg)} nao vulneraveis")

tem = lambda d: str(d["func_hash"]) in info
print(f"(1) com arquivo no file_info: vulneraveis {sum(map(tem, pos))} de {len(pos)}; "
      f"nao vulneraveis {sum(map(tem, neg))} de {len(neg)}")
print(f"    commits da arena: {len({d['commit_id'] for d in arena})}; "
      f"commits com TODAS as funcoes no file_info: "
      f"{sum(1 for c, g in itertools.groupby(sorted(arena, key=lambda d: d['commit_id']), key=lambda d: d['commit_id']) if all(tem(x) for x in g))}")

# (2) versao: no mesmo commit e no mesmo caminho, quantos file_hash distintos?
por_cp = collections.defaultdict(lambda: collections.defaultdict(set))
for d in arena:
    if tem(d):
        i = info[str(d["func_hash"])]
        por_cp[(d["commit_id"], i["project_file_path"])][d["target"]].add(i["file_hash"])
dist = collections.Counter(len(v[0] | v[1]) for v in por_cp.values())
print(f"(2) pares (commit, caminho) com arquivo: {len(por_cp)}; file_hash distintos por par: {dict(dist)}")
cv = [v for v in por_cp.values() if v[1]]
print(f"    pares com vulneravel: {len(cv)}; neles, existe negativo num arquivo DIFERENTE do da vulneravel "
      f"(= a versao consertada): {sum(1 for v in cv if v[0] - v[1])}; negativo no MESMO arquivo da vulneravel "
      f"(= nao alteradas, versao antes): {sum(1 for v in cv if v[0] & v[1])}")
arqs = {(info[str(d['func_hash'])]['local_file_path']) for d in arena if tem(d)}
print(f"    arquivos distintos a obter (file_contents): {len(arqs)} em {len({a.split('/')[1] for a in arqs})} projetos")

# (4) hosts dos commits (para buscar pelo commit o que nao tiver arquivo)
print("(4) hosts do commit_url:", collections.Counter(urlparse(d.get("commit_url") or "").netloc for d in arena).most_common(6))
print("    func_hash repetido dentro da arena (corpo identico):", sum(c - 1 for c in collections.Counter(str(d['func_hash']) for d in arena).values() if c > 1))
