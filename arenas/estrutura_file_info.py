# Estrutura do file_info.json do PrimeVul v0.1 (so metadados: chaves, tipos, exemplos de caminho).
# Nenhum codigo de funcao e impresso. Nenhum modelo.
import json, os, collections
P = os.path.expanduser("~/curadoria/arenas/primevul/file_info.json")
d = json.load(open(P, encoding="utf-8"))
print("tipo raiz:", type(d).__name__, "| tamanho:", len(d))
if isinstance(d, dict):
    k0 = next(iter(d))
    print("exemplo de chave:", k0)
    v = d[k0]
else:
    v = d[0]
def mostra(x, pref=""):
    if isinstance(x, dict):
        for k, y in x.items():
            if isinstance(y, (dict, list)):
                print(f"{pref}{k}: {type(y).__name__} ({len(y)})"); mostra(y if isinstance(y, dict) else (y[0] if y else {}), pref + "  ")
            else:
                s = str(y)
                print(f"{pref}{k}: {s[:100]!r}" + (" ..." if len(s) > 100 else ""))
mostra(v)
# quantos registros tem cada campo, e valores tipicos dos campos curtos
vals = list(d.values()) if isinstance(d, dict) else d
cont = collections.Counter(k for x in vals if isinstance(x, dict) for k in x)
print("campos e quantos registros os tem:", dict(cont))
