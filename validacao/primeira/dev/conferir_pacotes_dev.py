#!/usr/bin/env python3
"""Prova que os pacotes do dev batem com o dev_set.tsv, e monta o mapa caso_NN -> item.

Sem este mapa a Etapa 4b nao existe: a evidencia da curadoria e indexada por
`NNNN__projeto` e a anotacao do modelo e indexada por `caso_NN`. O `caso_NN` sai da
ordem de `df.sample(n=30, random_state=7)`; o `NNNN` sai do indice do parquet. Sao a
mesma amostra em duas ordens diferentes, e juntar na mao seria pedir para errar.

Confere tambem que a rubrica e byte a byte a mesma dos 50 — se for outra, a anotacao
do dev nao e comparavel com nada.
"""

import csv
import os
import sys

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
CEGA = os.path.dirname(AQUI)
BIGVUL = os.path.dirname(CEGA)


def main():
    man = pd.read_csv(os.path.join(AQUI, "manifesto_cve_visivel.csv"))
    dev = pd.read_csv(os.path.join(BIGVUL, "traversal", "dev_set.tsv"), sep="\t")

    # 1. a rubrica e a mesma dos 50?
    ref = pd.read_csv(os.path.join(CEGA, "manifesto_cve_visivel.csv"))
    sha_dev = set(man["rubrica_sha256"])
    sha_ref = set(ref["rubrica_sha256"])
    if sha_dev != sha_ref:
        sys.exit("ERRO: rubrica diferente da usada nos 50.\n  dev {}\n  50  {}"
                 .format(sha_dev, sha_ref))
    print("rubrica identica a dos 50: ok ({})".format(list(sha_dev)[0][:16]))

    # 2. os 30 pacotes sao os 30 itens do dev_set.tsv?
    #    O par (commit, cve) nao e unico quando o commit toca varias funcoes — o
    #    cluster CVE-2016-1621 tem 5 itens no dev. A conferencia e por MULTICONJUNTO.
    from collections import Counter
    a = Counter(zip(man["commit_id"].astype(str).str.strip(),
                    man["cve_id"].astype(str).str.strip()))
    b = Counter(zip(dev["item"].map(lambda s: None),  # placeholder, trocado abaixo
                    dev["cve"].astype(str).str.strip()))
    # o dev_set.tsv nao carrega commit; reconstroi do parquet pelo id da pasta
    pos = pd.read_parquet(os.path.join(BIGVUL, "saida", "bigvul_memoria_positivos.parquet"),
                          columns=["commit_id", "CVE ID"])
    b = Counter((str(pos.iloc[i - 1]["commit_id"]).strip(),
                 str(pos.iloc[i - 1]["CVE ID"]).strip()) for i in dev["id"])
    if a != b:
        sys.exit("ERRO: os pacotes nao sao a mesma amostra do dev_set.tsv\n"
                 "  so nos pacotes: {}\n  so no dev_set: {}"
                 .format(sorted((a - b).elements()), sorted((b - a).elements())))
    print("os 30 pacotes sao a mesma amostra do dev_set.tsv: ok")

    # 3. o mapa. Empate (mesmo commit+cve em varias linhas) e resolvido pela ordem:
    #    tanto o manifesto quanto o dev_set preservam a ordem de df.sample, entao
    #    a n-esima ocorrencia de um par casa com a n-esima do outro lado.
    ordem_dev = list(pos.iloc[[i - 1 for i in dev["id"]]].index)
    chave_dev = {}
    for pos_i, item_id in zip(ordem_dev, dev["id"]):
        chave = (str(pos.loc[pos_i, "commit_id"]).strip(),
                 str(pos.loc[pos_i, "CVE ID"]).strip())
        chave_dev.setdefault(chave, []).append(int(item_id))
    itens = {int(r["id"]): r["item"] for _, r in dev.iterrows()}

    linhas, usados = [], {}
    for _, m in man.sort_values("id").iterrows():
        chave = (str(m["commit_id"]).strip(), str(m["cve_id"]).strip())
        k = usados.get(chave, 0)
        usados[chave] = k + 1
        item_id = chave_dev[chave][k]
        linhas.append({"caso": int(m["id"]), "item": itens[item_id],
                       "id_parquet": item_id, "projeto": m["project"],
                       "cve": m["cve_id"], "cwe": m["cwe_bigvul"]})

    destino = os.path.join(AQUI, "mapa_caso_item.csv")
    with open(destino, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(linhas[0].keys()))
        w.writeheader()
        w.writerows(linhas)
    print("\nmapa em {}".format(destino))
    for l in linhas:
        print("  caso_{:02d}  {:<22} {}".format(l["caso"], l["item"], l["cve"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
