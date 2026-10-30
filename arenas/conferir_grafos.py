#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Conferencias dos grafos de uma arena e contagem por faixa de tamanho.

O QUE E, situando
-----------------
Preparacao das arenas (PREREGISTRO_ARENAS.md §10, passo 3). Duas coisas, para a ficha de preparacao:
  1. as invariantes que o dataset v3 conferiu (_conferir_dataset.py, DATASET.md): nenhum no fora
     da faixa de linhas da funcao (vazamento de rotulo), nenhuma aresta para no inexistente, nenhum
     id repetido, n_nos igual ao numero de nos; e mais: todo grafo e de uma funcao que ficou na
     deduplicacao (indice_<arena>.tsv com motivo vazio);
  2. a contagem por faixa de tamanho (Decisao I; faixas do PREREGISTRO_TAMANHO.md §2: ate 46 |
     47-131 | 132-339 | 340+ nos), positivas e negativas — e o que decide, mecanicamente, quais
     metricas por faixa e quais criterios de vies (V1, V2) se aplicam na arena. Contar nao e ver
     resultado (PREREGISTRO_TAMANHO.md §3).
Nenhum modelo. Uso: python3 conferir_grafos.py <arena> [pasta_de_grafos]
  ex.: conferir_grafos.py sonda | conferir_grafos.py ventivul_familia ventivul
Com pasta_de_grafos (arenas que dividem a pasta, como as duas do VentiVul), so contam os grafos cujo
id esta naquela arena; os outros sao de outra arena e so aparecem contados.
"""
import csv
import glob
import json
import os
import sys
from collections import Counter

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(AQUI), "traversal"))
import montar_dataset as md  # noqa: E402  mesmo filtro de no fora da funcao

FAIXAS = [("ate 46", 0, 46), ("47-131", 47, 131), ("132-339", 132, 339), ("340+", 340, 10**9)]


def faixa(n):
    return next(nome for nome, a, b in FAIXAS if a <= n <= b)


def main(arena, pasta_grafos=None):
    compartilhada = pasta_grafos is not None
    pasta = os.path.expanduser(f"~/curadoria/arenas/{pasta_grafos or arena}/grafos")
    outra = 0
    fica = {r["id"]: r for r in csv.DictReader(open(os.path.join(AQUI, f"indice_{arena}.tsv"), encoding="utf-8"),
                                               delimiter="\t") if not r["motivo"]}
    ids, prob, cont = Counter(), Counter(), Counter()
    for p in sorted(glob.glob(os.path.join(pasta, "*.jsonl"))):
        for l in open(p, encoding="utf-8"):
            g = json.loads(l)
            if compartilhada and g["id"] not in fica:
                outra += 1
                continue
            ids[g["id"]] += 1
            n = len(g["nos"])
            if n != g["n_nos"] or len(g["arestas"]) != g["n_arestas"]:
                prob["contagem_inconsistente"] += 1
            if any(not (0 <= a < n and 0 <= b < n) for a, b, _ in g["arestas"]):
                prob["aresta_para_no_inexistente"] += 1
            if md.fora_da_funcao(g):
                prob["no_fora_da_funcao"] += 1
            if g["id"] not in fica:
                prob["fora_do_indice_deduplicado"] += 1
            elif int(fica[g["id"]]["rotulo"]) != g["rotulo"]:
                prob["rotulo_diferente_do_indice"] += 1
            cont[(faixa(g["n_nos"]), g["rotulo"])] += 1
    prob["id_repetido"] = sum(1 for c in ids.values() if c > 1)
    print(f"[{arena}] grafos: {sum(ids.values())} ({sum(cont[(f, 1)] for f, _, _ in FAIXAS)} vulneraveis)")
    print(f"[{arena}] invariantes (tudo tem de ser 0): {dict(prob)}")
    if compartilhada:
        print(f"[{arena}] grafos da mesma pasta que sao de outra arena (nao contam aqui): {outra}")
    print(f"[{arena}] por faixa de tamanho (vulneraveis / nao vulneraveis):")
    for f, _, _ in FAIXAS:
        print(f"    {f:8s} {cont[(f, 1)]:6d} / {cont[(f, 0)]:6d}")
    if any(prob.values()):
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
