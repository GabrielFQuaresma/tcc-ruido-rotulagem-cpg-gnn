#!/usr/bin/env python3
"""POS HOC / QUALITATIVO (13/10/2026): o que os bracos fazem com os anotados que cairam no teste.

    python3 posthoc_50_teste.py

ONDE ESTAMOS. O teste do BigVul foi aberto em 13/10 (IMPLEMENTACAO.md §9). A regua do BigVul e o
rotulo dele, que tem ~57% de positivos errados. Os 50 casos anotados a mao pelo autor
(saida/amostra_validacao_revisao.csv, coluna tipo_ruido) sao a unica regua limpa que existe: D = a
funcao e o sitio da vulnerabilidade; A, B, C = rotulo indevido (A sem mudanca semantica, B mudou
por outro motivo, C mudou no conserto mas o defeito nao esta nela). Dos 50, so 9 cairam no teste
do dataset v3; os do treino nao servem (os modelos aprenderam com eles).

PERGUNTA: o M_cur acusa os D e poupa os A/B/C mais que os controles?

O QUE ISTO E: o SEGUNDO USO dos 50 (o primeiro foi a Etapa 5, a precisao do filtro), previsto no
PREREGISTRO_PRINCIPAL.md §9 como evidencia QUALITATIVA. Com 9 casos de 9 commits nao ha metrica
nem regua de "1 em 6": e uma tabela caso a caso.

DADOS PESSOAIS: o CSV de anotacao tem o patch inteiro de cada commit (com autores). Este script
le SO as colunas id, commit_id, cve_id e tipo_ruido, e nao grava nem imprime mais nada dele.

SAIDA: posthoc_50_teste.md (ao lado deste script).
"""

import csv
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analisar_resultados as A  # noqa: E402
import reveal_comum as C  # noqa: E402

csv.field_size_limit(1 << 30)
ANOTACAO = os.path.join(C.REPO, "saida", "amostra_validacao_revisao.csv")
MAPA = os.path.join(C.TRAVERSAL, "mapa_caso_item_50.csv")
BRACOS = ["M_cur", "M_raw"] + list(C.CONTROLES) + ["M_cur_bal"]


def main():
    anot = {}
    with open(ANOTACAO, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            anot[str(r["id"]).strip()] = {"commit": r["commit_id"].strip(), "cve": r["cve_id"].strip(),
                                          "tipo": (r["tipo_ruido"] or "").strip().upper()}
    mapa = list(csv.DictReader(open(MAPA, encoding="utf-8")))
    ids, y, nos = A.carregar_indice("teste")
    pos = {i: k for k, i in enumerate(ids)}
    fx = A.faixa_de(nos)
    regra = A.V.carregar_regra(A.REGRA)

    casos, problemas = [], []
    for m in mapa:
        if m["item"] not in pos:
            continue
        a = anot.get(str(m["caso"]).strip())        # o `id` da anotacao e o numero do caso (1-50)
        if a is None or a["commit"] != m["commit"] or a["cve"] != m["cve"]:
            problemas.append(m["caso"])
            continue
        casos.append({"caso": int(m["caso"]), "item": m["item"], "cve": m["cve"], "tipo": a["tipo"] or "?",
                      "faixa": A.FAIXAS[fx[pos[m["item"]]]][0], "n_nos": int(nos[pos[m["item"]]]),
                      "regra": A.veredito_positivo(m["item"], regra)})
    if problemas:
        sys.exit("casos sem casamento entre mapa e anotacao: %s" % problemas)

    for b in BRACOS:
        cont = {c["item"]: 0 for c in casos}
        for s in C.F2_SEMENTES:
            _, pred = A.carregar_predicao(b, s, "teste", ids)
            for c in casos:
                cont[c["item"]] += int(pred[pos[c["item"]]])
        for c in casos:
            c[b] = cont[c["item"]]

    casos.sort(key=lambda c: (c["tipo"] != "D", c["caso"]))
    L = ["# POS HOC / QUALITATIVO — os anotados que cairam no teste", "",
         "> 13/10/2026, depois de abrir o teste. Segundo uso dos 50 casos anotados (o primeiro foi a "
         "Etapa 5), previsto no PREREGISTRO_PRINCIPAL.md §9 como evidencia qualitativa. %d casos, sem "
         "metrica. Cada celula de braco = em quantas das 30 repeticoes ele ACUSOU a funcao." % len(casos), "",
         "Categoria (anotacao do autor): **D** = e o sitio da vulnerabilidade; A, B, C = rotulo indevido.", "",
         "| caso | item | CVE | categoria | nos (faixa) | regra | " + " | ".join(BRACOS) + " |",
         "| --- | --- | --- | --- | --- | --- |" + " --- |" * len(BRACOS)]
    for c in casos:
        L.append("| %d | %s | %s | **%s** | %d (%s) | %s | %s |" % (
            c["caso"], c["item"], c["cve"], c["tipo"], c["n_nos"], c["faixa"], c["regra"],
            " | ".join(str(c[b]) for b in BRACOS)))
    L += ["", "## Resumo descritivo (media de repeticoes que acusam, por grupo)", "",
          "| grupo | n | " + " | ".join(BRACOS) + " |", "| --- | --- |" + " --- |" * len(BRACOS)]
    for nome, sel in (("D (sitio)", lambda c: c["tipo"] == "D"),
                      ("A/B/C (rotulo indevido)", lambda c: c["tipo"] in ("A", "B", "C"))):
        g = [c for c in casos if sel(c)]
        if g:
            L.append("| %s | %d | %s |" % (nome, len(g), " | ".join("%.1f" % np.mean([c[b] for c in g]) for b in BRACOS)))
    saida = os.path.join(os.path.dirname(os.path.abspath(__file__)), "posthoc_50_teste.md")
    open(saida, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
