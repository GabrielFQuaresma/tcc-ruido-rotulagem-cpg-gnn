#!/usr/bin/env python3
"""Confere a Fase II refeita com os modelos salvos (PREREGISTRO_PRINCIPAL.md §6, passo 2).

    python3 conferir_fase2_v2.py

SO CONTAGEM E IDENTIDADE. Nao le rotulo, nao calcula metrica, nao imprime probabilidade nem
predicao. Para cada braco e semente:
  - existem semente_<s>.tsv, semente_<s>.tsv.json e modelo_<s>.pt em fase2_v2/;
  - o .tsv novo e IDENTICO ao da rodada original (fase2/)? Comparado so por SHA-256 do arquivo;
  - os ids do .tsv novo, por particao, sao exatamente os da validacao e do teste do
    dataset_indice_v3.tsv, sem repeticao (le so as colunas id e particao).
O conjunto oficial e o novo em qualquer caso (pre-registro §6); a contagem de identicos so registra
se a GPU reproduziu a rodada original.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reveal_comum as C  # noqa: E402

ORIG = os.path.join(C.SAIDA, "fase2")
NOVA = os.path.join(C.SAIDA, "fase2_v2")


def sha(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def ids_esperados():
    esp = {"validacao": set(), "teste": set()}
    with open(C.INDICE, encoding="utf-8") as f:
        cab = f.readline().rstrip("\n").split("\t")
        i_id, i_part = cab.index("id"), cab.index("particao")
        for linha in f:
            c = linha.rstrip("\n").split("\t")
            if c[i_part] in esp:
                esp[c[i_part]].add(c[i_id])
    return esp


def ids_do_arquivo(caminho):
    vistos = {"validacao": [], "teste": []}
    with open(caminho, encoding="utf-8") as f:
        cab = f.readline().rstrip("\n").split("\t")
        i_id, i_part = cab.index("id"), cab.index("particao")
        for linha in f:
            c = linha.rstrip("\n").split("\t")
            vistos.setdefault(c[i_part], []).append(c[i_id])
    return vistos


def main():
    esp = ids_esperados()
    print("esperado: validacao %d, teste %d ids" % (len(esp["validacao"]), len(esp["teste"])))
    tot_ok = tot_ident = tot_arq = 0
    problemas = []
    for b in C.TODOS_BRACOS:
        ok = ident = 0
        for s in C.F2_SEMENTES:
            nova = os.path.join(NOVA, b, "semente_%d.tsv" % s)
            faltam = [p for p in (nova, nova + ".json", os.path.join(NOVA, b, "modelo_%d.pt" % s))
                      if not os.path.exists(p)]
            if faltam:
                problemas.append("%s s%d: falta %s" % (b, s, ", ".join(os.path.basename(p) for p in faltam)))
                continue
            tot_arq += 1
            v = ids_do_arquivo(nova)
            certo = all(len(v.get(p, [])) == len(set(v.get(p, []))) and set(v.get(p, [])) == esp[p]
                        for p in ("validacao", "teste")) and set(v) <= {"validacao", "teste"}
            if certo:
                ok += 1
            else:
                problemas.append("%s s%d: ids nao batem com o indice" % (b, s))
            orig = os.path.join(ORIG, b, "semente_%d.tsv" % s)
            if os.path.exists(orig) and sha(orig) == sha(nova):
                ident += 1
        tot_ok += ok
        tot_ident += ident
        print("%-18s ids ok %2d/30 | identico a fase2/ %2d/30" % (b, ok, ident))
    print("TOTAL: %d arquivos; ids ok %d; identicos a fase2/ %d" % (tot_arq, tot_ok, tot_ident))
    for p in problemas:
        print("PROBLEMA:", p)
    sys.exit(1 if problemas or tot_arq != 390 else 0)


if __name__ == "__main__":
    main()
