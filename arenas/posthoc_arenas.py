#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Observacoes POS HOC da abertura das arenas (18/10/2026) — descritivas, nao mudam veredito nenhum.

    python3 posthoc_arenas.py

ONDE ESTAMOS. As arenas foram abertas uma vez por `analisar_arenas.py --abrir` (PREREGISTRO_ARENAS.md,
secao 10, passo 7). Este script NAO recalcula metrica nenhuma: so le o `resultado_arenas.json` gravado
na abertura e imprime, sem arredondar, os valores que o registro (PREPARACAO_ARENAS.md, "Passo 7")
usa nas observacoes pos hoc. E o mesmo tipo de leitura feita no BigVul em 13/10 (IMPLEMENTACAO.md
secao 9).

O QUE ELE IMPRIME, por arena:
  1. a posicao exata (sem arredondar) do M_cur contra a faixa dos 5 controles, nos dois desenhos, e a
     checagem de tamanho (inclinacao do V1, acima por faixa do V2);
  2. medianas das 30 repeticoes de VP e FP por braco, e o F1 por faixa;
  3. a traversal pura (VP, FP, FN, VN);
  4. POS HOC: em quantas das 30 repeticoes o F1 do M_cur passa a maior mediana dos controles;
  5. POS HOC: por faixa de tamanho, medianas de VP, FP e taxa de falso positivo, e a razao entre a
     taxa nas funcoes de 340+ nos e nas de ate 46.
"""
import json
import os
import statistics as st

AQUI = os.path.dirname(os.path.abspath(__file__))
J = json.load(open(os.path.join(AQUI, "resultado_arenas.json"), encoding="utf-8"))
CTRL = ["M_ctrl_g2026", "M_ctrl_g2027", "M_ctrl_g2028", "M_ctrl_g2029", "M_ctrl_g2030"]
BAL = ["M_cur_bal"] + [c + "_bal" for c in CTRL]
PRINC = ["M_raw", "M_cur"] + CTRL

print("sintese:", J["sintese"][:2])
for a, r in J["arenas"].items():
    print("=" * 20, a, "| P", r["P"], "N", r["N"], "| status", r["status"], "| piso", r["piso"])
    for nome, d in r["desenhos"].items():
        t = d["tamanho"]
        print(f"  [{nome}] M_cur {d['m_cur']:.5f} | controles {d['min']:.5f} a {d['max']:.5f} | {d['posicao']}")
        print("    V1 aplica", t["v1_aplica"], "dispara", t["v1"], "| inclinacao (FPR 340+ menos FPR ate46):",
              ", ".join(f"{k.replace('M_ctrl_g', 'g')} {v:.4f}" for k, v in t["inclinacao"].items()))
        print("    V2", t["v2"], "| acima por faixa:", t["acima_por_faixa"], "|", t["veredito"])
    print("  braco: VP FP (medianas das 30) | F1 por faixa (mediana) ate46 / 47-131 / 132-339 / 340+")
    for b in PRINC + BAL:
        ps = r["por_semente"][b]
        vp = st.median(ps[s]["geral"]["tp"] for s in ps)
        fp = st.median(ps[s]["geral"]["fp"] for s in ps)
        f1f = " / ".join(f"{r['resumo_faixa'][b][k]['f1']['mediana']:.3f}" for k in range(4))
        print(f"    {b:18s} VP {vp:6.1f} FP {fp:7.1f} | {f1f}")
    if "traversal_pura" in r:
        t = r["traversal_pura"]
        print(f"  traversal pura: VP {t['tp']} FP {t['fp']} FN {t['fn']} VN {t['tn']} | F1 {t['f1']:.5f}")
    for nome, cur in (("principal", "M_cur"), ("par balanceado", "M_cur_bal")):
        mx = r["desenhos"][nome]["max"]
        f1s = [r["por_semente"][cur][s]["geral"]["f1"] for s in r["por_semente"][cur]]
        print(f"  POS HOC [{nome}] repeticoes do {cur} com F1 > maior mediana dos controles ({mx:.5f}): "
              f"{sum(f > mx for f in f1s)} de {len(f1s)}")
    if a == "ventivul_inteiro":
        continue
    print("  POS HOC por faixa | VP (ate46/47-131/132-339/340+) | FP | FPR | FPR340+/FPRate46")
    for b in PRINC:
        ps = r["por_semente"][b]
        vp = [st.median(ps[s]["faixas"][k]["tp"] for s in ps) for k in range(4)]
        fp = [st.median(ps[s]["faixas"][k]["fp"] for s in ps) for k in range(4)]
        fpr = [r["resumo_faixa"][b][k]["fpr"]["mediana"] for k in range(4)]
        razao = fpr[3] / fpr[0] if fpr[0] > 0 else float("inf")
        print(f"    {b:16s} | {' / '.join(f'{x:6.1f}' for x in vp)} | {' / '.join(f'{x:7.1f}' for x in fp)} | "
              f"{' / '.join(f'{x:.4f}' for x in fpr)} | {razao:7.1f}")
