#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Confere, na fonte primaria, os numeros que o artigo cita do teste do BigVul e das arenas.

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/conferir_numeros.py

ONDE ESTAMOS. Escrita do artigo final (Tex/PLANO_ARTIGO_FINAL.md, secao 7): as Secoes 3.6, 4.3, 4.4
e 4.5 citam resultados ja abertos (BigVul em 13/10/2026, arenas em 18/10/2026). A regra do projeto
e que nenhum numero entra no texto sem fonte primaria conferida. A fonte primaria aqui sao os dois
JSONs gravados na abertura, nao os .md que os transcrevem nem os registros escritos depois.

O QUE O SCRIPT FAZ. So le. (1) Confere o SHA-256 dos arquivos de resultado e da ficha de preparacao
contra os valores registrados no dia da abertura; se algum divergir, para. (2) Imprime, sem
arredondar, cada numero que o texto usa, inclusive os das observacoes pos hoc (que ja estao em
modelo/IMPLEMENTACAO.md secao 9 e em arenas/PREPARACAO_ARENAS.md, "Passo 7"), recalculados aqui
a partir das predicoes por repeticao gravadas no JSON. Nao calcula nenhuma metrica nova a partir
das predicoes: so medianas e contagens sobre os valores por repeticao que a abertura gravou.

O QUE ELE NAO E. Nao e analise nova e nao muda veredito nenhum.
"""
import hashlib
import json
import os
import statistics as st
import sys

BASE = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul"
CTRL = ["M_ctrl_g2026", "M_ctrl_g2027", "M_ctrl_g2028", "M_ctrl_g2029", "M_ctrl_g2030"]
CTRL_BAL = [c + "_bal" for c in CTRL]
FAIXAS = ["ate 46", "47-131", "132-339", "340+"]

# SHA-256 registrados no dia de cada abertura (IMPLEMENTACAO.md secao 9; PREPARACAO_ARENAS.md,
# "Passo 7") e da ficha (PREPARACAO_ARENAS.md, "Fim do passo 3"; conferido pelo analisar_arenas.py).
# 21/10/2026: a abertura das arenas foi refeita so para corrigir a conta do excesso sobre o acaso
# (PREPARACAO_ARENAS.md, "Achado na escrita do artigo"); a versao de 18/10 ficou guardada como
# resultado_arenas_anterior_20261021_123410 e continua conferida aqui.
HASHES = {
    "modelo/resultado_teste_bigvul.md": "39296fad703b850a0db4bc75e50617bd383e294978178ebdeba7d7185480cf1c",
    "modelo/resultado_teste_bigvul.json": "f8ea66693ceac645cc1d9a7dd16aed5d08b45a4703f661519acc9bad63991402",
    "arenas/resultado_arenas.md": "bf173e893843da671e28afd6f5205f4d135bdca1ad00fa4b86cd2a2c153c2c9b",
    "arenas/resultado_arenas.json": "34ff46c06ea6c08631af5b6417fd25b2a7b40162f0bc42ee9ede8ea15e9f92b0",
    "arenas/resultado_arenas_anterior_20261021_123410.md":
        "ec698b72535b24514f6f245b1185e082c395dc1c82a4517cce6740eb20a3ec41",
    "arenas/resultado_arenas_anterior_20261021_123410.json":
        "f45efc4115efeea6fe8ab75949b7c4290ef31f576b035714a4baf721c5d1c6f2",
}
FICHA_PREFIXO, FICHA_SUFIXO = "e5ead135", "8b842e"


def sha(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def med(xs):
    return st.median(list(xs))


def f1_de(tp, fp, fn):
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


print("== 1. Os arquivos sao os da abertura")
for rel, esperado in HASHES.items():
    obtido = sha(os.path.join(BASE, rel))
    ok = obtido == esperado
    print(f"  {rel}: {'confere' if ok else 'DIVERGE'}")
    if not ok:
        sys.exit(f"SHA-256 divergente em {rel}: {obtido}")
ficha = sha(os.path.join(BASE, "arenas/FICHA_PREPARACAO.md"))
if not (ficha.startswith(FICHA_PREFIXO) and ficha.endswith(FICHA_SUFIXO)):
    sys.exit(f"SHA-256 divergente na ficha: {ficha}")
print(f"  arenas/FICHA_PREPARACAO.md: confere ({ficha[:12]}...)")

B = json.load(open(os.path.join(BASE, "modelo/resultado_teste_bigvul.json"), encoding="utf-8"))
A = json.load(open(os.path.join(BASE, "arenas/resultado_arenas.json"), encoding="utf-8"))


def bloco_comum(nome, r, comp, tam, trav):
    """Imprime o que vale igual para o BigVul e para as arenas."""
    rg, rf, ps = r["resumo_geral"], r["resumo_faixa"], r["por_semente"]
    print(f"-- comparacao que decide (F1, mediana das 30)")
    for des, d in comp.items():
        print(f"  [{des}] M_cur {d['m_cur']:.5f} | controles {d['min']:.5f} a {d['max']:.5f} | {d['posicao']}")
    print("-- checagem de tamanho")
    for des, t in tam.items():
        incl = ", ".join(f"{k.replace('M_ctrl_g', 'g')} {v:.4f}" for k, v in t["inclinacao"].items())
        print(f"  [{des}] V1 aplica {t['v1_aplica']} dispara {t['v1']} | inclinacao: {incl}")
        print(f"  [{des}] V2 {t['v2']} | acima por faixa {t['acima_por_faixa']} | {t['veredito']}")
    print("-- metricas gerais, mediana [Q1 a Q3] das 30")
    for b in ["M_raw", "M_cur"] + CTRL + ["M_cur_bal"] + CTRL_BAL:
        partes = []
        for m in ("f1", "recall", "precisao", "pr_auc", "mcc", "fpr"):
            v = rg[b][m]
            partes.append(f"{m} {v['mediana']:.4f} [{v['q1']:.4f}-{v['q3']:.4f}]")
        print(f"  {b:17s} " + " | ".join(partes))
    for m in ("f1", "recall", "precisao", "pr_auc", "mcc", "fpr"):
        for grupo, membros in (("controles", CTRL), ("controles bal", CTRL_BAL)):
            vs = [rg[c][m]["mediana"] for c in membros]
            print(f"  faixa dos {grupo:13s} {m:8s}: {min(vs):.4f} a {max(vs):.4f}")
    print("-- F1 por faixa de tamanho (mediana) e posicao do M_cur contra os 5 controles")
    for k, fx in enumerate(FAIXAS):
        cur = rf["M_cur"][k]["f1"]["mediana"]
        vs = [rf[c][k]["f1"]["mediana"] for c in CTRL]
        pos = "acima" if cur > max(vs) else ("abaixo" if cur < min(vs) else "dentro")
        print(f"  {fx:8s}: M_cur {cur:.4f} | controles {min(vs):.4f} a {max(vs):.4f} | {pos}")
    print("-- POS HOC: VP e FP (medianas das 30), total e por faixa; razao FPR 340+ / FPR ate 46")
    for b in ["M_raw", "M_cur"] + CTRL:
        tp = med(ps[b][s]["geral"]["tp"] for s in ps[b])
        fp = med(ps[b][s]["geral"]["fp"] for s in ps[b])
        tpf = [med(ps[b][s]["faixas"][k]["tp"] for s in ps[b]) for k in range(4)]
        fpf = [med(ps[b][s]["faixas"][k]["fp"] for s in ps[b]) for k in range(4)]
        fpr = [rf[b][k]["fpr"]["mediana"] for k in range(4)]
        razao = fpr[3] / fpr[0] if fpr[0] > 0 else float("inf")
        print(f"  {b:13s} VP {tp:6.1f} FP {fp:7.1f} | VP/faixa {tpf} | FP/faixa {fpf} | "
              f"FPR ate46 {fpr[0]:.5f} 340+ {fpr[3]:.5f} razao {razao:.1f}")
    mx = comp["principal"]["max"]
    f1s = [ps["M_cur"][s]["geral"]["f1"] for s in ps["M_cur"]]
    print(f"-- POS HOC: repeticoes do M_cur com F1 > maior mediana dos controles ({mx:.5f}): "
          f"{sum(f > mx for f in f1s)} de {len(f1s)}")
    q1cur = rg["M_cur"]["f1"]["q1"]
    q3ctrl = max(rg[c]["f1"]["q3"] for c in CTRL)
    print(f"-- POS HOC: Q1 do F1 do M_cur {q1cur:.4f} | maior Q3 dos controles {q3ctrl:.4f}")
    if trav is not None:
        print(f"-- traversal pura: F1 {trav['f1']:.5f} recall {trav['recall']:.4f} precisao "
              f"{trav['precisao']:.4f} FPR {trav['fpr']:.4f} | VP {trav['tp']} FP {trav['fp']} "
              f"FN {trav['fn']} VN {trav['tn']}")
        print(f"   repeticoes do M_cur com F1 > F1 da traversal: {sum(f > trav['f1'] for f in f1s)} de {len(f1s)}")
        todos = {b: rg[b]["f1"]["mediana"] for b in rg}
        acima = [b for b, v in todos.items() if v >= trav["f1"]]
        print(f"   bracos (dos 13) com F1 mediano >= o da traversal: {acima or 'nenhum'}; "
              f"maior: {max(todos, key=todos.get)} {max(todos.values()):.4f}")


print("\n== 2. Teste do BigVul (aberto em", B["gerado"], ")")
cont = B["contagem_faixas"]
P = sum(c[0] for c in cont)
N = sum(c[1] for c in cont)
print(f"  funcoes {P + N}, positivas {P}, negativas {N}; por faixa {cont}; "
      f"% positivas por faixa {[round(100 * c[0] / (c[0] + c[1]), 1) for c in cont]}")
bloco_comum("bigvul", B, B["comparacoes"], B["tamanho"], B["traversal_pura"])

print("\n== 3. Arenas (abertas em", A["gerado"], ")")
print("  sintese:", A["sintese"])
for nome, r in A["arenas"].items():
    print(f"\n==== {nome} | P {r['P']} N {r['N']} ({100 * r['P'] / (r['P'] + r['N']):.1f}% vuln.) | "
          f"status {r['status']} | piso {r['piso']}")
    cont = r["cont"]
    print(f"  por faixa {cont}; % vuln. por faixa "
          f"{[round(100 * c[0] / (c[0] + c[1]), 1) for c in cont]}")
    comp = {des: d for des, d in r["desenhos"].items()}
    tam = {des: d["tamanho"] for des, d in r["desenhos"].items()}
    bloco_comum(nome, r, comp, tam, r.get("traversal_pura"))
    exc = r["excesso_principal"]
    print("-- excesso sobre o acaso (mediana):", ", ".join(f"{k.replace('M_ctrl_g', 'g')} {v:.1f}" for k, v in exc.items()))
    qd = r["queda"]
    vs = [qd[c]["mediana"] for c in CTRL]
    print(f"-- queda de F1 (BigVul - arena): M_cur {qd['M_cur']['mediana']:.4f} | controles "
          f"{min(vs):.4f} a {max(vs):.4f} | M_raw {qd['M_raw']['mediana']:.4f}")
    if nome == "ventivul_familia":
        ps = r["por_semente"]["M_cur"]
        tp = med(ps[s]["geral"]["tp"] for s in ps)
        fp = med(ps[s]["geral"]["fp"] for s in ps)
        Pv = r["P"]
        acus = tp + fp
        print(f"-- POS HOC VentiVul: mediana VP {tp} FP {fp} (acusa {acus}); F1 = 2VP/(acusadas + P):"
              f" com VP {tp}: {f1_de(tp, fp, Pv - tp):.4f}; com VP {tp - 1} e as mesmas acusacoes:"
              f" {f1_de(tp - 1, acus - tp + 1, Pv - tp + 1):.4f}; um acerto vale {2 / (acus + Pv):.4f};"
              f" margem {r['desenhos']['principal']['m_cur'] - r['desenhos']['principal']['max']:.5f}"
              f" = {(r['desenhos']['principal']['m_cur'] - r['desenhos']['principal']['max']) / (2 / (acus + Pv)):.3f} acerto")
