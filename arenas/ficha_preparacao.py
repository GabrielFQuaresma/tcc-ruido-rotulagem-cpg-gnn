#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Escreve a FICHA DE PREPARACAO das arenas externas (PREREGISTRO_ARENAS.md §10, fim do passo 3).

O que o adendo manda a ficha conter: contagens por arena e por faixa (Decisao I), removidas por
motivo e rotulo (deduplicacao, Decisao H), falhas por motivo e rotulo (extracao), taxa de tokens
fora do vocabulario. E aplica, MECANICAMENTE, o que a contagem decide (Decisao I): se a arena tem
veredito (>= 30 positivos e >= 30 negativos), quais metricas por faixa entram (>= 30 positivos: F1 e
recall; >= 30 negativos: taxa de falso positivo), se o V1 se aplica (>= 30 negativos nas faixas ate 46
E 340+), se o V2 se aplica (>= 30 positivos em pelo menos uma faixa pequena; senao "nao se aplica",
E3), e "nao verificavel" se nenhum dos dois. Para o VentiVul, a troca automatica da G3.

Tudo e CONTAGEM: nenhuma predicao existe, nenhuma e lida (PREREGISTRO_TAMANHO.md §3). Depois de
escrita, o SHA-256 da ficha e registrado (PREPARACAO_ARENAS.md e Notion) e o script de analise o
confere antes de abrir (§10, passo 6).

Uso (no WSL): python3 ficha_preparacao.py   ->  arenas/FICHA_PREPARACAO.md
"""
import csv
import datetime
import glob
import hashlib
import json
import os
import sys
from collections import Counter

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import vetorizar_arena as va  # noqa: E402  o mesmo laco de vetorizacao (Word2Vec do treino)

FAIXAS = [("ate 46", 0, 46), ("47-131", 47, 131), ("132-339", 132, 339), ("340+", 340, 10**9)]
PEQUENAS, GRANDES = ("ate 46", "47-131"), ("132-339", "340+")
MIN = 30
# arena -> (indice da deduplicacao, indice da extracao, pasta de grafos, tem veredito?)
ARENAS = {
    "sonda": ("indice_sonda.tsv", "grafos_sonda.tsv", "sonda", True),
    "ventivul_familia": ("indice_ventivul_familia.tsv", "grafos_ventivul.tsv", "ventivul", True),
    "primevul": ("indice_primevul.tsv", "grafos_primevul.tsv", "primevul", True),
    "ventivul_inteiro": ("indice_ventivul_inteiro.tsv", "grafos_ventivul.tsv", "ventivul", False),
}
NOMES = {"sonda": "Sonda CWE-416", "ventivul_familia": "VentiVul v3 — família de memória",
         "primevul": "PrimeVul v0.1", "ventivul_inteiro": "VentiVul v3 — inteiro (descritivo)"}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def tsv(nome):
    return list(csv.DictReader(open(os.path.join(AQUI, nome), encoding="utf-8"), delimiter="\t"))


def faixa(n):
    return next(f for f, a, b in FAIXAS if a <= n <= b)


def contar(arena):
    idx, ext, pasta, veredito = ARENAS[arena]
    cand = tsv(idx)
    fica = {r["id"]: int(r["rotulo"]) for r in cand if not r["motivo"]}
    dedup = Counter((r["motivo"] or "fica", int(r["rotulo"])) for r in cand)
    stat = {r["id"]: r for r in tsv(ext)}
    falhas = Counter((stat[i]["status"], rot) for i, rot in fica.items() if stat[i]["status"] != "grafo")
    # grafos da arena (os da pasta cujo id esta na arena) e OOV com o Word2Vec do treino
    V = va.Vetorizador()
    bandas, n_grafos = Counter(), Counter()
    for arq in sorted(glob.glob(os.path.expanduser(f"~/curadoria/arenas/{pasta}/grafos/*.jsonl"))):
        for l in open(arq, encoding="utf-8"):
            g = json.loads(l)
            if g["id"] not in fica:
                continue
            assert fica[g["id"]] == g["rotulo"], g["id"]
            bandas[(faixa(g["n_nos"]), g["rotulo"])] += 1
            n_grafos[g["rotulo"]] += 1
            V.grafo(g)
    return {"cand": Counter(int(r["rotulo"]) for r in cand), "dedup": dedup, "fica": Counter(fica.values()),
            "falhas": falhas, "grafos": n_grafos, "bandas": bandas, "veredito": veredito,
            "oov": (V.oov, V.tok_total), "arquivos": {idx: sha256(os.path.join(AQUI, idx)),
                                                      ext: sha256(os.path.join(AQUI, ext))}}


def decide(c):
    """O que a contagem decide, mecanicamente (Decisao I; PREREGISTRO_TAMANHO.md §3, §6; E3)."""
    b = c["bandas"]
    pos, neg = c["grafos"][1], c["grafos"][0]
    d = {"tem_veredito": pos >= MIN and neg >= MIN}
    d["f1_recall_por_faixa"] = [f for f, _, _ in FAIXAS if b[(f, 1)] >= MIN]
    d["fpr_por_faixa"] = [f for f, _, _ in FAIXAS if b[(f, 0)] >= MIN]
    d["v1"] = b[("ate 46", 0)] >= MIN and b[("340+", 0)] >= MIN
    pequenas_ok = [f for f in PEQUENAS if b[(f, 1)] >= MIN]
    grandes_ok = [f for f in GRANDES if b[(f, 1)] >= MIN]
    # como o analisar_resultados.py que abriu o BigVul: o V2 so se aplica com pelo menos uma faixa
    # pequena E uma grande com 30 positivos; pequena sem grande e o "caso nao previsto" de la
    d["v2"] = ("se aplica" if pequenas_ok and grandes_ok else
               "nao se aplica (caso nao previsto: sem faixa grande com 30)" if pequenas_ok else "nao se aplica")
    d["v2_faixas"] = [f for f, _, _ in FAIXAS if b[(f, 1)] >= MIN]
    v2 = d["v2"] == "se aplica"
    d["veredito_tamanho"] = ("nao verificavel" if not d["v1"] and not v2
                             else "V1 e V2" if d["v1"] and v2 else "so V1" if d["v1"] else "so V2")
    return d


def main():
    R = {a: contar(a) for a in ARENAS}
    D = {a: decide(R[a]) for a in ARENAS}
    L = []
    w = L.append
    w("# Ficha de preparação das arenas externas")
    w("")
    w(f"> Gerada em {datetime.datetime.now():%d/%m/%Y %H:%M} por `arenas/ficha_preparacao.py`, no fim do passo 3 do "
      "§10 do `PREREGISTRO_ARENAS.md` (congelado em 15/10/2026, SHA-256 `6284d831…a01838`). **Nenhuma predição "
      "existe; nenhuma foi lida.** Tudo aqui é contagem. Depois de gravada, o SHA-256 desta ficha é registrado e o "
      "script de análise o confere antes de abrir as arenas (§10, passo 6).")
    w("")
    w("## Situando")
    w("")
    w("As arenas externas são os conjuntos fora do treino onde se mede se o `M_cur` (o modelo treinado só com os "
      "positivos que a traversal confirmou) generaliza melhor que os 5 controles. Esta ficha fecha a preparação: "
      "quantas funções cada arena tem no fim, o que saiu e por quê, e o que essas contagens decidem, mecanicamente, "
      "sobre o que vai poder ser lido na abertura. O como de cada passo está em `arenas/PREPARACAO_ARENAS.md`.")
    w("")
    w("## 1. Quantas funções cada arena tem no fim (vulneráveis / não vulneráveis)")
    w("")
    w("| arena | candidatas | ficam na deduplicação | **com grafo** | % vulneráveis | veredito? |")
    w("| --- | --- | --- | --- | --- | --- |")
    for a in ARENAS:
        c, d = R[a], D[a]
        p, n = c["grafos"][1], c["grafos"][0]
        ver = ("descritiva (sem veredito)" if not c["veredito"] else
               "**sim**" if d["tem_veredito"] else "abaixo do mínimo")
        w(f"| {NOMES[a]} | {c['cand'][1]} / {c['cand'][0]} | {c['fica'][1]} / {c['fica'][0]} | **{p} / {n}** | "
          f"{100 * p / max(p + n, 1):.1f}% | {ver} |")
    w("")
    fam = R["ventivul_familia"]["grafos"][1]
    w(f"**Troca automática da G3 (VentiVul):** a família de memória tem {fam} positivos com grafo "
      f"({'≥' if fam >= MIN else '<'} 30) → {'**não dispara**; decide a família de memória.' if fam >= MIN else '**dispara**; o veredito passa ao VentiVul inteiro.'}")
    w("")
    w("## 2. O que saiu na deduplicação (Decisão H), por motivo e rótulo")
    w("")
    mot = ["cve", "commit", "corpo", "duplicata_interna", "duplicata_conflito", "falha_sem_corpo"]
    w("| motivo | " + " | ".join(NOMES[a] for a in ARENAS) + " |")
    w("| --- |" + " --- |" * len(ARENAS))
    for m in mot:
        w(f"| {m} | " + " | ".join(f"{R[a]['dedup'][(m, 1)]} / {R[a]['dedup'][(m, 0)]}" for a in ARENAS) + " |")
    w("")
    w("## 3. O que se perdeu na extração (arquivo, CPG, localização), por motivo e rótulo")
    w("")
    todos = sorted({k[0] for a in ARENAS for k in R[a]["falhas"]})
    w("| motivo | " + " | ".join(NOMES[a] for a in ARENAS) + " |")
    w("| --- |" + " --- |" * len(ARENAS))
    for m in todos:
        w(f"| {m} | " + " | ".join(f"{R[a]['falhas'][(m, 1)]} / {R[a]['falhas'][(m, 0)]}" for a in ARENAS) + " |")
    w("| **perda total** | " + " | ".join(
        f"{100 * (R[a]['fica'][1] - R[a]['grafos'][1]) / max(R[a]['fica'][1], 1):.1f}% / "
        f"{100 * (R[a]['fica'][0] - R[a]['grafos'][0]) / max(R[a]['fica'][0], 1):.1f}%" for a in ARENAS) + " |")
    w("")
    w("A perda é desigual entre rótulos em todas as arenas; os motivos estão em `PREPARACAO_ARENAS.md` (passos 3b–3d).")
    w("")
    w("## 4. Contagem por faixa de tamanho e o que ela decide (Decisão I)")
    w("")
    w("Faixas do `PREREGISTRO_TAMANHO.md` §2 (nós do grafo). Mínimo de 30 (convenção do §3 de lá).")
    w("")
    w("| faixa | " + " | ".join(NOMES[a] for a in ARENAS) + " |")
    w("| --- |" + " --- |" * len(ARENAS))
    for f, _, _ in FAIXAS:
        w(f"| {f} | " + " | ".join(f"{R[a]['bandas'][(f, 1)]} / {R[a]['bandas'][(f, 0)]}" for a in ARENAS) + " |")
    w("")
    w("| o que a contagem decide | " + " | ".join(NOMES[a] for a in ARENAS) + " |")
    w("| --- |" + " --- |" * len(ARENAS))
    w("| F1 e recall por faixa (≥ 30 positivos) | " + " | ".join(", ".join(D[a]["f1_recall_por_faixa"]) or "nenhuma" for a in ARENAS) + " |")
    w("| taxa de falso positivo por faixa (≥ 30 negativos) | " + " | ".join(", ".join(D[a]["fpr_por_faixa"]) or "nenhuma" for a in ARENAS) + " |")
    w("| V1 (≥ 30 negativos em até 46 e 340+) | " + " | ".join("se aplica" if D[a]["v1"] else "não se aplica" for a in ARENAS) + " |")
    w("| V2 (≥ 30 positivos em alguma faixa pequena) | " + " | ".join(
        D[a]["v2"].replace("nao", "não") + (f" (faixas: {', '.join(D[a]['v2_faixas'])})" if D[a]["v2"] == "se aplica" else "")
        for a in ARENAS) + " |")
    w("| veredito de tamanho | " + " | ".join(D[a]["veredito_tamanho"].replace("nao verificavel", "não verificável").replace("so ", "só ") for a in ARENAS) + " |")
    w("")
    w("## 5. Tokens fora do vocabulário (Word2Vec do treino, sem ajuste em dado de arena)")
    w("")
    w("| arena | tokens de nó calculados | fora do vocabulário | taxa |")
    w("| --- | --- | --- | --- |")
    w("| teste do BigVul (referência; o Word2Vec também não o viu) | 5.467.742 | 586.098 | 10,7% |")
    for a in ARENAS:
        o, t = R[a]["oov"]
        w(f"| {NOMES[a]} | {t} | {o} | {100 * o / max(t, 1):.1f}% |")
    w("")
    w("## 6. Arquivos de onde esta ficha saiu")
    w("")
    w("| arquivo | SHA-256 |")
    w("| --- | --- |")
    vistos = {}
    for a in ARENAS:
        vistos.update(R[a]["arquivos"])
    for k in sorted(vistos):
        w(f"| `arenas/{k}` | `{vistos[k]}` |")
    w(f"| Word2Vec do treino | `{va.sha256(os.path.join(va.C.VETORES, 'word2vec.model'))}` |")
    w("")
    w("## O que esta ficha NÃO é")
    w("")
    w("- não é resultado: nenhum modelo previu nenhuma função de arena até aqui;")
    w("- não traz a traversal pura (passo 4, depois desta ficha) nem as predições (passo 5).")
    saida = os.path.join(AQUI, "FICHA_PREPARACAO.md")
    open(saida, "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")
    print(f"gravada: {saida}\nSHA-256: {sha256(saida)}")


if __name__ == "__main__":
    main()
