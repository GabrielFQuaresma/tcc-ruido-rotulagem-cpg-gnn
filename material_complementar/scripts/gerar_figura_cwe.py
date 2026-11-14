#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gera a figura de barras com a composição do recorte por CWE (Seção 3.2).

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/gerar_figura_cwe.py

ONDE ESTAMOS. Revisão do orientador (04-09/11/2026, PDF comentado): pediu um gráfico com as
porcentagens de CWE no recorte de 2957 positivos, hoje só em prosa na Seção 3.2.

O QUE O SCRIPT FAZ. Confere o SHA-256 de saida_final/indice_bigvul.csv contra o registrado nas
aberturas. Conta, por CWE, as linhas com vul=1 dentro das quatro CWEs do recorte (CWE-119, 120,
125, 787) e escreve secoes/fig_cwe.tex (só o tikzpicture; a legenda fica no 03_metodologia.tex).

O QUE ELE NÃO É. Não decide o recorte (as quatro CWEs vêm da Seção 3.2). Rodar de novo dá o mesmo
arquivo, contanto que o índice não mude.
"""
import csv
import hashlib
import io
import sys

BASE = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/"
CSV = BASE + "saida_final/indice_bigvul.csv"
SAIDA = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/secoes/fig_cwe.tex"
HASH_ESPERADO = "c4df450507614524dec1781b9f567badc10eaab687f57cd1e17b975429008486"
ALVO = ["CWE-119", "CWE-125", "CWE-787", "CWE-120"]  # ordem do texto da 3.2, maior para menor

with open(CSV, "rb") as f:
    h = hashlib.sha256(f.read()).hexdigest()
    if h != HASH_ESPERADO:
        sys.exit(f"SHA-256 divergente em indice_bigvul.csv ({h}); nada foi gravado")

contagem = {c: 0 for c in ALVO}
total = 0
with open(CSV, encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f):
        if row["vul"] != "1":
            continue
        cwe = row["CWE ID"].strip()
        if cwe in contagem:
            contagem[cwe] += 1
            total += 1

if total != 2957:
    sys.exit(f"total {total} diverge dos 2957 esperados; nada foi gravado")


def pct(n):
    return f"{100 * n / total:.1f}".replace(".", ",")


LARGURA = 9.0  # cm, para 71,9%
ALTURA_BARRA = 0.55
PASSO = 0.85

out = [
    "% GERADO por Tex/gerar_figura_cwe.py a partir de saida_final/indice_bigvul.csv",
    "% (SHA-256 conferido). NÃO EDITAR À MÃO: rodar o script de novo.",
    "\\begin{tikzpicture}[font=\\footnotesize]",
]
for i, cwe in enumerate(ALVO):
    n = contagem[cwe]
    p = n / total
    y = -i * PASSO
    largura = LARGURA * p / (contagem[ALVO[0]] / total)
    out.append(f"% {cwe}: {n} de {total} ({pct(n)}\\%)")
    out.append(f"\\node[anchor=east, text width=1.6cm, align=right] at (-0.15,{y:.2f}) {{{cwe}}};")
    out.append(f"\\fill[tccDado] (0,{y - ALTURA_BARRA / 2:.2f}) rectangle ({largura:.3f},{y + ALTURA_BARRA / 2:.2f});")
    out.append(f"\\node[anchor=west, font=\\footnotesize\\bfseries] at ({largura + 0.15:.3f},{y:.2f}) {{{pct(n)}\\% ({n})}};")
out.append("\\end{tikzpicture}")

with io.open(SAIDA, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out) + "\n")
print("gravado", SAIDA, f"(total {total})")
for cwe in ALVO:
    print(f"  {cwe}: {contagem[cwe]} ({pct(contagem[cwe])}%)")
