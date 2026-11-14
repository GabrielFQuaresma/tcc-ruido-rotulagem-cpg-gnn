#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gera o gráfico do ruído por fan-out do commit (Seção 4.1), que substitui a antiga Tabela 2.

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/gerar_figura_fanout.py

ONDE ESTAMOS. Revisão do orientador (09/11/2026, PDF comentado, p. 9): "poderíamos ter um gráfico de
barras? barras sobrepostas (amostra/sítio) indicando a % do ruído?". O autor pediu as duas
orientações (vertical e horizontal) para escolher, no lugar da tabela, não junto com ela.

O QUE O SCRIPT FAZ. Confere o SHA-256 das duas fontes, refaz a conta do Dataset/bigvul/
tally_por_commit.py e escreve secoes/fig_fanout_vertical.tex e secoes/fig_fanout_horizontal.tex
(só o tikzpicture; a legenda fica no 04_resultados.tex). Por faixa de fan-out (número de funções
positivas que o commit de correção tem no recorte inteiro de 2957), a barra clara é o total de
funções da faixa na amostra anotada e a escura, sobreposta, as que são o local da vulnerabilidade
(categoria D da rubrica). O que sobra da barra clara é o ruído.

O QUE ELE NÃO É. Não é uma análise nova: os números são os da Tabela 2 que o texto já trazia
(7/5, 15/10, 27/6), e o script para se a conta não bater com eles. O fan-out vem do recorte
inteiro, e não da amostra (ver o docstring do tally_por_commit.py).
"""
import csv
import hashlib
import sys
from collections import Counter

import pandas as pd

BASE = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/"
POSITIVOS = BASE + "Dataset/bigvul/saida/bigvul_memoria_positivos.parquet"
AMOSTRA = BASE + "Dataset/bigvul/saida/amostra_validacao_revisao.csv"
HASH = {
    POSITIVOS: "4d8e401fbdf201e5388c1b640bffb25c769dd6f0b8f98beac6e13d4280daa333",
    AMOSTRA: "59d82a74d5116251ea67f4e3399d865ca4b5562023f8a21928b193203ad19e3c",
}
SAIDA = BASE + "Tex/secoes/fig_fanout_{}.tex"
ESPERADO = {"1": (7, 5), "2-4": (15, 10), "5+": (27, 6)}  # (na amostra, são o local)
FAIXAS = [("1", "1 função"), ("2-4", "2 a 4 funções"), ("5+", "5 ou mais funções")]

for caminho, esperado in HASH.items():
    with open(caminho, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    if h != esperado:
        sys.exit(f"SHA-256 divergente em {caminho} ({h}); nada foi gravado")


def faixa(n):
    return "1" if n <= 1 else ("2-4" if n <= 4 else "5+")


fan = pd.read_parquet(POSITIVOS).groupby("commit_id").size()
with open(AMOSTRA, encoding="utf-8-sig", newline="") as f:
    linhas = [l for l in csv.DictReader(f) if l["tipo_ruido"].strip().upper() in ("A", "B", "C", "D")]
total, local = Counter(), Counter()
for l in linhas:
    k = faixa(int(fan.get(l["commit_id"], 0)))
    total[k] += 1
    local[k] += l["tipo_ruido"].strip().upper() == "D"
contas = {k: (total[k], local[k]) for k in ESPERADO}
if contas != ESPERADO:
    sys.exit(f"contagens {contas} divergem das da Tabela 2 {ESPERADO}; nada foi gravado")


def pct(t, d):
    return f"{100 * (t - d) / t:.1f}".replace(".", ",")


MAIOR = max(t for t, _ in ESPERADO.values())
CABECALHO = [
    "% GERADO por Tex/gerar_figura_fanout.py a partir de saida/bigvul_memoria_positivos.parquet e",
    "% saida/amostra_validacao_revisao.csv (SHA-256 conferido). NÃO EDITAR À MÃO: rodar o script de novo.",
    "\\begin{tikzpicture}[font=\\footnotesize]",
]
# Cores (13/11/2026): a parte de baixo, em tccCorreto (azul), são as funções que são o local; a de
# cima, em tccRuido (laranja), o ruído. A altura total continua sendo o total da faixa na amostra.
LEGENDA = ("\\fill[tccCorreto] ({x},{y}) rectangle ++(0.35,0.22);"
           " \\node[anchor=west] at ({x2},{ym}) {{são o local da vulnerabilidade}};\n"
           "\\fill[tccRuido] ({x3},{y}) rectangle ++(0.35,0.22);"
           " \\node[anchor=west] at ({x4},{ym}) {{ruído (rótulo indevido)}};")


def vertical():
    alt, larg, passo = 3.6, 1.3, 2.9  # cm: altura da maior barra, largura, distância entre barras
    out = list(CABECALHO)
    out.append(f"\\draw[tccEixo] (-0.4,0) -- ({passo * 2 + larg + 0.4:.2f},0);")
    for i, (k, nome) in enumerate(FAIXAS):
        t, d = ESPERADO[k]
        x = i * passo
        ht, hd = alt * t / MAIOR, alt * d / MAIOR
        negrito = "\\bfseries" if k == "5+" else ""
        out.append(f"% faixa {k}: {d} de {t} são o local; ruído {pct(t, d)}%")
        out.append(f"\\fill[tccCorreto] ({x:.2f},0) rectangle ({x + larg:.2f},{hd:.3f});")
        out.append(f"\\fill[tccRuido] ({x:.2f},{hd:.3f}) rectangle ({x + larg:.2f},{ht:.3f});")
        out.append(f"\\draw[white, line width=1pt] ({x:.2f},{hd:.3f}) -- ({x + larg:.2f},{hd:.3f});")
        out.append(f"\\node[anchor=south, align=center] at ({x + larg / 2:.2f},{ht + 0.05:.3f}) "
                   f"{{{d} de {t}\\\\{{{negrito} ruído {pct(t, d)}\\%}}}};")
        out.append(f"\\node[anchor=north] at ({x + larg / 2:.2f},-0.08) {{{nome}}};")
    out.append(LEGENDA.format(x=-0.6, y=-0.95, x2=-0.2, ym=-0.84, x3=4.6, x4=5.0))
    out.append("\\end{tikzpicture}")
    return out


def horizontal():
    comp, alt_barra, passo = 8.0, 0.5, 0.8  # cm: comprimento da maior barra, espessura, entre barras
    out = list(CABECALHO)
    for i, (k, nome) in enumerate(FAIXAS):
        t, d = ESPERADO[k]
        y = -i * passo
        lt, ld = comp * t / MAIOR, comp * d / MAIOR
        negrito = "\\bfseries" if k == "5+" else ""
        out.append(f"% faixa {k}: {d} de {t} são o local; ruído {pct(t, d)}%")
        out.append(f"\\node[anchor=east] at (-0.15,{y:.2f}) {{{nome}}};")
        out.append(f"\\fill[tccCorreto] (0,{y - alt_barra / 2:.2f}) rectangle ({ld:.3f},{y + alt_barra / 2:.2f});")
        out.append(f"\\fill[tccRuido] ({ld:.3f},{y - alt_barra / 2:.2f}) rectangle ({lt:.3f},{y + alt_barra / 2:.2f});")
        out.append(f"\\draw[white, line width=1pt] ({ld:.3f},{y - alt_barra / 2:.2f}) -- ({ld:.3f},{y + alt_barra / 2:.2f});")
        out.append(f"\\node[anchor=west] at ({lt + 0.15:.3f},{y:.2f}) {{{d} de {t}, {{{negrito} ruído {pct(t, d)}\\%}}}};")
    ybase = -2 * passo - 0.75
    out.append(LEGENDA.format(x=0, y=f"{ybase:.2f}", x2=0.4, ym=f"{ybase + 0.11:.2f}", x3=5.2, x4=5.6))
    out.append("\\end{tikzpicture}")
    return out


for nome, linhas_tex in (("vertical", vertical()), ("horizontal", horizontal())):
    with open(SAIDA.format(nome), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(linhas_tex) + "\n")
    print("gravado", SAIDA.format(nome))
print("contagens conferidas:", contas)
