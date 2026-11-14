#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gera a figura das épocas de treino da GGNN (Apêndice C) direto dos históricos do treino.

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/gerar_figura_epocas.py

ONDE ESTAMOS. Revisão do autor (item 46, decidido em 28/10/2026): um gráfico de quantas épocas cada
modelo treinou, no apêndice. Só o desenho principal (escolha do autor, 29/10/2026).

O QUE O SCRIPT FAZ. Lê ~/curadoria/modelo/ggnn/<braço>/historico.tsv, gravado pelo
modelo/treinar_ggnn.py ao fim de cada época (coluna f1_val: F1 da GGNN na partição de validação, no
limiar de 0,5), e escreve secoes/fig_epocas.tex (um gráfico pgfplots). Esses históricos não têm
SHA-256 registrado em nenhum congelamento; o script grava o SHA-256 de cada um no cabeçalho do
arquivo gerado, para a figura poder ser conferida depois. A época guardada é a de maior F1 na
validação (a primeira, se houver empate), como no treinar_ggnn.py.

O QUE ELE NÃO É. Não é análise nova: só desenha o que o treino gravou. Não decide nada.
"""
import hashlib
import io
import os

BASE = os.path.expanduser("~/curadoria/modelo/ggnn")
SAIDA = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/secoes/fig_epocas.tex"
CTRL = ["M_ctrl_g2026", "M_ctrl_g2027", "M_ctrl_g2028", "M_ctrl_g2029", "M_ctrl_g2030"]
BRACOS = CTRL + ["M_raw", "M_cur"]   # o curado por último, para ficar por cima no desenho


def ler(braco):
    cam = os.path.join(BASE, braco, "historico.tsv")
    with open(cam, "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    linhas = [ln.rstrip("\n").split("\t") for ln in io.open(cam, encoding="utf-8")]
    cab = linhas[0]
    ie, i1 = cab.index("epoca"), cab.index("f1_val")
    pts = [(int(d[ie]), float(d[i1])) for d in linhas[1:] if d and d[0]]
    melhor = max(range(len(pts)), key=lambda i: (pts[i][1], -i))
    return {"pts": pts, "melhor": pts[melhor], "sha": h, "n": len(pts)}


H = {b: ler(b) for b in BRACOS}


def coords(pts):
    return " ".join(f"({e},{100 * f:.2f})" for e, f in pts)


ESTILO = {"ctrl": "tccControle!70, thin", "M_raw": "tccBruto, densely dashed, thin", "M_cur": "tccCurado, semithick"}
out = ["% GERADO por Tex/gerar_figura_epocas.py a partir de ~/curadoria/modelo/ggnn/<braço>/historico.tsv.",
       "% NÃO EDITAR À MÃO: rodar o script de novo. SHA-256 dos históricos lidos:"]
out += [f"%   {b}: {H[b]['sha']}" for b in BRACOS]
out += ["\\begin{tikzpicture}",
        "\\begin{axis}[width=\\linewidth, height=5.2cm, xmin=0, ymin=0, font=\\footnotesize,",
        "  xlabel={Época}, ylabel={F1 na validação (\\%)}, tick label style={font=\\scriptsize},",
        "  /pgf/number format/use comma, legend cell align=left,",
        "  legend style={draw=none, fill=white, fill opacity=0.85, text opacity=1, font=\\scriptsize,"
        " at={(0.99,0.98)}, anchor=north east}]"]
primeiro_ctrl = True
for b in BRACOS:
    est = ESTILO["ctrl"] if b in CTRL else ESTILO[b]
    out.append(f"\\addplot[{est}] coordinates {{{coords(H[b]['pts'])}}};")
    if b in CTRL:
        out.append("\\addlegendentry{Controles}" if primeiro_ctrl else "")
        if not primeiro_ctrl:
            out[-2] = out[-2].replace("\\addplot[", "\\addplot[forget plot, ", 1)
        primeiro_ctrl = False
    else:
        out.append("\\addlegendentry{" + ("Curado" if b == "M_cur" else "Bruto") + "}")
for b in BRACOS:
    cor = "tccControle" if b in CTRL else ("tccBruto" if b == "M_raw" else "tccCurado")
    e, f = H[b]["melhor"]
    out.append(f"\\addplot[forget plot, only marks, mark=*, mark size=1.5pt, {cor}] coordinates {{({e},{100 * f:.2f})}};")
out += ["\\end{axis}", "\\end{tikzpicture}"]
out = [ln for ln in out if ln != ""]

with io.open(SAIDA, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out) + "\n")
print("gravado", SAIDA)
for b in BRACOS:
    e, f = H[b]["melhor"]
    print(f"  {b:14s} épocas {H[b]['n']:4d}  guardada a {e:4d}  F1 val {100 * f:.1f}%")
