#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gera a Figura 3 do artigo (o gráfico da régua) direto dos resultados das aberturas.

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/gerar_figura_regua.py

ONDE ESTAMOS. Revisão do autor (item 46, decidido em 28/10/2026): a Tabela 3 da Seção 4.4 vira um
gráfico que mostra a régua de decisão. Em cada arena, a faixa entre o menor e o maior dos cinco
controles, os controles como pontos cinza e o curado como ponto preto, com o F1 (mediana das 30
repetições) escrito ao lado e a posição (acima, dentro, abaixo) à direita. O teste do BigVul entra
como primeira linha (escolha do autor, 29/10/2026).

O QUE O SCRIPT FAZ. Confere o SHA-256 dos dois arquivos de resultado contra os registrados nas
aberturas (os mesmos do gerar_tabelas_apendice.py); se algum divergir, para sem gravar nada. Lê as
medianas do desenho principal e a posição gravada na abertura, e escreve secoes/fig_regua.tex (só o
tikzpicture; a legenda fica no 04_resultados.tex). Os números saem com o mesmo deslocamento de
vírgula das tabelas (0,262 -> 26,2), sem arredondar de novo.

O QUE ELE NÃO É. Não calcula métrica nem posição. Rodar de novo dá o mesmo arquivo.
"""
import hashlib
import io
import json
import sys

BASE = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/"
SAIDA = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/secoes/fig_regua.tex"
HASHES = {
    "modelo/resultado_teste_bigvul.json": "f8ea66693ceac645cc1d9a7dd16aed5d08b45a4703f661519acc9bad63991402",
    "arenas/resultado_arenas.json": "34ff46c06ea6c08631af5b6417fd25b2a7b40162f0bc42ee9ede8ea15e9f92b0",
}
CTRL = ["M_ctrl_g2026", "M_ctrl_g2027", "M_ctrl_g2028", "M_ctrl_g2029", "M_ctrl_g2030"]
# Coluna da traversal pura à direita, como na antiga Tabela 3: o F1 dela fica escrito, sem entrar
# na escala (no VentiVul ela vale 12,2% e esmagaria a faixa). Escolha do autor, 29/10/2026: os
# números dela têm de ficar no corpo, porque o apêndice pode sair do artigo.
COM_TRAVERSAL = True

for rel, h in HASHES.items():
    with open(BASE + rel, "rb") as f:
        if hashlib.sha256(f.read()).hexdigest() != h:
            sys.exit(f"SHA-256 divergente em {rel}; nada foi gravado")
B = json.load(open(BASE + "modelo/resultado_teste_bigvul.json"))
A = json.load(open(BASE + "arenas/resultado_arenas.json"))


def num(x):
    return f"{x:.3f}".replace(".", ",")


def pct(x):
    inteira, frac = num(x).split(",")
    return f"{int(inteira + frac[:2])},{frac[2]}"


def linha(nome, rg, posicao, trav):
    return {"nome": nome, "cur": rg["M_cur"]["f1"]["mediana"],
            "ctrl": [rg[c]["f1"]["mediana"] for c in CTRL], "pos": posicao, "trav": trav}


LINHAS = [linha("Teste do BigVul", B["resumo_geral"], B["comparacoes"]["principal"]["posicao"],
                B["traversal_pura"]["f1"])]
for chave, nome in (("primevul", "PrimeVul"), ("ventivul_familia", "VentiVul"), ("sonda", "Sonda CWE-416")):
    r = A["arenas"][chave]
    LINHAS.append(linha(nome, r["resumo_geral"], r["desenhos"]["principal"]["posicao"], r["traversal_pura"]["f1"]))

X0, X1 = 3.0, 10.6       # eixo de cada linha, em cm
XPOS = 11.1              # coluna da posição
XTRAV = 13.5             # coluna da traversal (se ligada)
PASSO = 1.0              # distância vertical entre linhas, em cm

out = ["% GERADO por Tex/gerar_figura_regua.py a partir de modelo/resultado_teste_bigvul.json e",
       "% arenas/resultado_arenas.json (SHA-256 conferidos). NÃO EDITAR À MÃO: rodar o script de novo.",
       "\\begin{tikzpicture}[font=\\footnotesize]"]
if COM_TRAVERSAL:
    out.append(f"\\node[anchor=south west, font=\\scriptsize, text=gray!80!black] at ({XPOS},0.42) {{posição}};")
    out.append(f"\\node[anchor=south, font=\\scriptsize, text=gray!80!black] at ({XTRAV},0.42) {{\\textit{{traversal}} pura}};")
for i, L in enumerate(LINHAS):
    y = -i * PASSO
    valores = L["ctrl"] + [L["cur"]]
    lo, hi = min(valores), max(valores)
    folga = 0.12 * (hi - lo)
    lo, hi = lo - folga, hi + folga

    def x(v):
        return X0 + (v - lo) / (hi - lo) * (X1 - X0)
    cmin, cmax = min(L["ctrl"]), max(L["ctrl"])
    out.append(f"% {L['nome']}: curado {num(L['cur'])}; controles {', '.join(num(c) for c in L['ctrl'])}")
    out.append(f"\\node[anchor=west] at (0,{y:.2f}) {{{L['nome']}}};")
    out.append(f"\\draw[gray!55] ({X0:.2f},{y:.2f}) -- ({X1:.2f},{y:.2f});")
    out.append(f"\\fill[gray!22] ({x(cmin):.3f},{y - 0.13:.2f}) rectangle ({x(cmax):.3f},{y + 0.13:.2f});")
    for c in L["ctrl"]:
        out.append(f"\\fill[gray!65] ({x(c):.3f},{y:.2f}) circle (1.7pt);")
    out.append(f"\\fill[black] ({x(L['cur']):.3f},{y:.2f}) circle (2.7pt);")
    out.append(f"\\node[anchor=north, font=\\scriptsize, text=gray!80!black] at ({x(cmin):.3f},{y - 0.16:.2f}) {{{pct(cmin)}}};")
    out.append(f"\\node[anchor=north, font=\\scriptsize, text=gray!80!black] at ({x(cmax):.3f},{y - 0.16:.2f}) {{{pct(cmax)}}};")
    out.append(f"\\node[anchor=south, font=\\scriptsize\\bfseries] at ({x(L['cur']):.3f},{y + 0.12:.2f}) {{{pct(L['cur'])}}};")
    out.append(f"\\node[anchor=west, font=\\footnotesize\\itshape] at ({XPOS},{y:.2f}) {{{L['pos']}}};")
    if COM_TRAVERSAL:
        out.append(f"\\node[anchor=center] at ({XTRAV},{y:.2f}) {{{pct(L['trav'])}\\%}};")
out.append("\\end{tikzpicture}")

with io.open(SAIDA, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out) + "\n")
print("gravado", SAIDA, f"({len(LINHAS)} linhas; traversal {'ligada' if COM_TRAVERSAL else 'desligada'})")
for L in LINHAS:
    print(f"  {L['nome']:16s} curado {pct(L['cur'])}  controles {pct(min(L['ctrl']))}-{pct(max(L['ctrl']))}  "
          f"{L['pos']:7s} traversal {pct(L['trav'])}")
