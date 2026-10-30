#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Confere a abertura refeita das arenas (21/10/2026) contra a original (18/10/2026).

    python3 comparar_refeito.py

O QUE E. Em 21/10 a abertura foi refeita com --refazer (PREREGISTRO_ARENAS.md, §10 passo 8), so para
corrigir a conta do excesso sobre o acaso (Decisao J: o acaso usa todas as funcoes da arena, nao so as
nao vulneraveis). Este script prova que nada mais mudou: compara os dois JSON campo a campo, ignorando
so os campos de excesso e a data, e imprime o excesso nas duas versoes e o veredito do piso. So le.
"""
import json
import os

AQUI = os.path.dirname(os.path.abspath(__file__))
ANTERIOR = os.path.join(AQUI, "resultado_arenas_anterior_20261021_123410.json")
NOVO = os.path.join(AQUI, "resultado_arenas.json")


def diferencas(a, b, caminho=""):
    """Lista os caminhos em que a e b diferem, ignorando qualquer chave 'excesso*' e 'gerado'."""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k.startswith("excesso") or k == "gerado":
                continue
            if k not in a or k not in b:
                out.append(f"{caminho}/{k}: so existe em uma das versoes")
                continue
            out += diferencas(a[k], b[k], f"{caminho}/{k}")
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{caminho}: tamanhos {len(a)} e {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            out += diferencas(x, y, f"{caminho}[{i}]")
    elif a != b:
        out.append(f"{caminho}: {a!r} -> {b!r}")
    return out


A = json.load(open(ANTERIOR, encoding="utf-8"))
B = json.load(open(NOVO, encoding="utf-8"))
d = diferencas(A, B)
print(f"diferencas fora do excesso e da data: {len(d)}")
for linha in d[:20]:
    print("  ", linha)
for nome in B["arenas"]:
    ea, eb = A["arenas"][nome]["excesso_principal"], B["arenas"][nome]["excesso_principal"]
    print(f"== {nome}: piso antes {A['arenas'][nome]['piso']} | piso agora {B['arenas'][nome]['piso']}")
    for braco in eb:
        print(f"   {braco:13s} {ea[braco]:8.2f} -> {eb[braco]:8.2f}")
    ra = A["arenas"][nome]["resumo_geral"]["M_raw"]["excesso"]["mediana"]
    rb = B["arenas"][nome]["resumo_geral"]["M_raw"]["excesso"]["mediana"]
    print(f"   {'M_raw':13s} {ra:8.2f} -> {rb:8.2f}")
print("sintese antes:", A["sintese"][:2], "| agora:", B["sintese"][:2])
