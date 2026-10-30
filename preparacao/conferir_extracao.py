#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Confere o resultado da extracao de arquivos e produz os numeros que vao para o
texto do TCC.

Nao basta contar quantos downloads deram 200. O que importa para o pipeline e se
o arquivo baixado serve para gerar um CPG util: precisa ser codigo de verdade
(nao uma pagina de erro), precisa conter a funcao que o BigVul marcou e precisa
ser a versao ANTERIOR a correcao.

Uso:
    python3 conferir_extracao.py --dir saida_full
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from buscar_arquivo import detectar, nome_da_funcao

EXT_CODIGO = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")


def linha(titulo):
    print(f"\n{'=' * 66}\n{titulo}\n{'=' * 66}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="saida_full")
    ap.add_argument("--mostrar-falhas", type=int, default=10)
    args = ap.parse_args()

    itens = os.path.join(args.dir, "itens")
    rel = pd.read_csv(os.path.join(args.dir, "relatorio_extracao.csv"))
    n = len(rel)

    linha("1. COBERTURA")
    ok = rel["status_download"].astype(str).str.startswith("ok").sum()
    forte = (rel["status_download"] == "ok").sum()
    print(f"  itens processados ................ {n}")
    print(f"  com arquivo baixado ............. {ok:5d}  ({100*ok/n:.1f}%)")
    print(f"    dos quais com funcao confirmada  {forte:5d}  ({100*forte/n:.1f}%)")
    print(f"  sem arquivo ..................... {n-ok:5d}  ({100*(n-ok)/n:.1f}%)")

    linha("2. POR STATUS")
    for k, v in rel["status_download"].value_counts().items():
        print(f"  {str(k):28s} {v:5d}  ({100*v/n:.1f}%)")

    linha("3. POR FAMILIA DE FORGE")
    # A familia e derivada do codeLink, nao lida da coluna: o modo --retomar pode
    # ter regravado meta.json sem esse campo, e a derivacao e barata e nao usa rede.
    fam = rel["codelink"].map(lambda u: detectar(u)[0] or "(nao detectada)")
    gravada = rel["familia"].fillna("")
    fam = fam.where(~gravada.str.contains("espelho", na=False), "github (espelho)")
    for k, v in fam.value_counts().items():
        sub = rel[fam == k]
        taxa = sub["status_download"].astype(str).str.startswith("ok").mean()
        print(f"  {str(k):22s} {v:5d} itens   sucesso {100*taxa:5.1f}%")

    linha("4. ORIGEM DO CAMINHO DO ARQUIVO")
    for k, v in rel["origem_paths"].fillna("(nenhuma)").value_counts().items():
        print(f"  {str(k):22s} {v:5d}  ({100*v/n:.1f}%)")

    linha("5. SANIDADE DOS ARQUIVOS BAIXADOS")
    tam, html, sem_func, nao_codigo, vazios = [], 0, 0, 0, 0
    checados = 0
    for d in sorted(os.listdir(itens)):
        p = os.path.join(itens, d)
        mj = os.path.join(p, "meta.json")
        if not os.path.exists(mj):
            continue
        meta = json.load(open(mj, encoding="utf-8"))
        # Procura o arquivo no disco em vez de confiar no campo do meta, que o
        # modo --retomar pode nao ter preenchido.
        nomes = [x for x in os.listdir(p) if x.startswith("arquivo__")]
        if not nomes:
            continue
        caminho = os.path.join(p, meta.get("arquivo_inteiro") or nomes[0])
        if not os.path.exists(caminho):
            caminho = os.path.join(p, nomes[0])
        try:
            conteudo = open(caminho, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        tam.append(len(conteudo))
        if len(conteudo) < 200:
            vazios += 1
        ini = conteudo[:400].lower()
        if "<!doctype html" in ini or "<html" in ini:
            html += 1
        ref = str(meta.get("caminho_no_repo") or os.path.basename(caminho))
        if not ref.lower().endswith(EXT_CODIGO):
            nao_codigo += 1
        func = open(os.path.join(p, "func_before.c"), encoding="utf-8",
                    errors="replace").read()
        alvo = nome_da_funcao(func)
        if alvo:
            checados += 1
            if alvo not in conteudo:
                sem_func += 1

    s = pd.Series(tam)
    print(f"  arquivos no disco ............... {len(tam)}")
    if len(tam):
        print(f"  tamanho (bytes) ................. min {s.min()}  "
              f"mediana {int(s.median())}  max {s.max()}")
        print(f"  soma ............................ {s.sum()/1e6:.1f} MB")
    print(f"  suspeitos de pagina HTML ........ {html}")
    print(f"  menores que 200 bytes ........... {vazios}")
    print(f"  extensao nao e de codigo ........ {nao_codigo}")
    print(f"  contem a funcao marcada ......... {checados-sem_func}/{checados}"
          f"  ({100*(checados-sem_func)/max(checados,1):.1f}%)")

    linha("6. FALHAS, POR PROJETO")
    falhas = rel[~rel["status_download"].astype(str).str.startswith("ok")]
    if len(falhas) == 0:
        print("  nenhuma.")
    else:
        for k, v in falhas["project"].value_counts().head(15).items():
            print(f"  {str(k):22s} {v}")
        print(f"\n  primeiros {args.mostrar_falhas} casos:")
        for _, r in falhas.head(args.mostrar_falhas).iterrows():
            print(f"    id={r['id']:5d} {str(r['project'])[:14]:14s} "
                  f"{r['status_download']:22s} {str(r.get('codelink'))[:60]}")

    linha("7. O QUE ISSO SIGNIFICA PARA O PROXIMO PASSO")
    print(f"  {ok} arquivos prontos para o Joern gerar CPG.")
    print(f"  {forte} deles com a funcao marcada confirmada dentro do arquivo,")
    print("  que sao os que podem entrar na curadoria sem conferencia manual.")
    if len(falhas):
        print(f"  {len(falhas)} itens ficam de fora e devem ser declarados nas")
        print("  Ameacas a Validade como perda de cobertura da reconstrucao.")


if __name__ == "__main__":
    main()
