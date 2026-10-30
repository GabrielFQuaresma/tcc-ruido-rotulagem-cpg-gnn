#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grava o hash do corpo de cada POSITIVO — a Fase 1 da traversal v3 (TRAVERSAL_V3.md).

POR QUE, situando
-----------------
O hash do corpo e a impressao digital do texto de uma funcao. Ele serve para descobrir, entre
varias funcoes com o mesmo nome no mesmo arquivo, qual e a que o BigVul rotulou: compara-se o
hash do `func_before` com o hash do trecho de cada candidata recortado do arquivo-fonte.

Os negativos ja tinham hash desde 21/09 (`negativos_nomes.tsv` e `negativos_hash_sc.tsv`). Os
positivos nao — entraram na montagem do dataset com `shas: []`, e 157 positivos de treino com
homonimo ficaram sem grafo (PERDA_BRACOS.md). Este script fecha esse buraco.

O QUE GRAVA: `split/positivos_hash.tsv`, uma linha por positivo do split (os 2957), com os MESMOS
dois hashes do lado negativo e as MESMAS colunas:
  sha1_corpo     — espacos colapsados (como `negativos_nomes.tsv`)
  sha1_corpo_sc  — sem comentarios, espacos colapsados (como `negativos_hash_sc.tsv`)
Calculados por `normalizar_corpo.hash_corpo`, o mesmo modulo do lado do arquivo-fonte —
importado, nao copiado.

DE ONDE VEM O TEXTO: `saida_final/itens/<item>/func_before.c`, o mesmo arquivo de onde o
`rodar_curadoria.py` tira o nome da funcao. Assim curadoria e hash olham o mesmo texto.

O QUE NAO FAZ: nao escolhe metodo, nao toca no dataset nem na curadoria. So grava hash.

Uso (no WSL):
  python3 extrair_hash_positivos.py              # autoteste + grava o TSV
  python3 extrair_hash_positivos.py --conferir   # e confere contra a revisao de 05/10
"""

import argparse
import csv
import glob
import json
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from normalizar_corpo import hash_corpo, hashes_do_texto, recortar_linhas  # noqa: E402

ITENS = os.path.join(os.path.dirname(AQUI), "saida_final", "itens")
POSITIVOS = os.path.join(AQUI, "split", "positivos.tsv")
SAIDA = os.path.join(AQUI, "split", "positivos_hash.tsv")


def log(*a):
    print(*a, flush=True)


def autoteste():
    """As duas pecas que a Fase 1 mudou. Se uma delas estiver errada, tudo abaixo mede errado."""
    ok = True
    # 1. recortar_linhas conta linha so por '\n' — o form feed NAO abre linha nova.
    texto = "linha1\nlinha2 \f com form feed\nlinha3"
    if recortar_linhas(texto, 3, 3) != "linha3":
        log("AUTOTESTE FALHOU: recortar_linhas(…, 3, 3) = %r" % recortar_linhas(texto, 3, 3))
        ok = False
    if texto.splitlines()[2] == "linha3":
        log("AUTOTESTE FALHOU: o caso de teste nao reproduz o problema do splitlines()")
        ok = False
    # 2. hashes_do_texto devolve exatamente os dois hashes gravados aqui.
    corpo = "int f(int a) { // nota\n  return a; }"
    esperado = {hash_corpo(corpo, tirar_comentarios=False), hash_corpo(corpo)}
    if hashes_do_texto(corpo) != esperado or len(esperado) != 2:
        log("AUTOTESTE FALHOU: hashes_do_texto difere dos dois hashes gravados")
        ok = False
    if ok:
        log("autoteste: ok (recorte por '\\n' e os dois hashes)")
    return ok


def gravar():
    itens = [r["item"] for r in csv.DictReader(open(POSITIVOS, encoding="utf-8"), delimiter="\t")]
    sem_texto = []
    with open(SAIDA, "w", encoding="utf-8", newline="") as fh:
        fh.write("item\tsha1_corpo\tsha1_corpo_sc\n")
        for item in itens:
            caminho = os.path.join(ITENS, item, "func_before.c")
            if not os.path.exists(caminho):
                sem_texto.append(item)
                fh.write("%s\t\t\n" % item)
                continue
            txt = open(caminho, encoding="utf-8", errors="replace").read()
            fh.write("%s\t%s\t%s\n" % (item, hash_corpo(txt, tirar_comentarios=False),
                                      hash_corpo(txt)))
    log("positivos no split: %d | sem func_before.c: %d %s"
        % (len(itens), len(sem_texto), sem_texto[:5]))
    log("gravado: %s" % SAIDA)
    return itens


def conferir():
    """Refaz, com o TSV recem-gravado e as funcoes centralizadas, dois numeros da revisao de
    05/10 (HANDOFF_2026-10-04.md, secao 8). Se nao baterem, a funcao mudou de comportamento."""
    import montar_dataset as md   # aqui dentro: montar_dataset importa normalizar_corpo

    hashes = {}
    for r in csv.DictReader(open(SAIDA, encoding="utf-8"), delimiter="\t"):
        hashes[r["item"]] = {h for h in (r["sha1_corpo"], r["sha1_corpo_sc"]) if h}

    # (a) os 183 com colisao: quantos homonimos o hash aponta (revisao: 176 recuperaveis, 7 nao)
    rec, iguais_faixa = {"recuperavel": 0, "nenhum_casa": 0, "empate": 0}, 0
    linhas_rec = []
    for nome_tsv in ("_recuperabilidade_hash.tsv", "_recuperabilidade_hash_avaliacao.tsv"):
        linhas_rec += list(csv.DictReader(open(os.path.join(AQUI, nome_tsv), encoding="utf-8"),
                                          delimiter="\t"))
    for r in linhas_rec:
        cont = json.load(open(os.path.expanduser("~/curadoria/_diag_perda/%s.json" % r["arquivo"]),
                              encoding="utf-8"))
        faixas = [tuple(int(x) for x in f.split("-")) for f in cont[r["nome"]][3].split(",") if f]
        pasta = os.path.join(md.CACHE_CPG, r["item"])
        casam = [f for f in faixas if hashes[r["item"]] & md.hashes_do_metodo(pasta, f[0], f[1])]
        classe = "recuperavel" if len(casam) == 1 else ("nenhum_casa" if not casam else "empate")
        rec[classe] += 1
        if classe == r["classe"] and (classe != "recuperavel" or "%d-%d" % casam[0] == r["faixa"]):
            iguais_faixa += 1
    log()
    log("(a) 183 com colisao: %s | mesma classe e mesma faixa da revisao: %d de %d"
        % (rec, iguais_faixa, len(linhas_rec)))

    # (b) os 2366 de definicao unica com grafo: em quantos o hash casa (revisao: 1687)
    casa = total = 0
    for p in glob.glob(os.path.join(md.GRUPOS, "*.jsonl")):
        for l in open(p, encoding="utf-8"):
            if not l.strip():
                continue
            g = json.loads(l)
            if g["rotulo"] != 1:
                continue
            total += 1
            pasta = os.path.join(md.CACHE_CPG, g["id"])
            if hashes[g["id"]] & md.hashes_do_metodo(pasta, g["linha_inicio"], g["linha_fim"]):
                casa += 1
    log("(b) %d positivos com grafo: o hash casa em %d" % (total, casa))

    ok = (rec == {"recuperavel": 176, "nenhum_casa": 7, "empate": 0}
          and iguais_faixa == len(linhas_rec) == 183 and total == 2366 and casa == 1687)
    log()
    log("CONFERENCIA: %s" % ("ok — reproduz a revisao de 05/10" if ok else
                             "DIVERGIU da revisao de 05/10 — parar e investigar"))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conferir", action="store_true")
    args = ap.parse_args()
    if not autoteste():
        return 1
    gravar()
    if args.conferir and not conferir():
        return 1
    return 0


if __name__ == "__main__":
    import traceback
    try:
        codigo = main()
    except BaseException:
        log("=== FALHOU ===")
        log(traceback.format_exc())
        codigo = 1
    sys.exit(codigo)
