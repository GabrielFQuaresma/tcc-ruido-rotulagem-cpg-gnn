#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hash do corpo de TODAS as linhas do BigVul (all_c_cpp_release2.0.csv), para a deduplicacao.

O QUE E, situando
-----------------
Preparacao das arenas externas, passo 3 (PREREGISTRO_ARENAS.md §10), deduplicacao (Decisao H).
Duas coisas precisam do corpo de funcoes do BigVul que ainda nao tinham hash:
  - a referencia da dedup ESTRITA do PrimeVul: o BigVul INTEIRO (todas as 188.636 linhas, todas as
    CWEs e particoes), "o corpo pelo func_before do all_c_cpp_release2.0.csv" (Decisao H);
  - o lado da ARENA da sonda CWE-416, que e o proprio BigVul.
Ate aqui so os negativos do split (32.479) e os positivos (2957) tinham hash.

O hash e o `hash_corpo` do traversal/normalizar_corpo.py (sem comentarios, espacos colapsados) —
importado, nao copiado: se os dois lados normalizassem diferente, a diferenca viria da
normalizacao e nao do dado. E o mesmo `sha1_corpo_sc` dos arquivos do split.

CONFERENCIA EMBUTIDA: para as 32.479 linhas que ja tinham hash (split/negativos_hash_sc.tsv), o
hash recalculado aqui tem de ser identico. Se uma divergir, o script avisa e sai com erro.

LEITURA EM BLOCOS: o CSV e um ZIP de 1,5 GB com codigo inteiro em quatro colunas; carregar tudo
derrubou o WSL tres vezes (_extrair_indice.py). Le-se so `func_before`, em blocos, na mesma ordem
do indice_bigvul.csv (a linha_indice e a posicao, contando de 0).

Saida: ~/curadoria/arenas/bigvul_hash_sc.tsv (linha_indice, sha1_corpo_sc). Idempotente: se a
saida ja existe completa, nao faz nada. Nenhum modelo.
"""
import csv
import os
import sys
import time
from multiprocessing import Pool

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
sys.path.insert(0, os.path.join(BV, "traversal"))
from normalizar_corpo import hash_corpo  # noqa: E402

CSV_COMPLETO = os.path.join(BV, "all_c_cpp_release2.0.csv")
NEG_HASH = os.path.join(BV, "traversal", "split", "negativos_hash_sc.tsv")
SAIDA = os.path.expanduser("~/curadoria/arenas/bigvul_hash_sc.tsv")
TOTAL = 188636


def log(*a):
    print(*a, flush=True)


def main():
    if os.path.exists(SAIDA):
        n = sum(1 for _ in open(SAIDA)) - 1
        if n == TOTAL:
            log(f"ja existe completo ({n} linhas): {SAIDA}")
            return conferir()
        log(f"existe incompleto ({n} linhas); refazendo")
    os.makedirs(os.path.dirname(SAIDA), exist_ok=True)
    parcial = SAIDA + ".parcial"
    t0 = time.time()
    linha = 0
    with open(parcial, "w", encoding="utf-8") as out, Pool(4) as pool:
        out.write("linha_indice\tsha1_corpo_sc\n")
        leitor = pd.read_csv(CSV_COMPLETO, compression="zip", encoding="latin-1",
                             usecols=["func_before"], chunksize=2000, dtype=str)
        for bloco in leitor:
            hs = pool.map(hash_corpo, bloco["func_before"].fillna("").tolist(), chunksize=100)
            for h in hs:
                out.write(f"{linha}\t{h}\n")
                linha += 1
            if linha % 20000 < 2000:
                log(f"  {linha} linhas, {time.time() - t0:.0f} s")
    if linha != TOTAL:
        log(f"ERRO: {linha} linhas lidas, esperado {TOTAL}")
        sys.exit(1)
    os.replace(parcial, SAIDA)
    log(f"pronto: {linha} linhas em {time.time() - t0:.0f} s")
    conferir()


def conferir():
    meu = {}
    for r in csv.DictReader(open(SAIDA, encoding="utf-8"), delimiter="\t"):
        meu[int(r["linha_indice"])] = r["sha1_corpo_sc"]
    iguais = difs = 0
    for r in csv.DictReader(open(NEG_HASH, encoding="utf-8"), delimiter="\t"):
        if meu.get(int(r["linha_indice"])) == r["sha1_corpo_sc"]:
            iguais += 1
        else:
            difs += 1
    log(f"conferencia contra split/negativos_hash_sc.tsv: {iguais} iguais, {difs} diferentes")
    vazios = sum(1 for h in meu.values() if not h)
    log(f"linhas com corpo vazio (sem hash): {vazios}")
    if difs:
        sys.exit(1)


if __name__ == "__main__":
    main()
