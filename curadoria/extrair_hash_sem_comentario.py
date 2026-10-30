#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grava um SEGUNDO hash de corpo dos negativos, agora sem comentarios.

POR QUE, situando
-----------------
O `negativos_nomes.tsv` (NEGATIVOS.md, 21/09) guarda `sha1_corpo`: hash do `func_before` com
espacos colapsados. Ele serve para desempatar funcoes homonimas comparando com o corpo do
metodo no CPG — e foi medido que, do jeito que esta, ele quase nunca bate, por um motivo que
nao e "funcao diferente": **o `func_before` do BigVul vem sem comentario de linha (`//`) e o
arquivo-fonte baixado tem**. Diagnostico em `_diag_hash.py`.

Este script faz uma segunda passada e grava o hash com comentario REMOVIDO dos dois tipos,
usando o `normalizar_corpo.py` — o mesmo modulo que o lado do CPG usa, importado e nao copiado.

NAO SOBRESCREVE o `negativos_nomes.tsv`. Ele e o artefato registrado no NEGATIVOS.md e os
numeros daquele registro (28.578 usaveis etc.) dependem dele. A saida vai para um arquivo
proprio, `split/negativos_hash_sc.tsv`, que casa pela mesma chave `linha_indice`.

MEMORIA: mesma disciplina do extrair_nomes_negativos.py — blocos pequenos, so as colunas
necessarias, nada acumulado.

Idempotente: --retomar pula linha ja gravada.

Uso:
  python3 extrair_hash_sem_comentario.py
  python3 extrair_hash_sem_comentario.py --retomar
"""

import argparse
import csv
import os
import sys
import time

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from normalizar_corpo import hash_corpo, sem_comentarios   # noqa: E402

BIGVUL = os.path.dirname(AQUI)
CSV_COMPLETO = os.path.join(BIGVUL, "all_c_cpp_release2.0.csv")
NEGATIVOS = os.path.join(AQUI, "split", "negativos.tsv")
SAIDA = os.path.join(AQUI, "split", "negativos_hash_sc.tsv")


def log(*a):
    print(*a, flush=True)


def autoteste():
    """Se a maquina de estados estiver errada, tudo abaixo mede a coisa errada."""
    casos = [
        ('int f(){ // nota\n return 1; }', 'int f(){ return 1; }'),
        ('int f(){ /* nota */ return 1; }', 'int f(){ return 1; }'),
        ('char*u(){ return "http://x"; }', 'char*u(){ return "http://x"; }'),
        ("char c(){ return '/'; }", "char c(){ return '/'; }"),
        ('char*s(){ return "a/*b"; }', 'char*s(){ return "a/*b"; }'),
        ('int f(){ return 1; } // fim', 'int f(){ return 1; }'),
    ]
    from normalizar_corpo import normalizar
    for entrada, esperado in casos:
        obtido = normalizar(sem_comentarios(entrada))
        if obtido != normalizar(esperado):
            log("AUTOTESTE FALHOU")
            log("  entrada : %r" % entrada)
            log("  esperado: %r" % normalizar(esperado))
            log("  obtido  : %r" % obtido)
            return False
    log("autoteste do removedor de comentario: ok (%d casos)" % len(casos))
    return True


def ler_pedidos():
    pedidos = set()
    with open(NEGATIVOS, encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            pedidos.add(int(r["linha_indice"]))
    return pedidos


def ler_feitos():
    if not os.path.exists(SAIDA):
        return set()
    feitos = set()
    with open(SAIDA, encoding="utf-8") as fh:
        cab = fh.readline()
        if not cab.startswith("linha_indice\t"):
            return set()
        for linha in fh:
            if linha.strip():
                feitos.add(int(linha.split("\t", 1)[0]))
    return feitos


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--retomar", action="store_true")
    ap.add_argument("--blocos", type=int, default=1000)
    args = ap.parse_args()

    if not autoteste():
        return 1

    pedidos = ler_pedidos()
    log("negativos pedidos pelo split: %d" % len(pedidos))
    feitos = ler_feitos() if args.retomar else set()
    faltam = pedidos - feitos
    if not faltam:
        log("nada a fazer — todos ja estao em %s" % SAIDA)
        return 0
    log("faltam: %d" % len(faltam))

    modo = "a" if (args.retomar and os.path.exists(SAIDA)) else "w"
    saida = open(SAIDA, modo, encoding="utf-8", newline="")
    if modo == "w":
        saida.write("linha_indice\tsha1_corpo_sc\n")

    t0 = time.time()
    linha_global = 0
    gravados = 0
    restam = set(faltam)
    leitor = pd.read_csv(CSV_COMPLETO, compression="zip", encoding="latin-1",
                         usecols=["func_before"], chunksize=args.blocos, dtype=str)
    for bloco in leitor:
        inicio = linha_global
        linha_global += len(bloco)
        alvos = [i for i in range(inicio, linha_global) if i in restam]
        if alvos:
            corpos = bloco["func_before"].tolist()
            for i in alvos:
                saida.write("%d\t%s\n" % (i, hash_corpo(corpos[i - inicio])))
                gravados += 1
                restam.discard(i)
            saida.flush()
        if not restam:
            log("  todos encontrados na linha %d; parando a leitura" % linha_global)
            break

    saida.close()
    log()
    log("tempo: %.0f s | linhas lidas: %d | gravados: %d"
        % (time.time() - t0, linha_global, gravados))
    if restam:
        log("NAO ENCONTRADOS: %d — se nao for 0, a chave por numero de linha esta errada"
            % len(restam))
        return 1
    log("saida: %s" % SAIDA)
    log()
    log("O `negativos_nomes.tsv` NAO foi tocado: ele e o artefato do NEGATIVOS.md.")
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
