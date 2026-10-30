#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extrai o NOME da funcao de cada negativo do split, a partir do codigo-fonte.

POR QUE ISTO EXISTE, situando
------------------------------
O dataset de treino do ReVeal precisa de um grafo POR FUNCAO. Para recortar a funcao de dentro
do CPG do arquivo, e preciso localiza-la no grafo — e a busca e por nome (`cpg.method.nameExact`).

Para os positivos o nome ja existe: vem do `relatorio_extracao.csv`. Para os negativos, nao.
O `indice_bigvul.csv` tem 7 colunas de metadado e nenhuma e nome de funcao; o CSV completo do
BigVul tem 36 colunas e **tambem nao tem nome** — o que ele tem e `func_before`, o codigo-fonte
da funcao inteira. Entao o nome tem de ser extraido da assinatura.

MESMO EXTRATOR DOS POSITIVOS, de proposito: `nome_da_funcao` do buscar_arquivo.py, importado e
nao copiado. Se os dois lados usassem extratores diferentes, uma diferenca de resultado entre
positivos e negativos poderia vir da extracao em vez do modelo.

DECISAO DE 21/09/2026 (do autor): os negativos sao **exatamente as linhas que o BigVul rotulou
com vul==0**, e nao "os metodos vizinhos do arquivo". A alternativa dispensaria este script,
mas trocaria o conjunto por outro que inclui funcoes que o BigVul nunca rotulou, enfraquecendo
a comparacao com os numeros publicados do ReVeal.

O QUE ELE GRAVA, por negativo:
  linha_indice   numero da linha no indice_bigvul.csv, que e a MESMA do CSV completo (o
                 _extrair_indice.py gravou em blocos sequenciais, preservando a ordem). E a
                 chave que casa com split/negativos.tsv.
  nome           o que o extrator devolveu, ou vazio se nao deu para decidir
  linhas_corpo   quantas linhas tem o func_before — serve de sanidade e de desempate depois
  sha1_corpo     hash do corpo normalizado; e o que vai permitir desambiguar nome repetido
                 sem chutar, quando a montagem do dataset esbarrar em colisao

MEMORIA: o all_c_cpp_release2.0.csv e um ZIP de 1,4 GB e quatro colunas guardam codigo inteiro.
O _extrair_indice.py registra que varre-lo levou SIGKILL TRES VEZES nos 7,7 GB do WSL. Aqui a
leitura e em blocos pequenos, so 3 colunas, e cada bloco vai para o disco antes do proximo ser
lido. Nada acumula em memoria.

Idempotente: --retomar pula linha que ja foi gravada.

Uso:
  python3 extrair_nomes_negativos.py
  python3 extrair_nomes_negativos.py --retomar
"""

import argparse
import csv
import hashlib
import os
import re
import sys
import time
from collections import Counter

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BIGVUL = os.path.dirname(AQUI)
sys.path.insert(0, BIGVUL)
from buscar_arquivo import nome_da_funcao   # noqa: E402  mesmo extrator dos positivos

CSV_COMPLETO = os.path.join(BIGVUL, "all_c_cpp_release2.0.csv")
NEGATIVOS = os.path.join(AQUI, "split", "negativos.tsv")
SAIDA = os.path.join(AQUI, "split", "negativos_nomes.tsv")

COLUNAS = ["vul", "commit_id", "func_before"]
RE_ESPACO = re.compile(r"\s+")


def log(*a):
    print(*a, flush=True)


def sha1_corpo(codigo):
    """Hash do corpo com espacos normalizados. Serve para desambiguar homonimos depois:
    dois metodos com o mesmo nome no CPG tem corpos diferentes, e o corpo o BigVul tem."""
    texto = RE_ESPACO.sub(" ", str(codigo or "")).strip()
    return hashlib.sha1(texto.encode("utf-8", "replace")).hexdigest() if texto else ""


def ler_pedidos():
    """{linha_indice} dos negativos do split."""
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
            log("AVISO: %s tem cabecalho inesperado; ignorando o que ja existe" % SAIDA)
            return set()
        for linha in fh:
            if linha.strip():
                feitos.add(int(linha.split("\t", 1)[0]))
    return feitos


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--retomar", action="store_true")
    ap.add_argument("--blocos", type=int, default=1000,
                    help="linhas por bloco de leitura (menor = menos memoria)")
    args = ap.parse_args()

    if not os.path.exists(NEGATIVOS):
        log("FALHA: nao ha split em %s — rode montar_split.py antes." % NEGATIVOS)
        return 1

    pedidos = ler_pedidos()
    log("negativos pedidos pelo split: %d" % len(pedidos))

    feitos = ler_feitos() if args.retomar else set()
    if feitos:
        log("ja gravados (--retomar): %d" % len(feitos))
    faltam = pedidos - feitos
    if not faltam:
        log("nada a fazer — todos ja estao em %s" % SAIDA)
        return resumir()

    log("faltam: %d" % len(faltam))
    log("lendo %s em blocos de %d linhas..." % (os.path.basename(CSV_COMPLETO), args.blocos))

    modo = "a" if (args.retomar and os.path.exists(SAIDA)) else "w"
    saida = open(SAIDA, modo, encoding="utf-8", newline="")
    if modo == "w":
        saida.write("linha_indice\tnome\tlinhas_corpo\tsha1_corpo\n")

    t0 = time.time()
    linha_global = 0
    gravados = 0
    blocos = 0
    restam = set(faltam)

    leitor = pd.read_csv(CSV_COMPLETO, compression="zip", encoding="latin-1",
                         usecols=COLUNAS, chunksize=args.blocos, dtype=str)
    for bloco in leitor:
        inicio = linha_global
        linha_global += len(bloco)
        blocos += 1

        # O bloco so interessa se alguma linha dele esta na lista. Testar o intervalo
        # primeiro evita iterar 188 mil linhas uma a uma.
        alvos = [i for i in range(inicio, linha_global) if i in restam]
        if alvos:
            corpos = bloco["func_before"].tolist()
            for i in alvos:
                codigo = corpos[i - inicio]
                nome = nome_da_funcao(codigo)
                n_linhas = str(codigo).count("\n") + 1 if codigo and str(codigo) != "nan" else 0
                saida.write("%d\t%s\t%d\t%s\n" % (i, nome, n_linhas, sha1_corpo(codigo)))
                gravados += 1
                restam.discard(i)
            saida.flush()

        if blocos % 20 == 0:
            log("  linha %d — gravados %d, restam %d" % (linha_global, gravados, len(restam)))

        if not restam:
            log("  todos os pedidos encontrados na linha %d; parando a leitura" % linha_global)
            break

    saida.close()
    log()
    log("tempo: %.0f s | linhas lidas: %d | gravados: %d" % (time.time() - t0, linha_global,
                                                             gravados))
    if restam:
        log("NAO ENCONTRADOS: %d  (o indice e o CSV completo deveriam ter a mesma ordem — se"
            % len(restam))
        log("este numero nao for 0, a premissa da chave por numero de linha esta errada e o")
        log("resultado NAO pode ser usado)")
    return resumir()


def resumir():
    if not os.path.exists(SAIDA):
        log("nada a resumir")
        return 1
    total = 0
    sem_nome = 0
    nomes = Counter()
    sem_corpo = 0
    with open(SAIDA, encoding="utf-8") as fh:
        fh.readline()
        for linha in fh:
            if not linha.strip():
                continue
            c = linha.rstrip("\n").split("\t")
            total += 1
            if not c[1]:
                sem_nome += 1
            else:
                nomes[c[1]] += 1
            if len(c) > 2 and c[2] == "0":
                sem_corpo += 1

    log()
    log("=" * 72)
    log("RESUMO — %s" % os.path.basename(SAIDA))
    log("=" * 72)
    log("negativos com linha gravada .............. %d" % total)
    log("  sem nome extraido ...................... %d (%.1f%%)"
        % (sem_nome, 100.0 * sem_nome / max(total, 1)))
    log("  sem corpo (func_before vazio) .......... %d" % sem_corpo)
    log("  nomes distintos ........................ %d" % len(nomes))
    log()
    log("nomes que se repetem mais (candidatos a colisao no CPG):")
    for n, c in nomes.most_common(8):
        log("  %-36s %d" % (n[:36], c))
    log()
    log("LEITURA: 'sem nome' e perda de cobertura do MESMO tipo que a dos positivos — o item")
    log("simplesmente nao entra no dataset. Nome repetido nao e problema por si: so importa")
    log("quando duas funcoes homonimas estao no MESMO arquivo, e para esses o sha1_corpo")
    log("permite desambiguar sem chutar.")
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
