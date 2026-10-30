#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resorteia os M_ctrl dentro da populacao que TEM grafo, e testa se da para parear tamanho.

POR QUE RESORTEAR (a decisao "a", tomada em 21/09/2026)
-------------------------------------------------------
O `M_ctrl` existe para que a UNICA diferenca entre ele e o `M_cur` seja o rotulo. O sorteio de
05/09 foi feito sobre os positivos do treino, ANTES de se saber quais teriam grafo. Como
`M_cur` nao pode conter item cego por construcao (sem corpo parseado a traversal nao ve
evidencia para confirmar) e o `M_ctrl` pode, sobrou perda assimetrica: 96,2% contra 91,1%.

Resortear dentro de quem TEM grafo aplica a MESMA definicao no estagio certo. E isso ja resolve
o desequilibrio binario "com corpo / sem corpo", porque ter grafo implica ter corpo.

NAO SOBRESCREVE `M_ctrl_s*.tsv`. Aqueles sao o registro de 05/09. A saida vai para
`M_ctrl_g<semente>.tsv` ("g" de com grafo), ao lado.

E O QUE SOBRA: O TAMANHO
------------------------
Medido em `_conferir_composicao.py`: a densidade de parse quase nao difere (+10%), mas o
TAMANHO sim — mediana de 316 nos no `M_cur` contra ~139 no `M_raw` e nos `M_ctrl`. A regra de
curadoria exige camada 1 E camada 2, e funcao maior tem mais chance de satisfazer as duas.
Entao a regra e MECANICAMENTE enviesada para funcao grande.

Isso NAO e efeito do #ifdef e existiria com parse perfeito. E confundimento de verdade: se o
`M_cur` ganhar, nao da para separar "rotulo mais limpo" de "grafo maior".

O modo --parear tenta montar um `M_ctrl` com a MESMA distribuicao de tamanho do `M_cur`, e
RELATA SE E VIAVEL em vez de forcar. Pode nao ser: o `M_cur` ja levou as maiores, e pode nao
sobrar funcao grande bastante no resto do bruto.

NAO ALTERA NADA ja existente. So cria arquivos novos.

Uso:
  python3 montar_ctrl_com_grafo.py --viabilidade     # so mede, nao grava
  python3 montar_ctrl_com_grafo.py --gravar          # grava os M_ctrl_g
"""

import argparse
import csv
import glob
import json
import os
import random
import sys
from collections import Counter, defaultdict

AQUI = os.path.dirname(os.path.abspath(__file__))
CONJUNTOS = os.path.join(AQUI, "conjuntos_treino")
GRUPOS = os.path.expanduser("~/curadoria/dataset/grupos")

SEMENTES = [2026, 2027, 2028, 2029, 2030]   # as mesmas de 05/09; a POPULACAO e que muda
N_FAIXAS = 5                                 # quantis de tamanho para o pareamento


def log(*a):
    print(*a, flush=True)


def carregar():
    """Positivos de treino COM grafo: id -> n_nos. E as listas dos bracos.

    CONJUNTOS e GRUPOS vem de --conjuntos/--grupos (05/10/2026): na v3 sao
    conjuntos_treino_v3 e ~/curadoria/dataset_v3/grupos, e os M_ctrl_g* sao gravados la —
    os de 22/09 em conjuntos_treino/ nao sao tocados."""
    tam = {}
    for p in sorted(glob.glob(os.path.join(GRUPOS, "*.jsonl"))):
        for linha in open(p, encoding="utf-8"):
            if not linha.strip():
                continue
            r = json.loads(linha)
            if r["rotulo"] == 1 and r["particao"] == "treino":
                tam[r["id"]] = r["n_nos"]

    bracos = {}
    for p in sorted(glob.glob(os.path.join(CONJUNTOS, "*.tsv"))):
        nome = os.path.basename(p)[:-4]
        if nome.startswith("M_ctrl_g"):
            continue
        bracos[nome] = [r["item"] for r in
                        csv.DictReader(open(p, encoding="utf-8"), delimiter="\t")
                        if r.get("item")]
    return tam, bracos


def cabecalho_de(caminho):
    with open(caminho, encoding="utf-8") as fh:
        return fh.readline().rstrip("\n").split("\t")


def linhas_por_item(caminho):
    out = {}
    with open(caminho, encoding="utf-8") as fh:
        r = csv.DictReader(fh, delimiter="\t")
        for linha in r:
            out[linha["item"]] = linha
    return out


def faixas_de(valores, k):
    """Cortes por quantil, para estratificar tamanho."""
    s = sorted(valores)
    return [s[int(len(s) * (i + 1) / k) - 1] for i in range(k - 1)]


def faixa_do(v, cortes):
    for i, c in enumerate(cortes):
        if v <= c:
            return i
    return len(cortes)


def main():
    global CONJUNTOS, GRUPOS
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gravar", action="store_true")
    ap.add_argument("--viabilidade", action="store_true")
    ap.add_argument("--conjuntos", default="conjuntos_treino",
                    help="pasta dos bracos; os M_ctrl_g* sao gravados nela")
    ap.add_argument("--grupos", default="~/curadoria/dataset/grupos",
                    help="grupos do dataset de grafos")
    args = ap.parse_args()

    CONJUNTOS = args.conjuntos if os.path.isabs(args.conjuntos) else os.path.join(AQUI, args.conjuntos)
    GRUPOS = os.path.expanduser(args.grupos)
    log("bracos em %s | grafos em %s" % (CONJUNTOS, GRUPOS))

    tam, bracos = carregar()
    if "M_cur" not in bracos or "M_raw" not in bracos:
        log("faltam M_cur/M_raw em %s" % CONJUNTOS)
        return 1

    cur = [i for i in bracos["M_cur"] if i in tam]
    raw = [i for i in bracos["M_raw"] if i in tam]
    log("positivos de treino com grafo ....... %d" % len(tam))
    log("M_cur com grafo (N alvo) ............ %d" % len(cur))
    log("M_raw com grafo (populacao) ......... %d" % len(raw))

    # ---------------------------------------------------------------- (a) resorteio simples
    log()
    log("=" * 74)
    log("(a) RESORTEIO dentro de quem tem grafo, N = %d" % len(cur))
    log("=" * 74)
    novos = {}
    for s in SEMENTES:
        novos["M_ctrl_g%d" % s] = sorted(random.Random(s).sample(raw, len(cur)))
    for nome, itens in sorted(novos.items()):
        ts = sorted(tam[i] for i in itens)
        log("  %-16s n=%d  mediana de nos=%d" % (nome, len(itens), ts[len(ts) // 2]))
    tc = sorted(tam[i] for i in cur)
    log("  %-16s n=%d  mediana de nos=%d   <<< o alvo" % ("M_cur", len(cur), tc[len(tc) // 2]))
    log()
    log("  Isto iguala o N e resolve o desequilibrio 'com corpo / sem corpo'.")
    log("  NAO resolve o tamanho — veja abaixo.")

    # ---------------------------------------------------------------- viabilidade do pareamento
    log()
    log("=" * 74)
    log("VIABILIDADE de um M_ctrl PAREADO POR TAMANHO")
    log("=" * 74)
    cortes = faixas_de([tam[i] for i in cur], N_FAIXAS)
    quer = Counter(faixa_do(tam[i], cortes) for i in cur)
    # o pool honesto exclui o proprio M_cur: um controle nao pode ser feito dos confirmados
    pool = [i for i in raw if i not in set(cur)]
    tem = Counter(faixa_do(tam[i], cortes) for i in pool)
    log("  pool disponivel (M_raw com grafo, FORA do M_cur): %d" % len(pool))
    log()
    log("  %-8s %-18s %10s %10s %s" % ("faixa", "tamanho (nos)", "precisa", "disponivel", ""))
    viavel = True
    for f in range(N_FAIXAS):
        lo = 0 if f == 0 else cortes[f - 1] + 1
        hi = cortes[f] if f < len(cortes) else max(tam.values())
        falta = quer[f] - tem[f]
        marca = "" if falta <= 0 else "  <<< FALTAM %d" % falta
        if falta > 0:
            viavel = False
        log("  %-8d %-18s %10d %10d%s" % (f, "%d..%d" % (lo, hi), quer[f], tem[f], marca))

    log()
    if viavel:
        log("  >>> VIAVEL: da para montar um controle com a mesma distribuicao de tamanho.")
    else:
        log("  >>> NAO E VIAVEL parear exatamente. O M_cur ja levou as funcoes grandes e nao")
        log("      sobra equivalente no resto do bruto. Forcar o pareamento significaria")
        log("      reamostrar com reposicao ou afrouxar as faixas — as duas coisas mudam o que")
        log("      o controle e, e teriam de ir declaradas.")
    log()
    log("  LEITURA, e ela e o ponto: se NAO da para montar um controle do mesmo tamanho, isso")
    log("  nao e falha do script — e uma propriedade do conjunto. Quer dizer que 'curado' e")
    log("  'grande' estao amarrados neste dataset, e o experimento nao consegue separar os")
    log("  dois sozinho. O caminho passa a ser declarar e controlar na ANALISE (comparar")
    log("  dentro de faixas de tamanho), nao na amostragem.")

    # ---------------------------------------------------------------- gravar
    if args.gravar:
        base = os.path.join(CONJUNTOS, "M_cur.tsv")
        cab = cabecalho_de(base)
        origem = {}
        for p in glob.glob(os.path.join(CONJUNTOS, "M_*.tsv")):
            if "_g" in os.path.basename(p):
                continue
            origem.update(linhas_por_item(p))
        log()
        for nome, itens in sorted(novos.items()):
            destino = os.path.join(CONJUNTOS, nome + ".tsv")
            with open(destino, "w", encoding="utf-8", newline="") as fh:
                fh.write("\t".join(cab) + "\n")
                for i in itens:
                    linha = origem.get(i, {})
                    fh.write("\t".join(str(linha.get(c, "")) for c in cab) + "\n")
            log("gravado: %s (%d itens)" % (destino, len(itens)))
        log()
        log("Os M_ctrl_s*.tsv de 05/09 NAO foram tocados — sao o registro daquela decisao.")
    elif not args.viabilidade:
        log()
        log("(nada gravado; use --gravar)")
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
