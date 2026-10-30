#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tally do ruido de rotulagem tendo o COMMIT como unidade, nao a funcao.

Complementa `revisar_validacao.py tally`, que conta funcoes. A pergunta aqui e
outra e e a que explica o MECANISMO do ruido do BigVul:

    o rotulo positivo erra mais quando o commit de correcao toca muitas funcoes?

O BigVul marca `vul=1` em TODA funcao tocada pelo commit que corrige a CVE. Se
essa heuristica e a fonte do ruido, entao o ruido tem que crescer com o fan-out
do commit. Este script mede isso cruzando a amostra anotada com o fan-out real
de cada commit no conjunto inteiro de positivos.

Cuidado ao ler: o fan-out vem do conjunto COMPLETO de positivos (2957 funcoes),
nao da amostra. Um commit pode ter 20 funcoes positivas e so 1 ter caido na
amostra de 50 -- por isso o bucket precisa ser calculado do parquet, nunca
contando linhas da amostra.

Uso:
  python3 tally_por_commit.py \
      --positivos saida/bigvul_memoria_positivos.parquet \
      --csv saida/amostra_validacao_revisao.csv
"""

import argparse
import csv
from collections import defaultdict

import pandas as pd

BUCKETS = ("1", "2-4", "5+")


def bucket(n):
    if n <= 1:
        return "1"
    return "2-4" if n <= 4 else "5+"


def ler_amostra(caminho):
    with open(caminho, encoding="utf-8-sig", newline="") as f:
        linhas = list(csv.DictReader(f))
    for c in ("commit_id", "cve_id", "tipo_ruido"):
        if c not in linhas[0]:
            raise SystemExit("ERRO: a planilha nao tem a coluna %s." % c)
    # os `?` e vazios ficam fora da conta, como manda a rubrica_v1
    return [l for l in linhas if l["tipo_ruido"].strip().upper() in ("A", "B", "C", "D")]


def tabela_por_funcao(linhas, fan, titulo):
    print("\n--- %s (n = %d funcoes) ---" % (titulo, len(linhas)))
    b = defaultdict(lambda: [0, 0])
    for l in linhas:
        k = bucket(int(fan.get(l["commit_id"], 0)))
        b[k][0] += 1
        b[k][1] += l["tipo_ruido"].strip().upper() == "D"
    for k in BUCKETS:
        tot, d = b[k]
        if tot:
            print("  commit toca %-4s funcao(oes): %2d amostradas, %2d D -> %5.1f%% D "
                  "(ruido %.1f%%)" % (k, tot, d, 100.0 * d / tot, 100.0 - 100.0 * d / tot))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--positivos", required=True, help="parquet dos positivos do BigVul")
    ap.add_argument("--csv", required=True, help="planilha de revisao preenchida")
    args = ap.parse_args()

    pos = pd.read_parquet(args.positivos)
    fan = pos.groupby("commit_id").size()
    am = ler_amostra(args.csv)

    print("=" * 68)
    print("FAN-OUT DOS COMMITS NO CONJUNTO INTEIRO DE POSITIVOS")
    print("=" * 68)
    total_f = int(fan.sum())
    print("funcoes positivas : %d" % total_f)
    print("commits distintos : %d" % len(fan))
    print("funcoes por commit: media %.2f | mediana %.0f | max %d"
          % (fan.mean(), fan.median(), fan.max()))
    print()
    for k, cond in (("1", fan == 1),
                    ("2-4", (fan >= 2) & (fan <= 4)),
                    ("5+", fan >= 5)):
        nf, nc = int(fan[cond].sum()), int(cond.sum())
        print("  bucket %-4s: %4d funcoes (%5.1f%% do dataset) concentradas em %4d commits"
              % (k, nf, 100.0 * nf / total_f, nc))

    print()
    print("=" * 68)
    print("RUIDO DA AMOSTRA CRUZADO COM O FAN-OUT")
    print("=" * 68)
    tabela_por_funcao(am, fan, "todas as funcoes decididas")

    # A amostra tem um cluster grande de uma CVE so; sem ele o efeito precisa sobreviver.
    cves = [l["cve_id"] for l in am]
    dominante = max(set(cves), key=cves.count)
    if cves.count(dominante) >= 5:
        tabela_por_funcao([l for l in am if l["cve_id"] != dominante], fan,
                          "sem o cluster %s (%d linhas)" % (dominante, cves.count(dominante)))

    # Unidade = commit: o commit "acerta" se QUALQUER funcao amostrada dele e D.
    por = defaultdict(list)
    for l in am:
        por[l["commit_id"]].append(l["tipo_ruido"].strip().upper())
    print("\n--- unidade = COMMIT (%d commits distintos) ---" % len(por))
    b = defaultdict(lambda: [0, 0])
    for cid, tipos in por.items():
        k = bucket(int(fan.get(cid, 0)))
        b[k][0] += 1
        b[k][1] += "D" in tipos
    for k in BUCKETS:
        tot, d = b[k]
        if tot:
            print("  commit toca %-4s funcao(oes): %2d commits, %2d com pelo menos uma D "
                  "-> %5.1f%%" % (k, tot, d, 100.0 * d / tot))
    com_d = sum(1 for t in por.values() if "D" in t)
    print("\n  ruido por commit (nenhuma funcao amostrada e o sitio): %.1f%% (%d/%d)"
          % (100.0 * (len(por) - com_d) / len(por), len(por) - com_d, len(por)))

    print("\n> n por bucket e pequeno e as linhas do mesmo commit nao sao")
    print("> independentes. Reportar como evidencia do MECANISMO, com as contagens")
    print("> a vista, nunca como estimativa pontual do ruido por estrato.")


if __name__ == "__main__":
    main()
