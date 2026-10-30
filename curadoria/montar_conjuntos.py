#!/usr/bin/env python3
"""Monta M_raw, M_cur e M_ctrl a partir da rodada completa da curadoria.

Os tres conjuntos sao o desenho experimental do TCC (lado POSITIVO apenas — as amostras
negativas sao as mesmas nos tres e entram na montagem do dataset de treino, que e o card do
pipeline do ReVeal, nao este):

  M_raw   positivos do BigVul nas 4 CWEs de memoria, rotulo original, SEM filtro.
          Aqui: os itens de corpo sadio, isto e, aqueles sobre os quais a curadoria
          conseguiu opinar. Indeterminado fica de fora dos TRES conjuntos — se ficasse so
          fora do M_cur, a diferenca entre M_cur e M_ctrl passaria a incluir "a ferramenta
          conseguiu olhar", que nao e a variavel de interesse.

  M_cur   os que a traversal CONFIRMOU (regra congelada v1: camada 1 E camada 2).

  M_ctrl  amostra aleatoria do M_raw com o MESMO N do M_cur. E o controle de tamanho: sem
          ele, qualquer diferenca entre M_raw e M_cur poderia ser explicada por treinar com
          menos dados. M_cur e M_ctrl tem o mesmo N e saem do mesmo pool; diferem SO em
          quais positivos entram. Semente declarada abaixo e fixada antes de olhar qualquer
          resultado de treino.

    python3 montar_conjuntos.py
"""

import argparse
import csv
import glob
import json
import os
import random
import sys
from collections import Counter

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from congelar import conferir                                    # noqa: E402
from veredito import carregar_regra, julgar, CONFIRMADO, INDETERMINADO  # noqa: E402

# Semente do M_ctrl. NAO e 42 (a amostra dos 50 do teste) nem 7 (o dev set), de proposito:
# reusar uma delas faria o controle correlacionar com um conjunto que ja tem papel no
# desenho. Fixada aqui, antes de qualquer treino.
SEMENTE_CTRL = 2026


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--evidencia", default=os.path.join(AQUI, "saida_completa"))
    p.add_argument("--regra", default=os.path.join(AQUI, "regra_veredito.toml"))
    p.add_argument("--saida", default=os.path.join(AQUI, "conjuntos"))
    p.add_argument("--versao", default="v2",
                   help="qual congelamento conferir (v3: --evidencia saida_completa_v3 "
                        "--saida conjuntos_v3)")
    args = p.parse_args()

    print("--- congelamento ---")
    if conferir(versao=args.versao) != 0:
        print("\nRECUSANDO MONTAR. A regra mudou desde o congelamento: o M_cur sairia de uma\n"
              "regra diferente da que foi medida nos 50.")
        return 1

    regra = carregar_regra(args.regra)
    linhas = []
    for caminho in sorted(glob.glob(os.path.join(args.evidencia, "*.json"))):
        with open(caminho, encoding="utf-8") as fh:
            e = json.load(fh)
        v, motivo, n1, n2 = julgar(e, regra)
        linhas.append({"item": e.get("item", ""), "veredito": v, "motivo": motivo,
                       "camada1": n1, "camada2": n2,
                       "cwe_bigvul": (e.get("cwe_bigvul") or "").strip(),
                       "projeto": (e.get("projeto") or "").strip()})

    raw = [l for l in linhas if l["veredito"] != INDETERMINADO]
    cur = [l for l in raw if l["veredito"] == CONFIRMADO]

    rnd = random.Random(SEMENTE_CTRL)
    ctrl = sorted(rnd.sample(raw, len(cur)), key=lambda l: l["item"])

    os.makedirs(args.saida, exist_ok=True)
    campos = ["item", "veredito", "camada1", "camada2", "cwe_bigvul", "projeto"]
    for nome, conj in (("M_raw", raw), ("M_cur", cur), ("M_ctrl", ctrl)):
        destino = os.path.join(args.saida, nome + ".tsv")
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=campos, delimiter="\t", extrasaction="ignore")
            w.writeheader()
            for l in sorted(conj, key=lambda x: x["item"]):
                w.writerow(l)
        print("\n{}: {} itens -> {}".format(nome, len(conj), destino))
        c = Counter(l["cwe_bigvul"] for l in conj)
        for cwe in sorted(c, key=lambda x: -c[x]):
            print("    {:<10} {:>5}  ({:.1f}%)".format(cwe, c[cwe], 100.0 * c[cwe] / len(conj)))

    sobrepos = len({l["item"] for l in cur} & {l["item"] for l in ctrl})
    print("\n--- conferencias ---")
    print("  M_cur e M_ctrl tem o mesmo N ......... {}".format(len(cur) == len(ctrl)))
    print("  M_ctrl esta contido no M_raw ......... {}".format(
        {l['item'] for l in ctrl} <= {l['item'] for l in raw}))
    print("  itens em comum entre M_cur e M_ctrl .. {} ({:.1f}% do M_cur)".format(
        sobrepos, 100.0 * sobrepos / len(cur)))
    print("     ^ sobreposicao e ESPERADA: o M_ctrl e sorteado do bruto inteiro, que inclui")
    print("       os confirmados. Nao sortear entre os confirmados faria do M_ctrl um")
    print("       'complemento do M_cur', que e outra coisa e enviesaria o controle.")
    print("  semente do M_ctrl .................... {}".format(SEMENTE_CTRL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
