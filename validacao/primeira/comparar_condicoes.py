#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compara a anotacao do MODELO entre as duas condicoes (cve_visivel x cve_oculta)
para ler a sonda de memorizacao.

POS-HOC. Nao consta do pre_registro.md, que preve a condicao cve_oculta apenas
como "sensibilidade" e nao especifica esta comparacao pareada. Reportar como
analise exploratoria, nunca como teste pre-registrado.

A pergunta que este script responde e uma so:

    esconder a CVE muda o julgamento do modelo MAIS do que o modelo muda de
    ideia sozinho quando perguntado de novo com o mesmo insumo?

Sem o segundo termo a primeira metade nao significa nada: um modelo que oscila
a esmo produziria a mesma queda de concordancia sem nenhuma memorizacao
envolvida. O piso vem das 3 repeticoes da condicao visivel, que sao chamadas
independentes com entrada identica.

Uso:
  python3 comparar_condicoes.py
"""

import csv
import itertools
import os
import sys
from collections import Counter, defaultdict

AQUI = os.path.dirname(os.path.abspath(__file__))
SAIDA = os.path.join(AQUI, "saida")


def ler(nome):
    caminho = os.path.join(SAIDA, nome)
    if not os.path.exists(caminho):
        sys.exit("ERRO: falta %s. Rode consolidar_brutos.py nas duas condicoes." % caminho)
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(caminho, encoding=enc, newline="") as f:
                return list(csv.DictReader(f))
        except UnicodeDecodeError:
            continue
    sys.exit("ERRO: nao decodifiquei %s" % caminho)


def col(linhas, *nomes):
    for n in nomes:
        if n in linhas[0]:
            return n
    sys.exit("ERRO: colunas esperadas %s; achei %s" % (nomes, list(linhas[0].keys())))


def main():
    vis = ler("anotacao_modelo_cve_visivel.csv")
    ocu = ler("anotacao_modelo_cve_oculta.csv")

    c_id, c_tipo = col(vis, "id", "caso"), col(vis, "tipo_ruido", "tipo")
    c_rep = col(vis, "repeticao", "run")

    reps = defaultdict(dict)
    for l in vis:
        reps[int(l[c_id])][int(l[c_rep])] = l[c_tipo].strip().upper()
    ocul = {int(l[c_id]): l[c_tipo].strip().upper() for l in ocu}

    # ---------------------------------------------------------------- piso
    completos = sorted(k for k, v in reps.items() if len(v) == 3)
    pares = list(itertools.combinations((1, 2, 3), 2))
    pb, p4 = [], []
    for a, b in pares:
        pb.append(sum(1 for i in completos if (reps[i][a] == "D") == (reps[i][b] == "D")) / len(completos))
        p4.append(sum(1 for i in completos if reps[i][a] == reps[i][b]) / len(completos))
    piso_bin, piso_4 = sum(pb) / len(pb), sum(p4) / len(p4)

    print("=" * 66)
    print("PISO -- mesmo insumo, chamadas independentes (cve_visivel, 3 reps)")
    print("=" * 66)
    print("casos com 3 repeticoes : %d" % len(completos))
    print("estabilidade binaria   : %.3f  (media par a par)" % piso_bin)
    print("estabilidade 4-cat     : %.3f  (media par a par)" % piso_4)
    inst = sorted(i for i in completos if len({reps[i][r] == "D" for r in (1, 2, 3)}) > 1)
    print("instaveis em binario   : %s" % (inst if inst else "nenhum"))

    # ------------------------------------------------------- entre condicoes
    maj = {}
    for k, v in reps.items():
        c = Counter(v.values()).most_common()
        maj[k] = c[0][0] if (len(c) == 1 or c[0][1] > c[1][1]) else "?"

    ids = sorted(set(maj) & set(ocul))
    flip_bin = [i for i in ids if (maj[i] == "D") != (ocul[i] == "D")]
    flip_4 = [i for i in ids if maj[i] != ocul[i]]
    est_bin = 1 - len(flip_bin) / len(ids)
    est_4 = 1 - len(flip_4) / len(ids)

    print()
    print("=" * 66)
    print("EFEITO -- CVE escondida (voto majoritario visivel x oculta)")
    print("=" * 66)
    print("casos comparados       : %d" % len(ids))
    print("estabilidade binaria   : %.3f   (%d mudaram: %s)" % (est_bin, len(flip_bin), flip_bin))
    print("estabilidade 4-cat     : %.3f   (%d mudaram: %s)" % (est_4, len(flip_4), flip_4))

    d_vis = sorted(i for i in ids if maj[i] == "D")
    d_ocu = sorted(i for i in ids if ocul[i] == "D")
    inter = sorted(set(d_vis) & set(d_ocu))
    print()
    print("D visivel : %2d %s" % (len(d_vis), d_vis))
    print("D oculta  : %2d %s" % (len(d_ocu), d_ocu))
    print("nas duas  : %2d %s" % (len(inter), inter))
    print("perdeu D  : %s" % sorted(set(d_vis) - set(d_ocu)))
    print("ganhou D  : %s" % sorted(set(d_ocu) - set(d_vis)))
    if len(d_vis) == len(d_ocu) and set(d_vis) != set(d_ocu):
        print()
        print("ATENCAO: a CONTAGEM de D e igual nas duas condicoes mas o CONJUNTO")
        print("nao e. A taxa de ruido agregada do modelo coincide por acaso -- nao")
        print("escrever que 'a estimativa e robusta a esconder a CVE'.")

    # ----------------------------------------------------------- veredito
    n = len(ids)
    esp_bin, esp_4 = (1 - piso_bin) * n, (1 - piso_4) * n
    # Regra de tres: 0 eventos em n ensaios -> limite superior 95% ~ 3/n.
    teto_bin = 3.0 if (1 - piso_bin) == 0 else esp_bin

    print()
    print("=" * 66)
    print("VEREDITO")
    print("=" * 66)
    print("binario : observadas %d mudancas; pelo piso esperava-se ~%.1f%s" % (
        len(flip_bin), esp_bin,
        " (piso zerado -- teto 95%% pela regra de tres: ~%.0f)" % teto_bin if (1 - piso_bin) == 0 else ""))
    print("4-cat   : observadas %d mudancas; pelo piso esperava-se ~%.1f" % (len(flip_4), esp_4))
    print()
    if len(flip_bin) > teto_bin or len(flip_4) > esp_4:
        print("HA efeito detectavel de esconder a CVE: o modelo muda mais do que")
        print("muda sozinho. Cuidado com a palavra 'memorizacao' -- remover id de")
        print("CVE, resumo e mensagem de commit tira EVIDENCIA LEGITIMA junto, e o")
        print("humano tinha essa evidencia. Parte da queda e assimetria de insumo")
        print("que nos mesmos introduzimos, nao recuperacao de CVE decorada.")
    else:
        print("NAO ha efeito detectavel acima do ruido do proprio modelo.")


if __name__ == "__main__":
    main()
