#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monta os conjuntos de treino DENTRO da particao de treino do split.

O QUE MUDOU EM RELACAO AO montar_conjuntos.py, e por que ele nao foi editado
---------------------------------------------------------------------------
O montar_conjuntos.py (11/08) sorteava o M_ctrl do M_raw INTEIRO, porque naquele momento nao
havia split — os tres conjuntos eram a populacao toda. Depois do acordo de 09/2026 com o
orientador ("o split vem antes de qualquer filtro"), aqueles conjuntos passaram a conter itens
que caem na particao de TESTE, e por isso nao servem mais como conjuntos de treino.

O script antigo NAO foi alterado e a pasta conjuntos/ NAO foi sobrescrita: ela e o registro do
que foi medido em RODADA_COMPLETA.md, e apagar um artefato ja registrado para produzir outro
com o mesmo nome e o tipo de coisa que torna um resultado indefensavel. Este script escreve em
conjuntos_treino/, ao lado.

OS CINCO CONTROLES, e a que objecao eles respondem
--------------------------------------------------
O M_ctrl e o conjunto SUJO com o mesmo tamanho do curado: ele mede se a curadoria melhorou o
rotulo ou se apenas reduziu o dataset. O orientador objetou, com razao, que o resultado
"depende completamente de quais 847 sao selecionadas".

Um sorteio e uma amostra de tamanho 1: se o M_cur ganhar do M_ctrl por alguma margem, nao da
para separar "a curadoria fez efeito" de "esse sorteio especifico saiu bom ou ruim". A resposta
nao e apagar o braco — e sortear CINCO controles com sementes diferentes e comparar o M_cur
contra a DISTRIBUICAO dos cinco. Se o M_cur cair fora da faixa dos controles, o efeito e da
curadoria; se cair dentro, a resposta e "so reduziu o dataset" — e essa tambem e uma resposta.

DEBITO CONHECIDO: os cinco controles sao uma decisao tomada antes da reuniao de 09/09/2026. Se
o desenho mudar la, isto pode virar trabalho jogado fora. Custo aceito de proposito.

O QUE ELE NAO FAZ: nao monta grafo, nao extrai funcao, nao decide proporcao de negativos. E o
lado POSITIVO dos bracos, so.

Uso:
  python3 montar_conjuntos_treino.py
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
from congelar import conferir                                          # noqa: E402
from veredito import carregar_regra, julgar, CONFIRMADO, INDETERMINADO  # noqa: E402

SPLIT = os.path.join(AQUI, "split", "positivos.tsv")

# As cinco sementes do M_ctrl. A primeira e 2026, a mesma do sorteio unico de 11/08, para a
# linhagem ficar rastreavel; as outras quatro sao sequenciais e declaradas aqui, fixadas antes
# de qualquer treino. Nenhuma delas e 42 (os 50 anotados), 7 (o dev set), 101 (a medida de
# subgrafo) nem 909 (o split).
SEMENTES_CTRL = (2026, 2027, 2028, 2029, 2030)


def log(*a):
    print(*a, flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--evidencia", default=os.path.join(AQUI, "saida_completa"))
    p.add_argument("--regra", default=os.path.join(AQUI, "regra_veredito.toml"))
    p.add_argument("--saida", default=os.path.join(AQUI, "conjuntos_treino"))
    p.add_argument("--versao", default="v2",
                   help="qual congelamento conferir (v3: --evidencia saida_completa_v3 "
                        "--saida conjuntos_treino_v3)")
    args = p.parse_args()

    log("--- congelamento da regra ---")
    if conferir(versao=args.versao) != 0:
        log("\nRECUSANDO MONTAR. A regra mudou desde o congelamento: o M_cur sairia de uma")
        log("regra diferente da que foi medida nos 50.")
        return 1

    if not os.path.exists(SPLIT):
        log("\nFALHA: nao ha split em %s" % SPLIT)
        log("       Rode montar_split.py antes. Sem split, o M_ctrl seria sorteado de um pool")
        log("       que inclui o conjunto de teste.")
        return 1

    particao = {}
    with open(SPLIT, encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            particao[r["item"]] = r["particao"]
    log("\nsplit: %d positivos particionados (%s)"
        % (len(particao), ", ".join("%s %d" % (p, n) for p, n
                                    in sorted(Counter(particao.values()).items()))))

    regra = carregar_regra(args.regra)
    linhas = []
    sem_particao = 0
    for caminho in sorted(glob.glob(os.path.join(args.evidencia, "*.json"))):
        with open(caminho, encoding="utf-8") as fh:
            e = json.load(fh)
        item = e.get("item", "")
        if item not in particao:
            sem_particao += 1
            continue
        v, motivo, n1, n2 = julgar(e, regra)
        linhas.append({"item": item, "veredito": v, "motivo": motivo,
                       "camada1": n1, "camada2": n2,
                       "cwe_bigvul": (e.get("cwe_bigvul") or "").strip(),
                       "projeto": (e.get("projeto") or "").strip(),
                       "particao": particao[item]})
    log("evidencia lida: %d itens" % len(linhas))
    if sem_particao:
        log("  itens com evidencia mas SEM linha no split: %d  (tem que ser 0)" % sem_particao)

    treino = [l for l in linhas if l["particao"] == "treino"]
    raw = [l for l in treino if l["veredito"] != INDETERMINADO]
    cur = [l for l in raw if l["veredito"] == CONFIRMADO]

    log()
    log("-" * 72)
    log("OS BRACOS, restritos a particao de TREINO")
    log("-" * 72)
    log("itens de treino com evidencia .......... %d" % len(treino))
    log("  indeterminados (fora dos tres) ....... %d" % (len(treino) - len(raw)))
    log("M_raw (corpo sadio, rotulo original) ... %d" % len(raw))
    log("M_cur (confirmados pela traversal) ..... %d  (%.1f%% do M_raw)"
        % (len(cur), 100.0 * len(cur) / max(len(raw), 1)))
    log("M_ctrl x %d (mesmo N do M_cur) ......... %d cada" % (len(SEMENTES_CTRL), len(cur)))

    os.makedirs(args.saida, exist_ok=True)
    campos = ["item", "veredito", "camada1", "camada2", "cwe_bigvul", "projeto"]

    def gravar(nome, conj):
        destino = os.path.join(args.saida, nome + ".tsv")
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=campos, delimiter="\t", extrasaction="ignore")
            w.writeheader()
            for l in sorted(conj, key=lambda x: x["item"]):
                w.writerow(l)
        return destino

    gravar("M_raw", raw)
    gravar("M_cur", cur)

    controles = {}
    for semente in SEMENTES_CTRL:
        ctrl = sorted(random.Random(semente).sample(raw, len(cur)), key=lambda l: l["item"])
        controles[semente] = ctrl
        gravar("M_ctrl_s%d" % semente, ctrl)

    log()
    log("-" * 72)
    log("OS CINCO CONTROLES")
    log("-" * 72)
    itens_cur = {l["item"] for l in cur}
    log("%-10s %6s %14s %22s" % ("semente", "n", "confirmados", "sobreposicao com M_cur"))
    fracoes = []
    for semente in SEMENTES_CTRL:
        ctrl = controles[semente]
        confirmados = sum(1 for l in ctrl if l["veredito"] == CONFIRMADO)
        sobrep = len(itens_cur & {l["item"] for l in ctrl})
        fracoes.append(100.0 * confirmados / max(len(ctrl), 1))
        log("%-10d %6d %8d (%4.1f%%) %12d (%4.1f%%)"
            % (semente, len(ctrl), confirmados, 100.0 * confirmados / max(len(ctrl), 1),
               sobrep, 100.0 * sobrep / max(len(ctrl), 1)))
    log()
    log("A coluna 'confirmados' e a razao de os cinco existirem: cada sorteio pega, por acaso,")
    log("uma quantidade diferente de itens que a traversal teria confirmado. Aqui a variacao")
    log("entre sorteios foi de %.1f%% a %.1f%% — e essa faixa que define o que e 'normal' para"
        % (min(fracoes), max(fracoes)))
    log("um controle, e contra ela que o M_cur tem que ser comparado, nunca contra um so.")
    log()
    log("A sobreposicao com o M_cur e ESPERADA e correta: o controle e sorteado do bruto")
    log("inteiro, que inclui os confirmados. Sortear so entre os descartados faria dele o")
    log("COMPLEMENTO do M_cur — outra coisa, e um controle enviesado.")

    log()
    log("distribuicao por CWE:")
    log("%-16s %8s %8s %8s %8s" % ("conjunto", "CWE-119", "CWE-120", "CWE-125", "CWE-787"))
    for nome, conj in [("M_raw", raw), ("M_cur", cur)] + \
                      [("M_ctrl_s%d" % s, controles[s]) for s in SEMENTES_CTRL]:
        c = Counter(l["cwe_bigvul"] for l in conj)
        tot = max(len(conj), 1)
        log("%-16s %7.1f%% %7.1f%% %7.1f%% %7.1f%%"
            % (nome, 100.0 * c["CWE-119"] / tot, 100.0 * c["CWE-120"] / tot,
               100.0 * c["CWE-125"] / tot, 100.0 * c["CWE-787"] / tot))

    log()
    log("--- conferencias ---")
    itens_treino = {l["item"] for l in treino}
    log("  nenhum item fora do treino ........... %s"
        % all({l["item"] for l in c} <= itens_treino
              for c in [raw, cur] + list(controles.values())))
    log("  M_cur contido no M_raw ............... %s"
        % (itens_cur <= {l["item"] for l in raw}))
    log("  os cinco controles tem o N do M_cur .. %s"
        % all(len(c) == len(cur) for c in controles.values()))
    log("  os cinco sorteios sao distintos ...... %s"
        % (len({tuple(sorted(l["item"] for l in c)) for c in controles.values()})
           == len(SEMENTES_CTRL)))
    log()
    log("gravado em %s" % args.saida)
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
