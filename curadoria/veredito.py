#!/usr/bin/env python3
"""Aplica a regra_veredito.toml a evidencia da curadoria e monta o M_cur.

Separacao deliberada: o curadoria_v2.sc emite EVIDENCIA (contagens), este modulo emite
VEREDITO (confirmado / descartado / indeterminado). Trocar a regra e trocar o .toml —
a traversal nao muda, e o hash dela continua valendo.

    python3 veredito.py --saida saida_dev              # resumo do M_cur
    python3 veredito.py --saida saida_dev --por-item   # linha a linha

Os tres vereditos, e a diferenca entre os dois ultimos importa:
  confirmado    — o rotulo do BigVul foi positivamente corroborado. Entra no M_cur.
  descartado    — o CPG olhou e nao achou o padrao. Sai do M_cur; conta como rotulo suspeito.
  indeterminado — a ferramenta nao conseguiu olhar. Sai do M_cur e NAO conta como rotulo
                  suspeito. Sem esta terceira casa, falha de ferramenta viraria ruido de
                  rotulo e a curadoria puniria o item errado.
"""

import argparse
import glob
import json
import os
import sys

try:
    import tomllib
except ModuleNotFoundError:                      # Python < 3.11
    import tomli as tomllib                      # noqa: F401

AQUI = os.path.dirname(os.path.abspath(__file__))
PADRAO_REGRA = os.path.join(AQUI, "regra_veredito.toml")

CONFIRMADO, DESCARTADO, INDETERMINADO = "confirmado", "descartado", "indeterminado"


def carregar_regra(caminho):
    with open(caminho, "rb") as fh:
        return tomllib.load(fh)


def _c1(evid, regra):
    """Contagem da camada 1 segundo a regra: presenca de acesso a buffer."""
    c1 = evid.get("camada1", {})
    cats = c1.get("por_categoria", {})
    permitidas = set(regra["camada1"]["categorias"])
    n = sum(v for k, v in cats.items() if k in permitidas)
    if regra["camada1"].get("contar_acessos_indexados", True):
        n += c1.get("acessos_indexados", 0)
    if regra["camada1"].get("contar_acessos_indexados_diretos", False):
        n += c1.get("acessos_indexados_diretos", 0)
    return n


def _c2(evid, regra):
    """Contagem da camada 2. Devolve (soma, estourou)."""
    c2 = evid.get("camada2", {})
    total, estourou = 0, False
    for k in regra["camada2"]["fluxos"]:
        v = c2.get(k, 0)
        if v < 0:                                # o motor de dataflow falhou nesse par
            estourou = True
            continue
        total += v
    return total, estourou


def _corpo_ausente(evid, regra):
    s = evid.get("saude", {})
    sa = regra.get("saude", {})
    if not sa.get("marcar_indeterminado_se_corpo_ausente", True):
        return False
    return (s.get("blocos", 0) <= sa.get("blocos_maximo_para_ausente", 0)
            and s.get("chamadas_total", 0) <= sa.get("chamadas_maximo_para_ausente", 0))


def julgar(evid, regra):
    """Devolve (veredito, motivo, n_camada1, n_camada2)."""
    sa = regra.get("saude", {})
    n1 = _c1(evid, regra)
    n2, estourou = _c2(evid, regra)

    if _corpo_ausente(evid, regra):
        return INDETERMINADO, "corpo_nao_parseado", n1, n2
    if estourou and sa.get("marcar_indeterminado_se_fluxo_estourou", True):
        return INDETERMINADO, "fluxo_estourou", n1, n2

    ok1 = n1 >= regra["camada1"]["minimo"]
    ok2 = n2 >= regra["camada2"]["minimo"]
    conector = regra["veredito"]["conector"].strip().upper()
    if conector == "E":
        passou = ok1 and ok2
    elif conector == "OU":
        passou = ok1 or ok2
    else:
        sys.exit("ERRO: conector desconhecido no .toml: {}".format(conector))

    if passou:
        return CONFIRMADO, "camada1={} camada2={}".format(n1, n2), n1, n2
    faltou = "camada1" if not ok1 else "camada2"
    return DESCARTADO, "sem_" + faltou, n1, n2


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--saida", default=os.path.join(AQUI, "saida_dev"),
                   help="pasta com os JSON de evidencia")
    p.add_argument("--regra", default=PADRAO_REGRA)
    p.add_argument("--excluir", default="1217__libgd",
                   help="itens fora da estatistica, separados por virgula. O caso de "
                        "regressao esta na amostra dos 50 e nao pode contaminar o dev.")
    p.add_argument("--por-item", action="store_true")
    p.add_argument("--tsv", default="", help="grava o veredito por item neste TSV")
    args = p.parse_args()

    regra = carregar_regra(args.regra)
    fora = {s.strip() for s in args.excluir.split(",") if s.strip()}

    linhas, contagem = [], {CONFIRMADO: 0, DESCARTADO: 0, INDETERMINADO: 0}
    for caminho in sorted(glob.glob(os.path.join(args.saida, "*.json"))):
        with open(caminho, encoding="utf-8") as fh:
            evid = json.load(fh)
        if evid.get("item") in fora:
            continue
        v, motivo, n1, n2 = julgar(evid, regra)
        contagem[v] += 1
        linhas.append((evid.get("item", "?"), v, motivo, n1, n2))

    n = len(linhas)
    olhaveis = n - contagem[INDETERMINADO]

    if args.por_item:
        print("{:<22} {:<14} {:>5} {:>5}  {}".format("item", "veredito", "c1", "c2", "motivo"))
        for item, v, motivo, n1, n2 in linhas:
            print("{:<22} {:<14} {:>5} {:>5}  {}".format(item, v, n1, n2, motivo))
        print()

    print("regra {} ({}), conector {}".format(
        regra["meta"]["versao"], regra["meta"]["fixada_em"], regra["veredito"]["conector"]))
    print("itens ................. {}".format(n))
    print("indeterminados ........ {}   (ferramenta nao olhou; fora do M_cur e fora do ruido)"
          .format(contagem[INDETERMINADO]))
    print("olhaveis (M_raw) ...... {}".format(olhaveis))
    print("confirmados (M_cur) ... {}   ({:.1f}% do M_raw olhavel)".format(
        contagem[CONFIRMADO], 100.0 * contagem[CONFIRMADO] / max(1, olhaveis)))
    print("descartados ........... {}   ({:.1f}%)".format(
        contagem[DESCARTADO], 100.0 * contagem[DESCARTADO] / max(1, olhaveis)))

    if args.tsv:
        with open(args.tsv, "w", encoding="utf-8") as fh:
            fh.write("item\tveredito\tcamada1\tcamada2\tmotivo\n")
            for item, v, motivo, n1, n2 in linhas:
                fh.write("{}\t{}\t{}\t{}\t{}\n".format(item, v, n1, n2, motivo))
        print("\npor item em {}".format(args.tsv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
