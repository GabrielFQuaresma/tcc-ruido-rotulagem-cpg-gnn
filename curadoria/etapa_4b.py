#!/usr/bin/env python3
"""Etapa 4b — confere a regra_veredito.toml contra os rotulos do dev set.

Escrito ANTES de os rotulos existirem, de proposito: decidir o que vai ser medido
depois de ver os numeros e escolher a medida que sai melhor. As duas leituras
possiveis do resultado ja estao fixadas aqui embaixo.

    python3 etapa_4b.py

TRES REGRAS QUE VALEM AQUI (do plano, secao Etapa 4b):

 1. Verificar e ajustar sao ambos legitimos, mas mudam a frase do artigo.
    Olhar e nao mexer -> "calibrada por tamanho e VERIFICADA contra um dev set
    independente". Olhar e mexer -> "...e REFINADA", e registra que voltou.
    O que nao e defensavel e fazer a segunda e escrever a primeira.

 2. O numero do dev NUNCA e resultado. Nao entra em tabela nem no resumo. A
    precisao do filtro e uma coisa so: a medida nos 50, depois do hash (Etapa 5).

 3. Os rotulos do dev vem do MODELO, nao do autor: taxa base ~34% (ruido 66,0%),
    nao ~43% (ruido humano 57,1%). Guarda-corpo grosso, nunca dial. Mexer no
    limiar para ganhar 3 pontos percentuais em 30 rotulos ruidosos e perseguir
    ruido, e o n aqui e menor ainda depois de tirar indeterminados e '?'.
"""

import argparse
import csv
import glob
import json
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
BIGVUL = os.path.dirname(AQUI)
DEV_CEGA = os.path.join(BIGVUL, "validacao_cega", "dev")

sys.path.insert(0, AQUI)
from veredito import carregar_regra, julgar, CONFIRMADO, INDETERMINADO  # noqa: E402


def ler_csv(caminho, sep=","):
    with open(caminho, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh, delimiter=sep))


def taxa(k, n):
    return "{}/{} = {:.1f}%".format(k, n, 100.0 * k / n) if n else "{}/0 = —".format(k)


def bloco(nome, linhas):
    """Tabela de contingencia veredito x rotulo e as taxas que interessam."""
    vistos = [l for l in linhas if l["veredito"] != INDETERMINADO and l["tipo"] in "ABCD"]
    indet = [l for l in linhas if l["veredito"] == INDETERMINADO]
    duvida = [l for l in linhas if l["veredito"] != INDETERMINADO and l["tipo"] not in "ABCD"]

    print("\n=== {} ===".format(nome))
    print("itens {} | indeterminados {} | rotulo '?' {} | comparaveis {}"
          .format(len(linhas), len(indet), len(duvida), len(vistos)))
    if not vistos:
        return
    if indet:
        print("  indeterminados (fora da conta, ferramenta nao olhou): {}"
              .format(", ".join(l["item"] for l in indet)))
    if duvida:
        print("  rotulo '?' (fora da conta): {}".format(", ".join(l["item"] for l in duvida)))

    conf = [l for l in vistos if l["veredito"] == CONFIRMADO]
    desc = [l for l in vistos if l["veredito"] != CONFIRMADO]
    d = lambda ls: sum(1 for l in ls if l["tipo"] == "D")  # noqa: E731

    print("\n  {:<14} {:>5} {:>5} {:>5} {:>5} | {:>5}".format("", "A", "B", "C", "D", "n"))
    for rot, ls in (("confirmado", conf), ("descartado", desc)):
        print("  {:<14} {:>5} {:>5} {:>5} {:>5} | {:>5}".format(
            rot, *[sum(1 for l in ls if l["tipo"] == t) for t in "ABCD"], len(ls)))

    print("\n  taxa base do dev (D / comparaveis) ...... {}".format(taxa(d(vistos), len(vistos))))
    print("  PRECISAO do filtro (D / confirmados) .... {}".format(taxa(d(conf), len(conf))))
    print("  entre os descartados, eram D ............ {}".format(taxa(d(desc), len(desc))))
    print("  cobertura dos D (D confirmados / D) ..... {}".format(taxa(d(conf), d(vistos))))
    print("     ^ recall NAO e criterio: o silencio nao inverte rotulo, so remove do curado.")

    base = 100.0 * d(vistos) / len(vistos)
    prec = 100.0 * d(conf) / len(conf) if conf else 0.0
    print("\n  levantou a taxa base em {:+.1f} pontos ({:.1f}% -> {:.1f}%)"
          .format(prec - base, base, prec))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--evidencia", default=os.path.join(AQUI, "saida_dev"))
    p.add_argument("--regra", default=os.path.join(AQUI, "regra_veredito.toml"))
    p.add_argument("--mapa", default=os.path.join(DEV_CEGA, "mapa_caso_item.csv"))
    p.add_argument("--anotacao",
                   default=os.path.join(DEV_CEGA, "saida", "anotacao_modelo_cve_visivel.csv"))
    p.add_argument("--dev-set", default=os.path.join(AQUI, "dev_set.tsv"))
    args = p.parse_args()

    for caminho in (args.mapa, args.anotacao):
        if not os.path.exists(caminho):
            sys.exit("ERRO: falta {}\n  (rode preparar_pacotes.py / anotar_modelo.ps1 / "
                     "consolidar_brutos.py --raiz dev antes)".format(caminho))

    regra = carregar_regra(args.regra)
    if regra["meta"].get("escolhida_olhando_rotulo"):
        print("AVISO: o .toml declara que a regra foi escolhida olhando rotulo. O numero\n"
              "abaixo nao e verificacao independente de nada.\n")
    if regra.get("verificacao_4b", {}).get("refinada_apos_4b"):
        print("AVISO: a regra ja foi REFINADA depois de ver o dev. O artigo tem que dizer\n"
              "'refinada', nao 'verificada', e a volta para a 4a e linha nas ameacas.\n")

    # rotulos: R=1, entao uma linha por caso
    rotulo = {}
    for r in ler_csv(args.anotacao):
        rotulo[int(r["id"])] = (r["tipo_ruido"].strip().upper(), r["confianca"].strip())

    # irmaos de commit com o teste — a ressalva declarada na Etapa 4a
    irmao = {r["item"]: r["irmao_de_commit_do_teste"].strip() == "sim"
             for r in ler_csv(args.dev_set, sep="\t")}

    evid = {}
    for caminho in glob.glob(os.path.join(args.evidencia, "*.json")):
        with open(caminho, encoding="utf-8") as fh:
            e = json.load(fh)
        evid[e["item"]] = e

    linhas, sem_evidencia = [], []
    for m in ler_csv(args.mapa):
        item, caso = m["item"], int(m["caso"])
        tipo, conf = rotulo.get(caso, ("", ""))
        if item not in evid:
            sem_evidencia.append(item)
            continue
        v, motivo, n1, n2 = julgar(evid[item], regra)
        linhas.append({"item": item, "caso": caso, "veredito": v, "tipo": tipo,
                       "confianca": conf, "c1": n1, "c2": n2, "irmao": irmao.get(item, False)})

    print("regra {} ({}), conector {}".format(
        regra["meta"]["versao"], regra["meta"]["fixada_em"], regra["veredito"]["conector"]))
    if sem_evidencia:
        print("sem evidencia da curadoria (falha de download, fora da conta): {}"
              .format(", ".join(sorted(sem_evidencia))))

    print("\n{:<22} {:>5} {:<14} {:>5} {:>8} {:>6} {:>6}".format(
        "item", "caso", "veredito", "tipo", "confianca", "c1", "c2"))
    for l in sorted(linhas, key=lambda x: x["item"]):
        print("{:<22} {:>5} {:<14} {:>5} {:>8} {:>6} {:>6}{}".format(
            l["item"], l["caso"], l["veredito"], l["tipo"] or "-", l["confianca"] or "-",
            l["c1"], l["c2"], "   (irmao do teste)" if l["irmao"] else ""))

    bloco("dev completo", linhas)
    bloco("sem os irmaos de commit do teste", [l for l in linhas if not l["irmao"]])
    print("\nA leitura vale se as duas versoes contarem a mesma historia. Se divergirem,\n"
          "vale a de baixo — dev e teste nao sao independentes por commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
