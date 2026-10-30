#!/usr/bin/env python3
"""Etapa 5, passo 3 — a precisao do filtro de curadoria medida nos 50 casos anotados.

ESTE E O NUMERO. A precisao medida no dev (Etapa 4b) era guarda-corpo: rotulo de modelo,
n=27, e a regra ainda podia mudar. Aqui a regra esta congelada por SHA-256 (CONGELAMENTO.md),
os rotulos sao do anotador humano, e o resultado entra no artigo.

    python3 etapa_5.py                    # a medida, com todos os recortes
    python3 etapa_5.py --tsv saida_50/_etapa5.tsv

A PRIMEIRA COISA QUE O SCRIPT FAZ e conferir o congelamento. Se algum arquivo de regra tiver
mudado desde o congelamento, ele recusa rodar — porque nesse caso o numero mediria uma regra
escrita depois de ver o teste, e nao valeria nada. E a mesma logica do `comparar.py`, que
recusa rodar sem o pre-registro.

O QUE E COMPARADO COM O QUE
---------------------------
  veredito da curadoria   confirmado / descartado / indeterminado   (regra_veredito.toml v1)
  rotulo do anotador      A / B / C / D                             (rubrica_v1.md, congelada)

  D  = a funcao marcada pelo BigVul e de fato o sitio da vulnerabilidade -> o filtro DEVERIA
       confirmar.
  A/B/C = rotulo suspeito (funcao inalterada, funcao de carona no commit, outra coisa) -> o
       filtro DEVERIA descartar.

  PRECISAO DO FILTRO = D entre os confirmados. E a unica medida que interessa, porque o
  silencio da traversal nao inverte rotulo: quem e descartado apenas nao entra no M_cur.
  Recall (cobertura dos D) e reportado por transparencia e NAO e criterio.

OS RECORTES FORAM FIXADOS ANTES, e nao escolhidos depois de ver a tabela:
  1. os 50 completos                      — a medida principal
  2. sem `1217__libgd`                    — o caso de regressao esta dentro da amostra dos 50
                                            e a traversal foi conferida contra ele desde a
                                            Etapa 0. Nao e cego. Sai, e a medida e refeita.
  3. por commit (1a linha de cada commit)  — pre_registro.md, "Nao-independencia das linhas":
                                            50 linhas, 37 commits, 14 da mesma CVE.
  4. IC 95% por bootstrap de cluster de commit, 10.000 reamostragens, semente 42 — a convencao
     ja usada no pre_registro.md. Com n destes tamanhos, reportar o ponto sem o intervalo e
     que seria escolher o numero.

FORA DA CONTA, e cada um por um motivo diferente:
  sem evidencia   — a curadoria nao produziu JSON (perda de download ou funcao nao encontrada
                    no CPG). Falha de ferramenta ANTES do veredito.
  indeterminado   — a curadoria olhou e nao conseguiu ver (corpo nao parseado, fluxo estourado).
                    Falha de ferramenta DENTRO do veredito. Nao vira "rotulo suspeito".
  rotulo '?'      — o anotador nao decidiu. O pre_registro.md ja mandava excluir; nao e uma
                    quinta categoria, e ausencia de decisao.
"""

import argparse
import csv
import glob
import json
import os
import random
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
BIGVUL = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)

from congelar import conferir                                        # noqa: E402
from veredito import carregar_regra, julgar, CONFIRMADO, INDETERMINADO  # noqa: E402

CASO_REGRESSAO = "1217__libgd"
N_BOOT, SEMENTE_BOOT = 10000, 42


def ler_csv(caminho, sep=","):
    with open(caminho, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh, delimiter=sep))


def rotulo_limpo(s):
    """'D\\r', ' d ', 'D\\t' -> 'D'. Qualquer outra coisa -> '?'.

    O CSV anotado a mao carrega \\r e \\t no fim de varios campos. Casar por string crua
    jogaria dois D fora da conta em silencio, e dois D e 4% da amostra.
    """
    t = (s or "").strip().strip("\r\n\t ").upper()
    return t if t in ("A", "B", "C", "D") else "?"


def taxa(k, n):
    return "{}/{} = {:.1f}%".format(k, n, 100.0 * k / n) if n else "{}/0 = —".format(k)


def voto_do_modelo(linhas_do_caso):
    """Voto majoritario entre as R repeticoes; empate resolve para '?' (pre_registro.md)."""
    votos = {}
    for r in linhas_do_caso:
        t = rotulo_limpo(r["tipo_ruido"])
        votos[t] = votos.get(t, 0) + 1
    melhor = max(votos.values())
    vencedores = [t for t, v in votos.items() if v == melhor]
    return vencedores[0] if len(vencedores) == 1 else "?"


# --------------------------------------------------------------------------
# A medida
# --------------------------------------------------------------------------

def medir(linhas, chave_rotulo):
    """Devolve o dicionario com as contagens de um recorte, ou None se nao ha comparaveis."""
    vistos = [l for l in linhas
              if l["veredito"] != INDETERMINADO and l[chave_rotulo] in "ABCD"]
    if not vistos:
        return None
    conf = [l for l in vistos if l["veredito"] == CONFIRMADO]
    desc = [l for l in vistos if l["veredito"] != CONFIRMADO]
    d = lambda ls: sum(1 for l in ls if l[chave_rotulo] == "D")  # noqa: E731
    return {
        "vistos": vistos, "conf": conf, "desc": desc,
        "n": len(vistos), "n_conf": len(conf), "n_desc": len(desc),
        "d_total": d(vistos), "d_conf": d(conf), "d_desc": d(desc),
        "base": 100.0 * d(vistos) / len(vistos),
        "precisao": 100.0 * d(conf) / len(conf) if conf else float("nan"),
    }


def bootstrap_cluster(linhas, chave_rotulo, n_boot=N_BOOT, semente=SEMENTE_BOOT):
    """IC 95% da precisao e do delta, reamostrando CLUSTERS DE COMMIT com reposicao.

    Bootstrap por linha subestimaria a incerteza: 14 das 50 linhas sao a mesma CVE e nao sao
    observacoes independentes. E a mesma escolha do pre_registro.md.
    """
    vistos = [l for l in linhas
              if l["veredito"] != INDETERMINADO and l[chave_rotulo] in "ABCD"]
    clusters = {}
    for l in vistos:
        clusters.setdefault(l["commit"], []).append(l)
    chaves = list(clusters)
    if not chaves:
        return None

    rnd = random.Random(semente)
    precisoes, deltas, vazios = [], [], 0
    for _ in range(n_boot):
        amostra = []
        for _ in range(len(chaves)):
            amostra.extend(clusters[chaves[rnd.randrange(len(chaves))]])
        conf = [l for l in amostra if l["veredito"] == CONFIRMADO]
        if not conf:
            vazios += 1                      # reamostragem sem nenhum confirmado: nao ha razao
            continue                         # a estimar; contada e reportada, nao mascarada
        prec = 100.0 * sum(1 for l in conf if l[chave_rotulo] == "D") / len(conf)
        base = 100.0 * sum(1 for l in amostra if l[chave_rotulo] == "D") / len(amostra)
        precisoes.append(prec)
        deltas.append(prec - base)

    def pct(v, p):
        v = sorted(v)
        return v[min(len(v) - 1, max(0, int(round(p / 100.0 * (len(v) - 1)))))]

    return {
        "n_clusters": len(chaves), "n_validas": len(precisoes), "vazios": vazios,
        "prec_lo": pct(precisoes, 2.5), "prec_hi": pct(precisoes, 97.5),
        "delta_lo": pct(deltas, 2.5), "delta_hi": pct(deltas, 97.5),
    }


def bloco(nome, linhas, chave_rotulo, com_ic=False):
    m = medir(linhas, chave_rotulo)
    indet = [l for l in linhas if l["veredito"] == INDETERMINADO]
    duvida = [l for l in linhas
              if l["veredito"] != INDETERMINADO and l[chave_rotulo] not in "ABCD"]

    print("\n=== {} ===".format(nome))
    print("linhas {} | indeterminados {} | rotulo '?' {} | comparaveis {}"
          .format(len(linhas), len(indet), len(duvida), m["n"] if m else 0))
    if indet:
        print("  indeterminados (ferramenta nao olhou): {}"
              .format(", ".join(l["item"] for l in indet)))
    if duvida:
        print("  rotulo '?' (anotador nao decidiu): {}"
              .format(", ".join(l["item"] for l in duvida)))
    if not m:
        return None

    print("\n  {:<14} {:>5} {:>5} {:>5} {:>5} | {:>5}".format("", "A", "B", "C", "D", "n"))
    for rot, ls in (("confirmado", m["conf"]), ("descartado", m["desc"])):
        print("  {:<14} {:>5} {:>5} {:>5} {:>5} | {:>5}".format(
            rot, *[sum(1 for l in ls if l[chave_rotulo] == t) for t in "ABCD"], len(ls)))

    print("\n  taxa base (D / comparaveis) ............. {}".format(taxa(m["d_total"], m["n"])))
    print("  PRECISAO do filtro (D / confirmados) .... {}".format(taxa(m["d_conf"], m["n_conf"])))
    print("  entre os descartados, eram D ............ {}".format(taxa(m["d_desc"], m["n_desc"])))
    print("  cobertura dos D (D confirmados / D) ..... {}".format(taxa(m["d_conf"], m["d_total"])))
    print("     ^ recall NAO e criterio: o silencio nao inverte rotulo, so remove do curado.")
    print("\n  levantou a taxa base em {:+.1f} pontos ({:.1f}% -> {:.1f}%)"
          .format(m["precisao"] - m["base"], m["base"], m["precisao"]))

    if com_ic:
        ic = bootstrap_cluster(linhas, chave_rotulo)
        if ic:
            print("\n  IC 95% por bootstrap de cluster de commit "
                  "({} clusters, {} reamostragens validas de {}):"
                  .format(ic["n_clusters"], ic["n_validas"], N_BOOT))
            print("    precisao ... [{:.1f}% ; {:.1f}%]".format(ic["prec_lo"], ic["prec_hi"]))
            print("    delta ...... [{:+.1f} ; {:+.1f}] pontos".format(
                ic["delta_lo"], ic["delta_hi"]))
            if ic["vazios"]:
                print("    ({} reamostragens sem nenhum confirmado, descartadas)"
                      .format(ic["vazios"]))
    return m


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--evidencia", default=os.path.join(AQUI, "saida_50"))
    p.add_argument("--regra", default=os.path.join(AQUI, "regra_veredito.toml"))
    p.add_argument("--mapa", default=os.path.join(AQUI, "mapa_caso_item_50.csv"))
    p.add_argument("--humano",
                   default=os.path.join(BIGVUL, "saida", "amostra_validacao_revisao.csv"))
    p.add_argument("--modelo",
                   default=os.path.join(BIGVUL, "validacao_cega", "saida",
                                        "anotacao_modelo_cve_visivel.csv"))
    p.add_argument("--tsv", default=os.path.join(AQUI, "saida_50", "_etapa5.tsv"))
    p.add_argument("--ignorar-congelamento", action="store_true",
                   help="NAO use isto para produzir numero de artigo")
    args = p.parse_args()

    # --- o portao ------------------------------------------------------------------
    print("--- congelamento (CONGELAMENTO.md) ---")
    if conferir() != 0:
        if not args.ignorar_congelamento:
            print("\nRECUSANDO RODAR. Sem o congelamento intacto, este numero mediria uma regra\n"
                  "que pode ter sido escrita depois de ver o teste.")
            return 1
        print("\nAVISO: rodando com o congelamento quebrado, a pedido. O numero abaixo NAO\n"
              "pode ir para o artigo.")

    regra = carregar_regra(args.regra)
    if regra["meta"].get("escolhida_olhando_rotulo"):
        print("\nAVISO: o .toml declara que a regra foi escolhida olhando rotulo.")
    print("\nregra {} ({}), conector {}".format(
        regra["meta"]["versao"], regra["meta"]["fixada_em"], regra["veredito"]["conector"]))

    # --- rotulos -------------------------------------------------------------------
    humano = {}
    for r in ler_csv(args.humano):
        humano[int(r["id"])] = (rotulo_limpo(r["tipo_ruido"]),
                                (r.get("confianca") or "").strip().strip("\r\n\t "))

    por_caso = {}
    for r in ler_csv(args.modelo):
        por_caso.setdefault(int(r["id"]), []).append(r)
    modelo = {caso: voto_do_modelo(ls) for caso, ls in por_caso.items()}
    reps = {len(ls) for ls in por_caso.values()}
    print("anotacao do modelo: {} casos, R={} (voto majoritario, empate -> '?')"
          .format(len(por_caso), sorted(reps)))

    # --- evidencia -----------------------------------------------------------------
    evid = {}
    for caminho in glob.glob(os.path.join(args.evidencia, "*.json")):
        with open(caminho, encoding="utf-8") as fh:
            e = json.load(fh)
        evid[e["item"]] = e

    linhas, sem_evidencia = [], []
    for m in ler_csv(args.mapa):
        caso, item = int(m["caso"]), m["item"]
        if not item or item not in evid:
            sem_evidencia.append("caso_{:02d} {}".format(caso, item or "(sem pasta)"))
            continue
        v, motivo, n1, n2 = julgar(evid[item], regra)
        rot_h, conf_h = humano.get(caso, ("?", ""))
        linhas.append({"caso": caso, "item": item, "commit": m["commit"], "cve": m["cve"],
                       "veredito": v, "motivo": motivo, "c1": n1, "c2": n2,
                       "humano": rot_h, "confianca": conf_h,
                       "modelo": modelo.get(caso, "?")})

    if sem_evidencia:
        print("sem evidencia da curadoria (falha de ferramenta, fora da conta): {}"
              .format(", ".join(sem_evidencia)))

    # --- por item ------------------------------------------------------------------
    print("\n{:>5} {:<24} {:<14} {:>7} {:>7} {:>5} {:>5}".format(
        "caso", "item", "veredito", "humano", "modelo", "c1", "c2"))
    for l in sorted(linhas, key=lambda x: x["caso"]):
        print("{:>5} {:<24} {:<14} {:>7} {:>7} {:>5} {:>5}{}".format(
            l["caso"], l["item"], l["veredito"], l["humano"], l["modelo"], l["c1"], l["c2"],
            "   (caso de regressao)" if l["item"] == CASO_REGRESSAO else ""))

    # --- M_cur ---------------------------------------------------------------------
    n_ind = sum(1 for l in linhas if l["veredito"] == INDETERMINADO)
    n_conf = sum(1 for l in linhas if l["veredito"] == CONFIRMADO)
    olhaveis = len(linhas) - n_ind
    print("\n--- tamanho do M_cur nesta amostra (sem olhar rotulo) ---")
    print("  com evidencia {} | indeterminados {} | olhaveis {} | confirmados {} ({:.1f}%)"
          .format(len(linhas), n_ind, olhaveis, n_conf, 100.0 * n_conf / max(1, olhaveis)))

    # --- os quatro recortes --------------------------------------------------------
    print("\n" + "=" * 74)
    print("MEDIDA PRINCIPAL — rotulo do anotador humano")
    print("=" * 74)
    bloco("os 50 completos", linhas, "humano", com_ic=True)
    bloco("sem o caso de regressao ({})".format(CASO_REGRESSAO),
          [l for l in linhas if l["item"] != CASO_REGRESSAO], "humano", com_ic=True)

    # uma linha por commit distinto: a primeira, na ordem do caso (pre_registro.md)
    vistos_commit, por_commit = set(), []
    for l in sorted(linhas, key=lambda x: x["caso"]):
        if l["commit"] in vistos_commit:
            continue
        vistos_commit.add(l["commit"])
        por_commit.append(l)
    bloco("por commit (1a linha de cada commit distinto)", por_commit, "humano", com_ic=False)

    print("\n" + "=" * 74)
    print("SENSIBILIDADE — rotulo do modelo (voto majoritario), NAO e ground truth")
    print("=" * 74)
    bloco("os 50 completos, rotulo do modelo", linhas, "modelo", com_ic=True)

    # --- gravar --------------------------------------------------------------------
    if args.tsv:
        campos = ["caso", "item", "commit", "cve", "veredito", "motivo",
                  "c1", "c2", "humano", "confianca", "modelo"]
        with open(args.tsv, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=campos, delimiter="\t")
            w.writeheader()
            for l in sorted(linhas, key=lambda x: x["caso"]):
                w.writerow({k: l[k] for k in campos})
        print("\npor item em {}".format(args.tsv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
