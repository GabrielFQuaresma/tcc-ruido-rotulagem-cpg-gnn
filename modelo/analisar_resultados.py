#!/usr/bin/env python3
"""Analise principal + checagem de tamanho, exatamente como os dois pre-registros congelados.

    python3 analisar_resultados.py --particao validacao                # ENSAIO (passo 5): nao e resultado
    python3 analisar_resultados.py --particao teste --abrir-teste      # ABERTURA (passo 6): uma vez
    python3 analisar_resultados.py --particao teste --abrir-teste --refazer "motivo"   # passo 7

ONDE ESTAMOS. Os 13 bracos do ReVeal estao treinados e a Fase II foi refeita com os modelos salvos
(IMPLEMENTACAO.md §6-7). A traversal rodou nas negativas do teste (traversal/
TRAVERSAL_NEGATIVOS_TESTE.md). Este script e o passo 4 da ordem de abertura
(PREREGISTRO_PRINCIPAL.md §6): calcula as tabelas que os dois pre-registros fixaram, e nada alem.

O QUE ELE CONFERE ANTES DE CALCULAR (se algo nao bater, para):
  - SHA-256 do PREREGISTRO_TAMANHO.md e do PREREGISTRO_PRINCIPAL.md;
  - congelamento da traversal v3 (`congelar.py --versao v3`), porque o veredito da "traversal
    pura" depende do regra_veredito.toml;
  - os ids de cada arquivo de predicao, na particao pedida, sao exatamente os do indice.

AUTOCONFERENCIAS (para achar defeito de codigo; o ensaio na validacao existe para isso):
  (a) so na validacao: o F1 que este script calcula em cada repeticao tem de ser IGUAL ao
      f1_validacao gravado no treino (semente_<s>.tsv.json) — mesma predicao, mesmos rotulos;
  (b) contagem de positivos e negativos por faixa de tamanho;
  (c) o veredito que este script aplica (veredito.julgar + regra_veredito.toml) aos positivos de
      TREINO e VALIDACAO tem de bater com traversal/conjuntos_v3/M_raw.tsv, e os confirmados de
      treino tem de ser 523 (o M_cur). Os positivos de TESTE nao entram nesta conferencia;
  (d) as 5241 evidencias das negativas do teste tem a estrutura que o veredito le (so estrutura,
      sem aplicar o veredito).

O QUE ELE NAO FAZ: nao escolhe nada. Limiar 0,5 (D12), mediana das 30 repeticoes, faixa dos 5
controles com empate = dentro, faixas e minimos de 30 do PREREGISTRO_TAMANHO, veredito de tamanho
por desenho e arena (E2/E3), so o F1 decide (decisao A). A "traversal pura" so e calculada no
TESTE: as negativas da validacao nao passaram pela regra.

SAIDA: um relatorio .md e um .json com todas as metricas por repeticao.
  - validacao: ~/curadoria/modelo/analise/ensaio_validacao.{md,json} (fora do repositorio: o
    ensaio nao e resultado);
  - teste: Dataset/bigvul/modelo/resultado_teste_bigvul.{md,json}. Se ja existir, so roda de novo
    com --refazer "motivo" (passo 7 do pre-registro: as duas versoes ficam).
"""

import argparse
import csv
import datetime
import hashlib
import json
import os
import subprocess
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reveal_comum as C  # noqa: E402

AQUI = os.path.dirname(os.path.abspath(__file__))
TRAVERSAL = C.TRAVERSAL
sys.path.insert(0, TRAVERSAL)
import veredito as V  # noqa: E402  o mesmo modulo que aplicou a regra aos positivos

PREREGISTROS = {
    "PREREGISTRO_TAMANHO.md": "57c0a26f79cb6b36248f8852ad8ba327ece0742e47a430aafe08afc28826e8ee",
    "PREREGISTRO_PRINCIPAL.md": "dbb2269cc6f1f76b176c8cedc426b3a85137b924f06b98c06def91e2209ab86c",
}
PRED = os.path.join(C.SAIDA, "fase2_v2")              # PREREGISTRO_PRINCIPAL §1: o conjunto oficial
EVID_POS = os.path.join(TRAVERSAL, "saida_completa_v3")
EVID_NEG = os.path.join(TRAVERSAL, "saida_negativos_teste_v3")
REF_VEREDITO = os.path.join(TRAVERSAL, "conjuntos_v3", "M_raw.tsv")
REGRA = os.path.join(TRAVERSAL, "regra_veredito.toml")

# PREREGISTRO_TAMANHO §2: quartis dos positivos de treino, arredondados para cima
FAIXAS = [("ate 46", 0, 46), ("47-131", 47, 131), ("132-339", 132, 339), ("340+", 340, 10 ** 9)]
PEQUENAS, GRANDES = (0, 1), (2, 3)
MINIMO = 30                                            # PREREGISTRO_TAMANHO §3

DESENHOS = {
    "principal": ("M_cur", list(C.CONTROLES)),
    "par balanceado": ("M_cur_bal", [c + "_bal" for c in C.CONTROLES]),
}
ORDEM = ["M_raw", "M_cur"] + list(C.CONTROLES) + ["M_cur_bal"] + [c + "_bal" for c in C.CONTROLES]
METRICAS = ["f1", "recall", "precisao", "pr_auc", "mcc", "fpr"]


# ------------------------------------------------------------------------------------ conferencias

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def conferir_preregistros():
    for nome, esperado in PREREGISTROS.items():
        obtido = sha256(os.path.join(AQUI, nome))
        if obtido != esperado:
            sys.exit("PRE-REGISTRO ALTERADO: %s\n  esperado %s\n  obtido   %s\nNao rodo."
                     % (nome, esperado, obtido))
    r = subprocess.run([sys.executable, os.path.join(TRAVERSAL, "congelar.py"), "--versao", "v3"],
                       capture_output=True, text=True, cwd=TRAVERSAL)
    if r.returncode != 0 or "ok" not in r.stdout:
        sys.exit("CONGELAMENTO DA TRAVERSAL V3 NAO CONFERE — nao rodo.\n" + r.stdout + r.stderr)
    return "os dois pre-registros e os 4 arquivos de regra da traversal v3 conferem"


# ------------------------------------------------------------------------------------------- dados

def carregar_indice(particao):
    ids, y, nos = [], [], []
    with open(C.INDICE, encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r["particao"] == particao:
                ids.append(r["id"])
                y.append(int(r["rotulo"]))
                nos.append(int(r["n_nos"]))
    ordem = np.argsort(ids)
    return ([ids[i] for i in ordem], np.array(y)[ordem], np.array(nos)[ordem])


def faixa_de(nos):
    out = np.full(len(nos), -1)
    for k, (_, lo, hi) in enumerate(FAIXAS):
        out[(nos >= lo) & (nos <= hi)] = k
    assert (out >= 0).all()
    return out


def carregar_predicao(braco, semente, particao, ids):
    arq = os.path.join(PRED, braco, "semente_%d.tsv" % semente)
    prob, pred = {}, {}
    with open(arq, encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r["particao"] == particao:
                prob[r["id"]] = float(r["prob_vulneravel"])
                pred[r["id"]] = int(r["predicao"])
    if set(prob) != set(ids) or len(prob) != len(ids):
        sys.exit("ids de %s semente %d na particao %s nao batem com o indice" % (braco, semente, particao))
    return np.array([prob[i] for i in ids]), np.array([pred[i] for i in ids])


# ----------------------------------------------------------------------------------------- metricas

def metricas(y, pred, prob=None):
    from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    m = {"f1": float(f1_score(y, pred, zero_division=0)),
         "recall": tp / (tp + fn) if tp + fn else float("nan"),
         "precisao": tp / (tp + fp) if tp + fp else 0.0,
         "fpr": fp / (fp + tn) if fp + tn else float("nan"),
         "mcc": float(matthews_corrcoef(y, pred)),
         "tp": tp, "fp": fp, "fn": fn, "tn": tn}
    if prob is not None:
        m["pr_auc"] = float(average_precision_score(y, prob))
    return m


def resumo(vals):
    v = np.array(vals, dtype=float)
    return {"mediana": float(np.median(v)), "q1": float(np.percentile(v, 25)),
            "q3": float(np.percentile(v, 75))}


def posicao(x, controles):
    """PREREGISTRO_PRINCIPAL §3 e E4: estritamente acima do maior / abaixo do menor; empate = dentro."""
    if x > max(controles):
        return "acima"
    if x < min(controles):
        return "abaixo"
    return "dentro"


# ------------------------------------------------------------------------------- traversal pura

def veredito_positivo(item, regra):
    p = os.path.join(EVID_POS, item + ".json")
    if not os.path.exists(p):
        return "sem_evidencia"
    return V.julgar(json.load(open(p, encoding="utf-8")), regra)[0]


def veredito_negativo(id_, regra):
    p = os.path.join(EVID_NEG, id_ + ".json")
    if not os.path.exists(p):
        return "sem_evidencia"
    r = json.load(open(p, encoding="utf-8"))
    if "evidencia" not in r:
        return "falha"
    return V.julgar(r["evidencia"], regra)[0]


# ------------------------------------------------------------------------------- autoconferencias

def autoconf_f1_validacao(por_semente):
    difs = []
    for b in ORDEM:
        for s in C.F2_SEMENTES:
            gravado = json.load(open(os.path.join(PRED, b, "semente_%d.tsv.json" % s)))["f1_validacao"]
            difs.append(abs(round(por_semente[b][s]["geral"]["f1"], 4) - gravado))
    return max(difs), sum(d > 1e-9 for d in difs), len(difs)


def autoconf_veredito_positivos(regra):
    ref = {r["item"]: r["veredito"]
           for r in csv.DictReader(open(REF_VEREDITO, encoding="utf-8"), delimiter="\t")}
    conf = {"treino": 0, "validacao": 0}
    difere, n = [], 0
    with open(C.INDICE, encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r["rotulo"] != "1" or r["particao"] not in conf:
                continue                                   # positivos de TESTE ficam de fora
            v = veredito_positivo(r["id"], regra)
            n += 1
            conf[r["particao"]] += v == V.CONFIRMADO
            if ref.get(r["id"]) != v:
                difere.append((r["id"], v, ref.get(r["id"])))
    return n, difere, conf


def autoconf_estrutura_negativas():
    ids, _, _ = carregar_indice("teste")
    y = dict(zip(*carregar_indice("teste")[:2]))
    neg = [i for i in ids if y[i] == 0]
    ruins = 0
    for i in neg:
        p = os.path.join(EVID_NEG, i + ".json")
        try:
            e = json.load(open(p, encoding="utf-8"))["evidencia"]
            ok = all(k in e for k in ("camada1", "camada2", "saude"))
        except Exception:
            ok = False
        ruins += not ok
    return len(neg), ruins


# ------------------------------------------------------------------------------------------- main

def fmt(x, casas=3):
    return "—" if x is None or (isinstance(x, float) and np.isnan(x)) else ("%." + str(casas) + "f") % x


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--particao", choices=["validacao", "teste"], required=True)
    ap.add_argument("--abrir-teste", action="store_true", help="obrigatorio para --particao teste")
    ap.add_argument("--refazer", default="", help="motivo; so com teste ja aberto (passo 7)")
    a = ap.parse_args()
    P = a.particao
    if P == "teste" and not a.abrir_teste:
        sys.exit("Abrir o teste exige --abrir-teste (PREREGISTRO_PRINCIPAL §6, passo 6).")
    if P == "teste":
        destino = os.path.join(AQUI, "resultado_teste_bigvul")
        if os.path.exists(destino + ".md"):
            if not a.refazer:
                sys.exit("O teste ja foi aberto (%s.md existe). Refazer so com --refazer \"motivo\" "
                         "(passo 7: as duas versoes ficam)." % destino)
            carimbo = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            for ext in (".md", ".json"):
                if os.path.exists(destino + ext):
                    os.replace(destino + ext, destino + "_anterior_" + carimbo + ext)
    else:
        destino = os.path.join(C.SAIDA, "analise", "ensaio_validacao")
        os.makedirs(os.path.dirname(destino), exist_ok=True)

    linhas_conf = [conferir_preregistros()]
    regra = V.carregar_regra(REGRA)

    ids, y, nos = carregar_indice(P)
    fx = faixa_de(nos)
    cont = [(int(((fx == k) & (y == 1)).sum()), int(((fx == k) & (y == 0)).sum())) for k in range(4)]

    # ---- metricas por braco, semente e faixa
    por_semente = {}
    for b in ORDEM:
        por_semente[b] = {}
        for s in C.F2_SEMENTES:
            prob, pred = carregar_predicao(b, s, P, ids)
            d = {"geral": metricas(y, pred, prob), "faixas": []}
            for k in range(4):
                m = fx == k
                d["faixas"].append(metricas(y[m], pred[m]))
            por_semente[b][s] = d

    def serie(b, metrica, faixa=None):
        if faixa is None:
            return [por_semente[b][s]["geral"][metrica] for s in C.F2_SEMENTES]
        return [por_semente[b][s]["faixas"][faixa][metrica] for s in C.F2_SEMENTES]

    resumo_geral = {b: {m: resumo(serie(b, m)) for m in METRICAS} for b in ORDEM}
    resumo_faixa = {b: [{m: resumo(serie(b, m, k)) for m in ("f1", "recall", "fpr")} for k in range(4)]
                    for b in ORDEM}

    # ---- comparacao principal (§3) e checagem de tamanho (PREREGISTRO_TAMANHO §5-6, E1-E4)
    comparacoes, tamanho = {}, {}
    for nome, (cur, ctrls) in DESENHOS.items():
        x = resumo_geral[cur]["f1"]["mediana"]
        cs = [resumo_geral[c]["f1"]["mediana"] for c in ctrls]
        comparacoes[nome] = {"m_cur": x, "min": min(cs), "max": max(cs), "posicao": posicao(x, cs)}

        # V1 — inclinacao do FPR (340+ menos ate 46), por repeticao, mediana das 30
        v1_aplica = cont[0][1] >= MINIMO and cont[3][1] >= MINIMO
        incl = {b: float(np.median([por_semente[b][s]["faixas"][3]["fpr"] - por_semente[b][s]["faixas"][0]["fpr"]
                                    for s in C.F2_SEMENTES])) for b in [cur] + ctrls}
        v1 = None if not v1_aplica else incl[cur] > max(incl[c] for c in ctrls)

        # V2 — F1 acima da faixa em >=1 grande e em nenhuma pequena; so faixas com 30 positivos
        acima = {}
        for k in range(4):
            if cont[k][0] >= MINIMO:
                acima[k] = posicao(resumo_faixa[cur][k]["f1"]["mediana"],
                                   [resumo_faixa[c][k]["f1"]["mediana"] for c in ctrls]) == "acima"
        peq = [k for k in PEQUENAS if k in acima]
        gra = [k for k in GRANDES if k in acima]
        nao_previsto = bool(peq) and not gra
        v2 = None if (not peq or not gra) else (any(acima[k] for k in gra) and not any(acima[k] for k in peq))
        if v1 is None and v2 is None:
            ver = "nao verificavel"
        elif v1 or v2:
            ver = "evidencia de vies de tamanho"
        else:
            ver = "sem evidencia de vies de tamanho"
        tamanho[nome] = {"v1_aplica": v1_aplica, "v1": v1, "inclinacao": incl, "v2": v2,
                         "acima_por_faixa": {FAIXAS[k][0]: acima[k] for k in acima},
                         "caso_nao_previsto_v2_sem_faixa_grande": nao_previsto, "veredito": ver}

    # ---- traversal pura (§7) — so no teste
    trav = None
    if P == "teste":
        pred_t = np.array([1 if (veredito_positivo(i, regra) if y[j] == 1 else veredito_negativo(i, regra))
                           == V.CONFIRMADO else 0 for j, i in enumerate(ids)])
        trav = metricas(y, pred_t)

    # ---- autoconferencias
    if P == "validacao":
        dmax, ndif, ntot = autoconf_f1_validacao(por_semente)
        linhas_conf.append("(a) F1 por repeticao = f1_validacao gravado no treino: %d de %d iguais "
                           "(maior diferenca %.6f)" % (ntot - ndif, ntot, dmax))
    esperado_val = [(41, 1732), (74, 1175), (72, 541), (68, 226)]
    esperado_tes = [(37, 2096), (129, 1732), (135, 968), (188, 445)]
    esperado = esperado_val if P == "validacao" else esperado_tes
    linhas_conf.append("(b) contagem por faixa (positivos, negativos) %s o medido em 12/10: %s"
                       % ("BATE com" if cont == esperado else "NAO BATE com", cont))
    n, difere, conf = autoconf_veredito_positivos(regra)
    linhas_conf.append("(c) veredito recalculado de %d positivos de treino+validacao: %d diferem de "
                       "conjuntos_v3/M_raw.tsv; confirmados de treino = %d (M_cur = 523)"
                       % (n, len(difere), conf["treino"]))
    nn, ruins = autoconf_estrutura_negativas()
    linhas_conf.append("(d) evidencias das negativas do teste com a estrutura que o veredito le: "
                       "%d de %d (so estrutura, sem veredito)" % (nn - ruins, nn))

    # ---- relatorio
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    L = []
    if P == "validacao":
        L += ["# ENSAIO na validacao — NAO E RESULTADO", "",
              "> Gerado em %s por `analisar_resultados.py --particao validacao` (PREREGISTRO_PRINCIPAL"
              ".md §6, passo 5). Serve para achar defeito de codigo antes de abrir o teste. A validacao"
              " ja foi usada para escolher a epoca da GGNN e da Fase II; nada daqui entra no texto." % agora, ""]
    else:
        L += ["# Resultado no teste do BigVul (dentro da distribuicao)", "",
              "> Gerado em %s por `analisar_resultados.py --particao teste --abrir-teste`, seguindo o "
              "PREREGISTRO_PRINCIPAL.md e o PREREGISTRO_TAMANHO.md (hashes conferidos). No BigVul a "
              "metrica mede concordancia com o rotulo do BigVul (§4 do pre-registro)." % agora, ""]
        if a.refazer:
            L += ["> **Refeito** (passo 7): %s. A versao anterior foi mantida com sufixo `_anterior_`." % a.refazer, ""]
    L += ["## Conferencias", ""] + ["- " + x for x in linhas_conf]
    if difere:
        L += ["  - exemplos de diferenca: %s" % difere[:5]]
    L += ["", "Particao: %s — %d funcoes, %d positivas, %d negativas." % (P, len(y), int(y.sum()), int((y == 0).sum())), ""]

    L += ["## Comparacao que decide (§3): F1, mediana das 30 repeticoes", "",
          "| desenho | M_cur | faixa dos 5 controles | posicao |", "| --- | --- | --- | --- |"]
    for nome, c in comparacoes.items():
        L.append("| %s | %s | %s a %s | **%s** |" % (nome, fmt(c["m_cur"]), fmt(c["min"]), fmt(c["max"]), c["posicao"]))
    L += ["", "Leitura (§3): acima ou abaixo por acaso 1 vez em 6 cada; dentro 4 vezes em 6. Desenho "
          "principal decide; par balanceado e sensibilidade (§7).", ""]

    L += ["## Checagem de tamanho (PREREGISTRO_TAMANHO §6; E1-E4)", "",
          "| desenho | V1 (inclinacao do FPR) | V2 (ganho so nas grandes) | veredito |", "| --- | --- | --- | --- |"]
    for nome, t in tamanho.items():
        cur = DESENHOS[nome][0]
        incl_c = [t["inclinacao"][c] for c in DESENHOS[nome][1]]
        v1s = "nao se aplica" if t["v1"] is None else ("DISPARA" if t["v1"] else "nao dispara")
        v2s = "nao se aplica" if t["v2"] is None else ("DISPARA" if t["v2"] else "nao dispara")
        L.append("| %s | %s (M_cur %s; controles %s a %s) | %s (acima em: %s) | **%s** |"
                 % (nome, v1s, fmt(t["inclinacao"][cur]), fmt(min(incl_c)), fmt(max(incl_c)), v2s,
                    ", ".join(k for k, v in t["acima_por_faixa"].items() if v) or "nenhuma", t["veredito"]))
        if t["caso_nao_previsto_v2_sem_faixa_grande"]:
            L.append("| | CASO NAO PREVISTO: nenhuma faixa grande com 30 positivos | | |")
    L += ["", "Qualifica a conclusao so o veredito do desenho principal (E2). Ele vai lado a lado com o "
          "resultado do §3, nunca o rebaixa a inconclusivo (E1).", ""]

    L += ["## Contagem por faixa de tamanho", "", "| faixa (nos) | positivos | negativos |", "| --- | --- | --- |"]
    for k, (nome, _, _) in enumerate(FAIXAS):
        L.append("| %s | %d | %d |" % (nome, cont[k][0], cont[k][1]))
    L.append("")

    L += ["## Todas as metricas, por braco (mediana [Q1–Q3] das 30 repeticoes; descritivas)", "",
          "| braco | F1 | recall | precisao | PR-AUC | MCC | FPR |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for b in ORDEM:
        r = resumo_geral[b]
        L.append("| %s | %s |" % (b, " | ".join("%s [%s–%s]" % (fmt(r[m]["mediana"]), fmt(r[m]["q1"]), fmt(r[m]["q3"]))
                                               for m in METRICAS)))
    L.append("")
    for metr, titulo, idx_min in (("f1", "F1", 0), ("recall", "recall (descritivo)", 0), ("fpr", "taxa de falso positivo", 1)):
        L += ["## %s por faixa de tamanho (mediana das 30)" % titulo, "",
              "| braco | " + " | ".join(f[0] for f in FAIXAS) + " |", "| --- |" + " --- |" * 4]
        for b in ORDEM:
            cel = []
            for k in range(4):
                cel.append(fmt(resumo_faixa[b][k][metr]["mediana"]) if cont[k][idx_min] >= MINIMO
                           else "so contagem (n=%d)" % cont[k][idx_min])
            L.append("| %s | %s |" % (b, " | ".join(cel)))
        L.append("")

    if trav is not None:
        L += ["## Traversal pura (§7; descritiva)", "",
              "| classificador | F1 | recall | precisao | FPR |", "| --- | --- | --- | --- | --- |",
              "| traversal v3 (confirmado = acusa) | %s | %s | %s | %s |"
              % (fmt(trav["f1"]), fmt(trav["recall"]), fmt(trav["precisao"]), fmt(trav["fpr"])),
              "| M_cur (mediana das 30) | %s | %s | %s | %s |"
              % tuple(fmt(resumo_geral["M_cur"][m]["mediana"]) for m in ("f1", "recall", "precisao", "fpr")), ""]
    else:
        L += ["## Traversal pura", "", "Nao calculada nesta particao: as negativas da validacao nao passaram "
              "pela regra. So no teste.", ""]

    with open(destino + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    with open(destino + ".json", "w", encoding="utf-8") as f:
        json.dump({"particao": P, "gerado": agora, "contagem_faixas": cont, "comparacoes": comparacoes,
                   "tamanho": tamanho, "traversal_pura": trav, "resumo_geral": resumo_geral,
                   "resumo_faixa": resumo_faixa,
                   "por_semente": {b: {str(s): v for s, v in d.items()} for b, d in por_semente.items()}},
                  f, ensure_ascii=False, indent=1)
    print("\n".join(linhas_conf))
    print("relatorio:", destino + ".md")


if __name__ == "__main__":
    main()
