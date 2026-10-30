#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analise das arenas externas, exatamente como os tres pre-registros congelados.

    python3 analisar_arenas.py --ensaio-validacao      # ENSAIO no BigVul (validacao): nao e resultado
    python3 analisar_arenas.py --ensaio-sintetico      # ENSAIO com predicoes aleatorias: nao e resultado
    python3 analisar_arenas.py --abrir                 # ABERTURA das tres arenas, juntas, UMA vez (§10 passo 7)
    python3 analisar_arenas.py --abrir --refazer "motivo"   # §10 passo 8 (as duas versoes ficam)

ONDE ESTAMOS. PREREGISTRO_ARENAS.md (congelado em 15/10/2026), §10 passo 6: "Script de analise
estendido: confere o hash dos dois pre-registros, deste adendo, da regra da traversal e da ficha;
recusa rodar se algum nao bater. Ensaio na particao de validacao do BigVul e em predicoes sinteticas."

O QUE ELE CALCULA, e onde cada coisa foi fixada (nada aqui e escolha nova):
  - por arena e braco, cada metrica em cada uma das 30 repeticoes; o valor do braco e a mediana
    (PRINCIPAL §2); F1, recall, precisao, PR-AUC, MCC, taxa de falso positivo (§7);
  - minimo por arena (Decisao I): >= 30 positivos e >= 30 negativos, senao "abaixo do minimo";
  - a comparacao que decide (PRINCIPAL §3, §8, Decisoes A e C): F1 do M_cur contra a faixa dos 5
    controles no desenho principal; acima / dentro / abaixo, empate = dentro; o par balanceado como
    sensibilidade (§7);
  - o piso (Decisao J): excesso = VP - A*P/N por repeticao, com N = TODAS as funcoes da arena,
    mediana por braco; piso se nenhum dos seis bracos do desenho principal tiver excesso mediano > 2.
    O excesso de cada braco (e do M_raw) vai para o resultado. (Corrigido em 21/10/2026: a versao da
    abertura de 18/10 dividia so pelas nao vulneraveis; ver a funcao excesso);
  - a checagem de tamanho por desenho e arena (PREREGISTRO_TAMANHO §5-6, E1-E5), com a mesma regra
    do analisar_resultados.py que abriu o BigVul (V1 so com >= 30 negativos nas faixas ate 46 e 340+;
    V2 so com faixa pequena E grande com 30 positivos);
  - a traversal pura (Decisao K): veredito.julgar sobre a evidencia gravada; confirmado = acusa;
    falha da ferramenta = nao acusa; comparacao descritiva com o F1 mediano do M_cur;
  - a queda de F1 (BigVul - arena) por repeticao e a mediana, descritiva (PRINCIPAL §8), com a
    ressalva da proporcao de vulneraveis (adendo §0, Decisao M);
  - a sintese (Decisao M): entram PrimeVul e VentiVul com veredito (nem abaixo do minimo nem piso);
    "evidencia a favor" so se o M_cur ficar acima em TODAS; o texto de cada caso e o da tabela da M.
  - a sonda le-se como concordancia com o rotulo do BigVul (PRINCIPAL §4) e nao entra na sintese;
    o VentiVul inteiro e descritivo (G3), salvo se a troca automatica disparar.

SAIDA: abertura -> arenas/resultado_arenas.{md,json}; ensaios -> ~/curadoria/arenas/analise/
(fora do repositorio: ensaio nao e resultado).
"""
import argparse
import csv
import datetime
import json
import os
import random
import shutil
import sys

import numpy as np

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
sys.path.insert(0, os.path.join(BV, "modelo"))
import analisar_resultados as AR  # noqa: E402  metricas, posicao e conferencias do BigVul
import reveal_comum as C  # noqa: E402

V = AR.V  # traversal/veredito.py, o mesmo modulo

PREREGISTROS = dict(AR.PREREGISTROS)
PREREGISTROS["PREREGISTRO_ARENAS.md"] = "6284d831d490048ad2da33d34e32fc2f8f4d67185ae20bc7f1cce36949a01838"
FICHA = os.path.join(AQUI, "FICHA_PREPARACAO.md")
FICHA_SHA256 = "e5ead1350a014d70851e9fcc1e546071e916f0a7afcb3ff483d5324ce18b842e"   # gravada em 16/10/2026 02:52 (§10 passo 3)

MINIMO, PISO = 30, 2
PRINCIPAL = ("M_cur", list(C.CONTROLES))
BALANCEADO = ("M_cur_bal", [c + "_bal" for c in C.CONTROLES])
ORDEM = AR.ORDEM
ARENAS = {
    "primevul": {"pasta": "primevul", "indice": "indice_primevul.tsv", "trav": "primevul/traversal",
                 "papel": "sintese", "nome": "PrimeVul v0.1 (cross-dataset)"},
    "ventivul_familia": {"pasta": "ventivul", "indice": "indice_ventivul_familia.tsv",
                         "trav": "ventivul/traversal_familia", "papel": "sintese",
                         "nome": "VentiVul v3, família de memória (temporal)"},
    "sonda": {"pasta": "sonda", "indice": "indice_sonda.tsv", "trav": "sonda/traversal", "papel": "concordancia",
              "nome": "Sonda CWE-416 (entre classes; rótulo do BigVul)"},
    "ventivul_inteiro": {"pasta": "ventivul", "indice": "indice_ventivul_inteiro.tsv", "trav": None,
                         "papel": "descritiva", "nome": "VentiVul v3 inteiro (descritivo)"},
}


def log(*a):
    print(*a, flush=True)


# ------------------------------------------------------------------------------------ conferencias
def conferir(exigir_ficha):
    for nome, esp in PREREGISTROS.items():
        p = os.path.join(BV, "modelo", nome)
        if AR.sha256(p) != esp:
            sys.exit(f"PRE-REGISTRO ALTERADO: {nome}. Nao rodo.")
    AR.conferir_preregistros()   # os dois do BigVul + congelamento da traversal v3 (congelar.py)
    linhas = ["os tres pre-registros e os 4 arquivos de regra da traversal v3 conferem"]
    if exigir_ficha:
        if FICHA_SHA256 is None or not os.path.exists(FICHA) or AR.sha256(FICHA) != FICHA_SHA256:
            sys.exit("FICHA DE PREPARACAO ausente, nao registrada ou alterada. Nao rodo.")
        linhas.append(f"ficha de preparacao confere (SHA-256 {FICHA_SHA256[:12]}...)")
    return linhas


# ------------------------------------------------------------------------------------------- dados
def carregar_arena(nome):
    a = ARENAS[nome]
    fica = {r["id"] for r in csv.DictReader(open(os.path.join(AQUI, a["indice"]), encoding="utf-8"),
                                             delimiter="\t") if not r["motivo"]}
    v = os.path.expanduser(f"~/curadoria/arenas/{a['pasta']}/vetores/grafos.tsv")
    ids, y, nos = [], [], []
    for r in csv.DictReader(open(v, encoding="utf-8"), delimiter="\t"):
        if r["id"] in fica:
            ids.append(r["id"]); y.append(int(r["rotulo"])); nos.append(int(r["n_nos"]))
    o = np.argsort(ids)
    return [ids[i] for i in o], np.array(y)[o], np.array(nos)[o]


def carregar_pred(pasta_pred, braco, s, ids):
    prob, pred = {}, {}
    for r in csv.DictReader(open(os.path.join(pasta_pred, braco, f"semente_{s}.tsv"), encoding="utf-8"),
                            delimiter="\t"):
        prob[r["id"]] = float(r["prob_vulneravel"]); pred[r["id"]] = int(r["predicao"])
    falta = [i for i in ids if i not in prob]
    if falta:
        sys.exit(f"predicao de {braco} semente {s} sem {len(falta)} funcoes da arena")
    return np.array([prob[i] for i in ids]), np.array([pred[i] for i in ids])


# ----------------------------------------------------------------------------------------- calculos
def excesso(m, P, N):
    """Decisao J: VP - A*P/T (A = funcoes acusadas; T = todas as funcoes da arena = P + N).

    Aqui N e o numero de NAO vulneraveis (como em `analisar`). O adendo define o acaso com todas as
    funcoes ("P vulneraveis entre N funcoes"; "quem acusa tudo tem excesso zero"). A versao usada na
    abertura de 18/10/2026 dividia por N, so as nao vulneraveis: defeito achado na escrita em
    20/10/2026, corrigido em 21/10/2026 com o ok do autor e refeito com --refazer (§10 passo 8);
    registro em PREPARACAO_ARENAS.md, logo depois do Passo 7. Linha antiga:
        return m["tp"] - (m["tp"] + m["fp"]) * P / N
    """
    return m["tp"] - (m["tp"] + m["fp"]) * P / (P + N)


def analisar(ids, y, nos, pasta_pred, evid_dir=None, regra=None, f1_bigvul=None):
    P, N = int(y.sum()), int((y == 0).sum())
    fx = AR.faixa_de(nos)
    cont = [(int(((fx == k) & (y == 1)).sum()), int(((fx == k) & (y == 0)).sum())) for k in range(4)]
    por = {}
    for b in ORDEM:
        por[b] = {}
        for s in C.F2_SEMENTES:
            prob, pred = carregar_pred(pasta_pred, b, s, ids)
            g = AR.metricas(y, pred, prob)
            g["excesso"] = excesso(g, P, N)
            por[b][s] = {"geral": g, "faixas": [AR.metricas(y[fx == k], pred[fx == k]) for k in range(4)]}

    def serie(b, m, k=None):
        return [(por[b][s]["geral"] if k is None else por[b][s]["faixas"][k])[m] for s in C.F2_SEMENTES]

    rg = {b: {m: AR.resumo(serie(b, m)) for m in AR.METRICAS + ["excesso"]} for b in ORDEM}
    rf = {b: [{m: AR.resumo(serie(b, m, k)) for m in ("f1", "recall", "fpr")} for k in range(4)] for b in ORDEM}
    out = {"P": P, "N": N, "cont": cont, "tem_veredito": P >= MINIMO and N >= MINIMO, "resumo_geral": rg,
           "resumo_faixa": rf, "desenhos": {}}
    for nome, (cur, ctrls) in (("principal", PRINCIPAL), ("par balanceado", BALANCEADO)):
        x = rg[cur]["f1"]["mediana"]
        cs = [rg[c]["f1"]["mediana"] for c in ctrls]
        d = {"m_cur": x, "min": min(cs), "max": max(cs), "posicao": AR.posicao(x, cs)}
        # checagem de tamanho: a mesma regra do analisar_resultados.py (BigVul)
        v1_aplica = cont[0][1] >= MINIMO and cont[3][1] >= MINIMO
        incl = {b: float(np.median([por[b][s]["faixas"][3]["fpr"] - por[b][s]["faixas"][0]["fpr"]
                                    for s in C.F2_SEMENTES])) for b in [cur] + ctrls}
        v1 = None if not v1_aplica else incl[cur] > max(incl[c] for c in ctrls)
        acima = {k: AR.posicao(rf[cur][k]["f1"]["mediana"], [rf[c][k]["f1"]["mediana"] for c in ctrls]) == "acima"
                 for k in range(4) if cont[k][0] >= MINIMO}
        peq = [k for k in AR.PEQUENAS if k in acima]
        gra = [k for k in AR.GRANDES if k in acima]
        v2 = None if (not peq or not gra) else (any(acima[k] for k in gra) and not any(acima[k] for k in peq))
        d["tamanho"] = {"v1_aplica": v1_aplica, "v1": v1, "inclinacao": incl, "v2": v2,
                        "acima_por_faixa": {AR.FAIXAS[k][0]: acima[k] for k in acima},
                        "caso_nao_previsto_v2_sem_faixa_grande": bool(peq) and not gra,
                        "veredito": ("nao verificavel" if v1 is None and v2 is None else
                                     "evidencia de vies de tamanho" if (v1 or v2) else "sem evidencia de vies de tamanho")}
        out["desenhos"][nome] = d
    exc = {b: rg[b]["excesso"]["mediana"] for b in [PRINCIPAL[0]] + PRINCIPAL[1]}
    out["piso"] = all(e <= PISO for e in exc.values())
    out["excesso_principal"] = exc
    out["status"] = ("abaixo do minimo" if not out["tem_veredito"] else "piso" if out["piso"]
                     else out["desenhos"]["principal"]["posicao"])
    if evid_dir is not None:     # traversal pura (Decisao K)
        pt = []
        for i in ids:
            p = os.path.join(evid_dir, i + ".json")
            r = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
            pt.append(int("evidencia" in r and V.julgar(r["evidencia"], regra)[0] == V.CONFIRMADO))
        out["traversal_pura"] = AR.metricas(y, np.array(pt))
        out["traversal_sem_saida"] = sum(not os.path.exists(os.path.join(evid_dir, i + ".json")) for i in ids)
    if f1_bigvul is not None:    # queda descritiva (PRINCIPAL §8): por repeticao, depois a mediana
        out["queda"] = {b: AR.resumo([f1_bigvul[b][s] - por[b][s]["geral"]["f1"] for s in C.F2_SEMENTES])
                        for b in ORDEM}
    out["por_semente"] = {b: {str(s): v for s, v in d.items()} for b, d in por.items()}
    return out


def e1(posicao, tam):
    """PRINCIPAL E1: o resultado geral decide a frase; a checagem de tamanho vai lado a lado."""
    ev = tam["veredito"] == "evidencia de vies de tamanho"
    if tam["veredito"] == "nao verificavel":
        return "checagem de tamanho nao verificavel (E3)"
    if posicao == "acima":
        return "ganho e evidencia de atalho de tamanho" if ev else "ganho sem sinal de atalho de tamanho"
    return "pegou o atalho e nao lucrou com ele" if ev else "nada a acrescentar"


def sintese(res):
    """Decisao M (tabela de casos)."""
    entram = [a for a in ("primevul", "ventivul_familia") if res[a]["status"] in ("acima", "dentro", "abaixo")]
    pos = {a: res[a]["status"] for a in entram}
    if not entram:
        return entram, "nenhuma com veredito", ("as arenas externas nao permitiram avaliar a hipotese; o colapso "
                                                "e relatado como achado")
    if all(p == "acima" for p in pos.values()):
        return entram, "todas acima", (f"evidencia a favor da hipotese ({len(entram)} arena(s) na sintese; por acaso, no "
                                       "maximo 1 vez em 6 qualquer que seja a dependencia, 1 em 36 se independentes). "
                                       "Nunca 'prova'.")
    if any(p == "abaixo" for p in pos.values()):
        contra = any(p == "acima" for p in pos.values())
        return entram, "alguma abaixo", ("relatada" + ("; ha 'acima' em outra arena: as arenas se contradizem" if contra else ""))
    if all(p == "dentro" for p in pos.values()):
        return entram, "todas dentro", ("a curadoria nao se distinguiu dos controles fora da distribuicao "
                                        "('reduziu o conjunto sem limpa-lo de forma util')")
    return entram, "misto", "resultado misto, arena por arena; a hipotese nao se confirma de forma consistente"


# ------------------------------------------------------------------------------------------ relatorio
def fmt(x, c=3):
    return AR.fmt(x, c)


def relatorio(res, sint, linhas_conf, titulo, aviso):
    L = [f"# {titulo}", "", f"> {aviso}", "", "## Conferências", ""] + ["- " + x for x in linhas_conf] + [""]
    L += ["## O que decide, por arena (F1 do `M_cur` contra a faixa dos 5 controles, mediana das 30)", "",
          "| arena | vuln. / não vuln. | M_cur | faixa dos 5 controles | posição | piso? | leitura |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for a, r in res.items():
        d = r["desenhos"]["principal"]
        L.append(f"| {ARENAS.get(a, {'nome': a})['nome']} | {r['P']} / {r['N']} | {fmt(d['m_cur'])} | {fmt(d['min'])} a {fmt(d['max'])} | "
                 f"{d['posicao']} | {'sim' if r['piso'] else 'não'} | **{r['status']}** ({ARENAS.get(a, {'papel': 'ensaio'})['papel']}) |")
    entram, caso, texto = sint
    L += ["", "## Síntese (Decisão M)", "", f"Arenas na síntese: {', '.join(entram) or 'nenhuma'}. Caso: **{caso}**.", "",
          f"O texto diz: {texto}", ""]
    L += ["## Checagem de tamanho (desenho principal qualifica; par balanceado no apêndice)", "",
          "| arena | desenho | V1 | V2 | veredito | E1 |", "| --- | --- | --- | --- | --- | --- |"]
    for a, r in res.items():
        for nome, d in r["desenhos"].items():
            t = d["tamanho"]
            v1 = "não se aplica" if t["v1"] is None else ("DISPARA" if t["v1"] else "não dispara")
            v2 = "não se aplica" if t["v2"] is None else ("DISPARA" if t["v2"] else "não dispara")
            # Decisao J: no piso, a checagem e relatada "como na linha 'dentro ou abaixo' do E1";
            # abaixo do minimo, nao ha posicao lida
            pos_lida = (None if r["status"] == "abaixo do minimo" else
                        "dentro" if r["status"] == "piso" else d["posicao"])
            frase = ("—" if nome != "principal" else "sem posição lida (abaixo do mínimo)" if pos_lida is None
                     else e1(pos_lida, t))
            L.append(f"| {a} | {nome} | {v1} | {v2} | {t['veredito']} | {frase} |")
    L += ["", "## Excesso sobre o acaso (Decisão J; mediana das 30) — piso se nenhum dos seis > 2", "",
          "| arena | " + " | ".join(ORDEM[:7]) + " |", "| --- |" + " --- |" * 7]
    for a, r in res.items():
        L.append(f"| {a} | " + " | ".join(fmt(r["resumo_geral"][b]["excesso"]["mediana"], 1) for b in ORDEM[:7]) + " |")
    L += ["", "## Traversal pura (Decisão K; descritiva)", "", "| arena | F1 regra | F1 M_cur (mediana) | recall regra | precisão regra | sem saída |",
          "| --- | --- | --- | --- | --- | --- |"]
    for a, r in res.items():
        if "traversal_pura" in r:
            t = r["traversal_pura"]
            L.append(f"| {a} | {fmt(t['f1'])} | {fmt(r['resumo_geral']['M_cur']['f1']['mediana'])} | {fmt(t['recall'])} | "
                     f"{fmt(t['precisao'])} | {r['traversal_sem_saida']} |")
    L += ["", "## Queda de F1 (BigVul − arena), mediana por repetição (descritiva; parte vem só da proporção de vulneráveis)", "",
          "| arena | " + " | ".join(ORDEM[:7]) + " |", "| --- |" + " --- |" * 7]
    for a, r in res.items():
        if "queda" in r:
            L.append(f"| {a} | " + " | ".join(fmt(r["queda"][b]["mediana"]) for b in ORDEM[:7]) + " |")
    L += ["", "## Todas as métricas por braço e arena (mediana [Q1–Q3]; descritivas)", ""]
    for a, r in res.items():
        L += [f"### {ARENAS.get(a, {'nome': a})['nome']}", "", "| braço | F1 | recall | precisão | PR-AUC | MCC | FPR |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
        for b in ORDEM:
            g = r["resumo_geral"][b]
            L.append(f"| {b} | " + " | ".join(f"{fmt(g[m]['mediana'])} [{fmt(g[m]['q1'])}–{fmt(g[m]['q3'])}]"
                                              for m in AR.METRICAS) + " |")
        L += ["", "| faixa | vuln. | não vuln. |", "| --- | --- | --- |"]
        L += [f"| {AR.FAIXAS[k][0]} | {r['cont'][k][0]} | {r['cont'][k][1]} |" for k in range(4)] + [""]
    return L


# --------------------------------------------------------------------------------------------- modos
def f1_bigvul_teste():
    j = json.load(open(os.path.join(BV, "modelo", "resultado_teste_bigvul.json"), encoding="utf-8"))
    return {b: {s: j["por_semente"][b][str(s)]["geral"]["f1"] for s in C.F2_SEMENTES} for b in ORDEM}


def ensaio_validacao():
    """A validacao do BigVul tratada como uma arena: o F1 por repeticao tem de ser IGUAL ao gravado."""
    ids, y, nos = AR.carregar_indice("validacao")
    pasta = os.path.expanduser("~/curadoria/arenas/analise/_pred_validacao")
    shutil.rmtree(pasta, ignore_errors=True)
    for b in ORDEM:      # reescreve as predicoes da validacao no formato das arenas
        os.makedirs(os.path.join(pasta, b))
        for s in C.F2_SEMENTES:
            prob, pred = AR.carregar_predicao(b, s, "validacao", ids)
            with open(os.path.join(pasta, b, f"semente_{s}.tsv"), "w") as f:
                f.write("id\tprob_vulneravel\tpredicao\n")
                f.writelines(f"{i}\t{p:.6f}\t{q}\n" for i, p, q in zip(ids, prob, pred))
    r = analisar(ids, y, nos, pasta)
    difs = [abs(round(r["por_semente"][b][str(s)]["geral"]["f1"], 4) -
                json.load(open(os.path.join(AR.PRED, b, f"semente_{s}.tsv.json")))["f1_validacao"])
            for b in ORDEM for s in C.F2_SEMENTES]
    conf = (f"(a) F1 por repeticao = f1_validacao gravado no treino: {sum(d < 1e-9 for d in difs)} de {len(difs)} "
            f"iguais (maior diferenca {max(difs):.6f})")
    exc = r["excesso_principal"]
    conf2 = (f"(b) contagem por faixa {r['cont']} | piso? {r['piso']} | excesso M_cur {exc['M_cur']:.1f} | posicao "
             f"{r['desenhos']['principal']['posicao']}")
    shutil.rmtree(pasta, ignore_errors=True)
    return [conf, conf2], {"validacao": r}


def ensaio_sintetico():
    """Predicoes aleatorias (semente 9090, nao usada antes) nas arenas: exercita o codigo inteiro."""
    rnd = np.random.RandomState(9090)
    res = {}
    regra = V.carregar_regra(AR.REGRA)
    for a, cfg in ARENAS.items():
        ids, y, nos = carregar_arena(a)
        pasta = os.path.expanduser(f"~/curadoria/arenas/analise/_pred_sintetico/{cfg['pasta']}")
        if not os.path.exists(os.path.join(pasta, ORDEM[-1], f"semente_{C.F2_SEMENTES[-1]}.tsv")):
            # como a inferencia real: predicao para TODOS os grafos da pasta (as duas arenas do
            # VentiVul dividem a pasta)
            todos = [r["id"] for r in csv.DictReader(open(os.path.expanduser(
                f"~/curadoria/arenas/{cfg['pasta']}/vetores/grafos.tsv"), encoding="utf-8"), delimiter="\t")]
            for b in ORDEM:
                os.makedirs(os.path.join(pasta, b), exist_ok=True)
                taxa = rnd.uniform(0.02, 0.3)   # cada braco acusa uma fracao diferente, ao acaso
                for s in C.F2_SEMENTES:
                    p = rnd.uniform(0, 1, len(todos)) * (0.5 / max(1 - taxa, 1e-3))
                    with open(os.path.join(pasta, b, f"semente_{s}.tsv"), "w") as f:
                        f.write("id\tprob_vulneravel\tpredicao\n")
                        f.writelines(f"{i}\t{min(q, 1):.6f}\t{int(q >= 0.5)}\n" for i, q in zip(todos, p))
        evid = os.path.expanduser(f"~/curadoria/arenas/{cfg['trav']}") if cfg["trav"] else None
        res[a] = analisar(ids, y, nos, pasta, evid, regra, f1_bigvul_teste())
    return ["predicoes SINTETICAS (aleatorias): o numero nao significa nada; so exercita o codigo"], res


def abrir():
    regra = V.carregar_regra(AR.REGRA)
    if sum(1 for _ in carregar_arena("ventivul_familia")[1] if _ == 1) < MINIMO:
        sys.exit("TROCA AUTOMATICA DA G3 disparou: o veredito passa ao VentiVul inteiro, que precisa de traversal "
                 "pura antes. Parar e voltar ao autor.")
    res = {}
    for a, cfg in ARENAS.items():
        ids, y, nos = carregar_arena(a)
        pred = os.path.expanduser(f"~/curadoria/arenas/{cfg['pasta']}/predicoes")
        evid = os.path.expanduser(f"~/curadoria/arenas/{cfg['trav']}") if cfg["trav"] else None
        res[a] = analisar(ids, y, nos, pred, evid, regra, f1_bigvul_teste())
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ensaio-validacao", action="store_true")
    ap.add_argument("--ensaio-sintetico", action="store_true")
    ap.add_argument("--abrir", action="store_true")
    ap.add_argument("--refazer", default="")
    a = ap.parse_args()
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    if a.abrir:
        destino = os.path.join(AQUI, "resultado_arenas")
        if os.path.exists(destino + ".md"):
            if not a.refazer:
                sys.exit("As arenas ja foram abertas. Refazer so com --refazer \"motivo\" (§10 passo 8).")
            car = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            for ext in (".md", ".json"):
                os.replace(destino + ext, destino + "_anterior_" + car + ext)
        linhas = conferir(exigir_ficha=True)
        res = abrir()
        titulo = "Resultado nas arenas externas"
        aviso = (f"Gerado em {agora} por `analisar_arenas.py --abrir`, seguindo os três pré-registros (hashes "
                 "conferidos) e a ficha de preparação." + (f" **Refeito** (§10 passo 8): {a.refazer}." if a.refazer else ""))
    elif a.ensaio_validacao or a.ensaio_sintetico:
        destino = os.path.expanduser("~/curadoria/arenas/analise/" +
                                     ("ensaio_validacao" if a.ensaio_validacao else "ensaio_sintetico"))
        os.makedirs(os.path.dirname(destino), exist_ok=True)
        linhas = conferir(exigir_ficha=False)
        extra, res = ensaio_validacao() if a.ensaio_validacao else ensaio_sintetico()
        linhas += extra
        titulo = "ENSAIO — NÃO É RESULTADO"
        aviso = f"Gerado em {agora}. Serve para achar defeito de código antes de abrir as arenas; nada daqui entra no texto."
    else:
        ap.error("--ensaio-validacao, --ensaio-sintetico ou --abrir")
    sint = sintese(res) if all(k in res for k in ("primevul", "ventivul_familia")) else ([], "—", "—")
    L = relatorio(res, sint, linhas, titulo, aviso)
    open(destino + ".md", "w", encoding="utf-8").write("\n".join(L) + "\n")
    json.dump({"gerado": agora, "sintese": sint, "arenas": res}, open(destino + ".json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1, default=float)
    print("\n".join(linhas))
    print("relatorio:", destino + ".md")


if __name__ == "__main__":
    main()
