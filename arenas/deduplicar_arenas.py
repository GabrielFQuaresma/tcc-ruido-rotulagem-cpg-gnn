#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deduplicacao das tres arenas externas (Decisao H), ANTES de qualquer grafo.

O QUE E, situando
-----------------
Preparacao das arenas, passo 3 (PREREGISTRO_ARENAS.md §10: "filtros da Decisao G, deduplicacao
(H), arquivo, CPG, grafo"). A deduplicacao tira da arena toda funcao que os modelos podem ter
visto, para que acerta-la nao conte como generalizar. Feita antes dos grafos porque nenhuma chave
precisa deles, e assim nao se gasta Joern em funcao que sai.

AS REGRAS (Decisao H do adendo, congelado em 15/10/2026):
  - referencia: treino + validacao do dataset v3 (VentiVul e sonda); no PrimeVul, o BigVul INTEIRO
    (todas as linhas do indice_bigvul.csv; corpo pelo func_before do all_c_cpp_release2.0.csv);
  - tres chaves, nesta ordem: CVE, commit, corpo (hash_corpo do normalizar_corpo.py: sem
    comentarios, espacos colapsados — o mesmo sha1_corpo_sc do split). Sai sempre a funcao da arena;
  - duplicata dentro da arena (mesmo corpo): mesmo rotulo -> fica a de menor identificador;
    rotulos diferentes -> saem todas;
  - quem e negativo foi decidido pelo rotulo publicado, antes de qualquer perda (§3, ordem das
    operacoes): este script monta a arena primeiro e so depois tira funcoes.
Funcao sem corpo (texto vazio) nao pode ser comparada nem localizada: sai como falha, contada.

CONFERENCIA: antes da chave do corpo, cada arena tem de ter o tamanho que o adendo registra
(sonda 330 + 9254; VentiVul familia 50 + 3326; PrimeVul 1027 + 31.149 depois de CVE e commit).
Se nao tiver, o script para sem gravar.

SAIDAS (no repositorio, sao pequenas): arenas/indice_<arena>.tsv, uma linha por funcao candidata,
com `motivo` vazio para quem fica; arenas/dedup_resumo.tsv. So metadados e hash; nenhum modelo.

Uso (no WSL): python3 deduplicar_arenas.py   (precisa de ~/curadoria/arenas/bigvul_hash_sc.tsv)
"""
import collections
import csv
import json
import os
import re
import sys

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
TRAV = os.path.join(BV, "traversal")
sys.path.insert(0, TRAV)
from normalizar_corpo import hash_corpo  # noqa: E402

DADOS = os.path.expanduser("~/curadoria/arenas")
FAM = {"CWE-119", "CWE-120", "CWE-125", "CWE-787"}
VAZIO = {"", "None", "nan", "NaN", "[]"}


def log(*a):
    print(*a, flush=True)


def ler_tsv(caminho):
    return list(csv.DictReader(open(caminho, encoding="utf-8", newline=""), delimiter="\t"))


def limpo(v):
    """Conjunto de valores validos (CVE, commit) de um campo que pode ser lista, texto ou vazio.
    Separa celula com varios valores: o BigVul tem 3 celulas de CVE assim (101 linhas, ex.
    "CVE-2014-3176, CVE-2014-3177"), e cada CVE delas aparece na referencia."""
    if v is None:
        return set()
    vals = v if isinstance(v, list) else [v]
    return {p for x in vals for p in re.split(r"[,;\s]+", str(x).strip()) if p not in VAZIO}


# ----------------------------------------------------------------------------- referencias
def ref_treino_validacao():
    """Tudo o que os modelos tocaram: treino + validacao do dataset v3, positivos e negativos."""
    pos_cve = {r["item"]: r["cve"] for r in ler_tsv(f"{TRAV}/split/positivos.tsv")}
    neg = {int(r["linha_indice"]): r for r in ler_tsv(f"{TRAV}/split/negativos.tsv")}
    pos_h = {r["item"]: r["sha1_corpo_sc"] for r in ler_tsv(f"{TRAV}/split/positivos_hash.tsv")}
    neg_h = {int(r["linha_indice"]): r["sha1_corpo_sc"] for r in ler_tsv(f"{TRAV}/split/negativos_hash_sc.tsv")}
    cves, commits, hashes, n, sem_hash = set(), set(), set(), 0, 0
    for r in ler_tsv(f"{TRAV}/dataset_indice_v3.tsv"):
        if r["particao"] not in ("treino", "validacao"):
            continue
        n += 1
        commits.add(r["commit"])
        if r["rotulo"] == "1":
            cve, h = pos_cve[r["id"]], pos_h.get(r["id"], "")
        else:
            li = int(r["id"].split("_", 1)[1])
            if neg[li]["commit"] != r["commit"]:
                sys.exit(f"ERRO: {r['id']} nao casa com split/negativos.tsv pelo commit")
            cve, h = neg[li]["cve"], neg_h.get(li, "")
        cves |= limpo(cve)
        if h:
            hashes.add(h)
        else:
            sem_hash += 1
    log(f"referencia treino+validacao (dataset v3): {n} funcoes, {len(cves)} CVEs, {len(commits)} commits, "
        f"{len(hashes)} corpos distintos ({sem_hash} sem hash)")
    return {"cves": cves, "commits": commits, "hashes": hashes}


def bigvul_indice_e_hash():
    linhas = list(csv.DictReader(open(f"{BV}/saida_final/indice_bigvul.csv", encoding="utf-8", newline="")))
    hs = [r["sha1_corpo_sc"] for r in ler_tsv(f"{DADOS}/bigvul_hash_sc.tsv")]
    if len(hs) != len(linhas):
        sys.exit(f"ERRO: {len(hs)} hashes para {len(linhas)} linhas do indice")
    return linhas, hs


def ref_bigvul_inteiro(linhas, hs):
    cves = set().union(*(limpo(r["CVE ID"]) for r in linhas))
    commits = {r["commit_id"] for r in linhas if r["commit_id"] not in VAZIO}
    hashes = {h for h in hs if h}
    log(f"referencia BigVul inteiro: {len(linhas)} linhas, {len(cves)} CVEs, {len(commits)} commits, "
        f"{len(hashes)} corpos distintos")
    return {"cves": cves, "commits": commits, "hashes": hashes}


# ----------------------------------------------------------------------------- a regra
def deduplicar(itens, ref):
    """itens: dicts com id, ordem, rotulo, cves, commits, hash. Preenche `motivo` (vazio = fica)."""
    for it in itens:
        if it["cves"] & ref["cves"]:
            it["motivo"] = "cve"
        elif it["commits"] & ref["commits"]:
            it["motivo"] = "commit"
        elif not it["hash"]:
            it["motivo"] = "falha_sem_corpo"
        elif it["hash"] in ref["hashes"]:
            it["motivo"] = "corpo"
        else:
            it["motivo"] = ""
    grupos = collections.defaultdict(list)
    for it in itens:
        if not it["motivo"]:
            grupos[it["hash"]].append(it)
    for g in grupos.values():
        if len(g) < 2:
            continue
        if len({x["rotulo"] for x in g}) > 1:
            for x in g:
                x["motivo"] = "duplicata_conflito"
        else:
            for x in sorted(g, key=lambda x: x["ordem"])[1:]:
                x["motivo"] = "duplicata_interna"
    return itens


def conferir_tamanho(nome, itens, esperado_pos, esperado_neg, antes_do_corpo=False):
    if antes_do_corpo:  # PrimeVul: o adendo conta depois de CVE e commit
        itens = [x for x in itens if x["motivo"] not in ("cve", "commit")]
    p = sum(x["rotulo"] == 1 for x in itens)
    n = len(itens) - p
    ok = (p, n) == (esperado_pos, esperado_neg)
    log(f"[{nome}] candidatas: {p} vulneraveis + {n} nao vulneraveis | adendo: {esperado_pos} + {esperado_neg} "
        f"-> {'BATE' if ok else 'NAO BATE'}")
    if not ok:
        sys.exit(f"ERRO: tamanho da arena {nome} diferente do adendo; nada gravado")


# ----------------------------------------------------------------------------- as arenas
def arena_sonda(linhas, hs):
    pos = [i for i, r in enumerate(linhas) if r["CWE ID"] == "CWE-416" and r["vul"] == "1"]
    com = {linhas[i]["commit_id"] for i in pos}
    neg = [i for i, r in enumerate(linhas) if r["CWE ID"] == "CWE-416" and r["vul"] == "0" and r["commit_id"] in com]
    outras = sum(1 for r in linhas if r["vul"] == "0" and r["commit_id"] in com and r["CWE ID"] != "CWE-416")
    log(f"[sonda] linhas vul=0 nesses commits com outra CWE (nao entram): {outras}")
    return [{"id": f"bv{i}", "ordem": i, "rotulo": int(linhas[i]["vul"]), "projeto": linhas[i]["project"],
             "origem": "bigvul", "cwe": linhas[i]["CWE ID"], "cves": limpo(linhas[i]["CVE ID"]),
             "commits": {linhas[i]["commit_id"]}, "hash": hs[i]} for i in pos + neg]


def cves_do_nome(nome):
    """Mesma leitura do modelo/contagens_arenas/contar_ventivul.py (conferida pelo tamanho 50 + 3326)."""
    m = re.fullmatch(r"cve(\d{4})(\d+)((?:_\d+)*)", str(nome).rsplit(".", 1)[0])
    if not m:
        return set()
    out = {f"CVE-{m.group(1)}-{m.group(2)}"}
    for t in m.group(3).split("_")[1:]:
        if len(t) >= 8 and t.startswith("20"):
            out.add(f"CVE-{t[:4]}-{t[4:]}")
    return out


def arenas_ventivul():
    df = pd.read_csv(f"{DADOS}/ventivul/ventivul.csv")
    par = df["pair_id"].astype(str) != "none"
    commits_cve = collections.defaultdict(set)  # so o Linux traz SHA de commit no link
    for c, l in zip(df.loc[par, "cve_id"], df.loc[par, "link"]):
        m = re.search(r"[?&]id=([0-9a-f]{40})", str(l))
        if m:
            commits_cve[c].add(m.group(1))
    itens = []
    for i, r in df.iterrows():
        cves = limpo(r["cve_id"]) if par[i] else cves_do_nome(r["file_name_ori"])
        itens.append({"id": f"vv{i}", "ordem": i, "rotulo": int(r["Vulnerable"]), "projeto": r["project"],
                      "origem": "par" if par[i] else "nao_relacionada",
                      "cwe": "" if pd.isna(r["cwe_id"]) else r["cwe_id"], "cves": cves,
                      "commits": set().union(*(commits_cve[c] for c in cves)) if cves else set(),
                      "hash": hash_corpo(r["Function"])})
    cves_fam = set().union(*(x["cves"] for x in itens if x["rotulo"] == 1 and x["cwe"] in FAM))
    familia = [dict(x) for x in itens
               if (x["rotulo"] == 1 and x["cwe"] in FAM) or (x["rotulo"] == 0 and x["cves"] & cves_fam)]
    return familia, [dict(x) for x in itens]


def arena_primevul():
    itens, vistos = [], set()
    for part in ("test", "valid", "train"):
        arq = f"{DADOS}/primevul/primevul_{part}.jsonl"
        com = set()
        for l in open(arq, encoding="utf-8"):
            if l.strip():
                d = json.loads(l)
                cw = limpo(d.get("cwe"))
                if d["target"] == 1 and cw and cw <= FAM:
                    com.add(d["commit_id"])
        for l in open(arq, encoding="utf-8"):
            if not l.strip():
                continue
            d = json.loads(l)
            cw = limpo(d.get("cwe"))
            pos = d["target"] == 1 and cw and cw <= FAM
            if not (pos or (d["target"] == 0 and d["commit_id"] in com)):
                continue
            if d["idx"] in vistos:
                sys.exit(f"ERRO: idx repetido no PrimeVul: {d['idx']}")
            vistos.add(d["idx"])
            itens.append({"id": f"pv{d['idx']}", "ordem": int(d["idx"]), "rotulo": int(d["target"]),
                          "projeto": d.get("project", ""), "origem": part, "cwe": ";".join(sorted(cw)),
                          "cves": limpo(d.get("cve")), "commits": {d["commit_id"]}, "hash": hash_corpo(d["func"])})
    return itens


# ----------------------------------------------------------------------------- saida
def gravar(nome, itens):
    caminho = os.path.join(AQUI, f"indice_{nome}.tsv")
    with open(caminho, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "rotulo", "projeto", "origem", "cwe", "cves", "commits", "sha1_corpo_sc", "motivo"])
        for x in sorted(itens, key=lambda x: x["ordem"]):
            w.writerow([x["id"], x["rotulo"], x["projeto"], x["origem"], x["cwe"], ";".join(sorted(x["cves"])),
                        ";".join(sorted(x["commits"])), x["hash"], x["motivo"]])
    return collections.Counter((x["motivo"] or "fica", x["rotulo"]) for x in itens)


def main():
    linhas, hs = bigvul_indice_e_hash()
    ref_tv = ref_treino_validacao()
    ref_bv = ref_bigvul_inteiro(linhas, hs)

    sonda = arena_sonda(linhas, hs)
    conferir_tamanho("sonda", sonda, 330, 9254)
    vv_fam, vv_int = arenas_ventivul()
    conferir_tamanho("ventivul_familia", vv_fam, 50, 3326)
    conferir_tamanho("ventivul_inteiro", vv_int, 263, 13063)
    pv = arena_primevul()
    deduplicar(pv, ref_bv)
    conferir_tamanho("primevul", pv, 1027, 31149, antes_do_corpo=True)

    resumo = {}
    for nome, itens, ref in (("sonda", sonda, ref_tv), ("ventivul_familia", vv_fam, ref_tv),
                             ("ventivul_inteiro", vv_int, ref_tv), ("primevul", pv, ref_bv)):
        deduplicar(itens, ref)
        resumo[nome] = gravar(nome, itens)

    motivos = ["cve", "commit", "corpo", "duplicata_interna", "duplicata_conflito", "falha_sem_corpo", "fica"]
    with open(os.path.join(AQUI, "dedup_resumo.tsv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["arena", "motivo", "vulneraveis", "nao_vulneraveis"])
        for nome, c in resumo.items():
            log(f"\n== {nome}")
            for m in motivos:
                w.writerow([nome, m, c[(m, 1)], c[(m, 0)]])
                log(f"  {m:20s} vulneraveis {c[(m, 1)]:6d} | nao vulneraveis {c[(m, 0)]:6d}")


if __name__ == "__main__":
    main()
