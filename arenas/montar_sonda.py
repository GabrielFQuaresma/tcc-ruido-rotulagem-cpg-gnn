#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafos da sonda CWE-416, pelo MESMO caminho que gerou o dataset v3.

O QUE E, situando
-----------------
Preparacao das arenas externas, passo 3 (PREREGISTRO_ARENAS.md §10). A sonda e o use-after-free
(CWE-416) do proprio BigVul, que ficou fora do treino de proposito; a Decisao L manda extrai-la
"pelo mesmo caminho que gerou o dataset v3 (arquivo no commit pai, CPG, localizacao da funcao,
exportacao do grafo), sem regra nova; falha sai e e contada". A deduplicacao ja foi feita
(indice_sonda.tsv): aqui entram so as funcoes com `motivo` vazio.

O MESMO CAMINHO, IMPORTADO E NAO COPIADO:
  - arquivo: buscar_arquivo.buscar_arquivos_do_commit (versao do commit PAI), como no
    preparar_bigvul.py; positivo sem file_name tem o arquivo achado pelo patch (como no v3);
    negativo sem file_name sai, como no v3 (montar_dataset.carregar_alvos: "not arq -> continue");
  - CPG: /opt/joern/joern-cli/c2cpg.sh <arquivo> --output cpg.bin, um por arquivo (rodar_curadoria);
  - nome da funcao: buscar_arquivo.nome_da_funcao(func_before), o extrator dos dois lados no v3;
  - localizacao: montar_dataset.escolher (nome unico no arquivo; se houver homonimo, os dois hashes
    do corpo de normalizar_corpo.hashes_do_texto) e o filtro montar_dataset.fora_da_funcao;
  - grafo: traversal/exportar_grafos.sc, chamado por montar_dataset.rodar_joern.

FASES (cada uma idempotente; rodar em primeiro plano, --minutos limita o tempo de uma execucao):
  preparar  le do CSV completo (ZIP) o texto e o codeLink das funcoes da sonda e baixa os arquivos
  exportar  CPG + grafos, grupo a grupo (um grupo = um arquivo de um commit)
  indice    grava arenas/grafos_sonda.tsv (uma linha por funcao: grafo ou motivo da falha)

Saida pesada em ~/curadoria/arenas/sonda/ (fora do repositorio). Nenhum modelo, nenhuma predicao.
"""
import argparse
import csv
import json
import os
import sys
import time
from collections import Counter, defaultdict

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
TRAV = os.path.join(BV, "traversal")
sys.path.insert(0, BV)
sys.path.insert(0, TRAV)
import montar_dataset as md  # noqa: E402
import comum_grafos as cg  # noqa: E402  exportacao comum as arenas
from buscar_arquivo import Sessao, buscar_arquivos_do_commit, nome_da_funcao  # noqa: E402
from normalizar_corpo import hashes_do_texto  # noqa: E402

BASE = os.path.expanduser("~/curadoria/arenas/sonda")
FUNCOES = os.path.join(BASE, "funcoes.jsonl")
ARQS = os.path.join(BASE, "arquivos")
GRAFOS = os.path.join(BASE, "grafos")
TRABALHO = os.path.join(BASE, "_trabalho")
CSV_COMPLETO = os.path.join(BV, "all_c_cpp_release2.0.csv")
INDICE_DEDUP = os.path.join(AQUI, "indice_sonda.tsv")
SAIDA_INDICE = os.path.join(AQUI, "grafos_sonda.tsv")
RUIM = md.RUIM


def log(*a):
    print(*a, flush=True)


def ler_funcoes():
    return [json.loads(l) for l in open(FUNCOES, encoding="utf-8")]


# ------------------------------------------------------------------------- preparar
def extrair_funcoes():
    """Texto, codeLink e file_name das funcoes que ficaram na deduplicacao (uma passada no ZIP)."""
    if os.path.exists(FUNCOES):
        log(f"ja existe: {FUNCOES}")
        return
    import pandas as pd
    fica = {int(r["id"][2:]): r for r in csv.DictReader(open(INDICE_DEDUP, encoding="utf-8"), delimiter="\t")
            if not r["motivo"]}
    cols = ["codeLink", "commit_id", "file_name", "func_before", "project", "vul", "CVE ID"]
    achadas, linha = [], 0
    for bloco in pd.read_csv(CSV_COMPLETO, compression="zip", encoding="latin-1", usecols=cols,
                             chunksize=2000, dtype=str):
        bloco = bloco[cols]     # usecols devolve na ordem do ARQUIVO, nao na da lista
        for j, row in enumerate(bloco.itertuples(index=False)):
            i = linha + j
            if i in fica:
                d = dict(zip(cols, row))
                achadas.append({"id": f"bv{i}", "linha_indice": i, "rotulo": int(d["vul"]),
                                "projeto": d["project"], "commit": d["commit_id"], "cve": d["CVE ID"],
                                "codelink": d["codeLink"], "file_name": d["file_name"] or "",
                                "func_before": d["func_before"] or ""})
        linha += len(bloco)
    if len(achadas) != len(fica):
        sys.exit(f"ERRO: {len(achadas)} achadas de {len(fica)}")
    os.makedirs(BASE, exist_ok=True)
    with open(FUNCOES + ".parcial", "w", encoding="utf-8") as f:
        for d in achadas:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    os.replace(FUNCOES + ".parcial", FUNCOES)
    log(f"funcoes extraidas: {len(achadas)} ({sum(d['rotulo'] for d in achadas)} vulneraveis)")


def base_de(caminho):
    return md.basename(str(caminho or ""))


def baixar(fs, minutos):
    """Um download por (commit, arquivo). Positivo sem file_name: um download proprio, pelo patch."""
    os.makedirs(ARQS, exist_ok=True)
    ses = Sessao(conexoes=4)
    pedidos = defaultdict(list)  # chave de download -> funcoes
    for d in fs:
        fn = str(d["file_name"]).strip()
        if fn and fn not in RUIM:
            pedidos[("nome", d["commit"], base_de(fn))].append(d)
        elif d["rotulo"] == 1:
            pedidos[("patch", d["commit"], d["id"])].append(d)
    t0, feitos = time.time(), Counter()
    for chave in sorted(pedidos):
        marca = md.marca_de((chave[1], chave[2]))
        pasta = os.path.join(ARQS, marca)
        if os.path.exists(os.path.join(pasta, "download.json")):
            continue
        if minutos and time.time() - t0 > minutos * 60:
            log("tempo esgotado; rode de novo para continuar")
            break
        ds = pedidos[chave]
        ref = next((d for d in ds if d["rotulo"] == 1), ds[0])
        res = buscar_arquivos_do_commit(ref["codelink"], ref["commit"], ref["file_name"], sessao=ses,
                                        so_um=True, funcao=ref["func_before"][:4000])
        os.makedirs(pasta, exist_ok=True)
        meta = {"chave": list(chave), "status": res.status, "familia": res.familia,
                "origem_paths": res.origem_paths, "detalhe": res.detalhe, "caminho": "", "arquivo": ""}
        for caminho, conteudo in res.arquivos[:1]:
            nome = base_de(caminho)
            if chave[0] == "nome" and nome != chave[2]:
                meta["status"] = "arquivo_errado"   # o buscador devolveu outro arquivo do commit
                meta["detalhe"] = f"pedido {chave[2]}, veio {caminho}"
                break
            with open(os.path.join(pasta, "arquivo__" + "".join(c if c.isalnum() or c in "._-" else "_" for c in nome)),
                      "w", encoding="utf-8", errors="replace") as f:
                f.write(conteudo)
            meta["caminho"], meta["arquivo"] = caminho, nome
        if meta["status"] == "ok" and not meta["arquivo"]:
            meta["status"] = "sem_arquivo"
        json.dump(meta, open(os.path.join(pasta, "download.json"), "w", encoding="utf-8"), indent=1)
        feitos[meta["status"]] += 1
    log(f"downloads nesta execucao: {dict(feitos)} | pedidos no total: {len(pedidos)}")


# ------------------------------------------------------------------------- exportar
def grupos_de(fs):
    """(commit, arquivo) -> pasta com o arquivo baixado e os alvos que caem nele."""
    baixados = {}
    for p in sorted(os.listdir(ARQS)) if os.path.isdir(ARQS) else []:
        m = json.load(open(os.path.join(ARQS, p, "download.json"), encoding="utf-8"))
        if m["status"] == "ok" and m["arquivo"]:
            baixados.setdefault((m["chave"][1], m["arquivo"]), os.path.join(ARQS, p))
            if m["chave"][0] == "patch":
                baixados[("patch", m["chave"][2])] = (m["chave"][1], m["arquivo"])
    grupos, falha = defaultdict(lambda: {"pasta": None, "alvos": []}), {}
    for d in fs:
        fn = str(d["file_name"]).strip()
        if fn and fn not in RUIM:
            chave = (d["commit"], base_de(fn))
        elif d["rotulo"] == 1 and ("patch", d["id"]) in baixados:
            chave = baixados[("patch", d["id"])]
        else:
            falha[d["id"]] = "sem_nome_de_arquivo" if d["rotulo"] == 0 else "sem_arquivo_baixado"
            continue
        if chave not in baixados:
            falha[d["id"]] = "sem_arquivo_baixado"
            continue
        nome = nome_da_funcao(d["func_before"])
        if not nome or nome in RUIM:
            falha[d["id"]] = "sem_nome_de_funcao"
            continue
        g = grupos[chave]
        g["pasta"] = baixados[chave]
        g["alvos"].append({"id": d["id"], "rotulo": d["rotulo"], "nome": nome, "particao": "sonda",
                           "projeto": d["projeto"], "cwe": "CWE-416", "commit": d["commit"],
                           "arquivo": chave[1], "shas": sorted(hashes_do_texto(d["func_before"])),
                           "linha": None})
    return grupos, falha


def exportar(fs, minutos, timeout):
    grupos, _ = grupos_de(fs)
    cg.exportar_grupos(grupos, GRAFOS, TRABALHO, minutos, timeout)


# ------------------------------------------------------------------------- indice
def indice(fs):
    grupos, falha = grupos_de(fs)
    por_id, info_grafo, pend = cg.ler_resultados(grupos, GRAFOS)
    por_id.update(falha)
    with open(SAIDA_INDICE, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "rotulo", "projeto", "commit", "arquivo", "nome", "status", "localizacao", "n_nos", "n_arestas"])
        c = Counter()
        for d in fs:
            g = info_grafo.get(d["id"])
            status = "grafo" if g else por_id.get(d["id"], "?")
            c[(status, d["rotulo"])] += 1
            w.writerow([d["id"], d["rotulo"], d["projeto"], d["commit"], g["arquivo"] if g else "",
                        g["nome"] if g else "", status, g["motivo"] if g else "",
                        g["n_nos"] if g else "", g["n_arestas"] if g else ""])
    log("status por rotulo (vulneraveis / nao vulneraveis):")
    for s in sorted({k[0] for k in c}):
        log(f"  {s:28s} {c[(s, 1)]:5d} / {c[(s, 0)]:5d}")
    if pend:
        log(f"ATENCAO: {pend} funcoes ainda pendentes")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fase", choices=["preparar", "exportar", "indice"])
    ap.add_argument("--minutos", type=float, default=8.5, help="para de comecar trabalho novo depois disso")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    if a.fase == "preparar":
        extrair_funcoes()
        baixar(ler_funcoes(), a.minutos)
    elif a.fase == "exportar":
        exportar(ler_funcoes(), a.minutos, a.timeout)
    else:
        indice(ler_funcoes())


if __name__ == "__main__":
    main()
