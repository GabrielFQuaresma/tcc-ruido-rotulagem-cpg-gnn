#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exportacao de grafos comum as arenas: CPG do arquivo -> localizar a funcao -> grafo.

Tirado do montar_sonda.py (15/10/2026) para que sonda, VentiVul e PrimeVul usem O MESMO codigo, e
nao copias. As pecas de dentro sao as do dataset v3, importadas: c2cpg.sh (um CPG por arquivo, como
o rodar_curadoria.py), montar_dataset.rodar_joern (traversal/exportar_grafos.sc), montar_dataset.
escolher (nome unico no arquivo; homonimo -> hash do corpo) e montar_dataset.fora_da_funcao.

Um GRUPO e um arquivo: {"pasta": <pasta com arquivo__<nome> e, depois, cpg.bin>, "alvos": [...]},
cada alvo com id, rotulo, nome, particao, projeto, cwe, commit, arquivo, shas, linha (None).
Idempotente: grupo cujo .meta.json tem a mesma assinatura (montar_dataset.assinatura) e pulado.
"""
import json
import os
import shutil
import subprocess
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
sys.path.insert(0, BV)
sys.path.insert(0, os.path.join(BV, "traversal"))
import montar_dataset as md  # noqa: E402

C2CPG = "/opt/joern/joern-cli/c2cpg.sh"


def log(*a):
    print(*a, flush=True)


def nome_seguro(nome):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in nome)


def cpg_do(pasta, timeout):
    cpg = os.path.join(pasta, "cpg.bin")
    if os.path.exists(cpg):
        return cpg, None
    fontes = [f for f in os.listdir(pasta) if f.startswith("arquivo__")]
    try:
        subprocess.run([C2CPG, fontes[0], "--output", "cpg.bin"], capture_output=True, text=True,
                       timeout=timeout, cwd=pasta)
    except subprocess.TimeoutExpired:
        return None, "timeout_c2cpg"
    if not os.path.exists(cpg):
        return None, "c2cpg_falhou"
    return cpg, None


def exportar_grupos(grupos, grafos, trabalho, minutos, timeout):
    os.makedirs(grafos, exist_ok=True)
    os.makedirs(trabalho, exist_ok=True)
    md.TRABALHO = trabalho      # rodar_joern usa esta pasta como cwd (workspace do Joern)
    t0, feitos, exportados = time.time(), 0, 0
    for chave in sorted(grupos):
        info = grupos[chave]
        marca = md.marca_de(chave)
        destino = os.path.join(grafos, marca + ".meta.json")
        assin = md.assinatura(info)
        if os.path.exists(destino) and json.load(open(destino, encoding="utf-8")).get("assinatura") == assin:
            continue
        if minutos and time.time() - t0 > minutos * 60:
            log("tempo esgotado; rode de novo para continuar")
            break
        cpg, erro = cpg_do(info["pasta"], timeout)
        por_alvo, linhas = {}, []
        if not erro:
            tmp = os.path.join(trabalho, "saida")
            shutil.rmtree(tmp, ignore_errors=True)
            os.makedirs(tmp)
            lista = os.path.join(trabalho, "alvos.txt")
            open(lista, "w", encoding="utf-8").write("\n".join(sorted({a["nome"] for a in info["alvos"]})) + "\n")
            cands, erro = md.rodar_joern(cpg, lista, tmp, timeout)
            shutil.rmtree(os.path.join(trabalho, "workspace"), ignore_errors=True)
        for a in info["alvos"]:
            if erro:
                por_alvo[a["id"]] = erro
                continue
            mid, motivo = md.escolher(a, cands.get(a["nome"], []), info["pasta"])
            por_alvo[a["id"]] = motivo
            if mid is None:
                continue
            cam = os.path.join(tmp, "m%d.json" % mid)
            if not os.path.exists(cam):
                por_alvo[a["id"]] = "json_ausente"
                continue
            g = json.load(open(cam, encoding="utf-8"))
            if md.fora_da_funcao(g):
                por_alvo[a["id"]] = "no_fora_da_funcao"
                continue
            linhas.append({"id": a["id"], "rotulo": a["rotulo"], "particao": a["particao"], "projeto": a["projeto"],
                           "cwe": a["cwe"], "commit": a["commit"], "arquivo": a["arquivo"], "nome": a["nome"],
                           "motivo": motivo, "linha_inicio": g["linha_inicio"], "linha_fim": g["linha_fim"],
                           "n_nos": g["n_nos"], "n_arestas": g["n_arestas"], "nos": g["nos"], "arestas": g["arestas"]})
        with open(os.path.join(grafos, marca + ".jsonl"), "w", encoding="utf-8") as f:
            for r in linhas:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        json.dump({"assinatura": assin, "pedidos": len(info["alvos"]), "exportados": len(linhas),
                   "por_alvo": por_alvo}, open(destino, "w", encoding="utf-8"), indent=1)
        feitos += 1
        exportados += len(linhas)
        log(f"  [{feitos}] {marca[:50]:50s} {len(linhas):4d}/{len(info['alvos']):<4d} {time.time() - t0:6.0f} s")
    log(f"grupos nesta execucao: {feitos} | grafos: {exportados} | grupos no total: {len(grupos)}")


def ler_resultados(grupos, grafos):
    """(status por id, grafo por id, pendentes) a partir do que exportar_grupos gravou."""
    por_id, info_grafo, pend = {}, {}, 0
    for chave, info in grupos.items():
        marca = md.marca_de(chave)
        meta = os.path.join(grafos, marca + ".meta.json")
        if not os.path.exists(meta):
            pend += len(info["alvos"])
            for a in info["alvos"]:
                por_id[a["id"]] = "pendente"
            continue
        por_id.update(json.load(open(meta, encoding="utf-8"))["por_alvo"])
        for l in open(os.path.join(grafos, marca + ".jsonl"), encoding="utf-8"):
            r = json.loads(l)
            # so os campos leves: guardar nos e arestas de 20 mil grafos derrubou o WSL (16/10)
            info_grafo[r["id"]] = {k: r[k] for k in ("id", "arquivo", "nome", "motivo", "n_nos", "n_arestas")}
    return por_id, info_grafo, pend
