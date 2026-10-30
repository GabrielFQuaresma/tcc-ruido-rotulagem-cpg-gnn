#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafos do VentiVul v3 (familia de memoria e inteiro), pelo mesmo caminho do dataset v3.

O QUE E, situando
-----------------
Preparacao das arenas externas, passo 3 (PREREGISTRO_ARENAS.md §10). O VentiVul e a arena temporal:
200 CVEs de Linux e Chromium divulgadas a partir de maio de 2025. O negativo e a versao consertada
de cada vulneravel mais as funcoes do mesmo arquivo que o conserto nao tocou (adendo §1 e G3). Ficam
as funcoes com `motivo` vazio em indice_ventivul_familia.tsv OU indice_ventivul_inteiro.tsv (a
deduplicacao ja foi feita; o inteiro sai ao lado, descritivo, e precisa de grafo tambem).

QUAL ARQUIVO E QUAL VERSAO (adendo §3, regras comuns; G3):
  - vulneravel (rotulo 1, com par)   -> arquivo ANTES do conserto
  - versao consertada (0, com par)   -> arquivo DEPOIS do conserto
  - nao relacionada (0, sem par)     -> arquivo ANTES do conserto
  O arquivo inteiro nao vem nos dados; busca-se pelo `link`:
  - Linux: commit no git.kernel.org (cgit). Antes = <sha>^, depois = <sha> (mesma URL do
    buscar_arquivo.url_arquivo_no_pai, com e sem o ^). Par sem nome de arquivo: o caminho sai do patch.
  - Chromium (e v8, angle, libvpx, dawn, vboot): a revisao no Gerrit, com o caminho no proprio link.
    Depois = conteudo do arquivo naquela revisao; antes = o mesmo com ?parent=1 (o commit pai).
  - Nao relacionada: o nome do arquivo codifica a CVE (cve202523142.c, cve202523142_1.c, ...), nao o
    caminho. Os candidatos sao os arquivos ANTES dos pares daquela(s) CVE(s); fica o candidato em
    cujo texto aparece a maior fracao dos nomes das funcoes daquele arquivo codificado ("cobertura",
    gravada por arquivo). Empate entre caminhos diferentes -> nao identificado (falha contada); empate
    entre versoes do MESMO caminho (dois links da mesma CVE) -> o primeiro na ordem, declarado.

DAI EM DIANTE e o caminho do v3, pelo comum_grafos.py: CPG por arquivo, localizacao por nome unico
ou hash do corpo, exportar_grafos.sc, filtro de no fora da funcao. Falha sai e e contada.

FASES (idempotentes; --minutos limita uma execucao): preparar | exportar | indice.
Saida pesada em ~/curadoria/arenas/ventivul/. Nenhum modelo, nenhuma predicao.
"""
import argparse
import base64
import csv
import glob
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from urllib.parse import quote, unquote

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
sys.path.insert(0, BV)
sys.path.insert(0, os.path.join(BV, "traversal"))
import comum_grafos as cg  # noqa: E402
import montar_dataset as md  # noqa: E402
from buscar_arquivo import Sessao, detectar, nome_da_funcao, paths_do_patch, url_patch  # noqa: E402
from normalizar_corpo import hashes_do_texto  # noqa: E402

BASE = os.path.expanduser("~/curadoria/arenas/ventivul")
CSV_V = os.path.join(BASE, "ventivul.csv")
ARQS = os.path.join(BASE, "arquivos")
GRAFOS = os.path.join(BASE, "grafos")
TRABALHO = os.path.join(BASE, "_trabalho")
MAPA = os.path.join(BASE, "mapa_codificados.json")
PARES = os.path.join(BASE, "pares.json")
INDICES = [os.path.join(AQUI, "indice_ventivul_familia.tsv"), os.path.join(AQUI, "indice_ventivul_inteiro.tsv")]
SAIDA = os.path.join(AQUI, "grafos_ventivul.tsv")
RUIM = md.RUIM


def log(*a):
    print(*a, flush=True)


def carregar():
    df = pd.read_csv(CSV_V)
    df["id"] = [f"vv{i}" for i in range(len(df))]
    df["par"] = df["pair_id"].astype(str) != "none"
    fica = set()
    for p in INDICES:
        fica |= {r["id"] for r in csv.DictReader(open(p, encoding="utf-8"), delimiter="\t") if not r["motivo"]}
    return df, fica


def fonte_do_link(link):
    m = re.match(r"https://([^/]+)/c/(.+?)/\+/(\d+)/(\d+)/(.+)$", str(link))
    if m:
        return {"tipo": "gerrit", "host": m.group(1), "proj": m.group(2), "change": m.group(3),
                "ps": m.group(4), "caminho": unquote(m.group(5)),
                "chave": f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"}
    fam, base, sha = detectar(link)
    if fam == "cgit" and sha:
        return {"tipo": "cgit", "base": base, "sha": sha, "caminho": None, "chave": f"{base}|{sha}"}
    return None


def url_versao(f, caminho, versao):
    if f["tipo"] == "gerrit":
        u = (f"https://{f['host']}/changes/{quote(f['proj'], safe='')}~{f['change']}/revisions/{f['ps']}"
             f"/files/{quote(caminho, safe='')}/content")
        return u + ("?parent=1" if versao == "antes" else "")
    return f"{f['base']}/plain/{quote(caminho.lstrip('/'))}?id={f['sha']}" + ("%5E" if versao == "antes" else "")


def chave_grupo(f, caminho, versao):
    """(fonte, versao__arquivo, caminho): a marca do grupo (md.marca_de) leva o hash do caminho."""
    return (hashlib.sha1(f["chave"].encode()).hexdigest()[:12], f"{versao}__{md.basename(caminho)}", caminho)


def pasta_de(chave):
    return os.path.join(ARQS, md.marca_de(chave))


def baixar_um(ses, f, caminho, versao):
    chave = chave_grupo(f, caminho, versao)
    pasta = pasta_de(chave)
    meta_p = os.path.join(pasta, "download.json")
    if os.path.exists(meta_p):
        return json.load(open(meta_p, encoding="utf-8"))
    url = url_versao(f, caminho, versao)
    txt = ses.get(url)
    if txt is not None and f["tipo"] == "gerrit":
        try:
            txt = base64.b64decode(txt).decode("utf-8", errors="replace")
        except Exception:
            txt = None
    os.makedirs(pasta, exist_ok=True)
    meta = {"chave": list(chave), "fonte": f["chave"], "caminho": caminho, "versao": versao, "url": url,
            "status": "ok" if (txt and txt.strip()) else "erro_download"}
    if meta["status"] == "ok":
        open(os.path.join(pasta, "arquivo__" + cg.nome_seguro(md.basename(caminho))), "w",
             encoding="utf-8", errors="replace").write(txt)
    json.dump(meta, open(meta_p, "w", encoding="utf-8"), indent=1)
    return meta


def texto_de(chave):
    pasta = pasta_de(chave)
    fs = [x for x in os.listdir(pasta) if x.startswith("arquivo__")] if os.path.isdir(pasta) else []
    return open(os.path.join(pasta, fs[0]), encoding="utf-8", errors="replace").read() if fs else ""


def baixados_antes():
    """fonte -> caminhos cujo arquivo ANTES ja foi baixado com sucesso (lido dos download.json)."""
    out = defaultdict(list)
    for p in glob.glob(os.path.join(ARQS, "*", "download.json")):
        m = json.load(open(p, encoding="utf-8"))
        if m["versao"] == "antes" and m["status"] == "ok":
            out[m["fonte"]].append(m["caminho"])
    return out


def aparece(nome, texto):
    return bool(nome) and re.search(r"\b" + re.escape(nome) + r"\s*\(", texto) is not None


def cves_do_nome(nome):
    m = re.fullmatch(r"cve(\d{4})(\d+)((?:_\d+)*)", str(nome).rsplit(".", 1)[0])
    if not m:
        return []
    out = [f"CVE-{m.group(1)}-{m.group(2)}"]
    out += [f"CVE-{t[:4]}-{t[4:]}" for t in m.group(3).split("_")[1:] if len(t) >= 8 and t.startswith("20")]
    return out


# ------------------------------------------------------------------------- preparar
def caminhos_dos_pares(df, ses, minutos, t0):
    """Para cada linha com par: (fonte, caminho). Linux sem nome de arquivo: caminho pelo patch.
    A resolucao e gravada uma vez em PARES; dai em diante so se le o arquivo (nada depende da rede
    nas fases seguintes — numa execucao de 15/10 o patch nao respondeu e a fase quebrou)."""
    if os.path.exists(PARES):
        return {i: (tuple(v) if v else None) for i, v in json.load(open(PARES, encoding="utf-8")).items()}
    out = {}
    for _, r in df[df["par"]].iterrows():
        f = fonte_do_link(r["link"])
        if f is None:
            out[r["id"]] = None
            continue
        cam = f["caminho"] if f["tipo"] == "gerrit" else None
        fn = str(r["file_name_ori"])
        if cam is None and fn not in RUIM:
            cam = re.sub(r"^root/", "", fn)
        if cam is None:   # Linux sem nome: caminhos do patch; fica o que contem o nome da funcao
            nome = nome_da_funcao(r["Function"])
            # primeiro o disco: arquivos ANTES ja baixados deste commit (o patch do git.kernel.org
            # falha de forma intermitente; uma resolucao ja feita nao pode depender da rede de novo)
            for c in sorted(baixados_antes().get(f["chave"], [])):
                if aparece(nome, texto_de(chave_grupo(f, c, "antes"))):
                    cam = c
                    break
        if cam is None:
            patch = ses.get(url_patch("cgit", f["base"], f["sha"]))
            for c in paths_do_patch(patch or ""):
                m = baixar_um(ses, f, c, "antes")
                if m["status"] == "ok" and aparece(nome, texto_de(chave_grupo(f, c, "antes"))):
                    cam = c
                    break
        out[r["id"]] = (f, cam) if cam else None
    if all(v is not None for v in out.values()):   # so grava quando tudo resolveu
        json.dump(out, open(PARES, "w", encoding="utf-8"), indent=1)
    else:
        log(f"pares sem caminho nesta execucao: {sum(v is None for v in out.values())} (nao gravado; rode de novo)")
    return out


def preparar(minutos):
    df, fica = carregar()
    ses = Sessao(conexoes=4)
    t0 = time.time()
    pares = caminhos_dos_pares(df, ses, minutos, t0)
    pedidos = set()
    for i, fc in pares.items():
        if fc:
            pedidos.add((fc[0]["chave"], fc[1]))
    fontes = {fc[0]["chave"]: fc[0] for fc in pares.values() if fc}
    st = Counter()
    for fk, cam in sorted(pedidos):
        for versao in ("antes", "depois"):
            if minutos and time.time() - t0 > minutos * 60:
                log("tempo esgotado; rode de novo para continuar")
                return
            st[baixar_um(ses, fontes[fk], cam, versao)["status"]] += 1
    log(f"arquivos (caminho x versao): {dict(st)}")
    if not os.path.exists(PARES):
        log("pares nao resolvidos por completo: o mapa dos arquivos codificados NAO foi regravado")
        return
    mapear_codificados(df, pares)


def mapear_codificados(df, pares):
    """Arquivo codificado (nao relacionadas) -> arquivo ANTES de um par da(s) CVE(s), por cobertura."""
    cand_por_cve = defaultdict(set)
    for _, r in df[df["par"]].iterrows():
        fc = pares.get(r["id"])
        if fc:
            cand_por_cve[r["cve_id"]].add((fc[0]["chave"], fc[1]))
    fontes = {fc[0]["chave"]: fc[0] for fc in pares.values() if fc}
    mapa = {}
    for cod, g in df[~df["par"]].groupby("file_name_ori"):
        nomes = [nome_da_funcao(x) for x in g["Function"]]
        cands = sorted(set().union(*(cand_por_cve.get(c, set()) for c in cves_do_nome(cod))))
        cob = []
        for fk, cam in cands:
            t = texto_de(chave_grupo(fontes[fk], cam, "antes"))
            cob.append((sum(aparece(n, t) for n in nomes) / max(len(nomes), 1), fk, cam))
        cob.sort(key=lambda x: (-x[0], x[1], x[2]))
        if not cob or cob[0][0] == 0:
            mapa[cod] = {"status": "sem_candidato" if not cob else "cobertura_zero", "candidatos": len(cob)}
        elif len(cob) > 1 and cob[1][0] == cob[0][0] and cob[1][2] != cob[0][2]:
            mapa[cod] = {"status": "empate", "candidatos": len(cob), "cobertura": cob[0][0]}
        else:
            mapa[cod] = {"status": "ok", "fonte": cob[0][1], "caminho": cob[0][2], "cobertura": round(cob[0][0], 4),
                         "candidatos": len(cob), "funcoes": len(nomes)}
    json.dump(mapa, open(MAPA, "w", encoding="utf-8"), indent=1)
    c = Counter(v["status"] for v in mapa.values())
    cobs = sorted(v["cobertura"] for v in mapa.values() if v["status"] == "ok")
    log(f"arquivos codificados: {len(mapa)} | {dict(c)} | cobertura minima {cobs[0] if cobs else '-'}, "
        f"mediana {cobs[len(cobs) // 2] if cobs else '-'}; com cobertura < 0,9: {sum(x < 0.9 for x in cobs)}")


# ------------------------------------------------------------------------- exportar / indice
def grupos_de(df, fica):
    if not (os.path.exists(PARES) and os.path.exists(MAPA)):
        sys.exit("ERRO: rode 'preparar' ate gravar pares.json e mapa_codificados.json")
    ses = Sessao(conexoes=2)
    pares = caminhos_dos_pares(df, ses, 0, time.time())   # ja baixado: so le os download.json
    mapa = json.load(open(MAPA, encoding="utf-8"))
    fontes = {fc[0]["chave"]: fc[0] for fc in pares.values() if fc}
    grupos, falha = defaultdict(lambda: {"pasta": None, "alvos": []}), {}
    for _, r in df.iterrows():
        if r["id"] not in fica:
            continue
        if r["par"]:
            fc = pares.get(r["id"])
            if not fc:
                falha[r["id"]] = "sem_caminho"
                continue
            f, cam = fc
            versao = "antes" if r["Vulnerable"] == 1 else "depois"
        else:
            m = mapa.get(r["file_name_ori"], {})
            if m.get("status") != "ok":
                falha[r["id"]] = "arquivo_codificado_" + m.get("status", "ausente")
                continue
            f, cam, versao = fontes[m["fonte"]], m["caminho"], "antes"
        chave = chave_grupo(f, cam, versao)
        meta_p = os.path.join(pasta_de(chave), "download.json")
        if not os.path.exists(meta_p) or json.load(open(meta_p, encoding="utf-8"))["status"] != "ok":
            falha[r["id"]] = "sem_arquivo_baixado"
            continue
        nome = nome_da_funcao(r["Function"])
        if not nome or nome in RUIM:
            falha[r["id"]] = "sem_nome_de_funcao"
            continue
        g = grupos[chave]
        g["pasta"] = pasta_de(chave)
        g["alvos"].append({"id": r["id"], "rotulo": int(r["Vulnerable"]), "nome": nome, "particao": "ventivul",
                           "projeto": r["project"], "cwe": "" if pd.isna(r["cwe_id"]) else r["cwe_id"],
                           "commit": f["chave"], "arquivo": md.basename(cam),
                           "shas": sorted(hashes_do_texto(r["Function"])), "linha": None})
    return grupos, falha


def indice(df, fica):
    grupos, falha = grupos_de(df, fica)
    por_id, info_grafo, pend = cg.ler_resultados(grupos, GRAFOS)
    por_id.update(falha)
    c = Counter()
    with open(SAIDA, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "rotulo", "projeto", "origem", "arquivo", "nome", "status", "localizacao", "n_nos", "n_arestas"])
        for _, r in df.iterrows():
            if r["id"] not in fica:
                continue
            g = info_grafo.get(r["id"])
            status = "grafo" if g else por_id.get(r["id"], "?")
            c[(status, int(r["Vulnerable"]))] += 1
            w.writerow([r["id"], int(r["Vulnerable"]), r["project"], "par" if r["par"] else "nao_relacionada",
                        g["arquivo"] if g else "", g["nome"] if g else "", status, g["motivo"] if g else "",
                        g["n_nos"] if g else "", g["n_arestas"] if g else ""])
    log("status por rotulo (vulneraveis / nao vulneraveis), uniao familia + inteiro:")
    for s in sorted({k[0] for k in c}):
        log(f"  {s:34s} {c[(s, 1)]:5d} / {c[(s, 0)]:5d}")
    if pend:
        log(f"ATENCAO: {pend} funcoes ainda pendentes")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fase", choices=["preparar", "exportar", "indice"])
    ap.add_argument("--minutos", type=float, default=8.5)
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    if a.fase == "preparar":
        preparar(a.minutos)
    elif a.fase == "exportar":
        df, fica = carregar()
        grupos, _ = grupos_de(df, fica)
        cg.exportar_grupos(grupos, GRAFOS, TRABALHO, a.minutos, a.timeout)
    else:
        indice(*carregar())


if __name__ == "__main__":
    main()
