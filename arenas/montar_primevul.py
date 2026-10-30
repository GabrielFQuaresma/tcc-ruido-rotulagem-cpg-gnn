#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafos do PrimeVul v0.1 (arena cross-dataset), pelo mesmo caminho do dataset v3.

O QUE E, situando
-----------------
Preparacao das arenas externas, passo 3 (PREREGISTRO_ARENAS.md §10). Entram as funcoes com `motivo`
vazio em indice_primevul.tsv (deduplicacao estrita ja feita: 1025 vulneraveis + 30.380 nao
vulneraveis). O negativo do PrimeVul e a versao consertada de cada vulneravel mais as funcoes nao
alteradas do mesmo commit (adendo §1, G4).

QUAL ARQUIVO E QUAL VERSAO (adendo §3, regras comuns; G4):
  - vulneravel                 -> arquivo ANTES do conserto
  - versao consertada (irma)   -> arquivo DEPOIS
  - nao alterada               -> arquivo ANTES (o corpo e o mesmo nas duas versoes, por definicao)
  Quem e irma consertada: o PrimeVul nao marca. Pela construcao dele, de cada commit so ficam a
  funcao vulneravel, a versao consertada dela e as nao alteradas (as outras alteradas sao
  descartadas); entao a irma e a nao vulneravel com o MESMO NOME (buscar_arquivo.nome_da_funcao) de
  uma vulneravel do mesmo commit e do mesmo arquivo. As demais sao nao alteradas.
  De onde vem o arquivo (G4: "da propria v0.1; se nao vier, busca-se pelo commit"):
  - file_contents/ do PrimeVul (Google Drive, listagem publica da pasta do projeto), pelo
    file_info.json: o ANTES de um (commit, caminho) e o arquivo das vulneraveis daquele caminho; o
    DEPOIS e o das irmas consertadas (ou, sem irma, o das nao alteradas que nao e o ANTES);
  - pelo commit, quando o file_contents nao tiver: ANTES por buscar_arquivo.buscar_arquivos_do_commit
    (commit pai); DEPOIS pela mesma URL sem o ^ (com o mesmo espelho do GitHub para host extinto).

DAI EM DIANTE e o caminho do v3, pelo comum_grafos.py: CPG por arquivo, localizacao por nome unico
ou hash do corpo, exportar_grafos.sc, filtro de no fora da funcao. Falha sai e e contada.

FASES (idempotentes; --minutos limita uma execucao): planejar | baixar | exportar | indice.
Saida pesada em ~/curadoria/arenas/primevul/. Nenhum modelo, nenhuma predicao.
"""
import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from urllib.parse import quote, urlparse

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
sys.path.insert(0, BV)
sys.path.insert(0, os.path.join(BV, "traversal"))
import comum_grafos as cg  # noqa: E402
import montar_dataset as md  # noqa: E402
from buscar_arquivo import (Sessao, buscar_arquivos_do_commit, decodifica, detectar, espelho_de,  # noqa: E402
                            nome_da_funcao, url_arquivo_no_pai)
from normalizar_corpo import hashes_do_texto  # noqa: E402

BASE = os.path.expanduser("~/curadoria/arenas/primevul")
ARQS = os.path.join(BASE, "arquivos")
GRAFOS = os.path.join(BASE, "grafos")
TRABALHO = os.path.join(BASE, "_trabalho")
PLANO = os.path.join(BASE, "plano.json")
RESOLUCAO = os.path.join(BASE, "resolucao_sem_caminho.json")
LISTAGEM = os.path.join(BASE, "drive_listagem.json")
PASTA_FILE_CONTENTS = "1L-k6UxsJ98lY8PB8QAskl-cVK5P5QTTi"   # file_contents/ da v0.1 (README oficial)
INDICE_DEDUP = os.path.join(AQUI, "indice_primevul.tsv")
SAIDA = os.path.join(AQUI, "grafos_primevul.tsv")
RUIM = md.RUIM


def log(*a):
    print(*a, flush=True)


def candidatas():
    """Todas as candidatas que passaram de CVE e commit (a estrutura do commit vem delas: a irma e
    o arquivo ANTES de uma nao alterada podem depender de uma vulneravel que saiu pelo corpo);
    e o conjunto das que ficaram."""
    rows = list(csv.DictReader(open(INDICE_DEDUP, encoding="utf-8"), delimiter="\t"))
    estrutura = {r["id"] for r in rows if r["motivo"] not in ("cve", "commit")}
    fica = {r["id"] for r in rows if not r["motivo"]}
    recs = {}
    for part in ("test", "valid", "train"):
        for l in open(os.path.join(BASE, f"primevul_{part}.jsonl"), encoding="utf-8"):
            if not l.strip():
                continue
            d = json.loads(l)
            i = f"pv{d['idx']}"
            if i in estrutura:
                recs[i] = {"id": i, "rotulo": int(d["target"]), "commit": d["commit_id"],
                           "commit_url": d.get("commit_url") or "", "projeto": d.get("project", ""),
                           "file_name": d.get("file_name") or "", "func_hash": str(d["func_hash"]),
                           "cwe": ";".join(d["cwe"]) if isinstance(d.get("cwe"), list) else str(d.get("cwe") or ""),
                           "func": d["func"]}
    return recs, fica


# ------------------------------------------------------------------------- resolver
def _sem_espaco(t):
    return re.sub(r"\s+", "", t or "")


def resolver(minutos, refazer_falhas=False):
    """Funcoes SEM caminho (sem file_info e sem nome de arquivo): busca pelo commit de verdade.

    Correcao de 16/10/2026. Na primeira montagem, todas as funcoes sem caminho de um commit iam para
    UM pedido, que baixava um so arquivo (o da primeira funcao): as que estavam em outros arquivos do
    commit nao tinham o arquivo certo (sem_metodo, ou grafo por coincidencia de nome). Aqui, para cada
    commit, os arquivos de codigo do patch sao baixados na versao ANTES e cada funcao vai para o
    arquivo cujo texto contem o CORPO dela (sem espacos); varios -> o que contem o corpo inteiro; a
    irma consertada vai para o caminho da vulneravel de mesmo nome do commit. Quem nao e achado fica
    "nao identificado" e sai como falha contada (G4: "se nem assim, e falha contada")."""
    recs, fica = candidatas()
    info = json.load(open(os.path.join(BASE, "file_info.json"), encoding="utf-8"))
    preparar_registros(recs, info)
    sem = [r for r in recs.values() if r["id"] in fica and not r["caminho_final"]]
    por_commit = defaultdict(list)
    for r in sem:
        por_commit[r["commit"]].append(r)
    res = json.load(open(RESOLUCAO, encoding="utf-8")) if os.path.exists(RESOLUCAO) else {}
    if refazer_falhas:   # commits de forge conhecido em que nenhum arquivo baixou (ex.: git.kernel.org intermitente)
        refazer = {r["commit"] for r in sem if (res.get(r["id"]) or {}).get("arquivos_do_commit") == 0
                   and (res.get(r["id"]) or {}).get("origem")}
        for r in sem:
            if r["commit"] in refazer:
                res.pop(r["id"], None)
        log(f"commits a refazer (nenhum arquivo baixado): {len(refazer)}")
    ses = Sessao(conexoes=4)
    t0 = time.time()
    for commit in sorted(por_commit):
        rs = por_commit[commit]
        if all(r["id"] in res for r in rs):
            continue
        if minutos and time.time() - t0 > minutos * 60:
            log("tempo esgotado; rode de novo para continuar")
            break
        familia, base, sha = detectar(rs[0]["commit_url"])
        sha = sha or commit
        textos, origem = {}, ""
        for fam, b in ((familia, base), ("github", espelho_de(base, familia) if base else None)):
            if not fam or not b or textos:
                continue
            caminhos = paths_do_patch_seguro(ses, fam, b, sha)
            for c in caminhos[:60]:
                t = decodifica(fam, ses.get(url_arquivo_no_pai(fam, b, sha, c)))
                if t and t.strip():
                    textos[c] = _sem_espaco(t)
            origem = fam
        # vulneraveis e nao alteradas: pelo corpo, no arquivo ANTES
        for r in rs:
            if r["tipo"] == "irma":
                continue
            corpo = _sem_espaco(r["func"])
            cands = [c for c, t in textos.items() if corpo[:150] in t]
            if len(cands) > 1:
                cands = [c for c in cands if corpo in textos[c]] or cands
            res[r["id"]] = ({"caminho": cands[0], "metodo": "corpo"} if len(cands) == 1 else
                            {"caminho": None, "metodo": "corpo_ambiguo" if cands else "nao_achado",
                             "arquivos_do_commit": len(textos), "origem": origem})
        # irmas: o caminho da vulneravel de mesmo nome no mesmo commit
        vuln_cam = {}
        for r in recs.values():
            if r["commit"] == commit and r["tipo"] == "vulneravel":
                cam = r["caminho_final"] or (res.get(r["id"]) or {}).get("caminho")
                if cam and r["nome"]:
                    vuln_cam.setdefault(r["nome"], cam)
        for r in rs:
            if r["tipo"] == "irma":
                cam = vuln_cam.get(r["nome"])
                res[r["id"]] = {"caminho": cam, "metodo": "irma_da_vulneravel" if cam else "nao_achado"}
        json.dump(res, open(RESOLUCAO, "w", encoding="utf-8"))
    c = Counter(v["metodo"] for i, v in res.items())
    log(f"funcoes sem caminho: {len(sem)} em {len(por_commit)} commits | resolvidas ate agora: {len(res)} | {dict(c)}")


def paths_do_patch_seguro(ses, fam, base, sha):
    from buscar_arquivo import paths_do_patch, url_patch
    u = url_patch(fam, base, sha)
    return paths_do_patch(decodifica(fam, ses.get(u)) or "") if u else []


# ------------------------------------------------------------------------- planejar
def preparar_registros(recs, info):
    """Nome, caminho (file_info), arquivo-base e tipo (vulneravel / irma / nao_alterada) de cada candidata."""
    for r in recs.values():
        fi = info.get(r["func_hash"])
        r["nome"] = nome_da_funcao(r["func"])
        r["caminho"] = fi["project_file_path"] if fi else None
        r["local"] = fi["local_file_path"] if fi else None
        r["base"] = md.basename(r["caminho"] or r["file_name"])
    vuln_nomes = defaultdict(set)
    for r in recs.values():
        if r["rotulo"] == 1 and r["nome"]:
            vuln_nomes[(r["commit"], r["base"])].add(r["nome"])
    caminho_de = {}
    for r in recs.values():
        if r["caminho"]:
            caminho_de.setdefault((r["commit"], r["base"]), r["caminho"])
    for r in recs.values():
        r["tipo"] = ("vulneravel" if r["rotulo"] == 1 else
                     "irma" if r["nome"] and r["nome"] in vuln_nomes[(r["commit"], r["base"])] else "nao_alterada")
        r["versao"] = "depois" if r["tipo"] == "irma" else "antes"
        r["caminho_final"] = r["caminho"] or caminho_de.get((r["commit"], r["base"]))


def planejar():
    recs, fica = candidatas()
    info = json.load(open(os.path.join(BASE, "file_info.json"), encoding="utf-8"))
    preparar_registros(recs, info)
    resol = json.load(open(RESOLUCAO, encoding="utf-8")) if os.path.exists(RESOLUCAO) else {}
    for r in recs.values():
        if not r["caminho_final"] and r["id"] in resol:
            r["caminho_final"] = resol[r["id"]]["caminho"]
            r["nao_identificado"] = resol[r["id"]]["caminho"] is None
            if r["caminho_final"]:
                r["base"] = md.basename(r["caminho_final"])
    # (tipo e versao ja vieram de preparar_registros, com a mesma regra da primeira montagem)
    # o ANTES e o DEPOIS de cada (commit, caminho) no file_contents
    locais = defaultdict(lambda: {"antes": Counter(), "irma": Counter(), "outros": Counter()})
    for r in recs.values():
        if r["local"]:
            k = (r["commit"], r["caminho"])
            locais[k]["antes" if r["tipo"] == "vulneravel" else "irma" if r["tipo"] == "irma" else "outros"][r["local"]] += 1
    escolha = {}
    for k, c in locais.items():
        antes = c["antes"].most_common(1)[0][0] if c["antes"] else None
        if c["irma"]:
            depois = c["irma"].most_common(1)[0][0]
        else:
            resto = [(n, l) for l, n in c["outros"].items() if l != antes]
            depois = max(resto)[1] if resto else None
        escolha[k] = {"antes": antes, "depois": depois}
    # um pedido de arquivo por (commit, versao, caminho-ou-base); de onde vem
    plano, pedidos = {}, {}
    for r in recs.values():
        if r["id"] not in fica:
            continue
        if r.get("nao_identificado"):   # a busca pelo commit nao achou o arquivo: falha, sem pedido
            plano[r["id"]] = {"unid": None, "tipo": r["tipo"], "versao": r["versao"], "nome": r["nome"],
                              "rotulo": r["rotulo"], "projeto": r["projeto"], "cwe": r["cwe"],
                              "commit": r["commit"], "shas": [], "nao_identificado": True}
            continue
        cam = r["caminho_final"]
        local = escolha.get((r["commit"], cam), {}).get(r["versao"]) if cam else None
        unid = f"{r['commit']}|{r['versao']}|{cam or 'base:' + r['base']}"
        if unid not in pedidos:
            pedidos[unid] = {"commit": r["commit"], "commit_url": r["commit_url"], "versao": r["versao"],
                             "caminho": cam, "base": r["base"], "local": local, "projeto": r["projeto"],
                             "funcao": r["func"][:4000] if r["tipo"] != "irma" else ""}
        elif local and not pedidos[unid]["local"]:
            pedidos[unid]["local"] = local
        if r["tipo"] == "vulneravel" and not pedidos[unid]["funcao"]:
            pedidos[unid]["funcao"] = r["func"][:4000]
        plano[r["id"]] = {"unid": unid, "tipo": r["tipo"], "versao": r["versao"], "nome": r["nome"],
                          "rotulo": r["rotulo"], "projeto": r["projeto"], "cwe": r["cwe"], "commit": r["commit"],
                          "shas": sorted(hashes_do_texto(r["func"])),
                          "nao_identificado": bool(r.get("nao_identificado"))}
    json.dump({"funcoes": plano, "pedidos": pedidos}, open(PLANO, "w", encoding="utf-8"))
    c = Counter((v["tipo"], "nao_identificado" if v["unid"] is None else
                 "file_contents" if pedidos[v["unid"]]["local"] is not None else "commit") for v in plano.values())
    log("funcoes que ficam, por tipo e de onde vem o arquivo:")
    for k in sorted(c):
        log(f"  {k[0]:14s} {k[1]:16s} {c[k]:6d}")
    cp = Counter((p["versao"], p["local"] is not None) for p in pedidos.values())
    log(f"pedidos de arquivo: {len(pedidos)} | (versao, file_contents?): {dict(cp)}")
    # conferencia da classificacao: a irma aponta, no file_info, para o arquivo DEPOIS — nunca para o
    # mesmo arquivo da vulneravel do seu caminho (isso indicaria irma mal classificada)
    suspeitas = sum(1 for r in recs.values() if r["tipo"] == "irma" and r["local"]
                    and r["local"] == escolha.get((r["commit"], r["caminho"]), {}).get("antes"))
    irmas = sum(1 for r in recs.values() if r["tipo"] == "irma")
    log(f"irmas consertadas: {irmas} (vulneraveis candidatas: {sum(r['rotulo'] for r in recs.values())}) | "
        f"irmas no MESMO arquivo da vulneravel (classificacao suspeita): {suspeitas}")


# ------------------------------------------------------------------------- baixar
def listar_drive(ses, fid):
    h = ses.get(f"https://drive.google.com/embeddedfolderview?id={fid}") or ""
    return dict(zip(re.findall(r'flip-entry-title">([^<]*)', h), re.findall(r'id="entry-([^"]+)"', h)))


def url_na_versao(familia, base, sha, caminho, versao):
    if versao == "antes":
        return url_arquivo_no_pai(familia, base, sha, caminho)
    c = quote(caminho.lstrip("/"))
    if familia == "github":
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", base)
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{sha}/{c}"
    if familia == "googlesource":
        return f"{base}/+/{sha}/{c}?format=TEXT"
    if familia == "gitweb":
        return f"{base};a=blob_plain;f={c};hb={sha}"
    if familia == "cgit":
        return f"{base}/plain/{c}?id={sha}"
    return None


def pelo_commit(ses, p):
    """(caminho, texto, origem) de um pedido que o file_contents nao tem."""
    if p["versao"] == "antes":
        res = buscar_arquivos_do_commit(p["commit_url"], p["commit"], p["caminho"] or p["base"], sessao=ses,
                                        so_um=True, funcao=p["funcao"])
        if res.arquivos and res.status in ("ok", "ok_sem_confirmar_funcao"):
            c, t = res.arquivos[0]
            return c, t, f"commit:{res.familia}:{res.status}"
        return None, None, f"commit:{res.status}"
    if not p["caminho"]:
        return None, None, "commit:depois_sem_caminho"
    familia, base, sha = detectar(p["commit_url"])
    sha = sha or p["commit"]
    for fam, b in ((familia, base), ("github", espelho_de(base, familia) if base else None)):
        if not fam or not b:
            continue
        u = url_na_versao(fam, b, sha, p["caminho"], "depois")
        t = decodifica(fam, ses.get(u)) if u else None
        if t and t.strip():
            return p["caminho"], t, f"commit:{fam}"
    return None, None, "commit:depois_nao_baixou"


def baixar(minutos, refazer_falhas=False):
    pl = json.load(open(PLANO, encoding="utf-8"))
    if refazer_falhas:   # tenta de novo so os pedidos cujo download.json registrou falha
        n = 0
        for unid, p in pl["pedidos"].items():
            mp = os.path.join(ARQS, md.marca_de(chave_grupo(p)), "download.json")
            if os.path.exists(mp) and json.load(open(mp, encoding="utf-8"))["status"] != "ok":
                os.remove(mp)
                n += 1
        log(f"falhas a refazer: {n}")
    ses = Sessao(conexoes=4)
    lst = json.load(open(LISTAGEM, encoding="utf-8")) if os.path.exists(LISTAGEM) else {}
    if "_raiz" not in lst:
        lst["_raiz"] = listar_drive(ses, PASTA_FILE_CONTENTS)
    t0, st = time.time(), Counter()
    for unid in sorted(pl["pedidos"]):
        p = pl["pedidos"][unid]
        chave = chave_grupo(p)
        pasta = os.path.join(ARQS, md.marca_de(chave))
        if os.path.exists(os.path.join(pasta, "download.json")):
            continue
        if minutos and time.time() - t0 > minutos * 60:
            log("tempo esgotado; rode de novo para continuar")
            break
        caminho, texto, origem = None, None, ""
        if p["local"]:
            proj, nome = p["local"].split("/")[1], p["local"].split("/")[-1]
            if proj not in lst and proj in lst["_raiz"]:
                lst[proj] = listar_drive(ses, lst["_raiz"][proj])
                json.dump(lst, open(LISTAGEM, "w", encoding="utf-8"))
            fid = lst.get(proj, {}).get(nome)
            if fid:
                texto = ses.get(f"https://drive.usercontent.google.com/download?id={fid}&export=download&confirm=t")
                caminho, origem = p["caminho"], "file_contents"
            if not (texto and texto.strip()):
                texto, origem = None, "file_contents_ausente"
        if texto is None:
            if p["versao"] == "depois" and not p["caminho"]:
                # sem file_info nem nome de arquivo: o caminho e o que o ANTES do mesmo commit
                # descobriu pelo patch (o pedido ANTES vem antes na ordem e ja foi baixado)
                ua = unid.replace("|depois|", "|antes|", 1)
                if ua in pl["pedidos"]:
                    ma = os.path.join(ARQS, md.marca_de(chave_grupo(pl["pedidos"][ua])), "download.json")
                    if os.path.exists(ma):
                        p = dict(p, caminho=json.load(open(ma, encoding="utf-8")).get("caminho"))
            c2, t2, o2 = pelo_commit(ses, p)
            origem = (origem + "->" if origem else "") + o2
            if t2:
                caminho, texto = c2, t2
        os.makedirs(pasta, exist_ok=True)
        meta = {"unid": unid, "origem": origem, "caminho": caminho, "status": "ok" if texto else "falhou"}
        if texto:
            open(os.path.join(pasta, "arquivo__" + cg.nome_seguro(md.basename(caminho or p["base"]))), "w",
                 encoding="utf-8", errors="replace").write(texto)
        json.dump(meta, open(os.path.join(pasta, "download.json"), "w", encoding="utf-8"), indent=1)
        st[(meta["status"], origem.split("->")[-1].split(":")[0])] += 1
    json.dump(lst, open(LISTAGEM, "w", encoding="utf-8"))
    log(f"downloads nesta execucao: {dict(st)} | pedidos no total: {len(pl['pedidos'])}")


# ------------------------------------------------------------------------- exportar / indice
def chave_grupo(p):
    cam = p["caminho"] or ("base:" + p["base"])
    return (hashlib.sha1(p["commit"].encode()).hexdigest()[:12], f"{p['versao']}__{p['base']}", cam)


def grupos_de():
    pl = json.load(open(PLANO, encoding="utf-8"))
    grupos, falha = defaultdict(lambda: {"pasta": None, "alvos": []}), {}
    for i, f in pl["funcoes"].items():
        if f.get("nao_identificado"):
            falha[i] = "arquivo_nao_identificado_no_commit"
            continue
        p = pl["pedidos"][f["unid"]]
        chave = chave_grupo(p)
        pasta = os.path.join(ARQS, md.marca_de(chave))
        mp = os.path.join(pasta, "download.json")
        if not os.path.exists(mp) or json.load(open(mp, encoding="utf-8"))["status"] != "ok":
            falha[i] = "sem_arquivo_baixado" if os.path.exists(mp) else "pendente_download"
            continue
        if not f["nome"] or f["nome"] in RUIM:
            falha[i] = "sem_nome_de_funcao"
            continue
        g = grupos[chave]
        g["pasta"] = pasta
        g["alvos"].append({"id": i, "rotulo": f["rotulo"], "nome": f["nome"], "particao": "primevul",
                           "projeto": f["projeto"], "cwe": f["cwe"], "commit": f["commit"], "arquivo": p["base"],
                           "shas": f["shas"], "linha": None})
    return grupos, falha, pl


def limpar():
    """Move para grafos_obsoletos/ os grafos de grupos que nao existem mais no plano (os pedidos unicos
    'base:' por commit, substituidos pela fase resolver em 16/10). Quem le a pasta inteira (vetorizacao,
    conferencias, ficha) contaria essas funcoes duas vezes. Nada e apagado."""
    import shutil
    grupos, _, _ = grupos_de()
    validas = {md.marca_de(k) for k in grupos}
    dest = os.path.join(BASE, "grafos_obsoletos")
    os.makedirs(dest, exist_ok=True)
    n = 0
    for f in sorted(os.listdir(GRAFOS)):
        marca = f[:-len(".meta.json")] if f.endswith(".meta.json") else f[:-len(".jsonl")] if f.endswith(".jsonl") else None
        if marca and marca not in validas:
            shutil.move(os.path.join(GRAFOS, f), os.path.join(dest, f))
            n += 1
    log(f"arquivos de grupos obsoletos movidos para grafos_obsoletos/: {n} | grupos validos: {len(validas)}")


def indice():
    grupos, falha, pl = grupos_de()
    por_id, info_grafo, pend = cg.ler_resultados(grupos, GRAFOS)
    por_id.update(falha)
    c = Counter()
    with open(SAIDA, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "rotulo", "tipo", "versao", "projeto", "arquivo", "nome", "status", "localizacao", "n_nos", "n_arestas"])
        for i in sorted(pl["funcoes"], key=lambda x: int(x[2:])):
            f = pl["funcoes"][i]
            g = info_grafo.get(i)
            status = "grafo" if g else por_id.get(i, "?")
            c[(status, f["rotulo"])] += 1
            w.writerow([i, f["rotulo"], f["tipo"], f["versao"], f["projeto"], g["arquivo"] if g else "",
                        g["nome"] if g else "", status, g["motivo"] if g else "",
                        g["n_nos"] if g else "", g["n_arestas"] if g else ""])
    log("status por rotulo (vulneraveis / nao vulneraveis):")
    for s in sorted({k[0] for k in c}):
        log(f"  {s:28s} {c[(s, 1)]:5d} / {c[(s, 0)]:5d}")
    if pend:
        log(f"ATENCAO: {pend} funcoes ainda pendentes")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fase", choices=["resolver", "planejar", "baixar", "exportar", "limpar", "indice"])
    ap.add_argument("--minutos", type=float, default=8.5)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--refazer-falhas", action="store_true", help="baixar: tenta de novo os pedidos que falharam")
    a = ap.parse_args()
    if a.fase == "resolver":
        resolver(a.minutos, a.refazer_falhas)
    elif a.fase == "planejar":
        planejar()
    elif a.fase == "baixar":
        baixar(a.minutos, a.refazer_falhas)
    elif a.fase == "exportar":
        grupos, _, _ = grupos_de()
        cg.exportar_grupos(grupos, GRAFOS, TRABALHO, a.minutos, a.timeout)
    elif a.fase == "limpar":
        limpar()
    else:
        indice()


if __name__ == "__main__":
    main()
