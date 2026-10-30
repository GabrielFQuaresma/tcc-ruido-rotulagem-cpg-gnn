#!/usr/bin/env python3
"""Traversal v3 CONGELADA sobre as funcoes NAO vulneraveis do teste (a linha "traversal pura").

    python3 rodar_traversal_negativos.py --ensaio 20           # ensaio: 17 sorteadas + 3 homonimas
    python3 rodar_traversal_negativos.py --retomar             # todas; pula o que ja tem saida
    python3 rodar_traversal_negativos.py --retomar --parar-apos 270   # fatia de ~5 min
    python3 rodar_traversal_negativos.py --retentar-timeout    # passada final: so os timeouts
    python3 rodar_traversal_negativos.py --resumo              # contagem de ok/falha, sem veredito

ONDE ESTAMOS. PREREGISTRO_PRINCIPAL.md (congelado em 12/10/2026), §7 e §6 passo 3: a regra da
curadoria entra na tabela de resultados como classificador ("confirmado" = acusa). A v3 so rodou
nos 2957 positivos (TRAVERSAL_V3.md, Fase 4); as 5241 negativas do teste nunca passaram por ela.
Este script roda a regra nelas, ANTES de abrir o teste.

O QUE E IGUAL AOS POSITIVOS DA V3: o mesmo curadoria_v3.sc, as mesmas tabelas de dados/ e a mesma
chamada (`joern --script curadoria_v3.sc --param cpg_file --param alvo --param dados [--param
linha]`). Antes de rodar, `congelar.py --versao v3` confere o hash dos 4 arquivos de regra; se
nao bater, nao roda. A `linha` so e passada quando o arquivo tem homonimo (motivo `hash` no
dataset_indice_v3.tsv), como nos positivos, onde a tabela de identificacao so a passou na
colisao (decisao do autor, 12/10).

O QUE E DIFERENTE, declarado:
  - o CPG e o ja guardado em ~/curadoria/completa (o mesmo de onde o dataset recortou o grafo
    desta funcao), em vez de regerado item a item. Mesmo c2cpg, mesmo arquivo;
  - o alvo (pasta do CPG e nome) vem de montar_dataset.carregar_alvos("v3"), a MESMA montagem
    que gerou o dataset v3 — a traversal olha o mesmo metodo de onde saiu o grafo;
  - se a regra recusar uma funcao `unico` por achar 2+ metodos com corpo e o mesmo nome
    (ERRO_V3_COLISAO_SEM_LINHA), roda de novo com a linha do grafo (o metodo de onde o grafo
    saiu), e o JSON registra `linha_por_trava`.

ESTE SCRIPT NAO EMITE VEREDITO. Grava so a EVIDENCIA (contagens), como o .sc. O veredito
(confirmado / descartado / indeterminado) sai do veredito.py com o regra_veredito.toml, no script
de analise, quando o teste for aberto: contar agora quantas negativas a regra confirma ja seria
ver parte do resultado da "traversal pura" no teste. Pelo pre-registro, falha da ferramenta conta
como "nao acusa".

SAIDA: traversal/saida_negativos_teste_v3/<id>.json — {"id", "nome", "pasta", "linha",
"segundos", "evidencia"} ou {"id", ..., "falha": motivo}. Idempotente com --retomar.
"""

import argparse
import csv
import json
import os
import random
import shutil
import subprocess
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import montar_dataset as md  # noqa: E402  mesma montagem de alvos do dataset v3

INDICE_V3 = os.path.join(AQUI, "dataset_indice_v3.tsv")
GRUPOS_V3 = os.path.expanduser("~/curadoria/dataset_v3/grupos")
SAIDA = os.path.join(AQUI, "saida_negativos_teste_v3")
TRABALHO = os.path.expanduser("~/curadoria/_trabalho_neg_v3")
SC = os.path.join(AQUI, "curadoria_v3.sc")
DADOS = os.path.join(AQUI, "dados")
SEMENTE_ENSAIO = 7070   # nao usada antes no projeto (42, 7, 909, 2026-2030, 101, 303, 404,
                        # 1000-1029, 5050, 6060)
T0 = time.time()


def log(*a):
    print("[%7.1fs]" % (time.time() - T0), *a, flush=True)


def conferir_congelamento():
    r = subprocess.run([sys.executable, os.path.join(AQUI, "congelar.py"), "--versao", "v3"],
                       capture_output=True, text=True, cwd=AQUI)
    if r.returncode != 0 or "ok" not in r.stdout:
        sys.exit("CONGELAMENTO V3 NAO CONFERE — nao rodo.\n" + r.stdout + r.stderr)
    log("congelamento v3 confere (4 arquivos de regra)")


def negativas_do_teste():
    """{id: motivo} das funcoes nao vulneraveis da particao de teste do dataset v3."""
    out = {}
    with open(INDICE_V3, encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if r["particao"] == "teste" and r["rotulo"] == "0":
                out[r["id"]] = r["motivo"]
    return out


def montar_fila():
    """Lista de alvos: id, nome, pasta do CPG, linha (so homonimos) e linha do grafo."""
    neg = negativas_do_teste()
    grupos = md.carregar_alvos("v3")
    fila, achados = [], set()
    for chave, info in sorted(grupos.items(), key=lambda kv: md.marca_de(kv[0])):
        meus = [a for a in info["alvos"] if a["id"] in neg]
        if not meus:
            continue
        linhas_grafo = {}
        arq = os.path.join(GRUPOS_V3, md.marca_de(chave) + ".jsonl")
        if os.path.exists(arq):
            ids = {a["id"] for a in meus}
            with open(arq, encoding="utf-8") as f:
                for linha in f:
                    g = json.loads(linha)
                    if g.get("id") in ids:
                        linhas_grafo[g["id"]] = g.get("linha_inicio")
        for a in meus:
            achados.add(a["id"])
            lg = linhas_grafo.get(a["id"])
            fila.append({"id": a["id"], "nome": a["nome"], "pasta": info["pasta"],
                         "motivo_dataset": neg[a["id"]], "linha_grafo": lg,
                         "linha": lg if neg[a["id"]] != "unico" else None})
    faltam = sorted(set(neg) - achados)
    log("fila: %d de %d negativas do teste (%d homonimas, com linha)%s"
        % (len(fila), len(neg), sum(1 for x in fila if x["linha"]),
           "" if not faltam else " — SEM ALVO: %d (%s...)" % (len(faltam), ", ".join(faltam[:5]))))
    return fila


def chamar(cpg, nome, linha, timeout):
    os.makedirs(TRABALHO, exist_ok=True)
    cmd = ["joern", "--script", SC, "--param", "cpg_file=" + cpg, "--param", "alvo=" + nome,
           "--param", "dados=" + DADOS]
    if linha:
        cmd += ["--param", "linha=" + str(linha)]
    try:
        # cwd=TRABALHO: o Joern cria workspace/ no cwd (ja sujou pasta de dataset uma vez)
        r = subprocess.run(cmd, cwd=TRABALHO, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout_joern"
    finally:
        shutil.rmtree(os.path.join(TRABALHO, "workspace"), ignore_errors=True)
    out = r.stdout or ""
    for l in out.splitlines():
        if l.startswith("EVIDENCIA_JSON "):
            return json.loads(l[len("EVIDENCIA_JSON "):]), None
    if "ERRO_V3_COLISAO_SEM_LINHA" in out:
        return None, "v3_trava_colisao_sem_linha"
    if "ERRO_V3_LINHA" in out:
        return None, "v3_linha_sem_metodo_unico"
    return None, "sem_evidencia:" + (out[-160:] + (r.stderr or "")[-160:]).replace("\n", " ")


def processar(alvo, timeout):
    t = time.time()
    cpg = os.path.join(md.CACHE_CPG, alvo["pasta"], "cpg.bin")
    res = {k: alvo[k] for k in ("id", "nome", "pasta", "motivo_dataset", "linha", "linha_grafo")}
    if not os.path.exists(cpg):
        res["falha"] = "sem_cpg"
        return res
    evid, falha = chamar(cpg, alvo["nome"], alvo["linha"], timeout)
    if falha == "v3_trava_colisao_sem_linha" and alvo["linha_grafo"]:
        res["linha_por_trava"] = alvo["linha_grafo"]
        evid, falha = chamar(cpg, alvo["nome"], alvo["linha_grafo"], timeout)
    res["segundos"] = round(time.time() - t, 1)
    if falha:
        res["falha"] = falha
    else:
        res["evidencia"] = evid
    return res


def gravar(res):
    os.makedirs(SAIDA, exist_ok=True)
    p = os.path.join(SAIDA, res["id"] + ".json")
    with open(p + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    os.replace(p + ".tmp", p)


def ja_tem(id_, retentar_timeout):
    p = os.path.join(SAIDA, id_ + ".json")
    if not os.path.exists(p):
        return False
    if retentar_timeout:
        try:
            return json.load(open(p, encoding="utf-8")).get("falha") != "timeout_joern"
        except Exception:
            return False
    return True


def resumo():
    """So contagens tecnicas: quantas tem evidencia, quantas falharam e por que. Sem veredito."""
    from collections import Counter
    neg = negativas_do_teste()
    ok, falhas, seg, trava = 0, Counter(), [], 0
    for id_ in neg:
        p = os.path.join(SAIDA, id_ + ".json")
        if not os.path.exists(p):
            continue
        r = json.load(open(p, encoding="utf-8"))
        if "evidencia" in r:
            ok += 1
        else:
            falhas[r.get("falha", "?").split(":")[0]] += 1
        if "segundos" in r:
            seg.append(r["segundos"])
        trava += "linha_por_trava" in r
    feitos = ok + sum(falhas.values())
    print("negativas do teste: %d | com saida: %d | com evidencia: %d | falha: %d | faltam: %d"
          % (len(neg), feitos, ok, sum(falhas.values()), len(neg) - feitos))
    for m, n in falhas.most_common():
        print("  falha %-32s %d" % (m, n))
    print("  refeitas com a linha do grafo (trava de colisao): %d" % trava)
    if seg:
        seg.sort()
        print("  segundos por funcao: mediana %.1f | p90 %.1f | max %.1f | soma %.1f h"
              % (seg[len(seg) // 2], seg[int(len(seg) * .9)], seg[-1], sum(seg) / 3600))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ensaio", type=int, default=0)
    ap.add_argument("--retomar", action="store_true")
    ap.add_argument("--retentar-timeout", action="store_true")
    ap.add_argument("--parar-apos", type=int, default=0, help="segundos; para antes de item novo")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--resumo", action="store_true")
    a = ap.parse_args()
    if a.resumo:
        resumo()
        return
    conferir_congelamento()
    fila = montar_fila()
    if a.ensaio:
        rnd = random.Random(SEMENTE_ENSAIO)
        homon = [x for x in fila if x["linha"]]
        resto = [x for x in fila if not x["linha"]]
        fila = rnd.sample(resto, max(0, a.ensaio - 3)) + rnd.sample(homon, min(3, len(homon)))
    pend = [x for x in fila if not ((a.retomar or a.retentar_timeout or a.ensaio)
                                    and ja_tem(x["id"], a.retentar_timeout))]
    log("a processar: %d" % len(pend))
    for i, alvo in enumerate(pend, 1):
        if a.parar_apos and time.time() - T0 > a.parar_apos:
            log("PARADA PROGRAMADA antes do item %d/%d" % (i, len(pend)))
            break
        res = processar(alvo, a.timeout)
        gravar(res)
        log("[%d/%d] %s %s (%.1fs)" % (i, len(pend), alvo["id"],
                                       "ok" if "evidencia" in res else "FALHOU " + res["falha"][:80],
                                       res.get("segundos", 0)))
    else:
        log("FILA TERMINADA")


if __name__ == "__main__":
    main()
