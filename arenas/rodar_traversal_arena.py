#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Traversal v3 CONGELADA como detector nas arenas externas (a linha "traversal pura", Decisao K).

    python3 rodar_traversal_arena.py --arena sonda --ensaio 20
    python3 rodar_traversal_arena.py --arena todas --retomar          # sonda, VentiVul familia, PrimeVul
    python3 rodar_traversal_arena.py --arena todas --retentar-timeout  # passada final: so os timeouts
    python3 rodar_traversal_arena.py --arena todas --resumo           # contagem tecnica, sem veredito
    python3 rodar_traversal_arena.py --arena todas --retomar --fatia 0/2   # e, em outra janela, 1/2

ONDE ESTAMOS. PREREGISTRO_ARENAS.md (congelado em 15/10/2026), Decisao K e §10 passo 4: a regra
congelada da traversal v3 roda nas tres arenas, no conjunto que tem veredito em cada uma (sonda,
VentiVul familia de memoria, PrimeVul), ANTES de qualquer modelo prever qualquer funcao de arena.
"Pelo mesmo executador da rodada nas negativas do BigVul (rodar_traversal_negativos.py, adaptado so
no caminho dos arquivos), no mesmo metodo de onde sai o grafo."

O QUE E IMPORTADO DO EXECUTADOR DO BIGVUL (traversal/rodar_traversal_negativos.py): a conferencia
do congelamento (congelar.py --versao v3: hash dos 4 arquivos de regra; se nao bater, nao roda) e a
chamada ao Joern (`joern --script curadoria_v3.sc --param cpg_file --param alvo --param dados
[--param linha]`, com os mesmos dados/ e a mesma leitura da evidencia).

O QUE MUDA, so o caminho dos arquivos:
  - o CPG e o da pasta do grupo da arena (o mesmo cpg.bin de onde o grafo desta funcao saiu),
    e nao ~/curadoria/completa;
  - a fila vem dos grafos exportados da arena (montar_<arena>.grupos_de + grafos/<marca>.jsonl):
    id, nome, pasta e a linha de inicio do metodo do grafo. A `linha` so e passada quando a
    localizacao foi por hash (homonimo), como nas negativas do BigVul; se a regra recusar por achar
    2+ metodos com o mesmo nome (ERRO_V3_COLISAO_SEM_LINHA), roda de novo com a linha do grafo e o
    JSON registra `linha_por_trava` — igual ao executador do BigVul.

ESTE SCRIPT NAO EMITE VEREDITO. Grava so a evidencia; o veredito (confirmado / descartado /
indeterminado) sai do veredito.py no script de analise, na abertura. Falha da ferramenta conta como
"nao acusa" (PREREGISTRO_PRINCIPAL.md §7).

SAIDA: ~/curadoria/arenas/<pasta>/traversal/<id>.json (sonda, primevul; o VentiVul familia em
ventivul/traversal_familia/). Idempotente com --retomar.

FATIAS (desvio de execucao, decisao do autor em 16/10/2026; PREPARACAO_ARENAS.md): com --fatia k/n,
esta copia so processa as funcoes cujo id cai na fatia k (sha1 do id, modulo n), e o Joern roda numa
pasta de trabalho propria — o chamar() apaga workspace/ ao fim de cada funcao, e duas copias na
mesma pasta apagariam o trabalho uma da outra. A chamada, a regra e a evidencia nao mudam; cada
funcao continua julgada sozinha, numa chamada propria do Joern.
"""
import argparse
import csv
import hashlib
import json
import os
import random
import sys
import time
from collections import Counter

AQUI = os.path.dirname(os.path.abspath(__file__))
BV = os.path.dirname(AQUI)
sys.path.insert(0, AQUI)
sys.path.insert(0, os.path.join(BV, "traversal"))
import montar_dataset as md  # noqa: E402
import rodar_traversal_negativos as rtn  # noqa: E402  o executador da rodada nas negativas do BigVul

ARENAS = ("sonda", "ventivul_familia", "primevul")
SEMENTE_ENSAIO = 8080   # nao usada antes no projeto (ver a lista em rodar_traversal_negativos.py; 7070)
T0 = time.time()


def log(*a):
    print("[%7.1fs]" % (time.time() - T0), *a, flush=True)


def saida_de(arena):
    sub = {"sonda": "sonda/traversal", "ventivul_familia": "ventivul/traversal_familia",
           "primevul": "primevul/traversal"}[arena]
    return os.path.expanduser(f"~/curadoria/arenas/{sub}")


def grupos_e_grafos(arena):
    if arena == "sonda":
        import montar_sonda as m
        grupos, _ = m.grupos_de(m.ler_funcoes())
        return grupos, m.GRAFOS, None
    if arena == "ventivul_familia":
        import montar_ventivul as m
        df, fica = m.carregar()
        grupos, _ = m.grupos_de(df, fica)
        so = {r["id"] for r in csv.DictReader(open(os.path.join(AQUI, "indice_ventivul_familia.tsv"),
                                                   encoding="utf-8"), delimiter="\t") if not r["motivo"]}
        return grupos, m.GRAFOS, so
    import montar_primevul as m
    grupos, _, _ = m.grupos_de()
    return grupos, m.GRAFOS, None


def montar_fila(arena):
    grupos, grafos, so = grupos_e_grafos(arena)
    fila = []
    for chave, info in sorted(grupos.items(), key=lambda kv: md.marca_de(kv[0])):
        arq = os.path.join(grafos, md.marca_de(chave) + ".jsonl")
        if not os.path.exists(arq):
            continue
        for l in open(arq, encoding="utf-8"):
            g = json.loads(l)
            if so is not None and g["id"] not in so:
                continue
            homonimo = g["motivo"] != "unico"
            fila.append({"id": g["id"], "nome": g["nome"], "pasta": info["pasta"], "motivo_dataset": g["motivo"],
                         "linha_grafo": g["linha_inicio"], "linha": g["linha_inicio"] if homonimo else None})
    log(f"[{arena}] fila: {len(fila)} funcoes com grafo ({sum(1 for x in fila if x['linha'])} homonimas, com linha)")
    return fila


def processar(alvo, timeout):
    """O processar() do rodar_traversal_negativos.py, com o CPG da pasta do grupo da arena."""
    t = time.time()
    cpg = os.path.join(alvo["pasta"], "cpg.bin")
    res = {k: alvo[k] for k in ("id", "nome", "pasta", "motivo_dataset", "linha", "linha_grafo")}
    if not os.path.exists(cpg):
        res["falha"] = "sem_cpg"
        return res
    evid, falha = rtn.chamar(cpg, alvo["nome"], alvo["linha"], timeout)
    if falha == "v3_trava_colisao_sem_linha" and alvo["linha_grafo"]:
        res["linha_por_trava"] = alvo["linha_grafo"]
        evid, falha = rtn.chamar(cpg, alvo["nome"], alvo["linha_grafo"], timeout)
    res["segundos"] = round(time.time() - t, 1)
    if falha:
        res["falha"] = falha
    else:
        res["evidencia"] = evid
    return res


def gravar(saida, res):
    os.makedirs(saida, exist_ok=True)
    p = os.path.join(saida, res["id"] + ".json")
    with open(p + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    os.replace(p + ".tmp", p)


def na_fatia(id_, fatia):
    """fatia = (k, n). Divisao fixa pelo id: nao depende da ordem da fila nem do que ja foi feito."""
    if fatia is None:
        return True
    k, n = fatia
    return int(hashlib.sha1(id_.encode("utf-8")).hexdigest(), 16) % n == k


def ler_fatia(s):
    k, n = (int(x) for x in s.split("/"))
    if not (n >= 1 and 0 <= k < n):
        raise argparse.ArgumentTypeError("use k/n com 0 <= k < n")
    return k, n


def ja_tem(saida, id_, retentar_timeout):
    p = os.path.join(saida, id_ + ".json")
    if not os.path.exists(p):
        return False
    if retentar_timeout:
        try:
            return json.load(open(p, encoding="utf-8")).get("falha") != "timeout_joern"
        except Exception:
            return False
    return True


def resumo(arena):
    """So contagens tecnicas (com evidencia / falha e motivo / tempo). Sem veredito."""
    saida = saida_de(arena)
    ids = [x["id"] for x in montar_fila(arena)]
    ok, falhas, seg, trava = 0, Counter(), [], 0
    for i in ids:
        p = os.path.join(saida, i + ".json")
        if not os.path.exists(p):
            continue
        r = json.load(open(p, encoding="utf-8"))
        ok += "evidencia" in r
        if "evidencia" not in r:
            falhas[r.get("falha", "?").split(":")[0]] += 1
        if "segundos" in r:
            seg.append(r["segundos"])
        trava += "linha_por_trava" in r
    feitos = ok + sum(falhas.values())
    log(f"[{arena}] funcoes: {len(ids)} | com saida: {feitos} | com evidencia: {ok} | falha: {sum(falhas.values())} "
        f"| faltam: {len(ids) - feitos} | refeitas com a linha do grafo: {trava}")
    for m, n in falhas.most_common():
        log(f"    falha {m:32s} {n}")
    if seg:
        seg.sort()
        log(f"    segundos por funcao: mediana {seg[len(seg) // 2]:.1f} | p90 {seg[int(len(seg) * .9)]:.1f} "
            f"| max {seg[-1]:.1f} | soma {sum(seg) / 3600:.1f} h")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arena", choices=ARENAS + ("todas",), required=True)
    ap.add_argument("--ensaio", type=int, default=0)
    ap.add_argument("--retomar", action="store_true")
    ap.add_argument("--retentar-timeout", action="store_true")
    ap.add_argument("--parar-apos", type=int, default=0, help="segundos; para antes de item novo")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--resumo", action="store_true")
    ap.add_argument("--fatia", type=ler_fatia, default=None, help="k/n: so a fatia k de n (ver FATIAS)")
    a = ap.parse_args()
    arenas = ARENAS if a.arena == "todas" else (a.arena,)
    if a.resumo:
        for ar in arenas:
            resumo(ar)
        return
    rtn.conferir_congelamento()
    rtn.TRABALHO = os.path.expanduser("~/curadoria/_trabalho_trav_arenas"
                                      + ("" if a.fatia is None else "_f%d" % a.fatia[0]))
    if a.fatia:
        log(f"fatia {a.fatia[0]}/{a.fatia[1]}; pasta de trabalho do Joern: {rtn.TRABALHO}")
    for ar in arenas:
        saida = saida_de(ar)
        fila = montar_fila(ar)
        if a.ensaio:
            rnd = random.Random(SEMENTE_ENSAIO)
            homon = [x for x in fila if x["linha"]]
            resto = [x for x in fila if not x["linha"]]
            fila = rnd.sample(resto, max(0, a.ensaio - 3)) + rnd.sample(homon, min(3, len(homon)))
        pend = [x for x in fila if na_fatia(x["id"], a.fatia)
                and not ((a.retomar or a.retentar_timeout or a.ensaio)
                         and ja_tem(saida, x["id"], a.retentar_timeout))]
        log(f"[{ar}] a processar: {len(pend)}")
        for i, alvo in enumerate(pend, 1):
            if a.parar_apos and time.time() - T0 > a.parar_apos:
                log(f"PARADA PROGRAMADA antes do item {i}/{len(pend)}")
                return
            res = processar(alvo, a.timeout)
            gravar(saida, res)
            if i % 50 == 0 or i == len(pend) or a.ensaio:
                log(f"[{ar}] [{i}/{len(pend)}] {alvo['id']} "
                    f"{'ok' if 'evidencia' in res else 'FALHOU ' + res['falha'][:80]} ({res.get('segundos', 0)}s)")
        log(f"[{ar}] FILA TERMINADA")


if __name__ == "__main__":
    main()
