#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monta o dataset de grafos: um grafo por funcao, positivos e negativos.

O QUE ESTA ETAPA E, situando
----------------------------
Ultimo passo antes de treinar. Ate aqui havia CPG POR ARQUIVO (~/curadoria/completa) e listas
de quais funcoes entram (split/, conjuntos_treino/). O ReVeal consome UM GRAFO POR FUNCAO.
Este script recorta cada funcao de dentro do CPG do arquivo dela e grava o grafo.

O RECORTE e o do RECORTE_SUBGRAFO.md, implementado no exportar_grafos.sc: subgrafo induzido
por `method.ast`, sem seguir `CALL`, tipo como atributo de no. O vazamento de rotulo e
impossivel por construcao — nenhum no de outra funcao entra no grafo.

A LOCALIZACAO e a do LOCALIZACAO.md, criterio ALTERNATIVO (decidido 21/09/2026): se o arquivo
tem UM UNICO metodo com aquele nome e com corpo, ele e a funcao — nao ha homonimo para
desempatar. Onde HA homonimo, o hash do corpo continua sendo obrigatorio.

UMA EXECUCAO DE JOERN POR ARQUIVO, nao por funcao. Abrir o CPG custa ~7-12 s e serve todas as
funcoes daquele arquivo, positivas e negativas juntas. Sao ~1500 arquivos, entao 3-5 h.

IDEMPOTENTE: --retomar pula grupo que ja tem saida. Roda em PRIMEIRO PLANO de proposito — o
setsid nohup nao sobrevive entre invocacoes do tool (a VM do WSL desliga junto).

ONDE A SAIDA VAI, e por que nao no repositorio: `~/curadoria/dataset/`. Sao ~26 mil grafos,
centenas de MB. O repositorio fica com o INDICE e as estatisticas, que e o que se le para
escrever o artigo. Mesma divisao que `~/curadoria/completa` ja usa.

O QUE ELE NAO FAZ: nao extrai feature, nao tokeniza, nao treina. Grava o grafo cru com o codigo
de cada no; a vetorizacao e passo separado, que muda sem precisar reabrir CPG nenhum.

Uso:
  python3 montar_dataset.py --n 5 --retomar        # teste
  python3 montar_dataset.py --retomar              # tudo
  python3 montar_dataset.py --indice               # so reconstroi o indice do que ja existe
"""

import argparse
import csv
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from normalizar_corpo import hashes_do_texto, recortar_linhas  # noqa: E402  mesmo modulo dos dois lados

SC = os.path.join(AQUI, "exportar_grafos.sc")
CACHE_CPG = os.path.expanduser("~/curadoria/completa")
DESTINO = os.path.expanduser("~/curadoria/dataset")
GRUPOS = os.path.join(DESTINO, "grupos")
TRABALHO = os.path.expanduser("~/curadoria/_trabalho_ds")

VEREDITOS = os.path.join(AQUI, "saida_completa")
POSITIVOS = os.path.join(AQUI, "split", "positivos.tsv")
NEGATIVOS = os.path.join(AQUI, "split", "negativos.tsv")
NOMES = os.path.join(AQUI, "split", "negativos_nomes.tsv")
HASH_SC = os.path.join(AQUI, "split", "negativos_hash_sc.tsv")
RELATORIO = os.path.join(AQUI, "..", "saida_final", "relatorio_extracao.csv")
INDICE = os.path.join(AQUI, "dataset_indice.tsv")

# Remontagem da traversal v3 (05/10/2026, TRAVERSAL_V3.md, Fase 5). Com --versao v3:
#  - positivos que a tabela de identificacao EXCLUI nao viram alvo;
#  - positivos com colisao levam a `linha` escolhida pela tabela — o grafo sai do MESMO metodo
#    que a traversal v3 avaliou;
#  - todo positivo leva os dois hashes do corpo (split/positivos_hash.tsv), como os negativos;
#  - grupos que juntavam arquivos diferentes com o mesmo nome-base sao separados (P6);
#  - a saida vai para pasta e indice NOVOS: o dataset da v2 fica intacto, como registro.
IDENTIFICACAO = os.path.join(AQUI, "identificacao_v3.tsv")
POS_HASH = os.path.join(AQUI, "split", "positivos_hash.tsv")
DESTINOS = {
    "v2": (os.path.expanduser("~/curadoria/dataset"), os.path.join(AQUI, "dataset_indice.tsv")),
    "v3": (os.path.expanduser("~/curadoria/dataset_v3"),
           os.path.join(AQUI, "dataset_indice_v3.tsv")),
}

RE_ESPACO = re.compile(r"\s+")

# O `file_name` do BigVul vem do pandas e um NaN chega aqui como a STRING "nan", que passa em
# qualquer teste de "tem valor". Em 21/09/2026 isso fundiu 127 itens positivos em 34 grupos com
# chave (commit, "nan") — e um grupo usa UM cpg.bin, entao itens seriam procurados no CPG do
# arquivo errado. Se houvesse homonimo la, sairia o grafo errado com o rotulo certo.
RUIM = {"", "nan", "NaN", "None", "null", "NULL"}

# Folga em linhas ao conferir se um no pertence a funcao. O no METHOD as vezes e marcado na
# linha do tipo de retorno em vez da assinatura; nos sinteticos vem com linha -1 e sao ignorados.
FOLGA_LINHA = 3


def fora_da_funcao(g):
    """Quantos nos caem FORA da faixa de linhas do metodo.

    O RECORTE_SUBGRAFO.md afirma que o vazamento de rotulo e impossivel por construcao, porque
    o conjunto de nos e `method.ast`. Medido no dataset inteiro, isso e verdade em 3.677.026 de
    3.677.027 nos — e falha em 1. O caso: funcao definida por macro (`PHP_FUNCTION`), onde o
    Joern gera metodos homonimos e a fronteira entre eles sai borrada; um no da funcao ANTERIOR
    entrou na AST da seguinte.

    Entao a afirmacao NAO e mantida por confianca: vira FILTRO. Grafo com no fora da faixa e
    descartado, porque nao da para garantir que o no e da propria funcao.

    A regra e ESTRUTURAL e se aplica igual a todo mundo — nao menciona projeto, CVE nem nome de
    funcao. E descartar e omissao, que pela regra do projeto e de graca.
    """
    ini, fim = g.get("linha_inicio", -1), g.get("linha_fim", -1)
    if not ini or ini < 1 or not fim or fim < ini:
        return 0
    n = 0
    for no in g.get("nos", []):
        ln = no.get("linha", -1)
        if ln is None or ln < 0:
            continue
        if ln < ini - FOLGA_LINHA or ln > fim + FOLGA_LINHA:
            n += 1
    return n


def log(*a):
    print(*a, flush=True)


def basename(caminho):
    s = (caminho or "").strip().replace("\\", "/")
    return s.rsplit("/", 1)[-1] if s else ""


def arquivo_real(pasta):
    """O nome do arquivo que de fato gerou este CPG, lido do DISCO e nao do BigVul.

    Cada pasta de item tem exatamente um `arquivo__<nome>`, que e a fonte que o Joern comeu.
    Conferido em 21/09/2026 contra o `file_name` do relatorio: 2686 concordam, **0 divergem**,
    e o disco ainda resolve 225 casos em que o relatorio traz "nan". Entao o disco e
    estritamente melhor e nao ha razao para consultar o relatorio para isto.
    """
    fontes = [p for p in glob.glob(os.path.join(CACHE_CPG, pasta, "arquivo__*"))
              if os.path.isfile(p)]
    if not fontes:
        return ""
    return os.path.basename(fontes[0])[len("arquivo__"):]


def marca_de(chave):
    m = "%s__%s" % (chave[0][:12], chave[1])
    if len(chave) > 2:
        # grupo separado pelo caminho completo (P6): o nome-base sozinho nao e unico no commit
        m += "__" + hashlib.sha1(chave[2].encode("utf-8")).hexdigest()[:8]
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in m)


def separar_por_caminho(grupos, onde, caminho_de_pasta, caminho_neg):
    """P6 (HANDOFF 8.3): a chave (commit, NOME-BASE) junta arquivos diferentes de mesmo nome no
    mesmo commit — e um grupo usa UM cpg.bin, o da sua `pasta`. Em 22/09 isso pos 60 alvos no CPG
    de outro arquivo (42 viraram grafo do arquivo errado).

    Conserto minimo: dentro de cada grupo, o alvo cujo caminho completo e CONHECIDO e DIFERENTE do
    da `pasta` sai para um grupo proprio, (commit, nome-base, caminho), cuja pasta e um item
    positivo daquele caminho. Se nenhum positivo tem aquele caminho, nao ha CPG daquele arquivo e
    o alvo sai (omissao). Grupo sem mistura nao muda — nem a marca, nem o conteudo.
    """
    pasta_por_caminho = {}
    for pasta in sorted(onde):
        cam = caminho_de_pasta.get(pasta)
        if cam:
            pasta_por_caminho.setdefault((onde[pasta][0], cam), pasta)
    separados, sem_cpg = 0, 0
    for chave in list(grupos):
        info = grupos[chave]
        cam_pasta = caminho_de_pasta.get(info["pasta"])
        if not cam_pasta:
            continue
        ficam, saem = [], defaultdict(list)
        for a in info["alvos"]:
            cam = caminho_de_pasta.get(a["id"]) if a["rotulo"] == 1 else caminho_neg.get(a["id"])
            if not cam or cam == cam_pasta:
                ficam.append(a)
            else:
                saem[cam].append(a)
        if not saem:
            continue
        info["alvos"] = ficam
        for cam, alvos in saem.items():
            pasta = pasta_por_caminho.get((chave[0], cam))
            if pasta is None:
                sem_cpg += len(alvos)
                continue
            nova = (chave[0], chave[1], cam)
            grupos[nova]["pasta"] = grupos[nova]["pasta"] or pasta
            grupos[nova]["alvos"].extend(alvos)
            separados += len(alvos)
    log("P6 — alvos movidos para o grupo do proprio arquivo: %d | sem CPG do proprio arquivo "
        "(saem): %d" % (separados, sem_cpg))


# ------------------------------------------------------------------ montar a lista de alvos

def carregar_alvos(versao="v2"):
    """{(commit, arquivo): {"pasta": ..., "alvos": [...]}} com positivos E negativos juntos.

    Com versao="v3", as regras da remontagem v3 (ver IDENTIFICACAO, acima)."""
    v3 = versao == "v3"
    ident, hashes_pos = {}, {}
    if v3:
        for r in csv.DictReader(open(IDENTIFICACAO, encoding="utf-8"), delimiter="\t"):
            ident[r["item"]] = r
        for r in csv.DictReader(open(POS_HASH, encoding="utf-8"), delimiter="\t"):
            hashes_pos[r["item"]] = [h for h in (r["sha1_corpo"], r["sha1_corpo_sc"]) if h]
    com_cpg = {}
    for d in sorted(os.listdir(CACHE_CPG)):
        if os.path.exists(os.path.join(CACHE_CPG, d, "cpg.bin")):
            com_cpg[d.split("__", 1)[0]] = d

    # pasta do item -> (commit, arquivo). O arquivo vem do DISCO (ver arquivo_real);
    # so o commit vem do relatorio.
    onde, caminho_de_pasta = {}, {}
    for r in csv.DictReader(open(RELATORIO, encoding="utf-8")):
        id_rel = (r.get("id") or "").strip()
        pasta = com_cpg.get(id_rel.zfill(4)) or com_cpg.get(id_rel)
        if not pasta:
            continue
        arq = arquivo_real(pasta)
        if not arq or arq in RUIM:
            continue
        commit = (r.get("commit_id") or "").strip()
        if not commit or commit in RUIM:
            continue
        onde[pasta] = (commit, arq)
        cam = (r.get("caminho_no_repo") or r.get("file_name") or "").strip()
        if cam and cam not in RUIM:
            caminho_de_pasta[pasta] = cam

    grupos = defaultdict(lambda: {"pasta": None, "alvos": []})

    # --- positivos: nome vem do campo `alvo` do JSON de evidencia (e o NOME, nao o veredito)
    part_pos = {}
    for r in csv.DictReader(open(POSITIVOS, encoding="utf-8"), delimiter="\t"):
        part_pos[r["item"]] = r
    n_pos = n_excl = 0
    for p in sorted(glob.glob(os.path.join(VEREDITOS, "*.json"))):
        item = os.path.basename(p)[:-5]
        if item not in onde or item not in part_pos:
            continue
        try:
            alvo = json.load(open(p, encoding="utf-8")).get("alvo")
        except Exception:
            continue
        if not alvo:
            continue
        linha = None
        if v3:
            r_id = ident.get(item)
            if r_id is None or r_id["acao"] == "excluir":
                n_excl += 1
                continue                    # a traversal v3 nao avalia; o grafo tambem nao entra
            if r_id["acao"] == "avaliar_na_linha":
                linha = int(r_id["linha"])
        chave = onde[item]
        meta = part_pos[item]
        grupos[chave]["pasta"] = grupos[chave]["pasta"] or item
        grupos[chave]["alvos"].append({
            "id": item, "rotulo": 1, "nome": alvo, "particao": meta["particao"],
            "projeto": meta.get("projeto", ""), "cwe": meta.get("cwe", ""),
            "commit": chave[0], "arquivo": chave[1],
            "shas": hashes_pos.get(item, []) if v3 else [],
            "linha": linha,
        })
        n_pos += 1

    # --- negativos: nome e hashes ja extraidos (NEGATIVOS.md e extrair_hash_sem_comentario.py)
    nomes, hsc = {}, {}
    for r in csv.DictReader(open(NOMES, encoding="utf-8"), delimiter="\t"):
        nomes[int(r["linha_indice"])] = (r["nome"], r.get("sha1_corpo", ""))
    if os.path.exists(HASH_SC):
        for r in csv.DictReader(open(HASH_SC, encoding="utf-8"), delimiter="\t"):
            hsc[int(r["linha_indice"])] = r.get("sha1_corpo_sc", "")

    por_chave_pasta = {v: k for k, v in onde.items()}   # (commit, arquivo) -> pasta
    n_neg = 0
    caminho_neg = {}
    for r in csv.DictReader(open(NEGATIVOS, encoding="utf-8"), delimiter="\t"):
        i = int(r["linha_indice"])
        nome, sha = nomes.get(i, ("", ""))
        arq = basename(r.get("arquivo", ""))
        if not nome or nome in RUIM or not arq or arq in RUIM:
            continue
        chave = ((r.get("commit") or "").strip(), arq)
        if chave not in por_chave_pasta:
            continue
        grupos[chave]["pasta"] = grupos[chave]["pasta"] or por_chave_pasta[chave]
        grupos[chave]["alvos"].append({
            "id": "neg_%d" % i, "rotulo": 0, "nome": nome, "particao": r["particao"],
            "projeto": r.get("projeto", ""), "cwe": r.get("cwe", ""),
            "commit": chave[0], "arquivo": arq,
            "shas": [h for h in (sha, hsc.get(i, "")) if h],
        })
        caminho_neg["neg_%d" % i] = (r.get("arquivo") or "").strip()
        n_neg += 1

    if v3:
        log("positivos excluidos pela tabela de identificacao (sem grafo): %d" % n_excl)
        separar_por_caminho(grupos, onde, caminho_de_pasta, caminho_neg)
        for chave in [k for k, v in grupos.items() if not v["alvos"]]:
            del grupos[chave]

    log("alvos montados: %d positivos + %d negativos em %d arquivos"
        % (n_pos, n_neg, len(grupos)))
    return grupos


# ------------------------------------------------------------------ desempate por corpo

def hashes_do_metodo(pasta, ini, fim):
    """Hashes do corpo recortado do arquivo-fonte. Mesma logica do _medir_localizacao.py:
    o m.code do Joern vem truncado em 1000 chars, entao o corpo sai do arquivo.

    05/10/2026: o recorte e o calculo vem de normalizar_corpo (recortar_linhas e
    hashes_do_texto), os mesmos usados no lado do BigVul. Ate esta data o recorte usava
    splitlines(), que desloca as linhas em arquivo com form feed (TRAVERSAL_V3.md, Fase 1)."""
    if ini < 1 or fim < ini:
        return set()
    fontes = [p for p in glob.glob(os.path.join(pasta, "arquivo__*")) if os.path.isfile(p)]
    if not fontes:
        return set()
    out = set()
    for codec in ("utf-8", "latin-1"):
        try:
            texto = open(fontes[0], encoding=codec, errors="replace").read()
        except Exception:
            continue
        out |= hashes_do_texto(recortar_linhas(texto, ini, fim))
    return out


def escolher(alvo, cands, pasta):
    """Qual metodo e a funcao. Devolve (metodo_id ou None, motivo).

    CRITERIO ALTERNATIVO (LOCALIZACAO.md, 21/09): um unico candidato => e ele, sem hash.
    Havendo mais de um, so o hash do corpo decide — nunca semelhanca, nunca a primeira.
    """
    if not cands:
        return None, "sem_metodo"
    if alvo.get("linha"):
        # v3: a tabela de identificacao ja escolheu (por hash) o metodo que a traversal avaliou;
        # o grafo sai do MESMO metodo. Nada de reescolher aqui.
        naquela = [c for c in cands if c["linha_inicio"] == alvo["linha"]]
        if len(naquela) == 1:
            return naquela[0]["metodo_id"], "linha_v3"
        return None, "linha_v3_sem_candidato_unico"
    if len(cands) == 1:
        return cands[0]["metodo_id"], "unico"
    if alvo["shas"]:
        batem = [c for c in cands
                 if set(alvo["shas"]) & hashes_do_metodo(pasta, c["linha_inicio"],
                                                         c["linha_fim"])]
        if len(batem) == 1:
            return batem[0]["metodo_id"], "hash"
        if len(batem) > 1:
            return batem[0]["metodo_id"], "hash_empate"
    return None, "ambiguo"


# ------------------------------------------------------------------ execucao

def rodar_joern(cpg, lista, saida, timeout):
    cmd = ["joern", "--script", SC, "--param", "cpg_file=" + cpg,
           "--param", "alvos=" + lista, "--param", "saida=" + saida]
    try:
        r = subprocess.run(cmd, cwd=TRABALHO, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    txt = (r.stdout or "") + "\n" + (r.stderr or "")
    if "FIM" not in txt:
        return None, "sem_saida"
    cands = defaultdict(list)
    for linha in txt.splitlines():
        if linha.startswith("CAND\t"):
            c = linha.split("\t")
            if len(c) >= 7:
                cands[c[1]].append({"metodo_id": int(c[2]), "linha_inicio": int(c[3]),
                                    "linha_fim": int(c[4]), "n_nos": int(c[5]),
                                    "n_arestas": int(c[6])})
    return cands, None


def processar(chave, info, timeout):
    pasta = os.path.join(CACHE_CPG, info["pasta"])
    cpg = os.path.join(pasta, "cpg.bin")
    if not os.path.exists(cpg):
        return None, "sem_cpg"

    tmp = os.path.join(TRABALHO, "saida")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)

    lista = os.path.join(TRABALHO, "alvos.txt")
    with open(lista, "w", encoding="utf-8") as fh:
        for n in sorted({a["nome"] for a in info["alvos"]}):
            fh.write(n + "\n")

    cands, erro = rodar_joern(cpg, lista, tmp, timeout)
    shutil.rmtree(os.path.join(TRABALHO, "workspace"), ignore_errors=True)
    if erro:
        return None, erro

    # Motivo POR ALVO, alem da contagem. Em 22/09 so a contagem por arquivo foi gravada, e foi
    # isso que obrigou a reconstruir o motivo de cada perda em 03/10 (PERDA_BRACOS.md).
    linhas, motivos, por_alvo = [], Counter(), {}
    for alvo in info["alvos"]:
        mid, motivo = escolher(alvo, cands.get(alvo["nome"], []), pasta)
        motivos[motivo] += 1
        por_alvo[alvo["id"]] = motivo
        if mid is None:
            continue
        cam = os.path.join(tmp, "m%d.json" % mid)
        if not os.path.exists(cam):
            motivos["json_ausente"] += 1
            por_alvo[alvo["id"]] = "json_ausente"
            continue
        try:
            g = json.load(open(cam, encoding="utf-8"))
        except Exception:
            motivos["json_ilegivel"] += 1
            por_alvo[alvo["id"]] = "json_ilegivel"
            continue
        if fora_da_funcao(g):
            motivos["no_fora_da_funcao"] += 1
            por_alvo[alvo["id"]] = "no_fora_da_funcao"
            continue
        linhas.append({
            "id": alvo["id"], "rotulo": alvo["rotulo"], "particao": alvo["particao"],
            "projeto": alvo["projeto"], "cwe": alvo["cwe"], "commit": alvo["commit"],
            "arquivo": alvo["arquivo"], "nome": alvo["nome"], "motivo": motivo,
            "linha_inicio": g["linha_inicio"], "linha_fim": g["linha_fim"],
            "n_nos": g["n_nos"], "n_arestas": g["n_arestas"],
            "nos": g["nos"], "arestas": g["arestas"],
        })

    shutil.rmtree(tmp, ignore_errors=True)
    return (linhas, motivos, por_alvo), None


def assinatura(info):
    """Impressao do PEDIDO de um grupo: quais alvos, com que nome, hash e linha. Se qualquer
    coisa disso mudar entre execucoes, a saida gravada do grupo deixa de valer."""
    partes = sorted("%s|%s|%s|%s" % (a["id"], a["nome"], ",".join(sorted(a.get("shas") or [])),
                                     a.get("linha") or "") for a in info["alvos"])
    partes.append("pasta=" + str(info["pasta"]))
    return hashlib.sha1("\n".join(partes).encode("utf-8")).hexdigest()


def gravar_grupo(marca, linhas, motivos, pedidos, por_alvo=None, assin=None):
    with open(os.path.join(GRUPOS, marca + ".jsonl"), "w", encoding="utf-8") as fh:
        for r in linhas:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    meta = {"pedidos": pedidos, "exportados": len(linhas), "motivos": dict(motivos)}
    if por_alvo is not None:
        meta["por_alvo"] = por_alvo
    if assin is not None:
        meta["assinatura"] = assin
    with open(os.path.join(GRUPOS, marca + ".meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)


def refiltrar():
    """Aplica `fora_da_funcao` ao que ja foi exportado, sem reabrir CPG nenhum.

    Existe porque o filtro nasceu DEPOIS da primeira montagem completa. Refazer as 1501
    execucoes de Joern custaria ~2,7 h para chegar exatamente ao mesmo resultado: o criterio
    so olha o JSON ja gravado. Idempotente — rodar de novo nao muda mais nada.
    """
    removidos = 0
    tocados = 0
    for p in sorted(glob.glob(os.path.join(GRUPOS, "*.jsonl"))):
        mantidas, fora = [], 0
        for linha in open(p, encoding="utf-8"):
            if not linha.strip():
                continue
            r = json.loads(linha)
            if fora_da_funcao(r):
                fora += 1
                continue
            mantidas.append(r)
        if not fora:
            continue
        with open(p, "w", encoding="utf-8") as fh:
            for r in mantidas:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        meta = p[:-len(".jsonl")] + ".meta.json"
        if os.path.exists(meta):
            d = json.load(open(meta, encoding="utf-8"))
            d["exportados"] = len(mantidas)
            d.setdefault("motivos", {})["no_fora_da_funcao"] = \
                d.get("motivos", {}).get("no_fora_da_funcao", 0) + fora
            json.dump(d, open(meta, "w", encoding="utf-8"), indent=2)
        removidos += fora
        tocados += 1
    log("refiltragem: %d exemplo(s) removido(s) em %d grupo(s)" % (removidos, tocados))
    return removidos


def construir_indice():
    cols = ["id", "rotulo", "particao", "projeto", "cwe", "commit", "arquivo", "nome",
            "motivo", "n_nos", "n_arestas"]
    n = 0
    porpart = defaultdict(Counter)
    tamanhos = []
    with open(INDICE, "w", encoding="utf-8", newline="") as fh:
        fh.write("\t".join(cols) + "\n")
        for p in sorted(glob.glob(os.path.join(GRUPOS, "*.jsonl"))):
            for linha in open(p, encoding="utf-8"):
                if not linha.strip():
                    continue
                r = json.loads(linha)
                fh.write("\t".join(str(r.get(c, "")) for c in cols) + "\n")
                porpart[r["particao"]][r["rotulo"]] += 1
                tamanhos.append(r["n_nos"])
                n += 1
    log()
    log("=" * 72)
    log("INDICE: %d exemplos -> %s" % (n, INDICE))
    log("=" * 72)
    log("  %-12s %10s %10s %10s" % ("particao", "positivos", "negativos", "total"))
    for part in ("treino", "validacao", "teste"):
        c = porpart[part]
        log("  %-12s %10d %10d %10d" % (part, c[1], c[0], c[1] + c[0]))
    if tamanhos:
        t = sorted(tamanhos)
        log()
        log("  nos por grafo: min %d, mediana %d, p95 %d, max %d"
            % (t[0], t[len(t) // 2], t[int(len(t) * 0.95)], t[-1]))
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=0, help="so os N primeiros grupos (0 = todos)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--retomar", action="store_true")
    ap.add_argument("--indice", action="store_true", help="so reconstroi o indice")
    ap.add_argument("--refiltrar", action="store_true",
                    help="aplica o filtro de invariante ao que ja existe, sem rodar Joern")
    ap.add_argument("--versao", default="v2", choices=sorted(DESTINOS),
                    help="v3 = remontagem da traversal v3 (pasta e indice proprios)")
    ap.add_argument("--destino", default="",
                    help="pasta de saida alternativa (teste); o indice vai para dentro dela")
    ap.add_argument("--so", default="",
                    help="teste: so os grupos cuja marca contem um destes trechos (virgula)")
    args = ap.parse_args()

    global DESTINO, GRUPOS, INDICE
    DESTINO, INDICE = DESTINOS[args.versao]
    if args.destino:
        DESTINO = os.path.expanduser(args.destino)
        INDICE = os.path.join(DESTINO, "dataset_indice.tsv")
    GRUPOS = os.path.join(DESTINO, "grupos")
    log("versao %s | saida %s | indice %s" % (args.versao, DESTINO, INDICE))

    os.makedirs(GRUPOS, exist_ok=True)
    os.makedirs(TRABALHO, exist_ok=True)

    if args.refiltrar:
        refiltrar()
        construir_indice()
        return 0

    if args.indice:
        return 0 if construir_indice() >= 0 else 1

    grupos = carregar_alvos(args.versao)
    chaves = sorted(grupos.keys())

    # RECONCILIACAO. Um grupo gravado numa execucao anterior pode ter sido montado com uma
    # lista de alvos DIFERENTE da atual — foi o que aconteceu em 21/09/2026, quando a chave
    # (commit, arquivo) passou a vir do disco em vez do `file_name` do BigVul. Sem isto, o
    # --retomar pularia esses grupos e o dataset ficaria meio velho e meio novo, sem aviso.
    # Regra: se o PEDIDO do grupo mudou, a saida daquele grupo nao vale mais e e refeita.
    # Ate 05/10 o pedido era comparado so pelo NUMERO de alvos — e um grupo com o mesmo numero
    # mas com hash ou linha novos passaria batido. Desde entao o .meta.json guarda a
    # `assinatura` (ids, nomes, hashes, linhas, pasta); meta antigo, sem ela, cai no numero.
    esperado = {marca_de(k): (len(grupos[k]["alvos"]), assinatura(grupos[k])) for k in chaves}
    descartados = 0
    for meta in sorted(glob.glob(os.path.join(GRUPOS, "*.meta.json"))):
        marca = os.path.basename(meta)[:-len(".meta.json")]
        try:
            m = json.load(open(meta, encoding="utf-8"))
        except Exception:
            m = {}
        exp = esperado.get(marca)
        if exp is None:
            valido = False
        elif "assinatura" in m:
            valido = m["assinatura"] == exp[1]
        else:
            valido = m.get("pedidos") == exp[0]
        if not valido:
            for ext in (".jsonl", ".meta.json"):
                try:
                    os.remove(os.path.join(GRUPOS, marca + ext))
                except OSError:
                    pass
            descartados += 1
    if descartados:
        log("reconciliacao: %d grupo(s) desatualizado(s) descartado(s), serao refeitos"
            % descartados)

    if args.so:
        trechos = [t for t in args.so.split(",") if t]
        chaves = [k for k in chaves if any(t in marca_de(k) for t in trechos)]
    if args.n:
        chaves = chaves[:args.n]

    falhas, motivos_tot = Counter(), Counter()
    t0 = time.time()
    feitos = exportados = 0
    for i, chave in enumerate(chaves, 1):
        marca = marca_de(chave)
        destino = os.path.join(GRUPOS, marca + ".jsonl")
        if args.retomar and os.path.exists(destino):
            continue
        info = grupos[chave]
        r, erro = processar(chave, info, args.timeout)
        if erro:
            falhas[erro] += 1
            log("  [%d/%d] %-44s FALHA: %s" % (i, len(chaves), marca[:44], erro))
            continue
        linhas, motivos, por_alvo = r
        gravar_grupo(marca, linhas, motivos, len(info["alvos"]), por_alvo, assinatura(info))
        motivos_tot.update(motivos)
        feitos += 1
        exportados += len(linhas)
        if feitos % 10 == 0 or len(chaves) < 20:
            dec = time.time() - t0
            log("  [%d/%d] %-40s %3d/%-3d exportados | total %d | %.1f s/arq"
                % (i, len(chaves), marca[:40], len(linhas), len(info["alvos"]),
                   exportados, dec / max(feitos, 1)))

    log()
    log("tempo: %.0f s para %d arquivos | %d grafos exportados"
        % (time.time() - t0, feitos, exportados))
    if motivos_tot:
        log("motivos: %s" % dict(motivos_tot))
    if falhas:
        log("falhas: %s" % dict(falhas))
    construir_indice()
    return 0


if __name__ == "__main__":
    import traceback
    try:
        codigo = main()
    except BaseException:
        log("=== FALHOU ===")
        log(traceback.format_exc())
        codigo = 1
    sys.exit(codigo)
