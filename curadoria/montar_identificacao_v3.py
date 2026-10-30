#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fase 2 da traversal v3: a tabela que diz, item a item, COMO a v3 vai avaliar cada positivo.

O QUE ESTA ETAPA E, situando
----------------------------
A traversal v3 so avalia um item se conseguir apontar no grafo o metodo que e a funcao rotulada
pelo BigVul (TRAVERSAL_V3.md, secao 3.1). Esta tabela registra, ANTES de rodar, o resultado
dessa identificacao para cada um dos 2957 positivos:

  avaliar            — 0 ou 1 metodo com o nome e com corpo, e (se 1) ele passa no teste de
                       posicao. A v3 roda exatamente como a v2.
  avaliar_na_linha   — 2+ metodos com o nome e com corpo, e o hash do func_before aponta
                       exatamente um. A v3 recebe `linha` = a linha onde ele comeca.
  excluir            — nao deu para apontar a funcao rotulada. O item sai dos tres bracos; a v3
                       nem roda nele. O motivo vai na tabela.

De onde vem cada resposta (nada aqui e medida nova — e a reuniao do que ja existe):
  - grafo no dataset (montar_dataset, 22/09): so havia grafo quando o arquivo tinha 1 metodo
    com o nome e com corpo. A faixa de linhas desse metodo esta no .jsonl do grupo.
  - colisao (_perda_bracos.tsv, _perda_avaliacao.tsv): as faixas de cada homonimo estao no
    cache do _diagnosticar_perda_bracos.py (~/curadoria/_diag_perda/).
  - indeterminado na v2: corpo nao parseado (0 metodo com corpo) — nada a identificar.
  - sem evidencia na v2 (as 169 falhas): a v3 tenta de novo como a v2; a trava do .sc segura
    qualquer colisao que aparecer.
  - os 5 itens que o montar_dataset procurou no ARQUIVO ERRADO (chave de grupo, P6): censo no
    CPG do proprio item, com o _contar_homonimos.sc — o unico uso do Joern aqui.

Os dois testes (TRAVERSAL_V3.md, 3.1):
  posicao — a 1a linha nao vazia do func_before, com espacos colapsados, e igual a uma linha do
            arquivo dentro de [inicio - FOLGA_LINHA, fim] do metodo. So CONFERE (1 metodo).
  hash    — os dois hashes do func_before (split/positivos_hash.tsv) contra os do trecho de cada
            homonimo (montar_dataset.hashes_do_metodo). So ESCOLHE (2+ metodos).

SAIDA: identificacao_v3.tsv. Nao e arquivo de regra (traz id de item, que tem nome de projeto);
o SHA-256 dela vai para o adendo do TRAVERSAL_V3.md antes da rodada.

Uso (no WSL):
  python3 montar_identificacao_v3.py
"""

import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
import montar_dataset as md                                    # noqa: E402
from veredito import carregar_regra, julgar, INDETERMINADO     # noqa: E402

ITENS = os.path.join(os.path.dirname(AQUI), "saida_final", "itens")
EVIDENCIA_V2 = os.path.join(AQUI, "saida_completa")
POS_HASH = os.path.join(AQUI, "split", "positivos_hash.tsv")
SC_CENSO = os.path.join(AQUI, "_contar_homonimos.sc")
CACHE_COLISAO = os.path.expanduser("~/curadoria/_diag_perda")
CACHE_CENSO = os.path.expanduser("~/curadoria/_ident_v3")
TRABALHO = os.path.expanduser("~/curadoria/_trabalho_ident_v3")
SAIDA = os.path.join(AQUI, "identificacao_v3.tsv")

# Os itens que o montar_dataset procurou no CPG de outro arquivo (HANDOFF 8.3, P6). Para eles a
# resposta "1 metodo / 2+ metodos" que existe hoje veio do arquivo errado.
ARQUIVO_ERRADO = ["1265__texlive-source", "1304__neomutt", "1305__neomutt",
                  "2317__Chrome", "2318__Chrome"]

# As 33 exclusoes previstas no pre-registro (TRAVERSAL_V3.md, secao 6). Conferencia P3.
PREVISTAS = {
    "0032__poppler", "0360__php-src", "1213__php-src", "1993__Chrome", "2194__Chrome",
    "2661__Android", "2803__Android", "1265__texlive-source", "1882__Chrome", "1946__Chrome",
    "1947__Chrome", "2107__Chrome", "2134__Chrome", "2179__Chrome", "2199__Chrome",
    "2229__Chrome", "2800__Android", "2801__Android", "2802__Android", "2804__Android",
    "2805__Android", "2806__Android", "2807__Android", "2808__Android", "2810__Android",
    "2813__Android", "2814__Android", "2815__Android", "2816__Android", "2817__Android",
    "2818__Android", "2932__Android", "2933__Android",
}

WS = re.compile(r"\s+")


def log(*a):
    print(*a, flush=True)


def tsv(caminho):
    return list(csv.DictReader(open(caminho, encoding="utf-8"), delimiter="\t"))


def texto_arquivo(item):
    fontes = [p for p in glob.glob(os.path.join(md.CACHE_CPG, item, "arquivo__*"))
              if os.path.isfile(p)]
    return open(fontes[0], encoding="utf-8", errors="replace").read() if fontes else ""


def func_before(item):
    return open(os.path.join(ITENS, item, "func_before.c"), encoding="utf-8",
                errors="replace").read()


def passa_posicao(item, ini, fim):
    """Teste de posicao. True se a 1a linha da funcao rotulada cai dentro do metodo."""
    p = next((WS.sub(" ", l).strip() for l in func_before(item).splitlines() if l.strip()), "")
    if not p:
        return False
    linhas = texto_arquivo(item).split("\n")         # so '\n', como o Joern conta
    for n in range(max(1, ini - md.FOLGA_LINHA), fim + 1):
        if n <= len(linhas) and WS.sub(" ", linhas[n - 1]).strip() == p:
            return True
    return False


def escolher_por_hash(item, faixas, hashes):
    """Faixas (ini, fim) cujo trecho tem hash em comum com o func_before."""
    pasta = os.path.join(md.CACHE_CPG, item)
    return [f for f in faixas if hashes & md.hashes_do_metodo(pasta, f[0], f[1])]


def faixas_de(campo):
    return [tuple(int(x) for x in f.split("-")) for f in (campo or "").split(",") if f]


def censo_proprio(item, nome):
    """[todos, internos, com_corpo, faixas] do nome no CPG do PROPRIO item. Cacheado."""
    cache = os.path.join(CACHE_CENSO, item + ".json")
    if os.path.exists(cache):
        return json.load(open(cache, encoding="utf-8"))
    os.makedirs(TRABALHO, exist_ok=True)
    lista = os.path.join(TRABALHO, "alvos.txt")
    with open(lista, "w", encoding="utf-8") as fh:
        fh.write(nome + "\n")
    cpg = os.path.join(md.CACHE_CPG, item, "cpg.bin")
    r = subprocess.run(["joern", "--script", SC_CENSO, "--param", "cpg_file=" + cpg,
                        "--param", "alvos=" + lista],
                       cwd=TRABALHO, capture_output=True, text=True, timeout=600)
    shutil.rmtree(os.path.join(TRABALHO, "workspace"), ignore_errors=True)
    saida = (r.stdout or "") + "\n" + (r.stderr or "")
    if "FIM" not in saida:
        raise RuntimeError("censo do %s falhou: %s" % (item, saida[-300:]))
    for linha in saida.splitlines():
        if linha.startswith("CONT\t"):
            c = linha.split("\t")
            out = [int(c[2]), int(c[3]), int(c[4]), c[5] if len(c) > 5 else ""]
            os.makedirs(CACHE_CENSO, exist_ok=True)
            json.dump(out, open(cache, "w", encoding="utf-8"))
            return out
    raise RuntimeError("censo do %s nao devolveu linha CONT" % item)


def main():
    regra = carregar_regra(os.path.join(AQUI, "regra_veredito.toml"))
    todos = sorted(d for d in os.listdir(ITENS) if os.path.isdir(os.path.join(ITENS, d)))
    hashes = {r["item"]: {h for h in (r["sha1_corpo"], r["sha1_corpo_sc"]) if h}
              for r in tsv(POS_HASH)}

    # --- o que se sabe hoje, de cada fonte
    evid = {}
    for p in glob.glob(os.path.join(EVIDENCIA_V2, "*.json")):
        e = json.load(open(p, encoding="utf-8"))
        evid[e["item"]] = e
    grafo = {}
    for p in glob.glob(os.path.join(md.GRUPOS, "*.jsonl")):
        for l in open(p, encoding="utf-8"):
            if l.strip():
                g = json.loads(l)
                if g["rotulo"] == 1:
                    grafo[g["id"]] = (g["linha_inicio"], g["linha_fim"])
    perda = {}
    for nome in ("_perda_bracos.tsv", "_perda_avaliacao.tsv"):
        for r in tsv(os.path.join(AQUI, nome)):
            perda[r["item"]] = r

    linhas = []
    for item in todos:
        e = evid.get(item)
        nome = e.get("alvo", "") if e else ""
        reg = {"item": item, "nome": nome, "acao": "avaliar", "linha": "", "motivo": "",
               "definicoes_com_corpo": "", "origem": ""}

        if e is None:
            reg["origem"] = "sem_evidencia_v2"            # as 169 falhas: tenta de novo
        elif julgar(e, regra)[0] == INDETERMINADO:
            reg["origem"] = "indeterminado_v2"            # corpo nao parseado: nada a apontar
            reg["definicoes_com_corpo"] = "0"
        else:
            if item in ARQUIVO_ERRADO:
                cont = censo_proprio(item, nome)
                faixas, origem = faixas_de(cont[3]), "censo_proprio_arquivo"
            elif item in grafo:
                faixas, origem = [grafo[item]], "grafo_unico"
            elif item in perda and perda[item]["motivo"] == "joern:homonimo_sem_hash":
                cont = json.load(open(os.path.join(CACHE_COLISAO, perda[item]["arquivo"] + ".json"),
                                      encoding="utf-8"))
                faixas, origem = faixas_de(cont[nome][3]), "colisao"
            else:
                raise RuntimeError("item com evidencia sem fonte de identificacao: %s" % item)

            reg["origem"] = origem
            reg["definicoes_com_corpo"] = str(len(faixas))
            if len(faixas) == 0:
                pass                                       # como a v2: o .sc decide
            elif len(faixas) == 1:
                if not passa_posicao(item, *faixas[0]):
                    reg["acao"], reg["motivo"] = "excluir", "funcao_unica_nao_e_a_rotulada"
            else:
                casam = escolher_por_hash(item, faixas, hashes.get(item, set()))
                if len(casam) == 1:
                    reg["acao"], reg["linha"] = "avaliar_na_linha", str(casam[0][0])
                else:
                    reg["acao"] = "excluir"
                    reg["motivo"] = "colisao_hash_nao_casa" if not casam else "colisao_hash_empata"
        linhas.append(reg)

    campos = ["item", "nome", "acao", "linha", "motivo", "definicoes_com_corpo", "origem"]
    with open(SAIDA, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=campos, delimiter="\t")
        w.writeheader()
        for reg in linhas:
            w.writerow(reg)

    # --- resumo e conferencias contra o pre-registro
    log("itens: %d -> %s" % (len(linhas), SAIDA))
    log("por acao:   %s" % dict(Counter(r["acao"] for r in linhas)))
    log("por origem: %s" % dict(Counter(r["origem"] for r in linhas)))
    log("motivos:    %s" % dict(Counter(r["motivo"] for r in linhas if r["motivo"])))
    log()
    log("os 5 do arquivo errado, agora no proprio CPG:")
    for r in linhas:
        if r["item"] in ARQUIVO_ERRADO:
            log("  %-22s definicoes=%s acao=%s %s" % (r["item"], r["definicoes_com_corpo"],
                                                     r["acao"], r["motivo"] or r["linha"]))

    excl = {r["item"] for r in linhas if r["acao"] == "excluir"}
    na_linha = sum(1 for r in linhas if r["acao"] == "avaliar_na_linha")
    rec = [r for r in tsv(os.path.join(AQUI, "_recuperabilidade_hash.tsv"))
           + tsv(os.path.join(AQUI, "_recuperabilidade_hash_avaliacao.tsv"))]
    faixa_rev = {r["item"]: r["faixa"].split("-")[0] for r in rec if r["classe"] == "recuperavel"}
    linha_tab = {r["item"]: r["linha"] for r in linhas if r["acao"] == "avaliar_na_linha"}
    mesma_linha = all(linha_tab.get(i) == f for i, f in faixa_rev.items())

    log()
    log("CONFERENCIAS (pre-registro):")
    extra, falta = sorted(excl - PREVISTAS), sorted(PREVISTAS - excl)
    p3 = not extra and (not falta or falta == ["1265__texlive-source"])
    log("  P3 exclusoes = as 33 previstas (so o 1265 pode sair): %s | a mais %s | a menos %s"
        % ("ok" if p3 else "FALHOU", extra, falta))
    log("  colisoes com linha: %d (176 previstas + colisoes dos 5 no proprio arquivo)" % na_linha)
    log("  linha escolhida = faixa da revisao nos 176: %s" % ("ok" if mesma_linha else "FALHOU"))
    return 0 if (p3 and mesma_linha) else 1


if __name__ == "__main__":
    import traceback
    try:
        codigo = main()
    except BaseException:
        log("=== FALHOU ===")
        log(traceback.format_exc())
        codigo = 1
    sys.exit(codigo)
