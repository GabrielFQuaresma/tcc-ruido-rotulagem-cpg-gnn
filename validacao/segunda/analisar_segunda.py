#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Segunda validacao manual: a analise pre-registrada (PRE_REGISTRO_SEGUNDA.md, secoes 7 e 8).

SITUANDO
  A traversal v3 deu a cada positivo do BigVul um veredito: `confirmado` (entra no M_cur, o
  conjunto curado) ou `descartado` (so fica de fora; o silencio nunca inverte rotulo). O autor
  anotou 60 funcoes sorteadas dos dois lados (30 + 30), CEGO ao veredito, com a rubrica_v1
  (A/B/C/D/?; so o D e rotulo correto). Este script cruza a planilha com a chave lacrada e
  calcula o que o pre-registro fixou:
    1. precisao do filtro = D / (A+B+C+D) entre os confirmados;
    2. taxa de D entre os descartados;
    3. taxa base estimada = media das duas, ponderada pelos tamanhos dos estratos na moldura
       (806 confirmados, 1646 descartados);
    4. ganho = precisao - taxa base;
    5. IC 95% das quatro por bootstrap estratificado e por cluster de commit (10.000
       reamostragens, random.Random(7074), percentil igual ao do traversal/etapa_5.py);
    6. tabela A/B/C/D/? x estrato; 7. leituras descritivas (A e B confirmados; cobertura dos D);
    8. sensibilidades 8.1 a 8.4 (so estimativa pontual e n).
  O `?` fica fora de todo denominador.

O QUE NAO E
  - Nao muda a planilha nem a chave; so le.
  - Nao e a Etapa 5 (os 50 da primeira validacao); os numeros dela entram so como referencia.
  - Nao escolhe a frase do resultado: a regra da secao 7 decide pelo limite inferior do IC do ganho.

TRAVAS (secao 12.5 do pre-registro, mais a planilha congelada)
  Recusa rodar se: o SHA-256 do pre-registro ou da planilha divergir do `congelamento_segunda.tsv`;
  o SHA-256 da chave divergir do da secao 13; o `montar_segunda.py --conferir` falhar; alguma
  linha da planilha estiver sem tipo_ruido valido; o commit da chave nao bater com o da planilha
  em algum caso. Com --abrir, recusa sobrescrever um resultado ja gravado (a chave se abre uma vez).

USO (no WSL)
  python3 analisar_segunda.py --ensaio   # chave SINTETICA sorteada aqui; a chave real nao e lida
  python3 analisar_segunda.py --abrir    # abre a chave real e grava resultado_segunda.{md,json}
"""

import argparse
import csv
import datetime
import hashlib
import json
import os
import random
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(AQUI))            # Dataset/bigvul
sys.dont_write_bytecode = True
sys.path.insert(0, BASE)
# A mesma normalizacao de confianca do `revisar_validacao.py tally` (secao 8.3 do pre-registro).
from revisar_validacao import MAPA_CONF  # noqa: E402

PRE_REGISTRO = os.path.join(AQUI, "PRE_REGISTRO_SEGUNDA.md")
PLANILHA = os.path.join(AQUI, "anotacao_segunda.csv")
CHAVE = os.path.join(AQUI, "chave", "chave_segunda.csv")
CONGELAMENTO = os.path.join(AQUI, "congelamento_segunda.tsv")
MONTAR = os.path.join(AQUI, "montar_segunda.py")
SAIDA_MD = os.path.join(AQUI, "resultado_segunda.md")
SAIDA_JSON = os.path.join(AQUI, "resultado_segunda.json")

# Secao 13 do pre-registro (amostra 30 + 30 de 30/10/2026).
SHA_CHAVE = "013f16819667bf3d8b4225652c031165abc824f9f06f3638d0a5a5e8bcf50afb"

ESTRATOS = ("confirmado", "descartado")
N_MOLDURA = {"confirmado": 806, "descartado": 1646}
N_ESPERADO = {"confirmado": 30, "descartado": 30}
CATEGORIAS = ("A", "B", "C", "D", "?")
DECIDIDAS = ("A", "B", "C", "D")
N_BOOT = 10000
SEMENTE_BOOT = 7074
SEMENTE_ENSAIO = 424242      # so para a chave sintetica do --ensaio; nao entra em nenhum resultado

# Etapa 5 (secao 10 do pre-registro; traversal/RESULTADO.md): so referencia, as amostras nao se somam.
ETAPA_5 = {
    "precisao": "64,7% (11 de 17), IC 95% [40,0; 86,7]",
    "taxa_base": "44,2% (19 de 43); na v3, entre 42,9% e 45,2%",
    "ganho": "+20,5 pontos, IC 95% [-1,8; +39,0]",
}


def parar(msg):
    sys.exit("RECUSANDO RODAR: " + msg)


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 16), b""):
            h.update(bloco)
    return h.hexdigest()


def pct(v, p):
    """Percentil igual ao do traversal/etapa_5.py (indice arredondado, sem interpolacao)."""
    v = sorted(v)
    return v[min(len(v) - 1, max(0, int(round(p / 100.0 * (len(v) - 1)))))]


def fmt(x, sinal=False):
    if x is None:
        return "n/d"
    s = "{:+.1f}".format(x) if sinal else "{:.1f}".format(x)
    return s.replace(".", ",")


# --- travas ------------------------------------------------------------------------------------

def conferir_travas():
    if not os.path.exists(CONGELAMENTO):
        parar("sem congelamento_segunda.tsv: o pre-registro nao foi congelado.")
    congelado = {}
    with open(CONGELAMENTO, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            congelado.setdefault(r["arquivo"], r["sha256"])
    shas = {}
    for nome, caminho in (("PRE_REGISTRO_SEGUNDA.md", PRE_REGISTRO),
                          ("anotacao_segunda.csv", PLANILHA)):
        if nome not in congelado:
            parar("{} nao esta no congelamento_segunda.tsv.".format(nome))
        atual = sha256_arquivo(caminho)
        if atual != congelado[nome]:
            parar("{} mudou depois do congelamento ({} != {}).".format(nome, atual, congelado[nome]))
        shas[nome] = atual
    atual = sha256_arquivo(CHAVE)
    if atual != SHA_CHAVE:
        parar("a chave mudou ({} != {} da secao 13).".format(atual, SHA_CHAVE))
    shas["chave/chave_segunda.csv"] = atual
    proc = subprocess.run([sys.executable, MONTAR, "--conferir"], cwd=AQUI,
                          capture_output=True, text=True)
    if proc.returncode != 0 or "conferir: OK" not in proc.stdout:
        parar("montar_segunda.py --conferir falhou:\n" + proc.stdout + proc.stderr)
    return shas


# --- leitura -----------------------------------------------------------------------------------

def ler_planilha():
    with open(PLANILHA, encoding="utf-8-sig", newline="") as f:
        amostra = f.read(4096)
        f.seek(0)
        dialeto = csv.Sniffer().sniff(amostra, delimiters=",;")
        linhas = list(csv.DictReader(f, dialect=dialeto))
    plan = {}
    for r in linhas:
        caso = int(r["id"])
        tipo = r["tipo_ruido"].strip().upper()
        if tipo not in CATEGORIAS:
            parar("caso {}: tipo_ruido {!r} fora de A/B/C/D/?.".format(caso, r["tipo_ruido"]))
        plan[caso] = {
            "tipo": tipo,
            "conf": MAPA_CONF.get(r["confianca"].strip().lower(), ""),
            "commit": r["commit_id"].strip(),
        }
    if len(plan) != sum(N_ESPERADO.values()):
        parar("a planilha tem {} casos; esperados {}.".format(len(plan), sum(N_ESPERADO.values())))
    return plan


def ler_chave_real():
    with open(CHAVE, encoding="utf-8", newline="") as f:
        return {int(r["caso"]): {"veredito": r["veredito"].strip(),
                                 "commit": r["commit"].strip(),
                                 "ordem": int(r["ordem_no_estrato"]),
                                 "visto": r["commit_na_primeira"].strip()}
                for r in csv.DictReader(f)}


def chave_sintetica(plan):
    """So para o --ensaio: vereditos sorteados, mesmos commits da planilha. Nao le a chave real."""
    rnd = random.Random(SEMENTE_ENSAIO)
    casos = sorted(plan)
    rnd.shuffle(casos)
    chave = {}
    for i, caso in enumerate(casos):
        est = "confirmado" if i < N_ESPERADO["confirmado"] else "descartado"
        chave[caso] = {"veredito": est, "commit": plan[caso]["commit"],
                       "ordem": i if est == "confirmado" else i - N_ESPERADO["confirmado"],
                       "visto": "sim" if rnd.random() < 0.3 else "nao"}
    return chave


def juntar(plan, chave):
    if set(plan) != set(chave):
        parar("os casos da planilha e da chave nao sao os mesmos.")
    linhas = []
    for caso in sorted(plan):
        p, k = plan[caso], chave[caso]
        if k["veredito"] not in ESTRATOS:
            parar("caso {}: veredito {!r} desconhecido na chave.".format(caso, k["veredito"]))
        if p["commit"] != k["commit"]:
            parar("caso {}: commit da planilha != commit da chave.".format(caso))
        linhas.append({"caso": caso, "estrato": k["veredito"], "tipo": p["tipo"],
                       "conf": p["conf"], "commit": k["commit"], "ordem": k["ordem"],
                       "visto": k["visto"]})
    for est in ESTRATOS:
        n = sum(1 for l in linhas if l["estrato"] == est)
        if n != N_ESPERADO[est]:
            parar("estrato {} tem {} casos; esperados {}.".format(est, n, N_ESPERADO[est]))
    return linhas


# --- medidas -----------------------------------------------------------------------------------

def medidas(linhas):
    """Secao 7, itens 1 a 4 e 7(b). Taxas em %; o `?` fica fora dos denominadores."""
    n, d = {}, {}
    for est in ESTRATOS:
        dec = [l for l in linhas if l["estrato"] == est and l["tipo"] in DECIDIDAS]
        n[est] = len(dec)
        d[est] = sum(1 for l in dec if l["tipo"] == "D")
    if not n["confirmado"] or not n["descartado"]:
        return {"n_conf": n["confirmado"], "n_desc": n["descartado"], "precisao": None,
                "taxa_desc": None, "taxa_base": None, "ganho": None, "cobertura": None,
                "d_conf": d["confirmado"], "d_desc": d["descartado"]}
    prec = 100.0 * d["confirmado"] / n["confirmado"]
    tdesc = 100.0 * d["descartado"] / n["descartado"]
    nc, nd = N_MOLDURA["confirmado"], N_MOLDURA["descartado"]
    base = (nc * prec + nd * tdesc) / (nc + nd)
    den = nc * prec + nd * tdesc
    return {"n_conf": n["confirmado"], "n_desc": n["descartado"],
            "d_conf": d["confirmado"], "d_desc": d["descartado"],
            "precisao": prec, "taxa_desc": tdesc, "taxa_base": base, "ganho": prec - base,
            "cobertura": 100.0 * nc * prec / den if den else None}


def tabela(linhas):
    return {est: {c: sum(1 for l in linhas if l["estrato"] == est and l["tipo"] == c)
                  for c in CATEGORIAS} for est in ESTRATOS}


def bootstrap(linhas):
    """Secao 7, item 5: dentro de cada estrato, sorteia com reposicao tantos commits quantos o
    estrato tem entre as linhas decididas, levando todas as linhas decididas de cada commit."""
    clusters = {}
    for est in ESTRATOS:
        cl = {}
        for l in linhas:
            if l["estrato"] == est and l["tipo"] in DECIDIDAS:
                cl.setdefault(l["commit"], []).append(l)
        clusters[est] = (sorted(cl), cl)            # ordem fixa dos commits: alfabetica
    rnd = random.Random(SEMENTE_BOOT)
    series = {k: [] for k in ("precisao", "taxa_desc", "taxa_base", "ganho")}
    vazios = 0
    for _ in range(N_BOOT):
        amostra = []
        for est in ESTRATOS:                        # sempre confirmados primeiro, depois descartados
            chaves, cl = clusters[est]
            for _ in range(len(chaves)):
                amostra.extend(cl[chaves[rnd.randrange(len(chaves))]])
        m = medidas(amostra)
        if m["precisao"] is None:
            vazios += 1                             # estrato sem linha decidida: contado, nao mascarado
            continue
        for k in series:
            series[k].append(m[k])
    ic = {k: (pct(v, 2.5), pct(v, 97.5)) if v else (None, None) for k, v in series.items()}
    return {"ic": ic, "n_validas": len(series["ganho"]), "vazios": vazios,
            "clusters": {est: len(clusters[est][0]) for est in ESTRATOS}}


def sensibilidades(linhas):
    s = {}
    s["8.1 sem commit ja visto"] = medidas([l for l in linhas if l["visto"] != "sim"])
    uma = []
    for est in ESTRATOS:
        prim = {}
        for l in linhas:
            if l["estrato"] == est and (l["commit"] not in prim or l["ordem"] < prim[l["commit"]]["ordem"]):
                prim[l["commit"]] = l
        uma.extend(prim.values())
    s["8.2 uma linha por commit"] = medidas(uma)
    s["8.3 so confianca alta"] = medidas([l for l in linhas if l["conf"] == "alta"])
    return s


def frase(m, ic):
    lo = ic["ganho"][0]
    if lo is not None and lo > 0:
        return ("na amostra estratificada, o filtro eleva a proporcao de rotulos corretos de {}% "
                "para {}% (IC 95% [{}; {}]; ganho de {} pontos, IC [{}; {}])").format(
            fmt(m["taxa_base"]), fmt(m["precisao"]), fmt(ic["precisao"][0]), fmt(ic["precisao"][1]),
            fmt(m["ganho"], True), fmt(ic["ganho"][0], True), fmt(ic["ganho"][1], True))
    return ("continua valendo a frase atual do artigo, agora com esta amostra: compativel com "
            "ganho ({} pontos, IC 95% [{}; {}]), mas nao exclui ganho nulo a 95%").format(
        fmt(m["ganho"], True), fmt(ic["ganho"][0], True), fmt(ic["ganho"][1], True))


# --- relatorio ---------------------------------------------------------------------------------

def relatorio(linhas, shas, modo):
    tab = tabela(linhas)
    m = medidas(linhas)
    b = bootstrap(linhas)
    ic = b["ic"]
    sens = sensibilidades(linhas)
    conf = [l for l in linhas if l["estrato"] == "confirmado"]
    desc_a = sum(1 for l in conf if l["tipo"] == "A")
    desc_b = sum(1 for l in conf if l["tipo"] == "B")
    tot_a = sum(1 for l in linhas if l["tipo"] == "A")
    tot_b = sum(1 for l in linhas if l["tipo"] == "B")
    agora = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    L = []
    L.append("# Resultado da segunda validacao manual — precisao do filtro"
             + (" (ENSAIO COM CHAVE SINTETICA — NAO E RESULTADO)" if modo == "ensaio" else ""))
    L.append("")
    L.append("Aberto em {} por `analisar_segunda.py --{}`. Plano: `PRE_REGISTRO_SEGUNDA.md` "
             "(congelado em 30/10/2026, 14:06, depois da anotacao e antes da chave; desvio "
             "declarado no topo do pre-registro).".format(agora, "abrir" if modo == "abrir" else "ensaio"))
    L.append("")
    L.append("**Situando.** A traversal v3 confirma ou descarta cada positivo do BigVul. O autor "
             "anotou 60 funcoes (30 confirmadas + 30 descartadas, misturadas) sem saber o veredito, "
             "com a rubrica_v1: so a categoria D (a funcao e o sitio do defeito) e rotulo correto. "
             "O `?` fica fora de todo denominador.")
    L.append("")
    L.append("## Tabela A/B/C/D/? por estrato")
    L.append("")
    L.append("| estrato | A | B | C | D | ? | decididas |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for est in ESTRATOS:
        t = tab[est]
        L.append("| {} | {} | {} | {} | {} | {} | {} |".format(
            est + "s", t["A"], t["B"], t["C"], t["D"], t["?"], sum(t[c] for c in DECIDIDAS)))
    L.append("")
    L.append("## Medidas principais (secao 7)")
    L.append("")
    L.append("| medida | estimativa | IC 95% | contagem |")
    L.append("| --- | --- | --- | --- |")
    L.append("| precisao do filtro (D entre os confirmados) | {}% | [{}; {}] | {} de {} |".format(
        fmt(m["precisao"]), fmt(ic["precisao"][0]), fmt(ic["precisao"][1]), m["d_conf"], m["n_conf"]))
    L.append("| D entre os descartados | {}% | [{}; {}] | {} de {} |".format(
        fmt(m["taxa_desc"]), fmt(ic["taxa_desc"][0]), fmt(ic["taxa_desc"][1]), m["d_desc"], m["n_desc"]))
    L.append("| taxa base estimada (ponderada 806 : 1646) | {}% | [{}; {}] | — |".format(
        fmt(m["taxa_base"]), fmt(ic["taxa_base"][0]), fmt(ic["taxa_base"][1])))
    L.append("| ganho (precisao - taxa base) | {} pontos | [{}; {}] | — |".format(
        fmt(m["ganho"], True), fmt(ic["ganho"][0], True), fmt(ic["ganho"][1], True)))
    L.append("")
    L.append("Bootstrap estratificado por cluster de commit: {} reamostragens validas de {}, "
             "{} descartadas por estrato vazio; {} commits entre os confirmados decididos e {} "
             "entre os descartados; `random.Random({})`.".format(
                 b["n_validas"], N_BOOT, b["vazios"], b["clusters"]["confirmado"],
                 b["clusters"]["descartado"], SEMENTE_BOOT))
    L.append("")
    L.append("**Frase pre-registrada que resulta (secao 7):** " + frase(m, ic) + ".")
    L.append("")
    L.append("## Leituras descritivas (secao 7, item 7; sem IC e sem criterio)")
    L.append("")
    L.append("- (a) o filtro confirmou {} das {} funcoes A e {} das {} funcoes B da amostra "
             "(na Etapa 5: 0 de 5 e 0 de 10).".format(desc_a, tot_a, desc_b, tot_b))
    L.append("- (b) cobertura dos D (fracao dos sitios que o filtro mantem, ponderada pela "
             "moldura): {}% (na Etapa 5: 11 de 19 = 57,9%).".format(fmt(m["cobertura"])))
    L.append("")
    L.append("## Sensibilidades (secao 8; so estimativa pontual e n)")
    L.append("")
    L.append("| recorte | precisao | D nos descartados | taxa base | ganho | n confirmados | n descartados |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for nome, s in sens.items():
        L.append("| {} | {}% | {}% | {}% | {} | {} | {} |".format(
            nome, fmt(s["precisao"]), fmt(s["taxa_desc"]), fmt(s["taxa_base"]),
            fmt(s["ganho"], True), s["n_conf"], s["n_desc"]))
    L.append("")
    L.append("8.4 os `?`: {} entre os confirmados e {} entre os descartados (fora de todo "
             "denominador).".format(tab["confirmado"]["?"], tab["descartado"]["?"]))
    L.append("")
    L.append("Nenhuma sensibilidade substitui a analise principal (secao 7).")
    L.append("")
    L.append("## Referencia: Etapa 5 (secao 10; as amostras NAO se somam)")
    L.append("")
    L.append("- precisao: " + ETAPA_5["precisao"])
    L.append("- taxa base: " + ETAPA_5["taxa_base"])
    L.append("- ganho: " + ETAPA_5["ganho"])
    L.append("")
    L.append("## Entradas (SHA-256)")
    L.append("")
    for nome, sha in shas.items():
        L.append("- `{}` `{}`".format(nome, sha))
    texto = "\n".join(L) + "\n"

    dados = {"modo": modo, "aberto_em": agora, "tabela": tab, "medidas": m,
             "ic95": {k: list(v) for k, v in ic.items()},
             "bootstrap": {"n_boot": N_BOOT, "semente": SEMENTE_BOOT, "validas": b["n_validas"],
                           "vazios": b["vazios"], "clusters": b["clusters"]},
             "descritivas": {"A_confirmados": desc_a, "A_total": tot_a,
                             "B_confirmados": desc_b, "B_total": tot_b,
                             "cobertura_D": m["cobertura"]},
             "sensibilidades": sens,
             "interrogacoes": {est: tab[est]["?"] for est in ESTRATOS},
             "frase": frase(m, ic), "entradas_sha256": shas}
    return texto, dados


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--ensaio", action="store_true", help="chave sintetica; nao le a chave real")
    g.add_argument("--abrir", action="store_true", help="abre a chave real e grava o resultado")
    args = p.parse_args()

    shas = conferir_travas()
    print("travas: ok (pre-registro e planilha iguais ao congelamento; chave igual a secao 13; "
          "montar_segunda.py --conferir OK)")
    plan = ler_planilha()

    if args.ensaio:
        texto, _ = relatorio(juntar(plan, chave_sintetica(plan)), shas, "ensaio")
        print(texto)
        return 0

    if os.path.exists(SAIDA_JSON) or os.path.exists(SAIDA_MD):
        parar("o resultado ja foi gravado ({}); a chave se abre uma vez.".format(SAIDA_JSON))
    texto, dados = relatorio(juntar(plan, ler_chave_real()), shas, "abrir")
    with open(SAIDA_MD, "w", encoding="utf-8") as f:
        f.write(texto)
    with open(SAIDA_JSON, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    print(texto)
    print("gravado: {} (sha256 {})".format(os.path.basename(SAIDA_MD), sha256_arquivo(SAIDA_MD)))
    print("gravado: {} (sha256 {})".format(os.path.basename(SAIDA_JSON), sha256_arquivo(SAIDA_JSON)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
