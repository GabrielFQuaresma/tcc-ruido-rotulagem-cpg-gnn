#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Segunda validacao manual: sorteia a amostra estratificada e monta o material de anotacao.

SITUANDO
  Estamos depois da curadoria. A traversal v3 (a consulta do Joern que olha cada funcao que o
  BigVul marcou como vulneravel) deu um veredito a cada positivo com corpo analisavel:
  `confirmado` (o padrao de erro de memoria esta na funcao; ela entra no M_cur, o braco curado
  do experimento) ou `descartado` (fica de fora; o silencio nunca inverte rotulo). Sao 2521
  itens em traversal/conjuntos_v3/M_raw.tsv: 836 confirmados e 1685 descartados.

  A PRIMEIRA validacao manual (agosto/2026; 50 positivos BRUTOS, semente 42) mediu o ruido do
  BigVul antes de qualquer filtro. Esta SEGUNDA mede a PRECISAO DO FILTRO numa amostra feita
  para isso: sorteada DEPOIS da curadoria e ESTRATIFICADA pelo veredito. Pergunta principal:
  entre as funcoes que o filtro confirmou, quantas sao de fato o sitio da vulnerabilidade
  (categoria D da rubrica_v1.md)? Secundaria: entre as descartadas, quantas sao D.

O QUE FAZ
  1. Confere as entradas e PARA se alguma nao bater:
     - o numero do item (NNNN__projeto) e a linha 1-based do parquet de positivos: commit, CVE e
       projeto conferidos elemento a elemento nos 50 do mapa_caso_item_50.csv; projeto e CVE nos
       30 do dev_set.tsv; projeto, CWE e commit (este contra split/positivos.tsv) em todos os
       itens do M_raw;
     - M_raw.tsv: 2521 itens unicos, 836 confirmados e 1685 descartados, nenhum outro valor.
  2. Moldura = M_raw menos os 50 da primeira validacao e os 30 do dev set.
  3. Sorteio ANINHADO por estrato: a moldura do estrato, em ordem crescente de id_parquet, e
     permutada com numpy.random.RandomState(semente).permutation (o gerador legado do numpy,
     de sequencia congelada); a amostra sao os n primeiros da permutacao. Aumentar o n so
     acrescenta os proximos da mesma permutacao, sem resortear.
  4. Ordem de apresentacao: os sorteados, em ordem crescente de id_parquet, permutados com a
     semente de ordem; viram os casos 01..N, com os dois estratos misturados.
  5. Monta caderno_segunda.md e anotacao_segunda.csv com o MESMO codigo de evidencia da
     primeira validacao (importa achar, txt, norm_ws, patch_url e diff_funcao do
     revisar_validacao.py; mesmo cabecalho por caso, resumo da CVE cortado em 1200 caracteres,
     diff da funcao cortado em 8000, pre-marcacao automatica de A), e a chave lacrada
     chave/chave_segunda.csv.
  6. Confere a CEGUEIRA antes de gravar: caderno e planilha nao podem conter "confirmado",
     "descartado", "camada", "estrato", nem identificador de item (NNNN__projeto).
  7. Grava e imprime o SHA-256 de cada arquivo. Nada por estrato que o anotador consiga ver no
     caderno (pre-marcados, commits ja vistos) e impresso: so totais.

O QUE NAO E
  - Nao anota nada e nao le rotulo de nenhuma validacao anterior: do mapa dos 50 usa so item,
    id_parquet, projeto, commit e CVE; do dev, so item, id, projeto e CVE. A
    saida/amostra_validacao_revisao.csv (os rotulos da primeira) nem e aberta.
  - Nao e a primeira validacao e nao reusa os 50 (nem o dev): eles saem da moldura.
  - Nao mede o ruido do BigVul bruto: mede o filtro.
  - Nao calcula precisao nem nada a partir de rotulo: a analise e outro script, escrito depois
    do congelamento do PRE_REGISTRO_SEGUNDA.md.

TRAVA
  Recusa sobrescrever anotacao_segunda.csv se ela ja tiver qualquer anotacao alem das
  pre-marcacoes automaticas de A (em tipo_ruido, cwe_correta, confianca ou observacao). Nesse
  caso nada e gravado, nem o caderno nem a chave.

USO (no WSL)
  python3 montar_segunda.py                        # monta com 30 confirmados + 20 descartados
  python3 montar_segunda.py --n-confirmados 25 --n-descartados 25
  python3 montar_segunda.py --conferir             # refaz em memoria e compara com o disco
"""

import argparse
import csv
import hashlib
import io
import os
import re
import statistics
import sys

import numpy as np
import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(AQUI))            # Dataset/bigvul
sys.dont_write_bytecode = True    # importar o revisar_validacao nao deixa __pycache__ fora desta pasta
sys.path.insert(0, BASE)
# As mesmas funcoes que geraram o caderno da primeira validacao: a evidencia sai identica.
from revisar_validacao import CAND, achar, diff_funcao, norm_ws, patch_url, txt  # noqa: E402

POSITIVOS = os.path.join(BASE, "saida", "bigvul_memoria_positivos.parquet")
M_RAW = os.path.join(BASE, "traversal", "conjuntos_v3", "M_raw.tsv")
MAPA_50 = os.path.join(BASE, "traversal", "mapa_caso_item_50.csv")
DEV = os.path.join(BASE, "traversal", "dev_set.tsv")
SPLIT = os.path.join(BASE, "traversal", "split", "positivos.tsv")
RUBRICA = os.path.join(BASE, "validacao_cega", "rubrica_v1.md")

CADERNO = os.path.join(AQUI, "caderno_segunda.md")
PLANILHA = os.path.join(AQUI, "anotacao_segunda.csv")
PASTA_CHAVE = os.path.join(AQUI, "chave")
CHAVE = os.path.join(PASTA_CHAVE, "chave_segunda.csv")
AVISO = os.path.join(PASTA_CHAVE, "NAO_ABRIR_ANTES_DE_TERMINAR.txt")

# Contagens do M_raw da v3 (traversal/TRAVERSAL_V3.md, secao 10). Se mudarem, algo mudou por baixo.
N_MRAW = 2521
N_ESPERADO = {"confirmado": 836, "descartado": 1685}
N_50, N_DEV = 50, 30
ESTRATOS = ("confirmado", "descartado")

# Sementes. A proposta inicial era 7070/7071/7072, mas a 7070 ja foi usada (ensaio da traversal
# nas negativas, 12/10/2026: traversal/rodar_traversal_negativos.py). O bloco foi deslocado uma
# unidade ANTES de qualquer sorteio; busca de 21/10/2026 em todo o TCC (.py, .md, .sh, .sc, .tex):
# 7071, 7072, 7073 e 7074 nao aparecem como semente. A 7074 e a do bootstrap da analise.
SEMENTE = {"confirmado": 7071, "descartado": 7072}
SEMENTE_ORDEM = 7073
N_PADRAO = {"confirmado": 30, "descartado": 20}

# Cortes do revisar_validacao.py (cmd_build): summ[:1200] e d[:8000].
CORTE_RESUMO, CORTE_DIFF = 1200, 8000
OBS_AUTO = "so espaco em branco / sem efeito semantico (auto)"
COLUNAS = ["id", "project", "commit_id", "cve_id", "cwe_bigvul", "commit_url", "commit_patch",
           "tipo_ruido", "cwe_correta", "confianca", "observacao"]
COLUNAS_ID = COLUNAS[:7]
COLUNAS_CHAVE = ["caso", "item", "id_parquet", "veredito", "ordem_no_estrato", "particao",
                 "commit", "commit_na_primeira", "commit_visto_em", "cve_na_primeira"]
PALAVRAS_PROIBIDAS = ("confirmado", "descartado", "camada", "estrato")
PADRAO_ITEM = re.compile(r"\d{4}__[A-Za-z0-9]")

TEXTO_AVISO = (
    "Esta pasta guarda a chave da segunda validacao: para cada caso do caderno, se o filtro de "
    "curadoria confirmou ou descartou aquela funcao - e saber isso antes de anotar puxa o "
    "julgamento na direcao do filtro e anula justamente o que esta validacao mede, o acerto do "
    "filtro julgado por quem nao sabe o que ele disse.\n"
    "Abra so depois de terminar as anotacoes e entregar a planilha para a analise, e nao edite "
    "nada aqui: o SHA-256 da chave esta no pre-registro, e o script de analise recusa rodar se "
    "ele mudar.\n"
)


# ----------------------------------------------------------------------------- utilitarios

def parar(msg):
    sys.exit("PARE: " + msg)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_arquivo(caminho):
    with open(caminho, "rb") as fh:
        return sha256_bytes(fh.read())


def ler_tabela(caminho, sep):
    return pd.read_csv(caminho, sep=sep, dtype=str, keep_default_na=False)


def numero(item):
    return int(item.split("__", 1)[0])


def gravar(caminho, conteudo):
    """Escrita atomica: grava num temporario ao lado e troca de uma vez."""
    tmp = caminho + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(conteudo)
    os.replace(tmp, caminho)


def ler_csv_tolerante(caminho):
    """Le um CSV que pode ter passado por Excel/LibreOffice (BOM, latin-1, ';', CRLF)."""
    with open(caminho, "rb") as fh:
        bruto = fh.read()
    try:
        texto = bruto.decode("utf-8-sig")
    except UnicodeDecodeError:
        texto = bruto.decode("latin-1")
    primeira = texto.splitlines()[0] if texto.strip() else ""
    delim = ";" if primeira.count(";") > primeira.count(",") else ","
    leitor = csv.DictReader(io.StringIO(texto), delimiter=delim)
    campos = [(f or "").strip() for f in (leitor.fieldnames or [])]
    linhas = []
    for r in leitor:
        linhas.append({(k or "").strip(): (v if isinstance(v, str) else "").strip()
                       for k, v in r.items() if k is not None})
    return campos, linhas


def anotacao_humana(caminho):
    """Lista as linhas da planilha que ja tem anotacao alem da pre-marcacao automatica de A.

    Lista vazia = planilha virgem (pode ser regravada). Planilha ilegivel conta como anotada:
    na duvida, nao se apaga trabalho de ninguem."""
    if not os.path.exists(caminho):
        return []
    try:
        campos, linhas = ler_csv_tolerante(caminho)
    except Exception as e:                           # noqa: BLE001
        return ["planilha ilegivel ({}) - tratada como anotada".format(e)]
    if "tipo_ruido" not in campos:
        return ["sem a coluna tipo_ruido - tratada como anotada"]
    achados = []
    for r in linhas:
        tp = r.get("tipo_ruido", "")
        cf = r.get("confianca", "")
        cc = r.get("cwe_correta", "")
        ob = r.get("observacao", "")
        auto = tp.upper() == "A" and cf == "alta" and cc == "" and ob == OBS_AUTO
        if auto:
            continue
        if tp or cf or cc or ob:
            achados.append("id {}".format(r.get("id", "?")))
    return achados


def vazamentos(texto, itens):
    """O que, no texto que o anotador vai ler, denunciaria o veredito ou o item."""
    achados = []
    baixo = texto.lower()
    for p in PALAVRAS_PROIBIDAS:
        n = baixo.count(p)
        if n:
            achados.append('palavra "{}" ({}x)'.format(p, n))
    n_itens = sum(1 for it in itens if it in texto)
    if n_itens:
        achados.append("{} identificador(es) de item da amostra".format(n_itens))
    if PADRAO_ITEM.search(texto):
        achados.append("padrao NNNN__projeto")
    return achados


# ----------------------------------------------------------------------------- entradas

def carregar_e_conferir():
    df = pd.read_parquet(POSITIVOS)
    col = {k: achar(df, k) for k in CAND}
    for k in ("before", "after", "commit", "project", "cve", "cwe", "codelink", "msg", "summary"):
        if col[k] is None:
            parar("o parquet nao tem a coluna de '{}' que o revisar_validacao.py procura".format(k))

    def campo(n, k):
        if not 1 <= n <= len(df):
            parar("id_parquet {} fora do parquet (1..{})".format(n, len(df)))
        return txt(df.iloc[n - 1][col[k]]).strip()

    # --- os 50 da primeira validacao: casamento item <-> parquet, elemento a elemento ----------
    mapa = ler_tabela(MAPA_50, ",")
    if len(mapa) != N_50 or mapa["item"].nunique() != N_50:
        parar("mapa_caso_item_50.csv deveria ter {} itens distintos".format(N_50))
    div = []
    for _, r in mapa.iterrows():
        n = int(r["id_parquet"])
        if numero(r["item"]) != n:
            div.append("caso {}: item {} != id_parquet {}".format(r["caso"], r["item"], n))
        for k, esperado in (("commit", r["commit"]), ("cve", r["cve"]), ("project", r["projeto"])):
            obtido = campo(n, k)
            if obtido != esperado.strip():
                div.append("caso {} ({}): {} do parquet {!r} != mapa {!r}"
                           .format(r["caso"], r["item"], k, obtido, esperado))
    if div:
        parar("o item NNNN nao e a linha NNNN (1-based) do parquet:\n  " + "\n  ".join(div))

    # --- os 30 do dev set ------------------------------------------------------------------
    dev = ler_tabela(DEV, "\t")
    if len(dev) != N_DEV or dev["item"].nunique() != N_DEV:
        parar("dev_set.tsv deveria ter {} itens distintos".format(N_DEV))
    div = []
    for _, r in dev.iterrows():
        n = int(r["id"])
        if numero(r["item"]) != n:
            div.append("{}: id {}".format(r["item"], n))
        for k, esperado in (("project", r["projeto"]), ("cve", r["cve"])):
            if campo(n, k) != esperado.strip():
                div.append("{}: {} diverge do parquet".format(r["item"], k))
    if div:
        parar("dev_set.tsv nao casa com o parquet:\n  " + "\n  ".join(div))
    if set(mapa["item"]) & set(dev["item"]):
        parar("o dev set intersecta os 50")

    # --- M_raw da v3 e a particao ------------------------------------------------------------
    mraw = ler_tabela(M_RAW, "\t")
    if len(mraw) != N_MRAW or mraw["item"].nunique() != N_MRAW:
        parar("M_raw.tsv deveria ter {} itens distintos; tem {} linhas".format(N_MRAW, len(mraw)))
    contagem = mraw["veredito"].value_counts().to_dict()
    if contagem != N_ESPERADO:
        parar("vereditos do M_raw {} != esperado {}".format(contagem, N_ESPERADO))
    split = ler_tabela(SPLIT, "\t").set_index("item")
    div = []
    for _, r in mraw.iterrows():
        it = r["item"]
        n = numero(it)
        proj = it.split("__", 1)[1]
        if campo(n, "project") != proj or r["projeto"] != proj:
            div.append("{}: projeto".format(it))
        if campo(n, "cwe") != r["cwe_bigvul"]:
            div.append("{}: CWE".format(it))
        if it not in split.index:
            div.append("{}: sem particao em split/positivos.tsv".format(it))
        elif split.loc[it, "commit"] != campo(n, "commit"):
            div.append("{}: commit do split != commit do parquet".format(it))
    if div:
        parar("M_raw nao casa com o parquet/split ({} divergencias):\n  {}"
              .format(len(div), "\n  ".join(div[:20])))

    return df, col, mapa, dev, mraw, split


# ----------------------------------------------------------------------------- sorteio

def sortear(mraw, mapa, dev, n_por_estrato):
    excluidos = set(mapa["item"]) | set(dev["item"])
    veredito = dict(zip(mraw["item"], mraw["veredito"]))
    moldura, saidos, amostra, ordem = {}, {}, {}, {}
    for e in ESTRATOS:
        do_estrato = [it for it, v in veredito.items() if v == e]
        saidos[e] = {"50": sum(1 for it in do_estrato if it in set(mapa["item"])),
                     "dev": sum(1 for it in do_estrato if it in set(dev["item"]))}
        itens = sorted((it for it in do_estrato if it not in excluidos), key=numero)
        moldura[e] = itens
        if n_por_estrato[e] > len(itens):
            parar("n={} maior que a moldura do estrato {} ({})".format(n_por_estrato[e], e, len(itens)))
        perm = np.random.RandomState(SEMENTE[e]).permutation(len(itens))
        permutada = [itens[i] for i in perm]
        amostra[e] = permutada[:n_por_estrato[e]]
        for pos, it in enumerate(amostra[e], start=1):
            ordem[it] = pos
    sel = sorted(amostra["confirmado"] + amostra["descartado"], key=numero)
    perm = np.random.RandomState(SEMENTE_ORDEM).permutation(len(sel))
    apresentacao = [sel[i] for i in perm]
    return veredito, moldura, saidos, amostra, ordem, apresentacao


# ----------------------------------------------------------------------------- montagem

def montar(df, col, mapa, dev, split, veredito, ordem, apresentacao):
    def campo(n, k):
        return txt(df.iloc[n - 1][col[k]])

    commits_50 = set(mapa["commit"].str.strip())
    cves_50 = set(mapa["cve"].str.strip())
    commits_dev = {campo(int(i), "commit").strip() for i in dev["id"]}
    cves_dev = {campo(int(i), "cve").strip() for i in dev["id"]}

    reg, blocos, chave, lista = [], [], [], []
    stats = {"auto_a": 0, "diff_cortado": 0, "resumo_cortado": 0, "tam_blocos": []}
    for caso, item in enumerate(apresentacao, start=1):
        n = numero(item)
        row = df.iloc[n - 1]
        antes, depois = row[col["before"]], row[col["after"]]
        link = txt(row[col["codelink"]])
        commit = txt(row[col["commit"]])
        proj = txt(row[col["project"]])
        cve = txt(row[col["cve"]])
        cwe = txt(row[col["cwe"]])
        msg = txt(row[col["msg"]])
        summ = txt(row[col["summary"]])

        # --- igual ao cmd_build do revisar_validacao.py ------------------------------------
        auto_a = norm_ws(antes) == norm_ws(depois)
        if auto_a:
            stats["auto_a"] += 1
        reg.append({
            "id": caso, "project": proj, "commit_id": commit, "cve_id": cve,
            "cwe_bigvul": cwe, "commit_url": link, "commit_patch": patch_url(link),
            "tipo_ruido": "A" if auto_a else "",
            "cwe_correta": "",
            "confianca": "alta" if auto_a else "",
            "observacao": OBS_AUTO if auto_a else "",
        })
        cab = ["## {:02d}. {}  |  {}  |  {}".format(caso, proj, cve, cwe)]
        if link:
            cab.append("- commit: {}".format(link))
            cab.append("- diff bruto: {}".format(patch_url(link)))
        if commit:
            cab.append("- commit_id: {}".format(commit))
        if msg:
            cab.append("\n**mensagem do commit**\n\n> " + msg.replace("\n", "\n> "))
        if summ:
            cab.append("\n**resumo da CVE**\n\n> " + summ[:CORTE_RESUMO].replace("\n", "\n> "))
            # unica adicao ao bloco da primeira validacao: avisar quando o corte acontece
            if len(summ) > CORTE_RESUMO:
                stats["resumo_cortado"] += 1
                cab.append("\n*(resumo cortado em {} caracteres, como na primeira validacao)*"
                           .format(CORTE_RESUMO))
        if auto_a:
            cab.append("\n**diff da funcao**: vazio apos normalizar o espaco "
                       "em branco (tipo A, ja pre-marcado)")
        else:
            d = diff_funcao(antes, depois)
            cab.append("\n**diff da funcao (func_before vs func_after)**\n\n"
                       "```diff\n" + d[:CORTE_DIFF] + "\n```")
            if len(d) > CORTE_DIFF:
                stats["diff_cortado"] += 1
                cab.append("\n*(diff cortado em {} caracteres, como na primeira validacao; o "
                           "resto esta no link do commit)*".format(CORTE_DIFF))
        bloco = "\n".join(cab)
        blocos.append(bloco)
        stats["tam_blocos"].append(len(bloco))
        lista.append("| {:02d} | {} | {} | {} |".format(caso, proj, cve, cwe))

        # --- chave (lacrada) ---------------------------------------------------------------
        c = commit.strip()
        visto = [nome for nome, conj in (("primeira", commits_50), ("dev", commits_dev)) if c in conj]
        chave.append({
            "caso": caso,
            "item": item,
            "id_parquet": n,
            "veredito": veredito[item],
            "ordem_no_estrato": ordem[item],
            "particao": split.loc[item, "particao"],
            "commit": c,
            "commit_na_primeira": "sim" if visto else "nao",
            "commit_visto_em": "+".join(visto),
            "cve_na_primeira": "sim" if cve.strip() in (cves_50 | cves_dev) else "nao",
        })

    cabecalho = (
        "# Caderno da segunda validação manual\n\n"
        "Leitura cega: este caderno não diz, e não deve dizer, o que a curadoria fez com cada "
        "função. Não abra a pasta `chave/` antes de terminar (o `LEIA_ME.md` explica por quê).\n\n"
        "**Como usar.** Para cada caso: leia a mensagem do commit e o resumo da CVE, olhe o diff "
        "da função (e, se precisar, o link do commit para ver o resto do conserto) e preencha a "
        "linha do caso em `anotacao_segunda.csv` — a coluna `id` é o número do caso. Não edite "
        "este caderno: o SHA-256 dele está no pré-registro.\n\n"
        "**Rubrica** (`../rubrica_v1.md`, congelada; a mesma da primeira validação):\n\n"
        "- **A** — sem mudança semântica na função (só espaço em branco, formatação ou "
        "comentário). Não vulnerável.\n"
        "- **B** — a função mudou, mas a mudança não tem relação com a CVE (refatoração, "
        "funcionalidade não relacionada, outro subsistema que veio junto no commit). Não "
        "vulnerável.\n"
        "- **C** — a função mudou como parte do conserto, mas o defeito explorável não está nela "
        "(ajuste de parâmetro, reset de contador, hardening de apoio, propagação de argumento). "
        "Não vulnerável.\n"
        "- **D** — a função é o sítio da vulnerabilidade: o defeito (acesso indevido, checagem de "
        "limite que falta, overflow que alimenta o tamanho) está no corpo dela. Vulnerável.\n"
        "- **?** — não deu para decidir com a evidência disponível (não chute para evitar o `?`).\n\n"
        "`confianca`: `alta`, `media` ou `baixa`. `cwe_correta`: só nos D, no formato `CWE-NNN`. "
        "`observacao`: uma ou duas frases; nos D, diga se reconheceu o bug só com a função ou se "
        "precisou do commit inteiro.\n\n"
        "Os casos cujo diff some depois de normalizar o espaço em branco já vêm marcados como "
        "**A** na planilha (confiança `alta`, observação terminada em \"(auto)\").\n\n"
        "## Casos\n\n"
        "| caso | projeto | CVE | CWE do BigVul |\n"
        "| --- | --- | --- | --- |\n"
        + "\n".join(lista) + "\n\n---\n\n"
    )
    caderno = cabecalho + "\n\n---\n\n".join(blocos) + "\n"

    planilha = pd.DataFrame(reg, columns=COLUNAS).to_csv(index=False, lineterminator="\n")

    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUNAS_CHAVE, lineterminator="\n")
    w.writeheader()
    w.writerows(chave)

    return (caderno, planilha.encode("utf-8"), buf.getvalue().encode("utf-8"),
            reg, chave, stats)


# ----------------------------------------------------------------------------- principal

def n_da_chave_em_disco():
    if not os.path.exists(CHAVE):
        parar("--conferir precisa de {} em disco".format(CHAVE))
    _, linhas = ler_csv_tolerante(CHAVE)
    return {e: sum(1 for r in linhas if r.get("veredito") == e) for e in ESTRATOS}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--n-confirmados", type=int, default=N_PADRAO["confirmado"])
    p.add_argument("--n-descartados", type=int, default=N_PADRAO["descartado"])
    p.add_argument("--conferir", action="store_true",
                   help="refaz tudo em memoria e compara com os arquivos em disco; nao grava")
    a = p.parse_args()

    df, col, mapa, dev, mraw, split = carregar_e_conferir()
    print("conferencias de entrada: ok")
    print("  item NNNN = linha NNNN (1-based) do parquet: 50/50 do mapa (commit, CVE, projeto); "
          "30/30 do dev; {} itens do M_raw (projeto, CWE, commit do split)".format(len(mraw)))

    if a.conferir:
        n_por_estrato = n_da_chave_em_disco()
        print("  --conferir: n por estrato lido da chave em disco: {} + {}"
              .format(n_por_estrato["confirmado"], n_por_estrato["descartado"]))
    else:
        n_por_estrato = {"confirmado": a.n_confirmados, "descartado": a.n_descartados}

    veredito, moldura, saidos, amostra, ordem, apresentacao = sortear(mraw, mapa, dev, n_por_estrato)
    caderno, planilha_b, chave_b, reg, chave, stats = montar(
        df, col, mapa, dev, split, veredito, ordem, apresentacao)
    caderno_b = caderno.encode("utf-8")

    # --- cegueira: nada no que o anotador le pode apontar o veredito ou o item ------------------
    itens = list(apresentacao)
    vaz = {"caderno": vazamentos(caderno, itens),
           "planilha": vazamentos(planilha_b.decode("utf-8"), itens)}
    if vaz["caderno"] or vaz["planilha"]:
        parar("vazamento no material de leitura: {}".format(vaz))
    print("cegueira: ok (sem 'confirmado', 'descartado', 'camada', 'estrato' nem NNNN__projeto "
          "no caderno e na planilha)")

    if a.conferir:
        ok = True
        for nome, caminho, novo in (("caderno", CADERNO, caderno_b), ("chave", CHAVE, chave_b)):
            if not os.path.exists(caminho):
                print("  {}: AUSENTE".format(nome))
                ok = False
                continue
            igual = sha256_arquivo(caminho) == sha256_bytes(novo)
            ok &= igual
            print("  {}: {}  sha256 {}".format(nome, "igual" if igual else "DIVERGE",
                                                sha256_arquivo(caminho)))
        if os.path.exists(PLANILHA):
            _, linhas = ler_csv_tolerante(PLANILHA)
            div = 0
            if len(linhas) != len(reg):
                div = abs(len(linhas) - len(reg)) or 1
            for r_disco, r_novo in zip(linhas, reg):
                if any(r_disco.get(c, "") != str(r_novo[c]) for c in COLUNAS_ID):
                    div += 1
            ok &= div == 0
            print("  planilha: colunas de identificacao {}  sha256 {}"
                  .format("iguais" if div == 0 else "DIVERGEM em {} linha(s)".format(div),
                          sha256_arquivo(PLANILHA)))
        else:
            print("  planilha: AUSENTE")
            ok = False
        print("conferir: {}".format("OK" if ok else "FALHOU"))
        return 0 if ok else 1

    # --- trava: nao apagar anotacao de ninguem --------------------------------------------------
    anotadas = anotacao_humana(PLANILHA)
    if anotadas:
        parar("{} ja tem anotacao alem das pre-marcacoes automaticas ({}). Nada foi gravado. "
              "Se for mesmo para recomecar, mova a planilha para outro lugar antes."
              .format(PLANILHA, ", ".join(anotadas[:10]) + (" ..." if len(anotadas) > 10 else "")))

    os.makedirs(PASTA_CHAVE, exist_ok=True)
    gravar(CADERNO, caderno_b)
    gravar(PLANILHA, planilha_b)
    gravar(CHAVE, chave_b)
    gravar(AVISO, TEXTO_AVISO.encode("utf-8"))

    # --- relatorio (so totais do que o anotador ve; nada por estrato da amostra) ----------------
    print("\nmoldura (M_raw da v3 menos os 50 e os 30):")
    for e in ESTRATOS:
        print("  {:<11} {:>5} no M_raw - {:>2} dos 50 - {:>2} do dev = {:>5} na moldura; "
              "n = {} (semente {})".format(e, N_ESPERADO[e], saidos[e]["50"], saidos[e]["dev"],
                                           len(moldura[e]), n_por_estrato[e], SEMENTE[e]))
    total = sum(len(m) for m in moldura.values())
    print("  total na moldura: {}".format(total))

    # Commit ja visto e algo que o anotador reconhece no caderno; por isso so o TOTAL da moldura,
    # nunca a quebra por estrato (seria uma pista, ainda que fraca, sobre o veredito).
    commits_conhecidos = set(mapa["commit"].str.strip()) | {
        txt(df.iloc[int(i) - 1][col["commit"]]).strip() for i in dev["id"]}
    commits_moldura = [txt(df.iloc[numero(it) - 1][col["commit"]]).strip()
                       for e in ESTRATOS for it in moldura[e]]
    nc = sum(1 for c in commits_moldura if c in commits_conhecidos)
    print("  commits distintos na moldura: {}; itens com commit ja visto (50 ou dev): {} ({:.1f}%)"
          .format(len(set(commits_moldura)), nc, 100.0 * nc / len(commits_moldura)))

    print("\namostra: {} casos (ordem de apresentacao: semente {})".format(len(reg), SEMENTE_ORDEM))
    print("  commits distintos: {}".format(len({r["commit_id"] for r in reg})))
    print("  CVEs distintas: {}".format(len({r["cve_id"] for r in reg})))
    print("  projetos distintos: {}".format(len({r["project"] for r in reg})))
    print("  commit_na_primeira = sim: {} (total, sem quebra por estrato)"
          .format(sum(1 for c in chave if c["commit_na_primeira"] == "sim")))
    print("  cve_na_primeira = sim: {} (total)"
          .format(sum(1 for c in chave if c["cve_na_primeira"] == "sim")))
    print("  pre-marcados como A (auto): {}".format(stats["auto_a"]))
    print("  diffs cortados em {}: {}; resumos cortados em {}: {}".format(
        CORTE_DIFF, stats["diff_cortado"], CORTE_RESUMO, stats["resumo_cortado"]))
    tb = stats["tam_blocos"]
    print("  caderno: {} caracteres ({} bytes); bloco por caso: min {}, mediana {:.0f}, max {}"
          .format(len(caderno), len(caderno_b), min(tb), statistics.median(tb), max(tb)))
    print("  blocos com mais de 4000 caracteres: {}".format(sum(1 for t in tb if t > 4000)))

    print("\nSHA-256:")
    for nome, caminho in (("caderno_segunda.md", CADERNO), ("anotacao_segunda.csv", PLANILHA),
                          ("chave/chave_segunda.csv", CHAVE),
                          ("chave/NAO_ABRIR_ANTES_DE_TERMINAR.txt", AVISO),
                          ("../rubrica_v1.md", RUBRICA),
                          ("montar_segunda.py", os.path.abspath(__file__))):
        print("  {}  {}".format(sha256_arquivo(caminho), nome))
    return 0


if __name__ == "__main__":
    sys.exit(main())
