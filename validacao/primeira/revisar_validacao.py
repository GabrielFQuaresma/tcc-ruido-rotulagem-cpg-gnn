#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apoio a validacao manual de rotulos do BigVul.

O link do commit ja existe nos dados, na coluna codeLink/ref_link do BigVul, que
e a URL do proprio commit. E o BigVul guarda func_before E func_after, entao da
para ver o que mudou DENTRO da funcao sem abrir a web. Este script junta as duas
coisas num caderno de leitura e numa planilha enxuta de registro.

Dois modos:

  1. build (padrao): le o arquivo de positivos salvo pelo preparar_bigvul.py,
     reproduz a mesma amostra (mesmo --seed e --sample-size do run original) e
     gera:
       - amostra_validacao_revisao.csv : planilha enxuta para anotar, com link do
         commit e a coluna tipo_ruido (mais confianca e observacao);
       - caderno_revisao.md : caderno para ler, com mensagem do commit, resumo da
         CVE, link e o diff de cada funcao (func_before vs func_after) inline.

       python revisar_validacao.py build \
           --positivos saida/bigvul_memoria_positivos.parquet \
           --outdir saida --sample-size 50 --seed 42

  2. tally: le a planilha preenchida e calcula o ruido, derivando o veredito do
     tipo_ruido (so D conta como vulneravel).

       python revisar_validacao.py tally --csv saida/amostra_validacao_revisao.csv

TIPOS DE RUIDO (coluna tipo_ruido):
  A = sem mudanca semantica na funcao (so espaco em branco/formatacao/comentario).
      Pre-preenchido quando func_before e func_after sao iguais apos normalizar o
      espaco em branco. Categoria documentada: o BigVul carrega correcoes que so
      mexeram em espaco em branco como se fossem de seguranca.
  B = a funcao mudou, mas a mudanca NAO tem relacao com a CVE (refatoracao,
      funcionalidade nao relacionada). Ex.: ReadCLIPBOARDImage na varredura de
      SetImageExtent. Nao vulneravel.
  C = a funcao mudou como parte do conserto, mas NAO e o sitio do bug (ajuste de
      parametros, reset de contador, hardening de apoio). Ex.: ih264d_start_of_pic.
      Nao vulneravel.
  D = a funcao E o sitio da vulnerabilidade, reconhecivel aqui. Vulneravel.
  ? = nao deu para decidir.

  Para os D, vale anotar na observacao se voce reconheceu o bug so com a funcao
  ou se precisou do contexto do arquivo. Isso liga direto com a decisao de usar o
  arquivo inteiro como unidade de analise.

  cwe_correta: preencher SO nos D. Nos A/B/C a funcao nao e vulneravel, entao nao
  ha CWE a corrigir. Nos D, sirve para pegar a funcao vulneravel cuja CWE real cai
  FORA da familia de erro de memoria, que e o caso que ameaca o recorte inicial.

  A, B e C sao todos NAO vulneravel, por motivos diferentes. So o D entra na conta
  de positivo verdadeiro. Os ? ficam de fora e sao reportados a parte.
"""

import argparse
import difflib
import os
import re
import sys

import pandas as pd

CAND = {
    "vul": ["vul", "target", "label", "is_vul"],
    "cwe": ["cwe_id", "cwe id", "cwe", "cweid"],
    "before": ["func_before", "func", "processed_func", "code", "function"],
    "after": ["func_after", "func_fixed", "func_post", "target_func"],
    "commit": ["commit_id", "commit", "commit_hash", "hash"],
    "project": ["project", "repo", "project_name"],
    "msg": ["commit_message", "message", "commit_msg"],
    "summary": ["summary", "cve_summary", "description"],
    "cve": ["cve_id", "cve id", "cve"],
    "codelink": ["codelink", "code_link", "ref_link", "commit_url", "url"],
}


def achar(df, chave):
    mapa = {c.lower().strip(): c for c in df.columns}
    for nome in CAND[chave]:
        if nome in mapa:
            return mapa[nome]
    return None


def ler(caminho):
    if caminho.lower().endswith((".parquet", ".pq")):
        return pd.read_parquet(caminho)
    return pd.read_csv(caminho, encoding="latin-1")


def txt(v):
    if v is None:
        return ""
    s = str(v)
    return "" if s.lower() in ("nan", "none") else s


def norm_ws(s):
    """Colapsa todo espaco em branco (espacos, tabs, quebras) num espaco so.
    Duas funcoes que so diferem em formatacao ficam iguais depois disto."""
    return re.sub(r"\s+", " ", txt(s)).strip()


def patch_url(codelink):
    """GitHub e GitLab aceitam .patch no fim da URL do commit para ver o diff
    cru. Gitiles (android.googlesource) usa ^! para abrir o diff no navegador."""
    u = txt(codelink)
    if not u:
        return ""
    if "github.com" in u or "gitlab" in u:
        return u.rstrip("/") + ".patch"
    if "googlesource.com" in u:
        return u.rstrip("/") + "^!"
    return u


def diff_funcao(antes, depois):
    a = txt(antes).splitlines()
    b = txt(depois).splitlines()
    return "\n".join(difflib.unified_diff(a, b, fromfile="func_before",
                                          tofile="func_after", lineterm=""))


def cmd_build(args):
    df = ler(args.positivos)
    col = {k: achar(df, k) for k in CAND}
    if col["before"] is None:
        sys.exit("ERRO: nao achei a coluna func_before no arquivo de positivos.")
    tem_after = col["after"] is not None
    if not tem_after:
        print("AVISO: sem coluna func_after. Nao da para gerar o diff por funcao "
              "nem pre-marcar o tipo A. Use o link do commit para julgar.")
    if col["codelink"] is None:
        print("AVISO: sem coluna de link. O caderno sai sem URL de commit.")

    n = min(args.sample_size, len(df))
    val = df.sample(n=n, random_state=args.seed).reset_index(drop=True)

    os.makedirs(args.outdir, exist_ok=True)
    reg, blocos, n_auto_a = [], [], 0
    for i, row in val.iterrows():
        rid = i + 1
        antes = row[col["before"]] if col["before"] else ""
        depois = row[col["after"]] if tem_after else ""
        link = txt(row[col["codelink"]]) if col["codelink"] else ""
        commit = txt(row[col["commit"]]) if col["commit"] else ""
        proj = txt(row[col["project"]]) if col["project"] else ""
        cve = txt(row[col["cve"]]) if col["cve"] else ""
        cwe = txt(row[col["cwe"]]) if col["cwe"] else ""
        msg = txt(row[col["msg"]]) if col["msg"] else ""
        summ = txt(row[col["summary"]]) if col["summary"] else ""

        # Pre-marca tipo A so quando a funcao nao mudou de forma semantica.
        auto_a = tem_after and norm_ws(antes) == norm_ws(depois)
        if auto_a:
            n_auto_a += 1

        reg.append({
            "id": rid, "project": proj, "commit_id": commit, "cve_id": cve,
            "cwe_bigvul": cwe, "commit_url": link, "commit_patch": patch_url(link),
            "tipo_ruido": "A" if auto_a else "",
            "cwe_correta": "",  # preencher SO nos D (funcao de fato vulneravel)
            "confianca": "alta" if auto_a else "",
            "observacao": "so espaco em branco / sem efeito semantico (auto)" if auto_a else "",
        })

        cab = [f"## {rid:02d}. {proj}  |  {cve}  |  {cwe}"]
        if link:
            cab.append(f"- commit: {link}")
            cab.append(f"- diff bruto: {patch_url(link)}")
        if commit:
            cab.append(f"- commit_id: {commit}")
        if msg:
            cab.append("\n**mensagem do commit**\n\n> " + msg.replace("\n", "\n> "))
        if summ:
            cab.append("\n**resumo da CVE**\n\n> " + summ[:1200].replace("\n", "\n> "))
        if tem_after:
            if auto_a:
                cab.append("\n**diff da funcao**: vazio apos normalizar o espaco "
                           "em branco (tipo A, ja pre-marcado)")
            else:
                d = diff_funcao(antes, depois)
                cab.append("\n**diff da funcao (func_before vs func_after)**\n\n"
                           "```diff\n" + d[:8000] + "\n```")
        else:
            cab.append("\n**diff da funcao**: indisponivel (sem func_after), "
                       "abra o link do commit")
        blocos.append("\n".join(cab))

    csv_out = os.path.join(args.outdir, "amostra_validacao_revisao.csv")
    pd.DataFrame(reg).to_csv(csv_out, index=False)

    md_out = os.path.join(args.outdir, "caderno_revisao.md")
    cabecalho = ("# Caderno de revisao de rotulos\n\n"
                 "Para cada item: leia a mensagem do commit e o resumo da CVE, "
                 "olhe o diff da funcao (e o link do commit para o contexto dos "
                 "outros arquivos) e preencha tipo_ruido na planilha.\n\n"
                 "A = sem mudanca semantica | B = mudou mas irrelevante a CVE | "
                 "C = mudou como apoio ao conserto, nao e o sitio | "
                 "D = vulneravel, sitio do bug aqui | ? = duvidoso.\n\n---\n\n")
    with open(md_out, "w", encoding="utf-8") as f:
        f.write(cabecalho + "\n\n---\n\n".join(blocos) + "\n")

    print(f"Itens na amostra: {len(reg)}")
    if tem_after:
        print(f"Pre-marcados como tipo A (sem mudanca semantica): {n_auto_a}")
    print(f"Planilha: {csv_out}")
    print(f"Caderno : {md_out}")


# A planilha e preenchida a mao: 'alta'/'alto', 'media'/'média'/'medio'.
# Sem normalizar, a comparacao == "alta" descarta linhas por grafia.
MAPA_CONF = {
    "alta": "alta", "alto": "alta",
    "media": "media", "medio": "media", "média": "media", "médio": "media",
    "baixa": "baixa", "baixo": "baixa",
}


def cmd_tally(args):
    # pandas grava UTF-8; ler em latin-1 vira mojibake nos acentos.
    try:
        df = pd.read_csv(args.csv, encoding="utf-8-sig")
    except UnicodeDecodeError:
        df = pd.read_csv(args.csv, encoding="latin-1")
    for c in ["tipo_ruido", "confianca"]:
        if c not in df.columns:
            sys.exit(f"ERRO: a planilha nao tem a coluna {c}.")
    df["_tp"] = df["tipo_ruido"].apply(lambda s: str(s).strip().upper())
    df["_cf"] = df["confianca"].apply(
        lambda s: MAPA_CONF.get(str(s).strip().lower(), ""))
    desconhecidas = sorted({str(s).strip() for s, n in
                            zip(df["confianca"], df["_cf"]) if not n
                            and str(s).strip().lower() not in ("", "nan")})
    if desconhecidas:
        print(f"AVISO: confianca nao reconhecida em {len(desconhecidas)} grafia(s): "
              f"{desconhecidas} — essas linhas ficam fora do recorte 'alta'.\n")

    total = len(df)
    indecisos = int((df["_tp"].isin(["?", "", "NAN"])).sum())
    altos = df[df["_cf"] == "alta"]
    n_alta = len(altos)
    vul_alta = int((altos["_tp"] == "D").sum())

    print(f"Total revisado: {total}")
    print(f"Sem decisao (? ou em branco): {indecisos}")
    print("\nPor tipo (todos):")
    for t in ["A", "B", "C", "D", "?"]:
        print(f"  {t}: {int((df['_tp'] == t).sum())}")
    print(f"\nSo com confianca alta: {n_alta} itens")
    if n_alta:
        acc = 100.0 * vul_alta / n_alta
        print(f"  vulneraveis verdadeiros (D): {vul_alta}")
        print(f"  acuracia de rotulo do BigVul estimada: {acc:.1f}% "
              f"({vul_alta}/{n_alta})")
        print(f"  ruido estimado (A+B+C): {100 - acc:.1f}%")

    # CWE so faz sentido conferir nos D (funcao de fato vulneravel).
    ds = df[df["_tp"] == "D"].copy()
    if len(ds) and "cwe_correta" in df.columns and "cwe_bigvul" in df.columns:
        nb = lambda s: str(s).strip().upper()
        ds["_cc"] = ds["cwe_correta"].apply(nb)
        ds["_cb"] = ds["cwe_bigvul"].apply(nb)
        com_cc = ds[~ds["_cc"].isin(["", "NAN"])]
        trocou = com_cc[com_cc["_cc"] != com_cc["_cb"]]
        print(f"\nCWE nos D ({len(ds)} funcoes vulneraveis):")
        print(f"  com cwe_correta preenchida: {len(com_cc)}")
        print(f"  reatribuida (correta != BigVul): {len(trocou)}")
        for _, r in trocou.iterrows():
            print(f"    id {r.get('id', '?')}: {r['_cb']} -> {r['_cc']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="monta caderno e planilha de revisao")
    b.add_argument("--positivos", required=True)
    b.add_argument("--outdir", default="saida")
    b.add_argument("--sample-size", type=int, default=50)
    b.add_argument("--seed", type=int, default=42,
                   help="use o MESMO seed do run do preparar_bigvul.py")
    b.set_defaults(func=cmd_build)
    t = sub.add_parser("tally", help="calcula o ruido a partir da planilha preenchida")
    t.add_argument("--csv", required=True)
    t.set_defaults(func=cmd_tally)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
