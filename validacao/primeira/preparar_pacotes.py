#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monta os pacotes de evidencia CEGOS para o segundo anotador (modelo).

Cego = o pacote nao contem, em lugar nenhum, o rotulo do anotador humano. Este
script nem abre o CSV preenchido, exceto no modo --conferir, que compara apenas
as colunas de identificacao (project/commit/cve) para provar que a amostra foi
reproduzida corretamente. As colunas tipo_ruido / confianca / observacao nunca
sao lidas.

A amostra e reproduzida do MESMO jeito que revisar_validacao.py build a produz:
df.sample(n=<sample-size>, random_state=<seed>), com os mesmos parametros do run
original (50 / 42). O diff da funcao usa a mesma normalizacao e o mesmo corte de
8000 caracteres do caderno_revisao.md, para que a evidencia bata com a que o
humano leu.

Contexto do commit inteiro: vem da coluna `files_changed` do proprio BigVul, que
carrega, por arquivo do commit, um JSON no estilo da API do GitHub (filename,
status, additions, deletions, patch), separados por '<_**next**_>'. Nao e
preciso baixar nada por HTTP. Cinco dos cinquenta casos nao tem essa coluna
preenchida; nesses o pacote declara a ausencia em vez de fingir.

Duas condicoes:

  cve_visivel (primaria) - mesma evidencia que o humano tinha.
  cve_oculta  (secundaria) - sem CVE ID, sem resumo da CVE, sem mensagem de
              commit, sem URLs e sem hash. Sonda o quanto a concordancia
              depende de memorizacao da CVE publica.

Uso:

  python3 preparar_pacotes.py \
      --positivos ../saida/bigvul_memoria_positivos.parquet \
      --outdir . --sample-size 50 --seed 42 --condicao cve_visivel

  python3 preparar_pacotes.py ... --condicao cve_oculta
  python3 preparar_pacotes.py ... --conferir ../saida/amostra_validacao_revisao.csv
"""

import argparse
import csv
import difflib
import hashlib
import json
import os
import re
import sys

import pandas as pd

SEP_ARQ = "<_**next**_>"
CORTE_DIFF = 8000      # mesmo corte do caderno_revisao.md
CORTE_RESUMO = 1200    # mesmo corte do caderno_revisao.md

COLUNAS = ["commit_id", "project", "CVE ID", "CWE ID", "codeLink", "commit_message",
           "Summary", "file_name", "files_changed", "func_before", "func_after"]


def txt(v):
    if v is None:
        return ""
    try:
        if pd.isna(v):
            return ""
    except (TypeError, ValueError):
        pass
    s = str(v)
    return "" if s.strip().lower() in ("nan", "none", "<na>") else s


def norm_ws(s):
    return re.sub(r"\s+", " ", txt(s)).strip()


def diff_funcao(antes, depois):
    a = txt(antes).splitlines()
    b = txt(depois).splitlines()
    return "\n".join(difflib.unified_diff(a, b, fromfile="func_before",
                                          tofile="func_after", lineterm=""))


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


def sha256_texto(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def parse_arquivos(blob):
    """files_changed -> lista de dicts. Blocos que nao parseiam viram None e sao
    contados, nunca silenciosamente descartados."""
    bruto = txt(blob)
    if not bruto:
        return [], 0
    itens, falhas = [], 0
    for bloco in bruto.split(SEP_ARQ):
        bloco = bloco.strip()
        if not bloco:
            continue
        try:
            d = json.loads(bloco)
            if isinstance(d, dict):
                itens.append(d)
            else:
                falhas += 1
        except (json.JSONDecodeError, ValueError):
            falhas += 1
    return itens, falhas


def render_contexto(arquivos, alvo, orcamento, ocultar_url):
    """Tabela de todos os arquivos + patch por arquivo ate estourar o orcamento.
    O arquivo que contem a funcao marcada vem primeiro e nunca e cortado por
    prioridade (so pelo orcamento global)."""
    if not arquivos:
        return "_O BigVul nao traz o diff do commit completo para este caso._"

    def nome(d):
        return txt(d.get("filename") or d.get("file_name"))

    alvo_norm = txt(alvo).strip().lstrip("./")
    ordenado = sorted(
        arquivos,
        key=lambda d: (0 if alvo_norm and nome(d).strip().lstrip("./") == alvo_norm else 1),
    )

    linhas = [f"Arquivos tocados pelo commit: **{len(arquivos)}**", "",
              "| arquivo | status | + | - |", "| --- | --- | --- | --- |"]
    for d in arquivos:
        marca = " **(funcao marcada esta aqui)**" if (
            alvo_norm and nome(d).strip().lstrip("./") == alvo_norm) else ""
        linhas.append(f"| `{nome(d)}`{marca} | {txt(d.get('status'))} | "
                      f"{txt(d.get('additions'))} | {txt(d.get('deletions'))} |")
    linhas.append("")

    gasto = sum(len(x) for x in linhas)
    incluidos, omitidos = 0, 0
    corpo = []
    for d in ordenado:
        patch = txt(d.get("patch"))
        if not patch:
            omitidos += 1
            continue
        cabecalho = f"\n### `{nome(d)}`\n\n```diff\n"
        bloco = cabecalho + patch + "\n```\n"
        if gasto + len(bloco) > orcamento and incluidos > 0:
            omitidos += 1
            continue
        if gasto + len(bloco) > orcamento:      # primeiro arquivo ja estoura: trunca
            sobra = max(0, orcamento - gasto - len(cabecalho) - 64)
            bloco = cabecalho + patch[:sobra] + "\n[... patch truncado ...]\n```\n"
        corpo.append(bloco)
        gasto += len(bloco)
        incluidos += 1

    linhas.extend(corpo)
    if omitidos:
        linhas.append(f"\n_[{omitidos} arquivo(s) do commit omitido(s) do diff "
                      f"por limite de tamanho; todos aparecem na tabela acima.]_")
    saida = "\n".join(linhas)
    if ocultar_url:
        saida = re.sub(r"https?://\S+", "[url removida]", saida)
    return saida


def montar_pacote(rid, row, rubrica, condicao, orcamento):
    oculta = condicao == "cve_oculta"

    projeto = txt(row["project"])
    cve = txt(row["CVE ID"])
    cwe = txt(row["CWE ID"])
    commit = txt(row["commit_id"])
    link = txt(row["codeLink"])
    msg = txt(row["commit_message"])
    resumo = txt(row["Summary"])[:CORTE_RESUMO]
    arquivo = txt(row["file_name"])
    antes, depois = row["func_before"], row["func_after"]

    auto_a = norm_ws(antes) == norm_ws(depois)
    arquivos, falhas = parse_arquivos(row["files_changed"])

    p = ["# Pacote de anotacao — caso %02d" % rid, "",
         "Voce e o segundo anotador de um estudo de confiabilidade sobre ruido de",
         "rotulagem no dataset BigVul. Leia a rubrica, leia a evidencia, e devolva",
         "o veredito no formato exigido. Julgue somente com a evidencia abaixo.", "",
         "---", "", rubrica.strip(), "", "---", "",
         "# Evidencia do caso %02d" % rid, ""]

    p.append("## Identificacao")
    p.append("")
    if oculta:
        p.append("- projeto: _[removido nesta condicao]_")
        p.append("- CVE: _[removida nesta condicao]_")
        p.append(f"- CWE atribuida pelo BigVul: {cwe or '_ausente_'}")
        p.append(f"- arquivo da funcao marcada: `{arquivo or '_ausente_'}`")
    else:
        p.append(f"- projeto: {projeto or '_ausente_'}")
        p.append(f"- CVE: {cve or '_ausente_'}")
        p.append(f"- CWE atribuida pelo BigVul: {cwe or '_ausente_'}")
        p.append(f"- commit: `{commit or '_ausente_'}`")
        if link:
            p.append(f"- URL do commit: {link}")
        p.append(f"- arquivo da funcao marcada: `{arquivo or '_ausente_'}`")
    p.append("")

    if not oculta:
        p.append("## Mensagem do commit")
        p.append("")
        p.append(("> " + msg.replace("\n", "\n> ")) if msg
                 else "_Nao disponivel neste registro._")
        p.append("")
        p.append("## Resumo da CVE")
        p.append("")
        p.append(("> " + resumo.replace("\n", "\n> ")) if resumo
                 else "_Nao disponivel neste registro._")
        p.append("")

    p.append("## Diff da funcao marcada (func_before vs func_after)")
    p.append("")
    if auto_a:
        p.append("As duas versoes da funcao sao **identicas apos normalizar o espaco**")
        p.append("**em branco** — o diff semantico e vazio.")
        p.append("")
        p.append("```diff")
        p.append(diff_funcao(antes, depois)[:CORTE_DIFF] or "(diff textual vazio)")
        p.append("```")
    else:
        p.append("```diff")
        p.append(diff_funcao(antes, depois)[:CORTE_DIFF])
        p.append("```")
    p.append("")

    p.append("## Corpo completo da funcao antes da correcao")
    p.append("")
    p.append("```c")
    p.append(txt(antes)[:CORTE_DIFF * 3])
    p.append("```")
    p.append("")

    p.append("## Contexto: o commit inteiro")
    p.append("")
    p.append(render_contexto(arquivos, arquivo, orcamento, ocultar_url=oculta))
    if falhas:
        p.append(f"\n_[{falhas} bloco(s) de metadados de arquivo nao puderam ser "
                 f"lidos e foram omitidos.]_")
    p.append("")

    p.append("---")
    p.append("")
    p.append("Responda **apenas** com o objeto JSON descrito no contrato de saida.")
    p.append("Nada antes, nada depois, sem cercas de codigo.")
    p.append("")

    texto = "\n".join(p)
    meta = {
        "id": rid,
        "condicao": condicao,
        "project": projeto,
        "commit_id": commit,
        "cve_id": cve,
        "cwe_bigvul": cwe,
        "file_name": arquivo,
        "pre_marcado_auto_a": int(auto_a),
        "n_arquivos_commit": len(arquivos),
        "tem_contexto_commit": int(bool(arquivos)),
        "blocos_ilegiveis": falhas,
        "chars_pacote": len(texto),
        "sha256_pacote": sha256_texto(texto),
    }
    return texto, meta


def conferir(val, caminho_csv):
    """Prova que a amostra reproduzida bate com o CSV do humano, olhando SO as
    colunas de identificacao. Nunca le tipo_ruido / confianca / observacao."""
    try:
        ref = pd.read_csv(caminho_csv, encoding="utf-8",
                          usecols=["id", "project", "commit_id", "cve_id"])
    except UnicodeDecodeError:
        ref = pd.read_csv(caminho_csv, encoding="latin-1",
                          usecols=["id", "project", "commit_id", "cve_id"])
    ref = ref.sort_values("id").reset_index(drop=True)
    if len(ref) != len(val):
        return [f"tamanhos diferem: CSV={len(ref)} amostra={len(val)}"]
    problemas = []
    for i in range(len(val)):
        esperado = (txt(ref.loc[i, "project"]), txt(ref.loc[i, "commit_id"]),
                    txt(ref.loc[i, "cve_id"]))
        obtido = (txt(val.loc[i, "project"]), txt(val.loc[i, "commit_id"]),
                  txt(val.loc[i, "CVE ID"]))
        if esperado != obtido:
            problemas.append(f"linha {i+1}: CSV={esperado} != amostra={obtido}")
    return problemas


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--positivos", required=True)
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--rubrica", default=None,
                    help="padrao: <outdir>/rubrica_v1.md")
    ap.add_argument("--sample-size", type=int, default=50)
    ap.add_argument("--seed", type=int, default=42,
                    help="use o MESMO seed do run do revisar_validacao.py")
    ap.add_argument("--condicao", choices=["cve_visivel", "cve_oculta"],
                    default="cve_visivel")
    ap.add_argument("--orcamento-contexto", type=int, default=120000,
                    help="teto de caracteres da secao de contexto do commit")
    ap.add_argument("--conferir", default=None,
                    help="CSV do humano, so para validar a reproducao da amostra")
    args = ap.parse_args()

    rubrica_path = args.rubrica or os.path.join(args.outdir, "rubrica_v1.md")
    if not os.path.exists(rubrica_path):
        sys.exit(f"ERRO: rubrica nao encontrada em {rubrica_path}")
    with open(rubrica_path, encoding="utf-8") as f:
        rubrica = f.read()
    rubrica_sha = sha256_arquivo(rubrica_path)

    df = pd.read_parquet(args.positivos, columns=COLUNAS)
    n = min(args.sample_size, len(df))
    val = df.sample(n=n, random_state=args.seed).reset_index(drop=True)

    if args.conferir:
        problemas = conferir(val, args.conferir)
        if problemas:
            print("FALHA na conferencia da amostra:")
            for p in problemas:
                print("  -", p)
            sys.exit(1)
        print(f"Conferencia OK: as {n} linhas batem com {args.conferir} "
              f"em project/commit_id/cve_id.")

    destino = os.path.join(args.outdir, "pacotes", args.condicao)
    os.makedirs(destino, exist_ok=True)

    metas = []
    for i, row in val.iterrows():
        rid = i + 1
        texto, meta = montar_pacote(rid, row, rubrica, args.condicao,
                                    args.orcamento_contexto)
        meta["rubrica_sha256"] = rubrica_sha
        caminho = os.path.join(destino, f"caso_{rid:02d}.md")
        with open(caminho, "w", encoding="utf-8", newline="\n") as f:
            f.write(texto)
        metas.append(meta)

    manifesto = os.path.join(args.outdir, f"manifesto_{args.condicao}.csv")
    with open(manifesto, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(metas[0].keys()))
        w.writeheader()
        w.writerows(metas)

    tam = [m["chars_pacote"] for m in metas]
    sem_ctx = [m["id"] for m in metas if not m["tem_contexto_commit"]]
    auto = [m["id"] for m in metas if m["pre_marcado_auto_a"]]
    print(f"\nCondicao       : {args.condicao}")
    print(f"Pacotes        : {len(metas)} em {destino}")
    print(f"Manifesto      : {manifesto}")
    print(f"Rubrica sha256 : {rubrica_sha}")
    print(f"Tamanho (chars): min={min(tam)} mediana={sorted(tam)[len(tam)//2]} "
          f"max={max(tam)}")
    print(f"Sem contexto de commit no BigVul: {len(sem_ctx)} caso(s) {sem_ctx}")
    print(f"Pre-marcados A por normalizacao : {len(auto)} caso(s) {auto}")


if __name__ == "__main__":
    main()
