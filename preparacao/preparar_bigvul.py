#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prepara o BigVul para o pipeline de CPG, em um passo so:

  1. filtra as funcoes positivas (vul == 1) das CWEs de erro de memoria;
  2. aplica um teto de quantidade (--limit); use --limit 0 para processar tudo;
  3. para cada item, salva LADO A LADO a funcao isolada (func_before) e o
     arquivo inteiro afetado na versao anterior a correcao;
  4. gera uma amostra para validacao manual de rotulos.

A busca do arquivo inteiro fica no modulo buscar_arquivo.py, que resolve o
codeLink do BigVul em uma URL HTTP direta por familia de forge (github,
googlesource, gitweb e cgit) e baixa so o arquivo, na versao <sha>^. A versao
anterior deste script clonava o repositorio inteiro para rodar
"git show <sha>^:<arquivo>", o que era caro e falhava nos forges menores, cujo
endpoint de clone nao responde por HTTP.

ATENCAO ao --limit sem --shuffle. O BigVul vem ordenado por projeto, entao as
primeiras N linhas nao sao representativas: as primeiras 200 caem inteiras em
savannah/php/ghostscript/qemu, que sao 100% dos casos sem file_name e os unicos
hosts problematicos, embora sejam apenas 8,4% do conjunto. Para um teste
pequeno que reflita o conjunto, use --shuffle.

Uso tipico:
  python preparar_bigvul.py --input all_c_cpp_release2.0.csv --outdir saida --limit 0

Teste rapido numa amostra representativa:
  python preparar_bigvul.py --input ... --outdir saida --limit 100 --shuffle

Para so filtrar e salvar as funcoes, sem baixar nada:
  python preparar_bigvul.py --input ... --outdir saida --skip-download

Dependencias: pandas, pyarrow (se parquet), requests.
  pip install pandas pyarrow requests --break-system-packages
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

from buscar_arquivo import Sessao, buscar_arquivos_do_commit

CWES_ALVO_PADRAO = ["CWE-119", "CWE-120", "CWE-125", "CWE-787"]
EXT_CODIGO = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")

CANDIDATOS = {
    "vul": ["vul", "target", "label", "is_vul"],
    "cwe": ["cwe_id", "cwe id", "cwe", "cweid"],
    "func": ["func_before", "func", "processed_func", "code", "function"],
    "commit": ["commit_id", "commit", "commit_hash", "hash"],
    "project": ["project", "repo", "project_name"],
    "msg": ["commit_message", "message", "commit_msg"],
    "summary": ["summary", "cve_summary", "description"],
    "cve": ["cve_id", "cve id", "cve"],
    "codelink": ["codelink", "code_link", "ref_link", "commit_url", "url"],
    "filename": ["file_name", "filename", "file", "filepath", "file_path"],
}

def detectar_zip(caminho):
    with open(caminho, "rb") as fh:
        return fh.read(4) == b"PK\x03\x04"


def ler_em_blocos(caminho, chunksize=50000):
    """Le um CSV, ou um CSV dentro de ZIP, em blocos, para nao carregar tudo na
    memoria de uma vez. Usa latin-1, que e rapido e nunca falha em bytes fora de
    UTF-8. Acentos podem ficar trocados, o que nao afeta o filtro por CWE nem a
    geracao dos CPGs."""
    comp = "zip" if detectar_zip(caminho) else "infer"
    if comp == "zip":
        print("Arquivo e um ZIP (assinatura PK). Lendo o CSV de dentro dele.")
    return pd.read_csv(caminho, compression=comp, encoding="latin-1",
                       chunksize=chunksize)


def achar(df, chave):
    mapa = {c.lower().strip(): c for c in df.columns}
    for nome in CANDIDATOS[chave]:
        if nome in mapa:
            return mapa[nome]
    return None


def extrair_cwes(valor):
    if valor is None:
        return []
    return re.findall(r"CWE-\d+", str(valor).upper())


def safe(s):
    return re.sub(r"[^\w.-]", "_", str(s))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--outdir", default="saida_bigvul")
    ap.add_argument("--cwes", nargs="+", default=CWES_ALVO_PADRAO)
    ap.add_argument("--limit", type=int, default=200,
                    help="teto de itens (0 = todos). Sem --shuffle pega as "
                         "primeiras N, que NAO sao representativas do conjunto")
    ap.add_argument("--sample-size", type=int, default=50,
                    help="tamanho da amostra de validacao manual")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--shuffle", action="store_true",
                    help="embaralha antes de aplicar o teto, em vez de pegar as primeiras")
    ap.add_argument("--skip-download", action="store_true",
                    help="so filtra e salva func_before, sem baixar arquivo")
    ap.add_argument("--jobs", type=int, default=8,
                    help="downloads simultaneos (o gargalo e rede, nao CPU)")
    ap.add_argument("--todos-arquivos", action="store_true",
                    help="salva todos os arquivos de codigo do commit, nao so o primeiro")
    ap.add_argument("--sem-parquet", action="store_true",
                    help="nao reexporta o parquet de positivos (centenas de MB)")
    ap.add_argument("--retomar", action="store_true",
                    help="tenta so os itens que ainda nao tem arquivo baixado")
    args = ap.parse_args()

    cwes_alvo = {c.upper() for c in args.cwes}
    os.makedirs(args.outdir, exist_ok=True)
    itens_dir = os.path.join(args.outdir, "itens")
    os.makedirs(itens_dir, exist_ok=True)

    def bate(v):
        return any(t in cwes_alvo for t in extrair_cwes(v))

    print(f"Lendo {args.input} ...")
    col = None
    if args.input.lower().endswith((".parquet", ".pq")):
        # Parquet e colunar e rapido; carrega direto.
        df = pd.read_parquet(args.input)
        col = {k: achar(df, k) for k in CANDIDATOS}
        for k in ["vul", "cwe", "func"]:
            if col[k] is None:
                sys.exit(f"ERRO: coluna '{k}' nao encontrada. Ajuste CANDIDATOS.")
        print("Colunas usadas:", {k: v for k, v in col.items() if v})
        vul = pd.to_numeric(df[col["vul"]], errors="coerce").fillna(0).astype(int)
        pos = df[vul == 1]
        sub = pos[pos[col["cwe"]].apply(bate)].copy()
        total_linhas = len(df)
    else:
        # CSV ou ZIP: le em blocos, filtrando em cada um. Nao carrega tudo.
        partes = []
        total_linhas = 0
        for i, bloco in enumerate(ler_em_blocos(args.input)):
            if col is None:
                col = {k: achar(bloco, k) for k in CANDIDATOS}
                for k in ["vul", "cwe", "func"]:
                    if col[k] is None:
                        sys.exit(f"ERRO: coluna '{k}' nao encontrada. Ajuste CANDIDATOS.")
                print("Colunas usadas:", {k: v for k, v in col.items() if v})
                if not args.skip_download and not col["codelink"]:
                    print("AVISO: coluna codelink ausente. Vou usar so o mapa de projetos.")
            total_linhas += len(bloco)
            vbloco = pd.to_numeric(bloco[col["vul"]], errors="coerce").fillna(0).astype(int)
            posb = bloco[vbloco == 1]
            achados = posb[posb[col["cwe"]].apply(bate)]
            if len(achados):
                partes.append(achados)
            n = sum(len(p) for p in partes)
            print(f"  bloco {i + 1}: {total_linhas} linhas lidas, "
                  f"{n} positivas nas CWEs alvo", end="\r")
        print()
        sub = pd.concat(partes, ignore_index=True) if partes else pd.DataFrame()

    print(f"Linhas totais: {total_linhas}")
    print(f"Positivas nas CWEs alvo: {len(sub)}")
    if len(sub) == 0:
        sys.exit("Nenhuma linha bateu. Verifique a coluna de CWE.")

    def cwe_norm(v):
        ts = [t for t in extrair_cwes(v) if t in cwes_alvo]
        return ts[0] if ts else "OUTRO"

    sub["_cwe"] = sub[col["cwe"]].apply(cwe_norm)
    print("Por CWE:\n" + sub["_cwe"].value_counts().to_string())

    # Subconjunto completo salvo para referencia. Sao centenas de MB, e reescrever
    # a cada execucao custa minutos quando a saida esta em /mnt/c pelo WSL. Quando
    # o proprio parquet ja e a entrada, nao ha o que reexportar.
    destino_pq = os.path.join(args.outdir, "bigvul_memoria_positivos.parquet")
    entrada_e_parquet = args.input.lower().endswith((".parquet", ".pq"))
    if args.sem_parquet or (entrada_e_parquet and os.path.exists(destino_pq)):
        print("Reexportacao do parquet de positivos: pulada.")
    else:
        try:
            sub.drop(columns=["_cwe"]).to_parquet(destino_pq, index=False)
        except Exception:
            sub.drop(columns=["_cwe"]).to_csv(
                os.path.join(args.outdir, "bigvul_memoria_positivos.csv"), index=False)

    # Amostra de validacao manual, tirada do conjunto inteiro filtrado.
    n_val = min(args.sample_size, len(sub))
    val = sub.sample(n=n_val, random_state=args.seed).reset_index(drop=True)
    vdf = pd.DataFrame({"id": range(1, len(val) + 1)})
    for nome, chave in [("project", "project"), ("commit_id", "commit"),
                        ("cve_id", "cve")]:
        if col[chave]:
            vdf[nome] = val[col[chave]].values
    vdf["cwe_bigvul"] = val["_cwe"].values
    if col["msg"]:
        vdf["commit_message"] = val[col["msg"]].astype(str).str.slice(0, 2000).values
    if col["summary"]:
        vdf["cve_summary"] = val[col["summary"]].astype(str).str.slice(0, 2000).values
    vdf["func_before"] = val[col["func"]].astype(str).str.slice(0, 6000).values
    for c in ["e_vulneravel", "cwe_correta", "confianca", "observacao"]:
        vdf[c] = ""
    vdf.to_csv(os.path.join(args.outdir, "amostra_validacao_manual.csv"), index=False)
    print(f"Amostra de validacao salva ({len(vdf)} funcoes).")

    # Aplica o teto para a extracao de codigo.
    alvo = sub.sample(frac=1, random_state=args.seed) if args.shuffle else sub
    if args.limit and args.limit > 0:
        alvo = alvo.head(args.limit)
    alvo = alvo.reset_index(drop=True)
    teto = args.limit if args.limit and args.limit > 0 else "sem teto"
    print(f"\nProcessando {len(alvo)} itens ({teto})...")
    if args.limit and args.limit > 0 and not args.shuffle:
        print("  AVISO: sem --shuffle, estas sao as PRIMEIRAS linhas, que o BigVul"
              " agrupa por projeto e nao representam o conjunto.")

    # Uma tarefa por item. A funcao isolada e escrita na hora; o arquivo inteiro
    # depende de rede e vai para o pool de threads. Como o gargalo e espera de
    # I/O, e nao CPU, threads resolvem bem e sem complicar o codigo.
    def preparar_item(i, row):
        rid = i + 1
        proj = str(row[col["project"]]) if col["project"] else "projeto"
        sha = str(row[col["commit"]]).strip() if col["commit"] else ""
        pasta = os.path.join(itens_dir, f"{rid:04d}__{safe(proj)}")
        os.makedirs(pasta, exist_ok=True)

        with open(os.path.join(pasta, "func_before.c"), "w",
                  encoding="utf-8", errors="replace") as f:
            f.write(str(row[col["func"]]))

        meta = {"id": rid, "project": proj, "commit_id": sha,
                "cwe_bigvul": row["_cwe"], "arquivo_inteiro": None,
                "status_download": "skip", "familia": None,
                "origem_paths": None, "n_arquivos": 0}
        if col["cve"]:
            meta["cve_id"] = str(row[col["cve"]])
        if col["filename"]:
            meta["file_name"] = str(row[col["filename"]])
        if col["codelink"]:
            meta["codelink"] = str(row[col["codelink"]])
        return rid, pasta, meta, row

    def ja_tem_arquivo(pasta):
        try:
            return any(n.startswith("arquivo__") for n in os.listdir(pasta))
        except OSError:
            return False

    def baixar(pasta, meta, row):
        codelink = str(row[col["codelink"]]) if col["codelink"] else ""
        sha = meta["commit_id"]
        fn = row[col["filename"]] if col["filename"] else ""
        res = buscar_arquivos_do_commit(codelink, sha, fn, sessao=sessao,
                                        so_um=not args.todos_arquivos,
                                        funcao=str(row[col["func"]])[:4000])
        meta["familia"] = res.familia
        meta["origem_paths"] = res.origem_paths
        meta["status_download"] = res.status
        if res.detalhe:
            meta["detalhe"] = res.detalhe
        for caminho, conteudo in res.arquivos:
            destino = os.path.join(pasta, "arquivo__" + safe(os.path.basename(caminho)))
            with open(destino, "w", encoding="utf-8", errors="replace") as f:
                f.write(conteudo)
            meta["arquivo_inteiro"] = os.path.basename(destino)
            meta["caminho_no_repo"] = caminho
        meta["n_arquivos"] = len(res.arquivos)
        return meta

    tarefas = [preparar_item(i, row) for i, row in alvo.iterrows()]
    relatorio = [t[2] for t in tarefas]
    print(f"  funcoes isoladas salvas: {len(tarefas)}")

    if not args.skip_download:
        sessao = Sessao(conexoes=args.jobs)
        por_id = {m["id"]: m for m in relatorio}
        feitos = ok = 0
        t0 = time.time()
        pendentes = [t for t in tarefas if t[2]["commit_id"]]
        if args.retomar:
            antes = len(pendentes)
            prontos = []
            for rid, pasta, meta, row in list(pendentes):
                if not ja_tem_arquivo(pasta):
                    continue
                # Recupera o meta.json da execucao anterior. Sem isso, o relatorio
                # final perderia familia, caminho e origem dos itens ja baixados,
                # que sao justamente os numeros que vao para o texto.
                try:
                    with open(os.path.join(pasta, "meta.json"), encoding="utf-8") as f:
                        meta.update({k: v for k, v in json.load(f).items()
                                     if v is not None})
                except (OSError, ValueError):
                    pass
                if not str(meta.get("status_download", "")).startswith("ok"):
                    meta["status_download"] = "ok_ja_existia"
                prontos.append((rid, pasta, meta, row))
            feitos_antes = {t[0] for t in prontos}
            pendentes = [t for t in pendentes if t[0] not in feitos_antes]
            print(f"  --retomar: {antes - len(pendentes)} ja tinham arquivo, "
                  f"{len(pendentes)} a tentar")
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futuros = {pool.submit(baixar, pasta, meta, row): rid
                       for rid, pasta, meta, row in pendentes}
            for fut in as_completed(futuros):
                feitos += 1
                try:
                    m = fut.result()
                except Exception as e:      # nao deixa um item derrubar o lote
                    m = por_id[futuros[fut]]
                    m["status_download"] = "erro"
                    m["detalhe"] = f"{type(e).__name__}: {e}"[:200]
                if str(m["status_download"]).startswith("ok"):
                    ok += 1
                if feitos % 25 == 0 or feitos == len(futuros):
                    taxa = feitos / max(time.time() - t0, 0.1)
                    resta = (len(futuros) - feitos) / max(taxa, 0.01)
                    print(f"  baixando: {feitos}/{len(futuros)}  ok={ok}  "
                          f"{taxa:.1f} itens/s  faltam ~{resta/60:.0f} min")
        print()

    rel = pd.DataFrame(relatorio)
    rel.to_csv(os.path.join(args.outdir, "relatorio_extracao.csv"), index=False)
    for _, pasta, meta, _ in tarefas:
        with open(os.path.join(pasta, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    print("\nResumo:")
    print(f"  funcoes isoladas salvas: {len(tarefas)}")
    if not args.skip_download:
        sucesso = rel["status_download"].astype(str).str.startswith("ok")
        n_ok = int(sucesso.sum())
        print(f"  arquivos inteiros salvos: {n_ok} de {len(rel)} "
              f"({100 * n_ok / max(len(rel), 1):.1f}%)")
        print("\n  por status:")
        for k, v in rel["status_download"].value_counts().items():
            print(f"    {k:22s} {v}")
        print("\n  por familia de forge:")
        for k, v in rel["familia"].fillna("(nao detectada)").value_counts().items():
            print(f"    {str(k):22s} {v}")
        print("\n  origem do caminho do arquivo:")
        for k, v in rel["origem_paths"].fillna("(nenhuma)").value_counts().items():
            print(f"    {str(k):22s} {v}")
        if sessao.recusas_429:
            print("\n  recusas 429 (limite de taxa do host):")
            for h, n in sessao.recusas_429.most_common():
                print(f"    {h:34s} {n}")
        if sessao.hosts_mortos:
            print("\n  hosts dados como fora do ar:")
            for h in sorted(sessao.hosts_mortos):
                print(f"    {h}")
        falhas = rel[~sucesso]
        if len(falhas):
            print(f"\n  projetos com falha ({len(falhas)} itens):")
            for k, v in falhas["project"].value_counts().head(12).items():
                print(f"    {str(k):22s} {v}")
    print(f"\nSaida em: {itens_dir}")
    print("Cada pasta tem func_before.c, o arquivo inteiro (quando baixado) e meta.json.")


if __name__ == "__main__":
    main()
