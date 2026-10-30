#!/usr/bin/env python3
"""Etapa 5, passo 2 — monta o conjunto de teste dos 50 e o mapa caso_NN -> NNNN__projeto.

Sem este mapa a Etapa 5 nao existe: a evidencia da curadoria e indexada por `NNNN__projeto`
(posicao 1-based da linha no parquet de positivos) e a anotacao humana e indexada por `id`
1..50 (a ordem de `df.sample(n=50, random_state=42)`). Sao a mesma amostra em duas ordens
diferentes, e juntar na mao seria pedir para errar.

    python3 montar_teste_50.py

DIFERENCA PARA O DEV (o `conferir_pacotes_dev.py`): la o casamento foi por MULTICONJUNTO
`(commit, cve)`, porque o mapa foi reconstruido a partir do manifesto dos pacotes. Aqui da
para fazer melhor. O `revisar_validacao.py build` grava `id = i + 1` na ordem exata de
`df.sample`, entao a conferencia e ELEMENTO A ELEMENTO: a linha `id=i` do CSV anotado tem
que ter o mesmo `commit_id`, `cve_id` e `project` da i-esima linha da amostra. Se as 50
baterem, o mapa e a propria ordem — nao ha empate para desempatar. O script falha em vez de
continuar se uma unica linha divergir.

ESTE SCRIPT NAO LE ROTULO. Ele usa `amostra_validacao_revisao.csv` so pelas colunas de
identificacao (`id`, `project`, `commit_id`, `cve_id`). A coluna `tipo_ruido` so e tocada
pelo `etapa_5.py`, depois do congelamento conferido.
"""

import argparse
import csv
import os
import sys

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(AQUI)

SEED_TESTE, N_TESTE = 42, 50          # fixados no preparar_bigvul.py / revisar_validacao.py
SEED_DEV, N_DEV = 7, 30               # o dev da Etapa 4a, so para reconferir a disjuncao

# Ancora do mapeamento id <-> linha do parquet. E o caso do artigo, ja em disco.
ANCORA = ("1217__libgd", "fb0e0cce0b9f25389ab56604c3547351617e1415")


def coluna(df, *nomes):
    mapa = {c.lower().strip(): c for c in df.columns}
    for n in nomes:
        if n in mapa:
            return mapa[n]
    sys.exit("ERRO: nenhuma destas colunas existe no parquet: {}".format(nomes))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--positivos",
                   default=os.path.join(BASE, "saida", "bigvul_memoria_positivos.parquet"))
    p.add_argument("--anotacao",
                   default=os.path.join(BASE, "saida", "amostra_validacao_revisao.csv"))
    p.add_argument("--itens", default=os.path.join(BASE, "saida_final", "itens"))
    p.add_argument("--tsv", default=os.path.join(AQUI, "teste_50.tsv"))
    p.add_argument("--mapa", default=os.path.join(AQUI, "mapa_caso_item_50.csv"))
    args = p.parse_args()

    df = pd.read_parquet(args.positivos)
    c_commit = coluna(df, "commit_id", "commit")
    c_proj = coluna(df, "project", "repo")
    c_cve = coluna(df, "cve id", "cve_id")
    c_cwe = coluna(df, "cwe id", "cwe_id", "_cwe")

    # --- 1. o id da pasta e mesmo a posicao 1-based no parquet? --------------------
    id_ancora = int(ANCORA[0].split("__")[0])
    obtido = str(df.iloc[id_ancora - 1][c_commit]).strip()
    if obtido != ANCORA[1]:
        sys.exit("ERRO: o mapeamento id<->parquet nao vale mais.\n"
                 "  esperado {} na linha {}\n  obtido   {}"
                 .format(ANCORA[1], id_ancora - 1, obtido))
    print("mapeamento id<->parquet: ok (ancora {})".format(ANCORA[0]))

    # --- 2. a amostra dos 50, na ordem em que foi anotada --------------------------
    teste = df.sample(n=N_TESTE, random_state=SEED_TESTE)
    anot = pd.read_csv(args.anotacao, encoding="utf-8-sig")
    if len(anot) != N_TESTE:
        sys.exit("ERRO: {} tem {} linhas, esperava {}".format(args.anotacao, len(anot), N_TESTE))

    divergencias = []
    for i, (_, linha_parquet) in enumerate(teste.iterrows(), start=1):
        linha_csv = anot[anot["id"] == i]
        if len(linha_csv) != 1:
            divergencias.append("id={}: {} linhas no CSV".format(i, len(linha_csv)))
            continue
        r = linha_csv.iloc[0]
        for campo, col_csv, col_pq in (("commit", "commit_id", c_commit),
                                       ("cve", "cve_id", c_cve),
                                       ("projeto", "project", c_proj)):
            a = str(r[col_csv]).strip()
            b = str(linha_parquet[col_pq]).strip()
            if a != b:
                divergencias.append("id={} {}: CSV {!r} != parquet {!r}".format(i, campo, a, b))
    if divergencias:
        print("ERRO: a ordem do CSV anotado nao e a de df.sample(50, random_state=42).")
        for d in divergencias[:20]:
            print("  " + d)
        sys.exit(1)
    print("ordem do CSV anotado == ordem de df.sample(50, seed 42): ok (50/50 elemento a elemento)")

    # --- 3. reconferencia da disjuncao com o dev ----------------------------------
    dev = df.sample(n=N_DEV, random_state=SEED_DEV)
    intersec = sorted(set(teste.index) & set(dev.index))
    if intersec:
        sys.exit("ERRO: o dev intersecta os 50 nos indices {}".format(intersec))
    print("intersecao dev x teste (por funcao): vazia — ok")

    # Disjuncao por funcao nao e disjuncao por commit: o fan-out coloca funcoes irmas
    # nos dois lados. Ja declarado na Etapa 4a; aqui so se conta do lado do teste.
    com_dev = set(dev[c_commit].astype(str).str.strip())
    teste = teste.copy()
    teste["_irmao"] = teste[c_commit].astype(str).str.strip().isin(com_dev)
    print("teste com commit tambem presente no dev: {} de {}"
          .format(int(teste["_irmao"].sum()), N_TESTE))

    # --- 4. as pastas de contexto existem? ----------------------------------------
    # Faltar pasta e uma das 45 perdas de reconstrucao ja declaradas: o item fica sem
    # evidencia e sai da conta, nao vira descartado.
    pastas = {int(d.split("__")[0]): d for d in os.listdir(args.itens) if "__" in d}
    ids = [int(i) + 1 for i in teste.index]
    faltando = [i for i in ids if i not in pastas]
    if faltando:
        print("sem pasta em saida_final/itens (perdas de download ja declaradas): {}"
              .format(faltando))

    # --- 5. gravar ----------------------------------------------------------------
    linhas = []
    for caso, (idx, r) in enumerate(teste.iterrows(), start=1):
        item_id = int(idx) + 1
        linhas.append({
            "caso": caso,
            "item": pastas.get(item_id, ""),
            "id_parquet": item_id,
            "projeto": str(r[c_proj]).strip(),
            "commit": str(r[c_commit]).strip(),
            "cve": str(r[c_cve]).strip(),
            "cwe": str(r[c_cwe]).strip(),
            "irmao_de_commit_do_dev": "sim" if r["_irmao"] else "nao",
        })

    with open(args.mapa, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(linhas[0].keys()))
        w.writeheader()
        w.writerows(linhas)

    com_pasta = [l for l in linhas if l["item"]]
    with open(args.tsv, "w", encoding="utf-8") as fh:
        fh.write("item\tid\tcaso\tprojeto\tcve\tcwe\n")
        for l in sorted(com_pasta, key=lambda x: x["id_parquet"]):
            fh.write("{}\t{}\t{}\t{}\t{}\t{}\n".format(
                l["item"], l["id_parquet"], l["caso"], l["projeto"], l["cve"], l["cwe"]))

    print("\nmapa completo (50 linhas) em {}".format(args.mapa))
    print("lista para o runner ({} itens com pasta) em {}".format(len(com_pasta), args.tsv))
    for l in linhas:
        print("  caso_{:02d}  {:<24} {:<16} {}".format(
            l["caso"], l["item"] or "(sem pasta)", l["cve"], l["projeto"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
