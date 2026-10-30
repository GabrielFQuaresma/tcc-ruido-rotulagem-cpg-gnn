#!/usr/bin/env python3
"""Monta o dev set da Etapa 4a: 30 positivos, semente 7, disjunto dos 50 do teste.

Os 50 casos anotados sao o unico conjunto de teste honesto que existe. O dev set
existe para ABSORVER OS OLHARES: toda conferencia minima que sairia dos 50 sai
daqui. Por isso a primeira coisa que este script faz e provar a disjuncao.

    python3 montar_dev_set.py                 # imprime e grava dev_set.tsv

O id da pasta em saida_final/itens/NNNN__proj e a posicao 1-based da linha no
parquet de positivos (o preparar_bigvul.py rodou sem --shuffle). Este script
NAO confia nisso: confere contra o caso de regressao antes de usar.
"""

import argparse
import os
import sys

import pandas as pd

AQUI = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(AQUI)

# Semente e tamanho dos 50: fixados no preparar_bigvul.py, sao o teste final.
SEED_TESTE, N_TESTE = 42, 50
# Semente do dev: qualquer uma != 42. O 7 ja e a semente do lote da Etapa 3.
SEED_DEV, N_DEV = 7, 30

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
    p.add_argument("--itens", default=os.path.join(BASE, "saida_final", "itens"))
    p.add_argument("--saida", default=os.path.join(AQUI, "dev_set.tsv"))
    args = p.parse_args()

    df = pd.read_parquet(args.positivos)
    c_commit = coluna(df, "commit_id", "commit")
    c_proj = coluna(df, "project", "repo")
    c_cve = coluna(df, "cve id", "cve_id")
    c_cwe = coluna(df, "cwe id", "cwe_id", "_cwe")

    # --- 1. o id da pasta e mesmo a posicao 1-based no parquet? ------------------
    id_ancora = int(ANCORA[0].split("__")[0])
    obtido = str(df.iloc[id_ancora - 1][c_commit]).strip()
    if obtido != ANCORA[1]:
        sys.exit("ERRO: o mapeamento id<->parquet nao vale mais.\n"
                 "  esperado {} na linha {}\n  obtido   {}"
                 .format(ANCORA[1], id_ancora - 1, obtido))
    print("mapeamento id<->parquet: ok (ancora {})".format(ANCORA[0]))

    # --- 2. as duas amostras, e a prova de disjuncao -----------------------------
    teste = df.sample(n=N_TESTE, random_state=SEED_TESTE)
    dev = df.sample(n=N_DEV, random_state=SEED_DEV)
    ids_teste = set(int(i) + 1 for i in teste.index)
    ids_dev = [int(i) + 1 for i in sorted(dev.index)]

    intersec = sorted(ids_teste & set(ids_dev))
    if intersec:
        sys.exit("ERRO: dev set intersecta os 50 nos ids {}".format(intersec))
    print("intersecao dev x teste (por funcao): vazia — ok")

    # Disjuncao por funcao nao e disjuncao por commit. Um commit de fan-out alto
    # coloca funcoes irmas nos dois conjuntos, e elas compartilham contexto. Nao e
    # motivo para reamostrar (mexer na amostra depois de ver a sobreposicao e a
    # mesma doenca que o dev set existe para evitar) — e motivo para declarar.
    com_teste = set(teste[c_commit].astype(str).str.strip())
    dev = dev.copy()
    dev["_irmao"] = dev[c_commit].astype(str).str.strip().isin(com_teste)
    n_irmaos = int(dev["_irmao"].sum())
    print("dev com commit tambem presente no teste: {} de {}".format(n_irmaos, N_DEV))

    # --- 3. as pastas existem? ---------------------------------------------------
    pastas = {int(d.split("__")[0]): d for d in os.listdir(args.itens) if "__" in d}
    faltando = [i for i in ids_dev if i not in pastas]
    if faltando:
        sys.exit("ERRO: sem pasta em saida_final/itens para os ids {}".format(faltando))

    # --- 4. gravar ---------------------------------------------------------------
    dev = dev.assign(_id=[int(i) + 1 for i in dev.index]).sort_values("_id")
    linhas = ["item\tid\tprojeto\tcve\tcwe\tirmao_de_commit_do_teste"]
    for _, r in dev.iterrows():
        linhas.append("\t".join([
            pastas[r["_id"]], str(r["_id"]), str(r[c_proj]),
            str(r[c_cve]), str(r[c_cwe]), "sim" if r["_irmao"] else "nao",
        ]))
    with open(args.saida, "w", encoding="utf-8") as fh:
        fh.write("\n".join(linhas) + "\n")
    print("\n{} itens gravados em {}".format(N_DEV, args.saida))
    for l in linhas[1:]:
        print("  " + l.replace("\t", "  "))
    return 0


if __name__ == "__main__":
    sys.exit(main())
