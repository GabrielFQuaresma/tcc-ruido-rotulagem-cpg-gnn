#!/usr/bin/env python3
"""Etapa 5, passo 1 — congela as regras da curadoria com SHA-256.

O QUE ESTE SCRIPT PROTEGE. A precisao do filtro so vale como medida se a regra tiver
sido escrita ANTES de ver os 50 casos anotados. "Antes" nao e uma promessa: e um hash.
Este script tira o SHA-256 de cada arquivo de regra e grava em CONGELAMENTO.md. A partir
daqui, qualquer edicao em qualquer um deles muda o hash, e a divergencia aparece no
proximo `--conferir` e no diff do git.

    python3 congelar.py --gravar      # grava o congelamento (uma vez so)
    python3 congelar.py               # confere; sai !=0 se algum hash divergir

O QUE E REGRA. Exatamente a lista REGRAS do rodar_curadoria.py — importada daqui, nao
copiada, para as duas nao poderem divergir em silencio. Sao os quatro arquivos que
decidem o veredito: a traversal, as duas tabelas de dados e o .toml. O veredito.py NAO
entra: ele so aplica a regra, e precisa poder nomear o caso de regressao. Escriturario,
nao regra.

O CONGELAMENTO NAO E BACKUP. Ele nao impede a edicao; ele torna a edicao visivel. Se uma
regra precisar mesmo mudar depois daqui, o caminho honesto e: mudar, regravar o
congelamento com --forcar, e registrar no RESULTADO.md que a medida dos 50 foi refeita
sob outra regra. O que nao e defensavel e mudar e nao contar.
"""

import argparse
import datetime
import hashlib
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)
from rodar_curadoria import REGRAS_POR_VERSAO, teste_generalidade  # noqa: E402

# UM CONGELAMENTO POR VERSAO (05/10/2026, TRAVERSAL_V3.md). O da v2 e a prova de que a regra
# veio antes dos 50 (Etapa 5): congelamento.tsv e CONGELAMENTO.md NUNCA sao regravados — nem com
# --forcar. A v3 tem os seus arquivos. Cada script confere a versao que usa: etapa_5.py e
# montar_split.py a v2 (padrao); a montagem dos bracos da v3, a v3.
ARQUIVOS = {
    "v2": ("congelamento.tsv", "CONGELAMENTO.md"),
    "v3": ("congelamento_v3.tsv", "CONGELAMENTO_V3.md"),
}
INTOCAVEIS = {"v2"}


def caminhos(versao):
    tsv, md = ARQUIVOS[versao]
    return os.path.join(AQUI, tsv), os.path.join(AQUI, md)


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as fh:
        for bloco in iter(lambda: fh.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


def hashes_atuais(versao="v2"):
    """[(caminho_relativo, sha256, bytes)] na ordem das regras da versao."""
    saida = []
    for rel in REGRAS_POR_VERSAO[versao]:
        caminho = os.path.join(AQUI, rel)
        if not os.path.exists(caminho):
            sys.exit("ERRO: arquivo de regra ausente: {}".format(rel))
        saida.append((rel, sha256_arquivo(caminho), os.path.getsize(caminho)))
    return saida


def ler_congelamento(versao="v2"):
    """{caminho_relativo: (sha256, bytes)} do TSV gravado, ou None se nao existe."""
    TSV, _ = caminhos(versao)
    if not os.path.exists(TSV):
        return None
    congelado = {}
    with open(TSV, encoding="utf-8") as fh:
        cab = fh.readline()
        if not cab.startswith("arquivo\t"):
            sys.exit("ERRO: {} tem cabecalho inesperado".format(TSV))
        for linha in fh:
            if not linha.strip():
                continue
            rel, sha, tam = linha.rstrip("\n").split("\t")
            congelado[rel] = (sha, int(tam))
    return congelado


def conferir(silencioso=False, versao="v2"):
    """0 se o congelamento da versao existe e bate; 1 caso contrario."""
    congelado = ler_congelamento(versao)
    if congelado is None:
        print("FALHA: nao ha congelamento da {}. Rode `python3 congelar.py --versao {} "
              "--gravar` antes.".format(versao, versao))
        return 1

    atuais = hashes_atuais(versao)
    problemas = []
    if set(congelado) != {rel for rel, _, _ in atuais}:
        so_no_tsv = sorted(set(congelado) - {rel for rel, _, _ in atuais})
        so_agora = sorted({rel for rel, _, _ in atuais} - set(congelado))
        problemas.append("a lista de arquivos de regra mudou desde o congelamento "
                         "(so no congelamento: {} | so agora: {})".format(so_no_tsv, so_agora))
    for rel, sha, tam in atuais:
        if rel not in congelado:
            continue
        sha_c, tam_c = congelado[rel]
        if sha != sha_c:
            problemas.append("{}\n    congelado {}\n    agora     {}".format(rel, sha_c, sha))
        elif tam != tam_c:
            problemas.append("{}: hash igual e tamanho diferente — impossivel, "
                             "confira o TSV".format(rel))

    if problemas:
        print("FALHA na conferencia do congelamento:")
        for p in problemas:
            print("  " + p)
        print("\nUm arquivo de regra mudou depois do congelamento. Ou a mudanca foi acidental\n"
              "e tem que voltar, ou foi deliberada e a medida dos 50 precisa ser refeita e\n"
              "declarada como tal. Nao ha terceira saida.")
        return 1

    if not silencioso:
        print("congelamento {}: ok — {} arquivos de regra conferem".format(versao, len(atuais)))
        for rel, sha, _ in atuais:
            print("  {:<34} {}".format(rel, sha[:16] + "..."))
    return 0


def texto_md_v3(agora, atuais):
    """O CONGELAMENTO_V3.md. Curto: o porque esta no TRAVERSAL_V3.md."""
    linhas = [
        "# Congelamento da traversal v3",
        "",
        "Gravado em **{}** por `congelar.py --versao v3 --gravar`, **antes** da rodada da v3."
        .format(agora),
        "",
        "É a foto da v3, ao lado da da v2 (`CONGELAMENTO.md`, 10/08/2026), que **não** foi",
        "regravada e continua provando que a regra da Etapa 5 veio antes dos 50. O que mudou da",
        "v2 para a v3, por quê, e o que se previu antes de rodar: `TRAVERSAL_V3.md`.",
        "",
        "| arquivo | sha256 | bytes |",
        "| --- | --- | --- |",
    ]
    for rel, sha, tam in atuais:
        linhas.append("| `{}` | `{}` | {} |".format(rel, sha, tam))
    linhas += [
        "",
        "Só o `.sc` muda em relação à v2; as duas tabelas de `dados/` e o `regra_veredito.toml`",
        "têm de ter o mesmo SHA-256 do congelamento da v2. A tabela `identificacao_v3.tsv` não",
        "é regra (traz id de item); o SHA-256 dela está no adendo do `TRAVERSAL_V3.md`.",
        "",
    ]
    return linhas


def gravar(forcar, versao="v2"):
    TSV, MD = caminhos(versao)
    if os.path.exists(TSV) and versao in INTOCAVEIS:
        print("FALHA: {} ja existe e e intocavel.".format(os.path.basename(TSV)))
        print("       E a prova de que a regra da Etapa 5 veio antes dos 50. Para uma regra")
        print("       nova, crie uma versao nova (REGRAS_POR_VERSAO e ARQUIVOS) — nunca regrave.")
        return 1
    if os.path.exists(TSV) and not forcar:
        print("FALHA: {} ja existe.".format(os.path.basename(TSV)))
        print("       Congelar de novo apaga a foto anterior desta versao. Se a regra mudou de")
        print("       proposito, use --forcar e registre o desvio no TRAVERSAL_V3.md.")
        return 1

    achados = teste_generalidade(versao)
    if achados:
        print("FALHA no teste de generalidade — nao se congela regra que viola a invariante:")
        for arq, linha, trecho in achados:
            print("  {}:{}  {}".format(arq, linha, trecho))
        return 1
    print("teste de generalidade ({}): ok".format(versao))

    atuais = hashes_atuais(versao)
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    with open(TSV, "w", encoding="utf-8") as fh:
        fh.write("arquivo\tsha256\tbytes\n")
        for rel, sha, tam in atuais:
            fh.write("{}\t{}\t{}\n".format(rel, sha, tam))

    if versao != "v2":
        with open(MD, "w", encoding="utf-8") as fh:
            fh.write("\n".join(texto_md_v3(agora, atuais)))
        print("\ncongelado em {} e {}:".format(os.path.basename(TSV), os.path.basename(MD)))
        for rel, sha, tam in atuais:
            print("  {:<34} {}  ({} bytes)".format(rel, sha, tam))
        return 0

    linhas = [
        "# Congelamento das regras da curadoria — Etapa 5, passo 1",
        "",
        "Gravado em **{}** por `congelar.py --gravar`.".format(agora),
        "",
        "A precisão do filtro só vale como medida se a regra tiver sido escrita **antes** de",
        "ver os 50 casos anotados. \"Antes\" não é uma promessa: é este hash. Daqui em diante,",
        "qualquer edição em qualquer um destes arquivos muda o SHA-256, e a divergência aparece",
        "em `congelar.py --conferir` e no diff do git.",
        "",
        "| arquivo | sha256 | bytes |",
        "| --- | --- | --- |",
    ]
    for rel, sha, tam in atuais:
        linhas.append("| `{}` | `{}` | {} |".format(rel, sha, tam))
    linhas += [
        "",
        "## O que está congelado, e o que não está",
        "",
        "Congelado é **regra**: o que decide o veredito. A traversal (`curadoria_v2.sc`), as duas",
        "tabelas de dados que ela consulta, e a `regra_veredito.toml`, que transforma evidência em",
        "veredito. A lista é importada de `rodar_curadoria.py` (`REGRAS`), não copiada — as duas",
        "não podem divergir em silêncio.",
        "",
        "**Não** está congelado o `veredito.py`: ele só aplica a regra e precisa poder nomear o",
        "caso de regressão para tirá-lo da estatística. Escriturário, não regra. Também não estão",
        "os runners nem os `.md` de registro.",
        "",
        "## O que este congelamento permite fazer, e só agora",
        "",
        "Rodar a curadoria nos **50 casos anotados** (`saida/amostra_validacao_revisao.csv`) e",
        "comparar o veredito com os rótulos humanos. Até este arquivo existir, nenhum arquivo dos",
        "50 podia ser lido — é a regra de método que a Etapa 4a e a 4b existiram para respeitar.",
        "",
        "Invertida a ordem, o número não vale nada.",
        "",
    ]
    with open(MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(linhas))

    print("\ncongelado em {} e {}:".format(os.path.basename(TSV), os.path.basename(MD)))
    for rel, sha, tam in atuais:
        print("  {:<34} {}  ({} bytes)".format(rel, sha, tam))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--gravar", action="store_true", help="grava o congelamento")
    p.add_argument("--conferir", action="store_true", help="confere (padrao)")
    p.add_argument("--forcar", action="store_true",
                   help="regrava por cima de um congelamento existente (nunca vale para a v2)")
    p.add_argument("--versao", default="v2", choices=sorted(ARQUIVOS))
    args = p.parse_args()

    if args.gravar:
        return gravar(args.forcar, args.versao)
    return conferir(versao=args.versao)


if __name__ == "__main__":
    sys.exit(main())
