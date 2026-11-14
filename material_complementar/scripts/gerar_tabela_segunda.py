#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gera as duas tabelas da segunda validação manual no Apêndice B, direto do resultado da abertura.

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/gerar_tabela_segunda.py

ONDE ESTAMOS. Conferência de 30/10/2026, depois da segunda validação (commit fd08354). O pré-registro
dela (validacao_cega/segunda/PRE_REGISTRO_SEGUNDA.md) manda reportar a tabela completa A/B/C/D/? por
estrato (§7.6) e as sensibilidades da §8 junto com a análise principal. O texto das Seções 3.4 e 4.2
já tinha os números principais, mas as duas tabelas não estavam no artigo.

O QUE O SCRIPT FAZ. Só lê. (1) Confere que os três arquivos de entrada da abertura (pré-registro,
planilha anotada e chave) têm hoje o mesmo SHA-256 gravado no congelamento_segunda.tsv e no próprio
resultado_segunda.json; se algum divergir, para sem gravar nada. (2) Lê a tabela por estrato e as
sensibilidades do resultado_segunda.json e escreve secoes/apendice_tab_segunda.tex, com o SHA-256 do
JSON no cabeçalho. Os números saem com uma casa decimal e vírgula, como no resultado_segunda.md.

O QUE ELE NÃO É. Não calcula medida nenhuma e não abre a chave de novo. Rodar de novo dá o mesmo
arquivo.
"""
import csv
import hashlib
import json
import sys

PASTA = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul/validacao_cega/segunda/"
RESULTADO = PASTA + "resultado_segunda.json"
CONGELAMENTO = PASTA + "congelamento_segunda.tsv"
SAIDA = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/secoes/apendice_tab_segunda.tex"


def sha(caminho):
    with open(caminho, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


r = json.load(open(RESULTADO, encoding="utf-8"))
congelados = {}
for linha in csv.DictReader(open(CONGELAMENTO, encoding="utf-8"), delimiter="\t"):
    congelados.setdefault(linha["arquivo"], linha["sha256"])

for arquivo, esperado in r["entradas_sha256"].items():
    atual = sha(PASTA + arquivo)
    if atual != esperado or congelados.get(arquivo) != esperado:
        sys.exit(f"SHA-256 divergente em {arquivo}; nada foi gravado")


def pct(x):
    return f"{x:.1f}".replace(".", ",") + "\\%"


def pontos(x):
    return ("+" if x >= 0 else "$-$") + f"{abs(x):.1f}".replace(".", ",")


t = r["tabela"]
s = r["sensibilidades"]
m = r["medidas"]
linhas_sens = [
    ("Análise principal", m),
    ("Sem os \\textit{commits} já vistos pelo autor", s["8.1 sem commit ja visto"]),
    ("Uma linha por \\textit{commit}", s["8.2 uma linha por commit"]),
    ("Só anotações de confiança alta", s["8.3 so confianca alta"]),
]

out = [
    "% GERADO por Tex/gerar_tabela_segunda.py a partir de validacao_cega/segunda/resultado_segunda.json",
    f"% (SHA-256 {sha(RESULTADO)}), com os SHA-256 das entradas conferidos. NÃO EDITAR À MÃO.",
    "\\begin{table}[!htb]",  # 14/11/2026: sem "p", para não criar página só de tabelas no apêndice curto
    "\\centering",
    "\\caption{Segunda validação manual. Rótulo do autor nas 30 funções confirmadas e nas 30 descartadas"
    " pelo filtro. D indica que a função é o local da vulnerabilidade; A, B e C, rótulo indevido; ?, sem"
    " decisão.}",
    "\\label{tab:segunda}",
    "\\small",
    "\\begin{tabular}{lcccccc}",
    "\\toprule",
    " & \\textbf{A} & \\textbf{B} & \\textbf{C} & \\textbf{D} & \\textbf{?} & \\textbf{$n$} \\\\",
    "\\midrule",
]
for rotulo, chave in (("Confirmado", "confirmado"), ("Descartado", "descartado")):
    c = t[chave]
    n = c["A"] + c["B"] + c["C"] + c["D"]
    d = f"\\textbf{{{c['D']}}}" if chave == "confirmado" else str(c["D"])
    out.append(f"\\textbf{{{rotulo}}} & {c['A']} & {c['B']} & {c['C']} & {d} & {c['?']} & {n} \\\\")
out += [
    "\\bottomrule",
    "\\end{tabular}",
    "\\end{table}",
    "",
    "\\begin{table}[!htb]",  # 14/11/2026: sem "p", para não criar página só de tabelas no apêndice curto
    "\\centering",
    "\\caption{Segunda validação manual. Análise principal e análises de sensibilidade fixadas no"
    " pré-registro. A taxa base é ponderada pelo tamanho dos dois lados na moldura.}",
    "\\label{tab:segunda_sens}",
    "\\small",
    "\\begin{tabular}{lcccc}",
    "\\toprule",
    "\\textbf{Análise} & \\textbf{$n$ (conf. / desc.)} & \\textbf{Taxa base} & \\textbf{Precisão}"
    " & \\textbf{Ganho} \\\\",
    "\\midrule",
]
for rotulo, v in linhas_sens:
    out.append(f"{rotulo} & {v['n_conf']} / {v['n_desc']} & {pct(v['taxa_base'])} & {pct(v['precisao'])}"
               f" & {pontos(v['ganho'])} \\\\")
out += ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]

open(SAIDA, "w", encoding="utf-8").write("\n".join(out))
print(f"gravado {SAIDA}")
