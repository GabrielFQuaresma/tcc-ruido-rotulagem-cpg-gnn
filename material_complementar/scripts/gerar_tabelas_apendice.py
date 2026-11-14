#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gera as tabelas do Apêndice A direto das fontes primárias, sem transcrever número à mão.

    wsl -d Ubuntu-24.04 -- python3 /mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/gerar_tabelas_apendice.py

ONDE ESTAMOS. Escrita do artigo final (Tex/PLANO_ARTIGO_FINAL.md, seção 7). Os pré-registros mandam
relatar no apêndice tabelas que não cabem no corpo: todas as métricas de todos os braços, com mediana
e IQR das 30 repetições (PREREGISTRO_PRINCIPAL.md, §7), o veredito de tamanho por desenho e arena
(PREREGISTRO_TAMANHO.md, §6; PREREGISTRO_PRINCIPAL.md, E2) e as perdas da preparação das arenas por
motivo (PREREGISTRO_ARENAS.md). São centenas de números; copiá-los à mão seria pedir erro.

O QUE O SCRIPT FAZ. Só lê as fontes e grava um arquivo .tex. (1) Confere o SHA-256 dos arquivos de
resultado e da ficha de preparação contra os registrados nas aberturas (os mesmos do
conferir_numeros.py); se algum divergir, para sem gravar nada. (2) Escreve três arquivos,
secoes/apendice_tab_{arenas,metricas,anotados}.tex, que o 06_apendices.tex inclui, cada um na sua
subseção. Não calcula métrica nenhuma: formata os valores que as aberturas
gravaram (medianas, quartis, vereditos) e as contagens da ficha. A única conta é o menor e o maior
dos cinco controles na tabela dos anotados, a partir das contagens do posthoc_50_teste.md.

O QUE ELE NÃO É. Não é análise nova e não muda veredito nenhum. Rodar de novo dá o mesmo arquivo.
"""
import hashlib
import io
import json
import os
import re
import sys

BASE = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Dataset/bigvul"
# Três arquivos, um por subseção do Apêndice A, para cada tabela ficar junto do seu texto.
SAIDA = "/mnt/c/Users/kntpr/OneDrive/Desktop/TCC/Tex/secoes/apendice_tab_{}.tex"
PARTES = ["arenas", "metricas", "anotados"]
HASHES = {
    "modelo/resultado_teste_bigvul.json": "f8ea66693ceac645cc1d9a7dd16aed5d08b45a4703f661519acc9bad63991402",
    "arenas/resultado_arenas.json": "34ff46c06ea6c08631af5b6417fd25b2a7b40162f0bc42ee9ede8ea15e9f92b0",
}
FICHA_PREFIXO, FICHA_SUFIXO = "e5ead135", "8b842e"

CTRL = ["M_ctrl_g2026", "M_ctrl_g2027", "M_ctrl_g2028", "M_ctrl_g2029", "M_ctrl_g2030"]
PRINCIPAL = ["M_raw", "M_cur"] + CTRL
PAR = ["M_cur_bal"] + [c + "_bal" for c in CTRL]
NOME = {"M_raw": "Bruto", "M_cur": "Curado"}
for c in CTRL:
    NOME[c] = "Controle " + c[-4:]
    NOME[c + "_bal"] = "Controle " + c[-4:]
NOME["M_cur_bal"] = "Curado"
METRICAS = [("f1", "F1"), ("recall", "\\textit{Recall}"), ("precisao", "Precisão"),
            ("pr_auc", "PR-AUC"), ("mcc", "MCC")]
ARENAS = [
    ("primevul", "PrimeVul", "met_primevul"),
    ("ventivul_familia", "VentiVul, família de memória", "met_ventivul"),
    ("sonda", "sonda CWE-416", "met_sonda"),
    ("ventivul_inteiro", "VentiVul inteiro (todas as CWEs; só descritivo)", "met_ventivul_inteiro"),
]
ARENA_CURTA = {"bigvul": "BigVul (teste)", "primevul": "PrimeVul", "ventivul_familia": "VentiVul, memória",
               "sonda": "Sonda CWE-416", "ventivul_inteiro": "VentiVul inteiro"}


def sha(caminho):
    with open(caminho, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def num(x, casas=3):
    return f"{x:.{casas}f}".replace(".", ",")


# Revisão do autor, item 62 (28/10/2026): métricas que são proporção em %, com uma casa. A conversão
# desloca a vírgula no texto de num(x) (0,262 -> 26,2), sem arredondar de novo, para o número da
# tabela ser sempre o mesmo do texto do artigo. O MCC continua em decimal (num).
def pct(x):
    s = num(x)
    sinal = "-" if s.startswith("-") else ""
    inteira, frac = s.lstrip("-").split(",")
    return f"{sinal}{int(inteira + frac[:2])},{frac[2]}"


def milhar(n):
    return f"{n:,}".replace(",", ".") if n >= 10000 else str(n)


# ---------------------------------------------------------------- 1. conferências
for rel, esperado in HASHES.items():
    if sha(os.path.join(BASE, rel)) != esperado:
        sys.exit(f"SHA-256 divergente em {rel}; nada foi gravado")
ficha_caminho = os.path.join(BASE, "arenas/FICHA_PREPARACAO.md")
h = sha(ficha_caminho)
if not (h.startswith(FICHA_PREFIXO) and h.endswith(FICHA_SUFIXO)):
    sys.exit("SHA-256 divergente na ficha; nada foi gravado")
B = json.load(open(os.path.join(BASE, "modelo/resultado_teste_bigvul.json"), encoding="utf-8"))
A = json.load(open(os.path.join(BASE, "arenas/resultado_arenas.json"), encoding="utf-8"))
ficha = io.open(ficha_caminho, encoding="utf-8").read()
anotados = io.open(os.path.join(BASE, "modelo/posthoc_50_teste.md"), encoding="utf-8").read()

CABECALHO = [
    "% GERADO por Tex/gerar_tabelas_apendice.py a partir de modelo/resultado_teste_bigvul.json,",
    "% arenas/resultado_arenas.json (abertura refeita em 21/10/2026), arenas/FICHA_PREPARACAO.md e",
    "% modelo/posthoc_50_teste.md, com os SHA-256 conferidos. NÃO EDITAR À MÃO: rodar o script de novo.",
    "",
]
saida = {p: list(CABECALHO) for p in PARTES}
parte_atual = ["arenas"]


def w(linha):
    saida[parte_atual[0]].append(linha)


# ---------------------------------------------------------------- 2. preparação e perdas (ficha)
def tabela_md(secao_titulo):
    """Linhas de dados da primeira tabela markdown depois do título de seção dado."""
    i = ficha.index(secao_titulo)
    linhas = []
    for ln in ficha[i:].splitlines()[1:]:
        if ln.startswith("|"):
            linhas.append([c.strip() for c in ln.strip().strip("|").split("|")])
        elif linhas:
            break
    return linhas[0], linhas[2:]  # cabeçalho, dados (pula a linha de ---)


def limpa(c):
    return c.replace("**", "").strip()


def par(c):
    v, n = [int(x) for x in limpa(c).split("/")]
    return f"{milhar(v)} / {milhar(n)}"


ORDEM_FICHA = ["PrimeVul v0.1", "VentiVul v3 — família de memória", "Sonda CWE-416",
               "VentiVul v3 — inteiro (descritivo)"]
CURTO_FICHA = dict(zip(ORDEM_FICHA, ["PrimeVul", "VentiVul, memória", "Sonda CWE-416", "VentiVul inteiro"]))

cab1, dados1 = tabela_md("## 1. Quantas funções")
por_arena = {limpa(d[0]): d for d in dados1}
w("\\begin{table}[htbp]")
w("\\centering")
w("\\caption{Preparação das arenas externas: funções candidatas, as que ficaram depois da deduplicação e as que "
  "tiveram grafo extraído (vulneráveis / não vulneráveis). Fonte: a ficha de preparação, gravada antes de "
  "qualquer predição.}")
w("\\label{tab:preparacao}")
w("\\small")
w("\\begin{tabular}{lcccc}")
w("\\toprule")
w("\\textbf{Arena} & \\textbf{Candidatas} & \\textbf{Depois da deduplicação} & \\textbf{Com grafo} & \\textbf{\\% vuln.} \\\\")
w("\\midrule")
for nome in ORDEM_FICHA:
    d = por_arena[nome]
    w(f"{CURTO_FICHA[nome]} & {par(d[1])} & {par(d[2])} & {par(d[3])} & {limpa(d[4]).replace('.', ',').replace('%', '')} \\\\")
w("\\bottomrule")
w("\\end{tabular}")
w("\\end{table}")
w("")

MOTIVO = {
    "cve": "mesma CVE do treino ou da validação$^{a}$",
    "commit": "mesmo \\textit{commit}$^{a}$",
    "corpo": "mesmo corpo normalizado$^{a}$",
    "duplicata_interna": "duplicata dentro da arena, mesmo rótulo",
    "duplicata_conflito": "duplicata dentro da arena, rótulos opostos",
    "falha_sem_corpo": "sem corpo para comparar",
    "ambiguo": "homônimos que o corpo não desempatou",
    "arquivo_codificado_cobertura_zero": "arquivo do VentiVul sem a função",
    "arquivo_codificado_sem_candidato": "arquivo do VentiVul não ligado ao repositório",
    "arquivo_nao_identificado_no_commit": "arquivo não identificado no \\textit{commit}",
    "no_fora_da_funcao": "nó fora da função no grafo",
    "sem_arquivo_baixado": "arquivo não baixado",
    "sem_metodo": "função sem corpo no CPG",
    "sem_nome_de_arquivo": "sem nome de arquivo no BigVul",
    "sem_nome_de_funcao": "nome da função não extraído",
}
cab2, dados2 = tabela_md("## 2. O que saiu na deduplicação")
cab3, dados3 = tabela_md("## 3. O que se perdeu na extração")
col2 = [limpa(c) for c in cab2[1:]]
col3 = [limpa(c) for c in cab3[1:]]
w("\\begin{table}[htbp]")
w("\\centering")
w("\\caption{O que saiu das arenas, por motivo (vulneráveis / não vulneráveis). Na deduplicação, a "
  "referência é o treino e a validação do BigVul, e no PrimeVul, o BigVul inteiro ($^{a}$). Na extração, a "
  "última linha é a perda em proporção do que ficou depois da deduplicação.}")
w("\\label{tab:perdas}")
w("\\scriptsize")
w("\\setlength{\\tabcolsep}{3pt}")
w("\\begin{tabular}{lcccc}")
w("\\toprule")
w("\\textbf{Motivo} & " + " & ".join(f"\\textbf{{{CURTO_FICHA[n]}}}" for n in ORDEM_FICHA) + " \\\\")
w("\\midrule")
w("\\multicolumn{5}{l}{\\textit{Deduplicação}} \\\\")
for d in dados2:
    m = limpa(d[0])
    vals = dict(zip(col2, d[1:]))
    w(f"{MOTIVO[m]} & " + " & ".join(par(vals[n]) for n in ORDEM_FICHA) + " \\\\")
w("\\midrule")
w("\\multicolumn{5}{l}{\\textit{Extração dos grafos}} \\\\")
for d in dados3:
    m = limpa(d[0])
    vals = dict(zip(col3, d[1:]))
    if m == "perda total":
        cel = [limpa(vals[n]).replace(".", ",") for n in ORDEM_FICHA]
        w("\\midrule")
        w("perda total na extração & " + " & ".join(c.replace("%", "\\%") for c in cel) + " \\\\")
    else:
        w(f"{MOTIVO[m]} & " + " & ".join(par(vals[n]) for n in ORDEM_FICHA) + " \\\\")
w("\\bottomrule")
w("\\end{tabular}")
w("\\end{table}")
w("")


# ---------------------------------------------------------------- 3. checagem de tamanho
def linha_tamanho(rotulo, desenho, posicao, t):
    inc = t["inclinacao"]
    cur = [v for k, v in inc.items() if k.startswith("M_cur")][0]
    ctr = [v for k, v in inc.items() if k.startswith("M_ctrl")]
    if not t["v1_aplica"]:
        v1 = "não se aplica"
    else:
        v1 = f"{pct(cur)} ({pct(min(ctr))}--{pct(max(ctr))}), {'\\textbf{dispara}' if t['v1'] else 'não dispara'}"
    if t["v2"] is None:
        v2 = "não se aplica"
    else:
        acima = [f.replace("ate 46", "até 46").replace("-", "--")
                 for f, a in t["acima_por_faixa"].items() if a]
        v2 = ("\\textbf{dispara}" if t["v2"] else "não dispara") + (f" (acima: {', '.join(acima)})" if acima else "")
    ver = "\\textbf{evidência de viés}" if t["veredito"].startswith("evidencia") else "sem evidência"
    return f"{rotulo} & {desenho} & {posicao} & {v1} & {v2} & {ver} \\\\"


w("\\begin{table}[htbp]")
w("\\centering")
w("\\caption{Checagem de tamanho, por arena e versão. Posição: o F1 do curado contra a faixa dos cinco controles. "
  "V1: diferença, em pontos percentuais, entre as taxas de falso positivo das faixas de 340 nós ou mais e de até 46, no curado e (entre "
  "parênteses) nos controles; dispara se a do curado passa a de todos. V2: dispara se o curado fica acima dos "
  "controles em alguma faixa grande e em nenhuma pequena, contando só faixas com 30 vulneráveis. Só o veredito "
  "da configuração principal qualifica a conclusão.}")
w("\\label{tab:tamanho}")
w("\\scriptsize")
w("\\setlength{\\tabcolsep}{3pt}")
w("\\begin{tabular}{llllll}")
w("\\toprule")
w("\\textbf{Arena} & \\textbf{Versão} & \\textbf{Posição} & \\textbf{V1: curado (controles)} & \\textbf{V2} & \\textbf{Veredito} \\\\")
w("\\midrule")
for des, rot_des in (("principal", "principal"), ("par balanceado", "balanceada")):
    w(linha_tamanho(ARENA_CURTA["bigvul"] if des == "principal" else "", rot_des,
                    B["comparacoes"][des]["posicao"], B["tamanho"][des]))
for chave, _, _ in ARENAS:
    r = A["arenas"][chave]
    for des, rot_des in (("principal", "principal"), ("par balanceado", "balanceada")):
        d = r["desenhos"][des]
        w(linha_tamanho(ARENA_CURTA[chave] if des == "principal" else "", rot_des, d["posicao"], d["tamanho"]))
w("\\bottomrule")
w("\\end{tabular}")
w("\\end{table}")
w("")


# ---------------------------------------------------------------- 4. todas as métricas
parte_atual[0] = "metricas"


def tabela_metricas(rotulo, titulo, P, N, rg):
    w("\\begin{table}[htbp]")
    w("\\centering")
    w(f"\\caption{{{titulo}, com {milhar(P)} vulneráveis e {milhar(N)} não vulneráveis. Mediana e, entre "
      "colchetes, primeiro e terceiro quartis das 30 repetições de cada braço.}")
    w(f"\\label{{tab:{rotulo}}}")
    w("\\scriptsize")
    w("\\setlength{\\tabcolsep}{3pt}")
    w("\\begin{tabular}{l" + "c" * len(METRICAS) + "}")
    w("\\toprule")
    w("\\textbf{Braço} & " + " & ".join(f"\\textbf{{{m}}}" for _, m in METRICAS) + " \\\\")
    w("\\midrule")
    for grupo, bracos in (("", PRINCIPAL), ("\\textit{Versão balanceada}", PAR)):
        if grupo:
            w("\\midrule")
            w(f"\\multicolumn{{{len(METRICAS) + 1}}}{{l}}{{{grupo}}} \\\\")
        for b in bracos:
            cel = []
            for chave, _ in METRICAS:
                v = rg[b][chave]
                if chave == "mcc":
                    cel.append(f"{num(v['mediana'])} [{num(v['q1'])}--{num(v['q3'])}]")
                else:
                    # o % uma vez por célula: com três, as tabelas do BigVul e do PrimeVul passam da
                    # largura da página; os quartis entre colchetes estão na mesma unidade da mediana
                    cel.append(f"{pct(v['mediana'])}\\% [{pct(v['q1'])}--{pct(v['q3'])}]")
            w(f"{NOME[b]} & " + " & ".join(cel) + " \\\\")
    w("\\bottomrule")
    w("\\end{tabular}")
    w("\\end{table}")
    w("")


cont = B["contagem_faixas"]
tabela_metricas("met_bigvul", "Todas as métricas no teste do BigVul",
                sum(c[0] for c in cont), sum(c[1] for c in cont), B["resumo_geral"])
for chave, titulo, rotulo in ARENAS:
    r = A["arenas"][chave]
    tabela_metricas(rotulo, f"Todas as métricas no {titulo}" if not titulo.startswith("sonda")
                    else f"Todas as métricas na {titulo}", r["P"], r["N"], r["resumo_geral"])


# ---------------------------------------------------------------- 5. os anotados que caíram no teste
parte_atual[0] = "anotados"
linhas =[ln for ln in anotados.splitlines() if re.match(r"^\| \d+ \|", ln)]
w("\\begin{table}[htbp]")
w("\\centering")
w("\\caption{Os 9 casos da amostra anotada que caíram no teste do BigVul: em quantas das 30 repetições cada "
  "braço sinalizou a função (para os controles, a menor e a maior contagem entre os cinco). Categoria: D é o local "
  "da vulnerabilidade; A, B e C, rótulo indevido. Nós: tamanho do grafo da função. Regra: o veredito da "
  "\\textit{traversal}. Observação qualitativa, prevista no pré-registro e feita depois da abertura.}")
w("\\label{tab:anotados_teste}")
w("\\small")
w("\\setlength{\\tabcolsep}{4pt}")
w("\\begin{tabular}{cccccccc}")
w("\\toprule")
w("\\textbf{Caso} & \\textbf{Categoria} & \\textbf{Nós} & \\textbf{Regra} & \\textbf{Curado} & \\textbf{Bruto} & "
  "\\textbf{Controles} & \\textbf{Curado bal.} \\\\")
w("\\midrule")
for ln in linhas:
    c = [x.strip() for x in ln.strip().strip("|").split("|")]
    caso, cat, nos, regra = c[0], limpa(c[3]), c[4].split(" ")[0], c[5]
    cur, raw = int(c[6]), int(c[7])
    ctr = [int(x) for x in c[8:13]]
    curbal = int(c[13])
    w(f"{caso} & {cat} & {nos} & {regra} & {cur} & {raw} & {min(ctr)}--{max(ctr)} & {curbal} \\\\")
w("\\bottomrule")
w("\\end{tabular}")
w("\\end{table}")
w("")

for p in PARTES:
    caminho = SAIDA.format(p)
    with io.open(caminho, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(saida[p]))
    print(f"gravado {caminho} ({len(saida[p])} linhas)")
