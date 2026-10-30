#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Particiona o BigVul em treino/validacao/teste ANTES de qualquer filtro de curadoria.

POR QUE ESTE SCRIPT EXISTE, situando para quem chegou agora
-----------------------------------------------------------
O TCC compara tres conjuntos de treino (M_raw bruto, M_cur curado, M_ctrl controle) que
diferem SO em quais positivos entram. Para a comparacao valer, os tres tem que ser avaliados
no MESMO conjunto de teste, e esse conjunto tem que ser definido ANTES de a curadoria filtrar
qualquer coisa. Se o split fosse feito depois, cada braco teria um teste diferente e nao
haveria comparacao nenhuma.

Acordado com o orientador em 09/2026 (documentos-orientacao/resposta_treinamentos_bigvul.md).

O QUE E UM "GRUPO", E POR QUE NAO E O COMMIT
--------------------------------------------
Vazamento aqui nao e hipotetico. No BigVul um commit de correcao toca varias funcoes (o
"fan-out"): um deles toca 230 funcoes positivas, e os negativos sao em geral funcoes do MESMO
arquivo que o commit tocou. Split aleatorio por funcao poria irmas do mesmo commit dos dois
lados, e o modelo veria no treino uma variante quase identica do que vai ser testado.

Agrupar por commit_id tambem NAO basta: medido em _explorar_split.py, 59 CVEs aparecem em
mais de um commit. Entao a unidade e o COMPONENTE CONEXO do grafo commit <-> CVE: dois itens
caem no mesmo grupo se compartilham commit, ou CVE, ou uma cadeia dos dois. E o unico criterio
que nao deixa fresta.

O QUE ELE PARTICIONA
--------------------
  positivos  as 2957 linhas do relatorio_extracao.csv (as 4 CWEs de memoria). TODAS, inclusive
             as que a curadoria depois classificou como indeterminadas ou que falharam — o
             split e anterior ao filtro, esse e o ponto.
  negativos  as linhas vul==0 do indice_bigvul.csv cujo commit tem positivo nosso. Cada
             negativo herda a particao do grupo do seu commit.

BALANCEAMENTO POR POSITIVOS (decisao do autor, 05/09/2026). O 70/10/20 e sobre a contagem de
POSITIVOS, nao sobre o total de funcoes. Motivo: os negativos sao ~92% do total e dominariam o
balanceamento, e o teste poderia acabar com poucos positivos — justamente a classe cuja
deteccao o trabalho mede. A distribuicao de negativos sai desigual de proposito e e reportada.

O QUE ELE NAO FAZ
-----------------
Nao le veredito, nao le rotulo humano, nao decide quem e M_cur. Nao sabe quais itens sao os 50
anotados enquanto particiona — ele so RELATA, no fim, onde eles cairam. E nao monta dataset:
quem faz isso e montar_conjuntos_treino.py, que consome este split.

Uso:
  python3 montar_split.py                # monta e grava
  python3 montar_split.py --conferir     # so confere os hashes do que ja esta gravado
"""

import argparse
import csv
import datetime
import hashlib
import json
import os
import random
import sys
from collections import Counter, defaultdict

AQUI = os.path.dirname(os.path.abspath(__file__))
BIGVUL = os.path.dirname(AQUI)
RELATORIO = os.path.join(BIGVUL, "saida_final", "relatorio_extracao.csv")
INDICE = os.path.join(BIGVUL, "saida_final", "indice_bigvul.csv")
AMOSTRA_50 = os.path.join(BIGVUL, "saida", "amostra_validacao_revisao.csv")
MAPA_50 = os.path.join(AQUI, "mapa_caso_item_50.csv")
SAIDA = os.path.join(AQUI, "split")

CWES_ALVO = {"CWE-119", "CWE-120", "CWE-125", "CWE-787"}
PARTICOES = ("treino", "validacao", "teste")
ALVO = {"treino": 0.70, "validacao": 0.10, "teste": 0.20}

# Semente do embaralhamento dos grupos antes do guloso. NAO e 42 (os 50 anotados), 7 (o dev
# set), 2026 (o M_ctrl) nem 101 (a medida de subgrafo), de proposito: reusar uma delas faria
# o split correlacionar com um conjunto que ja tem papel no desenho.
SEMENTE = 909

# Se um unico grupo tiver mais que isto da massa de positivos, um teste de 20% fica impossivel
# de montar sem que esse grupo o domine. Nesse caso o script PARA em vez de improvisar.
TETO_GRUPO = 0.20


def log(*a):
    print(*a, flush=True)


def norm(v):
    v = (v or "").strip()
    return "" if v.lower() in ("", "nan", "none") else v


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as fh:
        for bloco in iter(lambda: fh.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


# ---------------------------------------------------------------------------------------
# union-find: o grupo e o componente conexo do grafo commit <-> CVE
# ---------------------------------------------------------------------------------------
class Uniao:
    def __init__(self):
        self.pai = {}

    def achar(self, x):
        self.pai.setdefault(x, x)
        raiz = x
        while self.pai[raiz] != raiz:
            raiz = self.pai[raiz]
        while self.pai[x] != raiz:            # compressao de caminho
            self.pai[x], x = raiz, self.pai[x]
        return raiz

    def unir(self, a, b):
        ra, rb = self.achar(a), self.achar(b)
        if ra != rb:
            self.pai[max(ra, rb)] = min(ra, rb)   # deterministico: raiz e o menor rotulo


def ler_positivos():
    """[{item, commit, cve, cwe, projeto}] — as 2957 linhas, antes de qualquer filtro."""
    linhas = []
    with open(RELATORIO, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            linhas.append({
                "item": "{:04d}__{}".format(int(r["id"]), r["project"]),
                "commit": norm(r.get("commit_id")),
                "cve": norm(r.get("cve_id")),
                "cwe": norm(r.get("cwe_bigvul")),
                "projeto": norm(r.get("project")),
            })
    return linhas


def ler_negativos(commits_no_escopo):
    """[{linha_indice, commit, cve, cwe, projeto, arquivo}] dos negativos em commit nosso.

    linha_indice e o numero da linha no indice_bigvul.csv (0-indexado, sem contar o
    cabecalho). E o unico identificador estavel que o indice oferece — ele nao guarda nome de
    funcao. O hash do indice entra no congelamento justamente para esse id nao se mexer.
    """
    linhas = []
    with open(INDICE, encoding="utf-8") as fh:
        for n, r in enumerate(csv.DictReader(fh)):
            if norm(r.get("vul")) != "0":
                continue
            commit = norm(r.get("commit_id"))
            if commit not in commits_no_escopo:
                continue
            linhas.append({
                "linha_indice": n,
                "commit": commit,
                "cve": norm(r.get("CVE ID")),
                "cwe": norm(r.get("CWE ID")),
                "projeto": norm(r.get("project")),
                "arquivo": norm(r.get("file_name")),
            })
    return linhas


def montar_grupos(positivos, negativos):
    """Devolve (grupo_de_commit, grupos) com grupos = {gid: {commits, cves}}."""
    u = Uniao()
    for l in positivos + negativos:
        commit, cve = l["commit"], l["cve"]
        no_c = "c:" + commit if commit else None
        no_v = "v:" + cve if cve else None
        if no_c:
            u.achar(no_c)
        if no_v:
            u.achar(no_v)
        if no_c and no_v:
            u.unir(no_c, no_v)

    grupos = defaultdict(lambda: {"commits": set(), "cves": set()})
    grupo_de_commit = {}
    for no in sorted(u.pai):
        gid = u.achar(no)
        if no.startswith("c:"):
            grupos[gid]["commits"].add(no[2:])
            grupo_de_commit[no[2:]] = gid
        else:
            grupos[gid]["cves"].add(no[2:])
    return grupo_de_commit, grupos


def grupo_do_item(linha, grupo_de_commit):
    """Grupo de uma linha. Item sem commit vira grupo proprio — nao se junta o que nao se sabe."""
    if linha["commit"] and linha["commit"] in grupo_de_commit:
        return grupo_de_commit[linha["commit"]]
    return "orfao:" + linha.get("item", str(linha.get("linha_indice", "?")))


def particionar(grupos_ordenados, cwe_por_grupo, total_por_cwe):
    """Guloso estratificado por CWE — o mesmo criterio do StratifiedGroupKFold do sklearn.

    Por que estratificar: o guloso simples (so pelo total de positivos) enviesa a composicao.
    Medido nesta base com semente 909, ele punha 27,9% de CWE-125 no teste contra 21,1% na
    populacao — e a CWE-125 e justamente a que mais perde cobertura na curadoria (12,2% de
    indeterminados contra 7,5% da CWE-119). Um teste enriquecido na CWE que a ferramenta
    enxerga pior distorce a leitura dos tres bracos.

    Estratificar por CWE NAO e vazamento: a CWE e metadado do dataset, nao o rotulo que o
    modelo prediz (vulneravel / nao vulneravel). O split continua sem olhar veredito, sem olhar
    anotacao humana e sem olhar quem sao os 50.

    Criterio: para cada grupo, simula por-lo em cada particao e escolhe a que deixa o menor
    desvio-padrao entre as razoes de preenchimento (atual / alvo) de todos os pares
    (particao, CWE). Isso equilibra o total e a composicao ao mesmo tempo.
    """
    cwes = sorted(total_por_cwe)
    alvo = {p: {c: ALVO[p] * total_por_cwe[c] for c in cwes} for p in PARTICOES}
    atual = {p: {c: 0 for c in cwes} for p in PARTICOES}

    def desvio():
        razoes = [atual[p][c] / alvo[p][c] for p in PARTICOES for c in cwes if alvo[p][c] > 0]
        if not razoes:
            return 0.0
        media = sum(razoes) / len(razoes)
        return (sum((r - media) ** 2 for r in razoes) / len(razoes)) ** 0.5

    atribuicao = {}
    for gid in grupos_ordenados:
        contagem = cwe_por_grupo.get(gid, {})
        custos = []
        for p in PARTICOES:
            for c, n in contagem.items():
                atual[p][c] += n
            custos.append((desvio(), PARTICOES.index(p), p))
            for c, n in contagem.items():
                atual[p][c] -= n
        _, _, melhor = min(custos)          # empate resolvido pela ordem fixa de PARTICOES
        atribuicao[gid] = melhor
        for c, n in contagem.items():
            atual[melhor][c] += n

    return atribuicao, {p: sum(atual[p].values()) for p in PARTICOES}


def itens_dos_50():
    """{item} dos 50 casos anotados — SO para relatar onde cairam, nunca para particionar."""
    if not os.path.exists(MAPA_50):
        return set()
    itens = set()
    with open(MAPA_50, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            for chave in ("item", "item_id", "id_item"):
                if r.get(chave):
                    itens.add(r[chave].strip())
                    break
    return itens


def gravar_tsv(caminho, campos, linhas):
    with open(caminho, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=campos, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        for l in linhas:
            w.writerow(l)


def conferir():
    tsv = os.path.join(SAIDA, "congelamento_split.tsv")
    if not os.path.exists(tsv):
        log("FALHA: nao ha split gravado em %s" % SAIDA)
        return 1
    problemas = []
    with open(tsv, encoding="utf-8") as fh:
        fh.readline()
        for linha in fh:
            if not linha.strip():
                continue
            rel, sha = linha.rstrip("\n").split("\t")[:2]
            caminho = os.path.join(BIGVUL, rel)
            if not os.path.exists(caminho):
                problemas.append("%s: ausente" % rel)
                continue
            agora = sha256_arquivo(caminho)
            if agora != sha:
                problemas.append("%s\n    congelado %s\n    agora     %s" % (rel, sha, agora))
    if problemas:
        log("FALHA na conferencia do split:")
        for p in problemas:
            log("  " + p)
        log("\nOu a mudanca foi acidental e tem que voltar, ou foi deliberada e todos os")
        log("resultados medidos sob o split antigo precisam ser refeitos e declarados.")
        return 1
    log("split: ok — hashes conferem")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--conferir", action="store_true")
    p.add_argument("--forcar", action="store_true",
                   help="regrava por cima de um split existente")
    args = p.parse_args()

    if args.conferir:
        return conferir()

    if os.path.exists(os.path.join(SAIDA, "congelamento_split.tsv")) and not args.forcar:
        log("FALHA: ja existe um split gravado em %s" % SAIDA)
        log("       Regravar muda a definicao de treino/teste debaixo de qualquer numero que")
        log("       ja tenha sido medido. Use --forcar so se for deliberado, e registre.")
        return 1

    log("=" * 78)
    log("SPLIT AGRUPADO — treino/validacao/teste antes de qualquer filtro")
    log("=" * 78)

    positivos = ler_positivos()
    log("positivos (relatorio_extracao.csv): %d" % len(positivos))
    commits_no_escopo = {l["commit"] for l in positivos if l["commit"]}
    log("commits distintos com positivo: %d" % len(commits_no_escopo))

    log("varrendo o indice do BigVul pelos negativos...")
    negativos = ler_negativos(commits_no_escopo)
    log("negativos em commit nosso: %d" % len(negativos))
    fora = sum(1 for l in negativos if l["cwe"] not in CWES_ALVO)
    log("  fora das 4 CWEs de memoria: %d" % fora)

    grupo_de_commit, grupos = montar_grupos(positivos, negativos)
    log()
    log("grupos (componentes conexos commit <-> CVE): %d" % len(grupos))

    pos_por_grupo = Counter()
    neg_por_grupo = Counter()
    for l in positivos:
        l["grupo"] = grupo_do_item(l, grupo_de_commit)
        pos_por_grupo[l["grupo"]] += 1
    for l in negativos:
        l["grupo"] = grupo_do_item(l, grupo_de_commit)
        neg_por_grupo[l["grupo"]] += 1

    total_pos = len(positivos)
    maior_gid, maior_n = pos_por_grupo.most_common(1)[0]
    fracao = maior_n / total_pos
    log("maior grupo: %d positivos (%.1f%% dos %d)" % (maior_n, 100 * fracao, total_pos))
    log("    commits: %d | CVEs: %s"
        % (len(grupos[maior_gid]["commits"]),
           ", ".join(sorted(grupos[maior_gid]["cves"])[:3]) or "-"))
    if fracao > TETO_GRUPO:
        log()
        log("PARANDO. O maior grupo sozinho passa de %.0f%% dos positivos." % (100 * TETO_GRUPO))
        log("Um teste de 20%% ou exclui esse grupo (e perde o fenomeno de fan-out que ele")
        log("representa) ou e dominado por ele. As duas saidas sao decisoes de desenho, nao")
        log("de script — leve para o orientador antes de seguir.")
        return 1

    # embaralha com semente e depois ordena por tamanho: o embaralhamento so desempata
    ordenados = sorted(grupos)
    random.Random(SEMENTE).shuffle(ordenados)
    ordenados = sorted(ordenados, key=lambda g: -pos_por_grupo.get(g, 0))

    cwe_por_grupo = defaultdict(Counter)
    for l in positivos:
        cwe_por_grupo[l["grupo"]][l["cwe"]] += 1
    total_por_cwe = Counter(l["cwe"] for l in positivos)
    atribuicao, atual = particionar(ordenados, cwe_por_grupo, total_por_cwe)
    for l in positivos + negativos:
        l["particao"] = atribuicao.get(l["grupo"], "treino")

    log()
    log("-" * 78)
    log("RESULTADO DO SPLIT")
    log("-" * 78)
    log("%-11s %9s %7s %10s %8s %10s" % ("particao", "positivos", "%", "negativos", "%", "razao"))
    n_pos = Counter(l["particao"] for l in positivos)
    n_neg = Counter(l["particao"] for l in negativos)
    for p in PARTICOES:
        log("%-11s %9d %6.1f%% %10d %7.1f%% %9.1f:1"
            % (p, n_pos[p], 100.0 * n_pos[p] / total_pos, n_neg[p],
               100.0 * n_neg[p] / max(len(negativos), 1),
               n_neg[p] / max(n_pos[p], 1)))
    log("%-11s %9d %6.1f%% %10d %7.1f%%" % ("TOTAL", total_pos, 100.0, len(negativos), 100.0))
    log()
    log("alvo era 70/10/20 dos POSITIVOS. Os negativos vem de carona pelo grupo do commit,")
    log("entao a razao negativo:positivo difere entre particoes — e esperado e vai declarado.")

    log()
    log("distribuicao por CWE (conferindo que o guloso nao enviesou):")
    log("%-11s %8s %8s %8s %8s" % ("particao", "CWE-119", "CWE-120", "CWE-125", "CWE-787"))
    for p in PARTICOES:
        c = Counter(l["cwe"] for l in positivos if l["particao"] == p)
        tot = max(sum(c.values()), 1)
        log("%-11s %7.1f%% %7.1f%% %7.1f%% %7.1f%%"
            % (p, 100.0 * c["CWE-119"] / tot, 100.0 * c["CWE-120"] / tot,
               100.0 * c["CWE-125"] / tot, 100.0 * c["CWE-787"] / tot))
    c = Counter(l["cwe"] for l in positivos)
    tot = max(sum(c.values()), 1)
    log("%-11s %7.1f%% %7.1f%% %7.1f%% %7.1f%%"
        % ("populacao", 100.0 * c["CWE-119"] / tot, 100.0 * c["CWE-120"] / tot,
           100.0 * c["CWE-125"] / tot, 100.0 * c["CWE-787"] / tot))

    log()
    log("conferencias de vazamento:")
    por_grupo_particoes = defaultdict(set)
    for l in positivos + negativos:
        por_grupo_particoes[l["grupo"]].add(l["particao"])
    vazando = [g for g, ps in por_grupo_particoes.items() if len(ps) > 1]
    log("  grupos em mais de uma particao ....... %d  (tem que ser 0)" % len(vazando))
    commit_particoes = defaultdict(set)
    for l in positivos + negativos:
        if l["commit"]:
            commit_particoes[l["commit"]].add(l["particao"])
    log("  commits em mais de uma particao ...... %d  (tem que ser 0)"
        % sum(1 for ps in commit_particoes.values() if len(ps) > 1))
    cve_particoes = defaultdict(set)
    for l in positivos + negativos:
        if l["cve"]:
            cve_particoes[l["cve"]].add(l["particao"])
    log("  CVEs em mais de uma particao ......... %d  (tem que ser 0)"
        % sum(1 for ps in cve_particoes.values() if len(ps) > 1))

    cinquenta = itens_dos_50()
    onde_50 = Counter(l["particao"] for l in positivos if l["item"] in cinquenta)
    log()
    log("onde cairam os 50 anotados (relato, NAO entrou na particao):")
    if cinquenta:
        for p in PARTICOES:
            log("  %-11s %d" % (p, onde_50[p]))
        log("  (o split nao olhou quem eram: decisao de 05/09/2026, 'deixar cair onde cair')")
    else:
        log("  mapa nao encontrado em %s" % MAPA_50)

    os.makedirs(SAIDA, exist_ok=True)
    gravar_tsv(os.path.join(SAIDA, "positivos.tsv"),
               ["item", "particao", "grupo", "commit", "cve", "cwe", "projeto"],
               sorted(positivos, key=lambda l: l["item"]))
    gravar_tsv(os.path.join(SAIDA, "negativos.tsv"),
               ["linha_indice", "particao", "grupo", "commit", "cve", "cwe", "projeto", "arquivo"],
               sorted(negativos, key=lambda l: l["linha_indice"]))
    gravar_tsv(os.path.join(SAIDA, "grupos.tsv"),
               ["grupo", "particao", "n_positivos", "n_negativos", "n_commits", "n_cves", "cves"],
               [{"grupo": g, "particao": atribuicao[g],
                 "n_positivos": pos_por_grupo.get(g, 0), "n_negativos": neg_por_grupo.get(g, 0),
                 "n_commits": len(grupos[g]["commits"]), "n_cves": len(grupos[g]["cves"]),
                 "cves": ",".join(sorted(grupos[g]["cves"])[:6])}
                for g in sorted(grupos, key=lambda g: -pos_por_grupo.get(g, 0))])

    resumo = {
        "semente": SEMENTE, "alvo": ALVO, "balanceado_por": "positivos",
        "estratificado_por": "cwe_bigvul",
        "unidade_de_grupo": "componente conexo commit<->CVE",
        "gerado_em": datetime.date.today().isoformat(),
        "positivos": {p: n_pos[p] for p in PARTICOES},
        "negativos": {p: n_neg[p] for p in PARTICOES},
        "n_grupos": len(grupos), "maior_grupo_positivos": maior_n,
        "onde_cairam_os_50": {p: onde_50[p] for p in PARTICOES},
    }
    with open(os.path.join(SAIDA, "resumo.json"), "w", encoding="utf-8") as fh:
        json.dump(resumo, fh, indent=2, ensure_ascii=False, sort_keys=True)

    alvos_hash = [
        os.path.relpath(RELATORIO, BIGVUL), os.path.relpath(INDICE, BIGVUL),
        os.path.relpath(os.path.join(SAIDA, "positivos.tsv"), BIGVUL),
        os.path.relpath(os.path.join(SAIDA, "negativos.tsv"), BIGVUL),
        os.path.relpath(os.path.join(SAIDA, "grupos.tsv"), BIGVUL),
    ]
    with open(os.path.join(SAIDA, "congelamento_split.tsv"), "w", encoding="utf-8") as fh:
        fh.write("arquivo\tsha256\tbytes\n")
        for rel in alvos_hash:
            caminho = os.path.join(BIGVUL, rel)
            fh.write("%s\t%s\t%d\n" % (rel, sha256_arquivo(caminho), os.path.getsize(caminho)))

    log()
    log("gravado em %s" % SAIDA)
    log("  positivos.tsv  negativos.tsv  grupos.tsv  resumo.json  congelamento_split.tsv")
    log()
    log("O congelamento inclui os DOIS insumos (relatorio e indice) alem das saidas: o id dos")
    log("negativos e o numero da linha no indice, entao se o indice mudar os ids mudam junto.")
    return 0


if __name__ == "__main__":
    import traceback
    try:
        codigo = main()
    except BaseException:
        log("=== FALHOU ===")
        log(traceback.format_exc())
        codigo = 1
    sys.exit(codigo)
