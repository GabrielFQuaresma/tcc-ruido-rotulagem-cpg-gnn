#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compara a anotacao do humano com a do modelo e emite o relatorio de
confiabilidade previsto em pre_registro.md.

Recusa rodar sem o pre-registro, e grava no relatorio o SHA-256 do pre-registro
e da rubrica. Se o plano de analise mudar depois de os resultados serem vistos,
o hash muda e a mudanca aparece no diff.

Nenhum rotulo do humano e alterado por este script. As discordancias saem em
saida/discordancias.csv para leitura; a adjudicacao, se houver, e um passo
posterior e separado, e o kappa calculado aqui e o pre-adjudicacao.

Sem scipy e sem sklearn de proposito: kappa de Cohen, kappa de Fleiss e o
bootstrap por cluster sao curtos o bastante para ficarem legiveis aqui, e o
ambiente do projeto instala pacote com --break-system-packages.

Uso:
  python3 comparar.py --condicao cve_visivel
  python3 comparar.py --condicao cve_oculta --sufixo _oculta
"""

import argparse
import csv
import hashlib
import os
import random
import sys
from collections import Counter, defaultdict

TIPOS = ["A", "B", "C", "D"]
TIPOS_COM_INDEF = ["A", "B", "C", "D", "?"]
MAPA_CONF = {"alta": "alta", "alto": "alta", "media": "media", "médio": "media",
             "medio": "media", "média": "media", "baixa": "baixa", "baixo": "baixa"}


# ----------------------------------------------------------------- utilitarios

def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def norm_tipo(s):
    v = str(s or "").strip().upper().replace("\t", "").replace('"', "").replace("'", "")
    return v if v in TIPOS_COM_INDEF else ""


def norm_conf(s):
    return MAPA_CONF.get(str(s or "").strip().lower(), "")


def ler_csv(caminho):
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(caminho, encoding=enc, newline="") as f:
                return list(csv.DictReader(f))
        except UnicodeDecodeError:
            continue
    sys.exit(f"ERRO: nao consegui decodificar {caminho}")


# ----------------------------------------------------------------- estatistica

def kappa_cohen(pares):
    """pares: lista de (rotulo_a, rotulo_b). Devolve (kappa, po, pe, n)."""
    n = len(pares)
    if n == 0:
        return float("nan"), float("nan"), float("nan"), 0
    cats = sorted({x for p in pares for x in p})
    po = sum(1 for a, b in pares if a == b) / n
    ca = Counter(a for a, _ in pares)
    cb = Counter(b for _, b in pares)
    pe = sum((ca[k] / n) * (cb[k] / n) for k in cats)
    if abs(1 - pe) < 1e-12:
        return float("nan"), po, pe, n
    return (po - pe) / (1 - pe), po, pe, n


def kappa_fleiss(itens):
    """itens: lista de listas de rotulos (um por avaliador, mesmo R para todos).
    Devolve (kappa, pbar, pe, n, r)."""
    itens = [i for i in itens if i]
    n = len(itens)
    if n == 0:
        return float("nan"), float("nan"), float("nan"), 0, 0
    r = len(itens[0])
    if r < 2 or any(len(i) != r for i in itens):
        return float("nan"), float("nan"), float("nan"), n, r
    cats = sorted({x for i in itens for x in i})
    if len(cats) < 2:
        return float("nan"), 1.0, 1.0, n, r

    p_i = []
    total_por_cat = Counter()
    for it in itens:
        c = Counter(it)
        total_por_cat.update(c)
        p_i.append((sum(v * v for v in c.values()) - r) / (r * (r - 1)))
    pbar = sum(p_i) / n
    pj = {k: total_por_cat[k] / (n * r) for k in cats}
    pe = sum(v * v for v in pj.values())
    if abs(1 - pe) < 1e-12:
        return float("nan"), pbar, pe, n, r
    return (pbar - pe) / (1 - pe), pbar, pe, n, r


def bootstrap_cluster(registros, clusters, estatistica, reps=10000, semente=42):
    """Reamostra CLUSTERS com reposicao (nao linhas) e recalcula a estatistica.
    Devolve (ic_baixo, ic_alto, n_validas, n_degeneradas)."""
    rnd = random.Random(semente)
    por_cluster = defaultdict(list)
    for reg, c in zip(registros, clusters):
        por_cluster[c].append(reg)
    chaves = list(por_cluster)
    if not chaves:
        return float("nan"), float("nan"), 0, 0

    vals, degen = [], 0
    for _ in range(reps):
        amostra = []
        for _ in range(len(chaves)):
            amostra.extend(por_cluster[chaves[rnd.randrange(len(chaves))]])
        v = estatistica(amostra)
        if v is None or v != v:      # None ou NaN
            degen += 1
        else:
            vals.append(v)
    if len(vals) < 100:
        return float("nan"), float("nan"), len(vals), degen
    vals.sort()
    lo = vals[int(0.025 * (len(vals) - 1))]
    hi = vals[int(0.975 * (len(vals) - 1))]
    return lo, hi, len(vals), degen


def fmt(x, casas=3):
    return "n/d" if x is None or x != x else f"{x:.{casas}f}"


# ------------------------------------------------------------------- analise

def bloco_kappa(titulo, pares, clusters, reps, semente, linhas):
    """Emite kappa 4-categorias e kappa binario (D x resto), com IC bootstrap."""
    linhas.append(f"### {titulo}")
    linhas.append("")
    if not pares:
        linhas.append("_Sem casos elegiveis._")
        linhas.append("")
        return

    k4, po4, pe4, n = kappa_cohen(pares)
    binarios = [("D" if a == "D" else "nD", "D" if b == "D" else "nD")
                for a, b in pares]
    kb, pob, peb, _ = kappa_cohen(binarios)

    lo_b, hi_b, nv_b, dg_b = bootstrap_cluster(
        binarios, clusters,
        lambda amostra: kappa_cohen(amostra)[0], reps, semente)
    lo_4, hi_4, nv_4, dg_4 = bootstrap_cluster(
        pares, clusters,
        lambda amostra: kappa_cohen(amostra)[0], reps, semente)

    linhas.append(f"n = {n} casos | clusters (commits distintos) = "
                  f"{len(set(clusters))}")
    linhas.append("")
    linhas.append("| metrica | kappa | IC95% (bootstrap por commit) | concordancia bruta | esperada ao acaso |")
    linhas.append("| --- | --- | --- | --- | --- |")
    linhas.append(f"| **binario (D x A+B+C)** — primaria | **{fmt(kb)}** | "
                  f"[{fmt(lo_b)}, {fmt(hi_b)}] | {fmt(pob)} | {fmt(peb)} |")
    linhas.append(f"| 4 categorias (A/B/C/D) | {fmt(k4)} | "
                  f"[{fmt(lo_4)}, {fmt(hi_4)}] | {fmt(po4)} | {fmt(pe4)} |")
    linhas.append("")
    if dg_b or dg_4:
        linhas.append(f"_Reamostragens degeneradas descartadas: {dg_b} (binario), "
                      f"{dg_4} (4 categorias) de {reps}._")
        linhas.append("")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--condicao", choices=["cve_visivel", "cve_oculta"],
                    default="cve_visivel")
    ap.add_argument("--raiz", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--humano", default=None,
                    help="padrao: ../saida/amostra_validacao_revisao.csv")
    ap.add_argument("--reps", type=int, default=10000)
    ap.add_argument("--semente", type=int, default=42)
    ap.add_argument("--sufixo", default="")
    args = ap.parse_args()

    raiz = args.raiz
    pre_reg = os.path.join(raiz, "pre_registro.md")
    rubrica = os.path.join(raiz, "rubrica_v1.md")
    for p in (pre_reg, rubrica):
        if not os.path.exists(p):
            sys.exit(f"ERRO: {p} nao existe. A analise nao roda sem ele — ver "
                     f"o cabecalho de pre_registro.md.")

    humano_csv = args.humano or os.path.normpath(
        os.path.join(raiz, "..", "saida", "amostra_validacao_revisao.csv"))
    modelo_csv = os.path.join(raiz, "saida", f"anotacao_modelo_{args.condicao}.csv")
    manifesto = os.path.join(raiz, f"manifesto_{args.condicao}.csv")
    for p in (humano_csv, modelo_csv, manifesto):
        if not os.path.exists(p):
            sys.exit(f"ERRO: falta {p}")

    # ---------------------------------------------------------------- carga
    H = {}
    for r in ler_csv(humano_csv):
        rid = int(str(r["id"]).strip())
        H[rid] = {"tipo": norm_tipo(r.get("tipo_ruido")),
                  "conf": norm_conf(r.get("confianca")),
                  "cwe_bigvul": str(r.get("cwe_bigvul") or "").strip().upper(),
                  "obs": str(r.get("observacao") or "").strip()}

    runs = defaultdict(dict)
    for r in ler_csv(modelo_csv):
        runs[int(r["run"])][int(r["id"])] = {
            "tipo": norm_tipo(r.get("tipo_ruido")),
            "conf": norm_conf(r.get("confianca")),
            "obs": str(r.get("observacao") or "").strip()}

    manif = {int(r["id"]): r for r in ler_csv(manifesto)}
    commit_de = {i: (m.get("commit_id") or f"sem_commit_{i}") for i, m in manif.items()}
    auto_a = {i for i, m in manif.items() if str(m.get("pre_marcado_auto_a")) == "1"}

    ids = sorted(set(H) & set(manif))
    lista_runs = sorted(runs)
    if not lista_runs:
        sys.exit("ERRO: nenhuma repeticao no CSV do modelo.")

    # ----------------------------------------------------- voto majoritario
    M, empates, incompletos = {}, [], []
    for i in ids:
        votos = [runs[r][i]["tipo"] for r in lista_runs
                 if i in runs[r] and runs[r][i]["tipo"]]
        if len(votos) < len(lista_runs):
            incompletos.append(i)
        if not votos:
            M[i] = {"tipo": "", "votos": []}
            continue
        c = Counter(votos)
        topo = c.most_common()
        if len(topo) > 1 and topo[0][1] == topo[1][1]:
            M[i] = {"tipo": "?", "votos": votos}     # empate -> ? (pre-registrado)
            empates.append(i)
        else:
            M[i] = {"tipo": topo[0][0], "votos": votos}

    # ------------------------------------------------------------- relatorio
    L = []
    L.append("# Concordancia entre anotadores — ruido de rotulagem do BigVul")
    L.append("")
    L.append(f"- condicao: **{args.condicao}**")
    L.append(f"- repeticoes do modelo: {lista_runs}")
    L.append(f"- anotacao humana: `{os.path.basename(humano_csv)}`")
    L.append(f"- rubrica congelada: `rubrica_v1.md` sha256 `{sha256_arquivo(rubrica)}`")
    L.append(f"- plano de analise: `pre_registro.md` sha256 `{sha256_arquivo(pre_reg)}`")
    L.append(f"- bootstrap: {args.reps} reamostragens por cluster de commit, "
             f"semente {args.semente}")
    L.append("")
    L.append("> Os rotulos do humano sao os primarios. O modelo e verificacao de "
             "confiabilidade, nao ground truth. Nenhum rotulo foi alterado aqui; "
             "os kappas abaixo sao pre-adjudicacao.")
    L.append("")

    if incompletos:
        L.append(f"**Aviso:** {len(incompletos)} caso(s) sem todas as repeticoes: "
                 f"{incompletos}")
        L.append("")

    # -------------------------------------------------- 1. distribuicoes
    L.append("## 1. Distribuicao dos rotulos")
    L.append("")
    ch = Counter(H[i]["tipo"] or "(vazio)" for i in ids)
    cm = Counter(M[i]["tipo"] or "(vazio)" for i in ids)
    L.append("| tipo | humano | modelo (voto majoritario) |")
    L.append("| --- | --- | --- |")
    for t in TIPOS_COM_INDEF + ["(vazio)"]:
        if ch.get(t) or cm.get(t):
            L.append(f"| {t} | {ch.get(t, 0)} | {cm.get(t, 0)} |")
    L.append("")

    def taxa_ruido(rotulos):
        val = [t for t in rotulos if t in TIPOS]
        if not val:
            return None, 0, 0
        d = sum(1 for t in val if t == "D")
        return 100.0 * (1 - d / len(val)), d, len(val)

    th, dh, nh = taxa_ruido([H[i]["tipo"] for i in ids])
    tm, dm, nm = taxa_ruido([M[i]["tipo"] for i in ids])
    L.append("| anotador | D (vulneravel) | decididos | acuracia de rotulo | ruido estimado |")
    L.append("| --- | --- | --- | --- | --- |")
    L.append(f"| humano | {dh} | {nh} | {100-th:.1f}% | **{th:.1f}%** |")
    L.append(f"| modelo | {dm} | {nm} | {100-tm:.1f}% | **{tm:.1f}%** |")
    L.append("")

    # IC da taxa de ruido por bootstrap de cluster
    for nome, rot in (("humano", [H[i]["tipo"] for i in ids]),
                      ("modelo", [M[i]["tipo"] for i in ids])):
        cl = [commit_de[i] for i in ids]
        lo, hi, _, _ = bootstrap_cluster(
            rot, cl, lambda a: taxa_ruido(a)[0], args.reps, args.semente)
        L.append(f"- IC95% da taxa de ruido ({nome}): [{fmt(lo,1)}%, {fmt(hi,1)}%]")
    L.append("")
    L.append("**A faixa a reportar no TCC e a dos dois anotadores, com o humano "
             "como numero principal.**")
    L.append("")

    # -------------------------------------------------- 2. indefinidos
    L.append("## 2. Casos sem decisao (`?`)")
    L.append("")
    q_h = [i for i in ids if H[i]["tipo"] == "?"]
    q_m = [i for i in ids if M[i]["tipo"] == "?"]
    L.append(f"- humano marcou `?` em {len(q_h)} caso(s): {q_h or '—'}")
    L.append(f"- modelo marcou `?` em {len(q_m)} caso(s): {q_m or '—'}")
    if empates:
        L.append(f"- destes, {len(empates)} vieram de empate entre repeticoes "
                 f"(resolvido para `?` conforme pre-registro): {empates}")
    excluidos = sorted(set(q_h) | set(q_m) | {i for i in ids
                                              if not H[i]["tipo"] or not M[i]["tipo"]})
    L.append(f"- excluidos dos kappas e da taxa de ruido: {len(excluidos)} "
             f"caso(s) {excluidos or '—'}")
    L.append("")

    # -------------------------------------------------- 3. kappas
    L.append("## 3. Concordancia humano x modelo")
    L.append("")

    def monta(sub_ids):
        pares = [(H[i]["tipo"], M[i]["tipo"]) for i in sub_ids]
        cl = [commit_de[i] for i in sub_ids]
        return pares, cl

    base = [i for i in ids if i not in excluidos]
    p, c = monta(base)
    bloco_kappa("3.1 Todos os casos decididos por ambos (analise principal)",
                p, c, args.reps, args.semente, L)

    sem_auto = [i for i in base if i not in auto_a]
    if len(sem_auto) != len(base):
        p, c = monta(sem_auto)
        bloco_kappa(f"3.2 Excluindo o caso pre-preenchido automaticamente "
                    f"({sorted(auto_a)})", p, c, args.reps, args.semente, L)

    # por commit: primeira linha de cada commit distinto
    vistos, por_commit = set(), []
    for i in base:
        cid = commit_de[i]
        if cid not in vistos:
            vistos.add(cid)
            por_commit.append(i)
    p, c = monta(por_commit)
    bloco_kappa("3.3 Por commit (primeira linha de cada commit distinto)",
                p, c, args.reps, args.semente, L)

    # so alta confianca do humano
    alta = [i for i in base if H[i]["conf"] == "alta"]
    if alta:
        p, c = monta(alta)
        bloco_kappa("3.4 So casos em que o humano marcou confianca alta",
                    p, c, args.reps, args.semente, L)

    # -------------------------------------------------- 4. matriz de confusao
    L.append("## 4. Matriz de confusao (linhas = humano, colunas = modelo)")
    L.append("")
    L.append("Todos os casos, sem excluir `?`. Diagnostica **onde** os dois divergem.")
    L.append("")
    cats = TIPOS_COM_INDEF
    L.append("| H \\ M | " + " | ".join(cats) + " | total |")
    L.append("| --- |" + " --- |" * (len(cats) + 1))
    for th_ in cats:
        linha, tot = [], 0
        for tm_ in cats:
            n = sum(1 for i in ids if H[i]["tipo"] == th_ and M[i]["tipo"] == tm_)
            tot += n
            linha.append(f"**{n}**" if th_ == tm_ and n else str(n))
        L.append(f"| **{th_}** | " + " | ".join(linha) + f" | {tot} |")
    L.append("| **total** | " + " | ".join(
        str(sum(1 for i in ids if M[i]["tipo"] == tm_)) for tm_ in cats)
        + f" | {len(ids)} |")
    L.append("")

    # -------------------------------------------------- 5. auto-consistencia
    L.append("## 5. Auto-consistencia do modelo")
    L.append("")
    if len(lista_runs) < 2:
        L.append("_So uma repeticao: nao da para medir. Rode com R>=2 na condicao "
                 "primaria — um anotador que discorda de si mesmo nao serve como "
                 "segundo anotador._")
    else:
        itens = [[runs[r][i]["tipo"] for r in lista_runs]
                 for i in ids
                 if all(i in runs[r] and runs[r][i]["tipo"] for r in lista_runs)]
        kf, pbar, pe, n, r = kappa_fleiss(itens)
        iguais = sum(1 for it in itens if len(set(it)) == 1)
        L.append(f"- itens com todas as {len(lista_runs)} repeticoes validas: {n}")
        L.append(f"- **kappa de Fleiss entre repeticoes: {fmt(kf)}** "
                 f"(concordancia media {fmt(pbar)}, esperada {fmt(pe)})")
        L.append(f"- casos em que as {r} repeticoes deram o MESMO rotulo: "
                 f"{iguais}/{n} ({100.0*iguais/n:.1f}%)" if n else "")
        L.append("")
        instaveis = [i for i in ids
                     if all(i in runs[x] for x in lista_runs)
                     and len({runs[x][i]["tipo"] for x in lista_runs}) > 1]
        L.append(f"- casos instaveis entre repeticoes ({len(instaveis)}): "
                 f"{instaveis or '—'}")
        L.append("")
        L.append("> Este numero e o teto do kappa humano-modelo: o modelo nao pode "
                 "concordar com outro anotador mais do que concorda consigo mesmo.")
    L.append("")

    # -------------------------------------------------- 6. discordancias
    disc = [i for i in ids if H[i]["tipo"] != M[i]["tipo"]]
    L.append("## 6. Discordancias")
    L.append("")
    L.append(f"{len(disc)} de {len(ids)} casos. Detalhe em "
             f"`saida/discordancias{args.sufixo or ''}.csv`.")
    L.append("")
    if disc:
        L.append("| id | projeto | CVE | H | M | votos M | conf H |")
        L.append("| --- | --- | --- | --- | --- | --- | --- |")
        for i in disc:
            m = manif[i]
            L.append(f"| {i} | {m.get('project','')} | {m.get('cve_id','')} | "
                     f"{H[i]['tipo'] or '—'} | {M[i]['tipo'] or '—'} | "
                     f"{''.join(M[i]['votos']) or '—'} | {H[i]['conf'] or '—'} |")
        L.append("")
    troca_vered = [i for i in disc
                   if (H[i]["tipo"] == "D") != (M[i]["tipo"] == "D")
                   and H[i]["tipo"] in TIPOS and M[i]["tipo"] in TIPOS]
    L.append(f"Discordancias que mudam o veredito binario (vulneravel x nao): "
             f"{len(troca_vered)} — {troca_vered or '—'}. As demais sao divergencia "
             f"sobre *por que* nao e vulneravel e nao afetam a taxa de ruido.")
    L.append("")

    L.append("## 7. O que este relatorio nao diz")
    L.append("")
    L.append("- Nao diz quem esta certo. Mede reprodutibilidade, nao acuracia.")
    L.append("- As CVEs da amostra sao publicas e anteriores ao corte de treino do "
             "modelo; parte da concordancia pode ser memorizacao. A condicao "
             "`cve_oculta` sonda isso.")
    L.append("- n pequeno e linhas nao independentes: leia o IC, nao o ponto.")
    L.append("- Ver `pre_registro.md` para a lista completa de limitacoes "
             "declaradas antes da analise.")
    L.append("")

    saida_dir = os.path.join(raiz, "saida")
    os.makedirs(saida_dir, exist_ok=True)
    rel = os.path.join(saida_dir, f"relatorio_concordancia{args.sufixo or ''}.md")
    with open(rel, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))

    dcsv = os.path.join(saida_dir, f"discordancias{args.sufixo or ''}.csv")
    with open(dcsv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "project", "cve_id", "commit_id", "cwe_bigvul",
                    "tipo_humano", "conf_humano", "obs_humano",
                    "tipo_modelo", "votos_modelo", "obs_modelo_run1",
                    "muda_veredito_binario"])
        for i in disc:
            m = manif[i]
            obs_m = runs[lista_runs[0]].get(i, {}).get("obs", "")
            w.writerow([i, m.get("project", ""), m.get("cve_id", ""),
                        m.get("commit_id", ""), m.get("cwe_bigvul", ""),
                        H[i]["tipo"], H[i]["conf"], H[i]["obs"],
                        M[i]["tipo"], "".join(M[i]["votos"]), obs_m,
                        int(i in troca_vered)])

    print(f"Relatorio     : {rel}")
    print(f"Discordancias : {dcsv}  ({len(disc)} casos, "
          f"{len(troca_vered)} mudam o veredito binario)")
    print(f"Ruido humano  : {th:.1f}%   Ruido modelo: {tm:.1f}%")


if __name__ == "__main__":
    main()
