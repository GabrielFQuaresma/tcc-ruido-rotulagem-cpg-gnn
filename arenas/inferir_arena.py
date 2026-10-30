#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Predicoes dos 13 bracos (GGNN + 30 modelos da Fase II) nas arenas — PREREGISTRO_ARENAS.md §10 passo 5.

    python3 inferir_arena.py --conferir-bigvul          # conferencia de reproducao (so o teste do BigVul)
    python3 inferir_arena.py --arena sonda              # grava as predicoes; nao le nem calcula nada

ONDE ESTAMOS. Os modelos ja existem: a GGNN de cada braco (~/curadoria/modelo/ggnn/<braco>/melhor.pt) e
os 390 da Fase II (fase2_v2/<braco>/modelo_<s>.pt). **Nada e retreinado e nada e ajustado em dado de
arena** (adendo §0). O caminho e o do treino, importado: treinar_ggnn.Treino.prever (o x_g de cada
funcao, em lotes de 128 partidos pelo orcamento de arestas que o braco terminou o treino usando) e
treinar_fase2.probs (a probabilidade de vulneravel; predicao = prob >= 0,5, D12).

CONFERENCIA DE REPRODUCAO (exigida pelo §10 passo 5, antes de prever qualquer arena): rodado nos grafos
do TESTE DO BIGVUL (ja aberto em 13/10), o script tem de reproduzir as predicoes gravadas em fase2_v2/.
Compara, por braco: o x_g recalculado contra o vetores.npz do treino; e, por semente, a predicao e a
probabilidade (6 casas, como gravada) contra semente_<s>.tsv.

TRAVA DA DECISAO K: a traversal pura roda "antes de qualquer modelo prever a arena". O modo --arena
recusa rodar se a traversal daquela arena (no conjunto com veredito) nao estiver completa.

ESTE SCRIPT NAO CALCULA METRICA NAS ARENAS. Grava id, probabilidade e predicao em
~/curadoria/arenas/<pasta>/predicoes/<braco>/semente_<s>.tsv; quem le e o script de analise, na
abertura, com o autor presente (§10 passo 7).
"""
import argparse
import csv
import glob
import json
import os
import sys
import time

import numpy as np
import torch

AQUI = os.path.dirname(os.path.abspath(__file__))
MODELO = os.path.join(os.path.dirname(AQUI), "modelo")
sys.path.insert(0, MODELO)
sys.path.insert(0, AQUI)
import reveal_comum as C  # noqa: E402
import treinar_fase2 as F2  # noqa: E402
import treinar_ggnn as TG  # noqa: E402

T0 = time.time()
PASTAS = {"sonda": "sonda", "ventivul": "ventivul", "primevul": "primevul"}


def log(*a):
    print("[%7.1fs]" % (time.time() - T0), *a, flush=True)


class DadosArena(TG.Dados):
    """Os arrays do vetorizar_arena.py, no lugar dos do treino; rotulos de no/aresta do treino."""

    def __init__(self, pasta):
        v = os.path.expanduser(f"~/curadoria/arenas/{pasta}/vetores")
        linhas = open(os.path.join(v, "grafos.tsv"), encoding="utf-8").read().splitlines()
        cab = linhas[0].split("\t")
        self.grafos = []
        for l in linhas[1:]:
            d = dict(zip(cab, l.split("\t")))
            for k in ("rotulo", "n_nos", "n_arestas", "ini_no", "ini_aresta"):
                d[k] = int(d[k])
            self.grafos.append(d)
        self.por_id = {g["id"]: g for g in self.grafos}
        self.W = np.load(os.path.join(v, "nos_w2v.npy"), mmap_mode="r")
        self.R = np.load(os.path.join(v, "nos_rotulo.npy"))
        self.A = np.load(os.path.join(v, "arestas.npy"), mmap_mode="r")
        self.AT = np.load(os.path.join(v, "arestas_tipo.npy"), mmap_mode="r")
        self.n_rot_no = len(json.load(open(os.path.join(C.VETORES, "rotulos_no.json"))))
        self.n_tipos_aresta = len(json.load(open(os.path.join(C.VETORES, "rotulos_aresta.json"))))
        self.dim = self.n_rot_no + self.W.shape[1]


def ggnn_do_braco(braco, dados, dev):
    """O Treino do treinar_ggnn com os pesos de melhor.pt e o orcamento final do treino do braco."""
    pasta = os.path.join(C.SAIDA, "ggnn", braco)
    t = TG.Treino(dados, dev, TG.ORCAMENTO_PADRAO)
    ck = torch.load(os.path.join(pasta, "checkpoint.pt"), map_location="cpu", weights_only=False)
    t.orc = ck.get("orc", TG.ORCAMENTO_PADRAO)
    del ck
    t.model.load_state_dict(torch.load(os.path.join(pasta, "melhor.pt"), map_location=dev))
    return t


def fase2(braco, s, dev):
    m = C.MetricLearningModel(input_dim=C.GGNN_OCULTA, hidden_dim=C.F2_OCULTA, dropout_p=C.F2_DROPOUT,
                              aplha=C.F2_ALFA, lambda1=C.F2_LAMBDA1, lambda2=C.F2_LAMBDA2).to(dev)
    m.load_state_dict(torch.load(os.path.join(C.SAIDA, "fase2_v2", braco, f"modelo_{s}.pt"), map_location=dev))
    return m


def conferir_bigvul():
    dev = torch.device("cuda")
    torch.cuda.set_per_process_memory_fraction(TG.FRACAO_GPU, 0)
    dados = TG.Dados()
    teste = sorted(g["id"] for g in dados.grafos if g["particao"] == "teste")
    tot = {"x_maxdif": 0.0, "pred_dif": 0, "prob_dif": 0, "prob_maxdif": 0.0, "n": 0}
    for braco in C.TODOS_BRACOS:
        t = ggnn_do_braco(braco, dados, dev)
        _, X = t.prever(teste, devolver_vetor=True)
        v = np.load(os.path.join(C.SAIDA, "ggnn", braco, "vetores.npz"))
        pos = {i: k for k, i in enumerate(v["ids"])}
        X0 = v["X"][[pos[i] for i in teste]]
        xdif = float(np.abs(X.astype(np.float32) - X0).max())
        pdif = qdif = 0
        for s in C.F2_SEMENTES:
            m = fase2(braco, s, dev)
            p = F2.probs(m, torch.from_numpy(X.astype(np.float32)).to(dev))
            grav = {r["id"]: r for r in csv.DictReader(open(os.path.join(C.SAIDA, "fase2_v2", braco, f"semente_{s}.tsv")),
                                                       delimiter="\t") if r["particao"] == "teste"}
            for i, pp in zip(teste, p):
                pdif += int(pp >= C.LIMIAR) != int(grav[i]["predicao"])
                qdif += "%.6f" % pp != grav[i]["prob_vulneravel"]
                tot["prob_maxdif"] = max(tot["prob_maxdif"], abs(float(pp) - float(grav[i]["prob_vulneravel"])))
            tot["n"] += len(teste)
        tot["x_maxdif"] = max(tot["x_maxdif"], xdif)
        tot["pred_dif"] += pdif
        tot["prob_dif"] += qdif
        log(f"{braco:18s} x_g max |dif| {xdif:.2e} | predicoes diferentes {pdif} | probabilidades diferentes (6 casas) {qdif} "
            f"(de {len(teste) * len(C.F2_SEMENTES)})")
        del t
        torch.cuda.empty_cache()
    log("TOTAL", json.dumps(tot))
    return tot


def traversal_completa(arena):
    """A traversal pura da arena (conjunto com veredito) tem saida para toda funcao da fila?"""
    import rodar_traversal_arena as rta
    alvos = {"sonda": ["sonda"], "ventivul": ["ventivul_familia"], "primevul": ["primevul"]}[arena]
    for ar in alvos:
        fila = rta.montar_fila(ar)
        falta = [x for x in fila if not os.path.exists(os.path.join(rta.saida_de(ar), x["id"] + ".json"))]
        if falta:
            log(f"[{ar}] traversal incompleta: faltam {len(falta)} de {len(fila)}")
            return False
    return True


def prever_arena(arena):
    if not traversal_completa(arena):
        sys.exit("TRAVA DA DECISAO K: a traversal pura desta arena nao terminou; nenhum modelo preve antes.")
    dev = torch.device("cuda")
    torch.cuda.set_per_process_memory_fraction(TG.FRACAO_GPU, 0)
    dados = DadosArena(PASTAS[arena])
    ids = [g["id"] for g in dados.grafos]
    base = os.path.expanduser(f"~/curadoria/arenas/{PASTAS[arena]}/predicoes")
    for braco in C.TODOS_BRACOS:
        pasta = os.path.join(base, braco)
        if all(os.path.exists(os.path.join(pasta, f"semente_{s}.tsv")) for s in C.F2_SEMENTES):
            continue
        os.makedirs(pasta, exist_ok=True)
        t = ggnn_do_braco(braco, dados, dev)
        _, X = t.prever(ids, devolver_vetor=True)
        Xt = torch.from_numpy(X.astype(np.float32)).to(dev)
        for s in C.F2_SEMENTES:
            p = F2.probs(fase2(braco, s, dev), Xt)
            arq = os.path.join(pasta, f"semente_{s}.tsv")
            with open(arq + ".tmp", "w") as f:
                f.write("id\tprob_vulneravel\tpredicao\n")
                for i, pp in zip(ids, p):
                    f.write("%s\t%.6f\t%d\n" % (i, pp, int(pp >= C.LIMIAR)))
            os.replace(arq + ".tmp", arq)
        log(f"[{arena}] {braco}: {len(ids)} funcoes x {len(C.F2_SEMENTES)} sementes gravadas (nada lido)")
        del t, Xt
        torch.cuda.empty_cache()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conferir-bigvul", action="store_true")
    ap.add_argument("--arena", choices=sorted(PASTAS))
    a = ap.parse_args()
    if a.conferir_bigvul:
        r = conferir_bigvul()
        sys.exit(0 if r["pred_dif"] == 0 else 1)
    elif a.arena:
        prever_arena(a.arena)
    else:
        ap.error("--conferir-bigvul ou --arena")
