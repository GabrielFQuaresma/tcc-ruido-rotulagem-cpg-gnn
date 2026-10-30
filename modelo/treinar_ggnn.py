#!/usr/bin/env python3
"""ReVeal, passo 2 — treina a GGNN de um braco e grava o vetor de cada funcao (x_g).

    python3 treinar_ggnn.py --braco M_cur     # treina; se ja comecou, RETOMA do ultimo checkpoint
    python3 treinar_ggnn.py --fumaca          # teste de fumaca: amostra do TREINO, sem braco

ONDE ESTAMOS. Fase I do ReVeal: a GGNN (rede de grafos) e treinada no proprio dado, com uma camada
de classificacao provisoria; depois a camada e descartada e a soma dos estados dos nos de cada
funcao (x_g, 200 numeros) vira a entrada da Fase II. Uma GGNN por braco (D6), do zero (D4).

COMO TREINA (PLANO_TREINO.md §3.1 e D11): ate 500 epocas; ao fim de cada epoca, F1 na particao de
VALIDACAO no limiar 0,5 (D12); guarda a melhor; para depois de 50 epocas sem melhora. O codigo
oficial avalia em lotes de TREINO por acuracia — defeito registrado em PIPELINE_REVEAL.md §4.1.
Como no oficial: melhor = F1 estritamente maior, comecando de 0; se o F1 nunca passa de 0, nao ha
"melhor" e fica o ultimo modelo — o resumo marca `sem_melhora`, que e o caso de voltar ao autor.

MEMORIA. Um lote de 128 funcoes pode ter um grafo de 11.903 nos e 82.960 arestas. O lote e
processado em pedacos com no maximo ORCAMENTO arestas, e os gradientes sao somados antes do passo
do otimizador. Com a perda
somada (BCELoss reduction='sum', [D] main.py:71) e sem normalizacao por lote no GGNNSum, isso e a
mesma conta do lote inteiro (PLANO_TREINO.md §3.3 a). Se mesmo assim faltar memoria, o lote e
refeito do zero com metade do orcamento.

O QUE ESTE SCRIPT NAO FAZ: nao calcula metrica nenhuma no TESTE. Ele so grava x_g das funcoes de
teste (inferencia) para a Fase II. Resultado se abre num passo proprio, depois de todos os bracos.

SAIDA em ~/curadoria/modelo/ggnn/<braco>/: checkpoint.pt (retomada), melhor.pt, vetores.npz
(ids, particao, rotulo, x_g), resumo.json, historico.tsv.
"""

import argparse
import copy
import json
import os
import random
import sys
import time

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reveal_comum as C  # noqa: E402

T0 = time.time()
ORCAMENTO_PADRAO = 100000  # arestas por pedaco de lote; o teste de fumaca confere
# No WSL o driver do Windows deixa a GPU "emprestar" RAM do sistema quando a memoria acaba, em vez
# de dar erro — e tudo fica muito lento. Limitar a fracao faz faltar memoria virar erro, que o
# Treino.passo trata refazendo o lote com metade do orcamento.
FRACAO_GPU = 0.85


def log(*a):
    print("[%7.1fs]" % (time.time() - T0), *a, flush=True)


class Dados:
    """Le os arrays do vetorizar.py (memmap) e monta lotes DGL sob demanda."""

    def __init__(self):
        self.grafos = C.ler_grafos()
        self.por_id = {g["id"]: g for g in self.grafos}
        self.W = np.load(os.path.join(C.VETORES, "nos_w2v.npy"), mmap_mode="r")
        self.R = np.load(os.path.join(C.VETORES, "nos_rotulo.npy"))
        self.A = np.load(os.path.join(C.VETORES, "arestas.npy"), mmap_mode="r")
        self.AT = np.load(os.path.join(C.VETORES, "arestas_tipo.npy"), mmap_mode="r")
        self.n_rot_no = len(json.load(open(os.path.join(C.VETORES, "rotulos_no.json"))))
        self.n_tipos_aresta = len(json.load(open(os.path.join(C.VETORES, "rotulos_aresta.json"))))
        self.dim = self.n_rot_no + self.W.shape[1]

    def lote(self, ids, dev):
        import dgl
        gs = [self.por_id[i] for i in ids]
        ns = [g["n_nos"] for g in gs]
        es = [g["n_arestas"] for g in gs]
        x = np.zeros((sum(ns), self.dim), dtype=np.float32)
        src, dst, et = [], [], []
        p = 0
        for g, n, m in zip(gs, ns, es):
            a, b = g["ini_no"], g["ini_aresta"]
            x[p + np.arange(n), self.R[a:a + n]] = 1.0          # one-hot do rotulo do no
            x[p:p + n, self.n_rot_no:] = self.W[a:a + n]        # media Word2Vec do code do no
            ar = np.asarray(self.A[b:b + m])
            src.append(ar[:, 0] + p)
            dst.append(ar[:, 1] + p)
            et.append(np.asarray(self.AT[b:b + m]))
            p += n
        bg = dgl.graph((torch.from_numpy(np.concatenate(src)).long(),
                        torch.from_numpy(np.concatenate(dst)).long()), num_nodes=p)
        bg.set_batch_num_nodes(torch.tensor(ns, dtype=torch.long))
        bg.set_batch_num_edges(torch.tensor(es, dtype=torch.long))
        etypes = torch.from_numpy(np.concatenate(et).astype(np.int64))
        y = torch.tensor([float(g["rotulo"]) for g in gs])
        return bg.to(dev), torch.from_numpy(x).to(dev), etypes.to(dev), y.to(dev)


def pedacos(ids, dados, orcamento):
    """Divide um lote em pedacos de no maximo `orcamento` ARESTAS (um grafo maior fica sozinho).

    Quem ocupa memoria na GGNN sao as arestas: o GatedGraphConv do DGL calcula uma mensagem de 200
    numeros por aresta, em cada um dos 8 passos, e guarda para o backward. Media de 1233 arestas
    por funcao no dataset v3. (O teste de fumaca de 10/10 com orcamento por NOS transbordou para a
    RAM do sistema: pico de 8,96 GB numa placa de 4 GB.)"""
    atual, soma = [], 0
    for i in ids:
        m = dados.por_id[i]["n_arestas"]
        if atual and soma + m > orcamento:
            yield atual
            atual, soma = [], 0
        atual.append(i)
        soma += m
    if atual:
        yield atual


class Treino:
    def __init__(self, dados, dev, orcamento):
        self.d, self.dev, self.orc = dados, dev, orcamento
        C.fixar_sementes(C.GGNN_SEMENTE)
        self.model = C.GGNNSum(dados.dim, C.GGNN_OCULTA, dados.n_tipos_aresta, C.GGNN_PASSOS).to(dev)
        self.opt = torch.optim.Adam(self.model.parameters(), lr=C.GGNN_LR, weight_decay=C.GGNN_WD)
        self.perda = torch.nn.BCELoss(reduction="sum")
        self.pico = 0

    def passo(self, ids):
        """Um passo do otimizador sobre um lote; refaz com metade do orcamento se faltar memoria."""
        while True:
            self.opt.zero_grad()
            total = 0.0
            try:
                for pd in pedacos(ids, self.d, self.orc):
                    bg, x, et, y = self.d.lote(pd, self.dev)
                    l = self.perda(self.model(bg, x, et), y)
                    l.backward()
                    total += l.item()
                    del bg, x, et, y, l
                self.opt.step()
                self.pico = max(self.pico, torch.cuda.max_memory_allocated())
                return total
            except torch.cuda.OutOfMemoryError:
                self.opt.zero_grad()
                torch.cuda.empty_cache()
                if self.orc <= 2000:
                    raise
                self.orc //= 2
                log("sem memoria: orcamento de arestas por pedaco reduzido para", self.orc)

    @torch.no_grad()
    def prever(self, ids, devolver_vetor=False):
        self.model.eval()
        probs, vetores = [], []
        for k in range(0, len(ids), C.GGNN_LOTE):
            for pd in pedacos(ids[k:k + C.GGNN_LOTE], self.d, self.orc):
                bg, x, et, _ = self.d.lote(pd, self.dev)
                xg = self.model.vetor_da_funcao(bg, x, et)
                probs.append(self.model.sigmoid(self.model.classifier(xg)).squeeze(-1).cpu())
                if devolver_vetor:
                    vetores.append(xg.cpu())
        self.model.train()
        p = torch.cat(probs).numpy()
        return (p, torch.cat(vetores).numpy()) if devolver_vetor else p


def f1(y, pred):
    from sklearn.metrics import f1_score
    return float(f1_score(y, pred, zero_division=0))


def conjuntos(braco, dados):
    if braco.startswith("_fumaca"):
        # AMOSTRA DO TREINO, SEM BRACO, sem tocar validacao nem teste (PLANO_TREINO.md §7).
        # Semente 6060, nao usada antes no projeto. Entram a forca os 10 maiores grafos do treino,
        # para exercitar a memoria.
        treino = sorted(g["id"] for g in dados.grafos if g["particao"] == "treino")
        maiores = sorted(treino, key=lambda i: -dados.por_id[i]["n_nos"])[:10]
        resto = [i for i in treino if i not in set(maiores)]
        amostra = random.Random(6060).sample(resto, 590)
        pseudo_val = sorted(amostra[:120])
        pseudo_treino = sorted(amostra[120:] + maiores)
        return pseudo_treino, pseudo_val, []
    pos = C.positivos_do_braco(braco)
    sem_grafo = [i for i in pos if i not in dados.por_id]
    pos = [i for i in pos if i in dados.por_id]
    for i in pos:
        g = dados.por_id[i]
        assert g["particao"] == "treino" and g["rotulo"] == 1, i
    if sem_grafo:
        log("positivos do braco sem grafo (ficam fora):", sem_grafo)
    treino = sorted(pos + C.negativos_do_braco(braco, dados.grafos))
    val = sorted(g["id"] for g in dados.grafos if g["particao"] == "validacao")
    teste = sorted(g["id"] for g in dados.grafos if g["particao"] == "teste")
    return treino, val, teste


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--braco", choices=C.TODOS_BRACOS)
    ap.add_argument("--fumaca", action="store_true")
    ap.add_argument("--orcamento", type=int, default=ORCAMENTO_PADRAO)
    ap.add_argument("--max-epocas", type=int, default=C.GGNN_MAX_EPOCAS)
    ap.add_argument("--tf32", action="store_true",
                    help="so medicao no teste de fumaca: multiplicacao de matriz em TF32 (Ampere)")
    args = ap.parse_args()
    braco = "_fumaca" if args.fumaca else args.braco
    if args.tf32:
        if not args.fumaca:
            ap.error("--tf32 so no teste de fumaca, enquanto o autor nao decidir")
        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.allow_tf32 = True
        braco = "_fumaca_tf32"
    if not braco:
        ap.error("--braco ou --fumaca")
    if args.fumaca and args.max_epocas == C.GGNN_MAX_EPOCAS:
        args.max_epocas = 3
    pasta = os.path.join(C.SAIDA, "ggnn", braco)
    os.makedirs(pasta, exist_ok=True)
    if os.path.exists(os.path.join(pasta, "resumo.json")):
        log("ja terminado:", pasta)
        if json.load(open(os.path.join(pasta, "resumo.json")))["sem_melhora"] and not args.fumaca:
            log("...mas SEM MELHORA (F1 de validacao sempre 0) — parado ate o autor decidir")
            sys.exit(3)
        return
    dev = torch.device("cuda")
    torch.cuda.set_per_process_memory_fraction(FRACAO_GPU, 0)
    dados = Dados()
    treino, val, teste = conjuntos(braco, dados)
    y_tr = np.array([dados.por_id[i]["rotulo"] for i in treino])
    y_val = np.array([dados.por_id[i]["rotulo"] for i in val])
    log("braco %s | treino %d (%d positivos) | validacao %d (%d positivos) | teste %d (so vetor)" % (
        braco, len(treino), y_tr.sum(), len(val), y_val.sum(), len(teste)))

    t = Treino(dados, dev, args.orcamento)
    ck = os.path.join(pasta, "checkpoint.pt")
    st = {"epoca": 0, "melhor_f1": 0.0, "melhor_epoca": None, "paciencia": 0, "hist": []}
    if os.path.exists(ck):
        c = torch.load(ck, map_location=dev, weights_only=False)
        t.model.load_state_dict(c["model"])
        t.opt.load_state_dict(c["opt"])
        st = c["st"]
        t.orc = c.get("orc", t.orc)
        log("RETOMANDO da epoca", st["epoca"], "| melhor F1 val %.4f na epoca %s" % (
            st["melhor_f1"], st["melhor_epoca"]))

    while st["epoca"] < args.max_epocas and st["paciencia"] < C.GGNN_PACIENCIA:
        e = st["epoca"]
        ordem = np.random.RandomState(C.GGNN_SEMENTE + e).permutation(len(treino))
        t0, perda = time.time(), 0.0
        torch.cuda.reset_peak_memory_stats()
        for k in range(0, len(ordem), C.GGNN_LOTE):
            perda += t.passo([treino[j] for j in ordem[k:k + C.GGNN_LOTE]])
        t_treino = time.time() - t0
        p_val = t.prever(val)
        f1_val = f1(y_val, (p_val >= C.LIMIAR).astype(int))
        n_acusa = int((p_val >= C.LIMIAR).sum())
        t_epoca = time.time() - t0
        if f1_val > st["melhor_f1"]:
            st["melhor_f1"], st["melhor_epoca"], st["paciencia"] = f1_val, e, 0
            torch.save(t.model.state_dict(), os.path.join(pasta, "melhor.pt.tmp"))
            os.replace(os.path.join(pasta, "melhor.pt.tmp"), os.path.join(pasta, "melhor.pt"))
        else:
            st["paciencia"] += 1
        st["hist"].append([e, round(perda, 3), round(f1_val, 4), n_acusa, round(t_treino, 1),
                           round(t_epoca, 1), round(t.pico / 2**30, 2)])
        st["epoca"] = e + 1
        torch.save({"model": t.model.state_dict(), "opt": t.opt.state_dict(), "st": st, "orc": t.orc},
                   ck + ".tmp")
        os.replace(ck + ".tmp", ck)
        log("epoca %3d | perda %12.1f | F1 val %.4f (acusou %d de %d) | melhor %.4f (ep %s) | "
            "paciencia %2d | %.0fs treino + %.0fs val | pico GPU %.2f GB | orcamento %d" % (
                e, perda, f1_val, n_acusa, len(val), st["melhor_f1"], st["melhor_epoca"],
                st["paciencia"], t_treino, t_epoca - t_treino, t.pico / 2**30, t.orc))

    if braco.startswith("_fumaca") and st["hist"]:
        # projecao do tempo de uma epoca nos bracos de verdade, pela taxa de arestas por segundo
        ar = lambda ids: sum(dados.por_id[i]["n_arestas"] for i in ids)  # noqa: E731
        taxa = ar(treino) / st["hist"][-1][4]
        val_real = [g["id"] for g in dados.grafos if g["particao"] == "validacao"]
        for b in ("M_cur", "M_raw", "M_cur_bal"):
            tr_b, _, _ = conjuntos(b, dados)
            seg = ar(tr_b) / taxa + ar(val_real) / (3 * taxa)
            log("PROJECAO %s: %d funcoes, %.1f mi arestas -> ~%.0f min por epoca (51 epocas ~%.1f h; "
                "500 ~%.0f h)" % (b, len(tr_b), ar(tr_b) / 1e6, seg / 60, 51 * seg / 3600, 500 * seg / 3600))
    sem_melhora = st["melhor_epoca"] is None
    if not sem_melhora:
        t.model.load_state_dict(torch.load(os.path.join(pasta, "melhor.pt"), map_location=dev))
    else:
        log("ATENCAO: o F1 na validacao nunca passou de 0 — fica o ultimo modelo (como no oficial).",
            "Este e o caso de voltar ao autor (PLANO_TREINO.md §3.3 c).")
    ids = treino + val + teste
    _, X = t.prever(ids, devolver_vetor=True)
    np.savez(os.path.join(pasta, "vetores.npz"),
             ids=np.array(ids), X=X.astype(np.float32),
             particao=np.array([dados.por_id[i]["particao"] for i in ids]),
             rotulo=np.array([dados.por_id[i]["rotulo"] for i in ids], dtype=np.int8),
             no_treino_do_braco=np.array([1] * len(treino) + [0] * (len(val) + len(teste)), dtype=np.int8))
    with open(os.path.join(pasta, "historico.tsv"), "w") as f:
        f.write("epoca\tperda\tf1_val\tacusou_val\tseg_treino\tseg_epoca\tpico_gpu_gb\n")
        for h in st["hist"]:
            f.write("\t".join(map(str, h)) + "\n")
    resumo = {
        "braco": braco, "n_treino": len(treino), "positivos_treino": int(y_tr.sum()),
        "n_validacao": len(val), "n_teste_so_vetor": len(teste),
        "epocas_rodadas": st["epoca"], "melhor_epoca": st["melhor_epoca"],
        "melhor_f1_validacao": st["melhor_f1"], "sem_melhora": sem_melhora,
        "parou_por": "paciencia" if st["paciencia"] >= C.GGNN_PACIENCIA else "maximo de epocas",
        "orcamento_final": t.orc, "segundos_nesta_execucao": round(time.time() - T0, 1),
        "hiperparametros": {"oculta": C.GGNN_OCULTA, "passos": C.GGNN_PASSOS, "lr": C.GGNN_LR,
                            "wd": C.GGNN_WD, "lote": C.GGNN_LOTE, "max_epocas": args.max_epocas,
                            "paciencia": C.GGNN_PACIENCIA, "semente": C.GGNN_SEMENTE,
                            "limiar": C.LIMIAR, "entrada": dados.dim,
                            "tipos_de_aresta": dados.n_tipos_aresta},
    }
    json.dump(resumo, open(os.path.join(pasta, "resumo.json"), "w"), indent=2, ensure_ascii=False)
    log("PRONTO", json.dumps(resumo, ensure_ascii=False))
    if sem_melhora and not args.fumaca:
        sys.exit(3)  # para o rodar_todos.sh: os bracos seguintes esperam a decisao do autor


if __name__ == "__main__":
    main()
