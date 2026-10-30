#!/usr/bin/env python3
"""ReVeal, passo 3 — Fase II: SMOTE + rede com triplet loss, 30 repeticoes por braco.

    python3 treinar_fase2.py --braco M_cur    # 30 sementes; retoma (pula semente ja gravada)
    python3 treinar_fase2.py --fumaca         # sobre a GGNN do teste de fumaca, 2 sementes

ONDE ESTAMOS. A GGNN do braco ja gravou x_g (200 numeros por funcao). A Fase II rebalanceia o
treino com SMOTE (cria positivos sinteticos interpolando positivos vizinhos) e treina a rede de
representacao (MetricLearningModel), que soma classificacao + triplet loss + regularizacao.

O QUE VEM DO OFICIAL ([R] Vuld_SySe/representation_learning/): o modelo (reveal_comum.py), a
chamada do SMOTE (`SMOTE(random_state=1000).fit_resample`, graph_dataset.py:53-54), o laco de
treino (trainer.py:14-90: Adam, ate 100 epocas, validacao a cada epoca por F1 no argmax, paciencia
5), o sorteio dos exemplos da triplet loss (um da mesma classe e um da outra, uniforme no treino
fora do proprio lote, graph_dataset.py:160-185).

DIFERENCAS DECLARADAS (todas de PLANO_TREINO.md ou defeitos do oficial):
  - validacao = a particao de validacao do split, nao 10% sorteados do treino (§3.1);
  - sem redivisao a cada repeticao — o split e congelado (§3.2; o oficial vaza o teste, §4.2);
  - o oficial so restaura o melhor modelo quando a paciencia estoura; se chega a 100 epocas, fica
    o ultimo. Aqui a melhor epoca e restaurada sempre;
  - o oficial monta os lotes com `np.arange(0, total - 1)` e perde o ultimo exemplo de cada
    conjunto (inclusive da validacao); aqui entram todos;
  - o sorteio da triplet loss e o mesmo sorteio (uniforme na classe, fora do lote), feito com
    numpy vetorizado em vez de laco Python — o oficial converte o conjunto em lista a cada exemplo.

O QUE ESTE SCRIPT NAO FAZ: nao calcula metrica no TESTE. Grava a predicao de cada funcao de teste
COM O ID (que o PREREGISTRO_TAMANHO.md precisa) e so imprime o F1 da VALIDACAO.

SAIDA em ~/curadoria/modelo/fase2/<braco>/semente_<s>.tsv (id, particao, prob_vulneravel,
predicao) e resumo.json.

REFEITA COM OS MODELOS SALVOS (12/10/2026, PREREGISTRO_PRINCIPAL.md §6 passo 2): com
`--pasta fase2_v2`, grava tambem modelo_<s>.pt (state_dict da melhor epoca), para os mesmos 390
modelos preverem o teste do BigVul e, depois, as arenas externas. A unica mudanca e gravar o
modelo; nenhuma conta muda. A pasta original `fase2/` fica como registro.
"""

import argparse
import copy
import json
import os
import sys
import time

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reveal_comum as C  # noqa: E402

T0 = time.time()


def log(*a):
    print("[%7.1fs]" % (time.time() - T0), *a, flush=True)


def f1(y, pred):
    from sklearn.metrics import f1_score
    return float(f1_score(y, pred, zero_division=0))


def sortear_fora_do_lote(pools, classe_alvo, lote):
    """Para cada exemplo do lote, um indice uniforme do pool da `classe_alvo` dele, fora do lote."""
    fora = set(lote.tolist())
    saida = np.empty(len(lote), dtype=np.int64)
    for c in (0, 1):
        quem = np.where(classe_alvo == c)[0]
        if len(quem) == 0:
            continue
        pool = pools[c]
        esc = pool[np.random.randint(0, len(pool), size=len(quem))]
        ruins = np.array([e in fora for e in esc])
        while ruins.any():
            esc[ruins] = pool[np.random.randint(0, len(pool), size=int(ruins.sum()))]
            ruins = np.array([e in fora for e in esc])
        saida[quem] = esc
    return saida


@torch.no_grad()
def probs(model, X):
    model.eval()
    p = torch.cat([model(example_batch=X[k:k + 4096])[0] for k in range(0, len(X), 4096)])
    model.train()
    return p[:, 1].cpu().numpy()


def treinar_uma(semente, Xs, ys, Xv, yv, dev):
    C.fixar_sementes(semente)
    model = C.MetricLearningModel(input_dim=Xs.shape[1], hidden_dim=C.F2_OCULTA,
                                  dropout_p=C.F2_DROPOUT, aplha=C.F2_ALFA,
                                  lambda1=C.F2_LAMBDA1, lambda2=C.F2_LAMBDA2).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=C.F2_LR)
    Xt, yt = torch.from_numpy(Xs).to(dev), torch.from_numpy(ys).long().to(dev)
    pools = {0: np.where(ys == 0)[0], 1: np.where(ys == 1)[0]}
    melhor_f1, melhor, melhor_ep, paciencia, ep = 0.0, None, None, 0, 0
    for ep in range(C.F2_EPOCAS):
        ordem = np.random.permutation(len(ys))
        model.train()
        for k in range(0, len(ordem), C.F2_LOTE):
            b = ordem[k:k + C.F2_LOTE]
            mesma = sortear_fora_do_lote(pools, ys[b], b)
            outra = sortear_fora_do_lote(pools, 1 - ys[b], b)
            opt.zero_grad()
            _, _, perda = model(example_batch=Xt[b], targets=yt[b],
                                positive_batch=Xt[mesma], negative_batch=Xt[outra])
            perda.backward()
            opt.step()
        f1_v = f1(yv, (probs(model, Xv) >= C.LIMIAR).astype(int))
        if f1_v > melhor_f1:
            melhor_f1, melhor, melhor_ep, paciencia = f1_v, copy.deepcopy(model.state_dict()), ep, 0
        else:
            paciencia += 1
        if paciencia == C.F2_PACIENCIA:
            break
    if melhor is not None:
        model.load_state_dict(melhor)
    return model, {"semente": semente, "epocas": ep + 1, "melhor_epoca": melhor_ep,
                   "f1_validacao": round(melhor_f1, 4), "sem_melhora": melhor is None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--braco", choices=C.TODOS_BRACOS)
    ap.add_argument("--fumaca", action="store_true")
    ap.add_argument("--pasta", default="fase2",
                    help="pasta de saida em ~/curadoria/modelo/; fase2_v2 = rodada com modelos salvos")
    args = ap.parse_args()
    braco = "_fumaca" if args.fumaca else args.braco
    if not braco:
        ap.error("--braco ou --fumaca")
    sementes = C.F2_SEMENTES[:2] if args.fumaca else C.F2_SEMENTES
    v = np.load(os.path.join(C.SAIDA, "ggnn", braco, "vetores.npz"))
    ids, X, part, rot, notr = v["ids"], v["X"], v["particao"], v["rotulo"].astype(np.int64), \
        v["no_treino_do_braco"]
    tr = notr == 1
    va = (notr == 0) if args.fumaca else (part == "validacao")
    te = np.zeros_like(tr) if args.fumaca else (part == "teste")
    from imblearn.over_sampling import SMOTE
    Xs, ys = SMOTE(random_state=C.SMOTE_SEMENTE).fit_resample(X[tr], rot[tr])
    Xs, ys = Xs.astype(np.float32), ys.astype(np.int64)
    log("braco %s | treino %d (%d pos) -> SMOTE %d (%d pos) | validacao %d (%d pos) | teste %d" % (
        braco, tr.sum(), rot[tr].sum(), len(ys), ys.sum(), va.sum(), rot[va].sum(), te.sum()))
    dev = torch.device("cuda")
    Xv = torch.from_numpy(X[va]).to(dev)
    Xte = torch.from_numpy(X[te]).to(dev)
    pasta = os.path.join(C.SAIDA, args.pasta, braco)
    os.makedirs(pasta, exist_ok=True)
    salvar_modelo = args.pasta != "fase2"  # a rodada original nao gravava o modelo
    resumos = []
    for s in sementes:
        arq = os.path.join(pasta, "semente_%d.tsv" % s)
        rarq = arq + ".json"
        parq = os.path.join(pasta, "modelo_%d.pt" % s)
        if os.path.exists(arq) and os.path.exists(rarq) and (os.path.exists(parq) or not salvar_modelo):
            resumos.append(json.load(open(rarq)))
            continue
        model, r = treinar_uma(s, Xs, ys, Xv, rot[va], dev)
        if salvar_modelo:
            torch.save(model.state_dict(), parq + ".tmp")
            os.replace(parq + ".tmp", parq)
        linhas = ["id\tparticao\tprob_vulneravel\tpredicao"]
        for mask, Xm in ((va, Xv), (te, Xte)):
            if mask.sum() == 0:
                continue
            p = probs(model, Xm)
            for i, pp in zip(ids[mask], p):
                linhas.append("%s\t%s\t%.6f\t%d" % (i, part[mask][0] if not args.fumaca else "pseudo_val",
                                                     pp, int(pp >= C.LIMIAR)))
        open(arq + ".tmp", "w").write("\n".join(linhas) + "\n")
        os.replace(arq + ".tmp", arq)
        json.dump(r, open(rarq, "w"))
        resumos.append(r)
        log("semente %d | epocas %d | melhor %s | F1 validacao %.4f%s" % (
            s, r["epocas"], r["melhor_epoca"], r["f1_validacao"], " | SEM MELHORA" if r["sem_melhora"] else ""))
    f1s = [r["f1_validacao"] for r in resumos]
    resumo = {"braco": braco, "n_sementes": len(resumos), "f1_validacao_mediana": float(np.median(f1s)),
              "f1_validacao_min": min(f1s), "f1_validacao_max": max(f1s),
              "sementes_sem_melhora": sum(r["sem_melhora"] for r in resumos),
              "treino_apos_smote": int(len(ys)), "positivos_apos_smote": int(ys.sum())}
    if len(resumos) == len(sementes):
        json.dump(resumo, open(os.path.join(pasta, "resumo.json"), "w"), indent=2)
    log("PRONTO", json.dumps(resumo))


if __name__ == "__main__":
    main()
