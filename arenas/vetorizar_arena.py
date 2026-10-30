#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vetor inicial de cada no dos grafos de uma arena, com o Word2Vec DO TREINO (sem retreinar).

O QUE E, situando
-----------------
Preparacao das arenas (PREREGISTRO_ARENAS.md §10, passos 3 e 5). O ReVeal precisa de um vetor por no
antes da GGNN: o one-hot do rotulo do no (18 rotulos do Joern) + a media dos vetores Word2Vec dos
tokens do `code` do no (modelo/vetorizar.py, passo C; PLANO_TREINO.md D10). Nas arenas, **nada e
ajustado em dado de arena** (adendo §0): o Word2Vec e o do treino do BigVul, carregado de
~/curadoria/modelo/vetores/word2vec.model, e os indices de rotulo de no e de aresta sao os do treino.
Token fora do vocabulario conta como vetor zero na media, como no BigVul (4,7% la). A taxa de tokens
fora do vocabulario de cada arena vai para a ficha de preparacao (§10, passo 3).

O MESMO LACO DO TREINO. O passo C do vetorizar.py nao e uma funcao importavel; o laco abaixo o
reproduz (mesma tokenizacao nltk.word_tokenize, mesma media, mesmo cache por `code` curto, mesma
contagem de tokens). Para nao depender de confianca: `--conferir-bigvul N` vetoriza os N primeiros
grafos do dataset v3 com ESTE codigo e compara com os vetores gravados no treino (nos_w2v.npy,
nos_rotulo.npy, arestas.npy, arestas_tipo.npy). Tem de dar identico.

Uso:  python3 vetorizar_arena.py <arena>                # ex.: sonda | ventivul | primevul
      python3 vetorizar_arena.py --conferir-bigvul 300
Saida: ~/curadoria/arenas/<arena>/vetores/ (mesmos nomes do treino) + relatorio.json. Nenhum modelo
preve nada aqui.
"""
import glob
import hashlib
import json
import os
import sys

import numpy as np

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(AQUI), "modelo"))
import reveal_comum as C  # noqa: E402


def sha256(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Vetorizador:
    """O passo C do vetorizar.py, com o Word2Vec e os rotulos do treino."""

    def __init__(self):
        from gensim.models import Word2Vec
        from nltk import word_tokenize
        self.tok = word_tokenize
        self.caminho_w2v = os.path.join(C.VETORES, "word2vec.model")
        w2v = Word2Vec.load(self.caminho_w2v)
        self.kti, self.vec = w2v.wv.key_to_index, w2v.wv.vectors
        self.idx_no = {r: k for k, r in enumerate(json.load(open(os.path.join(C.VETORES, "rotulos_no.json"))))}
        self.idx_ar = {r: k for k, r in enumerate(json.load(open(os.path.join(C.VETORES, "rotulos_aresta.json"))))}
        self.cache, self.zero = {}, np.zeros(C.W2V_DIM, dtype=np.float32)
        self.oov = self.tok_total = 0

    def no(self, code):
        v = self.cache.get(code)
        if v is None:
            toks = self.tok(code)
            ids = [self.kti[t] for t in toks if t in self.kti]
            self.oov += len(toks) - len(ids)
            self.tok_total += len(toks)
            v = self.vec[ids].sum(axis=0) / len(toks) if ids else self.zero
            if len(code) <= 80:
                if len(self.cache) > 3_000_000:
                    self.cache.clear()
                self.cache[code] = v
        return v

    def grafo(self, d):
        """(W [n,100], R [n], A [m,2], AT [m]) de um grafo exportado; KeyError se rotulo desconhecido."""
        W = np.stack([self.no(n["code"]) for n in d["nos"]]).astype(np.float32)
        R = np.array([self.idx_no[n["label"]] for n in d["nos"]], dtype=np.int8)
        A = np.array([(a[0], a[1]) for a in d["arestas"]], dtype=np.int32).reshape(-1, 2)
        AT = np.array([self.idx_ar[a[2]] for a in d["arestas"]], dtype=np.int8)
        return W, R, A, AT


def conferir_bigvul(n):
    """Vetoriza os n primeiros grafos do dataset v3 (na ordem do grafos.tsv do treino) e compara."""
    V = Vetorizador()
    tab = [l.split("\t") for l in open(os.path.join(C.VETORES, "grafos.tsv"), encoding="utf-8").read().splitlines()[1:]]
    pos = {t[0]: (int(t[5]), int(t[6]), int(t[3]), int(t[4])) for t in tab}
    W0 = np.load(os.path.join(C.VETORES, "nos_w2v.npy"), mmap_mode="r")
    R0 = np.load(os.path.join(C.VETORES, "nos_rotulo.npy"), mmap_mode="r")
    A0 = np.load(os.path.join(C.VETORES, "arestas.npy"), mmap_mode="r")
    T0 = np.load(os.path.join(C.VETORES, "arestas_tipo.npy"), mmap_mode="r")
    vistos = difs = 0
    for arq in sorted(glob.glob(os.path.join(C.GRUPOS, "*.jsonl"))):
        for l in open(arq, encoding="utf-8"):
            d = json.loads(l)
            pn, pa, nn, na = pos[d["id"]]
            W, R, A, AT = V.grafo(d)
            ok = (np.array_equal(W, W0[pn:pn + nn]) and np.array_equal(R, R0[pn:pn + nn])
                  and np.array_equal(A, A0[pa:pa + na]) and np.array_equal(AT, T0[pa:pa + na]))
            difs += not ok
            vistos += 1
            if vistos >= n:
                print(f"conferencia contra o treino: {vistos} grafos, {difs} diferentes")
                return difs == 0
    print(f"conferencia contra o treino: {vistos} grafos, {difs} diferentes")
    return difs == 0


def vetorizar(arena):
    base = os.path.expanduser(f"~/curadoria/arenas/{arena}")
    saida = os.path.join(base, "vetores")
    os.makedirs(saida, exist_ok=True)
    V = Vetorizador()
    arquivos = sorted(glob.glob(os.path.join(base, "grafos", "*.jsonl")))
    # duas passadas, como o vetorizar.py do treino: conta, depois grava direto em arquivo mapeado
    # (acumular em lista e juntar no fim dava ~2 GB de pico no PrimeVul; o WSL tem 6 GB)
    n_nos = n_ar = 0
    for arq in arquivos:
        for l in open(arq, encoding="utf-8"):
            d = json.loads(l)
            n_nos += len(d["nos"])
            n_ar += len(d["arestas"])
    tmp = lambda n: os.path.join(saida, n + ".tmp.npy")  # noqa: E731
    Wm = np.lib.format.open_memmap(tmp("nos_w2v"), mode="w+", dtype=np.float32, shape=(n_nos, C.W2V_DIM))
    Rm = np.lib.format.open_memmap(tmp("nos_rotulo"), mode="w+", dtype=np.int8, shape=(n_nos,))
    Am = np.lib.format.open_memmap(tmp("arestas"), mode="w+", dtype=np.int32, shape=(n_ar, 2))
    ATm = np.lib.format.open_memmap(tmp("arestas_tipo"), mode="w+", dtype=np.int8, shape=(n_ar,))
    tabela = ["id\trotulo\tparticao\tn_nos\tn_arestas\tini_no\tini_aresta"]
    pn = pa = 0
    for arq in arquivos:
        for l in open(arq, encoding="utf-8"):
            d = json.loads(l)
            W, R, A, AT = V.grafo(d)
            Wm[pn:pn + len(R)] = W
            Rm[pn:pn + len(R)] = R
            Am[pa:pa + len(AT)] = A
            ATm[pa:pa + len(AT)] = AT
            tabela.append(f"{d['id']}\t{d['rotulo']}\t{d['particao']}\t{len(R)}\t{len(AT)}\t{pn}\t{pa}")
            pn += len(R)
            pa += len(AT)
    assert pn == n_nos and pa == n_ar
    for M in (Wm, Rm, Am, ATm):
        M.flush()
    del Wm, Rm, Am, ATm
    for n in ("nos_w2v", "nos_rotulo", "arestas", "arestas_tipo"):
        os.replace(tmp(n), os.path.join(saida, n + ".npy"))
    open(os.path.join(saida, "grafos.tsv"), "w", encoding="utf-8").write("\n".join(tabela) + "\n")
    rel = {"arena": arena, "grafos": len(tabela) - 1, "nos": pn, "arestas": pa,
           "tokens_de_no_calculados": V.tok_total, "tokens_de_no_fora_do_vocabulario": V.oov,
           "taxa_fora_do_vocabulario": round(V.oov / max(V.tok_total, 1), 4),
           "word2vec": V.caminho_w2v, "sha256_word2vec": sha256(V.caminho_w2v)}
    json.dump(rel, open(os.path.join(saida, "relatorio.json"), "w"), indent=2)
    print(json.dumps(rel, indent=1))


if __name__ == "__main__":
    if sys.argv[1] == "--conferir-bigvul":
        sys.exit(0 if conferir_bigvul(int(sys.argv[2])) else 1)
    vetorizar(sys.argv[1])
