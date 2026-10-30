#!/usr/bin/env python3
"""ReVeal, passo 1 — Word2Vec e o vetor inicial de cada no do dataset v3.

    python3 vetorizar.py          # faz o que falta; idempotente (pula o que ja existe)

ONDE ESTAMOS. Os grafos existem (dataset v3, 25.829 funcoes, um .jsonl por grupo de arquivo em
~/curadoria/dataset_v3/grupos). O ReVeal precisa de um vetor por no antes de a GGNN comecar.
Este script produz esses vetores, uma vez, iguais para todos os bracos.

O QUE CADA NO RECEBE (D10, PLANO_TREINO.md §3.3 b): one-hot do rotulo do no (18 rotulos do Joern)
+ media dos vetores Word2Vec dos tokens do `code` do no. O one-hot nao e gravado — e montado na
hora a partir do indice do rotulo; o que vai para o disco e o indice e os 100 numeros do Word2Vec.

WORD2VEC (PLANO_TREINO.md §3.1): treinado UMA vez, so no codigo das funcoes da particao de treino
(16.170 funcoes; o codigo oficial treina tambem no teste, o que vaza). Janela 10 e 100 dimensoes
do artigo; min_count 1 e 5 + 100 epocas do codigo oficial ([R] word2vec_train.py).
Uma frase por funcao: o texto da funcao recortado do arquivo-fonte que o Joern comeu (linhas
linha_inicio..linha_fim), CONFERIDO contra o inicio do `code` do no METHOD. Nao se usa o `code` do
METHOD direto porque o Joern o trunca em 1000 caracteres. Se nenhum arquivo-fonte confere, cai no
`code` do METHOD e conta (o numero sai no relatorio).

TOKENIZACAO — diferenca declarada. O oficial treina o Word2Vec com `code.split()` (espacos) e
tokeniza o no com `nltk.word_tokenize`: os dois nao casam ("buf[i]" e um token num e quatro no
outro), e muito token do no vira vetor zero. Aqui os dois usam `nltk.word_tokenize`. Token fora do
vocabulario conta como vetor zero na media, como no oficial ([R] create_ggnn_data.py:309-320).

ARESTAS. Todas as 18 rotulagens de aresta do grafo exportado, cada uma um tipo (o analogo do
conjunto "full" do oficial, que usava todos os tipos do Joern dele), na direcao exportada.

SAIDA em ~/curadoria/modelo/vetores/:
  grafos.tsv          id, rotulo, particao, n_nos, n_arestas, ini_no, ini_aresta (ordem dos arrays)
  nos_w2v.npy         float32 [n_nos_total, 100]
  nos_rotulo.npy      int8    [n_nos_total]      indice em rotulos_no.json
  arestas.npy         int32   [n_arestas_total, 2] (origem, destino) locais da funcao
  arestas_tipo.npy    int8    [n_arestas_total]   indice em rotulos_aresta.json
  word2vec.model      o modelo gensim
  relatorio.json      contagens, hashes, tempos
"""

import csv
import glob
import hashlib
import json
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reveal_comum as C  # noqa: E402

T0 = time.time()


def log(*a):
    print("[%7.1fs]" % (time.time() - T0), *a, flush=True)


def sha256(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def norm(s):
    return "".join(s.split())


def mapa_de_fontes():
    """(commit, nome-base do arquivo) -> [pastas em ~/curadoria/completa com aquele fonte]."""
    commit_de = {}
    with open(C.RELATORIO, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            commit_de[int(r["id"])] = r["commit_id"].strip()
    mapa = {}
    for pasta in sorted(os.listdir(C.COMPLETA)):
        try:
            item = int(pasta.split("__")[0])
        except ValueError:
            continue
        fontes = glob.glob(os.path.join(C.COMPLETA, pasta, "arquivo__*"))
        if item not in commit_de or len(fontes) != 1:
            continue
        nome = os.path.basename(fontes[0])[len("arquivo__"):]
        mapa.setdefault((commit_de[item], nome), []).append(fontes[0])
    return mapa


_cache_fonte = {}


def linhas_do_fonte(caminho):
    if caminho not in _cache_fonte:
        if len(_cache_fonte) > 64:
            _cache_fonte.clear()
        with open(caminho, encoding="utf-8", errors="replace") as f:
            _cache_fonte[caminho] = f.read().splitlines()
    return _cache_fonte[caminho]


def texto_da_funcao(d, mapa):
    met = next(n for n in d["nos"] if n["label"] == "METHOD")
    code = met["code"]
    if len(code) >= 1000 and code.endswith("..."):
        code = code[:-3]
    chave = norm(code)[:200]
    li, lf = d["linha_inicio"], d["linha_fim"]
    if chave and li > 0 and lf >= li:
        for caminho in mapa.get((d["commit"], d["arquivo"]), []):
            trecho = "\n".join(linhas_do_fonte(caminho)[li - 1:lf])
            if chave in norm(trecho):
                return trecho, "fonte"
    return met["code"], "metodo"


def arquivos_de_grupo():
    return sorted(glob.glob(os.path.join(C.GRUPOS, "*.jsonl")))


def ler_indice():
    linhas = open(C.INDICE, encoding="utf-8").read().splitlines()
    cab = linhas[0].split("\t")
    return {d["id"]: d for d in (dict(zip(cab, l.split("\t"))) for l in linhas[1:])}


def main():
    from nltk import word_tokenize
    os.makedirs(C.VETORES, exist_ok=True)
    pronto = os.path.join(C.VETORES, "relatorio.json")
    if os.path.exists(pronto):
        log("ja existe:", pronto, "— nada a fazer")
        return
    indice = ler_indice()

    # ---- passo A: conferir os grafos contra o indice, contar, e montar o corpus do treino
    mapa = mapa_de_fontes()
    log("pastas com fonte:", sum(len(v) for v in mapa.values()), "chaves:", len(mapa))
    rot_no, rot_ar = set(), set()
    n_nos = n_ar = n_graf = 0
    frases, origem = [], {"fonte": 0, "metodo": 0}
    vistos = set()
    for arq in arquivos_de_grupo():
        for linha in open(arq, encoding="utf-8"):
            d = json.loads(linha)
            i = indice[d["id"]]
            assert d["id"] not in vistos, d["id"]
            vistos.add(d["id"])
            assert int(i["n_nos"]) == len(d["nos"]) == d["n_nos"], d["id"]
            assert int(i["n_arestas"]) == len(d["arestas"]) == d["n_arestas"], d["id"]
            assert i["particao"] == d["particao"] and int(i["rotulo"]) == d["rotulo"], d["id"]
            n_graf += 1
            n_nos += len(d["nos"])
            n_ar += len(d["arestas"])
            rot_no.update(n["label"] for n in d["nos"])
            rot_ar.update(a[2] for a in d["arestas"])
            if d["particao"] == "treino":
                texto, de_onde = texto_da_funcao(d, mapa)
                origem[de_onde] += 1
                frases.append(word_tokenize(texto))
    assert n_graf == len(indice), (n_graf, len(indice))
    rot_no, rot_ar = sorted(rot_no), sorted(rot_ar)
    log("grafos", n_graf, "nos", n_nos, "arestas", n_ar, "| rotulos de no", len(rot_no),
        "de aresta", len(rot_ar))
    log("corpus do treino:", len(frases), "funcoes;", sum(len(f) for f in frases), "tokens;",
        "texto do fonte", origem["fonte"], "| caiu no code do METHOD", origem["metodo"])
    json.dump(rot_no, open(os.path.join(C.VETORES, "rotulos_no.json"), "w"))
    json.dump(rot_ar, open(os.path.join(C.VETORES, "rotulos_aresta.json"), "w"))

    # ---- passo B: Word2Vec (uma vez; reaproveita se ja existe)
    from gensim.models import Word2Vec
    caminho_w2v = os.path.join(C.VETORES, "word2vec.model")
    if os.path.exists(caminho_w2v):
        w2v = Word2Vec.load(caminho_w2v)
        log("Word2Vec reaproveitado:", caminho_w2v)
    else:
        log("Word2Vec: construtor (5 epocas)")
        w2v = Word2Vec(frases, vector_size=C.W2V_DIM, window=C.W2V_JANELA,
                       min_count=C.W2V_MIN_COUNT, workers=C.W2V_WORKERS)
        for e in range(C.W2V_EPOCAS_EXTRA):
            w2v.train(frases, total_examples=len(frases), epochs=1)
            if e % 10 == 9:
                log("Word2Vec: +%d epocas" % (e + 1))
        # arquivo unico (sep_limit alto): o gensim grava matrizes grandes em .npy separados com o
        # nome do arquivo como prefixo, e um rename depois quebraria o load.
        w2v.save(caminho_w2v, sep_limit=2**40)
    del frases
    kti, vec = w2v.wv.key_to_index, w2v.wv.vectors
    log("vocabulario:", len(kti))

    # ---- passo C: vetor de cada no, arestas, indice dos grafos
    idx_no = {r: k for k, r in enumerate(rot_no)}
    idx_ar = {r: k for k, r in enumerate(rot_ar)}
    tmp = lambda n: os.path.join(C.VETORES, n + ".tmp.npy")  # noqa: E731
    W = np.lib.format.open_memmap(tmp("nos_w2v"), mode="w+", dtype=np.float32, shape=(n_nos, C.W2V_DIM))
    R = np.lib.format.open_memmap(tmp("nos_rotulo"), mode="w+", dtype=np.int8, shape=(n_nos,))
    A = np.lib.format.open_memmap(tmp("arestas"), mode="w+", dtype=np.int32, shape=(n_ar, 2))
    AT = np.lib.format.open_memmap(tmp("arestas_tipo"), mode="w+", dtype=np.int8, shape=(n_ar,))
    cache, zero = {}, np.zeros(C.W2V_DIM, dtype=np.float32)
    oov = tok_total = 0
    pn = pa = 0
    tabela = ["id\trotulo\tparticao\tn_nos\tn_arestas\tini_no\tini_aresta"]
    for k, arq in enumerate(arquivos_de_grupo()):
        for linha in open(arq, encoding="utf-8"):
            d = json.loads(linha)
            nn_, na_ = len(d["nos"]), len(d["arestas"])
            for j, n in enumerate(d["nos"]):
                code = n["code"]
                v = cache.get(code)
                if v is None:
                    toks = word_tokenize(code)
                    ids = [kti[t] for t in toks if t in kti]
                    oov += len(toks) - len(ids)
                    tok_total += len(toks)
                    v = vec[ids].sum(axis=0) / len(toks) if ids else zero
                    if len(code) <= 80:
                        if len(cache) > 3_000_000:
                            cache.clear()
                        cache[code] = v
                W[pn + j] = v
                R[pn + j] = idx_no[n["label"]]
            if na_:
                arr = np.array([(a[0], a[1]) for a in d["arestas"]], dtype=np.int32)
                assert arr.min() >= 0 and arr.max() < nn_, d["id"]
                A[pa:pa + na_] = arr
                AT[pa:pa + na_] = [idx_ar[a[2]] for a in d["arestas"]]
            tabela.append("%s\t%d\t%s\t%d\t%d\t%d\t%d" % (
                d["id"], d["rotulo"], d["particao"], nn_, na_, pn, pa))
            pn += nn_
            pa += na_
        if k % 100 == 99:
            log("grupos %d/%d, nos %d/%d" % (k + 1, len(arquivos_de_grupo()), pn, n_nos))
    assert pn == n_nos and pa == n_ar
    for M in (W, R, A, AT):
        M.flush()
    del W, R, A, AT
    for n in ("nos_w2v", "nos_rotulo", "arestas", "arestas_tipo"):
        os.replace(tmp(n), os.path.join(C.VETORES, n + ".npy"))
    open(os.path.join(C.VETORES, "grafos.tsv"), "w", encoding="utf-8").write("\n".join(tabela) + "\n")
    rel = {
        "grafos": n_graf, "nos": n_nos, "arestas": n_ar,
        "rotulos_no": rot_no, "rotulos_aresta": rot_ar,
        "corpus_funcoes_treino": origem["fonte"] + origem["metodo"],
        "corpus_texto_do_fonte": origem["fonte"], "corpus_code_do_metodo": origem["metodo"],
        "vocabulario_w2v": len(kti),
        "tokens_de_no_unicos_calculados": tok_total, "tokens_de_no_fora_do_vocabulario": oov,
        "sha256_word2vec": sha256(caminho_w2v),
        "segundos": round(time.time() - T0, 1),
    }
    json.dump(rel, open(pronto + ".tmp", "w"), indent=2, ensure_ascii=False)
    os.replace(pronto + ".tmp", pronto)
    log("PRONTO", json.dumps(rel, ensure_ascii=False))


if __name__ == "__main__":
    main()
