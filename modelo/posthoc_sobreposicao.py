#!/usr/bin/env python3
"""POS HOC (13/10/2026, depois de abrir o teste): o M_cur acusa as MESMAS funcoes que a regra?

    python3 posthoc_sobreposicao.py

ONDE ESTAMOS. O teste do BigVul foi aberto em 13/10 (IMPLEMENTACAO.md §9). Na comparacao
pre-registrada, o F1 do M_cur (0,262) ficou um pouco abaixo do da traversal pura (0,270). F1
parecido nao diz se a rede IMITOU a regra. Esta analise, pedida pelo autor e NAO pre-registrada,
olha as funcoes: das que o modelo acusa, quantas a regra tambem confirma?

O QUE ELA NAO E: nao e resultado pre-registrado e nao muda nenhum veredito. Vai para o texto
declarada como pos hoc.

POR QUE OS CONTROLES ENTRAM: a regra e o modelo tendem, os dois, a funcoes grandes. Entao alguma
sobreposicao aparece sem imitacao nenhuma. Os controles nunca viram a regra (seus positivos sao
sorteados); a sobreposicao deles e a regua do que coincide "por tamanho". A conta por faixa de
tamanho separa as duas coisas.

SAIDA: posthoc_sobreposicao.md (ao lado deste script).
"""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analisar_resultados as A  # noqa: E402  mesmas funcoes de leitura e de veredito
import reveal_comum as C  # noqa: E402

BRACOS = ["M_raw", "M_cur"] + list(C.CONTROLES)


def main():
    regra = A.V.carregar_regra(A.REGRA)
    ids, y, nos = A.carregar_indice("teste")
    fx = A.faixa_de(nos)
    T = np.array([(A.veredito_positivo(i, regra) if y[j] == 1 else A.veredito_negativo(i, regra))
                  == A.V.CONFIRMADO for j, i in enumerate(ids)])
    N = len(ids)
    res = {}
    for b in BRACOS:
        linhas = []
        for s in C.F2_SEMENTES:
            _, pred = A.carregar_predicao(b, s, "teste", ids)
            Ac = pred == 1
            nA, nAT = int(Ac.sum()), int((Ac & T).sum())
            d = {"acusa": nA,
                 "frac_acusa_na_regra": nAT / nA if nA else float("nan"),
                 "frac_regra_acusada": nAT / int(T.sum()),
                 "acertos_dentro_da_regra": int((Ac & T & (y == 1)).sum()),
                 "acertos_fora_da_regra": int((Ac & ~T & (y == 1)).sum()),
                 "faixa": []}
            for k in range(4):
                m = fx == k
                na = int((Ac & m).sum())
                d["faixa"].append(int((Ac & T & m).sum()) / na if na else float("nan"))
            linhas.append(d)
        res[b] = linhas

    def med(b, chave, k=None):
        v = [d[chave] if k is None else d["faixa"][k] for d in res[b]]
        v = [x for x in v if not np.isnan(x)]
        return float(np.median(v)) if v else float("nan")

    L = ["# POS HOC — o M_cur acusa as mesmas funcoes que a regra?", "",
         "> Analise pedida pelo autor em 13/10/2026, **depois** de abrir o teste. Nao pre-registrada;"
         " nao muda nenhum veredito. Medianas das 30 repeticoes; teste do BigVul, %d funcoes." % N, "",
         "A regra (traversal v3, confirmado = acusa) acusa **%d** funcoes do teste (%.1f%%), das quais "
         "%d sao vulneraveis pelo rotulo do BigVul. Se um modelo acusasse ao acaso, %.1f%% das acusacoes "
         "dele cairiam nas da regra." % (T.sum(), 100 * T.mean(), int((T & (y == 1)).sum()), 100 * T.mean()), "",
         "## Sobreposicao geral", "",
         "| braco | funcoes acusadas | das acusacoes, % que a regra tambem confirma | das confirmacoes da regra, % que o braco acusa | acertos dentro da regra | acertos FORA da regra |",
         "| --- | --- | --- | --- | --- | --- |"]
    for b in BRACOS:
        L.append("| %s | %d | %.1f%% | %.1f%% | %d | %d |" % (
            b, med(b, "acusa"), 100 * med(b, "frac_acusa_na_regra"), 100 * med(b, "frac_regra_acusada"),
            med(b, "acertos_dentro_da_regra"), med(b, "acertos_fora_da_regra")))
    L += ["", "## Das acusacoes de cada braco, % que a regra tambem confirma, por faixa de tamanho", "",
          "Dentro de uma faixa o tamanho e parecido; se o M_cur coincidir mais com a regra que os "
          "controles mesmo assim, a coincidencia nao e so tamanho.", "",
          "| braco | " + " | ".join(f[0] for f in A.FAIXAS) + " |", "| --- |" + " --- |" * 4]
    for b in BRACOS:
        L.append("| %s | %s |" % (b, " | ".join("—" if np.isnan(med(b, None, k)) else "%.1f%%" % (100 * med(b, None, k))
                                                for k in range(4))))
    L += ["", "| regra: % das funcoes da faixa que ela confirma | " +
          " | ".join("%.1f%%" % (100 * T[fx == k].mean()) for k in range(4)) + " |"]
    saida = os.path.join(os.path.dirname(os.path.abspath(__file__)), "posthoc_sobreposicao.md")
    open(saida, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
