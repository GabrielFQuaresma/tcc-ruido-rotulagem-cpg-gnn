#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalizacao de corpo de funcao para comparar BigVul x arquivo-fonte.

POR QUE ISTO EXISTE, situando
------------------------------
Na montagem do dataset de grafos e preciso decidir se o metodo achado no CPG e a MESMA funcao
que o BigVul rotulou. O criterio e hash do corpo (`sha1_corpo`), e ele so funciona se os dois
lados forem escritos do mesmo jeito.

Medido em 21/09/2026 (`_diag_hash.py`), os dois lados divergem por duas razoes, e NENHUMA e
"funcao diferente":

  1. O `m.code` do Joern vem TRUNCADO em 1000 caracteres, com " ..." no fim. Resolvido nao
     usando o `m.code`: recorta-se o corpo do arquivo-fonte pelas linhas do metodo.
  2. O `func_before` do BigVul vem SEM COMENTARIO DE LINHA (`//`). O arquivo baixado tem.
     Comparar um com o outro reprova toda funcao comentada — e foi o que produziu 32,3% de
     "nome casou, corpo nao" mesmo depois de resolvido o truncamento.

Remover comentario dos DOIS lados e normalizacao simetrica, nao afrouxamento: comentario nao
e codigo e nao faz parte da identidade da funcao. O que se compara continua sendo texto exato.

POR QUE UM MODULO E NAO CODIGO COPIADO: o `extrair_nomes_negativos.py` ja registra que o
extrator de nome e importado e nao copiado, pelo mesmo motivo — se os dois lados normalizassem
diferente, uma diferenca de resultado viria da normalizacao em vez do dado.
"""

import hashlib
import re

RE_ESPACO = re.compile(r"\s+")


def sem_comentarios(codigo):
    """Remove comentarios C/C++ preservando o que esta dentro de string e de char.

    Nao e um parser: e uma maquina de estados sobre os quatro contextos que importam
    (codigo, string, char, comentario). O caso que uma troca ingenua por regex erra e
    `"http://exemplo"` — a barra dupla dentro de string nao abre comentario.
    """
    s = str(codigo or "")
    saida = []
    i, n = 0, len(s)
    estado = "codigo"
    while i < n:
        c = s[i]
        prox = s[i + 1] if i + 1 < n else ""

        if estado == "codigo":
            if c == "/" and prox == "/":
                estado = "linha"
                i += 2
                continue
            if c == "/" and prox == "*":
                estado = "bloco"
                i += 2
                continue
            if c == '"':
                estado = "string"
            elif c == "'":
                estado = "char"
            saida.append(c)
            i += 1
        elif estado == "linha":
            if c == "\n":
                estado = "codigo"
                saida.append(c)      # a quebra fica: separa tokens
            i += 1
        elif estado == "bloco":
            if c == "*" and prox == "/":
                estado = "codigo"
                saida.append(" ")    # o comentario vira separador, nao some colado
                i += 2
                continue
            i += 1
        elif estado in ("string", "char"):
            saida.append(c)
            if c == "\\" and prox:
                saida.append(prox)
                i += 2
                continue
            if (estado == "string" and c == '"') or (estado == "char" and c == "'"):
                # o caractere de abertura ja foi consumido no estado 'codigo'
                estado = "codigo"
            i += 1
    return "".join(saida)


def normalizar(codigo):
    """Colapsa espacos e apara. E a MESMA normalizacao do extrair_nomes_negativos.py."""
    return RE_ESPACO.sub(" ", str(codigo or "")).strip()


def hash_corpo(codigo, tirar_comentarios=True):
    """sha1 do corpo normalizado. Com tirar_comentarios=False reproduz o sha1_corpo original."""
    texto = sem_comentarios(codigo) if tirar_comentarios else codigo
    texto = normalizar(texto)
    return hashlib.sha1(texto.encode("utf-8", "replace")).hexdigest() if texto else ""


def hashes_do_texto(codigo):
    """Os DOIS hashes que identificam uma funcao: so espaco normalizado, e sem comentario.

    E o conjunto que se compara dos dois lados — o func_before do BigVul e o trecho recortado do
    arquivo-fonte. Basta um em comum. Os negativos guardam os mesmos dois (sha1_corpo e
    sha1_corpo_sc); os positivos, desde 05/10/2026, tambem (split/positivos_hash.tsv).
    Antes desta data a funcao existia copiada em _recuperabilidade_hash.py e embutida no
    montar_dataset.hashes_do_metodo; agora as duas importam daqui (TRAVERSAL_V3.md, Fase 1).
    """
    out = set()
    h = hash_corpo(codigo, tirar_comentarios=False)
    if h:
        out.add(h)
    h = hash_corpo(codigo)
    if h:
        out.add(h)
    return out


def recortar_linhas(texto, ini, fim):
    """Linhas ini..fim (contadas a partir de 1, inclusive) de um texto, cortando SO em '\\n'.

    POR QUE NAO splitlines(): ele tambem quebra em form feed (\\f), \\v, \\x1c-\\x1e, \\x85 e
    \\u2028/\\u2029. O Joern conta linha so por '\\n'. Num arquivo com form feed (codigo GNU,
    quase todo o ImageMagick), o splitlines() desloca a numeracao e o recorte sai do lugar
    errado — o hash nao casa sem aviso. Medido em 05/10/2026: 219 de 2911 arquivos-fonte
    (HANDOFF_2026-10-04.md, secao 8.3, P9).
    """
    if ini < 1 or fim < ini:
        return ""
    return "\n".join(str(texto or "").split("\n")[ini - 1:fim])
