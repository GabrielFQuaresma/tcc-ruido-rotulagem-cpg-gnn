#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Le os JSON brutos que o anotar_modelo.ps1 gravou e produz uma planilha tabular
por (caso, repeticao), no mesmo vocabulario da planilha do humano.

Cada bruto e a saida de `claude -p --output-format json`: um envelope com
metadados de execucao, onde o campo `result` traz o texto que o modelo devolveu.
Esse texto deve ser o objeto JSON do contrato de saida. Tolera cercas de codigo
e texto em volta, mas registra quando teve de tolerar — se muitos casos cairem
em `parse_sujo`, o contrato nao esta sendo respeitado e vale reanotar em vez de
remendar.

Uso:
  python3 consolidar_brutos.py --condicao cve_visivel
"""

import argparse
import csv
import glob
import json
import os
import re
import sys

TIPOS = {"A", "B", "C", "D", "?"}
CONFIANCAS = {"alta", "media", "baixa"}

# baixo/alto -> baixa/alta ; acentos -> sem acento
MAPA_CONF = {
    "alta": "alta", "alto": "alta",
    "media": "media", "médio": "media", "medio": "media", "média": "media",
    "baixa": "baixa", "baixo": "baixa",
}


def normaliza_conf(s):
    v = str(s or "").strip().lower()
    return MAPA_CONF.get(v, "")


def normaliza_tipo(s):
    v = str(s or "").strip().upper().replace("\t", "").replace('"', "")
    return v if v in TIPOS else ""


def extrai_json(texto):
    """Devolve (dict, sujo). sujo=True quando foi preciso mais do que um
    json.loads direto."""
    t = (texto or "").strip()
    try:
        return json.loads(t), False
    except (json.JSONDecodeError, ValueError):
        pass
    # cerca de codigo
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.S)
    if m:
        try:
            return json.loads(m.group(1)), True
        except (json.JSONDecodeError, ValueError):
            pass
    # primeiro objeto balanceado
    ini = t.find("{")
    if ini >= 0:
        prof = 0
        for i in range(ini, len(t)):
            if t[i] == "{":
                prof += 1
            elif t[i] == "}":
                prof -= 1
                if prof == 0:
                    try:
                        return json.loads(t[ini:i + 1]), True
                    except (json.JSONDecodeError, ValueError):
                        break
    # objeto sem a(s) chave(s) de fechamento. Acontece quando o modelo termina o
    # turno (stop_reason=end_turn, nao truncado por max_tokens) tendo emitido os
    # campos completos mas engolido o '}' final. So fecha o que ficou pendente —
    # nao inventa valor nem completa string aberta, entao um texto de fato
    # truncado no meio continua falhando aqui em vez de virar dado silencioso.
    if ini >= 0:
        faltam = t.count("{") - t.count("}")
        if faltam > 0:
            try:
                return json.loads(t[ini:] + ("}" * faltam)), True
            except (json.JSONDecodeError, ValueError):
                pass
    return None, True


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--condicao", choices=["cve_visivel", "cve_oculta"],
                    default="cve_visivel")
    ap.add_argument("--raiz", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()

    brutos = os.path.join(args.raiz, "brutos", args.condicao)
    if not os.path.isdir(brutos):
        sys.exit(f"ERRO: {brutos} nao existe. Rode anotar_modelo.ps1 antes.")

    arquivos = sorted(glob.glob(os.path.join(brutos, "caso_*_run*.json")))
    if not arquivos:
        sys.exit(f"ERRO: nenhum bruto em {brutos}.")

    linhas, problemas = [], []
    for caminho in arquivos:
        nome = os.path.basename(caminho)
        m = re.match(r"caso_(\d+)_run(\d+)\.json$", nome)
        if not m:
            problemas.append(f"{nome}: nome fora do padrao")
            continue
        rid, run = int(m.group(1)), int(m.group(2))

        # utf-8-sig: o PowerShell 5.1 grava UTF-8 COM BOM, e o BOM quebra json.load
        with open(caminho, encoding="utf-8-sig") as f:
            try:
                env = json.load(f)
            except (json.JSONDecodeError, ValueError) as e:
                problemas.append(f"{nome}: envelope ilegivel ({e})")
                continue

        if env.get("is_error"):
            problemas.append(f"{nome}: is_error=true, subtype={env.get('subtype')}")
            continue

        veredito, sujo = extrai_json(env.get("result", ""))
        if veredito is None:
            problemas.append(f"{nome}: nao achei JSON em result")
            continue

        tipo = normaliza_tipo(veredito.get("tipo_ruido"))
        conf = normaliza_conf(veredito.get("confianca"))
        if not tipo:
            problemas.append(f"{nome}: tipo_ruido invalido "
                             f"({veredito.get('tipo_ruido')!r})")
        if not conf:
            problemas.append(f"{nome}: confianca invalida "
                             f"({veredito.get('confianca')!r})")

        uso = env.get("usage", {}) or {}
        linhas.append({
            "id": rid,
            "run": run,
            "tipo_ruido": tipo,
            "confianca": conf,
            "cwe_correta": str(veredito.get("cwe_correta") or "").strip().upper(),
            "observacao": str(veredito.get("observacao") or "").strip().replace("\n", " "),
            "parse_sujo": int(sujo),
            "modelo": ",".join(sorted((env.get("modelUsage") or {}).keys())),
            "tokens_in": uso.get("input_tokens", ""),
            "tokens_cache_read": uso.get("cache_read_input_tokens", ""),
            "tokens_out": uso.get("output_tokens", ""),
            "custo_usd": env.get("total_cost_usd", ""),
            "duracao_ms": env.get("duration_ms", ""),
            "session_id": env.get("session_id", ""),
        })

    if not linhas:
        print(f"ERRO: nenhuma anotacao valida em {len(arquivos)} bruto(s).")
        for p in problemas[:40]:
            print("  -", p)
        sys.exit(1)

    linhas.sort(key=lambda d: (d["run"], d["id"]))
    saida_dir = os.path.join(args.raiz, "saida")
    os.makedirs(saida_dir, exist_ok=True)
    destino = os.path.join(saida_dir, f"anotacao_modelo_{args.condicao}.csv")
    with open(destino, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0].keys()))
        w.writeheader()
        w.writerows(linhas)

    runs = sorted({d["run"] for d in linhas})
    print(f"Brutos lidos    : {len(arquivos)}")
    print(f"Linhas validas  : {len(linhas)}  (repeticoes: {runs})")
    print(f"Parse sujo      : {sum(d['parse_sujo'] for d in linhas)}")
    custos = [d["custo_usd"] for d in linhas if isinstance(d["custo_usd"], (int, float))]
    if custos:
        print(f"Custo nocional  : US$ {sum(custos):.2f} "
              f"(referencia de API; na assinatura sai do uso do plano)")
    print(f"Planilha        : {destino}")
    if problemas:
        print(f"\nPROBLEMAS ({len(problemas)}):")
        for p in problemas[:40]:
            print("  -", p)
        if len(problemas) > 40:
            print(f"  ... e mais {len(problemas)-40}")
        print("\nApague os brutos correspondentes e rode anotar_modelo.ps1 de novo.")


if __name__ == "__main__":
    main()
