#!/usr/bin/env python3
"""Runner da curadoria: aplica curadoria_v2.sc a itens de saida_final/itens/.

O script NAO decide nada sobre rotulo. Ele produz um JSON de evidencia por item.
O veredito vem depois, do regra_veredito.toml, que ainda nao existe de proposito:
a regra so pode ser fixada depois de olhar a distribuicao da evidencia (Etapa 4a).

Uso (dentro do WSL):

    python3 rodar_curadoria.py --limite 50 --seed 7
    python3 rodar_curadoria.py --testes          # regressao + generalidade, sem rodar o lote

    # traversal v3 (05/10/2026, TRAVERSAL_V3.md): mesma fila, mais a tabela de identificacao
    python3 rodar_curadoria.py --versao v3 --identificacao identificacao_v3.tsv \\
        --limite 3000 --seed 7 --saida saida_completa_v3 \\
        --trabalho ~/curadoria/completa_v3 --retomar --pular-falhas

Cada item vira <saida>/<id>__<projeto>.json. Falha de um item nao derruba a fila:
o motivo fica em <saida>/_falhas.tsv e a fila continua.
"""

import argparse
import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(AQUI))          # para importar buscar_arquivo
from buscar_arquivo import nome_da_funcao          # noqa: E402

PADRAO_ITENS = os.path.join(os.path.dirname(AQUI), "saida_final", "itens")
C2CPG = "/opt/joern/joern-cli/c2cpg.sh"

# Numeros do BASELINE_libgd.md. Sao a referencia de regressao — NAO os do artigo.
BASELINE = {
    "caso": "1217__libgd",
    "alvo": "read_image_tga",
    "linha_inicio": 206,
    "linha_fim": 336,
    "camada1.por_nome.memcpy": 2,
    "camada1.acessos_indexados": 7,
    "camada2.fluxos_memoria_de_parametro": 12,
    "camada2.fluxos_indice_de_parametro": 14,
    "guardas.condicoes": 18,
}

# Invariante da Etapa 1: nada em traversal/ pode carregar nome de projeto ou id de CVE.
# A lista de projetos vem do proprio BigVul; se um deles aparecer no codigo da traversal,
# a regra foi escrita olhando a amostra.
PROIBIDOS = [
    r"\bCVE-\d{4}-\d{4,7}\b",
    r"\bgd[A-Z]\w+",           # gdGetBuf, gdMalloc — o caso que motivou a invariante
    r"\blibgd\b", r"\bffmpeg\b", r"\blibvpx\b", r"\bqemu\b", r"\blinux\b",
    r"\bphp\b", r"\bghostscript\b", r"\bwireshark\b", r"\bimagemagick\b",
    r"\bopenssl\b", r"\bcurl\b", r"\bu-boot\b", r"\bgnupg\b", r"\bhaproxy\b",
    r"\bread_image_tga\b",
]
# A invariante vale para as REGRAS, e so para elas. Por isso o teste usa lista BRANCA: varre o
# .sc e as tabelas, e mais nada. Lista negra de diretorios ja falhou duas vezes aqui — a prosa
# precisa poder nomear o contraexemplo (dados/README.md) e a saida obviamente carrega nome de
# projeto (e evidencia por item). Regra nova entra nesta lista de proposito, na mao.
REGRAS_POR_VERSAO = {
    "v2": ["curadoria_v2.sc", "dados/funcoes_memoria.tsv", "dados/fontes_nao_confiaveis.tsv",
           "regra_veredito.toml"],
    "v3": ["curadoria_v3.sc", "dados/funcoes_memoria.tsv", "dados/fontes_nao_confiaveis.tsv",
           "regra_veredito.toml"],
}
# REGRAS continua sendo a lista da v2: e a que o congelamento de 10/08 (Etapa 5) cobre, e a que
# etapa_5.py e montar_split.py conferem. A v3 entrou em 05/10/2026 (TRAVERSAL_V3.md) como
# versao SEPARADA, com congelamento proprio — a foto da v2 nunca e regravada.
REGRAS = REGRAS_POR_VERSAO["v2"]
# O regra_veredito.toml entrou na lista em 09/08 (Etapa 4a): ele decide o que confirma rotulo,
# entao e regra tanto quanto o .sc. O veredito.py NAO entra — ele so aplica a regra, e precisa
# poder nomear o caso de regressao para tira-lo da estatistica do dev. Escriturario, nao regra.
# A tabela identificacao_v3.tsv tambem NAO entra: traz id de item (com nome de projeto) e e
# entrada por item, como o nome da funcao. O SHA-256 dela fica no adendo do TRAVERSAL_V3.md.


def cavar(d, caminho):
    """Le 'a.b.c' de um dicionario aninhado, devolvendo None se faltar."""
    atual = d
    for parte in caminho.split("."):
        if not isinstance(atual, dict) or parte not in atual:
            return None
        atual = atual[parte]
    return atual


# --------------------------------------------------------------------------
# Testes que rodam antes do lote
# --------------------------------------------------------------------------

def teste_generalidade(versao="v2"):
    """Falha se algum arquivo de traversal/ contiver identificador de projeto ou CVE."""
    achados = []
    for rel in REGRAS_POR_VERSAO[versao]:
        caminho = os.path.join(AQUI, rel)
        if not os.path.exists(caminho):
            achados.append((rel, 0, "ARQUIVO DE REGRA AUSENTE"))
            continue
        with open(caminho, encoding="utf-8-sig") as fh:
            texto = fh.read()
        for padrao in PROIBIDOS:
            for m in re.finditer(padrao, texto, re.IGNORECASE):
                linha = texto[:m.start()].count("\n") + 1
                achados.append((rel, linha, m.group(0)))
    return achados


def teste_regressao(evidencia):
    """Compara a evidencia do caso do artigo com o BASELINE_libgd.md."""
    divergencias = []
    for chave, esperado in BASELINE.items():
        if chave in ("caso", "alvo"):
            continue
        obtido = cavar(evidencia, chave)
        if obtido != esperado:
            divergencias.append((chave, esperado, obtido))
    return divergencias


# --------------------------------------------------------------------------
# Execucao de um item
# --------------------------------------------------------------------------

def alvo_do_item(pasta):
    """Nome da funcao marcada. O meta.json nao guarda, entao sai do func_before.c."""
    fb = os.path.join(pasta, "func_before.c")
    if not os.path.exists(fb):
        return ""
    with open(fb, encoding="utf-8", errors="replace") as fh:
        return nome_da_funcao(fh.read())


def arquivo_de_contexto(pasta, meta):
    nome = meta.get("arquivo_inteiro") or ""
    if nome and os.path.exists(os.path.join(pasta, nome)):
        return os.path.join(pasta, nome)
    for f in sorted(os.listdir(pasta)):
        if f.startswith("arquivo__"):
            return os.path.join(pasta, f)
    return ""


def rodar_item(pasta, trabalho, timeout, sc="curadoria_v2.sc", linha=""):
    """Devolve (evidencia, motivo_da_falha). Um dos dois e sempre None.

    `linha` (so v3): linha onde comeca o metodo escolhido pela tabela de identificacao."""
    nome_item = os.path.basename(pasta)
    meta_path = os.path.join(pasta, "meta.json")
    if not os.path.exists(meta_path):
        return None, "sem_meta"
    with open(meta_path, encoding="utf-8-sig") as fh:
        meta = json.load(fh)

    alvo = alvo_do_item(pasta)
    if not alvo:
        return None, "sem_nome_de_funcao"
    fonte = arquivo_de_contexto(pasta, meta)
    if not fonte:
        return None, "sem_arquivo_de_contexto"

    local = os.path.join(trabalho, nome_item)
    os.makedirs(local, exist_ok=True)
    copia = os.path.join(local, os.path.basename(fonte))
    shutil.copyfile(fonte, copia)
    cpg = os.path.join(local, "cpg.bin")

    try:
        r = subprocess.run([C2CPG, copia, "--output", cpg],
                           capture_output=True, text=True, timeout=timeout, cwd=local)
    except subprocess.TimeoutExpired:
        return None, "timeout_c2cpg"
    if not os.path.exists(cpg):
        return None, "c2cpg_falhou:" + (r.stderr or r.stdout or "")[-160:].replace("\n", " ")

    cmd = ["joern", "--script", os.path.join(AQUI, sc),
           "--param", "cpg_file=" + cpg,
           "--param", "alvo=" + alvo,
           "--param", "dados=" + os.path.join(AQUI, "dados")]
    if linha:
        cmd += ["--param", "linha=" + str(linha)]
    try:
        # cwd=local: o Joern cria workspace/ no cwd e ja sujou pasta de dataset uma vez.
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=local)
    except subprocess.TimeoutExpired:
        return None, "timeout_joern"

    for linha in (r.stdout or "").splitlines():
        if linha.startswith("EVIDENCIA_JSON "):
            evid = json.loads(linha[len("EVIDENCIA_JSON "):])
            evid["item"] = nome_item
            evid["cwe_bigvul"] = meta.get("cwe_bigvul", "")
            evid["projeto"] = meta.get("project", "")
            return evid, None
    # v3: as duas recusas do .sc viram motivo proprio, para a conferencia P6 do pre-registro.
    if "ERRO_V3_COLISAO_SEM_LINHA" in (r.stdout or ""):
        return None, "v3_trava_colisao_sem_linha"
    if "ERRO_V3_LINHA" in (r.stdout or ""):
        return None, "v3_linha_sem_metodo_unico"
    cauda = (r.stdout or "")[-160:] + (r.stderr or "")[-160:]
    return None, "sem_evidencia:" + cauda.replace("\n", " ")


# --------------------------------------------------------------------------
# Resumo — o numero que o card da 4.5 esta esperando
# --------------------------------------------------------------------------

def resumir(evidencias):
    """Distribuicao so-camada-1 / so-camada-2 / ambas / nenhuma.

    E este quadro que decide se a regra 'alguma consulta dispara' da 4.5 e utilizavel.
    Camada 1 aqui NAO inclui alocacao: malloc/alloca disparam em quase toda funcao em C e
    inflariam a presenca artificialmente. A escolha esta declarada em dados/README.md.
    """
    baldes = {"so_camada1": 0, "so_camada2": 0, "ambas": 0, "nenhuma": 0}
    for e in evidencias:
        cats = cavar(e, "camada1.por_categoria") or {}
        presenca = sum(v for k, v in cats.items() if k != "alocacao")
        presenca += cavar(e, "camada1.acessos_indexados") or 0
        c2 = cavar(e, "camada2") or {}
        fluxo = sum(max(0, c2.get(k, 0)) for k in (
            "fluxos_memoria_de_parametro", "fluxos_memoria_de_libc",
            "fluxos_indice_de_parametro", "fluxos_indice_de_libc"))
        if presenca and fluxo:
            baldes["ambas"] += 1
        elif presenca:
            baldes["so_camada1"] += 1
        elif fluxo:
            baldes["so_camada2"] += 1
        else:
            baldes["nenhuma"] += 1
    return baldes


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--itens", default=PADRAO_ITENS)
    p.add_argument("--saida", default=os.path.join(AQUI, "saida"))
    p.add_argument("--trabalho", default=os.path.expanduser("~/curadoria/lote"))
    p.add_argument("--limite", type=int, default=50)
    p.add_argument("--seed", type=int, default=7, help="semente do sorteio; nunca 42")
    p.add_argument("--lista", default="", help="TSV com uma coluna 'item'; roda exatamente "
                                               "esses itens em vez de sortear (dev_set.tsv)")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--retomar", action="store_true", help="pula itens que ja tem JSON")
    p.add_argument("--testes", action="store_true", help="so os testes, sem o lote")
    p.add_argument("--versao", default="v2", choices=sorted(REGRAS_POR_VERSAO),
                   help="qual traversal roda (curadoria_<versao>.sc). Padrao v2, para que as "
                        "rodadas antigas continuem reproduziveis com o mesmo comando")
    p.add_argument("--identificacao", default="",
                   help="v3: identificacao_v3.tsv — diz, por item, avaliar / avaliar_na_linha / "
                        "excluir (TRAVERSAL_V3.md, secao 3)")
    p.add_argument("--pular-falhas", action="store_true",
                   help="com --retomar: nao retenta item que ja esta no _falhas.tsv da saida "
                        "(exceto timeout). As falhas sao deterministicas; retentar custa ~30 min")
    p.add_argument("--sem-timeout", action="store_true",
                   help="com --pular-falhas: tambem nao retenta timeout ja registrado (usado nas "
                        "fatias; os timeouts sao retentados numa passada final, sem esta opcao)")
    p.add_argument("--parar-apos", type=int, default=0,
                   help="segundos: passado esse tempo, para de forma limpa ANTES de comecar um "
                        "item novo e grava o _falhas.tsv. Para rodar em fatias em primeiro plano "
                        "(05/10/2026: o segundo plano foi encerrado duas vezes por falta de "
                        "memoria no Windows). 0 = sem limite")
    args = p.parse_args()

    sc = "curadoria_{}.sc".format(args.versao)
    acao = {}
    if args.versao != "v2":
        if not args.identificacao:
            print("FALHA: a {} precisa de --identificacao. Sem a tabela, todo item com "
                  "homonimo bateria na trava do .sc.".format(args.versao))
            return 1
        with open(args.identificacao, encoding="utf-8") as fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                acao[r["item"]] = r
    print("traversal: {} ({})".format(args.versao, sc))

    achados = teste_generalidade(args.versao)
    if achados:
        print("FALHA no teste de generalidade — identificador de projeto/CVE em traversal/:")
        for arq, linha, trecho in achados:
            print("  {}:{}  {}".format(arq, linha, trecho))
        return 1
    print("teste de generalidade: ok")

    if args.testes:
        return 0

    os.makedirs(args.saida, exist_ok=True)
    os.makedirs(args.trabalho, exist_ok=True)

    todos = sorted(d for d in os.listdir(args.itens)
                   if os.path.isdir(os.path.join(args.itens, d)))
    if args.lista:
        # Conjunto fixo (o dev_set.tsv da Etapa 4a). Sortear de novo aqui daria um
        # conjunto diferente do que foi provado disjunto dos 50 — o dev set inteiro
        # so vale porque a disjuncao foi provada.
        with open(args.lista, encoding="utf-8-sig") as fh:
            cab = fh.readline().rstrip("\n").split("\t")
            if "item" not in cab:
                print("FALHA: {} nao tem coluna 'item'".format(args.lista))
                return 1
            k = cab.index("item")
            escolhidos = [l.rstrip("\n").split("\t")[k]
                          for l in fh if l.strip()]
        ausentes = [n for n in escolhidos if n not in todos]
        if ausentes:
            print("FALHA: itens da lista sem pasta em {}: {}".format(args.itens, ausentes))
            return 1
    else:
        rnd = random.Random(args.seed)
        escolhidos = rnd.sample(todos, min(args.limite, len(todos)))
    if BASELINE["caso"] not in escolhidos:      # o caso de regressao entra sempre
        escolhidos.insert(0, BASELINE["caso"])

    if acao:
        sem_linha = [n for n in escolhidos if n not in acao]
        if sem_linha:
            print("FALHA: itens sem linha na tabela de identificacao: {}".format(sem_linha[:10]))
            return 1
        # Excluido NAO e falha: e a decisao pre-registrada de nao avaliar quem nao da para
        # identificar. Vai para um arquivo proprio, com o motivo da tabela.
        excluidos = [(n, acao[n]["motivo"]) for n in escolhidos if acao[n]["acao"] == "excluir"]
        with open(os.path.join(args.saida, "_exclusoes.tsv"), "w", encoding="utf-8") as fh:
            fh.write("item\tmotivo\n")
            for nome, motivo in excluidos:
                fh.write("{}\t{}\n".format(nome, motivo))
        print("excluidos pela tabela (nao rodam): {}".format(len(excluidos)))

    anteriores, registro = {}, {}
    caminho_falhas = os.path.join(args.saida, "_falhas.tsv")
    if args.retomar and os.path.exists(caminho_falhas):
        with open(caminho_falhas, encoding="utf-8") as fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                registro[r["item"]] = r["motivo"]
                if args.pular_falhas and (args.sem_timeout
                                          or not r["motivo"].startswith("timeout")):
                    anteriores[r["item"]] = r["motivo"]
        print("falhas ja registradas que nao serao retentadas: {}".format(len(anteriores)))

    falhas, evidencias = [], []
    inicio = time.time()
    for i, nome in enumerate(escolhidos, 1):
        destino = os.path.join(args.saida, nome + ".json")
        if args.retomar and os.path.exists(destino):
            with open(destino, encoding="utf-8") as fh:
                evidencias.append(json.load(fh))
            print("[{}/{}] {} (retomado)".format(i, len(escolhidos), nome), flush=True)
            continue
        if acao and acao[nome]["acao"] == "excluir":
            print("[{}/{}] {} EXCLUIDO {}".format(i, len(escolhidos), nome,
                                                  acao[nome]["motivo"]), flush=True)
            continue
        if nome in anteriores:
            falhas.append((nome, anteriores[nome]))
            print("[{}/{}] {} (falha ja registrada)".format(i, len(escolhidos), nome), flush=True)
            continue
        if args.parar_apos and time.time() - inicio >= args.parar_apos:
            print("PARADA PROGRAMADA antes do item {}/{} ({} s)".format(
                i, len(escolhidos), int(time.time() - inicio)), flush=True)
            break
        linha = acao[nome]["linha"] if acao and acao[nome]["acao"] == "avaliar_na_linha" else ""
        evid, motivo = rodar_item(os.path.join(args.itens, nome), args.trabalho, args.timeout,
                                  sc=sc, linha=linha)
        if evid is None:
            falhas.append((nome, motivo))
            print("[{}/{}] {} FALHOU {}".format(i, len(escolhidos), nome, motivo), flush=True)
            continue
        with open(destino, "w", encoding="utf-8") as fh:
            json.dump(evid, fh, ensure_ascii=False, indent=2)
        evidencias.append(evid)
        print("[{}/{}] {} ok".format(i, len(escolhidos), nome), flush=True)

    # Com --retomar, o _falhas.tsv e um REGISTRO acumulado: o que ja estava la continua (mesmo os
    # itens que esta execucao nao alcancou, por --parar-apos), o que falhou agora entra ou
    # atualiza, e sai so quem ganhou JSON. Ate 06/10/2026 o arquivo era regravado so com as
    # falhas vistas na execucao — e uma fatia que parava no meio da fila apagava as de depois.
    final = dict(registro)
    for nome, motivo in falhas:
        final[nome] = motivo
    final = {n: m for n, m in final.items()
             if not os.path.exists(os.path.join(args.saida, n + ".json"))}
    if final:
        with open(caminho_falhas, "w", encoding="utf-8") as fh:
            fh.write("item\tmotivo\n")
            for nome in sorted(final):
                fh.write("{}\t{}\n".format(nome, final[nome]))

    print("\n--- regressao ({}) ---".format(BASELINE["caso"]))
    base = next((e for e in evidencias if e.get("item") == BASELINE["caso"]), None)
    if base is None:
        print("FALHA: o caso de regressao nao produziu evidencia")
    else:
        div = teste_regressao(base)
        if div:
            print("FALHA — divergiu do BASELINE_libgd.md:")
            for chave, esperado, obtido in div:
                print("  {}: esperado {}, obtido {}".format(chave, esperado, obtido))
        else:
            print("ok — reproduz o BASELINE_libgd.md")

    print("\n--- distribuicao das camadas (n={}) ---".format(len(evidencias)))
    baldes = resumir(evidencias)
    total = max(1, sum(baldes.values()))
    for k in ("so_camada1", "so_camada2", "ambas", "nenhuma"):
        print("  {:<12} {:>4}  ({:.1f}%)".format(k, baldes[k], 100.0 * baldes[k] / total))
    print("\nfalhas: {} de {} | {:.0f}s".format(
        len(falhas), len(escolhidos), time.time() - inicio))
    return 0


if __name__ == "__main__":
    sys.exit(main())
