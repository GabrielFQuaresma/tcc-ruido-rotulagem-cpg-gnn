#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Busca o arquivo afetado por um commit, na versao ANTERIOR a correcao, sem clonar
o repositorio.

Motivacao. O preparar_bigvul.py clonava o repositorio inteiro para rodar
"git show <sha>^:<arquivo>". Isso e caro (clonar o kernel para ler um arquivo) e
falha nos forges menores, cujo endpoint de clone via HTTP nao responde. Medido no
conjunto de positivos de erro de memoria do BigVul: "git ls-remote" falha em
git.pengutronix.de, cgit.freedesktop.org e git.musl-libc.org, mas o mesmo
conteudo sai por HTTP nesses tres hosts. HTTP funciona onde o protocolo git nao.

Duas coisas precisam ser resolvidas por item:

  1. QUAL arquivo. A coluna file_name do BigVul cobre 91,6% dos positivos, mas
     esta ausente em exatamente 8,4% deles, e essa ausencia nao e aleatoria:
     coincide com as familias gitweb e cgit. Nesses casos o caminho e extraido do
     proprio patch do commit, baixado por HTTP.

  2. QUAL versao. A anterior a correcao. Todos os quatro forges aceitam o sufixo
     "^" na referencia, entao nao e preciso descobrir o SHA do pai por API. Isso
     foi verificado no GitHub comparando o md5 de "<sha>^" com o do pai obtido
     pela API: sao identicos, e a linha da correcao aparece so na versao filha.

Cobertura das quatro familias sobre os positivos de erro de memoria do BigVul:

    github        2103  (71,1%)
    googlesource   606  (20,5%)
    gitweb         147  ( 5,0%)
    cgit           100  ( 3,4%)
                        -------
                        99,97%   (sobra 1 item em git.infradead.org)

Uso como biblioteca:

    from buscar_arquivo import buscar_arquivos_do_commit
    res = buscar_arquivos_do_commit(codelink, sha, file_name)
    # res.arquivos -> lista de (caminho, conteudo)
    # res.status   -> "ok" | "sem_paths" | "forge_desconhecido" | "erro_http" | ...

Autoteste (bate em rede real, um caso por familia):

    python3 buscar_arquivo.py --autoteste
"""

import argparse
import base64
import os
import re
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, urlparse

import requests

EXT_CODIGO = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")

# (conexao, leitura). O timeout de conexao e curto de proposito: varios hosts do
# BigVul simplesmente nao existem mais (git.savannah.gnu.org nao aceita conexao) e
# esperar 30s por cada um domina o tempo total da extracao.
TIMEOUT = (10, 40)
TENTATIVAS = 3
PAUSA_ENTRE_TENTATIVAS = 2.0
# Depois de tantas falhas de CONEXAO seguidas, o host e dado como fora do ar e as
# requisicoes seguintes falham na hora, sem esperar o timeout. Um host que ja
# respondeu alguma vez nunca e marcado -- ver a nota em Sessao._marcar.
FALHAS_PARA_DESISTIR = 6

# Requisicoes simultaneas permitidas por host. O googlesource responde 429 quando
# recebe muitas em paralelo: com 12 threads, 1 em cada 12 ja e recusada, e como o
# Android sozinho e 20,5% do conjunto, isso derruba centenas de itens. Segurar a
# concorrencia por host e mais eficaz que retentar depois de recusado.
LIMITE_POR_HOST = {
    "android.googlesource.com": 1,
    "cgit.freedesktop.org": 2,
    "git.pengutronix.de": 2,
}
LIMITE_PADRAO = 16
# Intervalo minimo entre requisicoes ao mesmo host, em segundos. O googlesource
# recusa por taxa mesmo com pouca concorrencia, entao alem de serializar (limite 1)
# ele precisa de um respiro entre as chamadas. Nao ha espelho utilizavel: o
# aosp-mirror do GitHub nao tem os commits do BigVul (17 de 20 testados dao 404).
INTERVALO_POR_HOST = {
    "android.googlesource.com": 0.6,
}
# Espera apos um 429 sem cabecalho Retry-After.
PAUSA_APOS_429 = 5.0

# Alguns hosts do BigVul sairam do ar ou migraram desde 2020. Quando o host
# original nao responde, o mesmo commit e buscado em um espelho no GitHub. O SHA
# e o mesmo, porque sao espelhos do mesmo repositorio.
ESPELHOS = {
    "git.php.net": "https://github.com/php/php-src",
    "git.openssl.org": "https://github.com/openssl/openssl",
    "git.qemu.org": "https://github.com/qemu/qemu",
    "git.postgresql.org": "https://github.com/postgres/postgres",
    "git.libav.org": "https://github.com/libav/libav",
    "git.busybox.net": "https://github.com/mirror/busybox",   # host serve 404 hoje
    "git.savannah.gnu.org": None,      # varia por repo, resolvido em espelho_de()
    "git.ghostscript.com": None,       # idem
}

# Espelhos por repositorio, para hosts que hospedam varios projetos (savannah e
# ghostscript). Cada entrada foi confirmada buscando um commit REAL do BigVul no
# candidato: so entrou na lista o espelho que devolveu 200 para aquele commit.
ESPELHOS_POR_REPO = {
    # git.savannah.gnu.org (fora do ar: nao aceita conexao)
    "freetype2": "https://github.com/freetype/freetype2",
    "gnutls": "https://github.com/gnutls/gnutls",
    "libtasn1": "https://github.com/gnutls/libtasn1",
    "libidn": "https://github.com/libidn/libidn",
    "quagga": "https://github.com/Quagga/quagga",
    "gnulib": "https://github.com/coreutils/gnulib",
    "wget": "https://github.com/mirror/wget",
    "patch": "https://github.com/mirror/patch",
    # git.ghostscript.com (gitweb devolve 401)
    "mupdf": "https://github.com/ArtifexSoftware/mupdf",
    "ghostpdl": "https://github.com/ArtifexSoftware/ghostpdl",
    "jbig2dec": "https://github.com/ArtifexSoftware/jbig2dec",
    "mujs": "https://github.com/ArtifexSoftware/mujs",
    # demais hosts de projeto unico
    "qemu": "https://github.com/qemu/qemu",
    "openssl": "https://github.com/openssl/openssl",
    "postgresql": "https://github.com/postgres/postgres",
}
# Sem espelho confirmado, somando 8 itens: grep (1), bash (2) e freetype2-demos
# (5). Os candidatos obvios devolveram 404 para os commits do BigVul.


@dataclass
class Resultado:
    status: str
    familia: str = ""
    base: str = ""
    sha: str = ""
    origem_paths: str = ""          # "file_name" ou "patch"
    arquivos: list = field(default_factory=list)   # [(caminho, conteudo)]
    detalhe: str = ""


class Sessao:
    """Sessao HTTP com retentativa. Uma instancia reaproveita conexoes, o que
    importa quando se baixa milhares de arquivos do mesmo host."""

    def __init__(self, timeout=TIMEOUT, tentativas=TENTATIVAS, conexoes=16):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "tcc-bigvul-cpg/1.0"
        # O pool padrao do urllib3 guarda 10 conexoes. Com mais threads que isso,
        # as conexoes excedentes sao descartadas e reabertas a cada requisicao.
        ad = requests.adapters.HTTPAdapter(pool_connections=conexoes,
                                           pool_maxsize=conexoes)
        self.s.mount("https://", ad)
        self.s.mount("http://", ad)
        self.timeout = timeout
        self.tentativas = tentativas
        self._falhas = {}                 # host -> falhas de conexao seguidas
        self._trava = threading.Lock()
        self.hosts_mortos = set()
        self.hosts_vivos = set()
        self._sem = {}
        self._ultima = {}
        self.recusas_429 = Counter()

    def _porta(self, host):
        """Semaforo por host, criado sob demanda."""
        with self._trava:
            s = self._sem.get(host)
            if s is None:
                s = threading.Semaphore(LIMITE_POR_HOST.get(host, LIMITE_PADRAO))
                self._sem[host] = s
            return s

    def _respirar(self, host):
        """Segura a chamada ate completar o intervalo minimo daquele host."""
        minimo = INTERVALO_POR_HOST.get(host)
        if not minimo:
            return
        with self._trava:
            agora = time.monotonic()
            falta = self._ultima.get(host, 0.0) + minimo - agora
            self._ultima[host] = agora + max(falta, 0.0)
        if falta > 0:
            time.sleep(falta)

    def _morto(self, host):
        with self._trava:
            return host in self.hosts_mortos

    def _marcar(self, host, falhou):
        """Contabiliza o host. A regra que importa: um host que ja respondeu ao
        menos uma vez NUNCA e dado como morto.

        Sem essa regra, um host bom sob carga e condenado por azar. Foi o que
        aconteceu com android.googlesource.com: 290 itens baixaram, tres timeouts
        seguidos com 16 threads marcaram o host, e os 316 itens restantes falharam
        sem sequer tentar. Marcar so vale para host que nunca respondeu, que e o
        caso real de servidor extinto (git.savannah.gnu.org)."""
        with self._trava:
            if not falhou:
                self.hosts_vivos.add(host)
                self._falhas[host] = 0
                return
            if host in self.hosts_vivos:
                return
            n = self._falhas.get(host, 0) + 1
            self._falhas[host] = n
            if n >= FALHAS_PARA_DESISTIR:
                self.hosts_mortos.add(host)

    def get(self, url):
        """Devolve o texto, ou None.

        So retenta o que pode mudar numa segunda tentativa: erro de conexao,
        5xx e 429. Respostas 4xx sao definitivas -- o host disse que nao vai
        entregar, e esperar nao muda isso. Sem essa distincao, os hosts mortos
        do BigVul (o gitweb do ghostscript devolve 401 em todo commit) custavam
        cerca de 8 segundos cada em pausas inuteis, e sao justamente os primeiros
        itens do conjunto."""
        host = urlparse(url).netloc.lower()
        if self._morto(host):
            return None
        erro = ""
        porta = self._porta(host)
        for i in range(self.tentativas):
            try:
                with porta:
                    self._respirar(host)
                    r = self.s.get(url, timeout=self.timeout, allow_redirects=True)
                self._marcar(host, False)     # o host respondeu, seja o que for
                if r.status_code == 200:
                    return r.text
                erro = f"HTTP {r.status_code}"
                if r.status_code == 429:
                    self.recusas_429[host] += 1
                    espera = PAUSA_APOS_429 * (i + 1)
                    try:                      # o host costuma dizer quanto esperar
                        espera = max(espera, float(r.headers.get("retry-after", 0)))
                    except ValueError:
                        pass
                    time.sleep(min(espera, 30))
                    continue
                if 400 <= r.status_code < 500:
                    break
            except requests.RequestException as e:
                erro = type(e).__name__
                # So erro de conexao conta contra o host. ReadTimeout significa
                # servidor lento, nao servidor extinto.
                self._marcar(host, isinstance(e, requests.ConnectionError))
                if self._morto(host):
                    break
            if i < self.tentativas - 1:
                time.sleep(PAUSA_ENTRE_TENTATIVAS * (i + 1))
        self.ultimo_erro = erro
        return None


# --------------------------------------------------------------------------
# Identificacao da familia de forge a partir do codeLink do BigVul
# --------------------------------------------------------------------------

def normalizar_ref(ref):
    """Devolve um SHA utilizavel a partir de uma referencia do BigVul.

    Alguns itens trazem a saida de "git describe" em vez do hash, tanto no
    codeLink quanto na coluna commit_id (ex.: curl-7_51_0-162-g3ab3c16). O sufixo
    "-g<hash>" carrega o SHA abreviado, que os forges aceitam."""
    r = str(ref or "").strip()
    if re.fullmatch(r"[0-9a-f]{7,40}", r, re.I):
        return r
    m = re.search(r"-g([0-9a-f]{7,40})$", r, re.I)
    return m.group(1) if m else ""


def detectar(codelink):
    """Devolve (familia, base, sha) ou (None, None, None).

    Os formatos observados no BigVul:
      github        https://github.com/<o>/<r>/commit/<sha>
      github (PR)   https://github.com/<o>/<r>/pull/<n>/commits/<sha>
      github (desc) https://github.com/<o>/<r>/commit/curl-7_51_0-162-g3ab3c16
      googlesource  https://android.googlesource.com/<caminho>/+/<sha>
      gitweb        https://git.savannah.gnu.org/gitweb/?p=gnutls.git;a=commitdiff;h=<sha>
      cgit          https://cgit.freedesktop.org/xorg/lib/libXfont/commit/?id=<sha>
      cgit c/ path  https://git.pengutronix.de/cgit/barebox/commit/fs/nfs.c?h=next&id=<sha>
    """
    if not codelink:
        return None, None, None
    u = str(codelink).strip()
    if u.lower() in ("", "nan", "none"):
        return None, None, None

    # Aceita tanto /commit/<ref> quanto /pull/<n>/commits/<ref>. A ref nem sempre
    # e um hash; quando nao for, sai vazia e o chamador usa o commit_id.
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/"
                 r"(?:pull/\d+/commits?|commits?)/([^/?#]+)", u, re.I)
    if m:
        base = f"https://github.com/{m.group(1)}/{m.group(2)}"
        return "github", base, normalizar_ref(m.group(3))

    m = re.match(r"(https?://[^/]*googlesource\.com/.+?)/\+/([0-9a-f]{7,40})", u, re.I)
    if m:
        return "googlesource", m.group(1), m.group(2)

    # gitweb: os parametros vem separados por ';' ou '&', e o SHA fica em h= ou hb=
    if "?p=" in u or "/gitweb/" in u:
        p = urlparse(u)
        q = parse_qs(p.query.replace(";", "&"))
        repo = (q.get("p") or [""])[0]
        sha = (q.get("h") or q.get("hb") or [""])[0]
        if repo and re.fullmatch(r"[0-9a-f]{7,40}", sha or "", re.I):
            prefixo = p.path if p.path and p.path != "/" else "/"
            base = f"{p.scheme}://{p.netloc}{prefixo}"
            return "gitweb", f"{base}?p={repo}", sha

    # cgit: .../<caminho do repo>/commit/[<arquivo>]?...id=<sha>
    m = re.match(r"(https?://[^?]+?)/commit/[^?]*\?(.*)", u, re.I)
    if m:
        q = parse_qs(m.group(2).replace(";", "&"))
        sha = (q.get("id") or [""])[0]
        if re.fullmatch(r"[0-9a-f]{7,40}", sha or "", re.I):
            return "cgit", m.group(1), sha

    return None, None, None


def nome_do_repo(base):
    """Extrai o nome do repositorio da base, nos dois formatos que aparecem:
    gitweb (?p=gnutls.git) e cgit (/cgit/freetype/freetype2.git). O savannah usa
    o formato cgit com o repo aninhado em subdiretorio."""
    b = str(base)
    m = re.search(r"[?&;]p=([^;&]+?)(?:\.git)?(?:[;&]|$)", b)
    if m:
        return m.group(1).split("/")[-1].lower()
    m = re.search(r"/(?:cgit|gitweb|git)/(?:[^/]+/)*([^/?]+?)(?:\.git)?/?$", b)
    if m:
        return m.group(1).lower()
    m = re.search(r"/([^/?]+?)\.git", b)
    if m:
        return m.group(1).split("/")[-1].lower()
    return None


def espelho_de(base, familia):
    """Devolve uma base no GitHub para hosts que sairam do ar, ou None."""
    host = urlparse(base).netloc.lower()
    if host not in ESPELHOS:
        return None
    fixo = ESPELHOS[host]
    if fixo:
        return fixo
    repo = nome_do_repo(base)
    return ESPELHOS_POR_REPO.get(repo) if repo else None


# --------------------------------------------------------------------------
# Montagem de URL por familia
# --------------------------------------------------------------------------

def url_patch(familia, base, sha):
    if familia == "github":
        return f"{base}/commit/{sha}.patch"
    if familia == "googlesource":
        return f"{base}/+/{sha}%5E%21?format=TEXT"     # <sha>^! = so este commit
    if familia == "gitweb":
        return f"{base};a=patch;h={sha}"
    if familia == "cgit":
        return f"{base}/patch/?id={sha}"
    return None


def url_arquivo_no_pai(familia, base, sha, caminho):
    """URL do arquivo na versao anterior ao commit. O sufixo ^ e aceito pelas
    quatro familias, o que evita ter que descobrir o SHA do pai por API."""
    c = quote(caminho.lstrip("/"))
    if familia == "github":
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", base)
        o, r = m.group(1), m.group(2)
        return f"https://raw.githubusercontent.com/{o}/{r}/{sha}%5E/{c}"
    if familia == "googlesource":
        return f"{base}/+/{sha}%5E/{c}?format=TEXT"
    if familia == "gitweb":
        return f"{base};a=blob_plain;f={c};hb={sha}%5E"
    if familia == "cgit":
        return f"{base}/plain/{c}?id={sha}%5E"
    return None


def decodifica(familia, texto):
    """googlesource devolve base64; as outras familias devolvem texto puro."""
    if familia != "googlesource" or texto is None:
        return texto
    try:
        return base64.b64decode(texto).decode("utf-8", errors="replace")
    except Exception:
        return texto


# --------------------------------------------------------------------------
# Extracao dos caminhos a partir do patch
# --------------------------------------------------------------------------

def paths_do_patch(texto):
    """Le as linhas 'diff --git a/<x> b/<y>' e devolve os arquivos de codigo.
    Usa o lado b/ (pos-imagem) e cai para o a/ quando o arquivo foi removido."""
    if not texto:
        return []
    achados = []
    for a, b in re.findall(r'^diff --git ["\']?a/(.+?)["\']? ["\']?b/(.+?)["\']?$',
                           texto, re.M):
        alvo = b if b != "dev/null" else a
        if alvo.lower().endswith(EXT_CODIGO):
            achados.append(alvo)
    # cgit e gitweb as vezes emitem apenas '--- a/x' / '+++ b/x'
    if not achados:
        for b in re.findall(r"^\+\+\+ b/(.+)$", texto, re.M):
            if b.lower().endswith(EXT_CODIGO) and b != "dev/null":
                achados.append(b)
    vistos, out = set(), []
    for c in achados:
        if c not in vistos:
            vistos.add(c)
            out.append(c)
    return out


def limpar_file_name(file_name):
    """O file_name do BigVul as vezes vem com prefixo de diff, as vezes ausente
    como NaN. Devolve '' quando nao ha nada aproveitavel."""
    if file_name is None:
        return ""
    s = str(file_name).strip()
    if s.lower() in ("", "nan", "none", "<na>"):
        return ""
    return re.sub(r"^[ab]/", "", s)


# --------------------------------------------------------------------------
# Fluxo principal
# --------------------------------------------------------------------------

def nome_da_funcao(codigo):
    """Extrai o nome da funcao de um trecho em C, para saber qual arquivo do
    commit e o certo. Pula os controles de fluxo, que tambem sao seguidos de
    parenteses, e devolve '' quando nao da para decidir."""
    if not codigo:
        return ""
    palavras = {"if", "for", "while", "switch", "return", "sizeof", "static",
                "else", "do", "case", "defined", "typedef", "struct", "union"}
    for linha in str(codigo).splitlines():
        linha = linha.strip()
        if not linha or linha.startswith(("#", "/", "*", "}")):
            continue
        for m in re.finditer(r"([A-Za-z_]\w{2,})\s*\(", linha):
            if m.group(1).lower() not in palavras:
                return m.group(1)
    return ""


def ordenar_por_afinidade(caminhos, alvo_func, file_name=""):
    """Ordena os arquivos de um commit pela chance de conterem a funcao marcada.

    Um commit grande toca dezenas de arquivos e a ordem do patch e alfabetica,
    sem relacao com o alvo. Como as bases em C nomeiam arquivo e funcao com o
    mesmo prefixo (jbig2_text.c / jbig2_text_region), comparar os dois resolve a
    maioria dos casos sem baixar nada. Sem isso, um corte por quantidade descarta
    justamente o arquivo certo quando ele cai no fim da lista alfabetica."""
    alvo = (alvo_func or "").lower()
    base_fn = os.path.splitext(os.path.basename(str(file_name or "")))[0].lower()

    def score(c):
        raiz = os.path.splitext(os.path.basename(c))[0].lower()
        s = 9
        if base_fn and raiz == base_fn:
            s = 0                          # bate com o file_name do BigVul
        elif alvo and raiz and raiz in alvo:
            s = 1                          # jbig2_text.c  <-  jbig2_text_region
        elif alvo and raiz:
            toks = [t for t in raiz.split("_") if len(t) > 2]
            if toks and all(t in alvo for t in toks):
                s = 2
            elif any(t in alvo for t in toks):
                s = 3
        # a definicao mora no .c; o cabecalho quase nunca e o alvo
        return (s, 0 if c.lower().endswith((".c", ".cc", ".cpp", ".cxx")) else 1)

    return sorted(caminhos, key=score)


def buscar_arquivos_do_commit(codelink, sha_fallback="", file_name="",
                              sessao=None, max_arquivos=12, so_um=True,
                              funcao=""):
    """Devolve um Resultado com os arquivos afetados na versao anterior.

    so_um=True para no primeiro arquivo que sirva, o que basta para gerar o CPG
    da funcao marcada. Passe so_um=False para pegar todos os arquivos de codigo
    do commit.

    funcao: nome (ou corpo) da funcao marcada pelo BigVul. Quando informado, um
    commit que toca varios arquivos nao devolve o primeiro da lista, e sim aquele
    que de fato contem a funcao. Sem isso, casos como o do libXrandr devolvem
    XrrConfig.c quando a funcao marcada esta em outro arquivo do mesmo commit.
    """
    ses = sessao or Sessao()
    familia, base, sha = detectar(codelink)
    if not familia:
        return Resultado("forge_desconhecido", detalhe=str(codelink)[:120])
    if not sha:
        sha = normalizar_ref(sha_fallback)
    if not sha:
        return Resultado("sem_sha", familia=familia, base=base,
                         detalhe=f"codelink e commit_id sem hash: {str(sha_fallback)[:60]}")

    alvo_func = funcao if (funcao and " " not in funcao) else nome_da_funcao(funcao)
    res = Resultado("?", familia=familia, base=base, sha=sha)

    def tentar(familia, base):
        # 1. de onde vem a lista de caminhos
        fn = limpar_file_name(file_name)
        if fn and "/" in fn:
            caminhos, origem = [fn], "file_name"
        else:
            patch = decodifica(familia, ses.get(url_patch(familia, base, sha)))
            caminhos = paths_do_patch(patch)
            origem = "patch"
            if fn and not caminhos:
                caminhos = [fn]
                origem = "file_name"
            else:
                caminhos = ordenar_por_afinidade(caminhos, alvo_func, fn)
        if not caminhos:
            return None, origem, [], False

        # 2. baixa cada caminho na versao do pai. Com so_um, aceita o primeiro que
        #    contenha a funcao marcada ("forte"); se nenhum contiver, fica com o
        #    primeiro que baixou ("fraco"), para nao perder o item.
        obtidos, reserva = [], None
        for c in caminhos[:max_arquivos]:
            txt = decodifica(familia, ses.get(url_arquivo_no_pai(familia, base, sha, c)))
            if not (txt and txt.strip()):
                continue
            if not so_um:
                obtidos.append((c, txt))
                continue
            if not alvo_func or alvo_func in txt:
                return caminhos, origem, [(c, txt)], True
            if reserva is None:
                reserva = (c, txt)
        if so_um:
            return caminhos, origem, ([reserva] if reserva else []), False
        return caminhos, origem, obtidos, bool(obtidos)

    caminhos, origem, obtidos, forte = tentar(familia, base)
    res.origem_paths = origem

    # Vale tentar o espelho no GitHub em dois casos: o host original nao entregou
    # nada, ou entregou um arquivo que nao contem a funcao marcada. O segundo caso
    # aparece quando o gitweb do host nao serve o patch (jbig2dec): sem a lista de
    # caminhos, sobra o file_name do BigVul, que as vezes aponta o arquivo errado.
    if not forte:
        esp = espelho_de(base, familia)
        if esp:
            _c2, origem2, obtidos2, forte2 = tentar("github", esp)
            if obtidos2 and (forte2 or not obtidos):
                res.familia, res.base = "github (espelho)", esp
                res.origem_paths = origem2
                res.arquivos = obtidos2
                res.status = "ok" if forte2 else "ok_sem_confirmar_funcao"
                return res

    res.arquivos = obtidos
    if obtidos:
        # ok_sem_confirmar_funcao: o arquivo baixou, mas a funcao marcada nao foi
        # localizada nele. Serve para gerar CPG, porem merece conferencia antes de
        # entrar no conjunto final.
        res.status = "ok" if (forte or not alvo_func) else "ok_sem_confirmar_funcao"
    elif not caminhos:
        res.status = "sem_paths"
    else:
        res.status = "arquivo_nao_baixado"
        res.detalhe = f"{len(caminhos)} caminho(s) tentado(s), nenhum baixou"
    return res


# --------------------------------------------------------------------------
# Autoteste: um caso real por familia, todos vindos do BigVul
# --------------------------------------------------------------------------

CASOS = [
    # (familia esperada, codelink, sha, file_name, marcador que so existe na
    #  versao ANTERIOR ou trecho que deve estar presente)
    ("github",
     "https://github.com/libgd/libgd/commit/fb0e0cce0b9f25389ab56604c3547351617e1415",
     "fb0e0cce0b9f25389ab56604c3547351617e1415", "src/gd_tga.c",
     "read_image_tga"),
    ("github",
     "https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6",
     "f6e9d0d9955e85bdd7540b251cd50d598dacc5e6", "nan",
     None),
    ("googlesource",
     "https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d",
     "04839626ed859623901ebd3a5fd483982186b59d", "nan",
     None),
    ("cgit",
     "https://cgit.freedesktop.org/xorg/lib/libXfont/commit/?id=d11ee5886e9d9ec610051a206b135a4cdc1e09a0",
     "d11ee5886e9d9ec610051a206b135a4cdc1e09a0", "nan",
     None),
    ("cgit",
     "https://git.pengutronix.de/cgit/barebox/commit/fs/nfs.c?h=next&id=574ce994016107ad8ab0f845a785f28d7eaa5208",
     "574ce994016107ad8ab0f845a785f28d7eaa5208", "nan",
     None),
    ("gitweb",
     "https://git.savannah.gnu.org/gitweb/?p=gnutls.git;a=commitdiff;h=190cef6eed37d0e73a73c1e205eb31d45ab60a3c",
     "190cef6eed37d0e73a73c1e205eb31d45ab60a3c", "nan",
     None),
    ("gitweb",
     "https://git.php.net/?p=php-src.git;a=commit;h=c351b47ce85a3a147cfa801fa9f0149ab4160834",
     "c351b47ce85a3a147cfa801fa9f0149ab4160834", "nan",
     None),
    ("gitweb",
     "http://git.ghostscript.com/?p=mupdf.git;a=commit;h=97096297d409ec6f206298444ba00719607e8ba8",
     "97096297d409ec6f206298444ba00719607e8ba8", "nan",
     None),
    # Casos de borda encontrados na primeira rodada de 100 itens.
    ("cgit",   # host 404 desde 2020, resolvido por espelho no GitHub
     "https://git.busybox.net/busybox/commit/?id=74d9f1ba37010face4bd1449df4d60dd84450b06",
     "74d9f1ba37010face4bd1449df4d60dd84450b06", "nan",
     None),
    ("github",  # URL de pull request, nao de commit direto
     "https://github.com/OpenSC/OpenSC/pull/1447/commits/8fe377e93b4b56060e5bbfb6f3142ceaeca744fa",
     "8fe377e93b4b56060e5bbfb6f3142ceaeca744fa", "nan",
     None),
]

# Commits que tocam varios arquivos: o arquivo certo e o que contem a funcao
# marcada, nao o primeiro do patch. Ambos vieram da primeira rodada de 100 itens.
#   libXrandr: o patch toca 6 arquivos e o primeiro nao e o da funcao.
#   jbig2dec : o gitweb do host nao serve o patch, entao sobra o file_name do
#              BigVul ("jbig2.c"), que existe mas nao contem a funcao.
CASOS_ESCOLHA = [
    ("https://cgit.freedesktop.org/xorg/lib/libXrandr/commit/?id=a0df3e1c7728205e5c7650b2e6dce684139254a6",
     "a0df3e1c7728205e5c7650b2e6dce684139254a6", "XRRGetOutputInfo"),
    ("http://git.ghostscript.com/?p=jbig2dec.git;a=commit;h=e698d5c11d27212aa1098bc5b1673a3378563092",
     "e698d5c11d27212aa1098bc5b1673a3378563092", "jbig2_text_region"),
]

# Caso conhecido sem solucao, deixado registrado de proposito. O BigVul guarda a
# saida de "git describe" (curl-7_51_0-162-g3ab3c16) tanto no codeLink quanto no
# commit_id, e o hash abreviado 3ab3c16 nao existe mais em curl/curl: o .patch
# devolve 404 e a API devolve 422. Sem um hash valido nao ha o que buscar. E 1
# item em 2957, entao entra na contagem de perdas em vez de virar caso especial.
CASOS_SEM_SOLUCAO = [
    ("curl", "https://github.com/curl/curl/commit/curl-7_51_0-162-g3ab3c16",
     "curl-7_51_0-162-g3ab3c16"),
]


def autoteste():
    ses = Sessao()
    print("Autoteste: um caso real por familia de forge.\n")

    print("--- deteccao da familia ---")
    ok_det = 0
    for esperada, link, sha, _fn, _m in CASOS:
        fam, base, s = detectar(link)
        bateu = fam == esperada and s.lower() == sha.lower()
        ok_det += bateu
        print(f"  {'OK ' if bateu else 'ERRO'} {esperada:13s} -> {str(fam):13s} {str(base)[:58]}")
    print(f"  {ok_det}/{len(CASOS)} corretos\n")

    print("--- download do arquivo na versao anterior ---")
    ok = 0
    for esperada, link, sha, fn, marcador in CASOS:
        host = urlparse(link).netloc
        r = buscar_arquivos_do_commit(link, sha, fn, sessao=ses)
        if r.status == "ok":
            caminho, conteudo = r.arquivos[0]
            nota = ""
            if marcador and marcador not in conteudo:
                nota = f"  <-- ATENCAO: '{marcador}' ausente"
            else:
                ok += 1
            print(f"  OK   {host:26s} {r.familia:17s} paths={r.origem_paths:9s} "
                  f"{len(conteudo):7d} bytes  {caminho[:40]}{nota}")
        else:
            print(f"  FALHA {host:25s} {r.familia:17s} status={r.status:20s} {r.detalhe[:40]}")
    print(f"\n  {ok}/{len(CASOS)} arquivos baixados")

    print("\n--- escolhe o arquivo que contem a funcao, nao o primeiro do patch ---")
    ok_esc = 0
    for link, sha, func in CASOS_ESCOLHA:
        r = buscar_arquivos_do_commit(link, sha, "nan", sessao=ses, funcao=func)
        if r.arquivos:
            caminho, conteudo = r.arquivos[0]
            bateu = func in conteudo
            ok_esc += bateu
            print(f"  {'OK  ' if bateu else 'ERRO'} {func:26s} -> {caminho}  ({r.familia})")
        else:
            print(f"  FALHA {func:25s} status={r.status}")
    print(f"  {ok_esc}/{len(CASOS_ESCOLHA)} corretos")

    print("\n--- casos conhecidos sem solucao (devem falhar) ---")
    for proj, link, sha in CASOS_SEM_SOLUCAO:
        r = buscar_arquivos_do_commit(link, sha, "nan", sessao=ses)
        marca = "OK (falhou como esperado)" if r.status != "ok" else "INESPERADO: funcionou"
        print(f"  {proj:8s} status={r.status:22s} {marca}")

    print("\n--- confere que a versao e a ANTERIOR a correcao (libgd, CVE-2016-6906) ---")
    correcao = "buffer_caret + pixel_block_size > rle_size"
    link, sha = CASOS[0][1], CASOS[0][2]
    r = buscar_arquivos_do_commit(link, sha, "src/gd_tga.c", sessao=ses)
    if r.status == "ok":
        anterior = r.arquivos[0][1]
        depois = ses.get(f"https://raw.githubusercontent.com/libgd/libgd/{sha}/src/gd_tga.c") or ""
        a, d = correcao in anterior, correcao in depois
        print(f"  correcao presente na versao baixada (esperado False): {a}")
        print(f"  correcao presente no commit da correcao (esperado True): {d}")
        print("  >> " + ("CORRETO: e a versao anterior" if (not a and d)
                         else "ERRADO: versao suspeita"))
    else:
        print("  nao foi possivel verificar:", r.status)
    return 0 if ok == len(CASOS) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--autoteste", action="store_true",
                    help="roda um caso real por familia de forge (usa rede)")
    ap.add_argument("--codelink", help="testa um codeLink avulso")
    ap.add_argument("--sha", default="")
    ap.add_argument("--file-name", default="")
    args = ap.parse_args()

    if args.autoteste:
        sys.exit(autoteste())
    if args.codelink:
        r = buscar_arquivos_do_commit(args.codelink, args.sha, args.file_name)
        print(f"familia={r.familia}  status={r.status}  paths_de={r.origem_paths}")
        for c, txt in r.arquivos:
            print(f"  {c}  ({len(txt)} bytes)")
        if r.detalhe:
            print("  detalhe:", r.detalhe)
        sys.exit(0 if r.status == "ok" else 1)
    ap.print_help()


if __name__ == "__main__":
    main()
