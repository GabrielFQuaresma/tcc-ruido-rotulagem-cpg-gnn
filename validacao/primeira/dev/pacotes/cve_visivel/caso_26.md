# Pacote de anotacao — caso 26

Voce e o segundo anotador de um estudo de confiabilidade sobre ruido de
rotulagem no dataset BigVul. Leia a rubrica, leia a evidencia, e devolva
o veredito no formato exigido. Julgue somente com a evidencia abaixo.

---

# Rubrica de anotacao — versao 1 (CONGELADA)

> **Esta rubrica esta congelada.** Ela foi fixada antes da anotacao do segundo
> anotador (modelo) e NAO pode ser editada depois que as discordancias forem
> vistas. Qualquer alteracao invalida a comparacao: o criterio passaria a ser
> derivado dos rotulos ja conhecidos. Se algo precisar mudar, crie
> `rubrica_v2.md` e re-anote os dois lados.
>
> O hash SHA-256 deste arquivo e gravado em cada anotacao produzida. O script
> de comparacao recusa rodar se o hash gravado nas anotacoes nao bater com o
> hash do arquivo em disco.

## Contexto da tarefa

O BigVul e um dataset de funcoes C/C++ rotuladas a partir de commits de
correcao de CVEs. O rotulo positivo (`vul = 1`) e atribuido a TODA funcao
tocada pelo commit que corrige a CVE. Isso e uma heuristica: um commit de
correcao tipicamente altera varias funcoes, e a maioria delas nao e o sitio da
vulnerabilidade.

A tarefa e julgar, para uma funcao marcada como vulneravel pelo BigVul, se esse
rotulo esta correto — isto e, se **esta funcao especifica** e o sitio da
vulnerabilidade descrita pela CVE.

## Tipos de ruido (campo `tipo_ruido`)

- **A** = sem mudanca semantica na funcao (so espaco em branco, formatacao ou
  comentario). Categoria documentada: o BigVul carrega correcoes que so mexeram
  em espaco em branco como se fossem de seguranca. **Nao vulneravel.**

- **B** = a funcao mudou, mas a mudanca NAO tem relacao com a CVE (refatoracao,
  funcionalidade nao relacionada, alteracao em outro subsistema que veio junto
  no mesmo commit). **Nao vulneravel.**

- **C** = a funcao mudou como parte do conserto, mas NAO e o sitio do bug
  (ajuste de parametros, reset de contador, hardening de apoio, propagacao de
  um novo argumento). A mudanca e causalmente ligada a correcao, mas o defeito
  exploravel nao esta nesta funcao. **Nao vulneravel.**

- **D** = a funcao E o sitio da vulnerabilidade, reconhecivel aqui. O acesso
  de memoria indevido, a falta de checagem de limite, o overflow de inteiro que
  alimenta o tamanho — o defeito esta no corpo desta funcao. **Vulneravel.**

- **?** = nao deu para decidir com a evidencia disponivel.

**A, B e C sao todos NAO vulneravel, por motivos diferentes. So o D entra na
conta de positivo verdadeiro. Os `?` ficam de fora da conta e sao reportados a
parte.**

## Campo `confianca`

Exatamente um de: `alta`, `media`, `baixa`.

- `alta` — a evidencia disponivel decide o caso.
- `media` — a leitura mais provavel e essa, mas ha uma interpretacao alternativa
  plausivel.
- `baixa` — chute informado; falta contexto, conhecimento do subsistema, ou a
  evidencia e ambigua.

## Campo `cwe_correta`

Preencher **so nos D**. Nos A/B/C a funcao nao e vulneravel, entao nao ha CWE a
corrigir. Nos D, serve para identificar a funcao de fato vulneravel cuja CWE
real cai FORA da familia de erro de memoria em buffer (CWE-119, 120, 125, 787),
que e o caso que ameaca o recorte do trabalho.

Formato: `CWE-NNN`. Se a CWE do BigVul estiver correta, repita-a. Se nao houver
CWE aplicavel ou nao der para determinar, use string vazia.

## Campo `observacao`

Uma ou duas frases justificando o veredito. Nos D, vale anotar se o bug foi
reconhecivel so com a funcao ou se foi preciso o contexto do commit inteiro.

---

## Contrato de saida (para o anotador-modelo)

A resposta deve ser **exclusivamente** um objeto JSON, sem texto antes ou
depois, sem cercas de codigo:

```
{"tipo_ruido": "A|B|C|D|?", "confianca": "alta|media|baixa",
 "cwe_correta": "CWE-NNN ou vazio", "observacao": "uma ou duas frases"}
```

Regras:

- `tipo_ruido` e `confianca` sao obrigatorios e devem usar exatamente os valores
  listados.
- Julgue apenas com a evidencia fornecida no pacote. Nao use ferramentas, nao
  busque na web, nao tente abrir arquivos.
- Se a evidencia nao decidir o caso, use `?` — nao chute para evitar o `?`.

---

# Evidencia do caso 26

## Identificacao

- projeto: libxfont
- CVE: CVE-2007-5199
- CWE atribuida pelo BigVul: CWE-119
- commit: `5bf703700ee4a5d6eae20da07cb7a29369667aef`
- URL do commit: https://cgit.freedesktop.org/xorg/lib/libXfont/commit/?id=5bf703700ee4a5d6eae20da07cb7a29369667aef
- arquivo da funcao marcada: `_ausente_`

## Mensagem do commit

_Nao disponivel neste registro._

## Resumo da CVE

> A single byte overflow in catalogue.c in X.Org libXfont 1.3.1 allows remote attackers to have unspecified impact.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -30,7 +30,7 @@
      while (entry = readdir(dir), entry != NULL)
      {
  	snprintf(link, sizeof link, "%s/%s", path, entry->d_name);
-	len = readlink(link, dest, sizeof dest);
+	len = readlink(link, dest, sizeof dest - 1);
  	if (len < 0)
  	    continue;
 	dest[len] = '\0';
```

## Corpo completo da funcao antes da correcao

```c
CatalogueRescan (FontPathElementPtr fpe)
{
    CataloguePtr	cat = fpe->private;
    char		link[MAXFONTFILENAMELEN];
    char		dest[MAXFONTFILENAMELEN];
    char		*attrib;
    FontPathElementPtr	subfpe;
    struct stat		statbuf;
    const char		*path;
    DIR			*dir;
    struct dirent	*entry;
    int			len;
    int			pathlen;

    path = fpe->name + strlen(CataloguePrefix);
    if (stat(path, &statbuf) < 0 || !S_ISDIR(statbuf.st_mode))
	return BadFontPath;

    if (statbuf.st_mtime <= cat->mtime)
	return Successful;

    dir = opendir(path);
    if (dir == NULL)
    {
	xfree(cat);
	return BadFontPath;
    }

    CatalogueUnrefFPEs (fpe);
     while (entry = readdir(dir), entry != NULL)
     {
 	snprintf(link, sizeof link, "%s/%s", path, entry->d_name);
	len = readlink(link, dest, sizeof dest);
 	if (len < 0)
 	    continue;
	dest[len] = '\0';

	if (dest[0] != '/')
	{
	   pathlen = strlen(path);
	   memmove(dest + pathlen + 1, dest, sizeof dest - pathlen - 1);
	   memcpy(dest, path, pathlen);
	   memcpy(dest + pathlen, "/", 1);
	   len += pathlen + 1;
	}

	attrib = strchr(link, ':');
	if (attrib && len + strlen(attrib) < sizeof dest)
	{
	    memcpy(dest + len, attrib, strlen(attrib));
	    len += strlen(attrib);
	}

	subfpe = xalloc(sizeof *subfpe);
	if (subfpe == NULL)
	    continue;

	/* The fonts returned by OpenFont will point back to the
	 * subfpe they come from.  So set the type of the subfpe to
	 * what the catalogue fpe was assigned, so calls to CloseFont
	 * (which uses font->fpe->type) goes to CatalogueCloseFont. */
	subfpe->type = fpe->type;
	subfpe->name_length = len;
	subfpe->name = xalloc (len + 1);
	if (subfpe == NULL)
	{
	    xfree(subfpe);
	    continue;
	}

	memcpy(subfpe->name, dest, len);
	subfpe->name[len] = '\0';

	/* The X server will manipulate the subfpe ref counts
	 * associated with the font in OpenFont and CloseFont, so we
	 * have to make sure it's valid. */
	subfpe->refcount = 1;

	if (FontFileInitFPE (subfpe) != Successful)
	{
	    xfree(subfpe->name);
	    xfree(subfpe);
	    continue;
	}

	if (CatalogueAddFPE(cat, subfpe) != Successful)
	{
	    FontFileFreeFPE (subfpe);
	    xfree(subfpe);
	    continue;
	}
    }

    closedir(dir);

    qsort(cat->fpeList,
	  cat->fpeCount, sizeof cat->fpeList[0], ComparePriority);

    cat->mtime = statbuf.st_mtime;

    return Successful;
}

```

## Contexto: o commit inteiro

_O BigVul nao traz o diff do commit completo para este caso._

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
