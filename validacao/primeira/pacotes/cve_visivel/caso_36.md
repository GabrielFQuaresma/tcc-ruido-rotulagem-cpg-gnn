# Pacote de anotacao — caso 36

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

# Evidencia do caso 36

## Identificacao

- projeto: libsndfile
- CVE: CVE-2017-7586
- CWE atribuida pelo BigVul: CWE-119
- commit: `708e996c87c5fae77b104ccfeb8f6db784c32074`
- URL do commit: https://github.com/erikd/libsndfile/commit/708e996c87c5fae77b104ccfeb8f6db784c32074
- arquivo da funcao marcada: `src/common.c`

## Mensagem do commit

> src/ : Move to a variable length header buffer
> 
> Previously, the `psf->header` buffer was a fixed length specified by
> `SF_HEADER_LEN` which was set to `12292`. This was problematic for
> two reasons; this value was un-necessarily large for the majority
> of files and too small for some others.
> 
> Now the size of the header buffer starts at 256 bytes and grows as
> necessary up to a maximum of 100k.

## Resumo da CVE

> In libsndfile before 1.0.28, an error in the *header_read()* function (common.c) when handling ID3 tags can be exploited to cause a stack-based buffer overflow via a specially crafted FLAC file.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -1,6 +1,4 @@
  header_put_be_short (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 2)
-	{	psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = x ;
  } /* header_put_be_short */
```

## Corpo completo da funcao antes da correcao

```c
 header_put_be_short (SF_PRIVATE *psf, int x)
{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 2)
	{	psf->header [psf->headindex++] = (x >> 8) ;
		psf->header [psf->headindex++] = x ;
		} ;
 } /* header_put_be_short */

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `src/common.c` **(funcao marcada esta aqui)** | modified | 204 | 184 |
| `src/common.h` | modified | 9 | 6 |
| `src/sndfile.c` | modified | 5 | 4 |


### `src/common.c`

```diff
@@ -33,6 +33,49 @@
 #include "sfendian.h"
 #include "common.h"
 
+#define	INITAL_HEADER_SIZE	256
+
+/* Allocate and initialize the SF_PRIVATE struct. */
+SF_PRIVATE *
+psf_allocate (void)
+{	SF_PRIVATE * psf ;
+
+	if ((psf = calloc (1, sizeof (SF_PRIVATE))) == NULL)
+		return	NULL ;
+
+	if ((psf->header.ptr = calloc (1, INITAL_HEADER_SIZE)) == NULL)
+	{	free (psf) ;
+		return	NULL ;
+		} ;
+	psf->header.len = INITAL_HEADER_SIZE ;
+
+	return psf ;
+} /* psf_allocate */
+
+static int
+psf_bump_header_allocation (SF_PRIVATE * psf, sf_count_t needed)
+{
+	sf_count_t newlen, smallest = INITAL_HEADER_SIZE ;
+	void * ptr ;
+
+	newlen = (needed > psf->header.len) ? 2 * SF_MAX (needed, smallest) : 2 * psf->header.len ;
+
+	if (newlen > 100 * 1024)
+	{	psf_log_printf (psf, "Request for header allocation of %D denined.\n", newlen) ;
+		return 1 ;
+		}
+
+	if ((ptr = realloc (psf->header.ptr, newlen)) == NULL)
+	{	psf_log_printf (psf, "realloc (%p, %D) failed\n", psf->header.ptr, newlen) ;
+		psf->error = SFE_MALLOC_FAILED ;
+		return 1 ;
+		} ;
+
+	psf->header.ptr = ptr ;
+	psf->header.len = newlen ;
+	return 0 ;
+} /* psf_bump_header_allocation */
+
 /*-----------------------------------------------------------------------------------------------
 ** psf_log_printf allows libsndfile internal functions to print to an internal parselog which
 ** can later be displayed.
@@ -336,9 +379,9 @@ psf_asciiheader_printf (SF_PRIVATE *psf, const char *format, ...)
 	int		maxlen ;
 	char	*start ;
 
-	maxlen = strlen ((char*) psf->header) ;
-	start	= ((char*) psf->header) + maxlen ;
-	maxlen	= sizeof (psf->header) - maxlen ;
+	maxlen = strlen ((char*) psf->header.ptr) ;
+	start	= ((char*) psf->header.ptr) + maxlen ;
+	maxlen	= psf->header.len - maxlen ;
 
 	va_start (argptr, format) ;
 	vsnprintf (start, maxlen, format, argptr) ;
@@ -347,7 +390,7 @@ psf_asciiheader_printf (SF_PRIVATE *psf, const char *format, ...)
 	/* Make sure the string is properly terminated. */
 	start [maxlen - 1] = 0 ;
 
-	psf->headindex = strlen ((char*) psf->header) ;
+	psf->header.indx = strlen ((char*) psf->header.ptr) ;
 
 	return ;
 } /* psf_asciiheader_printf */
@@ -400,30 +443,25 @@ psf_asciiheader_printf (SF_PRIVATE *psf, const char *format, ...)
 
 static inline void
 header_put_byte (SF_PRIVATE *psf, char x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 1)
-		psf->header [psf->headindex++] = x ;
+{	psf->header.ptr [psf->header.indx++] = x ;
 } /* header_put_byte */
 
 #if (CPU_IS_BIG_ENDIAN == 1)
 static inline void
 header_put_marker (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 4)
-	{	psf->header [psf->headindex++] = (x >> 24) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = (x >> 24) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = x ;
 } /* header_put_marker */
 
 #elif (CPU_IS_LITTLE_ENDIAN == 1)
 static inline void
 header_put_marker (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 4)
-	{	psf->header [psf->headindex++] = x ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 24) ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = x ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 24) ;
 } /* header_put_marker */
 
 #else
@@ -433,120 +471,74 @@ header_put_marker (SF_PRIVATE *psf, int x)
 
 static inline void
 header_put_be_short (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 2)
-	{	psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = x ;
 } /* header_put_be_short */
 
 static inline void
 header_put_le_short (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 2)
-	{	psf->header [psf->headindex++] = x ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = x ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
 } /* header_put_le_short */
 
 static inline void
 header_put_be_3byte (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 3)
-	{	psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = x ;
 } /* header_put_be_3byte */
 
 static inline void
 header_put_le_3byte (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 3)
-	{	psf->header [psf->headindex++] = x ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = x ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
 } /* header_put_le_3byte */
 
 static inline void
 header_put_be_int (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 4)
-	{	psf->header [psf->headindex++] = (x >> 24) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = (x >> 24) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = x ;
 } /* header_put_be_int */
 
 static inline void
 header_put_le_int (SF_PRIVATE *psf, int x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 4)
-	{	psf->header [psf->headindex++] = x ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 24) ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = x ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 24) ;
 } /* header_put_le_int */
 
-#if (SIZEOF_SF_COUNT_T == 4)
-
-static inline void
-header_put_be_8byte (SF_PRIVATE *psf, sf_count_t x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 8)
-	{	psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = (x >> 24) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
-} /* header_put_be_8byte */
-
-static inline void
-header_put_le_8byte (SF_PRIVATE *psf, sf_count_t x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 8)
-	{	psf->header [psf->headindex++] = x ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 24) ;
-		psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = 0 ;
-		psf->header [psf->headindex++] = 0 ;
-		} ;
-} /* header_put_le_8byte */
-
-#elif (SIZEOF_SF_COUNT_T == 8)
+#if (SIZEOF_SF_COUNT_T == 8)
 
 static inline void
 header_put_be_8byte (SF_PRIVATE *psf, sf_count_t x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 8)
-	{	psf->header [psf->headindex++] = (x >> 56) ;
-		psf->header [psf->headindex++] = (x >> 48) ;
-		psf->header [psf->headindex++] = (x >> 40) ;
-		psf->header [psf->headindex++] = (x >> 32) ;
-		psf->header [psf->headindex++] = (x >> 24) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = x ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = (x >> 56) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 48) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 40) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 32) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 24) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = x ;
 } /* header_put_be_8byte */
 
 static inline void
 header_put_le_8byte (SF_PRIVATE *psf, sf_count_t x)
-{	if (psf->headindex < SIGNED_SIZEOF (psf->header) - 8)
-	{	psf->header [psf->headindex++] = x ;
-		psf->header [psf->headindex++] = (x >> 8) ;
-		psf->header [psf->headindex++] = (x >> 16) ;
-		psf->header [psf->headindex++] = (x >> 24) ;
-		psf->header [psf->headindex++] = (x >> 32) ;
-		psf->header [psf->headindex++] = (x >> 40) ;
-		psf->header [psf->headindex++] = (x >> 48) ;
-		psf->header [psf->headindex++] = (x >> 56) ;
-		} ;
+{	psf->header.ptr [psf->header.indx++] = x ;
+	psf->header.ptr [psf->header.indx++] = (x >> 8) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 16) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 24) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 32) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 40) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 48) ;
+	psf->header.ptr [psf->header.indx++] = (x >> 56) ;
 } /* header_put_le_8byte */
 
 #else
-#error "SIZEOF_SF_COUNT_T is not defined."
+#error "SIZEOF_SF_COUNT_T != 8"
 #endif
 
 int
@@ -567,7 +559,11 @@ psf_binheader_writef (SF_PRIVATE *psf, const char *format, ...)
 	va_start (argptr, format) ;
 
 	while ((c = *format++))
-	{	switch (c)
+	{
+		if (psf->header.indx + 16 >= psf->header.len && psf_bump_header_allocation (psf, 16))
+			return count ;
+
+		switch (c)
 		{	case ' ' : /* Do nothing. Just used to space out format string. */
 					break ;
 
@@ -658,20 +654,20 @@ psf_binheader_writef (SF_PRIVATE *psf, const char *format, ...)
 					/* Floats are passed as doubles. Is this always true? */
 					floatdata = (float) va_arg (argptr, double) ;
 					if (psf->rwf_endian == SF_ENDIAN_BIG)
-						float32_be_write (floatdata, psf->header + psf->headindex) ;
+						float32_be_write (floatdata, psf->header.ptr + psf->header.indx) ;
 					else
-						float32_le_write (floatdata, psf->header + psf->headindex) ;
-					psf->headindex += 4 ;
+						float32_le_write (floatdata, psf->header.ptr + psf->header.indx) ;
+					psf->header.indx += 4 ;
 					count += 4 ;
 					break ;
 
 			case 'd' :
 					doubledata = va_arg (argptr, double) ;
 					if (psf->rwf_endian == SF_ENDIAN_BIG)
-						double64_be_write (doubledata, psf->header + psf->headindex) ;
+						double64_be_write (doubledata, psf->header.ptr + psf->header.indx) ;
 					else
-						double64_le_write (doubledata, psf->header + psf->headindex) ;
-					psf->headindex += 8 ;
+						double64_le_write (doubledata, psf->header.ptr + psf->header.indx) ;
+					psf->header.indx += 8 ;
 					count += 8 ;
 					break ;
 
@@ -680,13 +676,17 @@ psf_binheader_writef (SF_PRIVATE *psf, const char *format, ...)
 					strptr = va_arg (argptr, char *) ;
 					size = strlen (strptr) + 1 ;
 					size += (size & 1) ;
+
+					if (psf->header.indx + (sf_count_t) size >= psf->header.len && psf_bump_header_allocation (psf, 16))
+						return count ;
+
 					if (psf->rwf_endian == SF_ENDIAN_BIG)
 						header_put_be_int (psf, size) ;
 					else
 						header_put_le_int (psf, size) ;
-					memcpy (&(psf->header [psf->headindex]), strptr, size) ;
-					psf->headindex += size ;
-					psf->header [psf->headindex - 1] = 0 ;
+					memcpy (&(psf->header.ptr [psf->header.indx]), strptr, size) ;
+					psf->header.indx += size ;
+					psf->header.ptr [psf->header.indx - 1] = 0 ;
 					count += 4 + size ;
 					break ;
 
@@ -697,14 +697,16 @@ psf_binheader_writef (SF_PRIVATE *psf, const char *format, ...)
 					*/
 					strptr = va_arg (argptr, char *) ;
 					size = strlen (strptr) ;
+					if (psf->header.indx + (sf_count_t) size > psf->header.len && psf_bump_header_allocation (psf, size))
+						return count ;
 					if (psf->rwf_endian == SF_ENDIAN_BIG)
 						header_put_be_int (psf, size) ;
 					else
 						header_put_le_int (psf, size) ;
-					memcpy (&(psf->header [psf->headindex]), strptr, size + 1) ;
+					memcpy (&(psf->header.ptr [psf->header.indx]), strptr, size + 1) ;
 					size += (size & 1) ;
-					psf->headindex += size ;
-					psf->header [psf->headindex] = 0 ;
+					psf->header.indx += size ;
+					psf->header.ptr [psf->header.indx] = 0 ;
 					count += 4 + size ;
 					break ;
 
@@ -715,51 +717,66 @@ psf_binheader_writef (SF_PRIVATE *psf, const char *format, ...)
 					size = strlen (strptr) ;
 					size = (size & 1) ? size : size + 1 ;
 					size = (size > 254) ? 254 : size ;
+
+					if (psf->header.indx + (sf_count_t) size > psf->header.len && psf_bump_header_allocation (psf, size))
+						return count ;
+
 					header_put_byte (psf, size) ;
-					memcpy (&(psf->header [psf->headindex]), strptr, size) ;
-					psf->headindex += size ;
+					memcpy (&(psf->header.ptr [psf->header.indx]), strptr, size) ;
+					psf->header.indx += size ;
 					count += 1 + size ;
 					break ;
 
 			case 'b' :
 					bindata	= va_arg (argptr, void *) ;
 					size	= va_arg (argptr, size_t) ;
-					if (psf->headindex + size < sizeof (psf->header))
-					{	memcpy (&(psf->header [psf->headindex]), bindata, size) ;
-						psf->headindex += size ;
-						count += size ;
-						} ;
+
+					if (psf->header.indx + (sf_count_t) size > psf->header.len && psf_bump_header_allocation (psf, size))
+						return count ;
+
+					memcpy (&(psf->header.ptr [psf->header.indx]), bindata, size) ;
+					psf->header.indx += size ;
+					count += size ;
 					break ;
 
 			case 'z' :
 					size = va_arg (argptr, size_t) ;
+
+					if (psf->header.indx + (sf_count_t) size > psf->header.len && psf_bump_header_allocation (psf, size))
+						return count ;
+
 					count += size ;
 					while (size)
-					{	psf->header [psf->headindex] = 0 ;
-						psf->headindex ++ ;
+					{	psf->header.ptr [psf->header.indx] = 0 ;
+						psf->header.indx ++ ;
 						size -- ;
 						} ;
 					break ;
 
 			case 'h' :
 					bindata = va_arg (argptr, void *) ;
-					memcpy (&(psf->header [psf->headindex]), bindata, 16) ;
-					psf->headindex += 16 ;
+					memcpy (&(psf->header.ptr [psf->header.indx]), bindata, 16) ;
+					psf->header.indx += 16 ;
 					count += 16 ;
 					break ;
 
 			case 'j' :	/* Jump forwards/backwards by specified amount. */
 					size = va_arg (argptr, size_t) ;
-					psf->headindex += size ;
+
+					if (psf->header.indx + (sf_count_t) size > psf->header.len && psf_bump_header_allocation (psf, size))
+						return count ;
+
+					psf->header.indx += size ;
 					count += size ;
 					break ;
 
 			case 'o' :	/* Jump to specified offset. */
 					size = va_arg (argptr, size_t) ;
-					if (size < sizeof (psf->header))
-					{	psf->headindex = size ;
-						count = 0 ;
-						} ;
+
+					if ((sf_count_t) size >= psf->header.len && psf_bump_header_allocation (psf, size))
+						return count ;
+
+					psf->header.indx = size ;
 					break ;
 
 			default :
@@ -824,31 +841,20 @@ static int
 header_read (SF_PRIVATE *psf, void *ptr, int bytes)
 {	int count = 0 ;
 
-	if (psf->headindex >= SIGNED_SIZEOF (psf->header))
-		return psf_fread (ptr, 1, bytes, psf) ;
-
-	if (psf->headindex + bytes > SIGNED_SIZEOF (psf->header))
-	{	int most ;
+	if (psf->header.indx + bytes >= psf->header.len && psf_bump_header_allocation (psf, bytes))
+		return count ;
 
-		most = SIGNED_SIZEOF (psf->header) - psf->headend ;
-		psf_fread (psf->header + psf->headend, 1, most, psf) ;
-		memcpy (ptr, psf->header + psf->headend, most) ;
-		psf->headend = psf->headindex += most ;
-		psf_fread ((char *) ptr + most, bytes - most, 1, psf) ;
-		return bytes ;
-		} ;
-
-	if (psf->headindex + bytes > psf->headend)
-	{	count = psf_fread (psf->header + psf->headend, 1, bytes - (psf->headend - psf->headindex), psf) ;
-		if (count != bytes - (int) (psf->headend - psf->headindex))
+	if (psf->header.indx + bytes > psf->header.end)
+	{	count = psf_fread (psf->header.ptr + psf->header.end, 1, bytes - (psf->header.end - psf->header.indx), psf) ;
+		if (count != bytes - (int) (psf->header.end - psf->header.indx))
 		{	psf_log_printf (psf, "Error : psf_fread returned short count.\n") ;
 			return count ;
 			} ;
-		psf->headend += count ;
+		psf->header.end += count ;
 		} ;
 
-	memcpy (ptr, psf->header + psf->headindex, bytes) ;
-	psf->headindex += bytes ;
+	memcpy (ptr, psf->header.ptr + psf->header.indx, bytes) ;
+	psf->header.indx += bytes ;
 
 	return bytes ;
 } /* header_read */
@@ -858,39 +864,44 @@ header_seek (SF_PRIVATE *psf, sf_count_t position, int whence)
 {
 	switch (whence)
 	{	case SEEK_SET :
-			if (position > SIGNED_SIZEOF (psf->header))
+			if (psf->header.indx + position >= psf->header.len)
+				psf_bump_header_allocation (psf, position) ;
+			if (position > psf->header.len)
 			{	/* Too much header to cache so just seek instead. */
 				psf_fseek (psf, position, whence) ;
 				return ;
 				} ;
-			if (position > psf->headend)
-				psf->headend += psf_fread (psf->header + psf->headend, 1, position - psf->headend, psf) ;
-			psf->headindex = position ;
+			if (position > psf->header.end)
+				psf->header.end += psf_fread (psf->header.ptr + psf->header.end, 1, position - psf->header.end, psf) ;
+			psf->header.indx = position ;
 			break ;
 
 		case SEEK_CUR :
-			if (psf->headindex + position < 0)
+			if (psf->header.indx + position >= psf->header.len)
+				psf_bump_header_allocation (psf, position) ;
+
+			if (psf->header.indx + position < 0)
 				break ;
 
-			if (psf->headindex >= SIGNED_SIZEOF (psf->header))
+			if (psf->header.indx >= psf->header.len)
 			{	psf_fseek (psf, position, whence) ;
 				return ;
 				} ;
 
-			if (psf->headindex + position <= psf->headend)
-			{	psf->headindex += position ;
+			if (psf->header.indx + position <= psf->header.end)
+			{	psf->header.indx += position ;
 				break ;
 				} ;
 
-			if (psf->headindex + position > SIGNED_SIZEOF (psf->header))
+			if (psf->header.indx + position > psf->header.len)
 			{	/* Need to jump this without caching it. */
-				psf->headindex = psf->headend ;
+				psf->header.indx = psf->header.end ;
 				psf_fseek (psf, position, SEEK_CUR) ;
 				break ;
 				} ;
 
-			psf->headend += psf_fread (psf->header + psf->headend, 1, position - (psf->headend - psf->headindex), psf) ;
-			psf->headindex = psf->headend ;
+			psf->header.end += psf_fread (psf->header.ptr + psf->header.end, 1, position - (psf->header.end - psf->header.indx), psf) ;
+			psf->header.indx = psf->header.end ;
 			break ;
 
 		case SEEK_END :
@@ -906,15 +917,18 @@ static int
 header_gets (SF_PRIVATE *psf, char *ptr, int bufsize)
 {	int		k ;
 
+	if (psf->header.indx + bufsize >= psf->header.len && psf_bump_header_allocation (psf, bufsize))
+		return 0 ;
+
 	for (k = 0 ; k < bufsize - 1 ; k++)
-	{	if (psf->headindex < psf->headend)
-		{	ptr [k] = psf->header [psf->headindex] ;
-			psf->headindex ++ ;
+	{	if (psf->header.indx < psf->header.end)
+		{	ptr [k] = psf->header.ptr [psf->header.indx] ;
+			psf->header.indx ++ ;
 			}
 		else
-		{	psf->headend += psf_fread (psf->header + psf->headend, 1, 1, psf) ;
-			ptr [k] = psf->header [psf->headindex] ;
-			psf->headindex = psf->headend ;
+		{	psf->header.end += psf_fread (psf->header.ptr + psf->header.end, 1, 1, psf) ;
+			ptr [k] = psf->header.ptr [psf->header.indx] ;
+			psf->header.indx = psf->header.end ;
 			} ;
 
 		if (ptr [k] == '\n')
@@ -937,15 +951,19 @@ psf_binheader_readf (SF_PRIVATE *psf, char const *format, ...)
 	float			*floatptr ;
 	double			*doubleptr ;
 	char			c ;
-	int				byte_count = 0, count ;
+	int				byte_count = 0, count = 0 ;
 
 	if (! format)
 		return psf_ftell (psf) ;
 
 	va_start (argptr, format) ;
 
 	while ((c = *format++))
-	{	switch (c)
+	{
+		if (psf->header.indx + 16 >= psf->header.len && psf_bump_header_allocation (psf, 16))
+			return count ;
+
+		switch (c)
 		{	case 'e' : /* All conversions are now from LE to host. */
 					psf->rwf_endian = SF_ENDIAN_LITTLE ;
 					break ;
@@ -956,13 +974,15 @@ psf_binheader_readf (SF_PRIVATE *psf, char const *format, ...)
 
 			case 'm' : /* 4 byte marker value eg 'RIFF' */
 					intptr = va_arg (argptr, unsigned int*) ;
+					*intptr = 0 ;
 					ucptr = (unsigned char*) intptr ;
 					byte_count += header_read (psf, ucptr, sizeof (int)) ;
 					*intptr = GET_MARKER (ucptr) ;
 					break ;
 
 			case 'h' :
 					intptr = va_arg (argptr, unsigned int*) ;
+					*intptr = 0 ;
 					ucptr = (unsigned char*) intptr ;
 					byte_count += header_read (psf, sixteen_bytes, sizeof (sixteen_bytes)) ;
 					{	int k ;
@@ -1050,51 +1070,51 @@ psf_binheader_readf (SF_PRIVATE *psf, char const *format, ...)
 					size  += (size & 1) ;
 					longdata = H2LE_32 (size) ;
 					get_int (psf, longdata) ;
-					memcpy (&(psf->header [psf->headindex]), strptr, size) ;
-					psf->headindex += size ;
+					memcpy (&(psf->header.ptr [psf->header.indx]), strptr, size) ;
+					psf->header.indx += size ;
 					*/
 					break ;
 
 			case 'b' : /* Raw bytes */
 					charptr = va_arg (argptr, char*) ;
 					count = va_arg (argptr, size_t) ;
-					if (count > 0)
-						byte_count += header_read (psf, charptr, count) ;
+					memset (charptr, 0, count) ;
+					byte_count += header_read (psf, charptr, count) ;
 					break ;
 
 			case 'G' :
 					charptr = va_arg (argptr, char*) ;
 					count = va_arg (argptr, size_t) ;
-					if (count > 0)
-						byte_count += header_gets (psf, charptr, count) ;
+					memset (charptr, 0, count) ;
+
+					if (psf->header.indx + count >= psf->header.len && psf_bump_header_allocation (psf, count))
+						return 0 ;
+
+					byte_count += header_gets (psf, charptr, count) ;
 					break ;
 
 			case 'z' :
 					psf_log_printf (psf, "Format conversion 'z' not implemented yet.\n") ;
 					/*
 					size    = va_arg (argptr, size_t) ;
 					while (size)
-					{	psf->header [psf->headindex] = 0 ;
-						psf->headindex ++ ;
+					{	psf->header.ptr [psf->header.indx] = 0 ;
+						psf->header.indx ++ ;
 						size -- ;
 						} ;
 					*/
 					break ;
 
-			case 'p' :
-					/* Get the seek position first. */
+			case 'p' :	/* Seek to position from start. */
 					count = va_arg (argptr, size_t) ;
 					header_seek (psf, count, SEEK_SET) ;
 					byte_count = count ;
 					break ;
 
-			case 'j' :
-					/* Get the seek position first. */
+			case 'j' :	/* Seek to position from current position. */
 					count = va_arg (argptr, size_t) ;
-					if (count)
-					{	header_seek (psf, count, SEEK_CUR) ;
-						byte_count += count ;
-						} ;
+					header_seek (psf, count, SEEK_CUR) ;
+					byte_count += count ;
 					break ;
 
 			default :
```


### `src/common.h`

```diff
@@ -79,7 +79,6 @@
 #define	SF_FILENAME_LEN			(1024)
 #define SF_SYSERR_LEN			(256)
 #define SF_MAX_STRINGS			(32)
-#define	SF_HEADER_LEN			(12292)
 #define	SF_PARSELOG_LEN			(2048)
 
 #define	PSF_SEEK_ERROR			((sf_count_t) -1)
@@ -382,7 +381,12 @@ typedef struct sf_private_tag
 		int				indx ;
 	} parselog ;
 
-	unsigned char	header		[SF_HEADER_LEN] ; /* Must be unsigned */
+
+	struct
+	{	unsigned char	* ptr ;
+		sf_count_t		indx, end, len ;
+	} header ;
+
 	int				rwf_endian ;	/* Header endian-ness flag. */
 
 	/* Storage and housekeeping data for adding/reading strings from
@@ -401,10 +405,6 @@ typedef struct sf_private_tag
 
 	unsigned		unique_id ;
 
-	/* Index variables for maintaining parselog and header above. */
-	int				headindex, headend ;
-	int				has_text ;
-
 	int				error ;
 
 	int				endian ;		/* File endianness : SF_ENDIAN_LITTLE or SF_ENDIAN_BIG. */
@@ -736,6 +736,9 @@ enum
 	SFE_MAX_ERROR			/* This must be last in list. */
 } ;
 
+/* Allocate and initialize the SF_PRIVATE struct. */
+SF_PRIVATE * psf_allocate (void) ;
+
 int subformat_to_bytewidth (int format) ;
 int s_bitwidth_to_subformat (int bits) ;
 int u_bitwidth_to_subformat (int bits) ;
```


### `src/sndfile.c`

```diff
@@ -267,7 +267,7 @@ ErrorStruct SndfileErrors [] =
 	{	SFE_BAD_CHUNK_MARKER	, "Error : Bad chunk marker." },
 	{	SFE_BAD_CHUNK_DATA_PTR	, "Error : Bad data pointer in SF_CHUNK_INFO struct." },
 	{	SFE_FILENAME_TOO_LONG	, "Error : Supplied filename too long." },
-
+	{	SFE_BAD_HEADER_ALLOC 	, "Error : Required header allocation is too large." },
 
 	{	SFE_MAX_ERROR			, "Maximum error number." },
 	{	SFE_MAX_ERROR + 1		, NULL }
@@ -326,7 +326,7 @@ sf_open	(const char *path, int mode, SF_INFO *sfinfo)
 	/* Ultimate sanity check. */
 	assert (sizeof (sf_count_t) == 8) ;
 
-	if ((psf = calloc (1, sizeof (SF_PRIVATE))) == NULL)
+	if ((psf = psf_allocate ()) == NULL)
 	{	sf_errno = SFE_MALLOC_FAILED ;
 		return	NULL ;
 		} ;
@@ -358,7 +358,7 @@ sf_open_fd	(int fd, int mode, SF_INFO *sfinfo, int close_desc)
 		return	NULL ;
 		} ;
 
-	if ((psf = calloc (1, sizeof (SF_PRIVATE))) == NULL)
+	if ((psf = psf_allocate ()) == NULL)
 	{	sf_errno = SFE_MALLOC_FAILED ;
 		return	NULL ;
 		} ;
@@ -400,7 +400,7 @@ sf_open_virtual	(SF_VIRTUAL_IO *sfvirtual, int mode, SF_INFO *sfinfo, void *user
 		return NULL ;
 		} ;
 
-	if ((psf = calloc (1, sizeof (SF_PRIVATE))) == NULL)
+	if ((psf = psf_allocate ()) == NULL)
 	{	sf_errno = SFE_MALLOC_FAILED ;
 		return	NULL ;
 		} ;
@@ -2688,6 +2688,7 @@ psf_close (SF_PRIVATE *psf)
 	psf_close_rsrc (psf) ;
 
 	/* For an ISO C compliant implementation it is ok to free a NULL pointer. */
+	free (psf->header.ptr) ;
 	free (psf->container_data) ;
 	free (psf->codec_data) ;
 	free (psf->interleave) ;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
