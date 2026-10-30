# Pacote de anotacao — caso 11

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

# Evidencia do caso 11

## Identificacao

- projeto: libtiff
- CVE: CVE-2016-9535
- CWE atribuida pelo BigVul: CWE-119
- commit: `3ca657a8793dd011bf869695d72ad31c779c3cc1`
- URL do commit: https://github.com/vadz/libtiff/commit/3ca657a8793dd011bf869695d72ad31c779c3cc1
- arquivo da funcao marcada: `libtiff/tif_predict.c`

## Mensagem do commit

> * libtiff/tif_predict.h, libtiff/tif_predict.c:
> Replace assertions by runtime checks to avoid assertions in debug mode,
> or buffer overflows in release mode. Can happen when dealing with
> unusual tile size like YCbCr with subsampling. Reported as MSVR 35105
> by Axel Souchet	& Vishal Chauhan from the MSRC Vulnerabilities & Mitigations
> team.

## Resumo da CVE

> tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions that can lead to assertion failures in debug mode, or buffer overflows in release mode, when dealing with unusual tile size like YCbCr with subsampling. Reported as MSVR 35105, aka *Predictor heap-buffer-overflow.*

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -7,6 +7,7 @@
  	assert(sp->encoderow != NULL);
  
  	/* XXX horizontal differencing alters user's data XXX */
-	(*sp->encodepfunc)(tif, bp, cc);
+	if( !(*sp->encodepfunc)(tif, bp, cc) )
+        return 0;
  	return (*sp->encoderow)(tif, bp, cc, s);
  }
```

## Corpo completo da funcao antes da correcao

```c
PredictorEncodeRow(TIFF* tif, uint8* bp, tmsize_t cc, uint16 s)
{
	TIFFPredictorState *sp = PredictorState(tif);

	assert(sp != NULL);
	assert(sp->encodepfunc != NULL);
 	assert(sp->encoderow != NULL);
 
 	/* XXX horizontal differencing alters user's data XXX */
	(*sp->encodepfunc)(tif, bp, cc);
 	return (*sp->encoderow)(tif, bp, cc, s);
 }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `ChangeLog` | modified | 9 | 0 |
| `libtiff/tif_predict.c` **(funcao marcada esta aqui)** | modified | 108 | 45 |
| `libtiff/tif_predict.h` | modified | 4 | 2 |


### `libtiff/tif_predict.c`

```diff
@@ -34,18 +34,18 @@
 
 #define	PredictorState(tif)	((TIFFPredictorState*) (tif)->tif_data)
 
-static void horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc);
-static void fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc);
+static int fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc);
 static int PredictorDecodeRow(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s);
 static int PredictorDecodeTile(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s);
 static int PredictorEncodeRow(TIFF* tif, uint8* bp, tmsize_t cc, uint16 s);
@@ -273,13 +273,19 @@ PredictorSetupEncode(TIFF* tif)
 /* - when storing into the byte stream, we explicitly mask with 0xff so */
 /*   as to make icc -check=conversions happy (not necessary by the standard) */
 
-static void
+static int
 horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
 
 	unsigned char* cp = (unsigned char*) cp0;
-	assert((cc%stride)==0);
+    if((cc%stride)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horAcc8",
+                     "%s", "(cc%stride)!=0");
+        return 0;
+    }
+
 	if (cc > stride) {
 		/*
 		 * Pipeline the most common cases.
@@ -321,26 +327,32 @@ horAcc8(TIFF* tif, uint8* cp0, tmsize_t cc)
 			} while (cc>0);
 		}
 	}
+	return 1;
 }
 
-static void
+static int
 swabHorAcc16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	uint16* wp = (uint16*) cp0;
 	tmsize_t wc = cc / 2;
 
         TIFFSwabArrayOfShort(wp, wc);
-        horAcc16(tif, cp0, cc);
+        return horAcc16(tif, cp0, cc);
 }
 
-static void
+static int
 horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
 	uint16* wp = (uint16*) cp0;
 	tmsize_t wc = cc / 2;
 
-	assert((cc%(2*stride))==0);
+    if((cc%(2*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horAcc16",
+                     "%s", "cc%(2*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -349,26 +361,32 @@ horAcc16(TIFF* tif, uint8* cp0, tmsize_t cc)
 			wc -= stride;
 		} while (wc > 0);
 	}
+	return 1;
 }
 
-static void
+static int
 swabHorAcc32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	uint32* wp = (uint32*) cp0;
 	tmsize_t wc = cc / 4;
 
         TIFFSwabArrayOfLong(wp, wc);
-	horAcc32(tif, cp0, cc);
+	return horAcc32(tif, cp0, cc);
 }
 
-static void
+static int
 horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
 	uint32* wp = (uint32*) cp0;
 	tmsize_t wc = cc / 4;
 
-	assert((cc%(4*stride))==0);
+    if((cc%(4*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horAcc32",
+                     "%s", "cc%(4*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -377,12 +395,13 @@ horAcc32(TIFF* tif, uint8* cp0, tmsize_t cc)
 			wc -= stride;
 		} while (wc > 0);
 	}
+	return 1;
 }
 
 /*
  * Floating point predictor accumulation routine.
  */
-static void
+static int
 fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
@@ -392,10 +411,15 @@ fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc)
 	uint8 *cp = (uint8 *) cp0;
 	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);
 
-	assert((cc%(bps*stride))==0);
+    if(cc%(bps*stride)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "fpAcc",
+                     "%s", "cc%(bps*stride))!=0");
+        return 0;
+    }
 
 	if (!tmp)
-		return;
+		return 0;
 
 	while (count > stride) {
 		REPEAT4(stride, cp[stride] =
@@ -417,6 +441,7 @@ fpAcc(TIFF* tif, uint8* cp0, tmsize_t cc)
 		}
 	}
 	_TIFFfree(tmp);
+    return 1;
 }
 
 /*
@@ -432,8 +457,7 @@ PredictorDecodeRow(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s)
 	assert(sp->decodepfunc != NULL);  
 
 	if ((*sp->decoderow)(tif, op0, occ0, s)) {
-		(*sp->decodepfunc)(tif, op0, occ0);
-		return 1;
+		return (*sp->decodepfunc)(tif, op0, occ0);
 	} else
 		return 0;
 }
@@ -456,10 +480,16 @@ PredictorDecodeTile(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s)
 	if ((*sp->decodetile)(tif, op0, occ0, s)) {
 		tmsize_t rowsize = sp->rowsize;
 		assert(rowsize > 0);
-		assert((occ0%rowsize)==0);
+		if((occ0%rowsize) !=0)
+        {
+            TIFFErrorExt(tif->tif_clientdata, "PredictorDecodeTile",
+                         "%s", "occ0%rowsize != 0");
+            return 0;
+        }
 		assert(sp->decodepfunc != NULL);
 		while (occ0 > 0) {
-			(*sp->decodepfunc)(tif, op0, rowsize);
+			if( !(*sp->decodepfunc)(tif, op0, rowsize) )
+                return 0;
 			occ0 -= rowsize;
 			op0 += rowsize;
 		}
@@ -468,14 +498,19 @@ PredictorDecodeTile(TIFF* tif, uint8* op0, tmsize_t occ0, uint16 s)
 		return 0;
 }
 
-static void
+static int
 horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	TIFFPredictorState* sp = PredictorState(tif);
 	tmsize_t stride = sp->stride;
 	unsigned char* cp = (unsigned char*) cp0;
 
-	assert((cc%stride)==0);
+    if((cc%stride)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horDiff8",
+                     "%s", "(cc%stride)!=0");
+        return 0;
+    }
 
 	if (cc > stride) {
 		cc -= stride;
@@ -513,17 +548,23 @@ horDiff8(TIFF* tif, uint8* cp0, tmsize_t cc)
 			} while ((cc -= stride) > 0);
 		}
 	}
+	return 1;
 }
 
-static void
+static int
 horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	TIFFPredictorState* sp = PredictorState(tif);
 	tmsize_t stride = sp->stride;
 	uint16 *wp = (uint16*) cp0;
 	tmsize_t wc = cc/2;
 
-	assert((cc%(2*stride))==0);
+    if((cc%(2*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horDiff8",
+                     "%s", "(cc%(2*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -533,28 +574,36 @@ horDiff16(TIFF* tif, uint8* cp0, tmsize_t cc)
 			wc -= stride;
 		} while (wc > 0);
 	}
+	return 1;
 }
 
-static void
+static int
 swabHorDiff16(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
     uint16* wp = (uint16*) cp0;
     tmsize_t wc = cc / 2;
 
-    horDiff16(tif, cp0, cc);
+    if( !horDiff16(tif, cp0, cc) )
+        return 0;
 
     TIFFSwabArrayOfShort(wp, wc);
+    return 1;
 }
 
-static void
+static int
 horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	TIFFPredictorState* sp = PredictorState(tif);
 	tmsize_t stride = sp->stride;
 	uint32 *wp = (uint32*) cp0;
 	tmsize_t wc = cc/4;
 
-	assert((cc%(4*stride))==0);
+    if((cc%(4*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "horDiff32",
+                     "%s", "(cc%(4*stride))!=0");
+        return 0;
+    }
 
 	if (wc > stride) {
 		wc -= stride;
@@ -564,23 +613,26 @@ horDiff32(TIFF* tif, uint8* cp0, tmsize_t cc)
 			wc -= stride;
 		} while (wc > 0);
 	}
+	return 1;
 }
 
-static void
+static int
 swabHorDiff32(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
     uint32* wp = (uint32*) cp0;
     tmsize_t wc = cc / 4;
 
-    horDiff32(tif, cp0, cc);
+    if( !horDiff32(tif, cp0, cc) )
+        return 0;
 
     TIFFSwabArrayOfLong(wp, wc);
+    return 1;
 }
 
 /*
  * Floating point predictor differencing routine.
  */
-static void
+static int
 fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc)
 {
 	tmsize_t stride = PredictorState(tif)->stride;
@@ -590,10 +642,14 @@ fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc)
 	uint8 *cp = (uint8 *) cp0;
 	uint8 *tmp = (uint8 *)_TIFFmalloc(cc);
 
-	assert((cc%(bps*stride))==0);
-
+    if((cc%(bps*stride))!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "fpDiff",
+                     "%s", "(cc%(bps*stride))!=0");
+        return 0;
+    }
 	if (!tmp)
-		return;
+		return 0;
 
 	_TIFFmemcpy(tmp, cp0, cc);
 	for (count = 0; count < wc; count++) {
@@ -613,6 +669,7 @@ fpDiff(TIFF* tif, uint8* cp0, tmsize_t cc)
 	cp += cc - stride - 1;
 	for (count = cc; count > stride; count -= stride)
 		REPEAT4(stride, cp[stride] = (unsigned char)((cp[stride] - cp[0])&0xff); cp--)
+    return 1;
 }
 
 static int
@@ -625,7 +682,8 @@ PredictorEncodeRow(TIFF* tif, uint8* bp, tmsize_t cc, uint16 s)
 	assert(sp->encoderow != NULL);
 
 	/* XXX horizontal differencing alters user's data XXX */
-	(*sp->encodepfunc)(tif, bp, cc);
+	if( !(*sp->encodepfunc)(tif, bp, cc) )
+        return 0;
 	return (*sp->encoderow)(tif, bp, cc, s);
 }
 
@@ -660,7 +718,12 @@ PredictorEncodeTile(TIFF* tif, uint8* bp0, tmsize_t cc0, uint16 s)
 
 	rowsize = sp->rowsize;
 	assert(rowsize > 0);
-	assert((cc0%rowsize)==0);
+	if((cc0%rowsize)!=0)
+    {
+        TIFFErrorExt(tif->tif_clientdata, "PredictorEncodeTile",
+                     "%s", "(cc0%rowsize)!=0");
+        return 0;
+    }
 	while (cc > 0) {
 		(*sp->encodepfunc)(tif, bp, rowsize);
 		cc -= rowsize;
```


### `ChangeLog`

```diff
@@ -1,3 +1,12 @@
+2016-10-31 Even Rouault <even.rouault at spatialys.com>
+
+	* libtiff/tif_predict.h, libtiff/tif_predict.c:
+	Replace assertions by runtime checks to avoid assertions in debug mode,
+	or buffer overflows in release mode. Can happen when dealing with
+	unusual tile size like YCbCr with subsampling. Reported as MSVR 35105
+	by Axel Souchet	& Vishal Chauhan from the MSRC Vulnerabilities & Mitigations
+	team.
+
 2016-10-26 Even Rouault <even.rouault at spatialys.com>
 
 	* tools/fax2tiff.c: fix segfault when specifying -r without
```


### `libtiff/tif_predict.h`

```diff
@@ -30,6 +30,8 @@
  * ``Library-private'' Support for the Predictor Tag
  */
 
+typedef int (*TIFFEncodeDecodeMethod)(TIFF* tif, uint8* buf, tmsize_t size);
+
 /*
  * Codecs that want to support the Predictor tag must place
  * this structure first in their private state block so that
@@ -43,12 +45,12 @@ typedef struct {
 	TIFFCodeMethod  encoderow;	/* parent codec encode/decode row */
 	TIFFCodeMethod  encodestrip;	/* parent codec encode/decode strip */
 	TIFFCodeMethod  encodetile;	/* parent codec encode/decode tile */ 
-	TIFFPostMethod  encodepfunc;	/* horizontal differencer */
+	TIFFEncodeDecodeMethod  encodepfunc;	/* horizontal differencer */
 
 	TIFFCodeMethod  decoderow;	/* parent codec encode/decode row */
 	TIFFCodeMethod  decodestrip;	/* parent codec encode/decode strip */
 	TIFFCodeMethod  decodetile;	/* parent codec encode/decode tile */ 
-	TIFFPostMethod  decodepfunc;	/* horizontal accumulator */
+	TIFFEncodeDecodeMethod  decodepfunc;	/* horizontal accumulator */
 
 	TIFFVGetMethod  vgetparent;	/* super-class method */
 	TIFFVSetMethod  vsetparent;	/* super-class method */
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
