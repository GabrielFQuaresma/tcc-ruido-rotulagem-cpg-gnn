# Pacote de anotacao — caso 39

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

# Evidencia do caso 39

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `third_party/libpng/pngrutil.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -73,12 +73,15 @@
  
              png_snprintf(umsg, sizeof umsg, msg, png_ptr->chunk_name);
              msg = umsg;
+            png_warning(png_ptr, msg);
  #else
              msg = "Damaged compressed datastream in chunk other than IDAT";
  #endif
           }
  
+#ifndef PNG_STDIO_SUPPORTED
           png_warning(png_ptr, msg);
+#endif
        }
  
        /* 0 means an error - notice that this code simple ignores
```

## Corpo completo da funcao antes da correcao

```c
png_inflate(png_structp png_ptr, const png_byte *data, png_size_t size,
        png_bytep output, png_size_t output_size)
{
   png_size_t count = 0;

   png_ptr->zstream.next_in = (png_bytep)data; /* const_cast: VALID */
   png_ptr->zstream.avail_in = size;

   while (1)
   {
      int ret, avail;

      /* Reset the output buffer each time round - we empty it
       * after every inflate call.
       */
      png_ptr->zstream.next_out = png_ptr->zbuf;
      png_ptr->zstream.avail_out = png_ptr->zbuf_size;

      ret = inflate(&png_ptr->zstream, Z_NO_FLUSH);
      avail = png_ptr->zbuf_size - png_ptr->zstream.avail_out;

      /* First copy/count any new output - but only if we didn't
       * get an error code.
       */
      if ((ret == Z_OK || ret == Z_STREAM_END) && avail > 0)
      {
         if (output != 0 && output_size > count)
         {
            png_size_t copy = output_size - count;
            if ((png_size_t) avail < copy) copy = (png_size_t) avail;
            png_memcpy(output + count, png_ptr->zbuf, copy);
         }
         count += avail;
      }

      if (ret == Z_OK)
         continue;

      /* Termination conditions - always reset the zstream, it
       * must be left in inflateInit state.
       */
      png_ptr->zstream.avail_in = 0;
      inflateReset(&png_ptr->zstream);

      if (ret == Z_STREAM_END)
         return count; /* NOTE: may be zero. */

      /* Now handle the error codes - the API always returns 0
       * and the error message is dumped into the uncompressed
       * buffer if available.
       */
      {
         PNG_CONST char *msg;
         if (png_ptr->zstream.msg != 0)
            msg = png_ptr->zstream.msg;
         else
         {
#if defined(PNG_STDIO_SUPPORTED) && !defined(_WIN32_WCE)
            char umsg[52];

            switch (ret)
            {
               case Z_BUF_ERROR:
                  msg = "Buffer error in compressed datastream in %s chunk";
                  break;
               case Z_DATA_ERROR:
                  msg = "Data error in compressed datastream in %s chunk";
                  break;
               default:
                  msg = "Incomplete compressed datastream in %s chunk";
                  break;
            }
 
             png_snprintf(umsg, sizeof umsg, msg, png_ptr->chunk_name);
             msg = umsg;
 #else
             msg = "Damaged compressed datastream in chunk other than IDAT";
 #endif
          }
 
          png_warning(png_ptr, msg);
       }
 
       /* 0 means an error - notice that this code simple ignores
       * zero length compressed chunks as a result.
       */
      return 0;
   }
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **14**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `third_party/libpng/LICENSE` | modified | 26 | 27 |
| `third_party/libpng/README` | modified | 8 | 8 |
| `third_party/libpng/README.chromium` | modified | 2 | 2 |
| `third_party/libpng/png.c` | modified | 19 | 12 |
| `third_party/libpng/png.h` | modified | 113 | 380 |
| `third_party/libpng/pngconf.h` | modified | 6 | 6 |
| `third_party/libpng/pngget.c` | modified | 8 | 5 |
| `third_party/libpng/pngpread.c` | modified | 6 | 3 |
| `third_party/libpng/pngread.c` | modified | 5 | 3 |
| `third_party/libpng/pngrtran.c` | modified | 24 | 12 |
| `third_party/libpng/pngrutil.c` **(funcao marcada esta aqui)** | modified | 46 | 23 |
| `third_party/libpng/pngset.c` | modified | 24 | 7 |
| `third_party/libpng/pngwrite.c` | modified | 11 | 134 |
| `third_party/libpng/pngwutil.c` | modified | 14 | 319 |


### `third_party/libpng/pngrutil.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngrutil.c - utilities to read a PNG file
  *
- * Last changed in libpng 1.2.51 [February 6, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.54 [November 12, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -57,24 +57,24 @@ png_get_uint_31(png_structp png_ptr, png_bytep buf)
    png_uint_32 i = png_get_uint_32(buf);
 #else
    /* Avoid an extra function call by inlining the result. */
-   png_uint_32 i = ((png_uint_32)(*buf) << 24) +
-      ((png_uint_32)(*(buf + 1)) << 16) +
-      ((png_uint_32)(*(buf + 2)) << 8) +
-      (png_uint_32)(*(buf + 3));
+   png_uint_32 i = ((png_uint_32)((*(buf    )) & 0xff) << 24) +
+                   ((png_uint_32)((*(buf + 1)) & 0xff) << 16) +
+                   ((png_uint_32)((*(buf + 2)) & 0xff) <<  8) +
+                   ((png_uint_32)((*(buf + 3)) & 0xff)      );
 #endif
    if (i > PNG_UINT_31_MAX)
-     png_error(png_ptr, "PNG unsigned integer out of range.");
+      png_error(png_ptr, "PNG unsigned integer out of range.");
    return (i);
 }
 #ifndef PNG_READ_BIG_ENDIAN_SUPPORTED
 /* Grab an unsigned 32-bit integer from a buffer in big-endian format. */
 png_uint_32 PNGAPI
 png_get_uint_32(png_bytep buf)
 {
-   png_uint_32 i = ((png_uint_32)(*buf) << 24) +
-      ((png_uint_32)(*(buf + 1)) << 16) +
-      ((png_uint_32)(*(buf + 2)) << 8) +
-      (png_uint_32)(*(buf + 3));
+   png_uint_32 i = ((png_uint_32)((*(buf    )) & 0xff) << 24) +
+                   ((png_uint_32)((*(buf + 1)) & 0xff) << 16) +
+                   ((png_uint_32)((*(buf + 2)) & 0xff) <<  8) +
+                   ((png_uint_32)((*(buf + 3)) & 0xff)      );
 
    return (i);
 }
@@ -86,10 +86,10 @@ png_get_uint_32(png_bytep buf)
 png_int_32 PNGAPI
 png_get_int_32(png_bytep buf)
 {
-   png_int_32 i = ((png_int_32)(*buf) << 24) +
-      ((png_int_32)(*(buf + 1)) << 16) +
-      ((png_int_32)(*(buf + 2)) << 8) +
-      (png_int_32)(*(buf + 3));
+   png_int_32 i = ((png_int_32)((*(buf    )) & 0xff) << 24) +
+                  ((png_int_32)((*(buf + 1)) & 0xff) << 16) +
+                  ((png_int_32)((*(buf + 2)) & 0xff) <<  8) +
+                  ((png_int_32)((*(buf + 3)) & 0xff)      );
 
    return (i);
 }
@@ -98,8 +98,8 @@ png_get_int_32(png_bytep buf)
 png_uint_16 PNGAPI
 png_get_uint_16(png_bytep buf)
 {
-   png_uint_16 i = (png_uint_16)(((png_uint_16)(*buf) << 8) +
-      (png_uint_16)(*(buf + 1)));
+   png_uint_16 i = ((png_uint_16)((*(buf     )) & 0xff) << 8) +
+                   ((png_uint_16)((*(buf +  1)) & 0xff)     );
 
    return (i);
 }
@@ -294,12 +294,15 @@ png_inflate(png_structp png_ptr, const png_byte *data, png_size_t size,
 
             png_snprintf(umsg, sizeof umsg, msg, png_ptr->chunk_name);
             msg = umsg;
+            png_warning(png_ptr, msg);
 #else
             msg = "Damaged compressed datastream in chunk other than IDAT";
 #endif
          }
 
+#ifndef PNG_STDIO_SUPPORTED
          png_warning(png_ptr, msg);
+#endif
       }
 
       /* 0 means an error - notice that this code simple ignores
@@ -503,7 +506,7 @@ void /* PRIVATE */
 png_handle_PLTE(png_structp png_ptr, png_infop info_ptr, png_uint_32 length)
 {
    png_color palette[PNG_MAX_PALETTE_LENGTH];
-   int num, i;
+   int max_palette_length, num, i;
 #ifdef PNG_POINTER_INDEXING_SUPPORTED
    png_colorp pal_ptr;
 #endif
@@ -555,8 +558,22 @@ png_handle_PLTE(png_structp png_ptr, png_infop info_ptr, png_uint_32 length)
       }
    }
 
+   /* The cast is safe because 'length' is less than 3*PNG_MAX_PALETTE_LENGTH */
    num = (int)length / 3;
 
+   /* If the palette has 256 or fewer entries but is too large for the bit
+    * depth, we don't issue an error, to preserve the behavior of previous
+    * libpng versions. We silently truncate the unused extra palette entries
+    * here.
+    */
+   if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
+      max_palette_length = (1 << png_ptr->bit_depth);
+   else
+      max_palette_length = PNG_MAX_PALETTE_LENGTH;
+
+   if (num > max_palette_length)
+      num = max_palette_length;
+
 #ifdef PNG_POINTER_INDEXING_SUPPORTED
    for (i = 0, pal_ptr = palette; i < num; i++, pal_ptr++)
    {
@@ -589,7 +606,7 @@ png_handle_PLTE(png_structp png_ptr, png_infop info_ptr, png_uint_32 length)
    if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
 #endif
    {
-      png_crc_finish(png_ptr, 0);
+      png_crc_finish(png_ptr, (int) length - num * 3);
    }
 #ifndef PNG_READ_OPT_PLTE_SUPPORTED
    else if (png_crc_error(png_ptr))  /* Only if we have a CRC error */
@@ -1130,10 +1147,10 @@ png_handle_iCCP(png_structp png_ptr, png_infop info_ptr, png_uint_32 length)
 
    /* Check the profile_size recorded in the first 32 bits of the ICC profile */
    pC = (png_bytep)(png_ptr->chunkdata + prefix_length);
-   profile_size = ((*(pC    ))<<24) |
-                  ((*(pC + 1))<<16) |
-                  ((*(pC + 2))<< 8) |
-                  ((*(pC + 3))    );
+   profile_size = ((png_uint_32) (*(pC    )<<24)) |
+                  ((png_uint_32) (*(pC + 1)<<16)) |
+                  ((png_uint_32) (*(pC + 2)<< 8)) |
+                  ((png_uint_32) (*(pC + 3)    ));
 
    if (profile_size < profile_length)
       profile_length = profile_size;
@@ -2714,7 +2731,9 @@ png_do_read_interlace(png_structp png_ptr)
    png_uint_32 transformations = png_ptr->transformations;
    /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
    /* Offset to next interlace block */
+#ifndef PNG_USE_GLOBAL_ARRAYS
    PNG_CONST int png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
+#endif
 
    png_debug(1, "in png_do_read_interlace");
    if (row != NULL && row_info != NULL)
@@ -3054,6 +3073,7 @@ void /* PRIVATE */
 png_read_finish_row(png_structp png_ptr)
 {
 #ifdef PNG_READ_INTERLACING_SUPPORTED
+#ifndef PNG_USE_GLOBAL_ARRAYS
    /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
 
    /* Start of interlace block */
@@ -3067,6 +3087,7 @@ png_read_finish_row(png_structp png_ptr)
 
    /* Offset to next interlace block in the y direction */
    PNG_CONST int png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+#endif
 #endif /* PNG_READ_INTERLACING_SUPPORTED */
 
    png_debug(1, "in png_read_finish_row");
@@ -3182,6 +3203,7 @@ void /* PRIVATE */
 png_read_start_row(png_structp png_ptr)
 {
 #ifdef PNG_READ_INTERLACING_SUPPORTED
+#ifndef PNG_USE_GLOBAL_ARRAYS
    /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
 
    /* Start of interlace block */
@@ -3195,6 +3217,7 @@ png_read_start_row(png_structp png_ptr)
 
    /* Offset to next interlace block in the y direction */
    PNG_CONST int png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+#endif
 #endif
 
    int max_pixel_depth;
```


### `third_party/libpng/LICENSE`

```diff
@@ -12,20 +12,15 @@ pngusr.h is distributed under the MPL 1.1/GPL 2.0/LGPL 2.1 tri-license.
 
 This code is released under the libpng license.
 
-libpng versions 1.2.6, August 15, 2004, through 1.2.52, November 20, 2014, are
-Copyright (c) 2004, 2006-2014 Glenn Randers-Pehrson, and are
-distributed according to the same disclaimer and license as libpng-1.2.5
-with the following individual added to the list of Contributing Authors
-
-   Cosmin Truta
-
-libpng versions 1.0.7, July 1, 2000, through 1.2.5 - October 3, 2002, are
-Copyright (c) 2000-2002 Glenn Randers-Pehrson, and are
-distributed according to the same disclaimer and license as libpng-1.0.6
-with the following individuals added to the list of Contributing Authors
+libpng versions 1.0.7, July 1, 2000, through 1.2.54, November 12, 2015, are
+Copyright (c) 2000-2002, 2004, 2006-2015 Glenn Randers-Pehrson, are
+derived from libpng-1.0.6, and are distributed according to the same
+disclaimer and license as libpng-1.0.6 with the following individuals
+added to the list of Contributing Authors:
 
    Simon-Pierre Cadieux
    Eric S. Raymond
+   Cosmin Truta
    Gilles Vollant
 
 and with the following additions to the disclaimer:
@@ -38,18 +33,20 @@ and with the following additions to the disclaimer:
    the user.
 
 libpng versions 0.97, January 1998, through 1.0.6, March 20, 2000, are
-Copyright (c) 1998, 1999 Glenn Randers-Pehrson, and are
-distributed according to the same disclaimer and license as libpng-0.96,
-with the following individuals added to the list of Contributing Authors:
+Copyright (c) 1998-2000 Glenn Randers-Pehrson, are derived from
+libpng-0.96, and are distributed according to the same disclaimer and
+license as libpng-0.96, with the following individuals added to the list
+of Contributing Authors:
 
    Tom Lane
    Glenn Randers-Pehrson
    Willem van Schaik
 
 libpng versions 0.89, June 1996, through 0.96, May 1997, are
-Copyright (c) 1996, 1997 Andreas Dilger
-Distributed according to the same disclaimer and license as libpng-0.88,
-with the following individuals added to the list of Contributing Authors:
+Copyright (c) 1996-1997 Andreas Dilger, are derived from libpng-0.88,
+and are distributed according to the same disclaimer and license as
+libpng-0.88, with the following individuals added to the list of
+Contributing Authors:
 
    John Bowler
    Kevin Bracey
@@ -59,7 +56,7 @@ with the following individuals added to the list of Contributing Authors:
    Tom Tanner
 
 libpng versions 0.5, May 1995, through 0.88, January 1996, are
-Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.
+Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
 
 For the purposes of this copyright and license, "Contributing Authors"
 is defined as the following set of individuals:
@@ -82,32 +79,34 @@ Permission is hereby granted to use, copy, modify, and distribute this
 source code, or portions hereof, for any purpose, without fee, subject
 to the following restrictions:
 
-1. The origin of this source code must not be misrepresented.
+  1. The origin of this source code must not be misrepresented.
 
-2. Altered versions must be plainly marked as such and must not
-   be misrepresented as being the original source.
+  2. Altered versions must be plainly marked as such and must not
+     be misrepresented as being the original source.
 
-3. This Copyright notice may not be removed or altered from any
-   source or altered source distribution.
+  3. This Copyright notice may not be removed or altered from any
+     source or altered source distribution.
 
 The Contributing Authors and Group 42, Inc. specifically permit, without
 fee, and encourage the use of this source code as a component to
 supporting the PNG file format in commercial products.  If you use this
 source code in a product, acknowledgment is not required but would be
 appreciated.
 
+END OF COPYRIGHT NOTICE, DISCLAIMER, and LICENSE.
 
 A "png_get_copyright" function is available, for convenient use in "about"
 boxes and the like:
 
-   printf("%s",png_get_copyright(NULL));
+   printf("%s", png_get_copyright(NULL));
 
 Also, the PNG logo (in PNG format, of course) is supplied in the
 files "pngbar.png" and "pngbar.jpg (88x31) and "pngnow.png" (98x31).
 
-Libpng is OSI Certified Open Source Software.  OSI Certified Open Source is a
-certification mark of the Open Source Initiative.
+Libpng is OSI Certified Open Source Software.  OSI Certified Open Source is
+a certification mark of the Open Source Initiative. OSI has not addressed
+the additional disclaimers inserted at version 1.0.7.
 
 Glenn Randers-Pehrson
 glennrp at users.sourceforge.net
-November 20, 2014
+November 12, 2015
```


### `third_party/libpng/README`

```diff
@@ -1,4 +1,4 @@
-README for libpng version 1.2.52 - November 20, 2014 (shared library 12.0)
+README for libpng version 1.2.54 - November 12, 2015 (shared library 12.0)
 See the note about version numbers near the top of png.h
 
 See INSTALL for instructions on how to install libpng.
@@ -135,7 +135,7 @@ and ...".  If in doubt, send questions to me.  I'll bounce them
 to others, if necessary.
 
 Please do not send suggestions on how to change PNG.  We have
-been discussing PNG for nineteen years now, and it is official and
+been discussing PNG for twenty years now, and it is official and
 finished.  If you have suggestions for libpng, however, I'll
 gladly listen.  Even if your suggestion is not used immediately,
 it may be used later.
@@ -207,11 +207,11 @@ Files in this distribution:
        makefile.std     =>  Generic UNIX makefile (cc, creates static
                             libpng.a)
        makefile.elf     =>  Linux/ELF gcc makefile symbol versioning,
-                            creates libpng12.so.0.1.2.52)
+                            creates libpng12.so.0.1.2.54)
        makefile.linux   =>  Linux/ELF makefile (gcc, creates
-                            libpng12.so.0.1.2.52)
+                            libpng12.so.0.1.2.54)
        makefile.gcmmx   =>  Linux/ELF makefile (gcc, creates
-                            libpng12.so.0.1.2.52, previously
+                            libpng12.so.0.1.2.54, previously
                             used assembler code tuned for Intel MMX
                             platform)
        makefile.gcc     =>  Generic makefile (gcc, creates static
@@ -236,12 +236,12 @@ Files in this distribution:
        makefile.openbsd =>  OpenBSD makefile
        makefile.sgi     =>  Silicon Graphics IRIX (cc, creates static lib)
        makefile.sggcc   =>  Silicon Graphics
-                            (gcc, creates libpng12.so.0.1.2.52)
+                            (gcc, creates libpng12.so.0.1.2.54)
        makefile.sunos   =>  Sun makefile
        makefile.solaris =>  Solaris 2.X makefile
-                            (gcc, creates libpng12.so.0.1.2.52)
+                            (gcc, creates libpng12.so.0.1.2.54)
        makefile.so9     =>  Solaris 9 makefile
-                            (gcc, creates libpng12.so.0.1.2.52)
+                            (gcc, creates libpng12.so.0.1.2.54)
        makefile.32sunu  =>  Sun Ultra 32-bit makefile
        makefile.64sunu  =>  Sun Ultra 64-bit makefile
        makefile.sco     =>  For SCO OSr5  ELF and Unixware 7 with Native cc
```


### `third_party/libpng/README.chromium`

```diff
@@ -1,6 +1,6 @@
 Name: libpng
 URL: [url removida]
-Version: 1.2.52
+Version: 1.2.54
 Security Critical: yes
 License: libpng license
 License Android Compatible: yes
@@ -10,7 +10,7 @@ Our custom configuration options are defined in pngusr.h. This was previously
 called mozpngconf.h, which was copied from Mozilla and modified by Apple (hence
 the wk_* names).
 
-Updated to 1.2.52, no changes to the source files but all unneeded files
+Updated to 1.2.54, no changes to the source files but all unneeded files
 stripped.
 
 - Unset PNG_NO_READ_PACK on Android in pngusr.h, required by freetype to support
```


### `third_party/libpng/png.c`

```diff
@@ -1,8 +1,8 @@
 
 /* png.c - location for general purpose libpng functions
  *
- * Last changed in libpng 1.2.51 [February 6, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.54 [November 12, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -17,7 +17,7 @@
 #include "png.h"
 
 /* Generate a compiler error if there is an old png.h in the search path. */
-typedef version_1_2_52 Your_png_h_is_not_version_1_2_52;
+typedef version_1_2_54 Your_png_h_is_not_version_1_2_54;
 
 /* Version information for C files.  This had better match the version
  * string defined in png.h.
@@ -158,12 +158,16 @@ voidpf /* PRIVATE */
 png_zalloc(voidpf png_ptr, uInt items, uInt size)
 {
    png_voidp ptr;
-   png_structp p=(png_structp)png_ptr;
-   png_uint_32 save_flags=p->flags;
+   png_structp p;
+   png_uint_32 save_flags;
    png_uint_32 num_bytes;
 
    if (png_ptr == NULL)
       return (NULL);
+
+   p=(png_structp)png_ptr;
+   save_flags=p->flags;
+
    if (items > PNG_UINT_32_MAX/size)
    {
      png_warning (p, "Potential overflow in png_zalloc()");
@@ -328,6 +332,8 @@ png_info_init_3(png_infopp ptr_ptr, png_size_t png_info_struct_size)
       png_destroy_struct(info_ptr);
       info_ptr = (png_infop)png_create_struct(PNG_STRUCT_INFO);
       *ptr_ptr = info_ptr;
+      if (info_ptr == NULL)
+         return;
    }
 
    /* Set everything to 0 */
@@ -675,6 +681,7 @@ png_convert_to_rfc1123(png_structp png_ptr, png_timep ptime)
 
    if (png_ptr == NULL)
       return (NULL);
+
    if (png_ptr->time_buffer == NULL)
    {
       png_ptr->time_buffer = (png_charp)png_malloc(png_ptr, (png_uint_32)(29*
@@ -685,7 +692,7 @@ png_convert_to_rfc1123(png_structp png_ptr, png_timep ptime)
    {
       wchar_t time_buf[29];
       wsprintf(time_buf, TEXT("%d %S %d %02d:%02d:%02d +0000"),
-          ptime->day % 32, short_months[(ptime->month - 1) % 12],
+          ptime->day % 32, short_months[(ptime->month - 1U) % 12],
         ptime->year, ptime->hour % 24, ptime->minute % 60,
           ptime->second % 61);
       WideCharToMultiByte(CP_ACP, 0, time_buf, -1, png_ptr->time_buffer,
@@ -696,15 +703,15 @@ png_convert_to_rfc1123(png_structp png_ptr, png_timep ptime)
    {
       char near_time_buf[29];
       png_snprintf6(near_time_buf, 29, "%d %s %d %02d:%02d:%02d +0000",
-          ptime->day % 32, short_months[(ptime->month - 1) % 12],
+          ptime->day % 32, short_months[(ptime->month - 1U) % 12],
           ptime->year, ptime->hour % 24, ptime->minute % 60,
           ptime->second % 61);
       png_memcpy(png_ptr->time_buffer, near_time_buf,
           29*png_sizeof(char));
    }
 #else
    png_snprintf6(png_ptr->time_buffer, 29, "%d %s %d %02d:%02d:%02d +0000",
-       ptime->day % 32, short_months[(ptime->month - 1) % 12],
+       ptime->day % 32, short_months[(ptime->month - 1U) % 12],
        ptime->year, ptime->hour % 24, ptime->minute % 60,
        ptime->second % 61);
 #endif
@@ -724,14 +731,14 @@ png_get_copyright(png_structp png_ptr)
 #else
 #ifdef __STDC__
    return ((png_charp) PNG_STRING_NEWLINE \
-     "libpng version 1.2.52 - November 20, 2014" PNG_STRING_NEWLINE \
-     "Copyright (c) 1998-2014 Glenn Randers-Pehrson" PNG_STRING_NEWLINE \
+     "libpng version 1.2.54 - November 12, 2015" PNG_STRING_NEWLINE \
+     "Copyright (c) 1998-2015 Glenn Randers-Pehrson" PNG_STRING_NEWLINE \
      "Copyright (c) 1996-1997 Andreas Dilger" PNG_STRING_NEWLINE \
      "Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc." \
      PNG_STRING_NEWLINE);
 #else
-      return ((png_charp) "libpng version 1.2.52 - November 20, 2014\
-      Copyright (c) 1998-2014 Glenn Randers-Pehrson\
+      return ((png_charp) "libpng version 1.2.54 - November 12, 2015\
+      Copyright (c) 1998-2015 Glenn Randers-Pehrson\
       Copyright (c) 1996-1997 Andreas Dilger\
       Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.");
 #endif
```


### `third_party/libpng/png.h`

```diff
@@ -1,318 +1,19 @@
+
 /* png.h - header file for PNG reference library
  *
- * libpng version 1.2.52 - November 20, 2014
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * libpng version 1.2.54, November 12, 2015
+ *
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
  * This code is released under the libpng license (See LICENSE, below)
  *
  * Authors and maintainers:
  *  libpng versions 0.71, May 1995, through 0.88, January 1996: Guy Schalnat
- *  libpng versions 0.89c, June 1996, through 0.96, May 1997: Andreas Dilger
- *  libpng versions 0.97, January 1998, through 1.2.52 - November 20, 2014: Glenn
+ *  libpng versions 0.89, June 1996, through 0.96, May 1997: Andreas Dilger
+ *  libpng versions 0.97, January 1998, through 1.2.54, November 12, 2015: Glenn
  *  See also "Contributing Authors", below.
- *
- * Note about libpng version numbers:
- *
- *    Due to various miscommunications, unforeseen code incompatibilities
- *    and occasional factors outside the authors' control, version numbering
- *    on the library has not always been consistent and straightforward.
- *    The following table summarizes matters since version 0.89c, which was
- *    the first widely used release:
- *
- *    source                 png.h  png.h  shared-lib
- *    version                string   int  version
- *    -------                ------ -----  ----------
- *    0.89c "1.0 beta 3"     0.89      89  1.0.89
- *    0.90  "1.0 beta 4"     0.90      90  0.90  [should have been 2.0.90]
- *    0.95  "1.0 beta 5"     0.95      95  0.95  [should have been 2.0.95]
- *    0.96  "1.0 beta 6"     0.96      96  0.96  [should have been 2.0.96]
- *    0.97b "1.00.97 beta 7" 1.00.97   97  1.0.1 [should have been 2.0.97]
- *    0.97c                  0.97      97  2.0.97
- *    0.98                   0.98      98  2.0.98
- *    0.99                   0.99      98  2.0.99
- *    0.99a-m                0.99      99  2.0.99
- *    1.00                   1.00     100  2.1.0 [100 should be 10000]
- *    1.0.0      (from here on, the   100  2.1.0 [100 should be 10000]
- *    1.0.1       png.h string is   10001  2.1.0
- *    1.0.1a-e    identical to the  10002  from here on, the shared library
- *    1.0.2       source version)   10002  is 2.V where V is the source code
- *    1.0.2a-b                      10003  version, except as noted.
- *    1.0.3                         10003
- *    1.0.3a-d                      10004
- *    1.0.4                         10004
- *    1.0.4a-f                      10005
- *    1.0.5 (+ 2 patches)           10005
- *    1.0.5a-d                      10006
- *    1.0.5e-r                      10100 (not source compatible)
- *    1.0.5s-v                      10006 (not binary compatible)
- *    1.0.6 (+ 3 patches)           10006 (still binary incompatible)
- *    1.0.6d-f                      10007 (still binary incompatible)
- *    1.0.6g                        10007
- *    1.0.6h                        10007  10.6h (testing xy.z so-numbering)
- *    1.0.6i                        10007  10.6i
- *    1.0.6j                        10007  2.1.0.6j (incompatible with 1.0.0)
- *    1.0.7beta11-14        DLLNUM  10007  2.1.0.7beta11-14 (binary compatible)
- *    1.0.7beta15-18           1    10007  2.1.0.7beta15-18 (binary compatible)
- *    1.0.7rc1-2               1    10007  2.1.0.7rc1-2 (binary compatible)
- *    1.0.7                    1    10007  (still compatible)
- *    1.0.8beta1-4             1    10008  2.1.0.8beta1-4
- *    1.0.8rc1                 1    10008  2.1.0.8rc1
- *    1.0.8                    1    10008  2.1.0.8
- *    1.0.9beta1-6             1    10009  2.1.0.9beta1-6
- *    1.0.9rc1                 1    10009  2.1.0.9rc1
- *    1.0.9beta7-10            1    10009  2.1.0.9beta7-10
- *    1.0.9rc2                 1    10009  2.1.0.9rc2
- *    1.0.9                    1    10009  2.1.0.9
- *    1.0.10beta1              1    10010  2.1.0.10beta1
- *    1.0.10rc1                1    10010  2.1.0.10rc1
- *    1.0.10                   1    10010  2.1.0.10
- *    1.0.11beta1-3            1    10011  2.1.0.11beta1-3
- *    1.0.11rc1                1    10011  2.1.0.11rc1
- *    1.0.11                   1    10011  2.1.0.11
- *    1.0.12beta1-2            2    10012  2.1.0.12beta1-2
- *    1.0.12rc1                2    10012  2.1.0.12rc1
- *    1.0.12                   2    10012  2.1.0.12
- *    1.1.0a-f                 -    10100  2.1.1.0a-f (branch abandoned)
- *    1.2.0beta1-2             2    10200  2.1.2.0beta1-2
- *    1.2.0beta3-5             3    10200  3.1.2.0beta3-5
- *    1.2.0rc1                 3    10200  3.1.2.0rc1
- *    1.2.0                    3    10200  3.1.2.0
- *    1.2.1beta1-4             3    10201  3.1.2.1beta1-4
- *    1.2.1rc1-2               3    10201  3.1.2.1rc1-2
- *    1.2.1                    3    10201  3.1.2.1
- *    1.2.2beta1-6            12    10202  12.so.0.1.2.2beta1-6
- *    1.0.13beta1             10    10013  10.so.0.1.0.13beta1
- *    1.0.13rc1               10    10013  10.so.0.1.0.13rc1
- *    1.2.2rc1                12    10202  12.so.0.1.2.2rc1
- *    1.0.13                  10    10013  10.so.0.1.0.13
- *    1.2.2                   12    10202  12.so.0.1.2.2
- *    1.2.3rc1-6              12    10203  12.so.0.1.2.3rc1-6
- *    1.2.3                   12    10203  12.so.0.1.2.3
- *    1.2.4beta1-3            13    10204  12.so.0.1.2.4beta1-3
- *    1.0.14rc1               13    10014  10.so.0.1.0.14rc1
- *    1.2.4rc1                13    10204  12.so.0.1.2.4rc1
- *    1.0.14                  10    10014  10.so.0.1.0.14
- *    1.2.4                   13    10204  12.so.0.1.2.4
- *    1.2.5beta1-2            13    10205  12.so.0.1.2.5beta1-2
- *    1.0.15rc1-3             10    10015  10.so.0.1.0.15rc1-3
- *    1.2.5rc1-3              13    10205  12.so.0.1.2.5rc1-3
- *    1.0.15                  10    10015  10.so.0.1.0.15
- *    1.2.5                   13    10205  12.so.0.1.2.5
- *    1.2.6beta1-4            13    10206  12.so.0.1.2.6beta1-4
- *    1.0.16                  10    10016  10.so.0.1.0.16
- *    1.2.6                   13    10206  12.so.0.1.2.6
- *    1.2.7beta1-2            13    10207  12.so.0.1.2.7beta1-2
- *    1.0.17rc1               10    10017  10.so.0.1.0.17rc1
- *    1.2.7rc1                13    10207  12.so.0.1.2.7rc1
- *    1.0.17                  10    10017  10.so.0.1.0.17
- *    1.2.7                   13    10207  12.so.0.1.2.7
- *    1.2.8beta1-5            13    10208  12.so.0.1.2.8beta1-5
- *    1.0.18rc1-5             10    10018  10.so.0.1.0.18rc1-5
- *    1.2.8rc1-5              13    10208  12.so.0.1.2.8rc1-5
- *    1.0.18                  10    10018  10.so.0.1.0.18
- *    1.2.8                   13    10208  12.so.0.1.2.8
- *    1.2.9beta1-3            13    10209  12.so.0.1.2.9beta1-3
- *    1.2.9beta4-11           13    10209  12.so.0.9[.0]
- *    1.2.9rc1                13    10209  12.so.0.9[.0]
- *    1.2.9                   13    10209  12.so.0.9[.0]
- *    1.2.10beta1-8           13    10210  12.so.0.10[.0]
- *    1.2.10rc1-3             13    10210  12.so.0.10[.0]
- *    1.2.10                  13    10210  12.so.0.10[.0]
- *    1.2.11beta1-4           13    10211  12.so.0.11[.0]
- *    1.0.19rc1-5             10    10019  10.so.0.19[.0]
- *    1.2.11rc1-5             13    10211  12.so.0.11[.0]
- *    1.0.19                  10    10019  10.so.0.19[.0]
- *    1.2.11                  13    10211  12.so.0.11[.0]
- *    1.0.20                  10    10020  10.so.0.20[.0]
- *    1.2.12                  13    10212  12.so.0.12[.0]
- *    1.2.13beta1             13    10213  12.so.0.13[.0]
- *    1.0.21                  10    10021  10.so.0.21[.0]
- *    1.2.13                  13    10213  12.so.0.13[.0]
- *    1.2.14beta1-2           13    10214  12.so.0.14[.0]
- *    1.0.22rc1               10    10022  10.so.0.22[.0]
- *    1.2.14rc1               13    10214  12.so.0.14[.0]
- *    1.0.22                  10    10022  10.so.0.22[.0]
- *    1.2.14                  13    10214  12.so.0.14[.0]
- *    1.2.15beta1-6           13    10215  12.so.0.15[.0]
- *    1.0.23rc1-5             10    10023  10.so.0.23[.0]
- *    1.2.15rc1-5             13    10215  12.so.0.15[.0]
- *    1.0.23                  10    10023  10.so.0.23[.0]
- *    1.2.15                  13    10215  12.so.0.15[.0]
- *    1.2.16beta1-2           13    10216  12.so.0.16[.0]
- *    1.2.16rc1               13    10216  12.so.0.16[.0]
- *    1.0.24                  10    10024  10.so.0.24[.0]
- *    1.2.16                  13    10216  12.so.0.16[.0]
- *    1.2.17beta1-2           13    10217  12.so.0.17[.0]
- *    1.0.25rc1               10    10025  10.so.0.25[.0]
- *    1.2.17rc1-3             13    10217  12.so.0.17[.0]
- *    1.0.25                  10    10025  10.so.0.25[.0]
- *    1.2.17                  13    10217  12.so.0.17[.0]
- *    1.0.26                  10    10026  10.so.0.26[.0]
- *    1.2.18                  13    10218  12.so.0.18[.0]
- *    1.2.19beta1-31          13    10219  12.so.0.19[.0]
- *    1.0.27rc1-6             10    10027  10.so.0.27[.0]
- *    1.2.19rc1-6             13    10219  12.so.0.19[.0]
- *    1.0.27                  10    10027  10.so.0.27[.0]
- *    1.2.19                  13    10219  12.so.0.19[.0]
- *    1.2.20beta01-04         13    10220  12.so.0.20[.0]
- *    1.0.28rc1-6             10    10028  10.so.0.28[.0]
- *    1.2.20rc1-6             13    10220  12.so.0.20[.0]
- *    1.0.28                  10    10028  10.so.0.28[.0]
- *    1.2.20                  13    10220  12.so.0.20[.0]
- *    1.2.21beta1-2           13    10221  12.so.0.21[.0]
- *    1.2.21rc1-3             13    10221  12.so.0.21[.0]
- *    1.0.29                  10    10029  10.so.0.29[.0]
- *    1.2.21                  13    10221  12.so.0.21[.0]
- *    1.2.22beta1-4           13    10222  12.so.0.22[.0]
- *    1.0.30rc1               10    10030  10.so.0.30[.0]
- *    1.2.22rc1               13    10222  12.so.0.22[.0]
- *    1.0.30                  10    10030  10.so.0.30[.0]
- *    1.2.22                  13    10222  12.so.0.22[.0]
- *    1.2.23beta01-05         13    10223  12.so.0.23[.0]
- *    1.2.23rc01              13    10223  12.so.0.23[.0]
- *    1.2.23                  13    10223  12.so.0.23[.0]
- *    1.2.24beta01-02         13    10224  12.so.0.24[.0]
- *    1.2.24rc01              13    10224  12.so.0.24[.0]
- *    1.2.24                  13    10224  12.so.0.24[.0]
- *    1.2.25beta01-06         13    10225  12.so.0.25[.0]
- *    1.2.25rc01-02           13    10225  12.so.0.25[.0]
- *    1.0.31                  10    10031  10.so.0.31[.0]
- *    1.2.25                  13    10225  12.so.0.25[.0]
- *    1.2.26beta01-06         13    10226  12.so.0.26[.0]
- *    1.2.26rc01              13    10226  12.so.0.26[.0]
- *    1.2.26                  13    10226  12.so.0.26[.0]
- *    1.0.32                  10    10032  10.so.0.32[.0]
- *    1.2.27beta01-06         13    10227  12.so.0.27[.0]
- *    1.2.27rc01              13    10227  12.so.0.27[.0]
- *    1.0.33                  10    10033  10.so.0.33[.0]
- *    1.2.27                  13    10227  12.so.0.27[.0]
- *    1.0.34                  10    10034  10.so.0.34[.0]
- *    1.2.28                  13    10228  12.so.0.28[.0]
- *    1.2.29beta01-03         13    10229  12.so.0.29[.0]
- *    1.2.29rc01              13    10229  12.so.0.29[.0]
- *    1.0.35                  10    10035  10.so.0.35[.0]
- *    1.2.29                  13    10229  12.so.0.29[.0]
- *    1.0.37                  10    10037  10.so.0.37[.0]
- *    1.2.30beta01-04         13    10230  12.so.0.30[.0]
- *    1.0.38rc01-08           10    10038  10.so.0.38[.0]
- *    1.2.30rc01-08           13    10230  12.so.0.30[.0]
- *    1.0.38                  10    10038  10.so.0.38[.0]
- *    1.2.30                  13    10230  12.so.0.30[.0]
- *    1.0.39rc01-03           10    10039  10.so.0.39[.0]
- *    1.2.31rc01-03           13    10231  12.so.0.31[.0]
- *    1.0.39                  10    10039  10.so.0.39[.0]
- *    1.2.31                  13    10231  12.so.0.31[.0]
- *    1.2.32beta01-02         13    10232  12.so.0.32[.0]
- *    1.0.40rc01              10    10040  10.so.0.40[.0]
- *    1.2.32rc01              13    10232  12.so.0.32[.0]
- *    1.0.40                  10    10040  10.so.0.40[.0]
- *    1.2.32                  13    10232  12.so.0.32[.0]
- *    1.2.33beta01-02         13    10233  12.so.0.33[.0]
- *    1.2.33rc01-02           13    10233  12.so.0.33[.0]
- *    1.0.41rc01              10    10041  10.so.0.41[.0]
- *    1.2.33                  13    10233  12.so.0.33[.0]
- *    1.0.41                  10    10041  10.so.0.41[.0]
- *    1.2.34beta01-07         13    10234  12.so.0.34[.0]
- *    1.0.42rc01              10    10042  10.so.0.42[.0]
- *    1.2.34rc01              13    10234  12.so.0.34[.0]
- *    1.0.42                  10    10042  10.so.0.42[.0]
- *    1.2.34                  13    10234  12.so.0.34[.0]
- *    1.2.35beta01-03         13    10235  12.so.0.35[.0]
- *    1.0.43rc01-02           10    10043  10.so.0.43[.0]
- *    1.2.35rc01-02           13    10235  12.so.0.35[.0]
- *    1.0.43                  10    10043  10.so.0.43[.0]
- *    1.2.35                  13    10235  12.so.0.35[.0]
- *    1.2.36beta01-05         13    10236  12.so.0.36[.0]
- *    1.2.36rc01              13    10236  12.so.0.36[.0]
- *    1.0.44                  10    10044  10.so.0.44[.0]
- *    1.2.36                  13    10236  12.so.0.36[.0]
- *    1.2.37beta01-03         13    10237  12.so.0.37[.0]
- *    1.2.37rc01              13    10237  12.so.0.37[.0]
- *    1.2.37                  13    10237  12.so.0.37[.0]
- *    1.0.45                  10    10045  12.so.0.45[.0]
- *    1.0.46                  10    10046  10.so.0.46[.0]
- *    1.2.38beta01            13    10238  12.so.0.38[.0]
- *    1.2.38rc01-03           13    10238  12.so.0.38[.0]
- *    1.0.47                  10    10047  10.so.0.47[.0]
- *    1.2.38                  13    10238  12.so.0.38[.0]
- *    1.2.39beta01-05         13    10239  12.so.0.39[.0]
- *    1.2.39rc01              13    10239  12.so.0.39[.0]
- *    1.0.48                  10    10048  10.so.0.48[.0]
- *    1.2.39                  13    10239  12.so.0.39[.0]
- *    1.2.40beta01            13    10240  12.so.0.40[.0]
- *    1.2.40rc01              13    10240  12.so.0.40[.0]
- *    1.0.49                  10    10049  10.so.0.49[.0]
- *    1.2.40                  13    10240  12.so.0.40[.0]
- *    1.2.41beta01-18         13    10241  12.so.0.41[.0]
- *    1.0.51rc01              10    10051  10.so.0.51[.0]
- *    1.2.41rc01-03           13    10241  12.so.0.41[.0]
- *    1.0.51                  10    10051  10.so.0.51[.0]
- *    1.2.41                  13    10241  12.so.0.41[.0]
- *    1.2.42beta01-02         13    10242  12.so.0.42[.0]
- *    1.2.42rc01-05           13    10242  12.so.0.42[.0]
- *    1.0.52                  10    10052  10.so.0.52[.0]
- *    1.2.42                  13    10242  12.so.0.42[.0]
- *    1.2.43beta01-05         13    10243  12.so.0.43[.0]
- *    1.0.53rc01-02           10    10053  10.so.0.53[.0]
- *    1.2.43rc01-02           13    10243  12.so.0.43[.0]
- *    1.0.53                  10    10053  10.so.0.53[.0]
- *    1.2.43                  13    10243  12.so.0.43[.0]
- *    1.2.44beta01-03         13    10244  12.so.0.44[.0]
- *    1.2.44rc01-03           13    10244  12.so.0.44[.0]
- *    1.2.44                  13    10244  12.so.0.44[.0]
- *    1.2.45beta01-03         13    10245  12.so.0.45[.0]
- *    1.0.55rc01              10    10055  10.so.0.55[.0]
- *    1.2.45rc01              13    10245  12.so.0.45[.0]
- *    1.0.55                  10    10055  10.so.0.55[.0]
- *    1.2.45                  13    10245  12.so.0.45[.0]
- *    1.2.46rc01-02           13    10246  12.so.0.46[.0]
- *    1.0.56                  10    10056  10.so.0.56[.0]
- *    1.2.46                  13    10246  12.so.0.46[.0]
- *    1.2.47beta01            13    10247  12.so.0.47[.0]
- *    1.2.47rc01              13    10247  12.so.0.47[.0]
- *    1.0.57rc01              10    10057  10.so.0.57[.0]
- *    1.2.47                  13    10247  12.so.0.47[.0]
- *    1.0.57                  10    10057  10.so.0.57[.0]
- *    1.2.48beta01            13    10248  12.so.0.48[.0]
- *    1.2.48rc01-02           13    10248  12.so.0.48[.0]
- *    1.0.58                  10    10058  10.so.0.58[.0]
- *    1.2.48                  13    10248  12.so.0.48[.0]
- *    1.2.49rc01              13    10249  12.so.0.49[.0]
- *    1.0.59                  10    10059  10.so.0.59[.0]
- *    1.2.49                  13    10249  12.so.0.49[.0]
- *    1.0.60                  10    10060  10.so.0.60[.0]
- *    1.2.50                  13    10250  12.so.0.50[.0]
- *    1.2.51beta01-05         13    10251  12.so.0.51[.0]
- *    1.2.51rc01-04           13    10251  12.so.0.51[.0]
- *    1.0.61                  10    10061  10.so.0.61[.0]
- *    1.2.51                  13    10251  12.so.0.51[.0]
- *    1.2.52beta01            13    10252  12.so.0.52[.0]
- *    1.2.52rc01-02           13    10252  12.so.0.52[.0]
- *    1.0.62                  10    10062  10.so.0.62[.0]
- *    1.2.52                  13    10252  12.so.0.52[.0]
- *
- *    Henceforth the source version will match the shared-library major
- *    and minor numbers; the shared-library major version number will be
- *    used for changes in backward compatibility, as it is intended.  The
- *    PNG_LIBPNG_VER macro, which is not used within libpng but is available
- *    for applications, is an unsigned integer of the form xyyzz corresponding
- *    to the source version x.y.z (leading zeros in y and z).  Beta versions
- *    were given the previous public release number plus a letter, until
- *    version 1.0.6j; from then on they were given the upcoming public
- *    release number plus "betaNN" or "rcNN".
- *
- *    Binary incompatibility exists only when applications make direct access
- *    to the info_ptr or png_ptr members through png.h, and the compiled
- *    application is loaded with a different version of the library.
- *
- *    DLLNUM will change each time there are forward or backward changes
- *    in binary compatibility (e.g., when a new feature is added).
- *
- * See libpng.txt or libpng.3 for more information.  The PNG specification
- * is available as a W3C Recommendation and as an ISO Specification,
- * <[url removida]
  */
 
 /*
@@ -323,20 +24,15 @@
  *
  * This code is released under the libpng license.
  *
- * libpng versions 1.2.6, August 15, 2004, through 1.2.52, November 20, 2014, are
- * Copyright (c) 2004, 2006-2013 Glenn Randers-Pehrson, and are
- * distributed according to the same disclaimer and license as libpng-1.2.5
- * with the following individual added to the list of Contributing Authors:
- *
- *    Cosmin Truta
- *
- * libpng versions 1.0.7, July 1, 2000, through 1.2.5, October 3, 2002, are
- * Copyright (c) 2000-2002 Glenn Randers-Pehrson, and are
- * distributed according to the same disclaimer and license as libpng-1.0.6
- * with the following individuals added to the list of Contributing Authors:
+ * libpng versions 1.0.7, July 1, 2000, through 1.2.54, November 12, 2015, are
+ * Copyright (c) 2000-2002, 2004, 2006-2015 Glenn Randers-Pehrson, are
+ * derived from libpng-1.0.6, and are distributed according to the same
+ * disclaimer and license as libpng-1.0.6 with the following individuals
+ * added to the list of Contributing Authors:
  *
  *    Simon-Pierre Cadieux
  *    Eric S. Raymond
+ *    Cosmin Truta
  *    Gilles Vollant
  *
  * and with the following additions to the disclaimer:
@@ -349,18 +45,20 @@
  *    the user.
  *
  * libpng versions 0.97, January 1998, through 1.0.6, March 20, 2000, are
- * Copyright (c) 1998, 1999, 2000 Glenn Randers-Pehrson, and are
- * distributed according to the same disclaimer and license as libpng-0.96,
- * with the following individuals added to the list of Contributing Authors:
+ * Copyright (c) 1998-2000 Glenn Randers-Pehrson, are derived from
+ * libpng-0.96, and are distributed according to the same disclaimer and
+ * license as libpng-0.96, with the following individuals added to the list
+ * of Contributing Authors:
  *
  *    Tom Lane
  *    Glenn Randers-Pehrson
  *    Willem van Schaik
  *
  * libpng versions 0.89, June 1996, through 0.96, May 1997, are
- * Copyright (c) 1996, 1997 Andreas Dilger
- * Distributed according to the same disclaimer and license as libpng-0.88,
- * with the following individuals added to the list of Contributing Authors:
+ * Copyright (c) 1996-1997 Andreas Dilger, are derived from libpng-0.88,
+ * and are distributed according to the same disclaimer and license as
+ * libpng-0.88, with the following individuals added to the list of
+ * Contributing Authors:
  *
  *    John Bowler
  *    Kevin Bracey
@@ -370,7 +68,7 @@
  *    Tom Tanner
  *
  * libpng versions 0.5, May 1995, through 0.88, January 1996, are
- * Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.
+ * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
  *
  * For the purposes of this copyright and license, "Contributing Authors"
  * is defined as the following set of individuals:
@@ -393,34 +91,37 @@
  * source code, or portions hereof, for any purpose, without fee, subject
  * to the following restrictions:
  *
- * 1. The origin of this source code must not be misrepresented.
+ *   1. The origin of this source code must not be misrepresented.
  *
- * 2. Altered versions must be plainly marked as such and
- * must not be misrepresented as being the original source.
+ *   2. Altered versions must be plainly marked as such and must not
+ *      be misrepresented as being the original source.
  *
- * 3. This Copyright notice may not be removed or altered from
- *    any source or altered source distribution.
+ *   3. This Copyright notice may not be removed or altered from any
+ *      source or altered source distribution.
  *
  * The Contributing Authors and Group 42, Inc. specifically permit, without
  * fee, and encourage the use of this source code as a component to
  * supporting the PNG file format in commercial products.  If you use this
  * source code in a product, acknowledgment is not required but would be
  * appreciated.
+ *
+ * END OF COPYRIGHT NOTICE, DISCLAIMER, and LICENSE.
  */
 
 /*
  * A "png_get_copyright" function is available, for convenient use in "about"
  * boxes and the like:
  *
- * printf("%s",png_get_copyright(NULL));
+ *    printf("%s", png_get_copyright(NULL));
  *
  * Also, the PNG logo (in PNG format, of course) is supplied in the
  * files "pngbar.png" and "pngbar.jpg (88x31) and "pngnow.png" (98x31).
  */
 
 /*
- * Libpng is OSI Certified Open Source Software.  OSI Certified is a
- * certification mark of the Open Source Initiative.
+ * Libpng is OSI Certified Open Source Software.  OSI Certified Open Source is
+ * a certification mark of the Open Source Initiative. OSI has not addressed
+ * the additional disclaimers inserted at version 1.0.7.
  */
 
 /*
@@ -431,17 +132,89 @@
  * Thanks to Frank J. T. Wojcik for helping with the documentation.
  */
 
+/* Note about libpng version numbers:
+ *
+ *    Due to various miscommunications, unforeseen code incompatibilities
+ *    and occasional factors outside the authors' control, version numbering
+ *    on the library has not always been consistent and straightforward.
+ *    The following table summarizes matters since version 0.89c, which was
+ *    the first widely used release:
+ *
+ *    source                 png.h  png.h  shared-lib
+ *    version                string   int  version
+ *    -------                ------ -----  ----------
+ *    0.89c "1.0 beta 3"     0.89      89  1.0.89
+ *    0.90  "1.0 beta 4"     0.90      90  0.90  [should have been 2.0.90]
+ *    0.95  "1.0 beta 5"     0.95      95  0.95  [should have been 2.0.95]
+ *    0.96  "1.0 beta 6"     0.96      96  0.96  [should have been 2.0.96]
+ *    0.97b "1.00.97 beta 7" 1.00.97   97  1.0.1 [should have been 2.0.97]
+ *    0.97c                  0.97      97  2.0.97
+ *    0.98                   0.98      98  2.0.98
+ *    0.99                   0.99      98  2.0.99
+ *    0.99a-m                0.99      99  2.0.99
+ *    1.00                   1.00     100  2.1.0 [100 should be 10000]
+ *    1.0.0      (from here on, the   100  2.1.0 [100 should be 10000]
+ *    1.0.1       png.h string is   10001  2.1.0
+ *    1.0.1a-e    identical to the  10002  from here on, the shared library
+ *    1.0.2       source version)   10002  is 2.V where V is the source code
+ *    1.0.2a-b                      10003  version, except as noted.
+ *    1.0.3                         10003
+ *    1.0.3a-d                      10004
+ *    1.0.4                         10004
+ *    1.0.4a-f                      10005
+ *    1.0.5 (+ 2 patches)           10005
+ *    1.0.5a-d                      10006
+ *    1.0.5e-r                      10100 (not source compatible)
+ *    1.0.5s-v                      10006 (not binary compatible)
+ *    1.0.6 (+ 3 patches)           10006 (still binary incompatible)
+ *    1.0.6d-f                      10007 (still binary incompatible)
+ *    1.0.6g                        10007
+ *    1.0.6h                        10007  10.6h (testing xy.z so-numbering)
+ *    1.0.6i                        10007  10.6i
+ *    1.0.6j                        10007  2.1.0.6j (incompatible with 1.0.0)
+ *    1.0.7beta11-14        DLLNUM  10007  2.1.0.7beta11-14 (binary compatible)
+ *    1.0.7beta15-18           1    10007  2.1.0.7beta15-18 (binary compatible)
+ *    1.0.7rc1-2               1    10007  2.1.0.7rc1-2 (binary compatible)
+ *    1.0.7                    1    10007  (still compatible)
+ *    ...
+ *    1.0.19                  10    10019  10.so.0.19[.0]
+ *    ...
+ *    1.0.64                  10    10064  10.so.0.64[.0]
+ *    1.2.54                  13    10254  12.so.0.54[.0]
+ *
+ *    Henceforth the source version will match the shared-library major
+ *    and minor numbers; the shared-library major version number will be
+ *    used for changes in backward compatibility, as it is intended.  The
+ *    PNG_LIBPNG_VER macro, which is not used within libpng but is available
+ *    for applications, is an unsigned integer of the form xyyzz corresponding
+ *    to the source version x.y.z (leading zeros in y and z).  Beta versions
+ *    were given the previous public release number plus a letter, until
+ *    version 1.0.6j; from then on they were given the upcoming public
+ *    release number plus "betaNN" or "rcNN".
+ *
+ *    Binary incompatibility exists only when applications make direct access
+ *    to the info_ptr or png_ptr members through png.h, and the compiled
+ *    application is loaded with a different version of the library.
+ *
+ *    DLLNUM will change each time there are forward or backward changes
+ *    in binary compatibility (e.g., when a new feature is added).
+ *
+ * See libpng.txt or libpng.3 for more information.  The PNG specification
+ * is available as a W3C Recommendation and as an ISO Specification,
+ * <[url removida]
+ */
+
 /*
  * Y2K compliance in libpng:
  * =========================
  *
- *    November 20, 2014
+ *    November 12, 2015
  *
  *    Since the PNG Development group is an ad-hoc body, we can't make
  *    an official declaration.
  *
  *    This is your unofficial assurance that libpng from version 0.71 and
- *    upward through 1.2.52 are Y2K compliant.  It is my belief that earlier
+ *    upward through 1.2.54 are Y2K compliant.  It is my belief that earlier
  *    versions were also Y2K compliant.
  *
  *    Libpng only has three year fields.  One is a 2-byte unsigned integer
@@ -497,17 +270,17 @@
  */
 
 /* Version information for png.h - this should match the version in png.c */
-#define PNG_LIBPNG_VER_STRING "1.2.52"
+#define PNG_LIBPNG_VER_STRING "1.2.54"
 #define PNG_HEADER_VERSION_STRING \
-   " libpng version 1.2.52 - November 20, 2014\n"
+   " libpng version 1.2.54 - November 12, 2015\n"
 
 #define PNG_LIBPNG_VER_SONUM   0
 #define PNG_LIBPNG_VER_DLLNUM  13
 
 /* These should match the first 3 components of PNG_LIBPNG_VER_STRING: */
 #define PNG_LIBPNG_VER_MAJOR   1
 #define PNG_LIBPNG_VER_MINOR   2
-#define PNG_LIBPNG_VER_RELEASE 52
+#define PNG_LIBPNG_VER_RELEASE 54
 /* This should match the numeric part of the final component of
  * PNG_LIBPNG_VER_STRING, omitting any leading zero:
  */
@@ -537,7 +310,7 @@
  * version 1.0.0 was mis-numbered 100 instead of 10000).  From
  * version 1.0.1 it's    xxyyzz, where x=major, y=minor, z=release
  */
-#define PNG_LIBPNG_VER 10252 /* 1.2.52 */
+#define PNG_LIBPNG_VER 10254 /* 1.2.54 */
 
 #ifndef PNG_VERSION_INFO_ONLY
 /* Include the compression library's header */
@@ -1453,16 +1226,6 @@ struct png_struct_def
    png_uint_16p hist PNG_DEPSTRUCT;                /* histogram */
 #endif
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-   png_byte heuristic_method PNG_DEPSTRUCT;        /* heuristic for row filter selection */
-   png_byte num_prev_filters PNG_DEPSTRUCT;        /* number of weights for previous rows */
-   png_bytep prev_filters PNG_DEPSTRUCT;           /* filter type(s) of previous row(s) */
-   png_uint_16p filter_weights PNG_DEPSTRUCT;      /* weight(s) for previous line(s) */
-   png_uint_16p inv_filter_weights PNG_DEPSTRUCT;  /* 1/weight(s) for previous line(s) */
-   png_uint_16p filter_costs PNG_DEPSTRUCT;        /* relative filter calculation cost */
-   png_uint_16p inv_filter_costs PNG_DEPSTRUCT;    /* 1/relative filter calculation cost */
-#endif
-
 #ifdef PNG_TIME_RFC1123_SUPPORTED
    png_charp time_buffer PNG_DEPSTRUCT;            /* String to hold RFC 1123 time text */
 #endif
@@ -1577,7 +1340,7 @@ struct png_struct_def
 /* This triggers a compiler error in png.c, if png.c and png.h
  * do not agree upon the version number.
  */
-typedef png_structp version_1_2_52;
+typedef png_structp version_1_2_54;
 
 typedef png_struct FAR * FAR * png_structpp;
 
@@ -1978,45 +1741,15 @@ extern PNG_EXPORT(void,png_set_filter) PNGARG((png_structp png_ptr, int method,
 #define PNG_FILTER_VALUE_PAETH 4
 #define PNG_FILTER_VALUE_LAST  5
 
-#if defined(PNG_WRITE_WEIGHTED_FILTER_SUPPORTED) /* EXPERIMENTAL */
-/* The "heuristic_method" is given by one of the PNG_FILTER_HEURISTIC_
- * defines, either the default (minimum-sum-of-absolute-differences), or
- * the experimental method (weighted-minimum-sum-of-absolute-differences).
- *
- * Weights are factors >= 1.0, indicating how important it is to keep the
- * filter type consistent between rows.  Larger numbers mean the current
- * filter is that many times as likely to be the same as the "num_weights"
- * previous filters.  This is cumulative for each previous row with a weight.
- * There needs to be "num_weights" values in "filter_weights", or it can be
- * NULL if the weights aren't being specified.  Weights have no influence on
- * the selection of the first row filter.  Well chosen weights can (in theory)
- * improve the compression for a given image.
- *
- * Costs are factors >= 1.0 indicating the relative decoding costs of a
- * filter type.  Higher costs indicate more decoding expense, and are
- * therefore less likely to be selected over a filter with lower computational
- * costs.  There needs to be a value in "filter_costs" for each valid filter
- * type (given by PNG_FILTER_VALUE_LAST), or it can be NULL if you aren't
- * setting the costs.  Costs try to improve the speed of decompression without
- * unduly increasing the compressed image size.
- *
- * A negative weight or cost indicates the default value is to be used, and
- * values in the range [0.0, 1.0) indicate the value is to remain unchanged.
- * The default values for both weights and costs are currently 1.0, but may
- * change if good general weighting/cost heuristics can be found.  If both
- * the weights and costs are set to 1.0, this degenerates the WEIGHTED method
- * to the UNWEIGHTED method, but with added encoding time/computation.
- */
+#if defined(PNG_WRITE_WEIGHTED_FILTER_SUPPORTED) /* DEPRECATED */
 #ifdef PNG_FLOATING_POINT_SUPPORTED
 extern PNG_EXPORT(void,png_set_filter_heuristics) PNGARG((png_structp png_ptr,
    int heuristic_method, int num_weights, png_doublep filter_weights,
    png_doublep filter_costs));
 #endif
 #endif /*  PNG_WRITE_WEIGHTED_FILTER_SUPPORTED */
 
-/* Heuristic used for row filter selection.  These defines should NOT be
- * changed.
- */
+/* The following are no longer used and will be removed from libpng-1.7: */
 #define PNG_FILTER_HEURISTIC_DEFAULT    0  /* Currently "UNWEIGHTED" */
 #define PNG_FILTER_HEURISTIC_UNWEIGHTED 1  /* Used by libpng < 0.95 */
 #define PNG_FILTER_HEURISTIC_WEIGHTED   2  /* Experimental feature */
```


### `third_party/libpng/pngconf.h`

```diff
@@ -1,17 +1,17 @@
 
 /* pngconf.h - machine configurable file for libpng
  *
- * libpng version 1.2.52 - November 20, 2014
- * Copyright (c) 1998-2013 Glenn Randers-Pehrson
+ * libpng version 1.2.54, November 12, 2015
+ *
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
  * This code is released under the libpng license.
  * For conditions of distribution and use, see the disclaimer
  * and license in png.h
- */
-
-/* Any machine specific code is near the front of this file, so if you
+ *
+ * Any machine specific code is near the front of this file, so if you
  * are configuring libpng for a machine, you may want to read the section
  * starting here down to where it starts to typedef png_color, png_text,
  * and png_info.
@@ -885,7 +885,7 @@
 
 /* Added at libpng-1.2.43 */
 #ifndef PNG_USER_CHUNK_MALLOC_MAX
-#  define PNG_USER_CHUNK_MALLOC_MAX 0
+#  define PNG_USER_CHUNK_MALLOC_MAX 8000000
 #endif
 
 #ifndef PNG_LITERAL_SHARP
```


### `third_party/libpng/pngget.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngget.c - retrieval of values from info struct
  *
- * Last changed in libpng 1.2.51 [February 6, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.53 [February 26, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -885,7 +885,8 @@ png_uint_32 PNGAPI
 png_get_asm_flags (png_structp png_ptr)
 {
     /* Obsolete, to be removed from libpng-1.4.0 */
-    return (png_ptr? 0L: 0L);
+    PNG_UNUSED(png_ptr)
+    return 0L;
 }
 
 /* This function was added to libpng 1.2.0 and should exist by default */
@@ -913,15 +914,17 @@ png_byte PNGAPI
 png_get_mmx_bitdepth_threshold (png_structp png_ptr)
 {
     /* Obsolete, to be removed from libpng-1.4.0 */
-    return (png_ptr? 0: 0);
+    PNG_UNUSED(png_ptr)
+    return 0L;
 }
 
 /* This function was added to libpng 1.2.0 */
 png_uint_32 PNGAPI
 png_get_mmx_rowbytes_threshold (png_structp png_ptr)
 {
     /* Obsolete, to be removed from libpng-1.4.0 */
-    return (png_ptr? 0L: 0L);
+    PNG_UNUSED(png_ptr)
+    return 0L;
 }
 #endif /* ?PNG_1_0_X */
 #endif /* ?PNG_ASSEMBLER_CODE_SUPPORTED */
```


### `third_party/libpng/pngpread.c`

```diff
@@ -685,9 +685,12 @@ png_push_save_buffer(png_structp png_ptr)
         png_free(png_ptr, old_buffer);
         png_error(png_ptr, "Insufficient memory for save_buffer");
       }
-      png_memcpy(png_ptr->save_buffer, old_buffer, png_ptr->save_buffer_size);
-      png_free(png_ptr, old_buffer);
-      png_ptr->save_buffer_max = new_max;
+      else
+      {
+        png_memcpy(png_ptr->save_buffer, old_buffer, png_ptr->save_buffer_size);
+        png_free(png_ptr, old_buffer);
+        png_ptr->save_buffer_max = new_max;
+      }
    }
    if (png_ptr->current_buffer_size)
    {
```


### `third_party/libpng/pngread.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngread.c - read a PNG file
  *
- * Last changed in libpng 1.2.52 [November 20, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.53 [February 26, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -274,7 +274,7 @@ png_read_init_3(png_structpp ptr_ptr, png_const_charp user_png_ver,
 
    do
    {
-      if (user_png_ver[i] != png_libpng_ver[i])
+      if (user_png_ver == NULL || user_png_ver[i] != png_libpng_ver[i])
       {
 #ifdef PNG_LEGACY_SUPPORTED
         png_ptr->flags |= PNG_FLAG_LIBRARY_MISMATCH;
@@ -597,10 +597,12 @@ png_start_read_image(png_structp png_ptr)
 void PNGAPI
 png_read_row(png_structp png_ptr, png_bytep row, png_bytep dsp_row)
 {
+#ifndef PNG_USE_GLOBAL_ARRAYS
    PNG_CONST PNG_IDAT;
    PNG_CONST int png_pass_dsp_mask[7] = {0xff, 0x0f, 0xff, 0x33, 0xff, 0x55,
       0xff};
    PNG_CONST int png_pass_mask[7] = {0x80, 0x08, 0x88, 0x22, 0xaa, 0x55, 0xff};
+#endif
    int ret;
  
    if (png_ptr == NULL)
```


### `third_party/libpng/pngrtran.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngrtran.c - transforms the data in a row for PNG readers
  *
- * Last changed in libpng 1.2.51 [February 6, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.53 [February 26, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -2410,10 +2410,14 @@ png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, png_bytep row)
                for (i = 0; i < row_width; i++)
                {
                   png_uint_16 red, green, blue, w;
+                  png_byte hi,lo;
 
-                  red   = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
-                  green = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
-                  blue  = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
+                  hi=*(sp)++; lo=*(sp)++;
+                  red   = (png_uint_16)((hi << 8) | (lo));
+                  hi=*(sp)++; lo=*(sp)++;
+                  green = (png_uint_16)((hi << 8) | (lo));
+                  hi=*(sp)++; lo=*(sp)++;
+                  blue  = (png_uint_16)((hi << 8) | (lo));
 
                   if (red == green && red == blue)
                      w = red;
@@ -2445,10 +2449,14 @@ png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, png_bytep row)
                for (i = 0; i < row_width; i++)
                {
                   png_uint_16 red, green, blue, gray16;
+                  png_byte hi,lo;
 
-                  red   = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
-                  green = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
-                  blue  = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
+                  hi=*(sp)++; lo=*(sp)++;
+                  red   = (png_uint_16)((hi << 8) | (lo));
+                  hi=*(sp)++; lo=*(sp)++;
+                  green = (png_uint_16)((hi << 8) | (lo));
+                  hi=*(sp)++; lo=*(sp)++;
+                  blue  = (png_uint_16)((hi << 8) | (lo));
 
                   if (red != green || red != blue)
                      rgb_error |= 1;
@@ -2508,10 +2516,14 @@ png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, png_bytep row)
                for (i = 0; i < row_width; i++)
                {
                   png_uint_16 red, green, blue, w;
-
-                  red   = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
-                  green = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
-                  blue  = (png_uint_16)(((*(sp))<<8) | *(sp+1)); sp+=2;
+                  png_byte hi,lo;
+
+                  hi=*(sp)++; lo=*(sp)++;
+                  red   = (png_uint_16)((hi << 8) | (lo));
+                  hi=*(sp)++; lo=*(sp)++;
+                  green = (png_uint_16)((hi << 8) | (lo));
+                  hi=*(sp)++; lo=*(sp)++;
+                  blue  = (png_uint_16)((hi << 8) | (lo));
 
                   if (red == green && red == blue)
                      w = red;
```


### `third_party/libpng/pngset.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngset.c - storage of image information into info struct
  *
- * Last changed in libpng 1.2.51 [February 6, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.54 [November 12, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -263,7 +263,10 @@ png_set_IHDR(png_structp png_ptr, png_infop info_ptr,
                  - 1        /* filter byte */
                  - 7*8      /* rounding of width to multiple of 8 pixels */
                  - 8)       /* extra max_pixel_depth pad */
+   {
       info_ptr->rowbytes = (png_size_t)0;
+      png_error(png_ptr, "Image width is too large for this architecture");
+   }
    else
       info_ptr->rowbytes = PNG_ROWBYTES(info_ptr->pixel_depth, width);
 }
@@ -446,12 +449,17 @@ png_set_PLTE(png_structp png_ptr, png_infop info_ptr,
    png_colorp palette, int num_palette)
 {
 
+   png_uint_32 max_palette_length;
+
    png_debug1(1, "in %s storage function", "PLTE");
 
    if (png_ptr == NULL || info_ptr == NULL)
       return;
 
-   if (num_palette < 0 || num_palette > PNG_MAX_PALETTE_LENGTH)
+   max_palette_length = (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE) ?
+      (1 << png_ptr->bit_depth) : PNG_MAX_PALETTE_LENGTH;
+
+   if (num_palette < 0 || num_palette > (int) max_palette_length)
    {
       if (info_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
          png_error(png_ptr, "Invalid palette length");
@@ -471,8 +479,8 @@ png_set_PLTE(png_structp png_ptr, png_infop info_ptr,
 #endif
 
    /* Changed in libpng-1.2.1 to allocate PNG_MAX_PALETTE_LENGTH instead
-    * of num_palette entries, in case of an invalid PNG file that has
-    * too-large sample values.
+    * of num_palette entries, in case of an invalid PNG file or incorrect
+    * call to png_set_PLTE() with too-large sample values.
     */
    png_ptr->palette = (png_colorp)png_calloc(png_ptr,
       PNG_MAX_PALETTE_LENGTH * png_sizeof(png_color));
@@ -770,10 +778,10 @@ png_set_text_2(png_structp png_ptr, png_infop info_ptr, png_textp text_ptr,
          (key_len + text_length + lang_len + lang_key_len + 4));
       if (textp->key == NULL)
          return(1);
-      png_debug2(2, "Allocated %lu bytes at %x in png_set_text",
+      png_debug2(2, "Allocated %lu bytes at %p in png_set_text",
                  (png_uint_32)
                  (key_len + lang_len + lang_key_len + text_length + 4),
-                 (int)textp->key);
+                 textp->key);
 
       png_memcpy(textp->key, text_ptr[i].key,(png_size_t)(key_len));
       *(textp->key + key_len) = '\0';
@@ -834,6 +842,15 @@ png_set_tIME(png_structp png_ptr, png_infop info_ptr, png_timep mod_time)
        (png_ptr->mode & PNG_WROTE_tIME))
       return;
 
+   if (mod_time->month == 0   || mod_time->month > 12  ||
+       mod_time->day   == 0   || mod_time->day   > 31  ||
+       mod_time->hour  > 23   || mod_time->minute > 59 ||
+       mod_time->second > 60)
+   {
+      png_warning(png_ptr, "Ignoring invalid time value");
+      return;
+   }
+
    png_memcpy(&(info_ptr->mod_time), mod_time, png_sizeof(png_time));
    info_ptr->valid |= PNG_INFO_tIME;
 }
```


### `third_party/libpng/pngwrite.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngwrite.c - general routines to write a PNG file
  *
- * Last changed in libpng 1.2.52 [November 20, 2014]
- * Copyright (c) 1998-2014 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.54 [November 12, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -584,11 +584,6 @@ png_create_write_struct_2(png_const_charp user_png_ver, png_voidp error_ptr,
    png_set_write_fn(png_ptr, png_voidp_NULL, png_rw_ptr_NULL,
       png_flush_ptr_NULL);
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-   png_set_filter_heuristics(png_ptr, PNG_FILTER_HEURISTIC_DEFAULT,
-      1, png_doublep_NULL, png_doublep_NULL);
-#endif
-
 #ifdef PNG_SETJMP_SUPPORTED
    /* Applications that neglect to set up their own setjmp() and then
     * encounter a png_error() will longjmp here.  Since the jmpbuf is
@@ -731,10 +726,6 @@ png_write_init_3(png_structpp ptr_ptr, png_const_charp user_png_ver,
    png_ptr->zbuf_size = PNG_ZBUF_SIZE;
    png_ptr->zbuf = (png_bytep)png_malloc(png_ptr,
      (png_uint_32)png_ptr->zbuf_size);
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-   png_set_filter_heuristics(png_ptr, PNG_FILTER_HEURISTIC_DEFAULT,
-      1, png_doublep_NULL, png_doublep_NULL);
-#endif
 }
 
 /* Write a few rows of image data.  If the image is interlaced,
@@ -1150,14 +1141,6 @@ png_write_destroy(png_structp png_ptr)
    png_free(png_ptr, png_ptr->time_buffer);
 #endif
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-   png_free(png_ptr, png_ptr->prev_filters);
-   png_free(png_ptr, png_ptr->filter_weights);
-   png_free(png_ptr, png_ptr->inv_filter_weights);
-   png_free(png_ptr, png_ptr->filter_costs);
-   png_free(png_ptr, png_ptr->inv_filter_costs);
-#endif
-
 #ifdef PNG_SETJMP_SUPPORTED
    /* Reset structure */
    png_memcpy(tmp_jmp, png_ptr->jmpbuf, png_sizeof(jmp_buf));
@@ -1201,14 +1184,13 @@ png_set_filter(png_structp png_ptr, int method, int filters)
    {
       switch (filters & (PNG_ALL_FILTERS | 0x07))
       {
+         case PNG_FILTER_VALUE_NONE:
+              png_ptr->do_filter = PNG_FILTER_NONE; break;
 #ifdef PNG_WRITE_FILTER_SUPPORTED
          case 5:
          case 6:
          case 7: png_warning(png_ptr, "Unknown row filter for method 0");
-#endif /* PNG_WRITE_FILTER_SUPPORTED */
-         case PNG_FILTER_VALUE_NONE:
-              png_ptr->do_filter = PNG_FILTER_NONE; break;
-#ifdef PNG_WRITE_FILTER_SUPPORTED
+                 break;
          case PNG_FILTER_VALUE_SUB:
               png_ptr->do_filter = PNG_FILTER_SUB; break;
          case PNG_FILTER_VALUE_UP:
@@ -1220,6 +1202,7 @@ png_set_filter(png_structp png_ptr, int method, int filters)
          default: png_ptr->do_filter = (png_byte)filters; break;
 #else
          default: png_warning(png_ptr, "Unknown row filter for method 0");
+                 break;
 #endif /* PNG_WRITE_FILTER_SUPPORTED */
       }
 
@@ -1310,117 +1293,11 @@ png_set_filter_heuristics(png_structp png_ptr, int heuristic_method,
    int num_weights, png_doublep filter_weights,
    png_doublep filter_costs)
 {
-   int i;
-
-   png_debug(1, "in png_set_filter_heuristics");
-
-   if (png_ptr == NULL)
-      return;
-   if (heuristic_method >= PNG_FILTER_HEURISTIC_LAST)
-   {
-      png_warning(png_ptr, "Unknown filter heuristic method");
-      return;
-   }
-
-   if (heuristic_method == PNG_FILTER_HEURISTIC_DEFAULT)
-   {
-      heuristic_method = PNG_FILTER_HEURISTIC_UNWEIGHTED;
-   }
-
-   if (num_weights < 0 || filter_weights == NULL ||
-      heuristic_method == PNG_FILTER_HEURISTIC_UNWEIGHTED)
-   {
-      num_weights = 0;
-   }
-
-   png_ptr->num_prev_filters = (png_byte)num_weights;
-   png_ptr->heuristic_method = (png_byte)heuristic_method;
-
-   if (num_weights > 0)
-   {
-      if (png_ptr->prev_filters == NULL)
-      {
-         png_ptr->prev_filters = (png_bytep)png_malloc(png_ptr,
-            (png_uint_32)(png_sizeof(png_byte) * num_weights));
-
-         /* To make sure that the weighting starts out fairly */
-         for (i = 0; i < num_weights; i++)
-         {
-            png_ptr->prev_filters[i] = 255;
-         }
-      }
-
-      if (png_ptr->filter_weights == NULL)
-      {
-         png_ptr->filter_weights = (png_uint_16p)png_malloc(png_ptr,
-            (png_uint_32)(png_sizeof(png_uint_16) * num_weights));
-
-         png_ptr->inv_filter_weights = (png_uint_16p)png_malloc(png_ptr,
-            (png_uint_32)(png_sizeof(png_uint_16) * num_weights));
-         for (i = 0; i < num_weights; i++)
-         {
-            png_ptr->inv_filter_weights[i] =
-            png_ptr->filter_weights[i] = PNG_WEIGHT_FACTOR;
-         }
-      }
-
-      for (i = 0; i < num_weights; i++)
-      {
-         if (filter_weights[i] < 0.0)
-         {
-            png_ptr->inv_filter_weights[i] =
-            png_ptr->filter_weights[i] = PNG_WEIGHT_FACTOR;
-         }
-         else
-         {
-            png_ptr->inv_filter_weights[i] =
-               (png_uint_16)((double)PNG_WEIGHT_FACTOR*filter_weights[i]+0.5);
-            png_ptr->filter_weights[i] =
-               (png_uint_16)((double)PNG_WEIGHT_FACTOR/filter_weights[i]+0.5);
-         }
-      }
-   }
-
-   /* If, in the future, there are other filter methods, this would
-    * need to be based on png_ptr->filter.
-    */
-   if (png_ptr->filter_costs == NULL)
-   {
-      png_ptr->filter_costs = (png_uint_16p)png_malloc(png_ptr,
-         (png_uint_32)(png_sizeof(png_uint_16) * PNG_FILTER_VALUE_LAST));
-
-      png_ptr->inv_filter_costs = (png_uint_16p)png_malloc(png_ptr,
-         (png_uint_32)(png_sizeof(png_uint_16) * PNG_FILTER_VALUE_LAST));
-
-      for (i = 0; i < PNG_FILTER_VALUE_LAST; i++)
-      {
-         png_ptr->inv_filter_costs[i] =
-         png_ptr->filter_costs[i] = PNG_COST_FACTOR;
-      }
-   }
-
-   /* Here is where we set the relative costs of the different filters.  We
-    * should take the desired compression level into account when setting
-    * the costs, so that Paeth, for instance, has a high relative cost at low
-    * compression levels, while it has a lower relative cost at higher
-    * compression settings.  The filter types are in order of increasing
-    * relative cost, so it would be possible to do this with an algorithm.
-    */
-   for (i = 0; i < PNG_FILTER_VALUE_LAST; i++)
-   {
-      if (filter_costs == NULL || filter_costs[i] < 0.0)
-      {
-         png_ptr->inv_filter_costs[i] =
-         png_ptr->filter_costs[i] = PNG_COST_FACTOR;
-      }
-      else if (filter_costs[i] >= 1.0)
-      {
-         png_ptr->inv_filter_costs[i] =
-            (png_uint_16)((double)PNG_COST_FACTOR / filter_costs[i] + 0.5);
-         png_ptr->filter_costs[i] =
-            (png_uint_16)((double)PNG_COST_FACTOR * filter_costs[i] + 0.5);
-      }
-   }
+   PNG_UNUSED(png_ptr)
+   PNG_UNUSED(heuristic_method)
+   PNG_UNUSED(num_weights)
+   PNG_UNUSED(filter_weights)
+   PNG_UNUSED(filter_costs)
 }
 #endif /* PNG_WRITE_WEIGHTED_FILTER_SUPPORTED */
 
```


### `third_party/libpng/pngwutil.c`

```diff
@@ -1,8 +1,8 @@
 
 /* pngwutil.c - utilities to write a PNG file
  *
- * Last changed in libpng 1.2.43 [February 25, 2010]
- * Copyright (c) 1998-2010 Glenn Randers-Pehrson
+ * Last changed in libpng 1.2.54 [November 12, 2015]
+ * Copyright (c) 1998-2015 Glenn Randers-Pehrson
  * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
  * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
  *
@@ -254,7 +254,7 @@ png_text_compress(png_structp png_ptr,
                old_ptr = comp->output_ptr;
                comp->output_ptr = (png_charpp)png_malloc(png_ptr,
                   (png_uint_32)
-                  (comp->max_output_ptr * png_sizeof(png_charpp)));
+                  (comp->max_output_ptr * png_sizeof(png_charp)));
                png_memcpy(comp->output_ptr, old_ptr, old_max
                   * png_sizeof(png_charp));
                png_free(png_ptr, old_ptr);
@@ -575,17 +575,20 @@ png_write_PLTE(png_structp png_ptr, png_colorp palette, png_uint_32 num_pal)
 #ifdef PNG_USE_LOCAL_ARRAYS
    PNG_PLTE;
 #endif
-   png_uint_32 i;
+   png_uint_32 max_palette_length, i;
    png_colorp pal_ptr;
    png_byte buf[3];
 
    png_debug(1, "in png_write_PLTE");
 
+   max_palette_length = (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE) ?
+      (1 << png_ptr->bit_depth) : PNG_MAX_PALETTE_LENGTH;
+
    if ((
 #ifdef PNG_MNG_FEATURES_SUPPORTED
         !(png_ptr->mng_features_permitted & PNG_FLAG_MNG_EMPTY_PLTE) &&
 #endif
-        num_pal == 0) || num_pal > 256)
+       num_pal == 0) || num_pal > max_palette_length)
    {
      if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
      {
@@ -1759,6 +1762,7 @@ void /* PRIVATE */
 png_write_start_row(png_structp png_ptr)
 {
 #ifdef PNG_WRITE_INTERLACING_SUPPORTED
+#ifndef PNG_USE_GLOBAL_ARRAYS
    /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
 
    /* Start of interlace block */
@@ -1772,6 +1776,7 @@ png_write_start_row(png_structp png_ptr)
 
    /* Offset to next interlace block in the y direction */
    int png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+#endif
 #endif
 
    png_size_t buf_size;
@@ -1857,6 +1862,7 @@ void /* PRIVATE */
 png_write_finish_row(png_structp png_ptr)
 {
 #ifdef PNG_WRITE_INTERLACING_SUPPORTED
+#ifndef PNG_USE_GLOBAL_ARRAYS
    /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
 
    /* Start of interlace block */
@@ -1870,6 +1876,7 @@ png_write_finish_row(png_structp png_ptr)
 
    /* Offset to next interlace block in the y direction */
    int png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+#endif
 #endif
 
    int ret;
@@ -1976,11 +1983,13 @@ png_do_write_interlace(png_row_infop row_info, png_bytep row, int pass)
 {
    /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
 
+#ifndef PNG_USE_GLOBAL_ARRAYS
    /* Start of interlace block */
    int png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
 
    /* Offset to next interlace block */
    int png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
+#endif
 
    png_debug(1, "in png_do_write_interlace");
 
@@ -2150,20 +2159,9 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
    png_uint_32 mins, bpp;
    png_byte filter_to_do = png_ptr->do_filter;
    png_uint_32 row_bytes = row_info->rowbytes;
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-   int num_p_filters = (int)png_ptr->num_prev_filters;
-#endif 
 
    png_debug(1, "in png_write_find_filter");
 
-#ifndef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-  if (png_ptr->row_number == 0 && filter_to_do == PNG_ALL_FILTERS)
-  {
-      /* These will never be selected so we need not test them. */
-      filter_to_do &= ~(PNG_FILTER_UP | PNG_FILTER_PAETH);
-  }
-#endif 
-
    /* Find out how many bytes offset each pixel is */
    bpp = (row_info->pixel_depth + 7) >> 3;
 
@@ -2213,41 +2211,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
          sum += (v < 128) ? v : 256 - v;
       }
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         png_uint_32 sumhi, sumlo;
-         int j;
-         sumlo = sum & PNG_LOMASK;
-         sumhi = (sum >> PNG_HISHIFT) & PNG_HIMASK; /* Gives us some footroom */
-
-         /* Reduce the sum if we match any of the previous rows */
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_NONE)
-            {
-               sumlo = (sumlo * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               sumhi = (sumhi * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         /* Factor in the cost of this filter (this is here for completeness,
-          * but it makes no sense to have a "cost" for the NONE filter, as
-          * it has the minimum possible computational cost - none).
-          */
-         sumlo = (sumlo * png_ptr->filter_costs[PNG_FILTER_VALUE_NONE]) >>
-            PNG_COST_SHIFT;
-         sumhi = (sumhi * png_ptr->filter_costs[PNG_FILTER_VALUE_NONE]) >>
-            PNG_COST_SHIFT;
-
-         if (sumhi > PNG_HIMASK)
-            sum = PNG_MAXSUM;
-         else
-            sum = (sumhi << PNG_HISHIFT) + sumlo;
-      }
-#endif
       mins = sum;
    }
 
@@ -2277,41 +2240,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
       png_uint_32 i;
       int v;
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      /* We temporarily increase the "minimum sum" by the factor we
-       * would reduce the sum of this filter, so that we can do the
-       * early exit comparison without scaling the sum each time.
-       */
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 lmhi, lmlo;
-         lmlo = lmins & PNG_LOMASK;
-         lmhi = (lmins >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_SUB)
-            {
-               lmlo = (lmlo * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               lmhi = (lmhi * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         lmlo = (lmlo * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_SUB]) >>
-            PNG_COST_SHIFT;
-         lmhi = (lmhi * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_SUB]) >>
-            PNG_COST_SHIFT;
-
-         if (lmhi > PNG_HIMASK)
-            lmins = PNG_MAXSUM;
-         else
-            lmins = (lmhi << PNG_HISHIFT) + lmlo;
-      }
-#endif
-
       for (i = 0, rp = row_buf + 1, dp = png_ptr->sub_row + 1; i < bpp;
            i++, rp++, dp++)
       {
@@ -2330,37 +2258,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
             break;
       }
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 sumhi, sumlo;
-         sumlo = sum & PNG_LOMASK;
-         sumhi = (sum >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_SUB)
-            {
-               sumlo = (sumlo * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               sumhi = (sumhi * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         sumlo = (sumlo * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_SUB]) >>
-            PNG_COST_SHIFT;
-         sumhi = (sumhi * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_SUB]) >>
-            PNG_COST_SHIFT;
-
-         if (sumhi > PNG_HIMASK)
-            sum = PNG_MAXSUM;
-         else
-            sum = (sumhi << PNG_HISHIFT) + sumlo;
-      }
-#endif
-
       if (sum < mins)
       {
          mins = sum;
@@ -2390,38 +2287,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
       png_uint_32 i;
       int v;
 
-
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 lmhi, lmlo;
-         lmlo = lmins & PNG_LOMASK;
-         lmhi = (lmins >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_UP)
-            {
-               lmlo = (lmlo * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               lmhi = (lmhi * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         lmlo = (lmlo * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_UP]) >>
-            PNG_COST_SHIFT;
-         lmhi = (lmhi * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_UP]) >>
-            PNG_COST_SHIFT;
-
-         if (lmhi > PNG_HIMASK)
-            lmins = PNG_MAXSUM;
-         else
-            lmins = (lmhi << PNG_HISHIFT) + lmlo;
-      }
-#endif
-
       for (i = 0, rp = row_buf + 1, dp = png_ptr->up_row + 1,
            pp = prev_row + 1; i < row_bytes; i++)
       {
@@ -2433,37 +2298,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
             break;
       }
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 sumhi, sumlo;
-         sumlo = sum & PNG_LOMASK;
-         sumhi = (sum >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_UP)
-            {
-               sumlo = (sumlo * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               sumhi = (sumhi * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         sumlo = (sumlo * png_ptr->filter_costs[PNG_FILTER_VALUE_UP]) >>
-            PNG_COST_SHIFT;
-         sumhi = (sumhi * png_ptr->filter_costs[PNG_FILTER_VALUE_UP]) >>
-            PNG_COST_SHIFT;
-
-         if (sumhi > PNG_HIMASK)
-            sum = PNG_MAXSUM;
-         else
-            sum = (sumhi << PNG_HISHIFT) + sumlo;
-      }
-#endif
-
       if (sum < mins)
       {
          mins = sum;
@@ -2496,37 +2330,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
       png_uint_32 i;
       int v;
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 lmhi, lmlo;
-         lmlo = lmins & PNG_LOMASK;
-         lmhi = (lmins >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_AVG)
-            {
-               lmlo = (lmlo * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               lmhi = (lmhi * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         lmlo = (lmlo * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_AVG]) >>
-            PNG_COST_SHIFT;
-         lmhi = (lmhi * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_AVG]) >>
-            PNG_COST_SHIFT;
-
-         if (lmhi > PNG_HIMASK)
-            lmins = PNG_MAXSUM;
-         else
-            lmins = (lmhi << PNG_HISHIFT) + lmlo;
-      }
-#endif
-
       for (i = 0, rp = row_buf + 1, dp = png_ptr->avg_row + 1,
            pp = prev_row + 1; i < bpp; i++)
       {
@@ -2545,37 +2348,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
             break;
       }
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 sumhi, sumlo;
-         sumlo = sum & PNG_LOMASK;
-         sumhi = (sum >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_NONE)
-            {
-               sumlo = (sumlo * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               sumhi = (sumhi * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         sumlo = (sumlo * png_ptr->filter_costs[PNG_FILTER_VALUE_AVG]) >>
-            PNG_COST_SHIFT;
-         sumhi = (sumhi * png_ptr->filter_costs[PNG_FILTER_VALUE_AVG]) >>
-            PNG_COST_SHIFT;
-
-         if (sumhi > PNG_HIMASK)
-            sum = PNG_MAXSUM;
-         else
-            sum = (sumhi << PNG_HISHIFT) + sumlo;
-      }
-#endif
-
       if (sum < mins)
       {
          mins = sum;
@@ -2629,37 +2401,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
       png_uint_32 i;
       int v;
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 lmhi, lmlo;
-         lmlo = lmins & PNG_LOMASK;
-         lmhi = (lmins >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_PAETH)
-            {
-               lmlo = (lmlo * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               lmhi = (lmhi * png_ptr->inv_filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         lmlo = (lmlo * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_PAETH]) >>
-            PNG_COST_SHIFT;
-         lmhi = (lmhi * png_ptr->inv_filter_costs[PNG_FILTER_VALUE_PAETH]) >>
-            PNG_COST_SHIFT;
-
-         if (lmhi > PNG_HIMASK)
-            lmins = PNG_MAXSUM;
-         else
-            lmins = (lmhi << PNG_HISHIFT) + lmlo;
-      }
-#endif
-
       for (i = 0, rp = row_buf + 1, dp = png_ptr->paeth_row + 1,
            pp = prev_row + 1; i < bpp; i++)
       {
@@ -2710,37 +2451,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
             break;
       }
 
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-      if (png_ptr->heuristic_method == PNG_FILTER_HEURISTIC_WEIGHTED)
-      {
-         int j;
-         png_uint_32 sumhi, sumlo;
-         sumlo = sum & PNG_LOMASK;
-         sumhi = (sum >> PNG_HISHIFT) & PNG_HIMASK;
-
-         for (j = 0; j < num_p_filters; j++)
-         {
-            if (png_ptr->prev_filters[j] == PNG_FILTER_VALUE_PAETH)
-            {
-               sumlo = (sumlo * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-               sumhi = (sumhi * png_ptr->filter_weights[j]) >>
-                  PNG_WEIGHT_SHIFT;
-            }
-         }
-
-         sumlo = (sumlo * png_ptr->filter_costs[PNG_FILTER_VALUE_PAETH]) >>
-            PNG_COST_SHIFT;
-         sumhi = (sumhi * png_ptr->filter_costs[PNG_FILTER_VALUE_PAETH]) >>
-            PNG_COST_SHIFT;
-
-         if (sumhi > PNG_HIMASK)
-            sum = PNG_MAXSUM;
-         else
-            sum = (sumhi << PNG_HISHIFT) + sumlo;
-      }
-#endif
-
       if (sum < mins)
       {
          best_row = png_ptr->paeth_row;
@@ -2750,21 +2460,6 @@ png_write_find_filter(png_structp png_ptr, png_row_infop row_info)
    /* Do the actual writing of the filtered row data from the chosen filter. */
 
    png_write_filtered_row(png_ptr, best_row);
-
-#ifdef PNG_WRITE_FILTER_SUPPORTED
-#ifdef PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
-   /* Save the type of filter we picked this time for future calculations */
-   if (png_ptr->num_prev_filters > 0)
-   {
-      int j;
-      for (j = 1; j < num_p_filters; j++)
-      {
-         png_ptr->prev_filters[j] = png_ptr->prev_filters[j - 1];
-      }
-      png_ptr->prev_filters[j] = best_row[0];
-   }
-#endif
-#endif /* PNG_WRITE_FILTER_SUPPORTED */
 }
 
 
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
