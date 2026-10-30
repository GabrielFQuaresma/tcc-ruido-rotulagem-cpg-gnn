# Pacote de anotacao — caso 01

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

# Evidencia do caso 01

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `coders/clipboard.c`

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -32,7 +32,7 @@
      bitmapH=(HBITMAP) GetClipboardData(CF_BITMAP);
      hPal=(HPALETTE) GetClipboardData(CF_PALETTE);
      CloseClipboard();
-    if ( bitmapH == NULL )
+    if (bitmapH == NULL)
        ThrowReaderException(CoderError,"NoBitmapOnClipboard");
      {
        BITMAPINFO
@@ -59,8 +59,14 @@
        GetObject(bitmapH,sizeof(BITMAP),(LPSTR) &bitmap);
        if ((image->columns == 0) || (image->rows == 0))
          {
+           image->columns=bitmap.bmWidth;
           image->rows=bitmap.bmHeight;
-           image->columns=bitmap.bmWidth;
+        }
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
          }
        /*
          Initialize the bitmap header info.
```

## Corpo completo da funcao antes da correcao

```c
static Image *ReadCLIPBOARDImage(const ImageInfo *image_info,
  ExceptionInfo *exception)
{
  Image
    *image;

  register ssize_t
    x;

  register PixelPacket
    *q;

  ssize_t
    y;

  assert(image_info != (const ImageInfo *) NULL);
  assert(image_info->signature == MagickSignature);
  if (image_info->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",
      image_info->filename);
  assert(exception != (ExceptionInfo *) NULL);
  assert(exception->signature == MagickSignature);
  image=AcquireImage(image_info);
  {
    HBITMAP
      bitmapH;

    HPALETTE
      hPal;

    OpenClipboard(NULL);
     bitmapH=(HBITMAP) GetClipboardData(CF_BITMAP);
     hPal=(HPALETTE) GetClipboardData(CF_PALETTE);
     CloseClipboard();
    if ( bitmapH == NULL )
       ThrowReaderException(CoderError,"NoBitmapOnClipboard");
     {
       BITMAPINFO
        DIBinfo;

      BITMAP
        bitmap;

      HBITMAP
        hBitmap,
        hOldBitmap;

      HDC
        hDC,
        hMemDC;

      RGBQUAD
        *pBits,
        *ppBits;

      /* create an offscreen DC for the source */
      hMemDC=CreateCompatibleDC(NULL);
      hOldBitmap=(HBITMAP) SelectObject(hMemDC,bitmapH);
       GetObject(bitmapH,sizeof(BITMAP),(LPSTR) &bitmap);
       if ((image->columns == 0) || (image->rows == 0))
         {
          image->rows=bitmap.bmHeight;
           image->columns=bitmap.bmWidth;
         }
       /*
         Initialize the bitmap header info.
      */
      (void) ResetMagickMemory(&DIBinfo,0,sizeof(BITMAPINFO));
      DIBinfo.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
      DIBinfo.bmiHeader.biWidth=(LONG) image->columns;
      DIBinfo.bmiHeader.biHeight=(-1)*(LONG) image->rows;
      DIBinfo.bmiHeader.biPlanes=1;
      DIBinfo.bmiHeader.biBitCount=32;
      DIBinfo.bmiHeader.biCompression=BI_RGB;
      hDC=GetDC(NULL);
      if (hDC == 0)
        ThrowReaderException(CoderError,"UnableToCreateADC");
      hBitmap=CreateDIBSection(hDC,&DIBinfo,DIB_RGB_COLORS,(void **) &ppBits,
        NULL,0);
      ReleaseDC(NULL,hDC);
      if (hBitmap == 0)
        ThrowReaderException(CoderError,"UnableToCreateBitmap");
      /* create an offscreen DC */
      hDC=CreateCompatibleDC(NULL);
      if (hDC == 0)
        {
          DeleteObject(hBitmap);
          ThrowReaderException(CoderError,"UnableToCreateADC");
        }
      hOldBitmap=(HBITMAP) SelectObject(hDC,hBitmap);
      if (hOldBitmap == 0)
        {
          DeleteDC(hDC);
          DeleteObject(hBitmap);
          ThrowReaderException(CoderError,"UnableToCreateBitmap");
        }
      if (hPal != NULL)
      {
        /* Kenichi Masuko says this needed */
        SelectPalette(hDC, hPal, FALSE);
        RealizePalette(hDC);
      }
      /* bitblt from the memory to the DIB-based one */
      BitBlt(hDC,0,0,(int) image->columns,(int) image->rows,hMemDC,0,0,SRCCOPY);
      /* finally copy the pixels! */
      pBits=ppBits;
      for (y=0; y < (ssize_t) image->rows; y++)
      {
        q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
        if (q == (PixelPacket *) NULL)
          break;
        for (x=0; x < (ssize_t) image->columns; x++)
        {
          SetPixelRed(q,ScaleCharToQuantum(pBits->rgbRed));
          SetPixelGreen(q,ScaleCharToQuantum(pBits->rgbGreen));
          SetPixelBlue(q,ScaleCharToQuantum(pBits->rgbBlue));
          SetPixelOpacity(q,OpaqueOpacity);
          pBits++;
          q++;
        }
        if (SyncAuthenticPixels(image,exception) == MagickFalse)
          break;
      }
      DeleteDC(hDC);
      DeleteObject(hBitmap);
    }
  }
  (void) CloseBlob(image);
  return(GetFirstImageInList(image));
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **84**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `ChangeLog` | modified | 2 | 0 |
| `coders/aai.c` | modified | 6 | 0 |
| `coders/art.c` | modified | 6 | 0 |
| `coders/avs.c` | modified | 6 | 0 |
| `coders/bgr.c` | modified | 6 | 0 |
| `coders/bmp.c` | modified | 6 | 0 |
| `coders/cin.c` | modified | 7 | 1 |
| `coders/clipboard.c` **(funcao marcada esta aqui)** | modified | 8 | 2 |
| `coders/cmyk.c` | modified | 6 | 0 |
| `coders/cut.c` | modified | 7 | 1 |
| `coders/dcm.c` | modified | 6 | 0 |
| `coders/dds.c` | modified | 6 | 0 |
| `coders/dib.c` | modified | 7 | 1 |
| `coders/djvu.c` | modified | 8 | 1 |
| `coders/dps.c` | modified | 6 | 0 |
| `coders/dpx.c` | modified | 6 | 0 |
| `coders/emf.c` | modified | 6 | 0 |
| `coders/exr.c` | modified | 6 | 0 |
| `coders/fax.c` | modified | 6 | 0 |
| `coders/fits.c` | modified | 6 | 0 |
| `coders/fpx.c` | modified | 6 | 0 |
| `coders/gif.c` | modified | 6 | 0 |
| `coders/gray.c` | modified | 6 | 0 |
| `coders/hald.c` | modified | 7 | 2 |
| `coders/hdr.c` | modified | 6 | 0 |
| `coders/hrz.c` | modified | 6 | 0 |
| `coders/icon.c` | modified | 6 | 0 |
| `coders/ipl.c` | modified | 7 | 1 |
| `coders/jbig.c` | modified | 6 | 0 |
| `coders/jp2.c` | modified | 6 | 0 |
| `coders/jpeg.c` | modified | 6 | 0 |
| `coders/label.c` | modified | 6 | 0 |
| `coders/mac.c` | modified | 6 | 0 |
| `coders/map.c` | modified | 6 | 0 |
| `coders/mat.c` | modified | 6 | 0 |
| `coders/miff.c` | modified | 6 | 0 |
| `coders/mono.c` | modified | 6 | 0 |
| `coders/mpc.c` | modified | 6 | 0 |
| `coders/mtv.c` | modified | 6 | 0 |
| `coders/mvg.c` | modified | 6 | 0 |
| `coders/null.c` | modified | 9 | 0 |
| `coders/otb.c` | modified | 6 | 0 |
| `coders/palm.c` | modified | 6 | 0 |
| `coders/pango.c` | modified | 8 | 2 |
| `coders/pcd.c` | modified | 6 | 0 |
| `coders/pcx.c` | modified | 6 | 0 |
| `coders/pdb.c` | modified | 6 | 0 |
| `coders/pict.c` | modified | 6 | 0 |
| `coders/pix.c` | modified | 6 | 0 |
| `coders/psd.c` | modified | 6 | 0 |
| `coders/raw.c` | modified | 6 | 0 |
| `coders/rgb.c` | modified | 6 | 0 |
| `coders/rgf.c` | modified | 6 | 2 |
| `coders/rla.c` | modified | 6 | 0 |
| `coders/rle.c` | modified | 6 | 0 |
| `coders/scr.c` | modified | 6 | 0 |
| `coders/screenshot.c` | modified | 9 | 1 |
| `coders/sct.c` | modified | 6 | 0 |
| `coders/sgi.c` | modified | 6 | 0 |
| `coders/sixel.c` | modified | 6 | 1 |
| `coders/stegano.c` | modified | 6 | 0 |
| `coders/sun.c` | modified | 6 | 0 |
| `coders/svg.c` | modified | 6 | 0 |
| `coders/tga.c` | modified | 6 | 0 |
| `coders/tiff.c` | modified | 6 | 0 |
| `coders/tile.c` | modified | 9 | 0 |
| `coders/tim.c` | modified | 6 | 0 |
| `coders/ttf.c` | modified | 6 | 0 |
| `coders/txt.c` | modified | 12 | 0 |
| `coders/uyvy.c` | modified | 6 | 0 |
| `coders/vicar.c` | modified | 6 | 0 |
| `coders/viff.c` | modified | 6 | 0 |
| `coders/vips.c` | modified | 6 | 0 |
| `coders/wbmp.c` | modified | 6 | 0 |
| `coders/webp.c` | modified | 6 | 0 |
| `coders/wmf.c` | modified | 9 | 0 |
| `coders/wpg.c` | modified | 6 | 0 |
| `coders/xbm.c` | modified | 6 | 0 |
| `coders/xc.c` | modified | 6 | 0 |
| `coders/xcf.c` | modified | 6 | 0 |
| `coders/xpm.c` | modified | 6 | 0 |
| `coders/xwd.c` | modified | 6 | 0 |
| `coders/ycbcr.c` | modified | 12 | 0 |
| `coders/yuv.c` | modified | 12 | 0 |


### `coders/clipboard.c`

```diff
@@ -136,7 +136,7 @@ static Image *ReadCLIPBOARDImage(const ImageInfo *image_info,
     bitmapH=(HBITMAP) GetClipboardData(CF_BITMAP);
     hPal=(HPALETTE) GetClipboardData(CF_PALETTE);
     CloseClipboard();
-    if ( bitmapH == NULL )
+    if (bitmapH == NULL)
       ThrowReaderException(CoderError,"NoBitmapOnClipboard");
     {
       BITMAPINFO
@@ -163,8 +163,14 @@ static Image *ReadCLIPBOARDImage(const ImageInfo *image_info,
       GetObject(bitmapH,sizeof(BITMAP),(LPSTR) &bitmap);
       if ((image->columns == 0) || (image->rows == 0))
         {
-          image->rows=bitmap.bmHeight;
           image->columns=bitmap.bmWidth;
+          image->rows=bitmap.bmHeight;
+        }
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
         }
       /*
         Initialize the bitmap header info.
```


### `ChangeLog`

```diff
@@ -22,6 +22,8 @@
     Mateusz Jurczyk of the Google Security Team).
   * Additional PNM sanity checks (reference
     [url removida]
+  * The SetImageBias() biad value is no longer ignored (reference
+    [url removida]
 
 2014-11-16  6.9.0-0 Cristy  <quetzlzacatenango@image...>
   * New version 6.9.0-0, SVN revision 17067.
```


### `coders/aai.c`

```diff
@@ -158,6 +158,12 @@ static Image *ReadAAIImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     pixels=(unsigned char *) AcquireQuantumMemory(image->columns,
       4*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
```


### `coders/art.c`

```diff
@@ -155,6 +155,12 @@ static Image *ReadARTImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/avs.c`

```diff
@@ -160,6 +160,12 @@ static Image *ReadAVSImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     pixels=(unsigned char *) AcquireQuantumMemory(image->columns,
       4*sizeof(*pixels));
     if (pixels == (unsigned char *) NULL)
```


### `coders/bgr.c`

```diff
@@ -197,6 +197,12 @@ static Image *ReadBGRImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     switch (image_info->interlace)
     {
       case NoInterlace:
```


### `coders/bmp.c`

```diff
@@ -928,6 +928,12 @@ static Image *ReadBMPImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Read image data.
     */
```


### `coders/cin.c`

```diff
@@ -721,11 +721,17 @@ static Image *ReadCINImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->depth=cin.image.channel[0].bits_per_pixel;
   image->columns=cin.image.channel[0].pixels_per_line;
   image->rows=cin.image.channel[0].lines_per_image;
-  if (image_info->ping)
+  if (image_info->ping != MagickFalse)
     {
       (void) CloseBlob(image);
       return(image);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert CIN raster image to pixel packets.
   */
```


### `coders/cmyk.c`

```diff
@@ -197,6 +197,12 @@ static Image *ReadCMYKImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     SetImageColorspace(image,CMYKColorspace);
     switch (image_info->interlace)
     {
```


### `coders/cut.c`

```diff
@@ -371,7 +371,13 @@ static Image *ReadCUTImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->depth=8;
   image->colors=(size_t) (GetQuantumRange(1UL*i)+1);
 
-  if (image_info->ping) goto Finish;
+  if (image_info->ping != MagickFalse) goto Finish;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
 
   /* ----- Do something with palette ----- */
   if ((clone_info=CloneImageInfo(image_info)) == NULL) goto NoPalette;
```


### `coders/dcm.c`

```diff
@@ -3689,6 +3689,12 @@ static Image *ReadDCMImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->columns=(size_t) width;
     image->rows=(size_t) height;
     image->depth=depth;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        break;
+      }
     image->colorspace=RGBColorspace;
     if ((image->colormap == (PixelPacket *) NULL) && (samples_per_pixel == 1))
       {
```


### `coders/dds.c`

```diff
@@ -1834,6 +1834,12 @@ static Image *ReadDDSImage(const ImageInfo *image_info,ExceptionInfo *exception)
         (void) CloseBlob(image);
         return(GetFirstImageInList(image));
       }
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
 
     if ((decoder)(image, &dds_info, exception) != MagickTrue)
       {
```


### `coders/dib.c`

```diff
@@ -520,7 +520,7 @@ static Image *ReadDIBImage(const ImageInfo *image_info,ExceptionInfo *exception)
   */
   (void) ResetMagickMemory(&dib_info,0,sizeof(dib_info));
   dib_info.size=ReadBlobLSBLong(image);
-  if (dib_info.size!=40)
+  if (dib_info.size != 40)
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   /*
     Microsoft Windows 3.X DIB image file.
@@ -573,6 +573,12 @@ static Image *ReadDIBImage(const ImageInfo *image_info,ExceptionInfo *exception)
         if ((geometry.height != 0) && (geometry.height < image->rows))
           image->rows=geometry.height;
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (image->storage_class == PseudoClass)
     {
       size_t
```


### `coders/djvu.c`

```diff
@@ -418,7 +418,7 @@ get_page_image(LoadContext *lc, ddjvu_page_t *page, int x, int y, int w, int h,
                                 if (SyncAuthenticPixels(image,&image->exception) == MagickFalse)
                                         break;
                         }
-                if (!image->ping)
+                if (image->ping == MagickFalse)
                   SyncImage(image);
         } else {
 #if DEBUG
@@ -577,6 +577,7 @@ static Image *ReadOneDJVUImage(LoadContext* lc,const int pagenum,
   Image *image;
   int logging;
   int tag;
+  MagickBooleanType status;
 
         /* so, we know that the page is there! Get its dimension, and  */
 
@@ -667,6 +668,12 @@ static Image *ReadOneDJVUImage(LoadContext* lc,const int pagenum,
                 image->matte = MagickTrue;
                 /* is this useful? */
         }
+        status=SetImageExtent(image,image->columns,image->rows);
+        if (status == MagickFalse)
+          {
+            InheritException(exception,&image->exception);
+            return(DestroyImageList(image));
+          }
 #if DEBUG
         printf("now filling %.20g x %.20g\n",(double) image->columns,(double)
           image->rows);
```


### `coders/dps.c`

```diff
@@ -328,6 +328,12 @@ static Image *ReadDPSImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   switch (image->storage_class)
   {
     case DirectClass:
```


### `coders/dpx.c`

```diff
@@ -1126,6 +1126,12 @@ static Image *ReadDPXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   for (n=0; n < (ssize_t) dpx.image.number_elements; n++)
   {
     /*
```


### `coders/emf.c`

```diff
@@ -507,6 +507,12 @@ static Image *ReadEMFImage(const ImageInfo *image_info,
       y=0;
       (void) GetGeometry(image_info->size,&x,&y,&image->columns,&image->rows);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (image_info->page != (char *) NULL)
     {
       char
```


### `coders/exr.c`

```diff
@@ -212,6 +212,12 @@ static Image *ReadEXRImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   scanline=(ImfRgba *) AcquireQuantumMemory(image->columns,sizeof(*scanline));
   if (scanline == (ImfRgba *) NULL)
     {
```


### `coders/fax.c`

```diff
@@ -178,6 +178,12 @@ static Image *ReadFAXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   status=HuffmanDecodeImage(image);
   if (status == MagickFalse)
     ThrowReaderException(CorruptImageError,"UnableToReadImageData");
```


### `coders/fits.c`

```diff
@@ -423,6 +423,12 @@ static Image *ReadFITSImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Initialize image structure.
     */
```


### `coders/fpx.c`

```diff
@@ -352,6 +352,12 @@ static Image *ReadFPXImage(const ImageInfo *image_info,ExceptionInfo *exception)
       FPX_ClearSystem();
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Allocate memory for the image and pixel buffer.
   */
```


### `coders/gif.c`

```diff
@@ -1350,6 +1350,12 @@ static Image *ReadGIFImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Decode image.
     */
```


### `coders/gray.c`

```diff
@@ -187,6 +187,12 @@ static Image *ReadGRAYImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     SetImageColorspace(image,GRAYColorspace);
     if (scene == 0)
       {
```


### `coders/hald.c`

```diff
@@ -125,6 +125,12 @@ static Image *ReadHALDImage(const ImageInfo *image_info,
   cube_size=level*level;
   image->columns=(size_t) (level*cube_size);
   image->rows=(size_t) (level*cube_size);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   for (y=0; y < (ssize_t) image->rows; y+=(ssize_t) level)
   {
     ssize_t
@@ -137,8 +143,7 @@ static Image *ReadHALDImage(const ImageInfo *image_info,
 
     if (status == MagickFalse)
       continue;
-    q=QueueAuthenticPixels(image,0,y,image->columns,(size_t) level,
-      exception);
+    q=QueueAuthenticPixels(image,0,y,image->columns,(size_t) level,exception);
     if (q == (PixelPacket *) NULL)
       {
         status=MagickFalse;
```


### `coders/hdr.c`

```diff
@@ -382,6 +382,12 @@ static Image *ReadHDRImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read RGBE (red+green+blue+exponent) pixels.
   */
```


### `coders/hrz.c`

```diff
@@ -142,6 +142,12 @@ static Image *ReadHRZImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->columns=256;
   image->rows=240;
   image->depth=8;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   pixels=(unsigned char *) AcquireQuantumMemory(image->columns,3*
     sizeof(*pixels));
   if (pixels == (unsigned char *) NULL)
```


### `coders/icon.c`

```diff
@@ -462,6 +462,12 @@ static Image *ReadICONImage(const ImageInfo *image_info,
             (image_info->number_scenes != 0))
           if (image->scene >= (image_info->scene+image_info->number_scenes-1))
             break;
+        status=SetImageExtent(image,image->columns,image->rows);
+        if (status == MagickFalse)
+          {
+            InheritException(exception,&image->exception);
+            return(DestroyImageList(image));
+          }
         bytes_per_line=(((image->columns*icon_info.bits_per_pixel)+31) &
           ~31) >> 3;
         (void) bytes_per_line;
```


### `coders/ipl.c`

```diff
@@ -315,9 +315,15 @@ static Image *ReadIPLImage(const ImageInfo *image_info,ExceptionInfo *exception)
   {
     SetHeaderFromIPL(image, &ipl_info);
 
-  if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
+    if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
 /*
    printf("Length: %.20g, Memory size: %.20g\n", (double) length,(double)
      image->depth);
```


### `coders/jbig.c`

```diff
@@ -219,6 +219,12 @@ static Image *ReadJBIGImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert X bitmap image to pixel packets.
   */
```


### `coders/jp2.c`

```diff
@@ -398,6 +398,12 @@ static Image *ReadJP2Image(const ImageInfo *image_info,ExceptionInfo *exception)
   image->columns=(size_t) jp2_image->comps[0].w;
   image->rows=(size_t) jp2_image->comps[0].h;
   image->depth=jp2_image->comps[0].prec;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   image->compression=JPEG2000Compression;
   if (jp2_image->numcomps <= 2)
     {
```


### `coders/jpeg.c`

```diff
@@ -1263,6 +1263,12 @@ static Image *ReadJPEGImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   memory_info=AcquireVirtualMemory((size_t) image->columns,
     jpeg_info.output_components*sizeof(*jpeg_pixels));
   if (memory_info == (MemoryInfo *) NULL)
```


### `coders/label.c`

```diff
@@ -213,6 +213,12 @@ static Image *ReadLABELImage(const ImageInfo *image_info,
       draw_info->stroke_width+0.5);
   if (image->rows == 0)
     image->rows=(size_t) (draw_info->pointsize+draw_info->stroke_width+0.5);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (draw_info->gravity == UndefinedGravity)
     {
       (void) FormatLocaleString(geometry,MaxTextExtent,"%+g%+g",
```


### `coders/mac.c`

```diff
@@ -156,6 +156,12 @@ static Image *ReadMACImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert MAC raster image to pixel packets.
   */
```


### `coders/map.c`

```diff
@@ -206,6 +206,12 @@ static Image *ReadMAPImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read image pixels.
   */
```


### `coders/mat.c`

```diff
@@ -874,6 +874,12 @@ RestoreMSCWarning
       image->rows = temp;
       goto done_reading; /* !!!!!! BAD  !!!! */
     }
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
 
   /* ----- Load raster data ----- */
     BImgBuff = (unsigned char *) AcquireQuantumMemory((size_t) (ldblk),sizeof(unsigned char));    /* Ldblk was set in the check phase */
```


### `coders/miff.c`

```diff
@@ -1246,6 +1246,12 @@ static Image *ReadMIFFImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Allocate image pixels.
     */
```


### `coders/mono.c`

```diff
@@ -154,6 +154,12 @@ static Image *ReadMONOImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/mpc.c`

```diff
@@ -929,6 +929,12 @@ static Image *ReadMPCImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Attach persistent pixel cache.
     */
```


### `coders/mtv.c`

```diff
@@ -158,6 +158,12 @@ static Image *ReadMTVImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Convert MTV raster image to pixel packets.
     */
```


### `coders/mvg.c`

```diff
@@ -190,6 +190,12 @@ static Image *ReadMVGImage(const ImageInfo *image_info,ExceptionInfo *exception)
     DefaultResolution;
   image->columns=(size_t) (draw_info->affine.sx*image->columns);
   image->rows=(size_t) (draw_info->affine.sy*image->rows);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (SetImageBackgroundColor(image) == MagickFalse)
     {
       InheritException(exception,&image->exception);
```


### `coders/null.c`

```diff
@@ -99,6 +99,9 @@ static Image *ReadNULLImage(const ImageInfo *image_info,
   Image
     *image;
 
+  MagickBooleanType
+    status;
+
   MagickPixelPacket
     background;
 
@@ -129,6 +132,12 @@ static Image *ReadNULLImage(const ImageInfo *image_info,
     image->columns=1;
   if (image->rows == 0)
     image->rows=1;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   image->matte=MagickTrue;
   GetMagickPixelPacket(image,&background);
   background.opacity=(MagickRealType) TransparentOpacity;
```


### `coders/otb.c`

```diff
@@ -168,6 +168,12 @@ static Image *ReadOTBImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/palm.c`

```diff
@@ -329,6 +329,12 @@ static Image *ReadPALMImage(const ImageInfo *image_info,
       ThrowReaderException(CorruptImageError,"ImproperImageHeader");
     if ((image->columns == 0) || (image->rows == 0))
       ThrowReaderException(CorruptImageError,"NegativeOrZeroImageSize");
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     bytes_per_row=ReadBlobMSBShort(image);
     flags=ReadBlobMSBShort(image);
     bits_per_pixel=(size_t) ReadBlobByte(image);
```


### `coders/pango.c`

```diff
@@ -375,11 +375,17 @@ static Image *ReadPANGOImage(const ImageInfo *image_info,
         (image->y_resolution == 0.0 ? 90.0 : image->y_resolution)+45.0)/90.0+
         0.5));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Render markup.
   */
-  stride=(size_t) cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32,
-    (int) image->columns);
+  stride=(size_t) cairo_format_stride_for_width(CAIRO_FORMAT_ARGB32,(int)
+    image->columns);
   pixel_info=AcquireVirtualMemory(image->rows,stride*sizeof(*pixels));
   if (pixel_info == (MemoryInfo *) NULL)
     {
```


### `coders/pcd.c`

```diff
@@ -594,6 +594,12 @@ static Image *ReadPCDImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->columns<<=1;
     image->rows<<=1;
   }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Allocate luma and chroma memory.
   */
```


### `coders/pcx.c`

```diff
@@ -395,6 +395,12 @@ static Image *ReadPCXImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Read image data.
     */
```


### `coders/pdb.c`

```diff
@@ -402,6 +402,12 @@ static Image *ReadPDBImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   packets=(bits_per_pixel*image->columns+7)/8;
   pixels=(unsigned char *) AcquireQuantumMemory(packets+256UL,image->rows*
     sizeof(*pixels));
```


### `coders/pict.c`

```diff
@@ -922,6 +922,12 @@ static Image *ReadPICTImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if ((version == 1) || ((TellBlob(image) % 2) != 0))
       code=ReadBlobByte(image);
     if (version == 2)
```


### `coders/pix.c`

```diff
@@ -161,6 +161,12 @@ static Image *ReadPIXImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Convert PIX raster image to pixel packets.
     */
```


### `coders/psd.c`

```diff
@@ -1653,6 +1653,12 @@ static Image *ReadPSDImage(const ImageInfo *image_info,
   image->depth=psd_info.depth;
   image->columns=psd_info.columns;
   image->rows=psd_info.rows;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (SetImageBackgroundColor(image) == MagickFalse)
     {
       InheritException(exception,&image->exception);
```


### `coders/raw.c`

```diff
@@ -180,6 +180,12 @@ static Image *ReadRAWImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if (scene == 0)
       {
         length=GetQuantumExtent(canvas_image,quantum_info,quantum_type);
```


### `coders/rgb.c`

```diff
@@ -201,6 +201,12 @@ static Image *ReadRGBImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     switch (image_info->interlace)
     {
       case NoInterlace:
```


### `coders/rgf.c`

```diff
@@ -172,8 +172,12 @@ static Image *ReadRGFImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
-
-
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read hex image data.
   */
```


### `coders/rla.c`

```diff
@@ -261,6 +261,12 @@ static Image *ReadRLAImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   scanlines=(ssize_t *) AcquireQuantumMemory(image->rows,sizeof(*scanlines));
   if (scanlines == (ssize_t *) NULL)
     ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```


### `coders/rle.c`

```diff
@@ -293,6 +293,12 @@ static Image *ReadRLEImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Allocate RLE pixels.
     */
```


### `coders/scr.c`

```diff
@@ -156,6 +156,12 @@ static Image *ReadSCRImage(const ImageInfo *image_info,ExceptionInfo *exception)
     }
   image->columns = 256;
   image->rows = 192;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   count=ReadBlob(image,6144,(unsigned char *) zxscr);
   (void) count;
   count=ReadBlob(image,768,(unsigned char *) zxattr);
```


### `coders/screenshot.c`

```diff
@@ -133,6 +133,9 @@ static Image *ReadSCREENSHOTImage(const ImageInfo *image_info,
     int
       i;
 
+    MagickBooleanType
+      status;
+
     register PixelPacket
       *q;
 
@@ -162,7 +165,12 @@ static Image *ReadSCREENSHOTImage(const ImageInfo *image_info,
       screen->columns=(size_t) GetDeviceCaps(hDC,HORZRES);
       screen->rows=(size_t) GetDeviceCaps(hDC,VERTRES);
       screen->storage_class=DirectClass;
-
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       if (image == (Image *) NULL)
         image=screen;
       else
```


### `coders/sct.c`

```diff
@@ -224,6 +224,12 @@ static Image *ReadSCTImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert SCT raster image to pixel packets.
   */
```


### `coders/sgi.c`

```diff
@@ -374,6 +374,12 @@ static Image *ReadSGIImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse)  && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Allocate SGI pixels.
     */
```


### `coders/sixel.c`

```diff
@@ -1027,7 +1027,12 @@ static Image *ReadSIXELImage(const ImageInfo *image_info,ExceptionInfo *exceptio
   sixel_buffer=(char *) RelinquishMagickMemory(sixel_buffer);
   image->depth=24;
   image->storage_class=PseudoClass;
-
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (AcquireImageColormap(image,image->colors) == MagickFalse)
     {
       sixel_pixels=(unsigned char *) RelinquishMagickMemory(sixel_pixels);
```


### `coders/stegano.c`

```diff
@@ -169,6 +169,12 @@ static Image *ReadSTEGANOImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Get hidden watermark from low-order bits of image.
   */
```


### `coders/sun.c`

```diff
@@ -412,6 +412,12 @@ static Image *ReadSUNImage(const ImageInfo *image_info,ExceptionInfo *exception)
         (void) CloseBlob(image);
         return(GetFirstImageInList(image));
       }
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if ((sun_info.length*sizeof(*sun_data))/sizeof(*sun_data) !=
         sun_info.length || !sun_info.length)
       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```


### `coders/svg.c`

```diff
@@ -2945,6 +2945,12 @@ static Image *ReadSVGImage(const ImageInfo *image_info,ExceptionInfo *exception)
         image->columns=gdk_pixbuf_get_width(pixel_buffer);
         image->rows=gdk_pixbuf_get_height(pixel_buffer);
 #endif
+        status=SetImageExtent(image,image->columns,image->rows);
+        if (status == MagickFalse)
+          {
+            InheritException(exception,&image->exception);
+            return(DestroyImageList(image));
+          }
         image->matte=MagickTrue;
         SetImageProperty(image,"svg:base-uri",
           rsvg_handle_get_base_uri(svg_handle));
```


### `coders/tga.c`

```diff
@@ -307,6 +307,12 @@ static Image *ReadTGAImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(image);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   (void) ResetMagickMemory(&pixel,0,sizeof(pixel));
   pixel.opacity=(Quantum) OpaqueOpacity;
   if (tga_info.colormap_type != 0)
```


### `coders/tiff.c`

```diff
@@ -1195,6 +1195,12 @@ RestoreMSCWarning
     image->columns=(size_t) width;
     image->rows=(size_t) height;
     image->depth=(size_t) bits_per_sample;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if (image->debug != MagickFalse)
       (void) LogMagickEvent(CoderEvent,GetMagickModule(),"Image depth: %.20g",
         (double) image->depth);
```


### `coders/tile.c`

```diff
@@ -95,6 +95,9 @@ static Image *ReadTILEImage(const ImageInfo *image_info,
   ImageInfo
     *read_info;
 
+  MagickBooleanType
+    status;
+
   /*
     Initialize Image structure.
   */
@@ -115,6 +118,12 @@ static Image *ReadTILEImage(const ImageInfo *image_info,
   image=AcquireImage(image_info);
   if ((image->columns == 0) || (image->rows == 0))
     ThrowReaderException(OptionError,"MustSpecifyImageSize");
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (*image_info->filename == '\0')
     ThrowReaderException(OptionError,"MustSpecifyAnImageName");
   image->colorspace=tile_image->colorspace;
```


### `coders/tim.c`

```diff
@@ -223,6 +223,12 @@ static Image *ReadTIMImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Read image data.
     */
```


### `coders/ttf.c`

```diff
@@ -225,6 +225,12 @@ static Image *ReadTTFImage(const ImageInfo *image_info,ExceptionInfo *exception)
       image=DestroyImageList(image);
       return((Image *) NULL);
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Color canvas with background color
   */
```


### `coders/txt.c`

```diff
@@ -228,6 +228,12 @@ static Image *ReadTEXTImage(const ImageInfo *image_info,Image *image,
     delta.x)+0.5);
   image->rows=(size_t) floor((((double) page.height*image->y_resolution)/
     delta.y)+0.5);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   image->page.x=0;
   image->page.y=0;
   texture=(Image *) NULL;
@@ -437,6 +443,12 @@ static Image *ReadTXTImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->rows=height;
     for (depth=1; (GetQuantumRange(depth)+1) < max_value; depth++) ;
     image->depth=depth;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     LocaleLower(colorspace);
     i=(ssize_t) strlen(colorspace)-1;
     image->matte=MagickFalse;
```


### `coders/uyvy.c`

```diff
@@ -145,6 +145,12 @@ static Image *ReadUYVYImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Accumulate UYVY, then unpack into two pixels.
   */
```


### `coders/vicar.c`

```diff
@@ -285,6 +285,12 @@ static Image *ReadVICARImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Read VICAR pixels.
   */
```


### `coders/viff.c`

```diff
@@ -478,6 +478,12 @@ static Image *ReadVIFFImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     /*
       Allocate VIFF pixels.
     */
```


### `coders/vips.c`

```diff
@@ -416,6 +416,12 @@ static Image *ReadVIPSImage(const ImageInfo *image_info,
     ThrowReaderException(CorruptImageError,"ImproperImageHeader");
   image->columns=(size_t) ReadBlobLong(image);
   image->rows=(size_t) ReadBlobLong(image);
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   channels=ReadBlobLong(image);
   (void) ReadBlobLong(image); /* Legacy */
   format=(VIPSBandFormat) ReadBlobLong(image);
```


### `coders/wbmp.c`

```diff
@@ -185,6 +185,12 @@ static Image *ReadWBMPImage(const ImageInfo *image_info,
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Convert bi-level image to pixel packets.
   */
```


### `coders/webp.c`

```diff
@@ -286,6 +286,12 @@ static Image *ReadWEBPImage(const ImageInfo *image_info,
           (void) CloseBlob(image);
           return(GetFirstImageInList(image));
         }
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       webp_status=WebPDecode(stream,length,&configure);
     }
   if (webp_status != VP8_STATUS_OK)
```


### `coders/wmf.c`

```diff
@@ -2584,6 +2584,9 @@ static Image *ReadWMFImage(const ImageInfo *image_info,ExceptionInfo *exception)
   Image
     *image;
 
+  MagickBooleanType
+    status;
+
   unsigned long
     wmf_options_flags = 0;
 
@@ -2875,6 +2878,12 @@ static Image *ReadWMFImage(const ImageInfo *image_info,ExceptionInfo *exception)
           "leave ReadWMFImage()");
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if (image->debug != MagickFalse)
     (void) LogMagickEvent(CoderEvent,GetMagickModule(),
        "  Creating canvas image with size %lux%lu",(unsigned long) image->rows,
```


### `coders/wpg.c`

```diff
@@ -1413,6 +1413,12 @@ static Image *ReadWPGImage(const ImageInfo *image_info,
          ThrowReaderException(CoderError,"DataEncodingSchemeIsNotSupported");
       }
    }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
 
  Finish:
   (void) CloseBlob(image);
```


### `coders/xbm.c`

```diff
@@ -291,6 +291,12 @@ static Image *ReadXBMImage(const ImageInfo *image_info,ExceptionInfo *exception)
       (void) CloseBlob(image);
       return(GetFirstImageInList(image));
     }
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   /*
     Initialize hex values.
   */
```


### `coders/xc.c`

```diff
@@ -132,6 +132,12 @@ static Image *ReadXCImage(const ImageInfo *image_info,ExceptionInfo *exception)
     image->columns=1;
   if (image->rows == 0)
     image->rows=1;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   (void) CopyMagickString(image->filename,image_info->filename,MaxTextExtent);
   status=QueryMagickColor((char *) image_info->filename,&color,exception);
   if (status == MagickFalse)
```


### `coders/xcf.c`

```diff
@@ -1275,6 +1275,12 @@ static Image *ReadXCFImage(const ImageInfo *image_info,ExceptionInfo *exception)
       XCFLayerInfo
         *layer_info;
 
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       /*
         The read pointer.
       */
```


### `coders/xpm.c`

```diff
@@ -432,6 +432,12 @@ static Image *ReadXPMImage(const ImageInfo *image_info,ExceptionInfo *exception)
       /*
         Read image pixels.
       */
+      status=SetImageExtent(image,image->columns,image->rows);
+      if (status == MagickFalse)
+        {
+          InheritException(exception,&image->exception);
+          return(DestroyImageList(image));
+        }
       for (y=0; y < (ssize_t) image->rows; y++)
       {
         p=NextXPMLine(p);
```


### `coders/xwd.c`

```diff
@@ -399,6 +399,12 @@ static Image *ReadXWDImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image->columns=(size_t) ximage->width;
   image->rows=(size_t) ximage->height;
   image->depth=8;
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   if ((header.ncolors == 0U) || (ximage->red_mask != 0) ||
       (ximage->green_mask != 0) || (ximage->blue_mask != 0))
     image->storage_class=DirectClass;
```


### `coders/ycbcr.c`

```diff
@@ -149,6 +149,12 @@ static Image *ReadYCBCRImage(const ImageInfo *image_info,
   image=AcquireImage(image_info);
   if ((image->columns == 0) || (image->rows == 0))
     ThrowReaderException(OptionError,"MustSpecifyImageSize");
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   SetImageColorspace(image,YCbCrColorspace);
   if (image_info->interlace != PartitionInterlace)
     {
@@ -204,6 +210,12 @@ static Image *ReadYCBCRImage(const ImageInfo *image_info,
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     SetImageColorspace(image,YCbCrColorspace);
     switch (image_info->interlace)
     {
```


### `coders/yuv.c`

```diff
@@ -146,6 +146,12 @@ static Image *ReadYUVImage(const ImageInfo *image_info,ExceptionInfo *exception)
   image=AcquireImage(image_info);
   if ((image->columns == 0) || (image->rows == 0))
     ThrowReaderException(OptionError,"MustSpecifyImageSize");
+  status=SetImageExtent(image,image->columns,image->rows);
+  if (status == MagickFalse)
+    {
+      InheritException(exception,&image->exception);
+      return(DestroyImageList(image));
+    }
   quantum=(size_t) (image->depth <= 8 ? 1 : 2);
   interlace=image_info->interlace;
   horizontal_factor=2;
@@ -213,6 +219,12 @@ static Image *ReadYUVImage(const ImageInfo *image_info,ExceptionInfo *exception)
     if ((image_info->ping != MagickFalse) && (image_info->number_scenes != 0))
       if (image->scene >= (image_info->scene+image_info->number_scenes-1))
         break;
+    status=SetImageExtent(image,image->columns,image->rows);
+    if (status == MagickFalse)
+      {
+        InheritException(exception,&image->exception);
+        return(DestroyImageList(image));
+      }
     if (interlace == PartitionInterlace)
       {
         AppendImageFormat("Y",image->filename);
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
