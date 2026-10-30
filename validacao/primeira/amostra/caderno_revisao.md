# Caderno de revisao de rotulos

Para cada item: leia a mensagem do commit e o resumo da CVE, olhe o diff da funcao (e o link do commit para o contexto dos outros arquivos) e preencha tipo_ruido na planilha.

A = sem mudanca semantica | B = mudou mas irrelevante a CVE | C = mudou como apoio ao conserto, nao e o sitio | D = vulneravel, sitio do bug aqui | ? = duvidoso.

---

## 01. ImageMagick  |  CVE-2016-10066  |  CWE-119
- commit: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6.patch
- commit_id: f6e9d0d9955e85bdd7540b251cd50d598dacc5e6

**resumo da CVE**

> Buffer overflow in the ReadVIFFImage function in coders/viff.c in ImageMagick before 6.9.4-5 allows remote attackers to cause a denial of service (application crash) via a crafted file.

**diff da funcao (func_before vs func_after)**

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

---

## 02. Android  |  CVE-2016-3820  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libavc/+/a78887bcffbc2995cf9ed72e0697acf560875e9e
- diff bruto: https://android.googlesource.com/platform/external/libavc/+/a78887bcffbc2995cf9ed72e0697acf560875e9e^!
- commit_id: a78887bcffbc2995cf9ed72e0697acf560875e9e

**mensagem do commit**

> Decoder: Fix slice number increment for error clips
> 
> Bug: 28673410
> 

**resumo da CVE**

> The ih264d decoder in mediaserver in Android 6.x before 2016-08-01 mishandles slice numbers, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, aka internal bug 28673410.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -215,6 +215,7 @@
      ps_dec->ps_parse_cur_slice = &(ps_dec->ps_dec_slice_buf[0]);
      ps_dec->ps_decode_cur_slice = &(ps_dec->ps_dec_slice_buf[0]);
      ps_dec->ps_computebs_cur_slice = &(ps_dec->ps_dec_slice_buf[0]);
+    ps_dec->u2_cur_slice_num = 0;
  
      /* Initialize all the HP toolsets to zero */
      ps_dec->s_high_profile.u1_scaling_present = 0;
@@ -413,7 +414,6 @@
      ps_dec->u2_mv_2mb[1] = 0;
      ps_dec->u1_last_pic_not_decoded = 0;
  
-    ps_dec->u2_cur_slice_num = 0;
      ps_dec->u2_cur_slice_num_dec_thread = 0;
      ps_dec->u2_cur_slice_num_bs = 0;
      ps_dec->u4_intra_pred_line_ofst = 0;
```

---

## 03. Chrome  |  CVE-2013-0917  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/02c8303512ebed345011f7b545e2f418799be2f0
- diff bruto: https://github.com/chromium/chromium/commit/02c8303512ebed345011f7b545e2f418799be2f0.patch
- commit_id: 02c8303512ebed345011f7b545e2f418799be2f0

**mensagem do commit**

> Oilpan: Ship Oilpan for SyncCallbackHelper, CreateFileResult and CallbackWrapper in filesystem/
> 
> These are leftovers when we shipped Oilpan for filesystem/ once.
> 
> BUG=340522
> 
> Review URL: https://codereview.chromium.org/501263003
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@180909 bbb929c8-8fbe-4397-9dbb-9b2b20218538

**resumo da CVE**

> The URL loader in Google Chrome before 26.0.1410.43 allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,6 +1,6 @@
  Metadata* EntrySync::getMetadata(ExceptionState& exceptionState)
  {
-    RefPtr<MetadataSyncCallbackHelper> helper = MetadataSyncCallbackHelper::create();
+    MetadataSyncCallbackHelper* helper = MetadataSyncCallbackHelper::create();
      m_fileSystem->getMetadata(this, helper->successCallback(), helper->errorCallback(), DOMFileSystemBase::Synchronous);
      return helper->getResult(exceptionState);
  }
```

---

## 04. libgd  |  CVE-2016-6906  |  CWE-125
- commit: https://github.com/libgd/libgd/commit/fb0e0cce0b9f25389ab56604c3547351617e1415
- diff bruto: https://github.com/libgd/libgd/commit/fb0e0cce0b9f25389ab56604c3547351617e1415.patch
- commit_id: fb0e0cce0b9f25389ab56604c3547351617e1415

**mensagem do commit**

> Fix OOB reads of the TGA decompression buffer
> 
> It is possible to craft TGA files which will overflow the decompression
> buffer, but not the image's bitmap. Therefore we augment the check for the
> bitmap's overflow with a check for the buffer's overflow.
> 
> This issue had been reported by Ibrahim El-Sayed to security@libgd.org.
> 
> CVE-2016-6906

**resumo da CVE**

> The read_image_tga function in gd_tga.c in the GD Graphics Library (aka libgd) before 2.2.4 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted TGA file, related to the decompression buffer.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -95,7 +95,8 @@
  				encoded_pixels = ( ( decompression_buffer[ buffer_caret ] & ~TGA_RLE_FLAG ) + 1 );
  				buffer_caret++;
  
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + pixel_block_size > rle_size) {
  					gdFree( decompression_buffer );
  					gdFree( conversion_buffer );
  					return -1;
@@ -111,7 +112,8 @@
  				encoded_pixels = decompression_buffer[ buffer_caret ] + 1;
  				buffer_caret++;
  
-				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size) {
+				if ((bitmap_caret + (encoded_pixels * pixel_block_size)) > image_block_size
+						|| buffer_caret + (encoded_pixels * pixel_block_size) > rle_size) {
  					gdFree( decompression_buffer );
  					gdFree( conversion_buffer );
  					return -1;
```

---

## 05. radare2  |  CVE-2018-14016  |  CWE-125
- commit: https://github.com/radare/radare2/commit/40b021ba29c8f90ccf7c879fde2580bc73a17e8e
- diff bruto: https://github.com/radare/radare2/commit/40b021ba29c8f90ccf7c879fde2580bc73a17e8e.patch
- commit_id: 40b021ba29c8f90ccf7c879fde2580bc73a17e8e

**mensagem do commit**

> Fix #10464 - oobread crash in mdmp

**resumo da CVE**

> The r_bin_mdmp_init_directory_entry function in mdmp.c in radare2 2.7.0 allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted Mini Crash Dump file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -24,7 +24,7 @@
  	/* We could confirm data sizes but a malcious MDMP will always get around
  	** this! But we can ensure that the data is not outside of the file */
  	if (entry->location.rva + entry->location.data_size > obj->b->length) {
-		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
+		eprintf ("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
  		return false;
  	}
  
```

---

## 06. linux  |  CVE-2016-4998  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/6e94e0cfb0887e4013b3b930fa6ab1fe6bb6ba91
- diff bruto: https://github.com/torvalds/linux/commit/6e94e0cfb0887e4013b3b930fa6ab1fe6bb6ba91.patch
- commit_id: 6e94e0cfb0887e4013b3b930fa6ab1fe6bb6ba91

**mensagem do commit**

> netfilter: x_tables: make sure e->next_offset covers remaining blob size
> 
> Otherwise this function may read data beyond the ruleset blob.
> 
> Signed-off-by: Florian Westphal <fw@strlen.de>
> Signed-off-by: Pablo Neira Ayuso <pablo@netfilter.org>

**resumo da CVE**

> The IPT_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem in the Linux kernel before 4.6 allows local users to cause a denial of service (out-of-bounds read) or possibly obtain sensitive information from kernel heap memory by leveraging in-container root access to provide a crafted offset value that leads to crossing a ruleset blob boundary.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -10,7 +10,8 @@
  	int err;
  
  	if ((unsigned long)e % __alignof__(struct ipt_entry) != 0 ||
-	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit) {
+	    (unsigned char *)e + sizeof(struct ipt_entry) >= limit ||
+	    (unsigned char *)e + e->next_offset > limit) {
  		duprintf("Bad offset %p\n", e);
  		return -EINVAL;
  	}
```

---

## 07. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,4 +1,4 @@
 int Chapters::Edition::GetAtomCount() const
-{
-    return m_atoms_count;
+long long Chapters::Atom::GetStopTime(const Chapters* pChapters) const {
+  return GetTime(pChapters, m_stop_timecode);
  }
```

---

## 08. Android  |  CVE-2016-0835  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libmpeg2/+/ba604d336b40fd4bde1622f64d67135bdbd61301
- diff bruto: https://android.googlesource.com/platform/external/libmpeg2/+/ba604d336b40fd4bde1622f64d67135bdbd61301^!
- commit_id: ba604d336b40fd4bde1622f64d67135bdbd61301

**mensagem do commit**

> Fix for handling streams which resulted in negative num_mbs_left
> 
> Bug: 26070014
> Change-Id: Id9f063a2c72a802d991b92abaf00ec687db5bb0f
> 

**resumo da CVE**

> decoder/impeg2d_dec_hdr.c in mediaserver in Android 6.x before 2016-04-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file that triggers a certain negative value, aka internal bug 26070014.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -51,7 +51,7 @@
          i4_row -= 1;
  
  
-        if(i4_prev_row != i4_row)
+        if(i4_prev_row < i4_row)
          {
              /* Create a job for previous slice row */
              if(i4_start_row != -1)
@@ -76,6 +76,8 @@
              /* Store current slice's row position */
              i4_start_row = i4_row;
  
+        } else if (i4_prev_row > i4_row) {
+            android_errorWriteLog(0x534e4554, "26070014");
          }
  
  
```

---

## 09. Chrome  |  CVE-2012-5157  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/7f0126ff011142c8619b10a6e64d04d1745c503a
- diff bruto: https://github.com/chromium/chromium/commit/7f0126ff011142c8619b10a6e64d04d1745c503a.patch
- commit_id: 7f0126ff011142c8619b10a6e64d04d1745c503a

**mensagem do commit**

> Revert 162155 "This review merges the two existing page serializ..."
> 
> Change r162155 broke the world even though it was landed using the CQ.
> 
> > This review merges the two existing page serializers, WebPageSerializerImpl and
> > PageSerializer, into one, PageSerializer. In addition to this it moves all
> > the old tests from WebPageNewSerializerTest and WebPageSerializerTest to the
> > PageSerializerTest structure and splits out one test for MHTML into a new
> > MHTMLTest file.
> > 
> > Saving as 'Webpage, Complete', 'Webpage, HTML Only' and as MHTML when the
> > 'Save Page as MHTML' flag is enabled now uses the same code, and should thus
> > have the same feature set. Meaning that both modes now should be a bit better.
> > 
> > Detailed list of changes:
> > 
> > - PageSerializerTest: Prepare for more DTD test
> > - PageSerializerTest: Remove now unneccesary input image test
> > - PageSerializerTest: Remove unused WebPageSerializer/Impl code
> > - PageSerializerTest: Move data URI morph test
> > - PageSerializerTest: Move data URI test
> > - PageSerializerTest: Move namespace test
> > - PageSerializerTest: Move SVG Image test
> > - MHTMLTest: Move MHTML specific test to own test file
> > - PageSerializerTest: Delete duplicate XML header test
> > - PageSerializerTest: Move blank frame test
> > - PageSerializerTest: Move CSS test
> > - PageSerializerTest: Add frameset/frame test
> > - PageSerializerTest: Move old iframe test
> > - PageSerializerTest: Move old elements test
> > - Use PageSerizer for saving web pages
> > - PageSerializerTest: Test for rewriting links
> > - PageSerializer: Add rewrite link accumulator
> > - PageSerializer: Serialize images in iframes/frames src
> > - PageSerializer: XHTML fix for meta tags
> > - PageSerializer: Add presentation CSS
> > - PageSerializer: Rename out parameter
> > 
> > BUG=
> > R=abarth@chromium.org
> > 
> > Review URL: https://codereview.chromium.org/68613003
> 
> TBR=tiger@opera.com
> 
> Review URL: https://codereview.chromium.org/73673003
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@162156 bbb929c8-8fbe-4397-9dbb-9b2b20218538

**resumo da CVE**

> Google Chrome before 24.0.1312.52 does not properly handle image data in PDF documents, which allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted document.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -10,19 +10,15 @@
          return;
      }
  
-    if (document->isImageDocument()) {
-        ImageDocument* imageDocument = toImageDocument(document);
-        addImageToResources(imageDocument->cachedImage(), imageDocument->imageElement()->renderer(), url);
+     Vector<Node*> nodes;
+    SerializerMarkupAccumulator accumulator(this, document, &nodes);
+     WTF::TextEncoding textEncoding(document->charset());
+    CString data;
+    if (!textEncoding.isValid()) {
+        // FIXME: iframes used as images trigger this. We should deal with them correctly.
         return;
     }
-     Vector<Node*> nodes;
-    OwnPtr<SerializerMarkupAccumulator> accumulator;
-    if (m_URLs)
-        accumulator = adoptPtr(new LinkChangeSerializerMarkupAccumulator(this, document, &nodes, m_URLs, m_directory));
-    else
-        accumulator = adoptPtr(new SerializerMarkupAccumulator(this, document, &nodes));
-    String text = accumulator->serializeNodes(document, IncludeNode);
-     WTF::TextEncoding textEncoding(document->charset());
+    String text = accumulator.serializeNodes(document, IncludeNode);
      CString frameHTML = textEncoding.normalizeAndEncode(text, WTF::EntitiesForUnencodables);
      m_resources->append(SerializedResource(url, document->suggestedMIMEType(), SharedBuffer::create(frameHTML.data(), frameHTML.length())));
      m_resourceURLs.add(url);
@@ -33,10 +29,8 @@
             continue;
  
          Element* element = toElement(node);
-        if (element->isStyledElement()) {
+        if (element->isStyledElement())
              retrieveResourcesForProperties(element->inlineStyle(), document);
-            retrieveResourcesForProperties(element->presentationAttributeStyle(), document);
-        }
  
          if (element->hasTagName(HTMLNames::imgTag)) {
              HTMLImageElement* imageElement = toHTMLImageElement(element);
```

---

## 10. Chrome  |  CVE-2013-2920  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/3ca8e38ff57e83fcce76f9b54cd8f8bfa09c34ad
- diff bruto: https://github.com/chromium/chromium/commit/3ca8e38ff57e83fcce76f9b54cd8f8bfa09c34ad.patch
- commit_id: 3ca8e38ff57e83fcce76f9b54cd8f8bfa09c34ad

**mensagem do commit**

> Fix OOB read when parsing protocol-relative URLs
> 
> BUG=285742
> 
> Review URL: https://chromiumcodereview.appspot.com/23902014
> 
> git-svn-id: svn://svn.chromium.org/chrome/trunk/src@223735 0039d316-1c4b-4281-b951-d872f2087c98

**resumo da CVE**

> The DoResolveRelativeHost function in url/url_canon_relative.cc in Google Chrome before 30.0.1599.66 allows remote attackers to cause a denial of service (out-of-bounds read) via a relative URL containing a hostname, as demonstrated by a protocol-relative URL beginning with a //www.google.com/ substring.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -6,9 +6,8 @@
                            CanonOutput* output,
                            url_parse::Parsed* out_parsed) {
    url_parse::Parsed relative_parsed;  // Everything but the scheme is valid.
-  url_parse::ParseAfterScheme(&relative_url[relative_component.begin],
-                              relative_component.len, relative_component.begin,
-                              &relative_parsed);
+  url_parse::ParseAfterScheme(relative_url, relative_component.end(),
+                              relative_component.begin, &relative_parsed);
  
   Replacements<CHAR> replacements;
   replacements.SetUsername(relative_url, relative_parsed.username);
```

---

## 11. libtiff  |  CVE-2016-9535  |  CWE-119
- commit: https://github.com/vadz/libtiff/commit/3ca657a8793dd011bf869695d72ad31c779c3cc1
- diff bruto: https://github.com/vadz/libtiff/commit/3ca657a8793dd011bf869695d72ad31c779c3cc1.patch
- commit_id: 3ca657a8793dd011bf869695d72ad31c779c3cc1

**mensagem do commit**

> * libtiff/tif_predict.h, libtiff/tif_predict.c:
> Replace assertions by runtime checks to avoid assertions in debug mode,
> or buffer overflows in release mode. Can happen when dealing with
> unusual tile size like YCbCr with subsampling. Reported as MSVR 35105
> by Axel Souchet	& Vishal Chauhan from the MSRC Vulnerabilities & Mitigations
> team.

**resumo da CVE**

> tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions that can lead to assertion failures in debug mode, or buffer overflows in release mode, when dealing with unusual tile size like YCbCr with subsampling. Reported as MSVR 35105, aka *Predictor heap-buffer-overflow.*

**diff da funcao (func_before vs func_after)**

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

---

## 12. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -35,9 +35,9 @@
    if (!decoder)
      die("Unknown input codec.");
  
-  printf("Using %s\n", vpx_codec_iface_name(decoder->interface()));
+  printf("Using %s\n", vpx_codec_iface_name(decoder->codec_interface()));
  
-  if (vpx_codec_dec_init(&codec, decoder->interface(), NULL, 0))
+  if (vpx_codec_dec_init(&codec, decoder->codec_interface(), NULL, 0))
      die_codec(&codec, "Failed to initialize decoder.");
  
    while (vpx_video_reader_read_frame(reader)) {
```

---

## 13. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,3 +1,4 @@
   void RunFwdTxfm(int16_t *in, int16_t *out, int stride) {
+  void RunFwdTxfm(int16_t *in, tran_low_t *out, int stride) {
      fwd_txfm_(in, out, stride, tx_type_);
    }
```

---

## 14. miniupnp  |  CVE-2016-3178  |  CWE-125
- commit: https://github.com/miniupnp/miniupnp/commit/b238cade9a173c6f751a34acf8ccff838a62aa47
- diff bruto: https://github.com/miniupnp/miniupnp/commit/b238cade9a173c6f751a34acf8ccff838a62aa47.patch
- commit_id: b238cade9a173c6f751a34acf8ccff838a62aa47

**mensagem do commit**

> minissdpd: Fix broken overflow test (p+l > buf+n) thanks to Salva Piero

**resumo da CVE**

> The processRequest function in minissdpd.c in MiniSSDPd 1.2.20130907-3 allows local users to cause a denial of service (out-of-bounds memory access and daemon crash) via vectors involving a negative length value.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -28,7 +28,7 @@
  	type = buf[0];
  	p = buf + 1;
  	DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-	if(p+l > buf+n) {
+	if(l > (unsigned)(buf+n-p)) {
  		syslog(LOG_WARNING, "bad request (length encoding l=%u n=%u)",
  		       l, (unsigned)n);
  		goto error;
@@ -150,7 +150,7 @@
  			goto error;
  		}
  		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
  			syslog(LOG_WARNING, "bad request (length encoding)");
  			goto error;
  		}
@@ -168,7 +168,7 @@
  		newserv->usn[l] = '\0';
  		p += l;
  		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
  			syslog(LOG_WARNING, "bad request (length encoding)");
  			goto error;
  		}
@@ -186,7 +186,7 @@
  		newserv->server[l] = '\0';
  		p += l;
  		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
-		if(p+l > buf+n) {
+		if(l > (unsigned)(buf+n-p)) {
  			syslog(LOG_WARNING, "bad request (length encoding)");
  			goto error;
  		}
```

---

## 15. libXrandr  |  CVE-2016-7948  |  CWE-787
- commit: https://cgit.freedesktop.org/xorg/lib/libXrandr/commit/?id=a0df3e1c7728205e5c7650b2e6dce684139254a6
- diff bruto: https://cgit.freedesktop.org/xorg/lib/libXrandr/commit/?id=a0df3e1c7728205e5c7650b2e6dce684139254a6
- commit_id: a0df3e1c7728205e5c7650b2e6dce684139254a6

**resumo da CVE**

> X.org libXrandr before 1.5.1 allows remote X servers to trigger out-of-bounds write operations by leveraging mishandling of reply data.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -23,6 +23,16 @@
  	return NULL;
      }
  
+    if (rep.length > INT_MAX >> 2 || rep.length < (OutputInfoExtra >> 2))
+    {
+        if (rep.length > (OutputInfoExtra >> 2))
+	    _XEatDataWords (dpy, rep.length - (OutputInfoExtra >> 2));
+	else
+	    _XEatDataWords (dpy, rep.length);
+	UnlockDisplay (dpy);
+	SyncHandle ();
+	return NULL;
+    }
      nbytes = ((long) (rep.length) << 2) - OutputInfoExtra;
  
      nbytesRead = (long) (rep.nCrtcs * 4 +
```

---

## 16. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,9 +1,6 @@
 const CuePoint* Cues::GetFirst() const
-{
-    if (m_cue_points == NULL)
-        return NULL;
-    if (m_count == 0)
-        return NULL;
+  if (m_count == 0)
+    return NULL;
  
  #if 0
      LoadCuePoint();  //init cues
@@ -15,12 +12,12 @@
          return NULL;
  #endif
  
-    CuePoint* const* const pp = m_cue_points;
-    assert(pp);
+  CuePoint* const* const pp = m_cue_points;
+  assert(pp);
  
-    CuePoint* const pCP = pp[0];
-    assert(pCP);
-    assert(pCP->GetTimeCode() >= 0);
+  CuePoint* const pCP = pp[0];
+  assert(pCP);
+  assert(pCP->GetTimeCode() >= 0);
  
-    return pCP;
+  return pCP;
  }
```

---

## 17. Android  |  CVE-2016-3819  |  CWE-119
- commit: https://android.googlesource.com/platform/frameworks/av/+/590d1729883f700ab905cdc9ad850f3ddd7e1f56
- diff bruto: https://android.googlesource.com/platform/frameworks/av/+/590d1729883f700ab905cdc9ad850f3ddd7e1f56^!
- commit_id: 590d1729883f700ab905cdc9ad850f3ddd7e1f56

**mensagem do commit**

> Fix potential overflow
> 
> Bug: 28533562
> Change-Id: I798ab24caa4c81f3ba564cad7c9ee019284fb702
> 

**resumo da CVE**

> Integer overflow in codecs/on2/h264dec/source/h264bsd_dpb.c in libstagefright in mediaserver in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-08-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, aka internal bug 28533562.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -20,6 +20,13 @@
      ASSERT(maxFrameNum);
      ASSERT(dpbSize);
  
+    // see comment in loop below about size calculation
+    if (picSizeInMbs > (UINT32_MAX - 32 - 15) / 384) {
+        ALOGE("b/28533562");
+        android_errorWriteLog(0x534e4554, "28533562");
+        return(MEMORY_ALLOCATION_ERROR);
+    }
+
      dpb->maxLongTermFrameIdx = NO_LONG_TERM_FRAME_INDICES;
      dpb->maxRefFrames        = MAX(maxRefFrames, 1);
      if (noReordering)
```

---

## 18. ngiflib  |  CVE-2018-10677  |  CWE-119
- commit: https://github.com/miniupnp/ngiflib/commit/b588a2249c7abbfc52173e32ee11d6facef82f89
- diff bruto: https://github.com/miniupnp/ngiflib/commit/b588a2249c7abbfc52173e32ee11d6facef82f89.patch
- commit_id: b588a2249c7abbfc52173e32ee11d6facef82f89

**mensagem do commit**

> check GIF image position and dimensions
> 
> fixes #1

**resumo da CVE**

> The DecodeGifImg function in ngiflib.c in MiniUPnP ngiflib 0.4 lacks certain checks against width and height, which allows remote attackers to cause a denial of service (WritePixels heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted GIF file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -22,6 +22,24 @@
  	i->width = GetWord(i->parent);	/* SizeX   */
  	i->height = GetWord(i->parent);	/* SizeY   */
  
+	if((i->width > i->parent->width) || (i->height > i->parent->height)) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** ERROR *** Image bigger than global GIF canvas !\n");
+#endif
+		return -1;
+	}
+	if((i->posX + i->width) > i->parent->width) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting X position\n");
+#endif
+		i->posX = i->parent->width - i->width;
+	}
+	if((i->posY + i->height) > i->parent->height) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting Y position\n");
+#endif
+		i->posY = i->parent->height - i->height;
+	}
  	context.Xtogo = i->width;
  	context.curY = i->posY;
  #ifdef NGIFLIB_INDEXED_ONLY
```

---

## 19. gst-plugins-ugly  |  CVE-2017-5847  |  CWE-125
- commit: https://github.com/GStreamer/gst-plugins-ugly/commit/d21017b52a585f145e8d62781bcc1c5fefc7ee37
- diff bruto: https://github.com/GStreamer/gst-plugins-ugly/commit/d21017b52a585f145e8d62781bcc1c5fefc7ee37.patch
- commit_id: d21017b52a585f145e8d62781bcc1c5fefc7ee37

**mensagem do commit**

> asfdemux: Check that we have enough data available before parsing bool/uint extended content descriptors
> 
> https://bugzilla.gnome.org/show_bug.cgi?id=777955

**resumo da CVE**

> The gst_asf_demux_process_ext_content_desc function in gst/asfdemux/gstasfdemux.c in gst-plugins-ugly in GStreamer allows remote attackers to cause a denial of service (out-of-bounds heap read) via vectors involving extended content descriptors.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -188,7 +188,12 @@
            break;
          }
          case ASF_DEMUX_DATA_TYPE_DWORD:{
-          guint uint_val = GST_READ_UINT32_LE (value);
+          guint uint_val;
+
+          if (value_len < 4)
+            break;
+
+          uint_val = GST_READ_UINT32_LE (value);
  
            /* this is the track number */
            g_value_init (&tag_value, G_TYPE_UINT);
@@ -202,7 +207,12 @@
          }
            /* Detect 3D */
          case ASF_DEMUX_DATA_TYPE_BOOL:{
-          gboolean bool_val = GST_READ_UINT32_LE (value);
+          gboolean bool_val;
+
+          if (value_len < 4)
+            break;
+
+          bool_val = GST_READ_UINT32_LE (value);
  
            if (strncmp ("Stereoscopic", name_utf8, strlen (name_utf8)) == 0) {
              if (bool_val) {
```

---

## 20. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,4 +1 @@
 unsigned long long Track::GetCodecDelay() const
-{
-    return m_info.codecDelay;
-}
```

---

## 21. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,26 +1,52 @@
   void RunAccuracyCheck() {
+  void RunAccuracyCheck(int limit) {
      ACMRandom rnd(ACMRandom::DeterministicSeed());
      uint32_t max_error = 0;
      int64_t total_error = 0;
      const int count_test_block = 10000;
      for (int i = 0; i < count_test_block; ++i) {
-      DECLARE_ALIGNED_ARRAY(16, int16_t, test_input_block, kNumCoeffs);
-      DECLARE_ALIGNED_ARRAY(16, int16_t, test_temp_block, kNumCoeffs);
-      DECLARE_ALIGNED_ARRAY(16, uint8_t, dst, kNumCoeffs);
-      DECLARE_ALIGNED_ARRAY(16, uint8_t, src, kNumCoeffs);
+      DECLARE_ALIGNED(16, int16_t, test_input_block[kNumCoeffs]);
+      DECLARE_ALIGNED(16, tran_low_t, test_temp_block[kNumCoeffs]);
+      DECLARE_ALIGNED(16, uint8_t, dst[kNumCoeffs]);
+      DECLARE_ALIGNED(16, uint8_t, src[kNumCoeffs]);
+#if CONFIG_VP9_HIGHBITDEPTH
+      DECLARE_ALIGNED(16, uint16_t, dst16[kNumCoeffs]);
+      DECLARE_ALIGNED(16, uint16_t, src16[kNumCoeffs]);
+#endif
  
        for (int j = 0; j < kNumCoeffs; ++j) {
-        src[j] = rnd.Rand8();
-        dst[j] = rnd.Rand8();
-        test_input_block[j] = src[j] - dst[j];
+        if (bit_depth_ == VPX_BITS_8) {
+          src[j] = rnd.Rand8();
+          dst[j] = rnd.Rand8();
+          test_input_block[j] = src[j] - dst[j];
+#if CONFIG_VP9_HIGHBITDEPTH
+        } else {
+          src16[j] = rnd.Rand16() & mask_;
+          dst16[j] = rnd.Rand16() & mask_;
+          test_input_block[j] = src16[j] - dst16[j];
+#endif
+        }
        }
  
-      REGISTER_STATE_CHECK(RunFwdTxfm(test_input_block,
-                                      test_temp_block, pitch_));
-      REGISTER_STATE_CHECK(RunInvTxfm(test_temp_block, dst, pitch_));
+      ASM_REGISTER_STATE_CHECK(RunFwdTxfm(test_input_block,
+                                          test_temp_block, pitch_));
+      if (bit_depth_ == VPX_BITS_8) {
+        ASM_REGISTER_STATE_CHECK(RunInvTxfm(test_temp_block, dst, pitch_));
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        ASM_REGISTER_STATE_CHECK(RunInvTxfm(test_temp_block,
+                                            CONVERT_TO_BYTEPTR(dst16), pitch_));
+#endif
+      }
  
        for (int j = 0; j < kNumCoeffs; ++j) {
+#if CONFIG_VP9_HIGHBITDEPTH
+        const uint32_t diff =
+            bit_depth_ == VPX_BITS_8 ? dst[j] - src[j] : dst16[j] - src16[j];
+#else
+        ASSERT_EQ(VPX_BITS_8, bit_depth_);
          const uint32_t diff = dst[j] - src[j];
+#endif
          const uint32_t error = diff * diff;
          if (max_error < error)
            max_error = error;
@@ -29,9 +55,11 @@
        }
      }
  
-    EXPECT_GE(1u, max_error)
-        << "Error: 4x4 FHT/IHT has an individual round trip error > 1";
+    EXPECT_GE(static_cast<uint32_t>(limit), max_error)
+        << "Error: 4x4 FHT/IHT has an individual round trip error > "
+        << limit;
  
-    EXPECT_GE(count_test_block , total_error)
-        << "Error: 4x4 FHT/IHT has average round trip error > 1 per block";
+    EXPECT_GE(count_test_block * limit, total_error)
+        << "Error: 4x4 FHT/IHT has average round trip error > " << limit
+        << " per block";
    }
```

---

## 22. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,3 +1 @@
 Chapters::Display::~Display()
-{
-}
```

---

## 23. yara  |  CVE-2017-9465  |  CWE-125
- commit: https://github.com/VirusTotal/yara/commit/992480c30f75943e9cd6245bb2015c7737f9b661
- diff bruto: https://github.com/VirusTotal/yara/commit/992480c30f75943e9cd6245bb2015c7737f9b661.patch
- commit_id: 992480c30f75943e9cd6245bb2015c7737f9b661

**mensagem do commit**

> Fix buffer overrun (issue #678). Add assert for detecting this kind of issues earlier.

**resumo da CVE**

> The yr_arena_write_data function in YARA 3.6.1 allows remote attackers to cause a denial of service (buffer over-read and application crash) or obtain sensitive information from process memory via a crafted file that is mishandled in the yr_re_fast_exec function in libyara/re.c and the _yr_scan_match_callback function in libyara/scan.c.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -16,6 +16,9 @@
 
    match_length += callback_args->forward_matches;
  
+  // make sure that match fits into the data.
+  assert(match_offset + match_length <= callback_args->data_size);
+
    if (callback_args->full_word)
    {
      if (flags & RE_FLAGS_WIDE)
```

---

## 24. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,29 +1,43 @@
 long Segment::Load()
-{
-    assert(m_clusters == NULL);
-    assert(m_clusterSize == 0);
-    assert(m_clusterCount == 0);
+  const long count = m_clusterCount + m_clusterPreloadCount;
  
+  long& size = m_clusterSize;
+  assert(size >= count);
  
-    const long long header_status = ParseHeaders();
+  if (count >= size) {
+    const long n = (size <= 0) ? 2048 : 2 * size;
  
-    if (header_status < 0)  //error
-        return static_cast<long>(header_status);
+    Cluster** const qq = new Cluster* [n];
+    Cluster** q = qq;
  
-    if (header_status > 0)  //underflow
-        return E_BUFFER_NOT_FULL;
+    Cluster** p = m_clusters;
+    Cluster** const pp = p + count;
  
-    assert(m_pInfo);
-    assert(m_pTracks);
+    while (p != pp)
+      *q++ = *p++;
  
-    for (;;)
-    {
-        const int status = LoadCluster();
+    delete[] m_clusters;
  
-        if (status < 0)  //error
-            return status;
+    m_clusters = qq;
+    size = n;
+  }
  
-        if (status >= 1)  //no more clusters
-            return 0;
-    }
+  assert(m_clusters);
+
+  Cluster** const p = m_clusters + idx;
+
+  Cluster** q = m_clusters + count;
+  assert(q >= p);
+  assert(q < (m_clusters + size));
+
+  while (q > p) {
+    Cluster** const qq = q - 1;
+    assert((*qq)->m_index < 0);
+
+    *q = *qq;
+    q = qq;
+  }
+
+  m_clusters[idx] = pCluster;
+  ++m_clusterPreloadCount;
  }
```

---

## 25. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -8,7 +8,7 @@
      delete comp;
    }
  
-  delete [] compression_entries_;
+  delete[] compression_entries_;
  
    ContentEncryption** enc_i = encryption_entries_;
    ContentEncryption** const enc_j = encryption_entries_end_;
@@ -19,5 +19,5 @@
      delete enc;
    }
  
-  delete [] encryption_entries_;
+  delete[] encryption_entries_;
  }
```

---

## 26. linux  |  CVE-2017-18222  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/412b65d15a7f8a93794653968308fc100f2aa87c
- diff bruto: https://github.com/torvalds/linux/commit/412b65d15a7f8a93794653968308fc100f2aa87c.patch
- commit_id: 412b65d15a7f8a93794653968308fc100f2aa87c

**mensagem do commit**

> net: hns: fix ethtool_get_strings overflow in hns driver
> 
> hns_get_sset_count() returns HNS_NET_STATS_CNT and the data space allocated
> is not enough for ethtool_get_strings(), which will cause random memory
> corruption.
> 
> When SLAB and DEBUG_SLAB are both enabled, memory corruptions like the
> the following can be observed without this patch:
> [   43.115200] Slab corruption (Not tainted): Acpi-ParseExt start=ffff801fb0b69030, len=80
> [   43.115206] Redzone: 0x9f911029d006462/0x5f78745f31657070.
> [   43.115208] Last user: [<5f7272655f746b70>](0x5f7272655f746b70)
> [   43.115214] 010: 70 70 65 31 5f 74 78 5f 70 6b 74 00 6b 6b 6b 6b  ppe1_tx_pkt.kkkk
> [   43.115217] 030: 70 70 65 31 5f 74 78 5f 70 6b 74 5f 6f 6b 00 6b  ppe1_tx_pkt_ok.k
> [   43.115218] Next obj: start=ffff801fb0b69098, len=80
> [   43.115220] Redzone: 0x706d655f6f666966/0x9f911029d74e35b.
> [   43.115229] Last user: [<ffff0000084b11b0>](acpi_os_release_object+0x28/0x38)
> [   43.115231] 000: 74 79 00 6b 6b 6b 6b 6b 70 70 65 31 5f 74 78 5f  ty.kkkkkppe1_tx_
> [   43.115232] 010: 70 6b 74 5f 65 72 72 5f 63 73 75 6d 5f 66 61 69  pkt_err_csum_fai
> 
> Signed-off-by: Timmy Li <lixiaoping3@huawei.com>
> Signed-off-by: David S. Miller <davem@davemloft.net>

**resumo da CVE**

> In the Linux kernel before 4.12, Hisilicon Network Subsystem (HNS) does not consider the ETH_SS_PRIV_FLAGS case when retrieving sset_count data, which allows local users to cause a denial of service (buffer overflow and memory corruption) or possibly have unspecified other impact, as demonstrated by incompatibility between hns_get_sset_count and ethtool_get_strings.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,6 +1,6 @@
  static int hns_gmac_get_sset_count(int stringset)
  {
-	if (stringset == ETH_SS_STATS)
+	if (stringset == ETH_SS_STATS || stringset == ETH_SS_PRIV_FLAGS)
  		return ARRAY_SIZE(g_gmac_stats_string);
  
  	return 0;
```

---

## 27. busybox  |  CVE-2019-5747  |  CWE-125
- commit: https://git.busybox.net/busybox/commit/?id=74d9f1ba37010face4bd1449df4d60dd84450b06
- diff bruto: https://git.busybox.net/busybox/commit/?id=74d9f1ba37010face4bd1449df4d60dd84450b06
- commit_id: 74d9f1ba37010face4bd1449df4d60dd84450b06

**resumo da CVE**

> An issue was discovered in BusyBox through 1.30.0. An out of bounds read in udhcp components (consumed by the DHCP server, client, and/or relay) might allow a remote attacker to leak sensitive information from the stack by sending a crafted DHCP message. This is related to assurance of a 4-byte length when decoding DHCP_SUBNET. NOTE: this issue exists because of an incomplete fix for CVE-2018-20679.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,7 +2,7 @@
  {
  	uint8_t *r = udhcp_get_option(packet, code);
  	if (r) {
-		if (r[-1] != 4)
+		if (r[-OPT_DATA + OPT_LEN] != 4)
  			r = NULL;
  	}
  	return r;
```

---

## 28. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,14 +1,13 @@
  int main(int argc, char **argv) {
    FILE *infile = NULL;
-  VpxVideoWriter *writer = NULL;
+  int w, h;
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t raw;
    vpx_codec_err_t res;
-  vpx_fixed_buf_t stats = {0};
-  VpxVideoInfo info = {0};
+  vpx_fixed_buf_t stats;
+
    const VpxInterface *encoder = NULL;
-  int pass;
    const int fps = 30;        // TODO(dkovalev) add command line argument
    const int bitrate = 200;   // kbit/s TODO(dkovalev) add command line argument
    const char *const codec_arg = argv[1];
@@ -26,78 +25,44 @@
    if (!encoder)
      die("Unsupported codec.");
  
-  info.codec_fourcc = encoder->fourcc;
-  info.time_base.numerator = 1;
-  info.time_base.denominator = fps;
-  info.frame_width = strtol(width_arg, NULL, 0);
-  info.frame_height = strtol(height_arg, NULL, 0);
+  w = strtol(width_arg, NULL, 0);
+  h = strtol(height_arg, NULL, 0);
  
-  if (info.frame_width <= 0 ||
-      info.frame_height <= 0 ||
-      (info.frame_width % 2) != 0 ||
-      (info.frame_height % 2) != 0) {
-    die("Invalid frame size: %dx%d", info.frame_width, info.frame_height);
-  }
+  if (w  <= 0 || h <= 0 || (w % 2) != 0 || (h  % 2) != 0)
+    die("Invalid frame size: %dx%d", w, h);
  
-  if (!vpx_img_alloc(&raw, VPX_IMG_FMT_I420, info.frame_width,
-                                             info.frame_height, 1)) {
-    die("Failed to allocate image", info.frame_width, info.frame_height);
-  }
+  if (!vpx_img_alloc(&raw, VPX_IMG_FMT_I420, w, h, 1))
+    die("Failed to allocate image", w, h);
  
-  writer = vpx_video_writer_open(outfile_arg, kContainerIVF, &info);
-  if (!writer)
-    die("Failed to open %s for writing", outfile_arg);
+  printf("Using %s\n", vpx_codec_iface_name(encoder->codec_interface()));
  
-  printf("Using %s\n", vpx_codec_iface_name(encoder->interface()));
-  res = vpx_codec_enc_config_default(encoder->interface(), &cfg, 0);
+  // Configuration
+  res = vpx_codec_enc_config_default(encoder->codec_interface(), &cfg, 0);
    if (res)
      die_codec(&codec, "Failed to get default codec config.");
  
-  cfg.g_w = info.frame_width;
-  cfg.g_h = info.frame_height;
-  cfg.g_timebase.num = info.time_base.numerator;
-  cfg.g_timebase.den = info.time_base.denominator;
+  cfg.g_w = w;
+  cfg.g_h = h;
+  cfg.g_timebase.num = 1;
+  cfg.g_timebase.den = fps;
    cfg.rc_target_bitrate = bitrate;
  
-  for (pass = 0; pass < 2; ++pass) {
-    int frame_count = 0;
+  if (!(infile = fopen(infile_arg, "rb")))
+    die("Failed to open %s for reading", infile_arg);
  
-    if (pass == 0) {
-      cfg.g_pass = VPX_RC_FIRST_PASS;
-    } else {
-      cfg.g_pass = VPX_RC_LAST_PASS;
-      cfg.rc_twopass_stats_in = stats;
-    }
+  // Pass 0
+  cfg.g_pass = VPX_RC_FIRST_PASS;
+  stats = pass0(&raw, infile, encoder, &cfg);
  
-    if (!(infile = fopen(infile_arg, "rb")))
-      die("Failed to open %s for reading", infile_arg);
-    if (vpx_codec_enc_init(&codec, encoder->interface(), &cfg, 0))
-      die_codec(&codec, "Failed to initialize encoder");
-    while (vpx_img_read(&raw, infile)) {
-      ++frame_count;
-      if (pass == 0) {
-        get_frame_stats(&codec, &raw, frame_count, 1, 0, VPX_DL_BEST_QUALITY,
-                        &stats);
-      } else {
-        encode_frame(&codec, &raw, frame_count, 1, 0, VPX_DL_BEST_QUALITY,
-                     writer);
-      }
-    }
-    if (pass == 0) {
-      get_frame_stats(&codec, NULL, frame_count, 1, 0, VPX_DL_BEST_QUALITY,
-                      &stats);
-    } else {
-      printf("\n");
-    }
-    fclose(infile);
-    printf("Pass %d complete. Processed %d frames.\n", pass + 1, frame_count);
-    if (vpx_codec_destroy(&codec))
-      die_codec(&codec, "Failed to destroy codec.");
-  }
-  vpx_img_free(&raw);
+  // Pass 1
+  rewind(infile);
+  cfg.g_pass = VPX_RC_LAST_PASS;
+  cfg.rc_twopass_stats_in = stats;
+  pass1(&raw, infile, outfile_arg, encoder, &cfg);
    free(stats.buf);
  
-  vpx_video_writer_close(writer);
+  vpx_img_free(&raw);
+  fclose(infile);
  
    return EXIT_SUCCESS;
  }
```

---

## 29. php  |  CVE-2016-4539  |  CWE-119
- commit: https://git.php.net/?p=php-src.git;a=commit;h=dccda88f27a084bcbbb30198ace12b4e7ae961cc
- diff bruto: https://git.php.net/?p=php-src.git;a=commit;h=dccda88f27a084bcbbb30198ace12b4e7ae961cc
- commit_id: dccda88f27a084bcbbb30198ace12b4e7ae961cc

**resumo da CVE**

> The xml_parse_into_struct function in ext/xml/xml.c in PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6 allows remote attackers to cause a denial of service (buffer under-read and segmentation fault) or possibly have unspecified other impact via crafted XML data in the second argument, leading to a parser level of zero.

**diff da funcao**: vazio apos normalizar o espaco em branco (tipo A, ja pre-marcado)

---

## 30. OpenSC  |  CVE-2018-16427  |  CWE-125
- commit: https://github.com/OpenSC/OpenSC/pull/1447/commits/8fe377e93b4b56060e5bbfb6f3142ceaeca744fa
- diff bruto: https://github.com/OpenSC/OpenSC/pull/1447/commits/8fe377e93b4b56060e5bbfb6f3142ceaeca744fa.patch
- commit_id: 8fe377e93b4b56060e5bbfb6f3142ceaeca744fa

**mensagem do commit**

> fixed out of bounds reads
> 
> Thanks to Eric Sesterhenn from X41 D-SEC GmbH
> for reporting and suggesting security fixes.

**resumo da CVE**

> Various out of bounds reads when handling responses in OpenSC before 0.19.0-rc1 could be used by attackers able to supply crafted smartcards to potentially crash the opensc library using programs.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -44,7 +44,7 @@
  	}
  
  	sc_log_hex(ctx, "ACL data", file->sec_attr, file->sec_attr_len);
-	for (ii = 0; ii < file->sec_attr_len / 2; ii++)  {
+	for (ii = 0; ii < file->sec_attr_len / 2 && ii < sizeof ops_DF; ii++)  {
  		unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];
  		unsigned char acl = *(file->sec_attr + ii*2);
  		unsigned char cred_id = *(file->sec_attr + ii*2 + 1);
```

---

## 31. ImageMagick  |  CVE-2016-7526  |  CWE-787
- commit: https://github.com/ImageMagick/ImageMagick/commit/d9b2209a69ee90d8df81fb124eb66f593eb9f599
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/d9b2209a69ee90d8df81fb124eb66f593eb9f599.patch
- commit_id: d9b2209a69ee90d8df81fb124eb66f593eb9f599

**mensagem do commit**

> Fixed out-of-bounds write reported in: https://github.com/ImageMagick/ImageMagick/issues/102

**resumo da CVE**

> coders/wpg.c in ImageMagick allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -337,7 +337,7 @@
                          AppendImageToList(&image,flip_image);
                        }
                      }
-      /* rotate command */
+                  /* rotate command */
                    if(BitmapHeader2.RotAngle & 0x0FFF)
                      {
                        Image
@@ -359,7 +359,7 @@
                if (image->next == (Image *) NULL)
                  goto Finish;
                image=SyncNextImageInList(image);
-              image->columns=image->rows=0;
+              image->columns=image->rows=1;
                image->colors=0;
                break;
  
@@ -492,7 +492,7 @@
                        }
  
                      if(BImgBuff)
-                      BImgBuff=(unsigned char *) RelinquishMagickMemory(BImgBuff);;
+                      BImgBuff=(unsigned char *) RelinquishMagickMemory(BImgBuff);
                      break;
                    }
                  case 1:    /*RLE for WPG2 */
```

---

## 32. tcpdump  |  CVE-2017-12899  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/c6e0531b5def26ecf912e8de6ade86cbdaed3751
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/c6e0531b5def26ecf912e8de6ade86cbdaed3751.patch
- commit_id: c6e0531b5def26ecf912e8de6ade86cbdaed3751

**mensagem do commit**

> CVE-2017-12899/DECnet: Fix bounds checking.
> 
> If we're skipping over padding before the *real* flags, check whether
> the real flags are in the captured data before fetching it.  This fixes
> a buffer over-read discovered by Kamil Frankowicz.
> 
> Note one place where we don't need to do bounds checking as it's already
> been done.
> 
> Add a test using the capture file supplied by the reporter(s).

**resumo da CVE**

> The DECnet parser in tcpdump before 4.9.2 has a buffer over-read in print-decnet.c:decnet_print().

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -43,6 +43,7 @@
  	    length -= padlen;
  	    caplen -= padlen;
  	    rhp = (const union routehdr *)&(ap[sizeof(short)]);
+	    ND_TCHECK(rhp->rh_short.sh_flags);
  	    mflags = EXTRACT_LE_8BITS(rhp->rh_short.sh_flags);
  	}
  
```

---

## 33. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,4 +1,5 @@
 void usage_exit() {
+void usage_exit(void) {
    fprintf(stderr, "Usage: %s <codec> <width> <height> <infile> <outfile>\n",
            exec_name);
    exit(EXIT_FAILURE);
```

---

## 34. busybox  |  CVE-2018-20679  |  CWE-125
- commit: https://git.busybox.net/busybox/commit/?id=6d3b4bb24da9a07c263f3c1acf8df85382ff562c
- diff bruto: https://git.busybox.net/busybox/commit/?id=6d3b4bb24da9a07c263f3c1acf8df85382ff562c
- commit_id: 6d3b4bb24da9a07c263f3c1acf8df85382ff562c

**resumo da CVE**

> An issue was discovered in BusyBox before 1.30.0. An out of bounds read in udhcp components (consumed by the DHCP server, client, and relay) allows a remote attacker to leak sensitive information from the stack by sending a crafted DHCP message. This is related to verification in udhcp_get_option() in networking/udhcp/common.c that 4-byte options are indeed 4 bytes.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,7 +1,7 @@
  static uint32_t select_lease_time(struct dhcp_packet *packet)
  {
  	uint32_t lease_time_sec = server_config.max_lease_sec;
-	uint8_t *lease_time_opt = udhcp_get_option(packet, DHCP_LEASE_TIME);
+	uint8_t *lease_time_opt = udhcp_get_option32(packet, DHCP_LEASE_TIME);
  	if (lease_time_opt) {
  		move_from_unaligned32(lease_time_sec, lease_time_opt);
  		lease_time_sec = ntohl(lease_time_sec);
```

---

## 35. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/04839626ed859623901ebd3a5fd483982186b59d^!
- commit_id: 04839626ed859623901ebd3a5fd483982186b59d

**mensagem do commit**

> libwebm: Pull from upstream
> 
> Rolling mkvparser from upstream. Primarily for fixing a bug on parsing
> failures with certain Opus WebM files.
> 
> Upstream commit hash of this pull: 574045edd4ecbeb802ee3f1d214b5510269852ae
> 
> The diff is so huge because there were some style clean ups upstream.
> But it was ensured that there were no breaking changes when the style
> clean ups was done upstream.
> 
> Change-Id: Ib6e907175484b4b0ae1b55ab39522ea3188ad039

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,8 +1,7 @@
 long ContentEncoding::ParseEncryptionEntry(
-    long long start,
-    long long size,
-    IMkvReader* pReader,
-    ContentEncryption* encryption) {
+long ContentEncoding::ParseEncryptionEntry(long long start, long long size,
+                                           IMkvReader* pReader,
+                                           ContentEncryption* encryption) {
    assert(pReader);
    assert(encryption);
  
@@ -12,12 +11,8 @@
  
    while (pos < stop) {
      long long id, size;
-    const long status = ParseElementHeader(pReader,
-                                           pos,
-                                           stop,
-                                           id,
-                                           size);
-    if (status < 0)  //error
+    const long status = ParseElementHeader(pReader, pos, stop, id, size);
+    if (status < 0)  // error
        return status;
  
      if (id == 0x7E1) {
@@ -26,7 +21,7 @@
 
          return E_FILE_FORMAT_INVALID;
      } else if (id == 0x7E2) {
-      delete[] encryption->key_id;
+      delete[] encryption -> key_id;
        encryption->key_id = NULL;
        encryption->key_id_len = 0;
  
@@ -40,9 +35,10 @@
        if (buf == NULL)
          return -1;
  
-      const int read_status = pReader->Read(pos, buflen, buf);
+      const int read_status =
+          pReader->Read(pos, static_cast<long>(buflen), buf);
        if (read_status) {
-        delete [] buf;
+        delete[] buf;
          return status;
        }
  
@@ -50,7 +46,7 @@
 
        encryption->key_id_len = buflen;
      } else if (id == 0x7E3) {
-      delete[] encryption->signature;
+      delete[] encryption -> signature;
        encryption->signature = NULL;
        encryption->signature_len = 0;
  
@@ -64,9 +60,10 @@
        if (buf == NULL)
          return -1;
  
-      const int read_status = pReader->Read(pos, buflen, buf);
+      const int read_status =
+          pReader->Read(pos, static_cast<long>(buflen), buf);
        if (read_status) {
-        delete [] buf;
+        delete[] buf;
          return status;
        }
  
@@ -74,7 +71,7 @@
 
        encryption->signature_len = buflen;
      } else if (id == 0x7E4) {
-      delete[] encryption->sig_key_id;
+      delete[] encryption -> sig_key_id;
        encryption->sig_key_id = NULL;
        encryption->sig_key_id_len = 0;
  
@@ -88,9 +85,10 @@
        if (buf == NULL)
          return -1;
  
-      const int read_status = pReader->Read(pos, buflen, buf);
+      const int read_status =
+          pReader->Read(pos, static_cast<long>(buflen), buf);
        if (read_status) {
-        delete [] buf;
+        delete[] buf;
          return status;
        }
  
@@ -103,15 +101,12 @@
 
      } else if (id == 0x7E7) {
        const long status = ParseContentEncAESSettingsEntry(
-          pos,
-          size,
-          pReader,
-          &encryption->aes_settings);
+          pos, size, pReader, &encryption->aes_settings);
        if (status)
          return status;
      }
  
-    pos += size;  //consume payload
+    pos += size;  // consume payload
      assert(pos <= stop);
    }
  
```

---

## 36. libsndfile  |  CVE-2017-7586  |  CWE-119
- commit: https://github.com/erikd/libsndfile/commit/708e996c87c5fae77b104ccfeb8f6db784c32074
- diff bruto: https://github.com/erikd/libsndfile/commit/708e996c87c5fae77b104ccfeb8f6db784c32074.patch
- commit_id: 708e996c87c5fae77b104ccfeb8f6db784c32074

**mensagem do commit**

> src/ : Move to a variable length header buffer
> 
> Previously, the `psf->header` buffer was a fixed length specified by
> `SF_HEADER_LEN` which was set to `12292`. This was problematic for
> two reasons; this value was un-necessarily large for the majority
> of files and too small for some others.
> 
> Now the size of the header buffer starts at 256 bytes and grows as
> necessary up to a maximum of 100k.

**resumo da CVE**

> In libsndfile before 1.0.28, an error in the *header_read()* function (common.c) when handling ID3 tags can be exploited to cause a stack-based buffer overflow via a specially crafted FLAC file.

**diff da funcao (func_before vs func_after)**

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

---

## 37. Android  |  CVE-2017-0587  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libmpeg2/+/a86eb798d077b9b25c8f8c77e3c02c2f287c1ce7
- diff bruto: https://android.googlesource.com/platform/external/libmpeg2/+/a86eb798d077b9b25c8f8c77e3c02c2f287c1ce7^!
- commit_id: a86eb798d077b9b25c8f8c77e3c02c2f287c1ce7

**mensagem do commit**

> Fix in handling header decode errors
> 
> If header decode was unsuccessful, do not try decoding a frame
> 
> Also, initialize pic_wd, pic_ht for reinitialization when
> decoder is created with smaller dimensions
> 
> Bug: 28886651
> Bug: 35219737
> Change-Id: I8c06d9052910e47fce2e6fe25ad318d4c83d2c50
> (cherry picked from commit 2b9fa9ace2dbedfbac026fc9b6ab6cdac7f68c27)
> (cherry picked from commit c2395cd7cc0c286a66de674032dd2ed26500aef4)
> 

**resumo da CVE**

> A remote code execution vulnerability in libmpeg2 in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-35219737.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -54,7 +54,9 @@
                      || (ps_dec->u2_vertical_size > ps_dec->u2_create_max_height))
      {
          IMPEG2D_ERROR_CODES_T e_error = IMPEG2D_UNSUPPORTED_DIMENSIONS;
-        return SET_IVD_FATAL_ERROR(e_error);
+        ps_dec->u2_reinit_max_height   = ps_dec->u2_vertical_size;
+        ps_dec->u2_reinit_max_width    = ps_dec->u2_horizontal_size;
+        return e_error;
      }
  
  
```

---

## 38. rdesktop  |  CVE-2018-20182  |  CWE-119
- commit: https://github.com/rdesktop/rdesktop/commit/4dca546d04321a610c1835010b5dad85163b65e1
- diff bruto: https://github.com/rdesktop/rdesktop/commit/4dca546d04321a610c1835010b5dad85163b65e1.patch
- commit_id: 4dca546d04321a610c1835010b5dad85163b65e1

**mensagem do commit**

> Malicious RDP server security fixes
> 
> This commit includes fixes for a set of 21 vulnerabilities in
> rdesktop when a malicious RDP server is used.
> 
> All vulnerabilities was identified and reported by Eyal Itkin.
> 
>  * Add rdp_protocol_error function that is used in several fixes
>  * Refactor of process_bitmap_updates
>  * Fix possible integer overflow in s_check_rem() on 32bit arch
>  * Fix memory corruption in process_bitmap_data - CVE-2018-8794
>  * Fix remote code execution in process_bitmap_data - CVE-2018-8795
>  * Fix remote code execution in process_plane - CVE-2018-8797
>  * Fix Denial of Service in mcs_recv_connect_response - CVE-2018-20175
>  * Fix Denial of Service in mcs_parse_domain_params - CVE-2018-20175
>  * Fix Denial of Service in sec_parse_crypt_info - CVE-2018-20176
>  * Fix Denial of Service in sec_recv - CVE-2018-20176
>  * Fix minor information leak in rdpdr_process - CVE-2018-8791
>  * Fix Denial of Service in cssp_read_tsrequest - CVE-2018-8792
>  * Fix remote code execution in cssp_read_tsrequest - CVE-2018-8793
>  * Fix Denial of Service in process_bitmap_data - CVE-2018-8796
>  * Fix minor information leak in rdpsnd_process_ping - CVE-2018-8798
>  * Fix Denial of Service in process_secondary_order - CVE-2018-8799
>  * Fix remote code execution in in ui_clip_handle_data - CVE-2018-8800
>  * Fix major information leak in ui_clip_handle_data - CVE-2018-20174
>  * Fix memory corruption in rdp_in_unistr - CVE-2018-20177
>  * Fix Denial of Service in process_demand_active - CVE-2018-20178
>  * Fix remote code execution in lspci_process - CVE-2018-20179
>  * Fix remote code execution in rdpsnddbg_process - CVE-2018-20180
>  * Fix remote code execution in seamless_process - CVE-2018-20181
>  * Fix remote code execution in seamless_process_line - CVE-2018-20182

**resumo da CVE**

> rdesktop versions up to and including v1.8.3 contain a Buffer Overflow over the global variables in the function seamless_process_line() that results in memory corruption and probably even a remote code execution.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -3,6 +3,12 @@
  	uint16 tick;
  	uint16 packsize;
  	STREAM out;
+	struct stream packet = *in;
+
+	if (!s_check_rem(in, 4))
+	{
+		rdp_protocol_error("rdpsnd_process_training(), consume of training data from stream would overrun", &packet);
+	}
  
  	in_uint16_le(in, tick);
  	in_uint16_le(in, packsize);
```

---

## 39. Chrome  |  CVE-2015-8126  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/7f3d85b096f66870a15b37c2f40b219b2e292693
- diff bruto: https://github.com/chromium/chromium/commit/7f3d85b096f66870a15b37c2f40b219b2e292693.patch
- commit_id: 7f3d85b096f66870a15b37c2f40b219b2e292693

**mensagem do commit**

> third_party/libpng: update to 1.2.54
> 
> TBR=darin@chromium.org
> BUG=560291
> 
> Review URL: https://codereview.chromium.org/1467263003
> 
> Cr-Commit-Position: refs/heads/master@{#362298}

**resumo da CVE**

> Multiple buffer overflows in the (1) png_set_PLTE and (2) png_get_PLTE functions in libpng before 1.0.64, 1.1.x and 1.2.x before 1.2.54, 1.3.x and 1.4.x before 1.4.17, 1.5.x before 1.5.24, and 1.6.x before 1.6.19 allow remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a small bit-depth value in an IHDR (aka image header) chunk in a PNG image.

**diff da funcao (func_before vs func_after)**

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

---

## 40. linux  |  CVE-2010-5332  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/0926f91083f34d047abc74f1ca4fa6a9c161f7db
- diff bruto: https://github.com/torvalds/linux/commit/0926f91083f34d047abc74f1ca4fa6a9c161f7db.patch
- commit_id: 0926f91083f34d047abc74f1ca4fa6a9c161f7db

**mensagem do commit**

> mlx4_en: Fix out of bounds array access
> 
> When searching for a free entry in either mlx4_register_vlan() or
> mlx4_register_mac(), and there is no free entry, the loop terminates without
> updating the local variable free thus causing out of array bounds access. Fix
> this by adding a proper check outside the loop.
> 
> Signed-off-by: Eli Cohen <eli@mellanox.co.il>
> Signed-off-by: David S. Miller <davem@davemloft.net>

**resumo da CVE**

> In the Linux kernel before 2.6.37, an out of bounds array access happened in drivers/net/mlx4/port.c. When searching for a free entry in either mlx4_register_vlan() or mlx4_register_mac(), and there is no free entry, the loop terminates without updating the local variable free thus causing out of array bounds access.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -19,6 +19,12 @@
  			goto out;
  		}
  	}
+
+	if (free < 0) {
+		err = -ENOMEM;
+		goto out;
+	}
+
  	mlx4_dbg(dev, "Free MAC index is %d\n", free);
  
  	if (table->total == table->max) {
```

---

## 41. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -5,4 +5,6 @@
      tx_type_  = GET_PARAM(2);
      pitch_    = 4;
      fwd_txfm_ref = fht4x4_ref;
+    bit_depth_ = GET_PARAM(3);
+    mask_ = (1 << bit_depth_) - 1;
    }
```

---

## 42. Chrome  |  CVE-2011-2794  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/3057be01bcbbd1d0938afb489e18f2ca6d9b8229
- diff bruto: https://github.com/chromium/chromium/commit/3057be01bcbbd1d0938afb489e18f2ca6d9b8229.patch
- commit_id: 3057be01bcbbd1d0938afb489e18f2ca6d9b8229

**mensagem do commit**

> Remove minimum and maximum scroll position as they are no
> longer required due to changes in ScrollViewBase.
> https://bugs.webkit.org/show_bug.cgi?id=87298
> 
> Patch by Genevieve Mak <gmak@rim.com> on 2012-05-23
> Reviewed by Antonio Gomes.
> 
> * WebKitSupport/InRegionScrollableArea.cpp:
> (BlackBerry::WebKit::InRegionScrollableArea::InRegionScrollableArea):
> * WebKitSupport/InRegionScrollableArea.h:
> (InRegionScrollableArea):
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@118233 bbb929c8-8fbe-4397-9dbb-9b2b20218538

**resumo da CVE**

> Google Chrome before 13.0.782.107 does not properly perform text iteration, which allows remote attackers to cause a denial of service (out-of-bounds read) via unspecified vectors.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,6 +1 @@
 Platform::IntPoint InRegionScrollableArea::calculateMinimumScrollPosition(const Platform::IntSize& viewportSize, float overscrollLimitFactor) const
-{
-    ASSERT(!allowsOverscroll());
-    return Platform::IntPoint(-(viewportSize.width() * overscrollLimitFactor),
-                              -(viewportSize.height() * overscrollLimitFactor));
-}
```

---

## 43. Android  |  CVE-2016-1621  |  CWE-119
- commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- diff bruto: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426^!
- commit_id: 5a9753fca56f0eeb9f61e342b2fccffc364f9426

**mensagem do commit**

> Merge Conflict Fix CL to lmp-mr1-release for ag/849478
> 
> DO NOT MERGE - libvpx: Pull from upstream
> 
> Current HEAD: 7105df53d7dc13d5e575bc8df714ec8d1da36b06
> 
> BUG=23452792
> 
> Change-Id: Ic78176fc369e0bacc71d423e0e2e6075d004aaec
> 

**resumo da CVE**

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,5 +1,15 @@
    virtual void SetUp() {
      InitializeConfig();
-    SetMode(GET_PARAM(1));
-    set_cpu_used_ = GET_PARAM(2);
+    SetMode(encoding_mode_);
+    if (encoding_mode_ != ::libvpx_test::kRealTime) {
+      cfg_.g_lag_in_frames = 25;
+      cfg_.rc_end_usage = VPX_VBR;
+    } else {
+      cfg_.g_lag_in_frames = 0;
+      cfg_.rc_end_usage = VPX_CBR;
+    }
+  }
+
+  virtual void BeginPassHook(unsigned int /*pass*/) {
+    min_psnr_ = kMaxPSNR;
    }
```

---

## 44. wildmidi  |  CVE-2017-11664  |  CWE-125
- commit: https://github.com/Mindwerks/wildmidi/commit/660b513d99bced8783a4a5984ac2f742c74ebbdd
- diff bruto: https://github.com/Mindwerks/wildmidi/commit/660b513d99bced8783a4a5984ac2f742c74ebbdd.patch
- commit_id: 660b513d99bced8783a4a5984ac2f742c74ebbdd

**mensagem do commit**

> Add a new size parameter to _WM_SetupMidiEvent() so that it knows
> where to stop reading, and adjust its users properly. Fixes bug #175
> (CVE-2017-11661, CVE-2017-11662, CVE-2017-11663, CVE-2017-11664.)

**resumo da CVE**

> The _WM_SetupMidiEvent function in internal_midi.c:2122 in WildMIDI 0.4.2 can cause a denial of service (invalid memory read and application crash) via a crafted mid file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -177,6 +177,7 @@
         }
  
          hmp_data = hmp_chunk[i] + chunk_length[i];
+        chunk_length[i] -= chunk_ofs[i];
          hmp_chunk[i] += chunk_ofs[i]++;
          chunk_end[i] = 0;
      }
@@ -211,10 +212,11 @@
             do {
                 if (((hmp_chunk[i][0] & 0xf0) == 0xb0 ) && ((hmp_chunk[i][1] == 110) || (hmp_chunk[i][1] == 111)) && (hmp_chunk[i][2] > 0x7f)) {
                      hmp_chunk[i] += 3;
+                    chunk_length[i] -= 3;
                  } else {
                      uint32_t setup_ret = 0;
  
-                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], 0)) == 0) {
+                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], chunk_length[i], 0)) == 0) {
                          goto _hmp_end;
                      }
  
@@ -222,6 +224,7 @@
                          /* End of Chunk */
                          end_of_chunks++;
                          chunk_end[i] = 1;
+                        chunk_length[i] -= 3;
                          hmp_chunk[i] += 3;
                          goto NEXT_CHUNK;
                      } else if ((hmp_chunk[i][0] == 0xff) && (hmp_chunk[i][1] == 0x51) && (hmp_chunk[i][2] == 0x03)) {
@@ -233,18 +236,26 @@
                          fprintf(stderr,"DEBUG: Tempo change %f\r\n", tempo_f);
                      }
                      hmp_chunk[i] += setup_ret;
+                    chunk_length[i] -= setup_ret;
                  }
                  var_len_shift = 0;
                  chunk_delta[i] = 0;
-                if (*hmp_chunk[i] < 0x80) {
+                if (chunk_length[i] && *hmp_chunk[i] < 0x80) {
                      do {
+                        if (! chunk_length[i]) break;
                          chunk_delta[i] = chunk_delta[i] + ((*hmp_chunk[i] & 0x7F) << var_len_shift);
                          var_len_shift += 7;
                          hmp_chunk[i]++;
+                        chunk_length[i]--;
                      } while (*hmp_chunk[i] < 0x80);
                  }
+                if (! chunk_length[i]) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMP, "file too short", 0);
+                    goto _hmp_end;
+                }
                  chunk_delta[i] = chunk_delta[i] + ((*hmp_chunk[i] & 0x7F) << var_len_shift);
                  hmp_chunk[i]++;
+                chunk_length[i]--;
              } while (!chunk_delta[i]);
  
              if ((!smallest_delta) || (smallest_delta > chunk_delta[i])) {
```

---

## 45. ImageMagick  |  CVE-2016-10066  |  CWE-119
- commit: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6.patch
- commit_id: f6e9d0d9955e85bdd7540b251cd50d598dacc5e6

**resumo da CVE**

> Buffer overflow in the ReadVIFFImage function in coders/viff.c in ImageMagick before 6.9.4-5 allows remote attackers to cause a denial of service (application crash) via a crafted file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -480,6 +480,12 @@
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

---

## 46. linux  |  CVE-2013-1860  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/c0f5ecee4e741667b2493c742b60b6218d40b3aa
- diff bruto: https://github.com/torvalds/linux/commit/c0f5ecee4e741667b2493c742b60b6218d40b3aa.patch
- commit_id: c0f5ecee4e741667b2493c742b60b6218d40b3aa

**mensagem do commit**

> USB: cdc-wdm: fix buffer overflow
> 
> The buffer for responses must not overflow.
> If this would happen, set a flag, drop the data and return
> an error after user space has read all remaining data.
> 
> Signed-off-by: Oliver Neukum <oliver@neukum.org>
> CC: stable@kernel.org
> Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

**resumo da CVE**

> Heap-based buffer overflow in the wdm_in_callback function in drivers/usb/class/cdc-wdm.c in the Linux kernel before 3.8.4 allows physically proximate attackers to cause a denial of service (system crash) or possibly execute arbitrary code via a crafted cdc-wdm USB device.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,6 +2,7 @@
  {
  	struct wdm_device *desc = urb->context;
  	int status = urb->status;
+	int length = urb->actual_length;
  
  	spin_lock(&desc->iuspin);
  	clear_bit(WDM_RESPONDING, &desc->flags);
@@ -32,9 +33,17 @@
  	}
  
  	desc->rerr = status;
-	desc->reslength = urb->actual_length;
-	memmove(desc->ubuf + desc->length, desc->inbuf, desc->reslength);
-	desc->length += desc->reslength;
+	if (length + desc->length > desc->wMaxCommand) {
+		/* The buffer would overflow */
+		set_bit(WDM_OVERFLOW, &desc->flags);
+	} else {
+		/* we may already be in overflow */
+		if (!test_bit(WDM_OVERFLOW, &desc->flags)) {
+			memmove(desc->ubuf + desc->length, desc->inbuf, length);
+			desc->length += length;
+			desc->reslength = length;
+		}
+	}
  skip_error:
  	wake_up(&desc->wait);
  
```

---

## 47. gstreamer  |  CVE-2009-0397  |  CWE-119
- commit: https://cgit.freedesktop.org/gstreamer/gst-plugins-good/commit/?id=bdc20b9baf13564d9a061343416395f8f9a92b53
- diff bruto: https://cgit.freedesktop.org/gstreamer/gst-plugins-good/commit/?id=bdc20b9baf13564d9a061343416395f8f9a92b53
- commit_id: bdc20b9baf13564d9a061343416395f8f9a92b53

**resumo da CVE**

> Heap-based buffer overflow in the qtdemux_parse_samples function in gst/qtdemux/qtdemux.c in GStreamer Good Plug-ins (aka gst-plugins-good) 0.10.9 through 0.10.11, and GStreamer Plug-ins (aka gstreamer-plugins) 0.8.5, might allow remote attackers to execute arbitrary code via crafted Time-to-sample (aka stts) atom data in a malformed QuickTime media .mov file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -105,13 +105,13 @@
      stream->min_duration = 0;
      time = 0;
      index = 0;
-    for (i = 0; i < n_sample_times; i++) {
+    for (i = 0; (i < n_sample_times) && (index < stream->n_samples); i++) {
        guint32 n;
        guint32 duration;
  
        n = QT_UINT32 ((guint8 *) stts->data + 16 + 8 * i);
        duration = QT_UINT32 ((guint8 *) stts->data + 16 + 8 * i + 4);
-      for (j = 0; j < n; j++) {
+      for (j = 0; (j < n) && (index < stream->n_samples); j++) {
          GST_DEBUG_OBJECT (qtdemux, "sample %d: timestamp %" GST_TIME_FORMAT,
              index, GST_TIME_ARGS (timestamp));
  
@@ -139,7 +139,7 @@
          for (i = 0; i < n_sample_syncs; i++) {
            /* note that the first sample is index 1, not 0 */
            index = QT_UINT32 ((guint8 *) stss->data + offset);
-          if (index > 0) {
+          if (index > 0 && index <= stream->n_samples) {
              samples[index - 1].keyframe = TRUE;
              offset += 4;
            }
@@ -238,7 +238,7 @@
      for (i = 0, j = 0; (j < stream->n_samples) && (i < n_entries); i++) {
        count = QT_UINT32 (ctts_data + 16 + i * 8);
        soffset = QT_UINT32 (ctts_data + 20 + i * 8);
-      for (k = 0; k < count; k++, j++) {
+      for (k = 0; (k < count) && (j < stream->n_samples); k++, j++) {
          /* we operate with very small soffset values here, it shouldn't overflow */
          samples[j].pts_offset = soffset * GST_SECOND / stream->timescale;
        }
```

---

## 48. Chrome  |  CVE-2011-2806  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/01e4ee2fda0a5e57a8d0c8cb829022eb84fdff12
- diff bruto: https://github.com/chromium/chromium/commit/01e4ee2fda0a5e57a8d0c8cb829022eb84fdff12.patch
- commit_id: 01e4ee2fda0a5e57a8d0c8cb829022eb84fdff12

**mensagem do commit**

> Rename isPositioned to isOutOfFlowPositioned for clarity
> https://bugs.webkit.org/show_bug.cgi?id=89836
> 
> Reviewed by Antti Koivisto.
> 
> RenderObject and RenderStyle had an isPositioned() method that was
> confusing, because it excluded relative positioning. Rename to
> isOutOfFlowPositioned(), which makes it clearer that it only applies
> to absolute and fixed positioning.
> 
> Simple rename; no behavior change.
> 
> Source/WebCore:
> 
> * css/CSSComputedStyleDeclaration.cpp:
> (WebCore::getPositionOffsetValue):
> * css/StyleResolver.cpp:
> (WebCore::StyleResolver::collectMatchingRulesForList):
> * dom/Text.cpp:
> (WebCore::Text::rendererIsNeeded):
> * editing/DeleteButtonController.cpp:
> (WebCore::isDeletableElement):
> * editing/TextIterator.cpp:
> (WebCore::shouldEmitNewlinesBeforeAndAfterNode):
> * rendering/AutoTableLayout.cpp:
> (WebCore::shouldScaleColumns):
> * rendering/InlineFlowBox.cpp:
> (WebCore::InlineFlowBox::addToLine):
> (WebCore::InlineFlowBox::placeBoxesInInlineDirection):
> (WebCore::InlineFlowBox::requiresIdeographicBaseline):
> (WebCore::InlineFlowBox::adjustMaxAscentAndDescent):
> (WebCore::InlineFlowBox::computeLogicalBoxHeights):
> (WebCore::InlineFlowBox::placeBoxesInBlockDirection):
> (WebCore::InlineFlowBox::flipLinesInBlockDirection):
> (WebCore::InlineFlowBox::computeOverflow):
> (WebCore::InlineFlowBox::computeOverAnnotationAdjustment):
> (WebCore::InlineFlowBox::computeUnderAnnotationAdjustment):
> * rendering/InlineIterator.h:
> (WebCore::isIteratorTarget):
> * rendering/LayoutState.cpp:
> (WebCore::LayoutState::LayoutState):
> * rendering/RenderBlock.cpp:
> (WebCore::RenderBlock::MarginInfo::MarginInfo):
> (WebCore::RenderBlock::styleWillChange):
> (WebCore::RenderBlock::styleDidChange):
> (WebCore::RenderBlock::addChildToContinuation):
> (WebCore::RenderBlock::addChildToAnonymousColumnBlocks):
> (WebCore::RenderBlock::containingColumnsBlock):
> (WebCore::RenderBlock::columnsBlockForSpanningElement):
> (WebCore::RenderBlock::addChildIgnoringAnonymousColumnBlocks):
> (WebCore::getInlineRun):
> (WebCore::RenderBlock::isSelfCollapsingBlock):
> (WebCore::RenderBlock::layoutBlock):
> (WebCore::RenderBlock::addOverflowFromBlockChildren):
> (WebCore::RenderBlock::expandsToEncloseOverhangingFloats):
> (WebCore::RenderBlock::handlePositionedChild):
> (WebCore::RenderBlock::moveRunInUnderSiblingBlockIfNeeded):
> (WebCore::RenderBlock::collapseMargins):
> (WebCore::RenderBlock::clearFloatsIfNeeded):
> (WebCore::RenderBlock::simplifiedNormalFlowLayout):
> (WebCore::RenderBlock::isSelectionRoot):
> (WebCore::RenderBlock::blockSelectionGaps):
> (WebCore::RenderBlock::clearFloats):
> (WebCore::RenderBlock::markAllDescendantsWithFloatsForLayout):
> (WebCore::RenderBlock::markSiblingsWithFloatsForLayout):
> (WebCore::isChildHitTestCandidate):
> (WebCore::InlineMinMaxIterator::next):
> (WebCore::RenderBlock::computeBlockPreferredLogicalWidths):
> (WebCore::RenderBlock::firstLineBoxBaseline):
> (WebCore::RenderBlock::lastLineBoxBaseline):
> (WebCore::RenderBlock::updateFirstLetter):
> (WebCore::shouldCheckLines):
> (WebCore::getHeightForLineCount):
> (WebCore::RenderBlock::adjustForBorderFit):
> (WebCore::inNormalFlow):
> (WebCore::RenderBlock::adjustLinePositionForPagination):
> (WebCore::RenderBlock::adjustBlockChildForPagination):
> (WebCore::RenderBlock::renderName):
> * rendering/RenderBlock.h:
> (WebCore::RenderBlock::shouldSkipCreatingRunsForObject):
> * rendering/RenderBlockLineLayout.cpp:
> (WebCore::RenderBlock::setMarginsForRubyRun):
> (WebCore::RenderBlock::computeInlineDirectionPositionsForLine):
> (WebCore::RenderBlock::computeBlockDirectionPositionsForLine):
> (WebCore::RenderBlock::layoutInlineChildren):
> (WebCore::requiresLineBox):
> (WebCore::RenderBlock::LineBreaker::skipTrailingWhitespace):
> (WebCore::RenderBlock::LineBreaker::skipLeadingWhitespace):
> (WebCore::RenderBlock::LineBreaker::nextLineBreak):
> * rendering/RenderBox.cpp:
> (WebCore::RenderBox::removeFloatingOrPositionedChildFromBlockLists):
> (WebCore::RenderBox::styleWillChange):
> (WebCore::RenderBox::styleDidChange):
> (WebCore::RenderBox::updateBoxModelInfoFromStyle):
> (WebCore::RenderBox::offsetFromContainer):
> (WebCore::RenderBox::positionLineBox):
> (WebCore::RenderBox::computeRectForRepaint):
> (WebCore::RenderBox::computeLogicalWidthInRegion):
> (WebCore::RenderBox::renderBoxRegionInfo):
> (WebCore::RenderBox::computeLogicalHeight):
> (WebCore::RenderBox::computePercentageLogicalHeight):
> (WebCore::RenderBox::computeReplacedLogicalWidthUsing):
> (WebCore::RenderBox::computeReplacedLogicalHeightUsing):
> (WebCore::RenderBox::availableLogicalHeightUsing):
> (WebCore::percentageLogicalHeightIsResolvable):
> * rendering/RenderBox.h:
> (WebCore::RenderBox::stretchesToViewport):
> (WebCore::RenderBox::isDeprecatedFlexItem):
> * rendering/RenderBoxModelObject.cpp:
> (WebCore::RenderBoxModelObject::adjustedPositionRelativeToOffsetParent):
> (WebCore::RenderBoxModelObject::mapAbsoluteToLocalPoint):
> * rendering/RenderBoxModelObject.h:
> (WebCore::RenderBoxModelObject::requiresLayer):
> * rendering/RenderDeprecatedFlexibleBox.cpp:
> (WebCore::childDoesNotAffectWidthOrFlexing):
> (WebCore::RenderDeprecatedFlexibleBox::layoutBlock):
> (WebCore::RenderDeprecatedFlexibleBox::layoutHorizontalBox):
> (WebCore::RenderDeprecatedFlexibleBox::layoutVerticalBox):
> (WebCore::RenderDeprecatedFlexibleBox::renderName):
> * rendering/RenderFieldset.cpp:
> (WebCore::RenderFieldset::findLegend):
> * rendering/RenderFlexibleBox.cpp:
> (WebCore::RenderFlexibleBox::computePreferredLogicalWidths):
> (WebCore::RenderFlexibleBox::autoMarginOffsetInMainAxis):
> (WebCore::RenderFlexibleBox::availableAlignmentSpaceForChild):
> (WebCore::RenderFlexibleBox::computeMainAxisPreferredSizes):
> (WebCore::RenderFlexibleBox::computeNextFlexLine):
> (WebCore::RenderFlexibleBox::resolveFlexibleLengths):
> (WebCore::RenderFlexibleBox::prepareChildForPositionedLayout):
> (WebCore::RenderFlexibleBox::layoutAndPlaceChildren):
> (WebCore::RenderFlexibleBox::layoutColumnReverse):
> (WebCore::RenderFlexibleBox::adjustAlignmentForChild):
> (WebCore::RenderFlexibleBox::flipForRightToLeftColumn):
> * rendering/RenderGrid.cpp:
> (WebCore::RenderGrid::renderName):
> * rendering/RenderImage.cpp:
> (WebCore::RenderImage::computeIntrinsicRatioInformation):
> * rendering/RenderInline.cpp:
> (WebCore::RenderInline::addChildIgnoringContinuation):
> (WebCore::RenderInline::addChildToContinuation):
> (WebCore::RenderInline::generateCulledLineBoxRects):
> (WebCore):
> (WebCore::RenderInline::culledInlineFirstLineBox):
> (WebCore::RenderInline::culledInlineLastLineBox):
> (WebCore::RenderInline::culledInlineVisualOverflowBoundingBox):
> (WebCore::RenderInline::computeRectForRepaint):
> (WebCore::RenderInline::dirtyLineBoxes):
> * rendering/RenderLayer.cpp:
> (WebCore::checkContainingBlockChainForPagination):
> (WebCore::RenderLayer::updateLayerPosition):
> (WebCore::isPositionedContainer):
> (WebCore::RenderLayer::calculateClipRects):
> (WebCore::RenderLayer::shouldBeNormalFlowOnly):
> * rendering/RenderLayerCompositor.cpp:
> (WebCore::RenderLayerCompositor::requiresCompositingForPosition):
> * rendering/RenderLineBoxList.cpp:
> (WebCore::RenderLineBoxList::dirtyLinesFromChangedChild):
> * rendering/RenderListItem.cpp:
> (WebCore::getParentOfFirstLineBox):
> * rendering/RenderMultiColumnBlock.cpp:
> (WebCore::RenderMultiColumnBlock::renderName):
> * rendering/RenderObject.cpp:
> (WebCore::RenderObject::markContainingBlocksForLayout):
> (WebCore::RenderObject::setPreferredLogicalWidthsDirty):
> (WebCore::RenderObject::invalidateContainerPreferredLogicalWidths):
> (WebCore::RenderObject::styleWillChange):
> (WebCore::RenderObject::offsetParent):
> * rendering/RenderObject.h:
> (WebCore::RenderObject::isOutOfFlowPositioned):
> (WebCore::RenderObject::isInFlowPositioned):
> (WebCore::RenderObject::hasClip):
> (WebCore::RenderObject::isFloatingOrOutOfFlowPositioned):
> * rendering/RenderObjectChildList.cpp:
> (WebCore::RenderObjectChildList::removeChildNode):
> * rendering/RenderReplaced.cpp:
> (WebCore::hasAutoHeightOrContainingBlockWithAutoHeight):
> * rendering/RenderRubyRun.cpp:
> (WebCore::RenderRubyRun::rubyText):
> * rendering/RenderTable.cpp:
> (WebCore::RenderTable::addChild):
> (WebCore::RenderTable::computeLogicalWidth):
> (WebCore::RenderTable::layout):
> * rendering/style/RenderStyle.h:
> 
> Source/WebKit/blackberry:
> 
> * Api/WebPage.cpp:
> (BlackBerry::WebKit::isPositionedContainer):
> (BlackBerry::WebKit::isNonRenderViewFixedPositionedContainer):
> (BlackBerry::WebKit::isFixedPositionedContainer):
> 
> Source/WebKit2:
> 
> * WebProcess/WebPage/qt/LayerTreeHostQt.cpp:
> (WebKit::updateOffsetFromViewportForSelf):
> 
> git-svn-id: svn://svn.chromium.org/blink/trunk@121123 bbb929c8-8fbe-4397-9dbb-9b2b20218538

**resumo da CVE**

> Google Chrome before 13.0.782.215 on Windows does not properly handle vertex data, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -29,8 +29,9 @@
          return cssValuePool().createValue(l);
      }
  
-    if (style->position() == RelativePosition)
+    if (style->position() == RelativePosition) {
          return cssValuePool().createValue(l);
+    }
  
      return cssValuePool().createIdentifierValue(CSSValueAuto);
  }
```

---

## 49. FFmpeg  |  CVE-2013-4263  |  CWE-119
- commit: https://github.com/FFmpeg/FFmpeg/commit/e43a0a232dbf6d3c161823c2e07c52e76227a1bc
- diff bruto: https://github.com/FFmpeg/FFmpeg/commit/e43a0a232dbf6d3c161823c2e07c52e76227a1bc.patch
- commit_id: e43a0a232dbf6d3c161823c2e07c52e76227a1bc

**mensagem do commit**

> avfilter: fix plane validity checks
> 
> Fixes out of array accesses
> 
> Signed-off-by: Michael Niedermayer <michaelni@gmx.at>

**resumo da CVE**

> libavfilter in FFmpeg before 2.0.1 has unspecified impact and remote vectors related to a crafted *plane,* which triggers an out-of-bounds heap write.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -28,7 +28,7 @@
      if (!sar.num)
          sar.num = sar.den = 1;
  
-    for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
          int hsub = plane == 1 || plane == 2 ? hsub0 : 0;
          int vsub = plane == 1 || plane == 2 ? vsub0 : 0;
  
```

---

## 50. ImageMagick  |  CVE-2019-10714  |  CWE-125
- commit: https://github.com/ImageMagick/ImageMagick/commit/58d9c46929ca0828edde34d263700c3a5fe8dc3c
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/58d9c46929ca0828edde34d263700c3a5fe8dc3c.patch
- commit_id: 58d9c46929ca0828edde34d263700c3a5fe8dc3c

**mensagem do commit**

> ...

**resumo da CVE**

> LocaleLowercase in MagickCore/locale.c in ImageMagick before 7.0.8-32 allows out-of-bounds access, leading to a SIGSEGV.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,6 +1,6 @@
  MagickExport int LocaleLowercase(const int c)
  {
-  if (c < 0)
+  if (c == EOF)
      return(c);
  #if defined(MAGICKCORE_LOCALE_SUPPORT)
    if (c_locale != (locale_t) NULL)
```
