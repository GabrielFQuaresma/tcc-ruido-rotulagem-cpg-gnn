# Caderno da segunda validação manual

Leitura cega: este caderno não diz, e não deve dizer, o que a curadoria fez com cada função. Não abra a pasta `chave/` antes de terminar (o `LEIA_ME.md` explica por quê).

**Como usar.** Para cada caso: leia a mensagem do commit e o resumo da CVE, olhe o diff da função (e, se precisar, o link do commit para ver o resto do conserto) e preencha a linha do caso em `anotacao_segunda.csv` — a coluna `id` é o número do caso. Não edite este caderno: o SHA-256 dele está no pré-registro.

**Rubrica** (`../rubrica_v1.md`, congelada; a mesma da primeira validação):

- **A** — sem mudança semântica na função (só espaço em branco, formatação ou comentário). Não vulnerável.
- **B** — a função mudou, mas a mudança não tem relação com a CVE (refatoração, funcionalidade não relacionada, outro subsistema que veio junto no commit). Não vulnerável.
- **C** — a função mudou como parte do conserto, mas o defeito explorável não está nela (ajuste de parâmetro, reset de contador, hardening de apoio, propagação de argumento). Não vulnerável.
- **D** — a função é o sítio da vulnerabilidade: o defeito (acesso indevido, checagem de limite que falta, overflow que alimenta o tamanho) está no corpo dela. Vulnerável.
- **?** — não deu para decidir com a evidência disponível (não chute para evitar o `?`).

`confianca`: `alta`, `media` ou `baixa`. `cwe_correta`: só nos D, no formato `CWE-NNN`. `observacao`: uma ou duas frases; nos D, diga se reconheceu o bug só com a função ou se precisou do commit inteiro.

Os casos cujo diff some depois de normalizar o espaço em branco já vêm marcados como **A** na planilha (confiança `alta`, observação terminada em "(auto)").

## Casos

| caso | projeto | CVE | CWE do BigVul |
| --- | --- | --- | --- |
| 01 | linux | CVE-2019-15090 | CWE-125 |
| 02 | FFmpeg | CVE-2016-10190 | CWE-119 |
| 03 | linux | CVE-2013-4312 | CWE-119 |
| 04 | Android | CVE-2018-9496 | CWE-787 |
| 05 | ghostscript | CVE-2016-9601 | CWE-119 |
| 06 | Chrome | CVE-2013-2877 | CWE-119 |
| 07 | tcpdump | CVE-2017-13000 | CWE-125 |
| 08 | rdesktop | CVE-2018-20182 | CWE-119 |
| 09 | Chrome | CVE-2015-1215 | CWE-119 |
| 10 | krb5 | CVE-2015-8631 | CWE-119 |
| 11 | ghostscript | CVE-2016-9601 | CWE-119 |
| 12 | libtiff | CVE-2016-9535 | CWE-119 |
| 13 | file | CVE-2014-2270 | CWE-119 |
| 14 | ImageMagick | CVE-2015-8958 | CWE-125 |
| 15 | Chrome | CVE-2016-1683 | CWE-119 |
| 16 | radare2 | CVE-2018-11376 | CWE-125 |
| 17 | php-src | CVE-2016-7416 | CWE-119 |
| 18 | libsndfile | CVE-2017-7586 | CWE-119 |
| 19 | Chrome | CVE-2017-5077 | CWE-125 |
| 20 | tcpdump | CVE-2017-13039 | CWE-125 |
| 21 | Android | CVE-2016-1621 | CWE-119 |
| 22 | pyfribidi | CVE-2012-1176 | CWE-119 |
| 23 | linux | CVE-2011-4098 | CWE-119 |
| 24 | Chrome | CVE-2016-1683 | CWE-119 |
| 25 | ImageMagick | CVE-2016-10066 | CWE-119 |
| 26 | rdesktop | CVE-2018-20182 | CWE-119 |
| 27 | Android | CVE-2016-1621 | CWE-119 |
| 28 | linux | CVE-2017-8069 | CWE-119 |
| 29 | libxfont | CVE-2013-6462 | CWE-119 |
| 30 | Android | CVE-2016-1621 | CWE-119 |
| 31 | openjpeg | CVE-2017-14040 | CWE-787 |
| 32 | tcpdump | CVE-2017-13010 | CWE-125 |
| 33 | Chrome | CVE-2016-1683 | CWE-119 |
| 34 | tcpdump | CVE-2017-13004 | CWE-125 |
| 35 | Android | CVE-2016-1621 | CWE-119 |
| 36 | FFmpeg | CVE-2017-14767 | CWE-119 |
| 37 | Chrome | CVE-2016-5209 | CWE-787 |
| 38 | ImageMagick | CVE-2016-10066 | CWE-119 |
| 39 | Android | CVE-2016-2476 | CWE-119 |
| 40 | Android | CVE-2016-3861 | CWE-119 |
| 41 | ImageMagick | CVE-2016-7527 | CWE-125 |
| 42 | ghostscript | CVE-2014-2013 | CWE-119 |
| 43 | tcpdump | CVE-2017-13690 | CWE-125 |
| 44 | Android | CVE-2016-1621 | CWE-119 |
| 45 | openssl | CVE-2015-1789 | CWE-119 |
| 46 | krb5 | CVE-2015-8631 | CWE-119 |
| 47 | Android | CVE-2015-3832 | CWE-119 |
| 48 | Chrome | CVE-2012-5152 | CWE-119 |
| 49 | liblouis | CVE-2018-17294 | CWE-125 |
| 50 | Chrome | CVE-2013-2877 | CWE-119 |
| 51 | Android | CVE-2016-3745 | CWE-119 |
| 52 | Android | CVE-2016-1621 | CWE-119 |
| 53 | tcpdump | CVE-2017-12894 | CWE-125 |
| 54 | Android | CVE-2016-2508 | CWE-119 |
| 55 | linux | CVE-2013-2234 | CWE-119 |
| 56 | imageworsener | CVE-2017-9203 | CWE-787 |
| 57 | savannah | CVE-2014-9665 | CWE-119 |
| 58 | Android | CVE-2016-3824 | CWE-119 |
| 59 | tcpdump | CVE-2017-13040 | CWE-125 |
| 60 | Android | CVE-2016-1621 | CWE-119 |

---

## 01. linux  |  CVE-2019-15090  |  CWE-125
- commit: https://github.com/torvalds/linux/commit/c09581a52765a85f19fc35340127396d5e3379cc
- diff bruto: https://github.com/torvalds/linux/commit/c09581a52765a85f19fc35340127396d5e3379cc.patch
- commit_id: c09581a52765a85f19fc35340127396d5e3379cc

**mensagem do commit**

> scsi: qedi: remove memset/memcpy to nfunc and use func instead
> 
> KASAN reports this:
> 
> BUG: KASAN: global-out-of-bounds in qedi_dbg_err+0xda/0x330 [qedi]
> Read of size 31 at addr ffffffffc12b0ae0 by task syz-executor.0/2429
> 
> CPU: 0 PID: 2429 Comm: syz-executor.0 Not tainted 5.0.0-rc7+ #45
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1ubuntu1 04/01/2014
> Call Trace:
>  __dump_stack lib/dump_stack.c:77 [inline]
>  dump_stack+0xfa/0x1ce lib/dump_stack.c:113
>  print_address_description+0x1c4/0x270 mm/kasan/report.c:187
>  kasan_report+0x149/0x18d mm/kasan/report.c:317
>  memcpy+0x1f/0x50 mm/kasan/common.c:130
>  qedi_dbg_err+0xda/0x330 [qedi]
>  ? 0xffffffffc12d0000
>  qedi_init+0x118/0x1000 [qedi]
>  ? 0xffffffffc12d0000
>  ? 0xffffffffc12d0000
>  ? 0xffffffffc12d0000
>  do_one_initcall+0xfa/0x5ca init/main.c:887
>  do_init_module+0x204/0x5f6 kernel/module.c:3460
>  load_module+0x66b2/0x8570 kernel/module.c:3808
>  __do_sys_finit_module+0x238/0x2a0 kernel/module.c:3902
>  do_syscall_64+0x147/0x600 arch/x86/entry/common.c:290
>  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x462e99
> Code: f7 d8 64 89 02 b8 ff ff ff ff c3 66 0f 1f 44 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
> RSP: 002b:00007f2d57e55c58 EFLAGS: 00000246 ORIG_RAX: 0000000000000139
> RAX: ffffffffffffffda RBX: 000000000073bfa0 RCX: 0000000000462e99
> RDX: 0000000000000000 RSI: 00000000200003c0 RDI: 0000000000000003
> RBP: 00007f2d57e55c70 R08: 0000000000000000 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000246 R12: 00007f2d57e566bc
> R13: 00000000004bcefb R14: 00000000006f7030 R15: 0000000000000004
> 
> The buggy address belongs to the variable:
>  __func__.67584+0x0/0xffffffffffffd520 [qedi]
> 
> Memory state around the buggy address:
>  ffffffffc12b0980: fa fa fa fa 00 04 fa fa fa fa fa fa 00 00 05 fa
>  ffffffffc12b0a00: fa fa fa fa 00 00 04 fa fa fa fa fa 00 05 fa fa
> > ffffffffc12b0a80: fa fa fa fa 00 06 fa fa fa fa fa fa 00 02 fa fa
>                                                           ^
>  ffffffffc12b0b00: fa fa fa fa 00 00 04 fa fa fa fa fa 00 00 03 fa
>  ffffffffc12b0b80: fa fa fa fa 00 00 02 fa fa fa fa fa 00 00 04 fa
> 
> Currently the qedi_dbg_* family of functions can overrun the end of the
> source string if it is less than the destination buffer length because of
> the use of a fixed sized memcpy. Remove the memset/memcpy calls to nfunc
> and just use func instead as it is always a null terminated string.
> 
> Reported-by: Hulk Robot <hulkci@huawei.com>
> Fixes: ace7f46ba5fd ("scsi: qedi: Add QLogic FastLinQ offload iSCSI driver framework.")
> Signed-off-by: YueHaibing <yuehaibing@huawei.com>
> Reviewed-by: Dan Carpenter <dan.carpenter@oracle.com>
> Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>

**resumo da CVE**

> An issue was discovered in drivers/scsi/qedi/qedi_dbg.c in the Linux kernel before 5.1.12. In the qedi_dbg_* family of functions, there is an out-of-bounds read.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -3,9 +3,6 @@
  {
  	va_list va;
  	struct va_format vaf;
-	char nfunc[32];
-	memset(nfunc, 0, sizeof(nfunc));
-	memcpy(nfunc, func, sizeof(nfunc) - 1);
  
  	va_start(va, fmt);
  
@@ -17,9 +14,9 @@
  
  	if (likely(qedi) && likely(qedi->pdev))
  		pr_warn("[%s]:[%s:%d]:%d: %pV", dev_name(&qedi->pdev->dev),
-			nfunc, line, qedi->host_no, &vaf);
+			func, line, qedi->host_no, &vaf);
  	else
-		pr_warn("[0000:00:00.0]:[%s:%d]: %pV", nfunc, line, &vaf);
+		pr_warn("[0000:00:00.0]:[%s:%d]: %pV", func, line, &vaf);
  
  ret:
  	va_end(va);
```

---

## 02. FFmpeg  |  CVE-2016-10190  |  CWE-119
- commit: https://github.com/FFmpeg/FFmpeg/commit/2a05c8f813de6f2278827734bf8102291e7484aa
- diff bruto: https://github.com/FFmpeg/FFmpeg/commit/2a05c8f813de6f2278827734bf8102291e7484aa.patch
- commit_id: 2a05c8f813de6f2278827734bf8102291e7484aa

**mensagem do commit**

> http: make length/offset-related variables unsigned.
> 
> Fixes #5992, reported and found by Paul Cher <paulcher@icloud.com>.

**resumo da CVE**

> Heap-based buffer overflow in libavformat/http.c in FFmpeg before 2.8.10, 3.0.x before 3.0.5, 3.1.x before 3.1.6, and 3.2.x before 3.2.2 allows remote web servers to execute arbitrary code via a negative chunk size in an HTTP response.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,7 +2,7 @@
  {
      HTTPContext *s = h->priv_data;
      URLContext *old_hd = s->hd;
-    int64_t old_off = s->off;
+    uint64_t old_off = s->off;
      uint8_t old_buf[BUFFER_SIZE];
      int old_buf_size, ret;
      AVDictionary *options = NULL;
@@ -13,7 +13,7 @@
               ((whence == SEEK_CUR && off == 0) ||
                (whence == SEEK_SET && off == s->off)))
          return s->off;
-    else if ((s->filesize == -1 && whence == SEEK_END))
+    else if ((s->filesize == UINT64_MAX && whence == SEEK_END))
          return AVERROR(ENOSYS);
  
      if (whence == SEEK_CUR)
```

---

## 03. linux  |  CVE-2013-4312  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/712f4aad406bb1ed67f3f98d04c044191f0ff593
- diff bruto: https://github.com/torvalds/linux/commit/712f4aad406bb1ed67f3f98d04c044191f0ff593.patch
- commit_id: 712f4aad406bb1ed67f3f98d04c044191f0ff593

**mensagem do commit**

> unix: properly account for FDs passed over unix sockets
> 
> It is possible for a process to allocate and accumulate far more FDs than
> the process' limit by sending them over a unix socket then closing them
> to keep the process' fd count low.
> 
> This change addresses this problem by keeping track of the number of FDs
> in flight per user and preventing non-privileged processes from having
> more FDs in flight than their configured FD limit.
> 
> Reported-by: socketpair@gmail.com
> Reported-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> Mitigates: CVE-2013-4312 (Linux 2.0+)
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Acked-by: Hannes Frederic Sowa <hannes@stressinduktion.org>
> Signed-off-by: Willy Tarreau <w@1wt.eu>
> Signed-off-by: David S. Miller <davem@davemloft.net>

**resumo da CVE**

> The Linux kernel before 4.4.1 allows local users to bypass file-descriptor limits and cause a denial of service (memory consumption) by sending each descriptor over a UNIX socket before closing it, related to net/unix/af_unix.c and net/unix/garbage.c.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,15 +2,17 @@
  {
  	struct sock *s = unix_get_socket(fp);
  
+	spin_lock(&unix_gc_lock);
+
  	if (s) {
  		struct unix_sock *u = unix_sk(s);
  
-		spin_lock(&unix_gc_lock);
  		BUG_ON(list_empty(&u->link));
  
  		if (atomic_long_dec_and_test(&u->inflight))
  			list_del_init(&u->link);
  		unix_tot_inflight--;
-		spin_unlock(&unix_gc_lock);
  	}
+	fp->f_cred->user->unix_inflight--;
+	spin_unlock(&unix_gc_lock);
  }
```

---

## 04. Android  |  CVE-2018-9496  |  CWE-787
- commit: https://android.googlesource.com/platform/external/libxaac/+/04e8cd58f075bec5892e369c8deebca9c67e855c
- diff bruto: https://android.googlesource.com/platform/external/libxaac/+/04e8cd58f075bec5892e369c8deebca9c67e855c^!
- commit_id: 04e8cd58f075bec5892e369c8deebca9c67e855c

**mensagem do commit**

> Fix for stack corruption in esbr
> 
> Bug: 110769924
> Test: poc from bug before/after
> Change-Id: I99c6e89902064849ea1310c271064bdeccf7f20e
> (cherry picked from commit 7e90d745c22695236437297cd8167a9312427a4a)
> (cherry picked from commit 5464927f0c1fc721fa03d1c5be77b0b43dfffc50)
> 

**resumo da CVE**

> In ixheaacd_real_synth_fft_p3 of ixheaacd_esbr_fft.c there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation. Product: Android Versions: Android-9.0 Android ID: A-110769924

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -67,8 +67,9 @@
        FLOAT32 *syn_buf = &buffer[kmax];
        kmax += synth_size;
  
-      if (ixheaacd_real_synth_fft != NULL)
-        (*ixheaacd_real_synth_fft)(synth_buf_r, synth_out, synth_size * 2);
+      if (ptr_hbe_txposer->ixheaacd_real_synth_fft != NULL)
+        (*(ptr_hbe_txposer->ixheaacd_real_synth_fft))(synth_buf_r, synth_out,
+                                                      synth_size * 2);
        else
          return -1;
  
```

---

## 05. ghostscript  |  CVE-2016-9601  |  CWE-119
- commit: http://git.ghostscript.com/?p=jbig2dec.git;a=commit;h=e698d5c11d27212aa1098bc5b1673a3378563092
- diff bruto: http://git.ghostscript.com/?p=jbig2dec.git;a=commit;h=e698d5c11d27212aa1098bc5b1673a3378563092
- commit_id: e698d5c11d27212aa1098bc5b1673a3378563092

**resumo da CVE**

> ghostscript before version 9.21 is vulnerable to a heap based buffer overflow that was found in the ghostscript jbig2_decode_gray_scale_image function which is used to decode halftone segments in a JBIG2 image. A document (PostScript or PDF) with an embedded, specially crafted, jbig2 image could trigger a segmentation fault in ghostscript.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,11 +1,12 @@
 jbig2_find_changing_element(const byte *line, int x, int w)
+jbig2_find_changing_element(const byte *line, uint32_t x, uint32_t w)
  {
      int a, b;
  
      if (line == 0)
-        return w;
+        return (int)w;
  
-    if (x == -1) {
+    if (x == MINUS1) {
          a = 0;
          x = 0;
      } else {
```

---

## 06. Chrome  |  CVE-2013-2877  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/d0947db40187f4708c58e64cbd6013faf9eddeed
- diff bruto: https://github.com/chromium/chromium/commit/d0947db40187f4708c58e64cbd6013faf9eddeed.patch
- commit_id: d0947db40187f4708c58e64cbd6013faf9eddeed

**mensagem do commit**

> libxml: XML_PARSER_EOF checks from upstream
> 
> BUG=229019
> TBR=cpu
> 
> Review URL: https://chromiumcodereview.appspot.com/14053009
> 
> git-svn-id: svn://svn.chromium.org/chrome/trunk/src@196804 0039d316-1c4b-4281-b951-d872f2087c98

**resumo da CVE**

> parser.c in libxml2 before 2.9.0, as used in Google Chrome before 28.0.1500.71 and other products, allows remote attackers to cause a denial of service (out-of-bounds read) via a document that ends abruptly, related to the lack of certain checks for the XML_PARSER_EOF state.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -9,6 +9,8 @@
  #endif
  
      GROW;
+    if (ctxt->instate == XML_PARSER_EOF)
+        return(NULL);
      c = CUR_CHAR(l);
  
      while (xmlIsNameChar(ctxt, c)) {
@@ -37,6 +39,10 @@
  		if (count++ > 100) {
  		    count = 0;
  		    GROW;
+                    if (ctxt->instate == XML_PARSER_EOF) {
+                        xmlFree(buffer);
+                        return(NULL);
+                    }
  		}
  		if (len + 10 > max) {
  		    xmlChar *tmp;
```

---

## 07. tcpdump  |  CVE-2017-13000  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/9be4e0b5938b705e7e36cfcb110a740c6ff0cb97
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/9be4e0b5938b705e7e36cfcb110a740c6ff0cb97.patch
- commit_id: 9be4e0b5938b705e7e36cfcb110a740c6ff0cb97

**mensagem do commit**

> CVE-2017-13000/IEEE 802.15.4: Add more bounds checks.
> 
> While we're at it, add a bunch of macros for the frame control field's
> subfields, have the reserved frame types show the frame type value, use
> the same code path for processing source and destination addresses
> regardless of whether -v was specified (just leave out the addresses in
> non-verbose mode), and return the header length in all cases.
> 
> This fixes a buffer over-read discovered by Forcepoint's security
> researchers Otto Airamo & Antti LevomÃ¤ki.
> 
> Add tests using the capture files supplied by the reporter(s).

**resumo da CVE**

> The IEEE 802.15.4 parser in tcpdump before 4.9.2 has a buffer over-read in print-802_15_4.c:ieee802_15_4_if_print().

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,86 +2,158 @@
                        const struct pcap_pkthdr *h, const u_char *p)
  {
  	u_int caplen = h->caplen;
-	int hdrlen;
+	u_int hdrlen;
  	uint16_t fc;
  	uint8_t seq;
+	uint16_t panid = 0;
  
  	if (caplen < 3) {
-		ND_PRINT((ndo, "[|802.15.4] %x", caplen));
+		ND_PRINT((ndo, "[|802.15.4]"));
  		return caplen;
  	}
+	hdrlen = 3;
  
  	fc = EXTRACT_LE_16BITS(p);
-	hdrlen = extract_header_length(fc);
  	seq = EXTRACT_LE_8BITS(p + 2);
  
  	p += 3;
  	caplen -= 3;
  
-	ND_PRINT((ndo,"IEEE 802.15.4 %s packet ", ftypes[fc & 0x7]));
+	ND_PRINT((ndo,"IEEE 802.15.4 %s packet ", ftypes[FC_FRAME_TYPE(fc)]));
  	if (ndo->ndo_vflag)
  		ND_PRINT((ndo,"seq %02x ", seq));
-	if (hdrlen == -1) {
-		ND_PRINT((ndo,"invalid! "));
-		return caplen;
+ 
+	/*
+	 * Destination address and PAN ID, if present.
+	 */
+	switch (FC_DEST_ADDRESSING_MODE(fc)) {
+	case FC_ADDRESSING_MODE_NONE:
+		if (fc & FC_PAN_ID_COMPRESSION) {
+			/*
+			 * PAN ID compression; this requires that both
+			 * the source and destination addresses be present,
+			 * but the destination address is missing.
+			 */
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
+ 			ND_PRINT((ndo,"none "));
+		break;
+	case FC_ADDRESSING_MODE_RESERVED:
+		if (ndo->ndo_vflag)
+ 			ND_PRINT((ndo,"reserved destination addressing mode"));
+		return hdrlen;
+	case FC_ADDRESSING_MODE_SHORT:
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		panid = EXTRACT_LE_16BITS(p);
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+ 		}
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p + 2)));
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		break;
+	case FC_ADDRESSING_MODE_LONG:
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		panid = EXTRACT_LE_16BITS(p);
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		if (caplen < 8) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p + 2)));
+		p += 8;
+		caplen -= 8;
+		hdrlen += 8;
+		break;
 	}
-	if (!ndo->ndo_vflag) {
-		p+= hdrlen;
-		caplen -= hdrlen;
-	} else {
-		uint16_t panid = 0;
+	if (ndo->ndo_vflag)
+ 		ND_PRINT((ndo,"< "));
  
-		switch ((fc >> 10) & 0x3) {
-		case 0x00:
+	/*
+	 * Source address and PAN ID, if present.
+	 */
+	switch (FC_SRC_ADDRESSING_MODE(fc)) {
+	case FC_ADDRESSING_MODE_NONE:
+		if (ndo->ndo_vflag)
  			ND_PRINT((ndo,"none "));
-			break;
-		case 0x01:
- 			ND_PRINT((ndo,"reserved destination addressing mode"));
-			return 0;
-		case 0x02:
+		break;
+	case FC_ADDRESSING_MODE_RESERVED:
+		if (ndo->ndo_vflag)
+ 			ND_PRINT((ndo,"reserved source addressing mode"));
+		return 0;
+	case FC_ADDRESSING_MODE_SHORT:
+		if (!(fc & FC_PAN_ID_COMPRESSION)) {
+			/*
+			 * The source PAN ID is not compressed out, so
+			 * fetch it.  (Otherwise, we'll use the destination
+			 * PAN ID, fetched above.)
+			 */
+			if (caplen < 2) {
+				ND_PRINT((ndo, "[|802.15.4]"));
+				return hdrlen;
+ 			}
+			panid = EXTRACT_LE_16BITS(p);
+ 			p += 2;
+			caplen -= 2;
+			hdrlen += 2;
+		}
+		if (caplen < 2) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
+			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
+		p += 2;
+		caplen -= 2;
+		hdrlen += 2;
+		break;
+	case FC_ADDRESSING_MODE_LONG:
+		if (!(fc & FC_PAN_ID_COMPRESSION)) {
+			/*
+			 * The source PAN ID is not compressed out, so
+			 * fetch it.  (Otherwise, we'll use the destination
+			 * PAN ID, fetched above.)
+			 */
+			if (caplen < 2) {
+				ND_PRINT((ndo, "[|802.15.4]"));
+				return hdrlen;
+ 			}
 			panid = EXTRACT_LE_16BITS(p);
 			p += 2;
-			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
-			p += 2;
-			break;
-		case 0x03:
-			panid = EXTRACT_LE_16BITS(p);
-			p += 2;
+			caplen -= 2;
+			hdrlen += 2;
+ 		}
+		if (caplen < 8) {
+			ND_PRINT((ndo, "[|802.15.4]"));
+			return hdrlen;
+		}
+		if (ndo->ndo_vflag)
 			ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p)));
-			p += 8;
-			break;
- 		}
- 		ND_PRINT((ndo,"< "));
- 
-		switch ((fc >> 14) & 0x3) {
-		case 0x00:
- 			ND_PRINT((ndo,"none "));
-			break;
-		case 0x01:
- 			ND_PRINT((ndo,"reserved source addressing mode"));
-			return 0;
-		case 0x02:
-			if (!(fc & (1 << 6))) {
-				panid = EXTRACT_LE_16BITS(p);
-				p += 2;
- 			}
-			ND_PRINT((ndo,"%04x:%04x ", panid, EXTRACT_LE_16BITS(p)));
- 			p += 2;
-			break;
-		case 0x03:
-			if (!(fc & (1 << 6))) {
-				panid = EXTRACT_LE_16BITS(p);
-				p += 2;
- 			}
-                        ND_PRINT((ndo,"%04x:%s ", panid, le64addr_string(ndo, p)));
-			p += 8;
-			break;
- 		}
-		caplen -= hdrlen;
+		p += 8;
+		caplen -= 8;
+		hdrlen += 8;
+		break;
  	}
  
  	if (!ndo->ndo_suppress_default_print)
  		ND_DEFAULTPRINT(p, caplen);
  
-	return 0;
+	return hdrlen;
  }
```

---

## 08. rdesktop  |  CVE-2018-20182  |  CWE-119
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
@@ -2,6 +2,12 @@
  {
  	unsigned int pkglen;
  	char *buf;
+	struct stream packet = *s;
+
+	if (!s_check(s))
+	{
+		rdp_protocol_error("seamless_process(), stream is in unstable state", &packet);
+	}
  
  	pkglen = s->end - s->p;
  	/* str_handle_lines requires null terminated strings */
```

---

## 09. Chrome  |  CVE-2015-1215  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/2bceda4948deeaed0a5a99305d0d488eb952f64f
- diff bruto: https://github.com/chromium/chromium/commit/2bceda4948deeaed0a5a99305d0d488eb952f64f.patch
- commit_id: 2bceda4948deeaed0a5a99305d0d488eb952f64f

**mensagem do commit**

> Allow serialization of empty bluetooth uuids.
> 
> This change allows the passing WTF::Optional<String> types as
> bluetooth.mojom.UUID optional parameter without needing to ensure the passed
> object isn't empty.
> 
> BUG=None
> 
> R=juncai, dcheng
> 
> Review-Url: https://codereview.chromium.org/2646613003
> Cr-Commit-Position: refs/heads/master@{#445809}

**resumo da CVE**

> The filters implementation in Skia, as used in Google Chrome before 41.0.2272.76, allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors that trigger an out-of-bounds write operation.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -18,11 +18,8 @@
    device()->gatt()->AddToActiveAlgorithms(resolver);
  
    mojom::blink::WebBluetoothService* service = m_device->bluetooth()->service();
-  WTF::Optional<String> uuid = WTF::nullopt;
-  if (!characteristicsUUID.isEmpty())
-    uuid = characteristicsUUID;
    service->RemoteServiceGetCharacteristics(
-      m_service->instance_id, quantity, uuid,
+      m_service->instance_id, quantity, characteristicsUUID,
        convertToBaseCallback(
            WTF::bind(&BluetoothRemoteGATTService::GetCharacteristicsCallback,
                      wrapPersistent(this), m_service->instance_id, quantity,
```

---

## 10. krb5  |  CVE-2015-8631  |  CWE-119
- commit: https://github.com/krb5/krb5/commit/83ed75feba32e46f736fcce0d96a0445f29b96c2
- diff bruto: https://github.com/krb5/krb5/commit/83ed75feba32e46f736fcce0d96a0445f29b96c2.patch
- commit_id: 83ed75feba32e46f736fcce0d96a0445f29b96c2

**mensagem do commit**

> Fix leaks in kadmin server stubs [CVE-2015-8631]
> 
> In each kadmind server stub, initialize the client_name and
> server_name variables, and release them in the cleanup handler.  Many
> of the stubs will otherwise leak the client and server name if
> krb5_unparse_name() fails.  Also make sure to free the prime_arg
> variables in rename_principal_2_svc(), or we can leak the first one if
> unparsing the second one fails.  Discovered by Simo Sorce.
> 
> CVE-2015-8631:
> 
> In all versions of MIT krb5, an authenticated attacker can cause
> kadmind to leak memory by supplying a null principal name in a request
> which uses one.  Repeating these requests will eventually cause
> kadmind to exhaust all available memory.
> 
>     CVSSv2 Vector: AV:N/AC:L/Au:S/C:N/I:N/A:C/E:POC/RL:OF/RC:C
> 
> ticket: 8343 (new)
> target_version: 1.14-next
> target_version: 1.13-next
> tags: pullup

**resumo da CVE**

> Multiple memory leaks in kadmin/server/server_stubs.c in kadmind in MIT Kerberos 5 (aka krb5) before 1.13.4 and 1.14.x before 1.14.1 allow remote authenticated users to cause a denial of service (memory consumption) via a request specifying a NULL principal name.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,8 +2,8 @@
  {
      static generic_ret              ret;
      char                            *prime_arg;
-    gss_buffer_desc                 client_name,
-        service_name;
+    gss_buffer_desc                 client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc                 service_name = GSS_C_EMPTY_BUFFER;
      OM_uint32                       minor_stat;
      kadm5_server_handle_t           handle;
      restriction_t                   *rp;
@@ -47,9 +47,9 @@
              krb5_free_error_message(handle->context, errmsg);
      }
      free(prime_arg);
+exit_func:
      gss_release_buffer(&minor_stat, &client_name);
      gss_release_buffer(&minor_stat, &service_name);
-exit_func:
      free_server_handle(handle);
      return &ret;
  }
```

---

## 11. ghostscript  |  CVE-2016-9601  |  CWE-119
- commit: http://git.ghostscript.com/?p=jbig2dec.git;a=commit;h=e698d5c11d27212aa1098bc5b1673a3378563092
- diff bruto: http://git.ghostscript.com/?p=jbig2dec.git;a=commit;h=e698d5c11d27212aa1098bc5b1673a3378563092
- commit_id: e698d5c11d27212aa1098bc5b1673a3378563092

**resumo da CVE**

> ghostscript before version 9.21 is vulnerable to a heap based buffer overflow that was found in the ghostscript jbig2_decode_gray_scale_image function which is used to decode halftone segments in a JBIG2 image. A document (PostScript or PDF) with an embedded, specially crafted, jbig2 image could trigger a segmentation fault in ghostscript.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,28 +1,29 @@
 jbig2_sd_new(Jbig2Ctx *ctx, int n_symbols)
+jbig2_sd_new(Jbig2Ctx *ctx, uint32_t n_symbols)
  {
-    Jbig2SymbolDict *new = NULL;
+    Jbig2SymbolDict *new_dict = NULL;
  
      if (n_symbols < 0) {
          jbig2_error(ctx, JBIG2_SEVERITY_FATAL, -1, "Negative number of symbols in symbol dict: %d", n_symbols);
          return NULL;
      }
  
-    new = jbig2_new(ctx, Jbig2SymbolDict, 1);
-    if (new != NULL) {
-        new->glyphs = jbig2_new(ctx, Jbig2Image *, n_symbols);
-        new->n_symbols = n_symbols;
+    new_dict = jbig2_new(ctx, Jbig2SymbolDict, 1);
+    if (new_dict != NULL) {
+        new_dict->glyphs = jbig2_new(ctx, Jbig2Image *, n_symbols);
+        new_dict->n_symbols = n_symbols;
      } else {
          jbig2_error(ctx, JBIG2_SEVERITY_FATAL, -1, "unable to allocate new empty symbol dict");
          return NULL;
      }
  
-    if (new->glyphs != NULL) {
-        memset(new->glyphs, 0, n_symbols * sizeof(Jbig2Image *));
+    if (new_dict->glyphs != NULL) {
+        memset(new_dict->glyphs, 0, n_symbols * sizeof(Jbig2Image *));
      } else {
          jbig2_error(ctx, JBIG2_SEVERITY_FATAL, -1, "unable to allocate glyphs for new empty symbol dict");
-        jbig2_free(ctx->allocator, new);
+        jbig2_free(ctx->allocator, new_dict);
          return NULL;
      }
  
-    return new;
+    return new_dict;
  }
```

---

## 12. libtiff  |  CVE-2016-9535  |  CWE-119
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
@@ -7,10 +7,15 @@
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
@@ -32,4 +37,5 @@
  		}
  	}
  	_TIFFfree(tmp);
+    return 1;
  }
```

---

## 13. file  |  CVE-2014-2270  |  CWE-119
- commit: https://github.com/file/file/commit/447558595a3650db2886cd2f416ad0beba965801
- diff bruto: https://github.com/file/file/commit/447558595a3650db2886cd2f416ad0beba965801.patch
- commit_id: 447558595a3650db2886cd2f416ad0beba965801

**mensagem do commit**

> PR/313: Aaron Reffett: Check properly for exceeding the offset.

**resumo da CVE**

> softmagic.c in file before 5.17 and libmagic allows context-dependent attackers to cause a denial of service (out-of-bounds memory access and crash) via crafted offsets in the softmagic of a PE executable.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -70,7 +70,7 @@
  		}
  		switch (in_type = cvt_flip(m->in_type, flip)) {
  		case FILE_BYTE:
-			if (nbytes < offset || nbytes < (offset + 1))
+			if (OFFSET_OOB(nbytes, offset, 1))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -105,7 +105,7 @@
  				offset = ~offset;
  			break;
  		case FILE_BESHORT:
-			if (nbytes < offset || nbytes < (offset + 2))
+			if (OFFSET_OOB(nbytes, offset, 2))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -157,7 +157,7 @@
  				offset = ~offset;
  			break;
  		case FILE_LESHORT:
-			if (nbytes < offset || nbytes < (offset + 2))
+			if (OFFSET_OOB(nbytes, offset, 2))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -209,7 +209,7 @@
  				offset = ~offset;
  			break;
  		case FILE_SHORT:
-			if (nbytes < offset || nbytes < (offset + 2))
+			if (OFFSET_OOB(nbytes, offset, 2))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -246,7 +246,7 @@
  			break;
  		case FILE_BELONG:
  		case FILE_BEID3:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -317,7 +317,7 @@
  			break;
  		case FILE_LELONG:
  		case FILE_LEID3:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -387,7 +387,7 @@
  				offset = ~offset;
  			break;
  		case FILE_MELONG:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -457,7 +457,7 @@
  				offset = ~offset;
  			break;
  		case FILE_LONG:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
  				return 0;
  			if (off) {
  				switch (m->in_op & FILE_OPS_MASK) {
@@ -534,14 +534,14 @@
  	/* Verify we have enough data to match magic type */
  	switch (m->type) {
  	case FILE_BYTE:
-		if (nbytes < (offset + 1)) /* should alway be true */
+		if (OFFSET_OOB(nbytes, offset, 1))
  			return 0;
  		break;
  
  	case FILE_SHORT:
  	case FILE_BESHORT:
  	case FILE_LESHORT:
-		if (nbytes < (offset + 2))
+		if (OFFSET_OOB(nbytes, offset, 2))
  			return 0;
  		break;
  
@@ -560,31 +560,31 @@
  	case FILE_FLOAT:
  	case FILE_BEFLOAT:
  	case FILE_LEFLOAT:
-		if (nbytes < (offset + 4))
+		if (OFFSET_OOB(nbytes, offset, 4))
  			return 0;
  		break;
  
  	case FILE_DOUBLE:
  	case FILE_BEDOUBLE:
  	case FILE_LEDOUBLE:
-		if (nbytes < (offset + 8))
+		if (OFFSET_OOB(nbytes, offset, 8))
  			return 0;
  		break;
  
  	case FILE_STRING:
  	case FILE_PSTRING:
  	case FILE_SEARCH:
-		if (nbytes < (offset + m->vallen))
+		if (OFFSET_OOB(nbytes, offset, m->vallen))
  			return 0;
  		break;
  
  	case FILE_REGEX:
-		if (nbytes < offset)
+		if (OFFSET_OOB(nbytes, offset, 0))
  			return 0;
  		break;
  
  	case FILE_INDIRECT:
-		if (nbytes < offset)
+		if (OFFSET_OOB(nbytes, offset, 0))
  			return 0;
  		sbuf = ms->o.buf;
  		soffset = ms->offset;
@@ -608,7 +608,7 @@
  		return rv;
  
  	case FILE_USE:
-		if (nbytes < offset)
+		if (OFFSET_OOB(nbytes, offset, 0))
  			return 0;
  		sbuf = m->value.s;
  		if (*sbuf == '^') {
```

---

## 14. ImageMagick  |  CVE-2015-8958  |  CWE-125
- commit: https://github.com/ImageMagick/ImageMagick/commit/8ea44b48a182dd46d018f4b4f09a5e2ee9638105
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/8ea44b48a182dd46d018f4b4f09a5e2ee9638105.patch
- commit_id: 8ea44b48a182dd46d018f4b4f09a5e2ee9638105

**resumo da CVE**

> coders/sun.c in ImageMagick before 6.9.0-4 Beta allows remote attackers to cause a denial of service (out-of-bounds read and application crash) via a crafted SUN file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -45,8 +45,7 @@
    size_t
      bytes_per_line,
      extent,
-    height,
-    length;
+    height;
  
    ssize_t
      count,
@@ -279,13 +278,6 @@
      else
        if (image->storage_class == PseudoClass)
          {
-          if (bytes_per_line == 0)
-            bytes_per_line=image->columns;
-          length=image->rows*(image->columns+image->columns % 2);
-          if (((sun_info.type == RT_ENCODED) &&
-               (length > (bytes_per_line*image->rows))) ||
-              ((sun_info.type != RT_ENCODED) && (length > sun_info.length)))
-            ThrowReaderException(CorruptImageError,"UnableToReadImageData");
            for (y=0; y < (ssize_t) image->rows; y++)
            {
              q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
@@ -319,11 +311,6 @@
              bytes_per_pixel++;
            if (bytes_per_line == 0)
              bytes_per_line=bytes_per_pixel*image->columns;
-          length=image->rows*(bytes_per_line+bytes_per_line % 2);
-          if (((sun_info.type == RT_ENCODED) &&
-               (length > (bytes_per_line*image->rows))) ||
-              ((sun_info.type != RT_ENCODED) && (length > sun_info.length)))
-            ThrowReaderException(CorruptImageError,"UnableToReadImageData");
            for (y=0; y < (ssize_t) image->rows; y++)
            {
              q=QueueAuthenticPixels(image,0,y,image->columns,1,exception);
```

---

## 15. Chrome  |  CVE-2016-1683  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab
- diff bruto: https://github.com/chromium/chromium/commit/96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab.patch
- commit_id: 96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab

**mensagem do commit**

> Roll libxslt to 891681e3e948f31732229f53cb6db7215f740fc7
> 
> BUG=583156,583171
> 
> Review URL: https://codereview.chromium.org/1853083002
> 
> Cr-Commit-Position: refs/heads/master@{#385338}

**resumo da CVE**

> numbers.c in libxslt before 1.1.29, as used in Google Chrome before 51.0.2704.63, mishandles namespace nodes, which allows remote attackers to cause a denial of service (out-of-bounds heap memory access) or possibly have unspecified other impact via a crafted document.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -38,11 +38,14 @@
      xsltCompMatchAdd(ctxt, comp, XSLT_OP_END, NULL, NULL, 0);
  
      /*
-     * detect consecutive XSLT_OP_PREDICATE indicating a direct
-     * matching should be done.
+     * Detect consecutive XSLT_OP_PREDICATE and predicates on ops which
+     * haven't been optimized yet indicating a direct matching should be done.
       */
      for (i = 0;i < comp->nbStep - 1;i++) {
-        if ((comp->steps[i].op == XSLT_OP_PREDICATE) &&
+        xsltOp op = comp->steps[i].op;
+
+        if ((op != XSLT_OP_ELEM) &&
+            (op != XSLT_OP_ALL) &&
  	    (comp->steps[i + 1].op == XSLT_OP_PREDICATE)) {
  
  	    comp->direct = 1;
```

---

## 16. radare2  |  CVE-2018-11376  |  CWE-125
- commit: https://github.com/radare/radare2/commit/1f37c04f2a762500222dda2459e6a04646feeedf
- diff bruto: https://github.com/radare/radare2/commit/1f37c04f2a762500222dda2459e6a04646feeedf.patch
- commit_id: 1f37c04f2a762500222dda2459e6a04646feeedf

**mensagem do commit**

> Fix #9904 - crash in r2_hoobr_r_read_le32 (over 9000 entrypoints) and read_le oobread (#9923)

**resumo da CVE**

> The r_read_le32() function in radare2 2.5.0 allows remote attackers to cause a denial of service (heap-based out-of-bounds read and application crash) via a crafted ELF file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -17,6 +17,10 @@
  			r_cons_printf ("[Entrypoints]\n");
  		}
  	}
+	if (r_list_length (entries) > 1024) {
+		eprintf ("Too many entrypoints (%d)\n", r_list_length (entries));
+		return false;
+	}
  
  	r_list_foreach (entries, iter, entry) {
  		ut64 paddr = entry->paddr;
```

---

## 17. php-src  |  CVE-2016-7416  |  CWE-119
- commit: https://github.com/php/php-src/commit/6d55ba265637d6adf0ba7e9c9ef11187d1ec2f5b?w=1
- diff bruto: https://github.com/php/php-src/commit/6d55ba265637d6adf0ba7e9c9ef11187d1ec2f5b?w=1.patch
- commit_id: 6d55ba265637d6adf0ba7e9c9ef11187d1ec2f5b?w=1

**mensagem do commit**

> Fix bug #73007: add locale length check

**resumo da CVE**

> ext/intl/msgformat/msgformat_format.c in PHP before 5.6.26 and 7.x before 7.0.11 does not properly restrict the locale length provided to the Locale class in the ICU library, which allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a MessageFormatter::formatMessage call with a long first argument.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -20,6 +20,8 @@
  		RETURN_FALSE;
  	}
  
+	INTL_CHECK_LOCALE_LEN(slocale_len);
+
  	msgformat_data_init(&mfo->mf_data TSRMLS_CC);
  
  	if(pattern && pattern_len) {
```

---

## 18. libsndfile  |  CVE-2017-7586  |  CWE-119
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
@@ -4,7 +4,7 @@
  	/* Ultimate sanity check. */
  	assert (sizeof (sf_count_t) == 8) ;
  
-	if ((psf = calloc (1, sizeof (SF_PRIVATE))) == NULL)
+	if ((psf = psf_allocate ()) == NULL)
  	{	sf_errno = SFE_MALLOC_FAILED ;
  		return	NULL ;
  		} ;
```

---

## 19. Chrome  |  CVE-2017-5077  |  CWE-125
- commit: https://github.com/chromium/chromium/commit/fec26ff33bf372476a70326f3669a35f34a9d474
- diff bruto: https://github.com/chromium/chromium/commit/fec26ff33bf372476a70326f3669a35f34a9d474.patch
- commit_id: fec26ff33bf372476a70326f3669a35f34a9d474

**mensagem do commit**

> Origins should be represented as url::Origin (not as GURL).
> 
> As pointed out in //docs/security/origin-vs-url.md, origins should be
> represented as url::Origin (not as GURL).  This CL applies this
> guideline to predictor-related code and changes the type of the
> following fields from GURL to url::Origin:
> - OriginRequestSummary::origin
> - PreconnectedRequestStats::origin
> - PreconnectRequest::origin
> 
> The old code did not depend on any non-origin parts of GURL
> (like path and/or query).  Therefore, this CL has no intended
> behavior change.
> 
> Bug: 973885
> Change-Id: Idd14590b4834cb9d50c74ed747b595fe1a4ba357
> Reviewed-on: https://chromium-review.googlesource.com/c/chromium/src/+/1895167
> Commit-Queue: Åukasz Anforowicz <lukasza@chromium.org>
> Reviewed-by: Alex Ilin <alexilin@chromium.org>
> Cr-Commit-Position: refs/heads/master@{#716311}

**resumo da CVE**

> Insufficient validation of untrusted input in Skia in Google Chrome prior to 59.0.3071.86 for Linux, Windows, and Mac, and 59.0.3071.92 for Android, allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -11,7 +11,6 @@
  
    for (auto request_it = requests.begin(); request_it != requests.end();
         ++request_it) {
-    DCHECK(request_it->origin.GetOrigin() == request_it->origin);
      PreresolveJobId job_id = preresolve_jobs_.Add(
          std::make_unique<PreresolveJob>(std::move(*request_it), info));
      queued_jobs_.push_back(job_id);
```

---

## 20. tcpdump  |  CVE-2017-13039  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/e0a5a02b0fc1900a69d6c37ed0aab36fb8494e6d
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/e0a5a02b0fc1900a69d6c37ed0aab36fb8494e6d.patch
- commit_id: e0a5a02b0fc1900a69d6c37ed0aab36fb8494e6d

**mensagem do commit**

> CVE-2017-13039/IKEv1: Do more bounds checking.
> 
> Have ikev1_attrmap_print() and ikev1_attr_print() do full bounds
> checking, and return null on a bounds overflow.  Have their callers
> check for a null return.
> 
> This fixes a buffer over-read discovered by Bhargava Shastry,
> SecT/TU Berlin.
> 
> Add a test using the capture file supplied by the reporter(s), modified
> so the capture file won't be rejected as an invalid capture.

**resumo da CVE**

> The ISAKMP parser in tcpdump before 4.9.2 has a buffer over-read in print-isakmp.c, several functions.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,28 +1,42 @@
 ikev1_attr_print(netdissect_options *ndo, const u_char *p, const u_char *ep)
+ikev1_attr_print(netdissect_options *ndo, const u_char *p, const u_char *ep2)
  {
  	int totlen;
  	uint32_t t;
  
+	ND_TCHECK(p[0]);
  	if (p[0] & 0x80)
  		totlen = 4;
-	else
+	else {
+		ND_TCHECK_16BITS(&p[2]);
  		totlen = 4 + EXTRACT_16BITS(&p[2]);
-	if (ep < p + totlen) {
+	}
+	if (ep2 < p + totlen) {
  		ND_PRINT((ndo,"[|attr]"));
-		return ep + 1;
+		return ep2 + 1;
  	}
  
+	ND_TCHECK_16BITS(&p[0]);
  	ND_PRINT((ndo,"("));
  	t = EXTRACT_16BITS(&p[0]) & 0x7fff;
  	ND_PRINT((ndo,"type=#%d ", t));
  	if (p[0] & 0x80) {
  		ND_PRINT((ndo,"value="));
  		t = p[2];
-		rawprint(ndo, (const uint8_t *)&p[2], 2);
+		if (!rawprint(ndo, (const uint8_t *)&p[2], 2)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
  	} else {
-		ND_PRINT((ndo,"len=%d value=", EXTRACT_16BITS(&p[2])));
-		rawprint(ndo, (const uint8_t *)&p[4], EXTRACT_16BITS(&p[2]));
+		ND_PRINT((ndo,"len=%d value=", totlen - 4));
+		if (!rawprint(ndo, (const uint8_t *)&p[4], totlen - 4)) {
+			ND_PRINT((ndo,")"));
+			goto trunc;
+		}
  	}
  	ND_PRINT((ndo,")"));
  	return p + totlen;
+
+trunc:
+	return NULL;
  }
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
@@ -1,7 +1,8 @@
  static void set_roi_map(const vpx_codec_enc_cfg_t *cfg,
                          vpx_codec_ctx_t *codec) {
    unsigned int i;
-  vpx_roi_map_t roi = {0};
+  vpx_roi_map_t roi;
+  memset(&roi, 0, sizeof(roi));
  
    roi.rows = (cfg->g_h + 15) / 16;
    roi.cols = (cfg->g_w + 15) / 16;
```

---

## 22. pyfribidi  |  CVE-2012-1176  |  CWE-119
- commit: https://github.com/pediapress/pyfribidi/commit/d2860c655357975e7b32d84e6b45e98f0dcecd7a
- diff bruto: https://github.com/pediapress/pyfribidi/commit/d2860c655357975e7b32d84e6b45e98f0dcecd7a.patch
- commit_id: d2860c655357975e7b32d84e6b45e98f0dcecd7a

**mensagem do commit**

> refactor pyfribidi.c module
> 
> pyfribidi.c is now compiled as _pyfribidi. This module only handles
> unicode internally and doesn't use the fribidi_utf8_to_unicode
> function (which can't handle 4 byte utf-8 sequences). This fixes the
> buffer overflow in issue #2.
> 
> The code is now also much simpler: pyfribidi.c is down from 280 to 130
> lines of code.
> 
> We now ship a pure python pyfribidi that handles the case when
> non-unicode strings are passed in.
> 
> We now also adapt the size of the output string if clean=True is
> passed.

**resumo da CVE**

> Buffer overflow in the fribidi_utf8_to_unicode function in PyFriBidi before 0.11.0 allows remote attackers to cause a denial of service (application crash) via a 4-byte utf-8 sequence.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,32 +1 @@
 log2vis_encoded_string (PyObject * string, const char *encoding,
-			FriBidiParType base_direction, int clean, int reordernsm)
-{
-	PyObject *logical = NULL;	/* logical unicode object */
-	PyObject *result = NULL;	/* output string object */
-	/* Always needed for the string length */
-	logical = PyUnicode_Decode (PyString_AS_STRING (string),
-				    PyString_GET_SIZE (string),
-				    encoding, "strict");
-	if (logical == NULL)
-		return NULL;
-	if (strcmp (encoding, "utf-8") == 0)
-		/* Shortcut for utf8 strings (little faster) */
-		result = log2vis_utf8 (string,
-				       PyUnicode_GET_SIZE (logical),
-				       base_direction, clean, reordernsm);
-	else
-	{
-		/* Invoke log2vis_unicode and encode back to encoding */
-		PyObject *visual = log2vis_unicode (logical, base_direction, clean, reordernsm);
-		if (visual)
-		{
-			result = PyUnicode_Encode (PyUnicode_AS_UNICODE
-						   (visual),
-						   PyUnicode_GET_SIZE (visual),
-						   encoding, "strict");
-			Py_DECREF (visual);
-		}
-	}
-	Py_DECREF (logical);
-	return result;
-}
```

---

## 23. linux  |  CVE-2011-4098  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/64dd153c83743af81f20924c6343652d731eeecb
- diff bruto: https://github.com/torvalds/linux/commit/64dd153c83743af81f20924c6343652d731eeecb.patch
- commit_id: 64dd153c83743af81f20924c6343652d731eeecb

**mensagem do commit**

> GFS2: rewrite fallocate code to write blocks directly
> 
> GFS2's fallocate code currently goes through the page cache. Since it's only
> writing to the end of the file or to holes in it, it doesn't need to, and it
> was causing issues on low memory environments. This patch pulls in some of
> Steve's block allocation work, and uses it to simply allocate the blocks for
> the file, and zero them out at allocation time.  It provides a slight
> performance increase, and it dramatically simplifies the code.
> 
> Signed-off-by: Benjamin Marzinski <bmarzins@redhat.com>
> Signed-off-by: Steven Whitehouse <swhiteho@redhat.com>

**resumo da CVE**

> The fallocate implementation in the GFS2 filesystem in the Linux kernel before 3.2 relies on the page cache, which might allow local users to cause a denial of service by preallocating blocks in certain situations involving insufficient memory.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,10 +1 @@
 static int needs_empty_write(sector_t block, struct inode *inode)
-{
-	int error;
-	struct buffer_head bh_map = { .b_state = 0, .b_blocknr = 0 };
-	bh_map.b_size = 1 << inode->i_blkbits;
-	error = gfs2_block_map(inode, block, &bh_map, 0);
-	if (unlikely(error))
-		return error;
-	return !buffer_mapped(&bh_map);
-}
```

---

## 24. Chrome  |  CVE-2016-1683  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab
- diff bruto: https://github.com/chromium/chromium/commit/96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab.patch
- commit_id: 96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab

**mensagem do commit**

> Roll libxslt to 891681e3e948f31732229f53cb6db7215f740fc7
> 
> BUG=583156,583171
> 
> Review URL: https://codereview.chromium.org/1853083002
> 
> Cr-Commit-Position: refs/heads/master@{#385338}

**resumo da CVE**

> numbers.c in libxslt before 1.1.29, as used in Google Chrome before 51.0.2704.63, mishandles namespace nodes, which allows remote attackers to cause a denial of service (out-of-bounds heap memory access) or possibly have unspecified other impact via a crafted document.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -6,23 +6,29 @@
      int amount, i;
      double number;
      xsltFormat tokens;
-    int tempformat = 0;
  
-    if ((data->format == NULL) && (data->has_format != 0)) {
-	data->format = xsltEvalAttrValueTemplate(ctxt, data->node,
+    if (data->format != NULL) {
+        xsltNumberFormatTokenize(data->format, &tokens);
+    }
+    else {
+        xmlChar *format;
+
+	/* The format needs to be recomputed each time */
+        if (data->has_format == 0)
+            return;
+	format = xsltEvalAttrValueTemplate(ctxt, data->node,
  					     (const xmlChar *) "format",
  					     XSLT_NAMESPACE);
-	tempformat = 1;
-    }
-    if (data->format == NULL) {
-	return;
+        if (format == NULL)
+            return;
+        xsltNumberFormatTokenize(format, &tokens);
+	xmlFree(format);
      }
  
      output = xmlBufferCreate();
      if (output == NULL)
  	goto XSLT_NUMBER_FORMAT_END;
  
-    xsltNumberFormatTokenize(data->format, &tokens);
      /*
       * Evaluate the XPath expression to find the value(s)
       */
@@ -47,9 +53,7 @@
  						      data->countPat,
  						      data->fromPat,
  						      &number,
-						      1,
-						      data->doc,
-						      data->node);
+						      1);
  	    if (amount == 1) {
  		xsltNumberFormatInsertNumbers(data,
  					      &number,
@@ -65,9 +69,7 @@
  						      data->countPat,
  						      data->fromPat,
  						      numarray,
-						      max,
-						      data->doc,
-						      data->node);
+						      max);
  	    if (amount > 0) {
  		xsltNumberFormatInsertNumbers(data,
  					      numarray,
@@ -80,9 +82,7 @@
  						 node,
  						 data->countPat,
  						 data->fromPat,
-						 &number,
-						 data->doc,
-						 data->node);
+						 &number);
  	    if (amount > 0) {
  		xsltNumberFormatInsertNumbers(data,
  					      &number,
@@ -95,6 +95,9 @@
      /* Insert number as text node */
      xsltCopyTextString(ctxt, ctxt->insert, xmlBufferContent(output), 0);
  
+    xmlBufferFree(output);
+
+XSLT_NUMBER_FORMAT_END:
      if (tokens.start != NULL)
  	xmlFree(tokens.start);
      if (tokens.end != NULL)
@@ -103,11 +106,4 @@
  	if (tokens.tokens[i].separator != NULL)
  	    xmlFree(tokens.tokens[i].separator);
      }
-XSLT_NUMBER_FORMAT_END:
-    if (tempformat == 1) {
-	/* The format need to be recomputed each time */
-	data->format = NULL;
-    }
-    if (output != NULL)
-	xmlBufferFree(output);
  }
```

---

## 25. ImageMagick  |  CVE-2016-10066  |  CWE-119
- commit: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6.patch
- commit_id: f6e9d0d9955e85bdd7540b251cd50d598dacc5e6

**resumo da CVE**

> Buffer overflow in the ReadVIFFImage function in coders/viff.c in ImageMagick before 6.9.4-5 allows remote attackers to cause a denial of service (application crash) via a crafted file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -48,6 +48,12 @@
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

---

## 26. rdesktop  |  CVE-2018-20182  |  CWE-119
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
@@ -4,6 +4,11 @@
  	static char *rest = NULL;
  	char *buf;
  
+	if (!s_check(s))
+	{
+		rdp_protocol_error("rdpsnddbg_process(), stream is in unstable state", s);
+	}
+
  	pkglen = s->end - s->p;
  	/* str_handle_lines requires null terminated strings */
  	buf = (char *) xmalloc(pkglen + 1);
```

---

## 27. Android  |  CVE-2016-1621  |  CWE-119
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
@@ -1,7 +1,7 @@
    void RunSignBiasCheck() {
      ACMRandom rnd(ACMRandom::DeterministicSeed());
-    DECLARE_ALIGNED_ARRAY(16, int16_t, test_input_block, 64);
-    DECLARE_ALIGNED_ARRAY(16, int16_t, test_output_block, 64);
+    DECLARE_ALIGNED(16, int16_t, test_input_block[64]);
+    DECLARE_ALIGNED(16, tran_low_t, test_output_block[64]);
      int count_sign_block[64][2];
      const int count_test_block = 100000;
  
@@ -10,8 +10,9 @@
 
      for (int i = 0; i < count_test_block; ++i) {
        for (int j = 0; j < 64; ++j)
-        test_input_block[j] = rnd.Rand8() - rnd.Rand8();
-      REGISTER_STATE_CHECK(
+        test_input_block[j] = ((rnd.Rand16() >> (16 - bit_depth_)) & mask_) -
+                              ((rnd.Rand16() >> (16 - bit_depth_)) & mask_);
+      ASM_REGISTER_STATE_CHECK(
            RunFwdTxfm(test_input_block, test_output_block, pitch_));
  
        for (int j = 0; j < 64; ++j) {
@@ -25,8 +26,8 @@
  
      for (int j = 0; j < 64; ++j) {
        const int diff = abs(count_sign_block[j][0] - count_sign_block[j][1]);
-      const int max_diff = 1125;
-      EXPECT_LT(diff, max_diff)
+      const int max_diff = kSignBiasMaxDiff255;
+      EXPECT_LT(diff, max_diff << (bit_depth_ - 8))
            << "Error: 8x8 FDCT/FHT has a sign bias > "
            << 1. * max_diff / count_test_block * 100 << "%"
            << " for input range [-255, 255] at index " << j
@@ -39,9 +40,11 @@
      memset(count_sign_block, 0, sizeof(count_sign_block));
  
      for (int i = 0; i < count_test_block; ++i) {
+      // Initialize a test block with input range [-mask_ / 16, mask_ / 16].
        for (int j = 0; j < 64; ++j)
-        test_input_block[j] = (rnd.Rand8() >> 4) - (rnd.Rand8() >> 4);
-      REGISTER_STATE_CHECK(
+        test_input_block[j] = ((rnd.Rand16() & mask_) >> 4) -
+                              ((rnd.Rand16() & mask_) >> 4);
+      ASM_REGISTER_STATE_CHECK(
            RunFwdTxfm(test_input_block, test_output_block, pitch_));
  
        for (int j = 0; j < 64; ++j) {
@@ -55,9 +58,9 @@
  
      for (int j = 0; j < 64; ++j) {
        const int diff = abs(count_sign_block[j][0] - count_sign_block[j][1]);
-      const int max_diff = 10000;
-      EXPECT_LT(diff, max_diff)
-          << "Error: 4x4 FDCT/FHT has a sign bias > "
+      const int max_diff = kSignBiasMaxDiff15;
+      EXPECT_LT(diff, max_diff << (bit_depth_ - 8))
+          << "Error: 8x8 FDCT/FHT has a sign bias > "
            << 1. * max_diff / count_test_block * 100 << "%"
            << " for input range [-15, 15] at index " << j
            << " count0: " << count_sign_block[j][0]
```

---

## 28. linux  |  CVE-2017-8069  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/7926aff5c57b577ab0f43364ff0c59d968f6a414
- diff bruto: https://github.com/torvalds/linux/commit/7926aff5c57b577ab0f43364ff0c59d968f6a414.patch
- commit_id: 7926aff5c57b577ab0f43364ff0c59d968f6a414

**mensagem do commit**

> rtl8150: Use heap buffers for all register access
> 
> Allocating USB buffers on the stack is not portable, and no longer
> works on x86_64 (with VMAP_STACK enabled as per default).
> 
> Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2")
> Signed-off-by: Ben Hutchings <ben@decadent.org.uk>
> Signed-off-by: David S. Miller <davem@davemloft.net>

**resumo da CVE**

> drivers/net/usb/rtl8150.c in the Linux kernel 4.9.x before 4.9.11 interacts incorrectly with the CONFIG_VMAP_STACK option, which allows local users to cause a denial of service (system crash or memory corruption) or possibly have unspecified other impact by leveraging use of more than one virtual page for a DMA scatterlist.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,6 +1,16 @@
 static int set_registers(rtl8150_t * dev, u16 indx, u16 size, void *data)
+static int set_registers(rtl8150_t * dev, u16 indx, u16 size, const void *data)
  {
-	return usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
-			       RTL8150_REQ_SET_REGS, RTL8150_REQT_WRITE,
-			       indx, 0, data, size, 500);
+	void *buf;
+	int ret;
+
+	buf = kmemdup(data, size, GFP_NOIO);
+	if (!buf)
+		return -ENOMEM;
+
+	ret = usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
+			      RTL8150_REQ_SET_REGS, RTL8150_REQT_WRITE,
+			      indx, 0, buf, size, 500);
+	kfree(buf);
+	return ret;
  }
```

---

## 29. libxfont  |  CVE-2013-6462  |  CWE-119
- commit: https://cgit.freedesktop.org/xorg/lib/libXfont/commit/?id=4d024ac10f964f6bd372ae0dd14f02772a6e5f63
- diff bruto: https://cgit.freedesktop.org/xorg/lib/libXfont/commit/?id=4d024ac10f964f6bd372ae0dd14f02772a6e5f63
- commit_id: 4d024ac10f964f6bd372ae0dd14f02772a6e5f63

**resumo da CVE**

> Stack-based buffer overflow in the bdfReadCharacters function in bitmap/bdfread.c in X.Org libXfont 1.1 through 1.4.6 allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a long string in a character name in a BDF font file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -89,7 +89,7 @@
  	char        charName[100];
  	int         ignore;
  
-	if (sscanf((char *) line, "STARTCHAR %s", charName) != 1) {
+	if (sscanf((char *) line, "STARTCHAR %99s", charName) != 1) {
  	    bdfError("bad character name in BDF file\n");
  	    goto BAILOUT;	/* bottom of function, free and return error */
  	}
```

---

## 30. Android  |  CVE-2016-1621  |  CWE-119
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
@@ -1,4 +1,6 @@
 ContentEncoding::GetEncryptionByIndex(unsigned long idx) const {
+const ContentEncoding::ContentEncryption* ContentEncoding::GetEncryptionByIndex(
+    unsigned long idx) const {
    const ptrdiff_t count = encryption_entries_end_ - encryption_entries_;
    assert(count >= 0);
  
```

---

## 31. openjpeg  |  CVE-2017-14040  |  CWE-787
- commit: https://github.com/uclouvain/openjpeg/commit/2cd30c2b06ce332dede81cccad8b334cde997281
- diff bruto: https://github.com/uclouvain/openjpeg/commit/2cd30c2b06ce332dede81cccad8b334cde997281.patch
- commit_id: 2cd30c2b06ce332dede81cccad8b334cde997281

**mensagem do commit**

> tgatoimage(): avoid excessive memory allocation attempt, and fixes unaligned load (#995)

**resumo da CVE**

> An invalid write access was discovered in bin/jp2/convert.c in OpenJPEG 2.2.0, triggering a crash in the tgatoimage function. The vulnerability may lead to remote denial of service or possibly unspecified other impact.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -20,17 +20,17 @@
      id_len = tga[0];
      /*cmap_type = tga[1];*/
      image_type = tga[2];
-    /*cmap_index = get_ushort(&tga[3]);*/
-    cmap_len = get_ushort(&tga[5]);
+    /*cmap_index = get_tga_ushort(&tga[3]);*/
+    cmap_len = get_tga_ushort(&tga[5]);
      cmap_entry_size = tga[7];
  
  
  #if 0
-    x_origin = get_ushort(&tga[8]);
-    y_origin = get_ushort(&tga[10]);
+    x_origin = get_tga_ushort(&tga[8]);
+    y_origin = get_tga_ushort(&tga[10]);
  #endif
-    image_w = get_ushort(&tga[12]);
-    image_h = get_ushort(&tga[14]);
+    image_w = get_tga_ushort(&tga[12]);
+    image_h = get_tga_ushort(&tga[14]);
      pixel_depth = tga[16];
      image_desc  = tga[17];
  
```

---

## 32. tcpdump  |  CVE-2017-13010  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/877b66b398518d9501513e0860c9f3a8acc70892
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/877b66b398518d9501513e0860c9f3a8acc70892.patch
- commit_id: 877b66b398518d9501513e0860c9f3a8acc70892

**mensagem do commit**

> CVE-2017-13010/BEEP: Do bounds checking when comparing strings.
> 
> This fixes a buffer over-read discovered by Brian 'geeknik' Carpenter.
> 
> Add a test using the capture file supplied by the reporter(s).

**resumo da CVE**

> The BEEP parser in tcpdump before 4.9.2 has a buffer over-read in print-beep.c:l_strnstart().

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,19 +1,19 @@
  beep_print(netdissect_options *ndo, const u_char *bp, u_int length)
  {
  
-	if (l_strnstart("MSG", 4, (const char *)bp, length)) /* A REQuest */
+	if (l_strnstart(ndo, "MSG", 4, (const char *)bp, length)) /* A REQuest */
  		ND_PRINT((ndo, " BEEP MSG"));
-	else if (l_strnstart("RPY ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "RPY ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP RPY"));
-	else if (l_strnstart("ERR ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "ERR ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP ERR"));
-	else if (l_strnstart("ANS ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "ANS ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP ANS"));
-	else if (l_strnstart("NUL ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "NUL ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP NUL"));
-	else if (l_strnstart("SEQ ", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "SEQ ", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP SEQ"));
-	else if (l_strnstart("END", 4, (const char *)bp, length))
+	else if (l_strnstart(ndo, "END", 4, (const char *)bp, length))
  		ND_PRINT((ndo, " BEEP END"));
  	else
  		ND_PRINT((ndo, " BEEP (payload or undecoded)"));
```

---

## 33. Chrome  |  CVE-2016-1683  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab
- diff bruto: https://github.com/chromium/chromium/commit/96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab.patch
- commit_id: 96dbafe288dbe2f0cc45fa3c39daf6d0c37acbab

**mensagem do commit**

> Roll libxslt to 891681e3e948f31732229f53cb6db7215f740fc7
> 
> BUG=583156,583171
> 
> Review URL: https://codereview.chromium.org/1853083002
> 
> Cr-Commit-Position: refs/heads/master@{#385338}

**resumo da CVE**

> numbers.c in libxslt before 1.1.29, as used in Google Chrome before 51.0.2704.63, mishandles namespace nodes, which allows remote attackers to cause a denial of service (out-of-bounds heap memory access) or possibly have unspecified other impact via a crafted document.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -147,6 +147,7 @@
  	cur = matchList->nodeTab[i];
  	if (! IS_XSLT_REAL_NODE(cur))
  	    continue;
+        ctxt->node = cur;
  	xpctxt->node = cur;
  	/*
  	* Process the 'use' of the xsl:key.
```

---

## 34. tcpdump  |  CVE-2017-13004  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/42073d54c53a496be40ae84152bbfe2c923ac7bc
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/42073d54c53a496be40ae84152bbfe2c923ac7bc.patch
- commit_id: 42073d54c53a496be40ae84152bbfe2c923ac7bc

**mensagem do commit**

> CVE-2017-13004/Juniper: Add a bounds check.
> 
> This fixes a buffer over-read discovered by Forcepoint's security
> researchers Otto Airamo & Antti LevomÃ¤ki.
> 
> Add tests using the capture files supplied by the reporter(s).

**resumo da CVE**

> The Juniper protocols parser in tcpdump before 4.9.2 has a buffer over-read in print-juniper.c:juniper_parse_header().

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -189,6 +189,7 @@
              if (ndo->ndo_eflag) ND_PRINT((ndo, ": ")); /* print demarc b/w L2/L3*/
  
  
+            ND_TCHECK_16BITS(p+l2info->cookie_len);
              l2info->proto = EXTRACT_16BITS(p+l2info->cookie_len);
              break;
          }
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
@@ -1,5 +1,38 @@
 BlockEntry::BlockEntry(Cluster* p, long idx) :
-    m_pCluster(p),
-    m_index(idx)
-{
+BlockEntry::~BlockEntry() {}
+
+bool BlockEntry::EOS() const { return (GetKind() == kBlockEOS); }
+
+const Cluster* BlockEntry::GetCluster() const { return m_pCluster; }
+
+long BlockEntry::GetIndex() const { return m_index; }
+
+SimpleBlock::SimpleBlock(Cluster* pCluster, long idx, long long start,
+                         long long size)
+    : BlockEntry(pCluster, idx), m_block(start, size, 0) {}
+
+long SimpleBlock::Parse() { return m_block.Parse(m_pCluster); }
+
+BlockEntry::Kind SimpleBlock::GetKind() const { return kBlockSimple; }
+
+const Block* SimpleBlock::GetBlock() const { return &m_block; }
+
+BlockGroup::BlockGroup(Cluster* pCluster, long idx, long long block_start,
+                       long long block_size, long long prev, long long next,
+                       long long duration, long long discard_padding)
+    : BlockEntry(pCluster, idx),
+      m_block(block_start, block_size, discard_padding),
+      m_prev(prev),
+      m_next(next),
+      m_duration(duration) {}
+
+long BlockGroup::Parse() {
+  const long status = m_block.Parse(m_pCluster);
+
+  if (status)
+    return status;
+
+  m_block.SetKey((m_prev > 0) && (m_next <= 0));
+
+  return 0;
  }
```

---

## 36. FFmpeg  |  CVE-2017-14767  |  CWE-119
- commit: https://github.com/FFmpeg/FFmpeg/commit/c42a1388a6d1bfd8001bf6a4241d8ca27e49326d
- diff bruto: https://github.com/FFmpeg/FFmpeg/commit/c42a1388a6d1bfd8001bf6a4241d8ca27e49326d.patch
- commit_id: c42a1388a6d1bfd8001bf6a4241d8ca27e49326d

**mensagem do commit**

> avformat/rtpdec_h264: Fix heap-buffer-overflow
> 
> Fixes: rtp_sdp/poc.sdp
> 
> Found-by: Bingchang <l.bing.chang.bc@gmail.com>
> Signed-off-by: Michael Niedermayer <michael@niedermayer.cc>

**resumo da CVE**

> The sdp_parse_fmtp_config_h264 function in libavformat/rtpdec_h264.c in FFmpeg before 3.3.4 mishandles empty sprop-parameter-sets values, which allows remote attackers to cause a denial of service (heap buffer overflow) or possibly have unspecified other impact via a crafted sdp file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -23,7 +23,7 @@
              parse_profile_level_id(s, h264_data, value);
      } else if (!strcmp(attr, "sprop-parameter-sets")) {
          int ret;
-        if (value[strlen(value) - 1] == ',') {
+        if (*value == 0 || value[strlen(value) - 1] == ',') {
              av_log(s, AV_LOG_WARNING, "Missing PPS in sprop-parameter-sets, ignoring\n");
              return 0;
          }
```

---

## 37. Chrome  |  CVE-2016-5209  |  CWE-787
- commit: https://github.com/chromium/chromium/commit/d59a4441697f6253e7dc3f7ae5caad6e5fd2c778
- diff bruto: https://github.com/chromium/chromium/commit/d59a4441697f6253e7dc3f7ae5caad6e5fd2c778.patch
- commit_id: d59a4441697f6253e7dc3f7ae5caad6e5fd2c778

**mensagem do commit**

> Prevent bad casting in ImageBitmap when calling ArrayBuffer::createOrNull
> 
> Currently when ImageBitmap's constructor is invoked, we check whether
> dstSize will overflow size_t or not. The problem comes when we call
> ArrayBuffer::createOrNull some times in the code.
> 
> Both parameters of ArrayBuffer::createOrNull are unsigned. In ImageBitmap
> when we call this method, the first parameter is usually width * height.
> This could overflow unsigned even if it has been checked safe with size_t,
> the reason is that unsigned is a 32-bit value on 64-bit systems, while
> size_t is a 64-bit value.
> 
> This CL makes a change such that we check whether the dstSize will overflow
> unsigned or not. In this case, we can guarantee that createOrNull will not have
> any crash.
> 
> BUG=664139
> 
> Review-Url: https://codereview.chromium.org/2500493002
> Cr-Commit-Position: refs/heads/master@{#431936}

**resumo da CVE**

> Bad casting in bitmap manipulation in Blink in Google Chrome prior to 55.0.2883.75 for Mac, Windows and Linux, and 55.0.2883.84 for Android allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -6,5 +6,5 @@
      return nullptr;
    return newSkImageFromRaster(
        info, std::move(dstPixels),
-      static_cast<size_t>(input->width()) * info.bytesPerPixel());
+      static_cast<unsigned>(input->width()) * info.bytesPerPixel());
  }
```

---

## 38. ImageMagick  |  CVE-2016-10066  |  CWE-119
- commit: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/f6e9d0d9955e85bdd7540b251cd50d598dacc5e6.patch
- commit_id: f6e9d0d9955e85bdd7540b251cd50d598dacc5e6

**resumo da CVE**

> Buffer overflow in the ReadVIFFImage function in coders/viff.c in ImageMagick before 6.9.4-5 allows remote attackers to cause a denial of service (application crash) via a crafted file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -836,6 +836,12 @@
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

---

## 39. Android  |  CVE-2016-2476  |  CWE-119
- commit: https://android.googlesource.com/platform/frameworks/av/+/295c883fe3105b19bcd0f9e07d54c6b589fc5bff
- diff bruto: https://android.googlesource.com/platform/frameworks/av/+/295c883fe3105b19bcd0f9e07d54c6b589fc5bff^!
- commit_id: 295c883fe3105b19bcd0f9e07d54c6b589fc5bff

**mensagem do commit**

> DO NOT MERGE Verify OMX buffer sizes prior to access
> 
> Bug: 27207275
> Change-Id: I4412825d1ee233d993af0a67708bea54304ff62d
> 

**resumo da CVE**

> mediaserver in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-06-01 does not validate OMX buffer sizes, which allows attackers to gain privileges via a crafted application, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 27207275.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -9,6 +9,10 @@
              OMX_AUDIO_PARAM_PCMMODETYPE *pcmParams =
                  (OMX_AUDIO_PARAM_PCMMODETYPE *)params;
  
+            if (!isValidOMXParam(pcmParams)) {
+                return OMX_ErrorBadParameter;
+            }
+
              if (pcmParams->nPortIndex > 1) {
                  return OMX_ErrorUndefined;
              }
@@ -31,6 +35,11 @@
          case OMX_IndexParamAudioFlac:
          {
              OMX_AUDIO_PARAM_FLACTYPE *flacParams = (OMX_AUDIO_PARAM_FLACTYPE *)params;
+
+            if (!isValidOMXParam(flacParams)) {
+                return OMX_ErrorBadParameter;
+            }
+
              flacParams->nCompressionLevel = mCompressionLevel;
              flacParams->nChannels = mNumChannels;
              flacParams->nSampleRate = mSampleRate;
```

---

## 40. Android  |  CVE-2016-3861  |  CWE-119
- commit: https://android.googlesource.com/platform/frameworks/base/+/866dc26ad4a98cc835d075b627326e7d7e52ffa1
- diff bruto: https://android.googlesource.com/platform/frameworks/base/+/866dc26ad4a98cc835d075b627326e7d7e52ffa1^!
- commit_id: 866dc26ad4a98cc835d075b627326e7d7e52ffa1

**mensagem do commit**

> Add bound checks to utf16_to_utf8
> 
> Test: ran libaapt2_tests64
> Bug: 29250543
> Change-Id: I1ebc017af623b6514cf0c493e8cd8e1d59ea26c3
> (cherry picked from commit 4781057e78f63e0e99af109cebf3b6a78f4bfbb6)
> 

**resumo da CVE**

> LibUtils in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, 6.x before 2016-09-01, and 7.0 before 2016-09-01 mishandles conversions between Unicode character encodings with different encoding widths, which allows remote attackers to execute arbitrary code or cause a denial of service (heap-based buffer overflow) via a crafted file, aka internal bug 29250543.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -6,7 +6,9 @@
      }
  
      std::string utf8;
+    // Make room for '\0' explicitly.
+    utf8.resize(utf8Length + 1);
+    utf16_to_utf8(utf16.data(), utf16.length(), &*utf8.begin(), utf8Length + 1);
      utf8.resize(utf8Length);
-    utf16_to_utf8(utf16.data(), utf16.length(), &*utf8.begin());
      return utf8;
  }
```

---

## 41. ImageMagick  |  CVE-2016-7527  |  CWE-125
- commit: https://github.com/ImageMagick/ImageMagick/commit/a251039393f423c7858e63cab6aa98d17b8b7a41
- diff bruto: https://github.com/ImageMagick/ImageMagick/commit/a251039393f423c7858e63cab6aa98d17b8b7a41.patch
- commit_id: a251039393f423c7858e63cab6aa98d17b8b7a41

**mensagem do commit**

> https://github.com/ImageMagick/ImageMagick/issues/122

**resumo da CVE**

> coders/wpg.c in ImageMagick allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -49,7 +49,7 @@
    if(exception->severity != UndefinedException) goto FINISH_UNL;
    if(magic_info->name == (char *) NULL) goto FINISH_UNL;
  
-  (void) CopyMagickMemory(clone_info->magick,magic_info->name,MaxTextExtent);
+  (void) strncpy(clone_info->magick,magic_info->name,MaxTextExtent);
  
      /* Read nested image */
    /*FormatString(clone_info->filename,"%s:%s",magic_info->name,postscript_file);*/
```

---

## 42. ghostscript  |  CVE-2014-2013  |  CWE-119
- commit: http://git.ghostscript.com/?p=mupdf.git;a=commitdiff;h=60dabde18d7fe12b19da8b509bdfee9cc886aafc
- diff bruto: http://git.ghostscript.com/?p=mupdf.git;a=commitdiff;h=60dabde18d7fe12b19da8b509bdfee9cc886aafc
- commit_id: 60dabde18d7fe12b19da8b509bdfee9cc886aafc

**resumo da CVE**

> Stack-based buffer overflow in the xps_parse_color function in xps/xps-common.c in MuPDF 1.3 and earlier allows remote attackers to execute arbitrary code via a large number of entries in the ContextColor value of the Fill attribute in a Path element.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -20,7 +20,7 @@
                 if (scb_color_att)
                 {
                         fz_colorspace *colorspace;
-                       float samples[32];
+                       float samples[FZ_MAX_COLORS];
                         xps_parse_color(doc, base_uri, scb_color_att, &colorspace, samples);
                         opacity = opacity * samples[0];
                 }
```

---

## 43. tcpdump  |  CVE-2017-13690  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/8dca25d26c7ca2caf6138267f6f17111212c156e
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/8dca25d26c7ca2caf6138267f6f17111212c156e.patch
- commit_id: 8dca25d26c7ca2caf6138267f6f17111212c156e

**mensagem do commit**

> CVE-2017-13690/IKEv2: Fix some bounds checks.
> 
> Use a pointer of the correct type in ND_TCHECK(), or use ND_TCHECK2()
> and provide the correct length.
> 
> While we're at it, remove the blank line between some checks and the
> UNALIGNED_MEMCPY()s they protect.
> 
> Also, note the places where we print the entire payload.
> 
> This fixes a buffer over-read discovered by Bhargava Shastry,
> SecT/TU Berlin.
> 
> Add a test using the capture file supplied by the reporter(s).

**resumo da CVE**

> The IKEv2 parser in tcpdump before 4.9.2 has a buffer over-read in print-isakmp.c, several functions.

**diff da funcao**: vazio apos normalizar o espaco em branco (tipo A, ja pre-marcado)

---

## 44. Android  |  CVE-2016-1621  |  CWE-119
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
@@ -1,28 +1,33 @@
 long Track::Create(
-    Segment* pSegment,
-    const Info& info,
-    long long element_start,
-    long long element_size,
-    Track*& pResult)
-{
-    if (pResult)
-        return -1;
+Track::Info::Info()
+    : uid(0),
+      defaultDuration(0),
+      codecDelay(0),
+      seekPreRoll(0),
+      nameAsUTF8(NULL),
+      language(NULL),
+      codecId(NULL),
+      codecNameAsUTF8(NULL),
+      codecPrivate(NULL),
+      codecPrivateSize(0),
+      lacing(false) {}
  
-    Track* const pTrack = new (std::nothrow) Track(pSegment,
-                                                   element_start,
-                                                   element_size);
+Track::Info::~Info() { Clear(); }
  
-    if (pTrack == NULL)
-        return -1;  //generic error
+void Track::Info::Clear() {
+  delete[] nameAsUTF8;
+  nameAsUTF8 = NULL;
  
-    const int status = info.Copy(pTrack->m_info);
+  delete[] language;
+  language = NULL;
  
-    if (status)  // error
-    {
-        delete pTrack;
-        return status;
-    }
+  delete[] codecId;
+  codecId = NULL;
  
-    pResult = pTrack;
-    return 0;  //success
+  delete[] codecPrivate;
+  codecPrivate = NULL;
+  codecPrivateSize = 0;
+
+  delete[] codecNameAsUTF8;
+  codecNameAsUTF8 = NULL;
  }
```

---

## 45. openssl  |  CVE-2015-1789  |  CWE-119
- commit: https://github.com/openssl/openssl/commit/f48b83b4fb7d6689584cf25f61ca63a4891f5b11
- diff bruto: https://github.com/openssl/openssl/commit/f48b83b4fb7d6689584cf25f61ca63a4891f5b11.patch
- commit_id: f48b83b4fb7d6689584cf25f61ca63a4891f5b11

**mensagem do commit**

> Fix length checks in X509_cmp_time to avoid out-of-bounds reads.
> 
> Also tighten X509_cmp_time to reject more than three fractional
> seconds in the time; and to reject trailing garbage after the offset.
> 
> CVE-2015-1789
> 
> Reviewed-by: Viktor Dukhovni <viktor@openssl.org>
> Reviewed-by: Richard Levitte <levitte@openssl.org>

**resumo da CVE**

> The X509_cmp_time function in crypto/x509/x509_vfy.c in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b allows remote attackers to cause a denial of service (out-of-bounds read and application crash) via a crafted length field in ASN1_TIME data, as demonstrated by an attack against a server that supports client authentication with a custom verification callback.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -4,47 +4,84 @@
      ASN1_TIME atm;
      long offset;
      char buff1[24], buff2[24], *p;
-    int i, j;
+    int i, j, remaining;
  
      p = buff1;
-    i = ctm->length;
+    remaining = ctm->length;
      str = (char *)ctm->data;
+    /*
+     * Note that the following (historical) code allows much more slack in the
+     * time format than RFC5280. In RFC5280, the representation is fixed:
+     * UTCTime: YYMMDDHHMMSSZ
+     * GeneralizedTime: YYYYMMDDHHMMSSZ
+     */
      if (ctm->type == V_ASN1_UTCTIME) {
-        if ((i < 11) || (i > 17))
+        /* YYMMDDHHMM[SS]Z or YYMMDDHHMM[SS](+-)hhmm */
+        int min_length = sizeof("YYMMDDHHMMZ") - 1;
+        int max_length = sizeof("YYMMDDHHMMSS+hhmm") - 1;
+        if (remaining < min_length || remaining > max_length)
              return 0;
          memcpy(p, str, 10);
          p += 10;
          str += 10;
+        remaining -= 10;
      } else {
-        if (i < 13)
+        /* YYYYMMDDHHMM[SS[.fff]]Z or YYYYMMDDHHMM[SS[.f[f[f]]]](+-)hhmm */
+        int min_length = sizeof("YYYYMMDDHHMMZ") - 1;
+        int max_length = sizeof("YYYYMMDDHHMMSS.fff+hhmm") - 1;
+        if (remaining < min_length || remaining > max_length)
              return 0;
          memcpy(p, str, 12);
          p += 12;
          str += 12;
+        remaining -= 12;
      }
  
      if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
          *(p++) = '0';
          *(p++) = '0';
      } else {
+        /* SS (seconds) */
+        if (remaining < 2)
+            return 0;
          *(p++) = *(str++);
          *(p++) = *(str++);
-        /* Skip any fractional seconds... */
-        if (*str == '.') {
+        remaining -= 2;
+        /*
+         * Skip any (up to three) fractional seconds...
+         * TODO(emilia): in RFC5280, fractional seconds are forbidden.
+         * Can we just kill them altogether?
+         */
+        if (remaining && *str == '.') {
              str++;
-            while ((*str >= '0') && (*str <= '9'))
-                str++;
+            remaining--;
+            for (i = 0; i < 3 && remaining; i++, str++, remaining--) {
+                if (*str < '0' || *str > '9')
+                    break;
+            }
          }
  
      }
      *(p++) = 'Z';
      *(p++) = '\0';
  
-    if (*str == 'Z')
+    /* We now need either a terminating 'Z' or an offset. */
+    if (!remaining)
+        return 0;
+    if (*str == 'Z') {
+        if (remaining != 1)
+            return 0;
          offset = 0;
-    else {
+    } else {
+        /* (+-)HHMM */
          if ((*str != '+') && (*str != '-'))
              return 0;
+        /* Historical behaviour: the (+-)hhmm offset is forbidden in RFC5280. */
+        if (remaining != 5)
+            return 0;
+        if (str[1] < '0' || str[1] > '9' || str[2] < '0' || str[2] > '9' ||
+            str[3] < '0' || str[3] > '9' || str[4] < '0' || str[4] > '9')
+            return 0;
          offset = ((str[1] - '0') * 10 + (str[2] - '0')) * 60;
          offset += (str[3] - '0') * 10 + (str[4] - '0');
          if (*str == '-')
```

---

## 46. krb5  |  CVE-2015-8631  |  CWE-119
- commit: https://github.com/krb5/krb5/commit/83ed75feba32e46f736fcce0d96a0445f29b96c2
- diff bruto: https://github.com/krb5/krb5/commit/83ed75feba32e46f736fcce0d96a0445f29b96c2.patch
- commit_id: 83ed75feba32e46f736fcce0d96a0445f29b96c2

**mensagem do commit**

> Fix leaks in kadmin server stubs [CVE-2015-8631]
> 
> In each kadmind server stub, initialize the client_name and
> server_name variables, and release them in the cleanup handler.  Many
> of the stubs will otherwise leak the client and server name if
> krb5_unparse_name() fails.  Also make sure to free the prime_arg
> variables in rename_principal_2_svc(), or we can leak the first one if
> unparsing the second one fails.  Discovered by Simo Sorce.
> 
> CVE-2015-8631:
> 
> In all versions of MIT krb5, an authenticated attacker can cause
> kadmind to leak memory by supplying a null principal name in a request
> which uses one.  Repeating these requests will eventually cause
> kadmind to exhaust all available memory.
> 
>     CVSSv2 Vector: AV:N/AC:L/Au:S/C:N/I:N/A:C/E:POC/RL:OF/RC:C
> 
> ticket: 8343 (new)
> target_version: 1.14-next
> target_version: 1.13-next
> tags: pullup

**resumo da CVE**

> Multiple memory leaks in kadmin/server/server_stubs.c in kadmind in MIT Kerberos 5 (aka krb5) before 1.13.4 and 1.14.x before 1.14.1 allow remote authenticated users to cause a denial of service (memory consumption) via a request specifying a NULL principal name.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,7 +2,8 @@
  {
      static generic_ret          ret;
      char                        *prime_arg, *funcname;
-    gss_buffer_desc             client_name, service_name;
+    gss_buffer_desc             client_name = GSS_C_EMPTY_BUFFER;
+    gss_buffer_desc             service_name = GSS_C_EMPTY_BUFFER;
      OM_uint32                   minor_stat;
      kadm5_server_handle_t       handle;
  
@@ -48,9 +49,9 @@
              krb5_free_error_message(handle->context, errmsg);
      }
      free(prime_arg);
+exit_func:
      gss_release_buffer(&minor_stat, &client_name);
      gss_release_buffer(&minor_stat, &service_name);
-exit_func:
      free_server_handle(handle);
      return &ret;
  }
```

---

## 47. Android  |  CVE-2015-3832  |  CWE-119
- commit: https://android.googlesource.com/platform/frameworks/av/+/d48f0f145f8f0f4472bc0af668ac9a8bce44ba9b
- diff bruto: https://android.googlesource.com/platform/frameworks/av/+/d48f0f145f8f0f4472bc0af668ac9a8bce44ba9b^!
- commit_id: d48f0f145f8f0f4472bc0af668ac9a8bce44ba9b

**mensagem do commit**

> Add AUtils::isInRange, and use it to detect malformed MPEG4 nal sizes
> 
> Bug: 19641538
> Change-Id: I5aae3f100846c125decc61eec7cd6563e3f33777
> 

**resumo da CVE**

> Multiple buffer overflows in MPEG4Extractor.cpp in libstagefright in Android before 5.1.1 LMY48I allow remote attackers to execute arbitrary code via invalid size values of NAL units in MP4 data, aka internal bug 19641538.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,8 +1,7 @@
  ssize_t MPEG4DataSource::readAt(off64_t offset, void *data, size_t size) {
      Mutex::Autolock autoLock(mLock);
  
-    if (offset >= mCachedOffset
-            && offset + size <= mCachedOffset + mCachedSize) {
+    if (isInRange(mCachedOffset, mCachedSize, offset, size)) {
          memcpy(data, &mCache[offset - mCachedOffset], size);
          return size;
      }
```

---

## 48. Chrome  |  CVE-2012-5152  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/802ecdb9cee0d66fe546bdf24e98150f8f716ad8
- diff bruto: https://github.com/chromium/chromium/commit/802ecdb9cee0d66fe546bdf24e98150f8f716ad8.patch
- commit_id: 802ecdb9cee0d66fe546bdf24e98150f8f716ad8

**mensagem do commit**

> Protect AudioRendererAlgorithm from invalid step sizes.
> 
> BUG=165430
> TEST=unittests and asan pass.
> 
> Review URL: https://codereview.chromium.org/11573023
> 
> git-svn-id: svn://svn.chromium.org/chrome/trunk/src@173249 0039d316-1c4b-4281-b951-d872f2087c98

**resumo da CVE**

> Google Chrome before 24.0.1312.52 allows remote attackers to cause a denial of service (out-of-bounds read) via vectors involving seek operations on video data.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,6 +1 @@
   void WriteFakeData(uint8* audio_data, size_t length) {
-    Type* output = reinterpret_cast<Type*>(audio_data);
-    for (size_t i = 0; i < length; i++) {
-      output[i] = i % 5 + 10;
-    }
-  }
```

---

## 49. liblouis  |  CVE-2018-17294  |  CWE-125
- commit: https://github.com/liblouis/liblouis/commit/5e4089659bb49b3095fa541fa6387b4c40d7396e
- diff bruto: https://github.com/liblouis/liblouis/commit/5e4089659bb49b3095fa541fa6387b4c40d7396e.patch
- commit_id: 5e4089659bb49b3095fa541fa6387b4c40d7396e

**mensagem do commit**

> Fix a buffer overflow
> 
> Fixes #635
> 
> Thanks to HongxuChen for reporting it

**resumo da CVE**

> The matchCurrentInput function inside lou_translateString.c of Liblouis prior to 3.7 does not check the input string's length, allowing attackers to cause a denial of service (application crash via out-of-bounds read) by crafting an input file with certain translation dictionaries.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -2,7 +2,9 @@
  		const InString *input, int pos, const widechar *passInstructions, int passIC) {
  	int k;
  	int kk = pos;
-	for (k = passIC + 2; k < passIC + 2 + passInstructions[passIC + 1]; k++)
+	for (k = passIC + 2;
+			((k < passIC + 2 + passInstructions[passIC + 1]) && (kk < input->length));
+			k++)
  		if (input->chars[kk] == ENDSEGMENT || passInstructions[k] != input->chars[kk++])
  			return 0;
  	return 1;
```

---

## 50. Chrome  |  CVE-2013-2877  |  CWE-119
- commit: https://github.com/chromium/chromium/commit/d0947db40187f4708c58e64cbd6013faf9eddeed
- diff bruto: https://github.com/chromium/chromium/commit/d0947db40187f4708c58e64cbd6013faf9eddeed.patch
- commit_id: d0947db40187f4708c58e64cbd6013faf9eddeed

**mensagem do commit**

> libxml: XML_PARSER_EOF checks from upstream
> 
> BUG=229019
> TBR=cpu
> 
> Review URL: https://chromiumcodereview.appspot.com/14053009
> 
> git-svn-id: svn://svn.chromium.org/chrome/trunk/src@196804 0039d316-1c4b-4281-b951-d872f2087c98

**resumo da CVE**

> parser.c in libxml2 before 2.9.0, as used in Google Chrome before 28.0.1500.71 and other products, allows remote attackers to cause a denial of service (out-of-bounds read) via a document that ends abruptly, related to the lack of certain checks for the XML_PARSER_EOF state.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -22,6 +22,8 @@
  	if (count++ > 100) {
  	    count = 0;
  	    GROW;
+            if (ctxt->instate == XML_PARSER_EOF)
+                return(NULL);
  	}
  	len += l;
  	NEXTL(l);
```

---

## 51. Android  |  CVE-2016-3745  |  CWE-119
- commit: https://android.googlesource.com/platform/hardware/qcom/audio/+/073a80800f341325932c66818ce4302b312909a4
- diff bruto: https://android.googlesource.com/platform/hardware/qcom/audio/+/073a80800f341325932c66818ce4302b312909a4^!
- commit_id: 073a80800f341325932c66818ce4302b312909a4

**mensagem do commit**

> DO NOT MERGE Fix AudioEffect reply overflow
> 
> Bug: 28173666
> Change-Id: I055af37a721b20c5da0f1ec4b02f630dcd5aee02
> 

**resumo da CVE**

> Multiple buffer overflows in mediaserver in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-07-01 allow attackers to gain privileges via a crafted application that provides an AudioEffect reply, as demonstrated by obtaining Signature or SignatureOrSystem access, aka internal bug 28173666.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -89,8 +89,9 @@
          if (pCmdData == NULL ||
              cmdSize < (int)(sizeof(effect_param_t) + sizeof(uint32_t)) ||
              pReplyData == NULL ||
-            *replySize < (int)(sizeof(effect_param_t) + sizeof(uint32_t) +
-                               sizeof(uint16_t))) {
+            *replySize < (int)(sizeof(effect_param_t) + sizeof(uint32_t) + sizeof(uint16_t)) ||
+            // constrain memcpy below
+            ((effect_param_t *)pCmdData)->psize > *replySize - sizeof(effect_param_t)) {
              status = -EINVAL;
              ALOGV("EFFECT_CMD_GET_PARAM invalid command cmdSize %d *replySize %d",
                    cmdSize, *replySize);
```

---

## 52. Android  |  CVE-2016-1621  |  CWE-119
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
@@ -1,41 +1,67 @@
 long long mkvparser::GetUIntLength(
-    IMkvReader* pReader,
-    long long pos,
-    long& len)
-{
-    assert(pReader);
-    assert(pos >= 0);
+long long mkvparser::GetUIntLength(IMkvReader* pReader, long long pos,
+                                   long& len) {
+  assert(pReader);
+  assert(pos >= 0);
  
-    long long total, available;
+  long long total, available;
  
-    int status = pReader->Length(&total, &available);
-    assert(status >= 0);
-    assert((total < 0) || (available <= total));
+  int status = pReader->Length(&total, &available);
+  assert(status >= 0);
+  assert((total < 0) || (available <= total));
  
-    len = 1;
+  len = 1;
  
-    if (pos >= available)
-        return pos;  //too few bytes available
+  if (pos >= available)
+    return pos;  // too few bytes available
  
+  unsigned char b;
+
+  status = pReader->Read(pos, 1, &b);
+
+  if (status < 0)
+    return status;
+
+  assert(status == 0);
+
+  if (b == 0)  // we can't handle u-int values larger than 8 bytes
+    return E_FILE_FORMAT_INVALID;
+
+  unsigned char m = 0x80;
+
+  while (!(b & m)) {
+    m >>= 1;
+    ++len;
+  }
+
+  return 0;  // success
+}
+
 //// TODO(vigneshv): This function assumes that unsigned values never have their
 //// high bit set.
+long long mkvparser::UnserializeUInt(IMkvReader* pReader, long long pos,
+                                     long long size) {
+  assert(pReader);
+  assert(pos >= 0);
+
+  if ((size <= 0) || (size > 8))
+    return E_FILE_FORMAT_INVALID;
+
+  long long result = 0;
+
+  for (long long i = 0; i < size; ++i) {
      unsigned char b;
  
-    status = pReader->Read(pos, 1, &b);
+    const long status = pReader->Read(pos, 1, &b);
  
      if (status < 0)
-        return status;
+      return status;
  
-    assert(status == 0);
+    result <<= 8;
+    result |= b;
  
-    if (b == 0)  //we can't handle u-int values larger than 8 bytes
-        return E_FILE_FORMAT_INVALID;
+    ++pos;
+  }
  
-    unsigned char m = 0x80;
-    while (!(b & m))
-    {
-        m >>= 1;
-        ++len;
-    }
-    return 0;  //success
+  return result;
  }
```

---

## 53. tcpdump  |  CVE-2017-12894  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/730fc35968c5433b9e2a829779057f4f9495dc51
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/730fc35968c5433b9e2a829779057f4f9495dc51.patch
- commit_id: 730fc35968c5433b9e2a829779057f4f9495dc51

**mensagem do commit**

> CVE-2017-12894/In lookup_bytestring(), take the length of the byte string into account.
> 
> Otherwise, if, in our search of the hash table, we come across a byte
> string that's shorter than the string we're looking for, we'll search
> past the end of the string in the hash table.
> 
> This fixes a buffer over-read discovered by Forcepoint's security
> researchers Otto Airamo & Antti LevomÃ¤ki.
> 
> Add a test using the capture file supplied by the reporter(s).

**resumo da CVE**

> Several protocol parsers in tcpdump before 4.9.2 could cause a buffer over-read in addrtoname.c:lookup_bytestring().

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -1,7 +1,7 @@
  lookup_bytestring(netdissect_options *ndo, register const u_char *bs,
  		  const unsigned int nlen)
  {
-	struct enamemem *tp;
+	struct bsnamemem *tp;
  	register u_int i, j, k;
  
  	if (nlen >= 6) {
@@ -16,26 +16,28 @@
  		i = j = k = 0;
  
  	tp = &bytestringtable[(i ^ j) & (HASHNAMESIZE-1)];
-	while (tp->e_nxt)
-		if (tp->e_addr0 == i &&
-		    tp->e_addr1 == j &&
-		    tp->e_addr2 == k &&
-		    memcmp((const char *)bs, (const char *)(tp->e_bs), nlen) == 0)
+	while (tp->bs_nxt)
+		if (nlen == tp->bs_nbytes &&
+		    tp->bs_addr0 == i &&
+		    tp->bs_addr1 == j &&
+		    tp->bs_addr2 == k &&
+		    memcmp((const char *)bs, (const char *)(tp->bs_bytes), nlen) == 0)
  			return tp;
  		else
-			tp = tp->e_nxt;
+			tp = tp->bs_nxt;
  
-	tp->e_addr0 = i;
-	tp->e_addr1 = j;
-	tp->e_addr2 = k;
+	tp->bs_addr0 = i;
+	tp->bs_addr1 = j;
+	tp->bs_addr2 = k;
  
-	tp->e_bs = (u_char *) calloc(1, nlen + 1);
-	if (tp->e_bs == NULL)
+	tp->bs_bytes = (u_char *) calloc(1, nlen + 1);
+	if (tp->bs_bytes == NULL)
  		(*ndo->ndo_error)(ndo, "lookup_bytestring: calloc");
  
-	memcpy(tp->e_bs, bs, nlen);
-	tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
-	if (tp->e_nxt == NULL)
+	memcpy(tp->bs_bytes, bs, nlen);
+	tp->bs_nbytes = nlen;
+	tp->bs_nxt = (struct bsnamemem *)calloc(1, sizeof(*tp));
+	if (tp->bs_nxt == NULL)
  		(*ndo->ndo_error)(ndo, "lookup_bytestring: calloc");
  
  	return tp;
```

---

## 54. Android  |  CVE-2016-2508  |  CWE-119
- commit: https://android.googlesource.com/platform/frameworks/av/+/f81038006b4c59a5a148dcad887371206033c28f
- diff bruto: https://android.googlesource.com/platform/frameworks/av/+/f81038006b4c59a5a148dcad887371206033c28f^!
- commit_id: f81038006b4c59a5a148dcad887371206033c28f

**mensagem do commit**

> MPEG4Extractor: ensure kKeyTrackID exists before creating an MPEG4Source as track.
> 
> GenericSource: return error when no track exists.
> 
> SampleIterator: make sure mSamplesPerChunk is not zero before using it as divisor.
> 
> Bug: 21657957
> Bug: 23705695
> Bug: 22802344
> Bug: 28799341
> Change-Id: I7664992ade90b935d3f255dcd43ecc2898f30b04
> (cherry picked from commit 0386c91b8a910a134e5898ffa924c1b6c7560b13)
> 

**resumo da CVE**

> media/libmediaplayerservice/nuplayer/GenericSource.cpp in mediaserver in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-07-01 does not validate certain track data, which allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, aka internal bug 28799341.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -32,6 +32,11 @@
  
      CHECK(sampleIndex < mStopChunkSampleIndex);
  
+    if (mSamplesPerChunk == 0) {
+        ALOGE("b/22802344");
+        return ERROR_MALFORMED;
+    }
+
      uint32_t chunk =
          (sampleIndex - mFirstChunkSampleIndex) / mSamplesPerChunk
          + mFirstChunk;
```

---

## 55. linux  |  CVE-2013-2234  |  CWE-119
- commit: https://github.com/torvalds/linux/commit/a5cc68f3d63306d0d288f31edfc2ae6ef8ecd887
- diff bruto: https://github.com/torvalds/linux/commit/a5cc68f3d63306d0d288f31edfc2ae6ef8ecd887.patch
- commit_id: a5cc68f3d63306d0d288f31edfc2ae6ef8ecd887

**mensagem do commit**

> af_key: fix info leaks in notify messages
> 
> key_notify_sa_flush() and key_notify_policy_flush() miss to initialize
> the sadb_msg_reserved member of the broadcasted message and thereby
> leak 2 bytes of heap memory to listeners. Fix that.
> 
> Signed-off-by: Mathias Krause <minipli@googlemail.com>
> Cc: Steffen Klassert <steffen.klassert@secunet.com>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Herbert Xu <herbert@gondor.apana.org.au>
> Signed-off-by: David S. Miller <davem@davemloft.net>

**resumo da CVE**

> The (1) key_notify_sa_flush and (2) key_notify_policy_flush functions in net/key/af_key.c in the Linux kernel before 3.10 do not initialize certain structure members, which allows local users to obtain sensitive information from kernel heap memory by reading a broadcast message from the notify interface of an IPSec key_socket.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -14,6 +14,7 @@
  	hdr->sadb_msg_version = PF_KEY_V2;
  	hdr->sadb_msg_errno = (uint8_t) 0;
  	hdr->sadb_msg_len = (sizeof(struct sadb_msg) / sizeof(uint64_t));
+	hdr->sadb_msg_reserved = 0;
  
  	pfkey_broadcast(skb, GFP_ATOMIC, BROADCAST_ALL, NULL, c->net);
  
```

---

## 56. imageworsener  |  CVE-2017-9203  |  CWE-787
- commit: https://github.com/jsummers/imageworsener/commit/a4f247707f08e322f0b41e82c3e06e224240a654
- diff bruto: https://github.com/jsummers/imageworsener/commit/a4f247707f08e322f0b41e82c3e06e224240a654.patch
- commit_id: a4f247707f08e322f0b41e82c3e06e224240a654

**mensagem do commit**

> Fixed a bug that could cause invalid memory to be accessed
> 
> The bug could happen when transparency is removed from an image.
> Also fixed a semi-related BMP error handling logic bug.
> Fixes issue #21

**resumo da CVE**

> imagew-main.c:960:12 in libimageworsener.a in ImageWorsener 1.3.1 allows remote attackers to cause a denial of service (buffer underflow) via a crafted image, related to imagew-bmp.c.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -24,13 +24,27 @@
  	iw_tmpsample *out_pix = NULL;
  	int num_in_pix;
  	int num_out_pix;
+	struct iw_channelinfo_out default_ci_out;
  
  	num_in_pix = ctx->intermed_canvas_width;
  	num_out_pix = ctx->img2.width;
  
  	int_ci = &ctx->intermed_ci[intermed_channel];
  	output_channel = int_ci->corresponding_output_channel;
-	out_ci = &ctx->img2_ci[output_channel];
+	if(output_channel>=0) {
+		out_ci = &ctx->img2_ci[output_channel];
+	}
+	else {
+		// If there is no output channelinfo struct, create a temporary one to
+		// use.
+		// TODO: This is admittedly ugly, but we use these settings for a few
+		// things even when there is no corresponding output channel, and I
+		// don't remember exactly why.
+		iw_zeromem(&default_ci_out, sizeof(struct iw_channelinfo_out));
+		default_ci_out.channeltype = IW_CHANNELTYPE_NONALPHA;
+		out_ci = &default_ci_out;
+	}
+
  	is_alpha_channel = (int_ci->channeltype==IW_CHANNELTYPE_ALPHA);
  	bkgd_has_transparency = iw_bkgd_has_transparency(ctx);
  
```

---

## 57. savannah  |  CVE-2014-9665  |  CWE-119
- commit: https://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=b3500af717010137046ec4076d1e1c0641e33727
- diff bruto: https://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=b3500af717010137046ec4076d1e1c0641e33727
- commit_id: b3500af717010137046ec4076d1e1c0641e33727

**resumo da CVE**

> The Load_SBit_Png function in sfnt/pngshim.c in FreeType before 2.5.4 does not restrict the rows and pitch values of PNG data, which allows remote attackers to cause a denial of service (integer overflow and heap-based buffer overflow) or possibly have unspecified other impact by embedding a PNG file in a .ttf font file.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -7,7 +7,7 @@
      int             pitch;
      int             new_pitch;
      FT_UInt         bpp;
-    FT_Int          i, width, height;
+    FT_UInt         i, width, height;
      unsigned char*  buffer = NULL;
  
  
@@ -45,17 +45,17 @@
      if ( ypixels == 0 && new_pitch <= pitch )
      {
        /* zero the padding */
-      FT_Int  bit_width = pitch * 8;
-      FT_Int  bit_last  = ( width + xpixels ) * bpp;
+      FT_UInt  bit_width = pitch * 8;
+      FT_UInt  bit_last  = ( width + xpixels ) * bpp;
  
  
        if ( bit_last < bit_width )
        {
          FT_Byte*  line  = bitmap->buffer + ( bit_last >> 3 );
          FT_Byte*  end   = bitmap->buffer + pitch;
-        FT_Int    shift = bit_last & 7;
+        FT_UInt   shift = bit_last & 7;
          FT_UInt   mask  = 0xFF00U >> shift;
-        FT_Int    count = height;
+        FT_UInt   count = height;
  
  
          for ( ; count > 0; count--, line += pitch, end += pitch )
@@ -84,7 +84,7 @@
      /* thus take care of the flow direction         */
      if ( bitmap->pitch > 0 )
      {
-      FT_Int  len = ( width * bpp + 7 ) >> 3;
+      FT_UInt  len = ( width * bpp + 7 ) >> 3;
  
  
        for ( i = 0; i < bitmap->rows; i++ )
@@ -93,7 +93,7 @@
      }
      else
      {
-      FT_Int  len = ( width * bpp + 7 ) >> 3;
+      FT_UInt  len = ( width * bpp + 7 ) >> 3;
  
  
        for ( i = 0; i < bitmap->rows; i++ )
```

---

## 58. Android  |  CVE-2016-3824  |  CWE-119
- commit: https://android.googlesource.com/platform/frameworks/av/+/b351eabb428c7ca85a34513c64601f437923d576
- diff bruto: https://android.googlesource.com/platform/frameworks/av/+/b351eabb428c7ca85a34513c64601f437923d576^!
- commit_id: b351eabb428c7ca85a34513c64601f437923d576

**mensagem do commit**

> DO NOT MERGE omx: check buffer port before using
> 
> Bug: 28816827
> Change-Id: I3d5bad4a1ef96dec544b05bb31cc6f7109aae0a5
> 

**resumo da CVE**

> omx/OMXNodeInstance.cpp in libstagefright in mediaserver in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, and 6.x before 2016-08-01 does not validate the buffer port, which allows attackers to gain privileges via a crafted application, aka internal bug 28816827.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -6,7 +6,10 @@
  
      removeActiveBuffer(portIndex, buffer);
  
-    OMX_BUFFERHEADERTYPE *header = findBufferHeader(buffer);
+    OMX_BUFFERHEADERTYPE *header = findBufferHeader(buffer, portIndex);
+    if (header == NULL) {
+        return BAD_VALUE;
+    }
      BufferMeta *buffer_meta = static_cast<BufferMeta *>(header->pAppPrivate);
  
      OMX_ERRORTYPE err = OMX_FreeBuffer(mHandle, portIndex, header);
```

---

## 59. tcpdump  |  CVE-2017-13040  |  CWE-125
- commit: https://github.com/the-tcpdump-group/tcpdump/commit/4c3aee4bb0294c232d56b6d34e9eeb74f630fe8c
- diff bruto: https://github.com/the-tcpdump-group/tcpdump/commit/4c3aee4bb0294c232d56b6d34e9eeb74f630fe8c.patch
- commit_id: 4c3aee4bb0294c232d56b6d34e9eeb74f630fe8c

**mensagem do commit**

> CVE-2017-13040/MPTCP: Clean up printing DSS suboption.
> 
> Do the length checking inline; that means we print stuff up to the point
> at which we run out of option data.
> 
> First check to make sure we have at least 4 bytes of option, so we have
> flags to check.
> 
> This fixes a buffer over-read discovered by Kim Gwan Yeong.
> 
> Add a test using the capture file supplied by the reporter(s).

**resumo da CVE**

> The MPTCP parser in tcpdump before 4.9.2 has a buffer over-read in print-mptcp.c, several functions.

**diff da funcao (func_before vs func_after)**

```diff
--- func_before
+++ func_after
@@ -3,7 +3,7 @@
  {
          const struct mp_capable *mpc = (const struct mp_capable *) opt;
  
-        if (!(opt_len == 12 && flags & TH_SYN) &&
+        if (!(opt_len == 12 && (flags & TH_SYN)) &&
              !(opt_len == 20 && (flags & (TH_SYN | TH_ACK)) == TH_ACK))
                  return 0;
  
```

---

## 60. Android  |  CVE-2016-1621  |  CWE-119
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
@@ -1,41 +1,48 @@
 const BlockEntry* Segment::GetBlock(
-    const CuePoint& cp,
-    const CuePoint::TrackPosition& tp)
-{
-    Cluster** const ii = m_clusters;
-    Cluster** i = ii;
+  const long count = m_clusterCount + m_clusterPreloadCount;
  
-    const long count = m_clusterCount + m_clusterPreloadCount;
+  Cluster** const jj = ii + count;
+  Cluster** j = jj;
  
-    Cluster** const jj = ii + count;
-    Cluster** j = jj;
+  while (i < j) {
+    // INVARIANT:
+    //[ii, i) < pTP->m_pos
+    //[i, j) ?
+    //[j, jj)  > pTP->m_pos
  
-    while (i < j)
-    {
+    Cluster** const k = i + (j - i) / 2;
+    assert(k < jj);
  
-        Cluster** const k = i + (j - i) / 2;
-        assert(k < jj);
-        Cluster* const pCluster = *k;
-        assert(pCluster);
-        const long long pos = pCluster->GetPosition();
-        assert(pos >= 0);
-        if (pos < tp.m_pos)
-            i = k + 1;
-        else if (pos > tp.m_pos)
-            j = k;
-        else
-            return pCluster->GetEntry(cp, tp);
-    }
-    assert(i == j);
-    Cluster* const pCluster = Cluster::Create(this, -1, tp.m_pos); //, -1);
+    Cluster* const pCluster = *k;
      assert(pCluster);
  
-    const ptrdiff_t idx = i - m_clusters;
+    // const long long pos_ = pCluster->m_pos;
+    // assert(pos_);
+    // const long long pos = pos_ * ((pos_ < 0) ? -1 : 1);
  
-    PreloadCluster(pCluster, idx);
-    assert(m_clusters);
-    assert(m_clusterPreloadCount > 0);
-    assert(m_clusters[idx] == pCluster);
+    const long long pos = pCluster->GetPosition();
+    assert(pos >= 0);
  
-    return pCluster->GetEntry(cp, tp);
+    if (pos < tp.m_pos)
+      i = k + 1;
+    else if (pos > tp.m_pos)
+      j = k;
+    else
+      return pCluster->GetEntry(cp, tp);
+  }
+
+  assert(i == j);
+  // assert(Cluster::HasBlockEntries(this, tp.m_pos));
+
+  Cluster* const pCluster = Cluster::Create(this, -1, tp.m_pos);  //, -1);
+  assert(pCluster);
+
+  const ptrdiff_t idx = i - m_clusters;
+
+  PreloadCluster(pCluster, idx);
+  assert(m_clusters);
+  assert(m_clusterPreloadCount > 0);
+  assert(m_clusters[idx] == pCluster);
+
+  return pCluster->GetEntry(cp, tp);
  }
```
