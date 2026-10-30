# Pacote de anotacao — caso 43

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

# Evidencia do caso 43

## Identificacao

- projeto: Android
- CVE: CVE-2016-1621
- CWE atribuida pelo BigVul: CWE-119
- commit: `5a9753fca56f0eeb9f61e342b2fccffc364f9426`
- URL do commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- arquivo da funcao marcada: `libvpx/test/cpu_speed_test.cc`

## Mensagem do commit

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

## Resumo da CVE

> libvpx in mediaserver in Android 4.x before 4.4.4, 5.x before 5.1.1 LMY49H, and 6.0 before 2016-03-01 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted media file, related to libwebm/mkvparser.cpp and other files, aka internal bug 23452792.

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
   virtual void SetUp() {
     InitializeConfig();
    SetMode(GET_PARAM(1));
    set_cpu_used_ = GET_PARAM(2);
   }

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **808**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `armv7a-neon/libvpx_srcs.txt` |  |  |  |
| `armv7a-neon/vp8_rtcd.h` |  |  |  |
| `armv7a-neon/vp9_rtcd.h` |  |  |  |
| `armv7a-neon/vpx_config.c` |  |  |  |
| `armv7a-neon/vpx_config.h` |  |  |  |
| `armv7a-neon/vpx_dsp_rtcd.h` |  |  |  |
| `armv7a-neon/vpx_scale_rtcd.h` |  |  |  |
| `armv7a-neon/vpx_version.h` |  |  |  |
| `armv7a/libvpx_srcs.txt` |  |  |  |
| `armv7a/vp8_rtcd.h` |  |  |  |
| `armv7a/vp9_rtcd.h` |  |  |  |
| `armv7a/vpx_config.c` |  |  |  |
| `armv7a/vpx_config.h` |  |  |  |
| `armv7a/vpx_dsp_rtcd.h` |  |  |  |
| `armv7a/vpx_scale_rtcd.h` |  |  |  |
| `armv7a/vpx_version.h` |  |  |  |
| `generic/libvpx_srcs.txt` |  |  |  |
| `generic/vp8_rtcd.h` |  |  |  |
| `generic/vp9_rtcd.h` |  |  |  |
| `generic/vpx_config.c` |  |  |  |
| `generic/vpx_config.h` |  |  |  |
| `generic/vpx_dsp_rtcd.h` |  |  |  |
| `generic/vpx_scale_rtcd.h` |  |  |  |
| `generic/vpx_version.h` |  |  |  |
| `libvpx/.mailmap` |  |  |  |
| `libvpx/AUTHORS` |  |  |  |
| `libvpx/CHANGELOG` |  |  |  |
| `libvpx/PATENTS` |  |  |  |
| `libvpx/README` |  |  |  |
| `libvpx/args.c` |  |  |  |
| `libvpx/args.h` |  |  |  |
| `libvpx/build/make/Android.mk` |  |  |  |
| `libvpx/build/make/Makefile` |  |  |  |
| `libvpx/build/make/configure.sh` |  |  |  |
| `libvpx/build/make/gen_msvs_proj.sh` |  |  |  |
| `libvpx/build/make/gen_msvs_sln.sh` |  |  |  |
| `libvpx/build/make/gen_msvs_vcxproj.sh` |  |  |  |
| `libvpx/build/make/iosbuild.sh` |  |  |  |
| `libvpx/build/make/msvs_common.sh` |  |  |  |
| `libvpx/build/make/rtcd.pl` |  |  |  |
| `libvpx/build/make/version.sh` |  |  |  |
| `libvpx/codereview.settings` |  |  |  |
| `libvpx/configure` |  |  |  |
| `libvpx/docs.mk` |  |  |  |
| `libvpx/examples.mk` |  |  |  |
| `libvpx/examples/decode_to_md5.c` |  |  |  |
| `libvpx/examples/decode_with_drops.c` |  |  |  |
| `libvpx/examples/postproc.c` |  |  |  |
| `libvpx/examples/resize_util.c` |  |  |  |
| `libvpx/examples/set_maps.c` |  |  |  |
| `libvpx/examples/simple_decoder.c` |  |  |  |
| `libvpx/examples/simple_encoder.c` |  |  |  |
| `libvpx/examples/twopass_encoder.c` |  |  |  |
| `libvpx/examples/vp8_multi_resolution_encoder.c` |  |  |  |
| `libvpx/examples/vp8cx_set_ref.c` |  |  |  |
| `libvpx/examples/vp9_lossless_encoder.c` |  |  |  |
| `libvpx/examples/vp9_spatial_svc_encoder.c` |  |  |  |
| `libvpx/examples/vpx_temporal_svc_encoder.c` |  |  |  |
| `libvpx/libs.doxy_template` |  |  |  |
| `libvpx/libs.mk` |  |  |  |
| `libvpx/mainpage.dox` |  |  |  |
| `libvpx/md5_utils.c` |  |  |  |
| `libvpx/rate_hist.c` |  |  |  |
| `libvpx/solution.mk` |  |  |  |
| `libvpx/test/acm_random.h` |  |  |  |
| `libvpx/test/active_map_test.cc` |  |  |  |
| `libvpx/test/android/Android.mk` |  |  |  |
| `libvpx/test/android/README` |  |  |  |
| `libvpx/test/aq_segment_test.cc` |  |  |  |
| `libvpx/test/blockiness_test.cc` |  |  |  |
| `libvpx/test/borders_test.cc` |  |  |  |
| `libvpx/test/byte_alignment_test.cc` |  |  |  |
| `libvpx/test/codec_factory.h` |  |  |  |
| `libvpx/test/consistency_test.cc` |  |  |  |
| `libvpx/test/convolve_test.cc` |  |  |  |
| `libvpx/test/cpu_speed_test.cc` **(funcao marcada esta aqui)** |  |  |  |
| `libvpx/test/cq_test.cc` |  |  |  |
| `libvpx/test/datarate_test.cc` |  |  |  |
| `libvpx/test/dct16x16_test.cc` |  |  |  |
| `libvpx/test/dct32x32_test.cc` |  |  |  |
| `libvpx/test/decode_api_test.cc` |  |  |  |
| `libvpx/test/decode_perf_test.cc` |  |  |  |
| `libvpx/test/decode_test_driver.cc` |  |  |  |
| `libvpx/test/decode_test_driver.h` |  |  |  |
| `libvpx/test/decode_to_md5.sh` |  |  |  |
| `libvpx/test/decode_with_drops.sh` |  |  |  |
| `libvpx/test/encode_perf_test.cc` |  |  |  |
| `libvpx/test/encode_test_driver.cc` |  |  |  |
| `libvpx/test/encode_test_driver.h` |  |  |  |
| `libvpx/test/error_resilience_test.cc` |  |  |  |
| `libvpx/test/examples.sh` |  |  |  |
| `libvpx/test/external_frame_buffer_test.cc` |  |  |  |
| `libvpx/test/fdct4x4_test.cc` |  |  |  |
| `libvpx/test/fdct8x8_test.cc` |  |  |  |
| `libvpx/test/frame_size_tests.cc` |  |  |  |
| `libvpx/test/i420_video_source.h` |  |  |  |
| `libvpx/test/idct8x8_test.cc` |  |  |  |
| `libvpx/test/idct_test.cc` |  |  |  |
| `libvpx/test/intrapred_test.cc` |  |  |  |
| `libvpx/test/invalid_file_test.cc` |  |  |  |
| `libvpx/test/lpf_8_test.cc` |  |  |  |
| `libvpx/test/md5_helper.h` |  |  |  |
| `libvpx/test/partial_idct_test.cc` |  |  |  |
| `libvpx/test/postproc.sh` |  |  |  |
| `libvpx/test/pp_filter_test.cc` |  |  |  |
| `libvpx/test/quantize_test.cc` |  |  |  |
| `libvpx/test/register_state_check.h` |  |  |  |
| `libvpx/test/resize_test.cc` |  |  |  |
| `libvpx/test/resize_util.sh` |  |  |  |
| `libvpx/test/sad_test.cc` |  |  |  |
| `libvpx/test/set_maps.sh` |  |  |  |
| `libvpx/test/set_roi.cc` |  |  |  |
| `libvpx/test/simple_decoder.sh` |  |  |  |
| `libvpx/test/simple_encoder.sh` |  |  |  |
| `libvpx/test/sixtap_predict_test.cc` |  |  |  |
| `libvpx/test/superframe_test.cc` |  |  |  |
| `libvpx/test/svc_test.cc` |  |  |  |
| `libvpx/test/test-data.mk` |  |  |  |
| `libvpx/test/test-data.sha1` |  |  |  |
| `libvpx/test/test.mk` |  |  |  |
| `libvpx/test/test_intra_pred_speed.cc` |  |  |  |
| `libvpx/test/test_libvpx.cc` |  |  |  |
| `libvpx/test/test_vector_test.cc` |  |  |  |
| `libvpx/test/test_vectors.cc` |  |  |  |
| `libvpx/test/tile_independence_test.cc` |  |  |  |
| `libvpx/test/tools_common.sh` |  |  |  |
| `libvpx/test/twopass_encoder.sh` |  |  |  |
| `libvpx/test/user_priv_test.cc` |  |  |  |
| `libvpx/test/variance_test.cc` |  |  |  |
| `libvpx/test/video_source.h` |  |  |  |
| `libvpx/test/vp8_boolcoder_test.cc` |  |  |  |
| `libvpx/test/vp8_decrypt_test.cc` |  |  |  |
| `libvpx/test/vp8_denoiser_sse2_test.cc` |  |  |  |
| `libvpx/test/vp8_fdct4x4_test.cc` |  |  |  |
| `libvpx/test/vp8_fragments_test.cc` |  |  |  |
| `libvpx/test/vp8_multi_resolution_encoder.sh` |  |  |  |
| `libvpx/test/vp8cx_set_ref.sh` |  |  |  |
| `libvpx/test/vp9_arf_freq_test.cc` |  |  |  |
| `libvpx/test/vp9_avg_test.cc` |  |  |  |
| `libvpx/test/vp9_boolcoder_test.cc` |  |  |  |
| `libvpx/test/vp9_decrypt_test.cc` |  |  |  |
| `libvpx/test/vp9_denoiser_sse2_test.cc` |  |  |  |
| `libvpx/test/vp9_encoder_parms_get_to_decoder.cc` |  |  |  |
| `libvpx/test/vp9_end_to_end_test.cc` |  |  |  |
| `libvpx/test/vp9_error_block_test.cc` |  |  |  |
| `libvpx/test/vp9_ethread_test.cc` |  |  |  |
| `libvpx/test/vp9_frame_parallel_test.cc` |  |  |  |
| `libvpx/test/vp9_intrapred_test.cc` |  |  |  |
| `libvpx/test/vp9_lossless_test.cc` |  |  |  |
| `libvpx/test/vp9_quantize_test.cc` |  |  |  |
| `libvpx/test/vp9_skip_loopfilter_test.cc` |  |  |  |
| `libvpx/test/vp9_spatial_svc_encoder.sh` |  |  |  |
| `libvpx/test/vp9_subtract_test.cc` |  |  |  |
| `libvpx/test/vp9_thread_test.cc` |  |  |  |
| `libvpx/test/vpx_scale_test.cc` |  |  |  |
| `libvpx/test/vpx_temporal_svc_encoder.sh` |  |  |  |
| `libvpx/test/vpxdec.sh` |  |  |  |
| `libvpx/test/vpxenc.sh` |  |  |  |
| `libvpx/test/webm_video_source.h` |  |  |  |
| `libvpx/test/y4m_test.cc` |  |  |  |
| `libvpx/test/y4m_video_source.h` |  |  |  |
| `libvpx/test/yuv_video_source.h` |  |  |  |
| `libvpx/third_party/googletest/README.libvpx` |  |  |  |
| `libvpx/third_party/googletest/src/src/gtest-all.cc` |  |  |  |
| `libvpx/third_party/libwebm/Android.mk` |  |  |  |
| `libvpx/third_party/libwebm/PATENTS.TXT` |  |  |  |
| `libvpx/third_party/libwebm/README.libvpx` |  |  |  |
| `libvpx/third_party/libwebm/mkvmuxer.cpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvmuxer.hpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvmuxertypes.hpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvmuxerutil.cpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvmuxerutil.hpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvparser.cpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvparser.hpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvreader.cpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvreader.hpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvwriter.cpp` |  |  |  |
| `libvpx/third_party/libwebm/mkvwriter.hpp` |  |  |  |
| `libvpx/third_party/libwebm/webmids.hpp` |  |  |  |
| `libvpx/third_party/libyuv/README.libvpx` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/basic_types.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/compare.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/convert.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/convert_argb.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/convert_from.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/convert_from_argb.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/cpu_id.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/mjpeg_decoder.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/planar_functions.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/rotate.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/rotate_argb.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/rotate_row.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/row.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/scale.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/scale_argb.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/scale_row.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/version.h` |  |  |  |
| `libvpx/third_party/libyuv/include/libyuv/video_common.h` |  |  |  |
| `libvpx/third_party/libyuv/source/compare.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/compare_common.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/compare_gcc.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/compare_neon.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/compare_neon64.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/compare_win.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert_argb.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert_from.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert_from_argb.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert_jpeg.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert_to_argb.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/convert_to_i420.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/cpu_id.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/mjpeg_decoder.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/mjpeg_validate.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/planar_functions.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_any.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_argb.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_common.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_gcc.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_mips.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_neon.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_neon64.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/rotate_win.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_any.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_common.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_gcc.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_mips.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_neon.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_neon64.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_win.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/row_x86.asm` |  |  |  |
| `libvpx/third_party/libyuv/source/scale.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_any.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_argb.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_common.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_gcc.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_mips.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_neon.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_neon64.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/scale_win.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/video_common.cc` |  |  |  |
| `libvpx/third_party/libyuv/source/x86inc.asm` |  |  |  |
| `libvpx/third_party/x86inc/README.libvpx` |  |  |  |
| `libvpx/third_party/x86inc/x86inc.asm` |  |  |  |
| `libvpx/tools/ftfy.sh` |  |  |  |
| `libvpx/tools_common.c` |  |  |  |
| `libvpx/tools_common.h` |  |  |  |
| `libvpx/usage.dox` |  |  |  |
| `libvpx/usage_cx.dox` |  |  |  |
| `libvpx/vp8/common/alloccommon.c` |  |  |  |
| `libvpx/vp8/common/arm/armv6/dequant_idct_v6.asm` |  |  |  |
| `libvpx/vp8/common/arm/dequantize_arm.c` |  |  |  |
| `libvpx/vp8/common/arm/filter_arm.c` |  |  |  |
| `libvpx/vp8/common/arm/loopfilter_arm.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/bilinearpredict_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/dequantizeb_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/idct_dequant_0_2x_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/idct_dequant_full_2x_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/iwalsh_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/loopfiltersimplehorizontaledge_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/loopfiltersimpleverticaledge_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/mbloopfilter_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/reconintra_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/shortidct4x4llm_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/sixtappredict_neon.c` |  |  |  |
| `libvpx/vp8/common/arm/neon/vp8_loopfilter_neon.c` |  |  |  |
| `libvpx/vp8/common/blockd.h` |  |  |  |
| `libvpx/vp8/common/common.h` |  |  |  |
| `libvpx/vp8/common/copy_c.c` |  |  |  |
| `libvpx/vp8/common/debugmodes.c` |  |  |  |
| `libvpx/vp8/common/dequantize.c` |  |  |  |
| `libvpx/vp8/common/entropy.c` |  |  |  |
| `libvpx/vp8/common/entropymode.c` |  |  |  |
| `libvpx/vp8/common/extend.c` |  |  |  |
| `libvpx/vp8/common/filter.c` |  |  |  |
| `libvpx/vp8/common/generic/systemdependent.c` |  |  |  |
| `libvpx/vp8/common/idct_blk.c` |  |  |  |
| `libvpx/vp8/common/idctllm.c` |  |  |  |
| `libvpx/vp8/common/mfqe.c` |  |  |  |
| `libvpx/vp8/common/mips/dspr2/dequantize_dspr2.c` |  |  |  |
| `libvpx/vp8/common/mips/dspr2/vp8_loopfilter_filters_dspr2.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/bilinear_filter_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/copymem_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/idct_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/loopfilter_filters_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/mfqe_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/postproc_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/reconintra_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/sixtap_filter_msa.c` |  |  |  |
| `libvpx/vp8/common/mips/msa/vp8_macros_msa.h` |  |  |  |
| `libvpx/vp8/common/onyx.h` |  |  |  |
| `libvpx/vp8/common/postproc.c` |  |  |  |
| `libvpx/vp8/common/postproc.h` |  |  |  |
| `libvpx/vp8/common/reconinter.c` |  |  |  |
| `libvpx/vp8/common/reconintra.c` |  |  |  |
| `libvpx/vp8/common/rtcd.c` |  |  |  |
| `libvpx/vp8/common/rtcd_defs.pl` |  |  |  |
| `libvpx/vp8/common/setupintrarecon.c` |  |  |  |
| `libvpx/vp8/common/vp8_loopfilter.c` |  |  |  |
| `libvpx/vp8/common/x86/copy_sse2.asm` |  |  |  |
| `libvpx/vp8/common/x86/copy_sse3.asm` |  |  |  |
| `libvpx/vp8/common/x86/idct_blk_mmx.c` |  |  |  |
| `libvpx/vp8/common/x86/loopfilter_block_sse2_x86_64.asm` |  |  |  |
| `libvpx/vp8/common/x86/recon_sse2.asm` |  |  |  |
| `libvpx/vp8/common/x86/vp8_asm_stubs.c` |  |  |  |
| `libvpx/vp8/common/x86/vp8_loopfilter_mmx.asm` |  |  |  |
| `libvpx/vp8/decoder/dboolhuff.c` |  |  |  |
| `libvpx/vp8/decoder/dboolhuff.h` |  |  |  |
| `libvpx/vp8/decoder/decodeframe.c` |  |  |  |
| `libvpx/vp8/decoder/decodemv.c` |  |  |  |
| `libvpx/vp8/decoder/detokenize.c` |  |  |  |
| `libvpx/vp8/decoder/error_concealment.c` |  |  |  |
| `libvpx/vp8/decoder/onyxd_if.c` |  |  |  |
| `libvpx/vp8/decoder/onyxd_int.h` |  |  |  |
| `libvpx/vp8/decoder/threading.c` |  |  |  |
| `libvpx/vp8/encoder/arm/neon/denoising_neon.c` |  |  |  |
| `libvpx/vp8/encoder/arm/neon/fastquantizeb_neon.c` |  |  |  |
| `libvpx/vp8/encoder/arm/neon/shortfdct_neon.c` |  |  |  |
| `libvpx/vp8/encoder/arm/neon/vp8_shortwalsh4x4_neon.c` |  |  |  |
| `libvpx/vp8/encoder/bitstream.c` |  |  |  |
| `libvpx/vp8/encoder/bitstream.h` |  |  |  |
| `libvpx/vp8/encoder/block.h` |  |  |  |
| `libvpx/vp8/encoder/boolhuff.h` |  |  |  |
| `libvpx/vp8/encoder/dct.c` |  |  |  |
| `libvpx/vp8/encoder/denoising.c` |  |  |  |
| `libvpx/vp8/encoder/denoising.h` |  |  |  |
| `libvpx/vp8/encoder/encodeframe.c` |  |  |  |
| `libvpx/vp8/encoder/encodeintra.c` |  |  |  |
| `libvpx/vp8/encoder/encodemb.c` |  |  |  |
| `libvpx/vp8/encoder/encodemb.h` |  |  |  |
| `libvpx/vp8/encoder/ethreading.c` |  |  |  |
| `libvpx/vp8/encoder/firstpass.c` |  |  |  |
| `libvpx/vp8/encoder/mcomp.c` |  |  |  |
| `libvpx/vp8/encoder/mcomp.h` |  |  |  |
| `libvpx/vp8/encoder/mips/msa/dct_msa.c` |  |  |  |
| `libvpx/vp8/encoder/mips/msa/denoising_msa.c` |  |  |  |
| `libvpx/vp8/encoder/mips/msa/encodeopt_msa.c` |  |  |  |
| `libvpx/vp8/encoder/mips/msa/quantize_msa.c` |  |  |  |
| `libvpx/vp8/encoder/mips/msa/temporal_filter_msa.c` |  |  |  |
| `libvpx/vp8/encoder/modecosts.c` |  |  |  |
| `libvpx/vp8/encoder/modecosts.h` |  |  |  |
| `libvpx/vp8/encoder/mr_dissim.c` |  |  |  |
| `libvpx/vp8/encoder/onyx_if.c` |  |  |  |
| `libvpx/vp8/encoder/onyx_int.h` |  |  |  |
| `libvpx/vp8/encoder/pickinter.c` |  |  |  |
| `libvpx/vp8/encoder/picklpf.c` |  |  |  |
| `libvpx/vp8/encoder/quantize.h` |  |  |  |
| `libvpx/vp8/encoder/ratectrl.c` |  |  |  |
| `libvpx/vp8/encoder/ratectrl.h` |  |  |  |
| `libvpx/vp8/encoder/rdopt.c` |  |  |  |
| `libvpx/vp8/encoder/rdopt.h` |  |  |  |
| `libvpx/vp8/encoder/segmentation.c` |  |  |  |
| `libvpx/vp8/encoder/temporal_filter.c` |  |  |  |
| `libvpx/vp8/encoder/tokenize.c` |  |  |  |
| `libvpx/vp8/encoder/vp8_quantize.c` |  |  |  |
| `libvpx/vp8/encoder/x86/denoising_sse2.c` |  |  |  |
| `libvpx/vp8/encoder/x86/quantize_sse4.c` |  |  |  |
| `libvpx/vp8/encoder/x86/quantize_ssse3.c` |  |  |  |
| `libvpx/vp8/encoder/x86/vp8_enc_stubs_mmx.c` |  |  |  |
| `libvpx/vp8/encoder/x86/vp8_enc_stubs_sse2.c` |  |  |  |
| `libvpx/vp8/encoder/x86/vp8_quantize_sse2.c` |  |  |  |
| `libvpx/vp8/vp8_common.mk` |  |  |  |
| `libvpx/vp8/vp8_cx_iface.c` |  |  |  |
| `libvpx/vp8/vp8_dx_iface.c` |  |  |  |
| `libvpx/vp8/vp8cx.mk` |  |  |  |
| `libvpx/vp8/vp8cx_arm.mk` |  |  |  |
| `libvpx/vp9/common/arm/neon/vp9_iht4x4_add_neon.c` |  |  |  |
| `libvpx/vp9/common/arm/neon/vp9_iht8x8_add_neon.c` |  |  |  |
| `libvpx/vp9/common/mips/dspr2/vp9_itrans16_dspr2.c` |  |  |  |
| `libvpx/vp9/common/mips/dspr2/vp9_itrans4_dspr2.c` |  |  |  |
| `libvpx/vp9/common/mips/dspr2/vp9_itrans8_dspr2.c` |  |  |  |
| `libvpx/vp9/common/mips/msa/vp9_idct16x16_msa.c` |  |  |  |
| `libvpx/vp9/common/mips/msa/vp9_idct4x4_msa.c` |  |  |  |
| `libvpx/vp9/common/mips/msa/vp9_idct8x8_msa.c` |  |  |  |
| `libvpx/vp9/common/mips/msa/vp9_mfqe_msa.c` |  |  |  |
| `libvpx/vp9/common/vp9_alloccommon.c` |  |  |  |
| `libvpx/vp9/common/vp9_alloccommon.h` |  |  |  |
| `libvpx/vp9/common/vp9_blockd.c` |  |  |  |
| `libvpx/vp9/common/vp9_blockd.h` |  |  |  |
| `libvpx/vp9/common/vp9_common.h` |  |  |  |
| `libvpx/vp9/common/vp9_common_data.c` |  |  |  |
| `libvpx/vp9/common/vp9_common_data.h` |  |  |  |
| `libvpx/vp9/common/vp9_debugmodes.c` |  |  |  |
| `libvpx/vp9/common/vp9_entropy.c` |  |  |  |
| `libvpx/vp9/common/vp9_entropy.h` |  |  |  |
| `libvpx/vp9/common/vp9_entropymode.c` |  |  |  |
| `libvpx/vp9/common/vp9_entropymode.h` |  |  |  |
| `libvpx/vp9/common/vp9_entropymv.c` |  |  |  |
| `libvpx/vp9/common/vp9_entropymv.h` |  |  |  |
| `libvpx/vp9/common/vp9_enums.h` |  |  |  |
| `libvpx/vp9/common/vp9_filter.c` |  |  |  |
| `libvpx/vp9/common/vp9_filter.h` |  |  |  |
| `libvpx/vp9/common/vp9_frame_buffers.c` |  |  |  |
| `libvpx/vp9/common/vp9_idct.c` |  |  |  |
| `libvpx/vp9/common/vp9_idct.h` |  |  |  |
| `libvpx/vp9/common/vp9_loopfilter.c` |  |  |  |
| `libvpx/vp9/common/vp9_loopfilter.h` |  |  |  |
| `libvpx/vp9/common/vp9_mfqe.c` |  |  |  |
| `libvpx/vp9/common/vp9_mfqe.h` |  |  |  |
| `libvpx/vp9/common/vp9_mv.h` |  |  |  |
| `libvpx/vp9/common/vp9_mvref_common.c` |  |  |  |
| `libvpx/vp9/common/vp9_mvref_common.h` |  |  |  |
| `libvpx/vp9/common/vp9_onyxc_int.h` |  |  |  |
| `libvpx/vp9/common/vp9_postproc.c` |  |  |  |
| `libvpx/vp9/common/vp9_postproc.h` |  |  |  |
| `libvpx/vp9/common/vp9_ppflags.h` |  |  |  |
| `libvpx/vp9/common/vp9_pred_common.c` |  |  |  |
| `libvpx/vp9/common/vp9_pred_common.h` |  |  |  |
| `libvpx/vp9/common/vp9_quant_common.c` |  |  |  |
| `libvpx/vp9/common/vp9_quant_common.h` |  |  |  |
| `libvpx/vp9/common/vp9_reconinter.c` |  |  |  |
| `libvpx/vp9/common/vp9_reconinter.h` |  |  |  |
| `libvpx/vp9/common/vp9_reconintra.c` |  |  |  |
| `libvpx/vp9/common/vp9_reconintra.h` |  |  |  |
| `libvpx/vp9/common/vp9_rtcd.c` |  |  |  |
| `libvpx/vp9/common/vp9_rtcd_defs.pl` |  |  |  |
| `libvpx/vp9/common/vp9_scale.c` |  |  |  |
| `libvpx/vp9/common/vp9_scale.h` |  |  |  |
| `libvpx/vp9/common/vp9_scan.c` |  |  |  |
| `libvpx/vp9/common/vp9_scan.h` |  |  |  |
| `libvpx/vp9/common/vp9_seg_common.c` |  |  |  |
| `libvpx/vp9/common/vp9_seg_common.h` |  |  |  |
| `libvpx/vp9/common/vp9_thread_common.c` |  |  |  |
| `libvpx/vp9/common/vp9_thread_common.h` |  |  |  |
| `libvpx/vp9/common/vp9_tile_common.c` |  |  |  |
| `libvpx/vp9/common/vp9_tile_common.h` |  |  |  |
| `libvpx/vp9/common/x86/vp9_idct_intrin_sse2.c` |  |  |  |
| `libvpx/vp9/common/x86/vp9_mfqe_sse2.asm` |  |  |  |
| `libvpx/vp9/decoder/vp9_decodeframe.c` |  |  |  |
| `libvpx/vp9/decoder/vp9_decodeframe.h` |  |  |  |
| `libvpx/vp9/decoder/vp9_decodemv.c` |  |  |  |
| `libvpx/vp9/decoder/vp9_decodemv.h` |  |  |  |
| `libvpx/vp9/decoder/vp9_decoder.c` |  |  |  |
| `libvpx/vp9/decoder/vp9_decoder.h` |  |  |  |
| `libvpx/vp9/decoder/vp9_detokenize.c` |  |  |  |
| `libvpx/vp9/decoder/vp9_detokenize.h` |  |  |  |
| `libvpx/vp9/decoder/vp9_dsubexp.c` |  |  |  |
| `libvpx/vp9/decoder/vp9_dsubexp.h` |  |  |  |
| `libvpx/vp9/decoder/vp9_dthread.c` |  |  |  |
| `libvpx/vp9/decoder/vp9_dthread.h` |  |  |  |
| `libvpx/vp9/encoder/arm/neon/vp9_avg_neon.c` |  |  |  |
| `libvpx/vp9/encoder/arm/neon/vp9_dct_neon.c` |  |  |  |
| `libvpx/vp9/encoder/arm/neon/vp9_error_neon.c` |  |  |  |
| `libvpx/vp9/encoder/arm/neon/vp9_quantize_neon.c` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_avg_msa.c` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_error_msa.c` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_fdct16x16_msa.c` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_fdct4x4_msa.c` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_fdct8x8_msa.c` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_fdct_msa.h` |  |  |  |
| `libvpx/vp9/encoder/mips/msa/vp9_temporal_filter_msa.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_aq_complexity.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_aq_complexity.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_aq_cyclicrefresh.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_aq_cyclicrefresh.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_aq_variance.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_aq_variance.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_avg.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_bitstream.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_bitstream.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_block.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_blockiness.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_context_tree.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_context_tree.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_cost.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_cost.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_dct.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_denoiser.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_denoiser.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_encodeframe.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_encodeframe.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_encodemb.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_encodemb.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_encodemv.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_encodemv.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_encoder.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_encoder.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_ethread.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_ethread.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_extend.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_firstpass.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_firstpass.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_lookahead.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_lookahead.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_mbgraph.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_mbgraph.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_mcomp.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_mcomp.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_picklpf.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_picklpf.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_pickmode.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_pickmode.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_quantize.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_quantize.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_ratectrl.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_ratectrl.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_rd.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_rd.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_rdopt.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_rdopt.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_resize.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_resize.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_segmentation.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_segmentation.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_skin_detection.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_skin_detection.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_speed_features.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_speed_features.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_subexp.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_subexp.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_svc_layercontext.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_svc_layercontext.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_temporal_filter.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_temporal_filter.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_tokenize.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_tokenize.h` |  |  |  |
| `libvpx/vp9/encoder/vp9_treewriter.c` |  |  |  |
| `libvpx/vp9/encoder/vp9_treewriter.h` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_avg_intrin_sse2.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_dct_mmx.asm` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_dct_sse2.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_dct_ssse3.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_dct_ssse3_x86_64.asm` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_denoiser_sse2.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_error_intrin_avx2.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_error_sse2.asm` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_highbd_block_error_intrin_sse2.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_quantize_sse2.c` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_quantize_ssse3_x86_64.asm` |  |  |  |
| `libvpx/vp9/encoder/x86/vp9_temporal_filter_apply_sse2.asm` |  |  |  |
| `libvpx/vp9/vp9_common.mk` |  |  |  |
| `libvpx/vp9/vp9_cx_iface.c` |  |  |  |
| `libvpx/vp9/vp9_dx_iface.c` |  |  |  |
| `libvpx/vp9/vp9_iface_common.h` |  |  |  |
| `libvpx/vp9/vp9cx.mk` |  |  |  |
| `libvpx/vp9/vp9dx.mk` |  |  |  |
| `libvpx/vpx/exports_dec` |  |  |  |
| `libvpx/vpx/exports_enc` |  |  |  |
| `libvpx/vpx/internal/vpx_codec_internal.h` |  |  |  |
| `libvpx/vpx/src/svc_encodeframe.c` |  |  |  |
| `libvpx/vpx/src/vpx_codec.c` |  |  |  |
| `libvpx/vpx/src/vpx_decoder.c` |  |  |  |
| `libvpx/vpx/src/vpx_encoder.c` |  |  |  |
| `libvpx/vpx/src/vpx_image.c` |  |  |  |
| `libvpx/vpx/svc_context.h` |  |  |  |
| `libvpx/vpx/vp8cx.h` |  |  |  |
| `libvpx/vpx/vp8dx.h` |  |  |  |
| `libvpx/vpx/vpx_codec.h` |  |  |  |
| `libvpx/vpx/vpx_codec.mk` |  |  |  |
| `libvpx/vpx/vpx_decoder.h` |  |  |  |
| `libvpx/vpx/vpx_encoder.h` |  |  |  |
| `libvpx/vpx/vpx_frame_buffer.h` |  |  |  |
| `libvpx/vpx/vpx_image.h` |  |  |  |
| `libvpx/vpx/vpx_integer.h` |  |  |  |
| `libvpx/vpx_dsp/arm/bilinear_filter_media.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/fwd_txfm_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct16x16_1_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct16x16_1_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct16x16_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct16x16_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct16x16_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct32x32_1_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct32x32_1_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct32x32_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct32x32_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct4x4_1_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct4x4_1_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct4x4_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct4x4_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct8x8_1_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct8x8_1_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/idct8x8_add_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/idct8x8_add_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/intrapred_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/intrapred_neon_asm.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_16_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_16_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_4_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_4_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_8_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_8_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_mb_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/loopfilter_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/sad4d_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/sad_media.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/sad_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/save_reg_neon.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/subpel_variance_media.c` |  |  |  |
| `libvpx/vpx_dsp/arm/subpel_variance_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/subtract_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/variance_halfpixvar16x16_h_media.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/variance_halfpixvar16x16_hv_media.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/variance_halfpixvar16x16_v_media.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/variance_media.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/variance_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve8_avg_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve8_avg_neon_asm.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve8_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve8_neon_asm.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve_avg_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve_avg_neon_asm.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve_copy_neon.c` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve_copy_neon_asm.asm` |  |  |  |
| `libvpx/vpx_dsp/arm/vpx_convolve_neon.c` |  |  |  |
| `libvpx/vpx_dsp/bitreader.c` |  |  |  |
| `libvpx/vpx_dsp/bitreader.h` |  |  |  |
| `libvpx/vpx_dsp/bitreader_buffer.c` |  |  |  |
| `libvpx/vpx_dsp/bitreader_buffer.h` |  |  |  |
| `libvpx/vpx_dsp/bitwriter.c` |  |  |  |
| `libvpx/vpx_dsp/bitwriter.h` |  |  |  |
| `libvpx/vpx_dsp/bitwriter_buffer.c` |  |  |  |
| `libvpx/vpx_dsp/bitwriter_buffer.h` |  |  |  |
| `libvpx/vpx_dsp/fastssim.c` |  |  |  |
| `libvpx/vpx_dsp/fwd_txfm.c` |  |  |  |
| `libvpx/vpx_dsp/fwd_txfm.h` |  |  |  |
| `libvpx/vpx_dsp/intrapred.c` |  |  |  |
| `libvpx/vpx_dsp/inv_txfm.c` |  |  |  |
| `libvpx/vpx_dsp/inv_txfm.h` |  |  |  |
| `libvpx/vpx_dsp/loopfilter.c` |  |  |  |
| `libvpx/vpx_dsp/mips/common_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/common_dspr2.h` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve2_avg_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve2_avg_horiz_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve2_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve2_horiz_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve2_vert_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve8_avg_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve8_avg_horiz_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve8_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve8_horiz_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve8_vert_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/convolve_common_dspr2.h` |  |  |  |
| `libvpx/vpx_dsp/mips/fwd_dct32x32_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/fwd_txfm_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/fwd_txfm_msa.h` |  |  |  |
| `libvpx/vpx_dsp/mips/idct16x16_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/idct32x32_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/idct4x4_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/idct8x8_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/intrapred16_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/intrapred4_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/intrapred8_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/intrapred_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/inv_txfm_dspr2.h` |  |  |  |
| `libvpx/vpx_dsp/mips/inv_txfm_msa.h` |  |  |  |
| `libvpx/vpx_dsp/mips/itrans16_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/itrans32_cols_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/itrans32_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/itrans4_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/itrans8_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_16_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_4_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_8_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_filters_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_filters_dspr2.h` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_macros_dspr2.h` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_masks_dspr2.h` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_mb_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_mb_horiz_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_mb_vert_dspr2.c` |  |  |  |
| `libvpx/vpx_dsp/mips/loopfilter_msa.h` |  |  |  |
| `libvpx/vpx_dsp/mips/macros_msa.h` |  |  |  |
| `libvpx/vpx_dsp/mips/sad_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/sub_pixel_variance_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/subtract_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/txfm_macros_msa.h` |  |  |  |
| `libvpx/vpx_dsp/mips/variance_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve8_avg_horiz_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve8_avg_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve8_avg_vert_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve8_horiz_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve8_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve8_vert_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve_avg_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve_copy_msa.c` |  |  |  |
| `libvpx/vpx_dsp/mips/vpx_convolve_msa.h` |  |  |  |
| `libvpx/vpx_dsp/prob.c` |  |  |  |
| `libvpx/vpx_dsp/prob.h` |  |  |  |
| `libvpx/vpx_dsp/psnrhvs.c` |  |  |  |
| `libvpx/vpx_dsp/quantize.c` |  |  |  |
| `libvpx/vpx_dsp/quantize.h` |  |  |  |
| `libvpx/vpx_dsp/sad.c` |  |  |  |
| `libvpx/vpx_dsp/ssim.c` |  |  |  |
| `libvpx/vpx_dsp/ssim.h` |  |  |  |
| `libvpx/vpx_dsp/subtract.c` |  |  |  |
| `libvpx/vpx_dsp/txfm_common.h` |  |  |  |
| `libvpx/vpx_dsp/variance.c` |  |  |  |
| `libvpx/vpx_dsp/variance.h` |  |  |  |
| `libvpx/vpx_dsp/vpx_convolve.c` |  |  |  |
| `libvpx/vpx_dsp/vpx_convolve.h` |  |  |  |
| `libvpx/vpx_dsp/vpx_dsp.mk` |  |  |  |
| `libvpx/vpx_dsp/vpx_dsp_common.h` |  |  |  |
| `libvpx/vpx_dsp/vpx_dsp_rtcd.c` |  |  |  |
| `libvpx/vpx_dsp/vpx_dsp_rtcd_defs.pl` |  |  |  |
| `libvpx/vpx_dsp/vpx_filter.h` |  |  |  |
| `libvpx/vpx_dsp/x86/convolve.h` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_dct32x32_impl_avx2.h` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_dct32x32_impl_sse2.h` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_txfm_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_txfm_impl_sse2.h` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_txfm_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_txfm_sse2.h` |  |  |  |
| `libvpx/vpx_dsp/x86/fwd_txfm_ssse3_x86_64.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_intrapred_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_loopfilter_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_quantize_intrin_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_sad4d_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_sad_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_subpel_variance_impl_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_variance_impl_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/highbd_variance_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/intrapred_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/intrapred_ssse3.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/inv_txfm_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/inv_txfm_sse2.h` |  |  |  |
| `libvpx/vpx_dsp/x86/inv_txfm_ssse3_x86_64.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/inv_wht_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/loopfilter_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/loopfilter_mmx.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/loopfilter_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/quantize_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/quantize_ssse3_x86_64.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/sad4d_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/sad4d_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/sad_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/sad_mmx.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/sad_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/sad_sse3.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/sad_sse4.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/sad_ssse3.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/ssim_opt_x86_64.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/subpel_variance_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/subtract_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/txfm_common_sse2.h` |  |  |  |
| `libvpx/vpx_dsp/x86/variance_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/variance_impl_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/variance_impl_mmx.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/variance_mmx.c` |  |  |  |
| `libvpx/vpx_dsp/x86/variance_sse2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_asm_stubs.c` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_convolve_copy_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_high_subpixel_8t_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_high_subpixel_bilinear_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_subpixel_8t_intrin_avx2.c` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_subpixel_8t_intrin_ssse3.c` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_subpixel_8t_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_subpixel_8t_ssse3.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_subpixel_bilinear_sse2.asm` |  |  |  |
| `libvpx/vpx_dsp/x86/vpx_subpixel_bilinear_ssse3.asm` |  |  |  |
| `libvpx/vpx_mem/include/vpx_mem_intrnl.h` |  |  |  |
| `libvpx/vpx_mem/vpx_mem.c` |  |  |  |
| `libvpx/vpx_mem/vpx_mem.h` |  |  |  |
| `libvpx/vpx_mem/vpx_mem.mk` |  |  |  |
| `libvpx/vpx_ports/arm.h` |  |  |  |
| `libvpx/vpx_ports/arm_cpudetect.c` |  |  |  |
| `libvpx/vpx_ports/bitops.h` |  |  |  |
| `libvpx/vpx_ports/mem.h` |  |  |  |
| `libvpx/vpx_ports/mem_ops.h` |  |  |  |
| `libvpx/vpx_ports/mem_ops_aligned.h` |  |  |  |
| `libvpx/vpx_ports/msvc.h` |  |  |  |
| `libvpx/vpx_ports/system_state.h` |  |  |  |
| `libvpx/vpx_ports/vpx_once.h` |  |  |  |
| `libvpx/vpx_ports/vpx_ports.mk` |  |  |  |
| `libvpx/vpx_ports/vpx_timer.h` |  |  |  |
| `libvpx/vpx_ports/x86.h` |  |  |  |
| `libvpx/vpx_ports/x86_abi_support.asm` |  |  |  |
| `libvpx/vpx_scale/generic/gen_scalers.c` |  |  |  |
| `libvpx/vpx_scale/generic/vpx_scale.c` |  |  |  |
| `libvpx/vpx_scale/generic/yv12config.c` |  |  |  |
| `libvpx/vpx_scale/generic/yv12extend.c` |  |  |  |
| `libvpx/vpx_scale/mips/dspr2/yv12extend_dspr2.c` |  |  |  |
| `libvpx/vpx_scale/vpx_scale.mk` |  |  |  |
| `libvpx/vpx_scale/vpx_scale_rtcd.c` |  |  |  |
| `libvpx/vpx_scale/vpx_scale_rtcd.pl` |  |  |  |
| `libvpx/vpx_scale/yv12config.h` |  |  |  |
| `libvpx/vpx_util/endian_inl.h` |  |  |  |
| `libvpx/vpx_util/vpx_thread.c` |  |  |  |
| `libvpx/vpx_util/vpx_thread.h` |  |  |  |
| `libvpx/vpx_util/vpx_util.mk` |  |  |  |
| `libvpx/vpxdec.c` |  |  |  |
| `libvpx/vpxenc.c` |  |  |  |
| `libvpx/vpxenc.h` |  |  |  |
| `libvpx/vpxstats.c` |  |  |  |
| `libvpx/webmdec.cc` |  |  |  |
| `libvpx/webmdec.h` |  |  |  |
| `libvpx/webmenc.cc` |  |  |  |
| `libvpx/webmenc.h` |  |  |  |
| `libvpx/y4menc.c` |  |  |  |
| `libvpx/y4menc.h` |  |  |  |
| `libvpx/y4minput.c` |  |  |  |
| `libvpx/y4minput.h` |  |  |  |
| `mips-dspr2/libvpx_srcs.txt` |  |  |  |
| `mips-dspr2/vp8_rtcd.h` |  |  |  |
| `mips-dspr2/vp9_rtcd.h` |  |  |  |
| `mips-dspr2/vpx_config.c` |  |  |  |
| `mips-dspr2/vpx_config.h` |  |  |  |
| `mips-dspr2/vpx_dsp_rtcd.h` |  |  |  |
| `mips-dspr2/vpx_scale_rtcd.h` |  |  |  |
| `mips-dspr2/vpx_version.h` |  |  |  |
| `mips/libvpx_srcs.txt` |  |  |  |
| `mips/vp8_rtcd.h` |  |  |  |
| `mips/vp9_rtcd.h` |  |  |  |
| `mips/vpx_config.c` |  |  |  |
| `mips/vpx_config.h` |  |  |  |
| `mips/vpx_dsp_rtcd.h` |  |  |  |
| `mips/vpx_scale_rtcd.h` |  |  |  |
| `mips/vpx_version.h` |  |  |  |


### `libvpx/test/cpu_speed_test.cc`

```diff
@@ -7,45 +7,65 @@

  *  in the file PATENTS.  All contributing project authors may
  *  be found in the AUTHORS file in the root of the source tree.
  */
-#include <climits>
-#include <vector>
 #include "third_party/googletest/src/include/gtest/gtest.h"
 #include "test/codec_factory.h"
 #include "test/encode_test_driver.h"
 #include "test/i420_video_source.h"
 #include "test/util.h"
+#include "test/y4m_video_source.h"
 
 namespace {
 
-class CpuSpeedTest : public ::libvpx_test::EncoderTest,
-    public ::libvpx_test::CodecTestWith2Params<
-        libvpx_test::TestMode, int> {
+const int kMaxPSNR = 100;
+
+class CpuSpeedTest
+    : public ::libvpx_test::EncoderTest,
+      public ::libvpx_test::CodecTestWith2Params<libvpx_test::TestMode, int> {
  protected:
-  CpuSpeedTest() : EncoderTest(GET_PARAM(0)) {}
+  CpuSpeedTest()
+      : EncoderTest(GET_PARAM(0)),
+        encoding_mode_(GET_PARAM(1)),
+        set_cpu_used_(GET_PARAM(2)),
+        min_psnr_(kMaxPSNR) {}
   virtual ~CpuSpeedTest() {}
 
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
 
   virtual void PreEncodeFrameHook(::libvpx_test::VideoSource *video,
                                   ::libvpx_test::Encoder *encoder) {
     if (video->frame() == 1) {
       encoder->Control(VP8E_SET_CPUUSED, set_cpu_used_);
-      encoder->Control(VP8E_SET_ENABLEAUTOALTREF, 1);
-      encoder->Control(VP8E_SET_ARNR_MAXFRAMES, 7);
-      encoder->Control(VP8E_SET_ARNR_STRENGTH, 5);
-      encoder->Control(VP8E_SET_ARNR_TYPE, 3);
+      if (encoding_mode_ != ::libvpx_test::kRealTime) {
+        encoder->Control(VP8E_SET_ENABLEAUTOALTREF, 1);
+        encoder->Control(VP8E_SET_ARNR_MAXFRAMES, 7);
+        encoder->Control(VP8E_SET_ARNR_STRENGTH, 5);
+        encoder->Control(VP8E_SET_ARNR_TYPE, 3);
+      }
     }
   }
 
-  virtual void FramePktHook(const vpx_codec_cx_pkt_t *pkt) {
-    if (pkt->data.frame.flags & VPX_FRAME_IS_KEY) {
-    }
+  virtual void PSNRPktHook(const vpx_codec_cx_pkt_t *pkt) {
+    if (pkt->data.psnr.psnr[0] < min_psnr_)
+      min_psnr_ = pkt->data.psnr.psnr[0];
   }
+
+  ::libvpx_test::TestMode encoding_mode_;
   int set_cpu_used_;
+  double min_psnr_;
 };
 
 TEST_P(CpuSpeedTest, TestQ0) {
@@ -53,7 +73,6 @@

   // without a mismatch when passing in a very low max q.  This pushes
   // the encoder to producing lots of big partitions which will likely
   // extend into the border and test the border condition.
-  cfg_.g_lag_in_frames = 25;
   cfg_.rc_2pass_vbr_minsection_pct = 5;
   cfg_.rc_2pass_vbr_minsection_pct = 2000;
   cfg_.rc_target_bitrate = 400;
@@ -63,16 +82,32 @@

   ::libvpx_test::I420VideoSource video("hantro_odd.yuv", 208, 144, 30, 1, 0,
                                        20);
 
+  init_flags_ = VPX_CODEC_USE_PSNR;
+
   ASSERT_NO_FATAL_FAILURE(RunLoop(&video));
+  EXPECT_GE(min_psnr_, kMaxPSNR);
 }
 
+TEST_P(CpuSpeedTest, TestScreencastQ0) {
+  ::libvpx_test::Y4mVideoSource video("screendata.y4m", 0, 25);
+  cfg_.g_timebase = video.timebase();
+  cfg_.rc_2pass_vbr_minsection_pct = 5;
+  cfg_.rc_2pass_vbr_minsection_pct = 2000;
+  cfg_.rc_target_bitrate = 400;
+  cfg_.rc_max_quantizer = 0;
+  cfg_.rc_min_quantizer = 0;
+
+  init_flags_ = VPX_CODEC_USE_PSNR;
+
+  ASSERT_NO_FATAL_FAILURE(RunLoop(&video));
+  EXPECT_GE(min_psnr_, kMaxPSNR);
+}
 
 TEST_P(CpuSpeedTest, TestEncodeHighBitrate) {
   // Validate that this non multiple of 64 wide clip encodes and decodes
   // without a mismatch when passing in a very low max q.  This pushes
   // the encoder to producing lots of big partitions which will likely
   // extend into the border and test the border condition.
-  cfg_.g_lag_in_frames = 25;
   cfg_.rc_2pass_vbr_minsection_pct = 5;
   cfg_.rc_2pass_vbr_minsection_pct = 2000;
   cfg_.rc_target_bitrate = 12000;
@@ -84,12 +119,11 @@

 
   ASSERT_NO_FATAL_FAILURE(RunLoop(&video));
 }
+
 TEST_P(CpuSpeedTest, TestLowBitrate) {
   // Validate that this clip encodes and decodes without a mismatch
   // when passing in a very high min q.  This pushes the encoder to producing
   // lots of small partitions which might will test the other condition.
-
-  cfg_.g_lag_in_frames = 25;
   cfg_.rc_2pass_vbr_minsection_pct = 5;
   cfg_.rc_2pass_vbr_minsection_pct = 2000;
   cfg_.rc_target_bitrate = 200;
@@ -101,13 +135,14 @@

   ASSERT_NO_FATAL_FAILURE(RunLoop(&video));
 }
 
-using std::tr1::make_tuple;
-
-#define VP9_FACTORY \
-  static_cast<const libvpx_test::CodecFactory*> (&libvpx_test::kVP9)
-
 VP9_INSTANTIATE_TEST_CASE(
     CpuSpeedTest,
+    ::testing::Values(::libvpx_test::kTwoPassGood, ::libvpx_test::kOnePassGood,
+                      ::libvpx_test::kRealTime),
+    ::testing::Range(0, 9));
+
+VP10_INSTANTIATE_TEST_CASE(
+    CpuSpeedTest,
     ::testing::Values(::libvpx_test::kTwoPassGood, ::libvpx_test::kOnePassGood),
-    ::testing::Range(0, 8));
+    ::testing::Range(0, 3));
 }  // namespace

```


### `armv7a-neon/libvpx_srcs.txt`

```diff
@@ -1,6 +1,6 @@

+CHANGELOG
 build/make/rtcd.pl
 build/make/version.sh
-CHANGELOG
 libs.mk
 vp8/common/alloccommon.c
 vp8/common/alloccommon.h
@@ -19,49 +19,32 @@

 vp8/common/arm/armv6/loopfilter_v6.asm.s
 vp8/common/arm/armv6/simpleloopfilter_v6.asm.s
 vp8/common/arm/armv6/sixtappredict8x4_v6.asm.s
-vp8/common/arm/armv6/vp8_sad16x16_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance16x16_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance8x8_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance_halfpixvar16x16_h_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance_halfpixvar16x16_hv_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance_halfpixvar16x16_v_armv6.asm.s
 vp8/common/arm/bilinearfilter_arm.c
 vp8/common/arm/bilinearfilter_arm.h
 vp8/common/arm/dequantize_arm.c
 vp8/common/arm/filter_arm.c
 vp8/common/arm/loopfilter_arm.c
 vp8/common/arm/neon/bilinearpredict_neon.c
-vp8/common/arm/neon/buildintrapredictorsmby_neon.asm.s
 vp8/common/arm/neon/copymem_neon.c
 vp8/common/arm/neon/dc_only_idct_add_neon.c
 vp8/common/arm/neon/dequant_idct_neon.c
 vp8/common/arm/neon/dequantizeb_neon.c
 vp8/common/arm/neon/idct_blk_neon.c
-vp8/common/arm/neon/idct_dequant_0_2x_neon.asm.s
-vp8/common/arm/neon/idct_dequant_full_2x_neon.asm.s
-vp8/common/arm/neon/iwalsh_neon.asm.s
-vp8/common/arm/neon/loopfilter_neon.asm.s
-vp8/common/arm/neon/loopfiltersimplehorizontaledge_neon.asm.s
-vp8/common/arm/neon/loopfiltersimpleverticaledge_neon.asm.s
-vp8/common/arm/neon/mbloopfilter_neon.asm.s
-vp8/common/arm/neon/sad16_neon.asm.s
-vp8/common/arm/neon/sad8_neon.asm.s
-vp8/common/arm/neon/save_reg_neon.asm.s
-vp8/common/arm/neon/shortidct4x4llm_neon.asm.s
-vp8/common/arm/neon/sixtappredict16x16_neon.asm.s
-vp8/common/arm/neon/sixtappredict4x4_neon.asm.s
-vp8/common/arm/neon/sixtappredict8x4_neon.asm.s
-vp8/common/arm/neon/sixtappredict8x8_neon.asm.s
-vp8/common/arm/neon/variance_neon.asm.s
-vp8/common/arm/neon/vp8_subpixelvariance16x16_neon.asm.s
-vp8/common/arm/neon/vp8_subpixelvariance16x16s_neon.asm.s
-vp8/common/arm/neon/vp8_subpixelvariance8x8_neon.asm.s
-vp8/common/arm/reconintra_arm.c
-vp8/common/arm/variance_arm.c
+vp8/common/arm/neon/idct_dequant_0_2x_neon.c
+vp8/common/arm/neon/idct_dequant_full_2x_neon.c
+vp8/common/arm/neon/iwalsh_neon.c
+vp8/common/arm/neon/loopfiltersimplehorizontaledge_neon.c
+vp8/common/arm/neon/loopfiltersimpleverticaledge_neon.c
+vp8/common/arm/neon/mbloopfilter_neon.c
+vp8/common/arm/neon/reconintra_neon.c
+vp8/common/arm/neon/shortidct4x4llm_neon.c
+vp8/common/arm/neon/sixtappredict_neon.c
+vp8/common/arm/neon/vp8_loopfilter_neon.c
 vp8/common/blockd.c
 vp8/common/blockd.h
 vp8/common/coefupdateprobs.h
 vp8/common/common.h
+vp8/common/copy_c.c
 vp8/common/debugmodes.c
 vp8/common/default_coef_probs.h
 vp8/common/dequantize.c
@@ -82,28 +65,25 @@

 vp8/common/idct_blk.c
 vp8/common/idctllm.c
 vp8/common/invtrans.h
-vp8/common/loopfilter.c
-vp8/common/loopfilter_filters.c
 vp8/common/loopfilter.h
+vp8/common/loopfilter_filters.c
 vp8/common/mbpitch.c
 vp8/common/modecont.c
 vp8/common/modecont.h
 vp8/common/mv.h
+vp8/common/onyx.h
 vp8/common/onyxc_int.h
 vp8/common/onyxd.h
-vp8/common/onyx.h
 vp8/common/ppflags.h
-vp8/common/pragmas.h
 vp8/common/quant_common.c
 vp8/common/quant_common.h
 vp8/common/reconinter.c
 vp8/common/reconinter.h
+vp8/common/reconintra.c
 vp8/common/reconintra4x4.c
 vp8/common/reconintra4x4.h
-vp8/common/reconintra.c
 vp8/common/rtcd.c
 vp8/common/rtcd_defs.pl
-vp8/common/sad_c.c
 vp8/common/setupintrarecon.c
 vp8/common/setupintrarecon.h
 vp8/common/swapyv12buffer.c
@@ -112,9 +92,8 @@

 vp8/common/threading.h
 vp8/common/treecoder.c
 vp8/common/treecoder.h
-vp8/common/variance_c.c
-vp8/common/variance.h
 vp8/common/vp8_entropymodedata.h
+vp8/common/vp8_loopfilter.c
 vp8/decoder/dboolhuff.c
 vp8/decoder/dboolhuff.h
 vp8/decoder/decodeframe.c
@@ -127,29 +106,17 @@

 vp8/decoder/onyxd_int.h
 vp8/decoder/threading.c
 vp8/decoder/treereader.h
-vp8/encoder/arm/armv5te/boolhuff_armv5te.asm.s
-vp8/encoder/arm/armv5te/vp8_packtokens_armv5.asm.s
-vp8/encoder/arm/armv5te/vp8_packtokens_mbrow_armv5.asm.s
-vp8/encoder/arm/armv5te/vp8_packtokens_partitions_armv5.asm.s
-vp8/encoder/arm/armv6/vp8_fast_quantize_b_armv6.asm.s
-vp8/encoder/arm/armv6/vp8_mse16x16_armv6.asm.s
 vp8/encoder/arm/armv6/vp8_short_fdct4x4_armv6.asm.s
-vp8/encoder/arm/armv6/vp8_subtract_armv6.asm.s
 vp8/encoder/arm/armv6/walsh_v6.asm.s
-vp8/encoder/arm/boolhuff_arm.c
 vp8/encoder/arm/dct_arm.c
 vp8/encoder/arm/neon/denoising_neon.c
-vp8/encoder/arm/neon/fastquantizeb_neon.asm.s
-vp8/encoder/arm/neon/picklpf_arm.c
-vp8/encoder/arm/neon/shortfdct_neon.asm.s
-vp8/encoder/arm/neon/subtract_neon.asm.s
-vp8/encoder/arm/neon/vp8_memcpy_neon.asm.s
-vp8/encoder/arm/neon/vp8_mse16x16_neon.asm.s
-vp8/encoder/arm/neon/vp8_shortwalsh4x4_neon.asm.s
-vp8/encoder/arm/quantize_arm.c
+vp8/encoder/arm/neon/fastquantizeb_neon.c
+vp8/encoder/arm/neon/shortfdct_neon.c
+vp8/encoder/arm/neon/vp8_shortwalsh4x4_neon.c
 vp8/encoder/bitstream.c
 vp8/encoder/bitstream.h
 vp8/encoder/block.h
+vp8/encoder/boolhuff.c
 vp8/encoder/boolhuff.h
 vp8/encoder/dct.c
 vp8/encoder/dct_value_cost.h
@@ -178,7 +145,6 @@

 vp8/encoder/pickinter.c
 vp8/encoder/pickinter.h
 vp8/encoder/picklpf.c
-vp8/encoder/quantize.c
 vp8/encoder/quantize.h
 vp8/encoder/ratectrl.c
 vp8/encoder/ratectrl.h
@@ -190,45 +156,22 @@

 vp8/encoder/tokenize.h
 vp8/encoder/treewriter.c
 vp8/encoder/treewriter.h
-vp8/encoder/vp8_asm_enc_offsets.c
+vp8/encoder/vp8_quantize.c
 vp8/vp8_common.mk
-vp8/vp8cx_arm.mk
 vp8/vp8_cx_iface.c
-vp8/vp8cx.mk
 vp8/vp8_dx_iface.c
+vp8/vp8cx.mk
+vp8/vp8cx_arm.mk
 vp8/vp8dx.mk
-vp9/common/arm/neon/vp9_avg_neon.asm.s
-vp9/common/arm/neon/vp9_convolve8_avg_neon.asm.s
-vp9/common/arm/neon/vp9_convolve8_neon.asm.s
-vp9/common/arm/neon/vp9_convolve_neon.c
-vp9/common/arm/neon/vp9_copy_neon.asm.s
-vp9/common/arm/neon/vp9_dc_only_idct_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct16x16_1_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct16x16_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct16x16_neon.c
-vp9/common/arm/neon/vp9_idct32x32_1_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct32x32_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct4x4_1_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct4x4_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct8x8_1_add_neon.asm.s
-vp9/common/arm/neon/vp9_idct8x8_add_neon.asm.s
-vp9/common/arm/neon/vp9_iht4x4_add_neon.asm.s
-vp9/common/arm/neon/vp9_iht8x8_add_neon.asm.s
-vp9/common/arm/neon/vp9_loopfilter_16_neon.asm.s
-vp9/common/arm/neon/vp9_loopfilter_16_neon.c
-vp9/common/arm/neon/vp9_loopfilter_neon.asm.s
-vp9/common/arm/neon/vp9_mb_lpf_neon.asm.s
-vp9/common/arm/neon/vp9_reconintra_neon.asm.s
-vp9/common/arm/neon/vp9_save_reg_neon.asm.s
+vp9/common/arm/neon/vp9_iht4x4_add_neon.c
+vp9/common/arm/neon/vp9_iht8x8_add_neon.c
 vp9/common/vp9_alloccommon.c
 vp9/common/vp9_alloccommon.h
 vp9/common/vp9_blockd.c
 vp9/common/vp9_blockd.h
+vp9/common/vp9_common.h
 vp9/common/vp9_common_data.c
 vp9/common/vp9_common_data.h
-vp9/common/vp9_common.h
-vp9/common/vp9_convolve.c
-vp9/common/vp9_convolve.h
 vp9/common/vp9_debugmodes.c
 vp9/common/vp9_entropy.c
 vp9/common/vp9_entropy.h
@@ -244,18 +187,14 @@

 vp9/common/vp9_idct.c
 vp9/common/vp9_idct.h
 vp9/common/vp9_loopfilter.c
-vp9/common/vp9_loopfilter_filters.c
 vp9/common/vp9_loopfilter.h
 vp9/common/vp9_mv.h
 vp9/common/vp9_mvref_common.c
 vp9/common/vp9_mvref_common.h
 vp9/common/vp9_onyxc_int.h
 vp9/common/vp9_ppflags.h
-vp9/common/vp9_pragmas.h
 vp9/common/vp9_pred_common.c
 vp9/common/vp9_pred_common.h
-vp9/common/vp9_prob.c
-vp9/common/vp9_prob.h
 vp9/common/vp9_quant_common.c
 vp9/common/vp9_quant_common.h
 vp9/common/vp9_reconinter.c
@@ -270,8 +209,9 @@

 vp9/common/vp9_scan.h
 vp9/common/vp9_seg_common.c
 vp9/common/vp9_seg_common.h
-vp9/common/vp9_systemdependent.h
 vp9/common/vp9_textblit.h
+vp9/common/vp9_thread_common.c
+vp9/common/vp9_thread_common.h
 vp9/common/vp9_tile_common.c
 vp9/common/vp9_tile_common.h
 vp9/decoder/vp9_decodeframe.c
@@ -286,21 +226,22 @@

 vp9/decoder/vp9_dsubexp.h
 vp9/decoder/vp9_dthread.c
 vp9/decoder/vp9_dthread.h
-vp9/decoder/vp9_read_bit_buffer.c
-vp9/decoder/vp9_read_bit_buffer.h
-vp9/decoder/vp9_reader.c
-vp9/decoder/vp9_reader.h
-vp9/decoder/vp9_thread.c
-vp9/decoder/vp9_thread.h
+vp9/encoder/arm/neon/vp9_avg_neon.c
+vp9/encoder/arm/neon/vp9_dct_neon.c
+vp9/encoder/arm/neon/vp9_error_neon.c
+vp9/encoder/arm/neon/vp9_quantize_neon.c
 vp9/encoder/vp9_aq_complexity.c
 vp9/encoder/vp9_aq_complexity.h
 vp9/encoder/vp9_aq_cyclicrefresh.c
 vp9/encoder/vp9_aq_cyclicrefresh.h
 vp9/encoder/vp9_aq_variance.c
 vp9/encoder/vp9_aq_variance.h
+vp9/encoder/vp9_avg.c
 vp9/encoder/vp9_bitstream.c
 vp9/encoder/vp9_bitstream.h
 vp9/encoder/vp9_block.h
+vp9/encoder/vp9_context_tree.c
+vp9/encoder/vp9_context_tree.h
 vp9/encoder/vp9_cost.c
 vp9/encoder/vp9_cost.h
 vp9/encoder/vp9_dct.c
@@ -310,6 +251,10 @@

 vp9/encoder/vp9_encodemb.h
 vp9/encoder/vp9_encodemv.c
 vp9/encoder/vp9_encodemv.h
+vp9/encoder/vp9_encoder.c
+vp9/encoder/vp9_encoder.h
+vp9/encoder/vp9_ethread.c
+vp9/encoder/vp9_ethread.h
 vp9/encoder/vp9_extend.c
 vp9/encoder/vp9_extend.h
 vp9/encoder/vp9_firstpass.c
@@ -320,8 +265,6 @@

 vp9/encoder/vp9_mbgraph.h
 vp9/encoder/vp9_mcomp.c
 vp9/encoder/vp9_mcomp.h
-vp9/encoder/vp9_onyx_if.c
-vp9/encoder/vp9_onyx_int.h
 vp9/encoder/vp9_picklpf.c
 vp9/encoder/vp9_picklpf.h
 vp9/encoder/vp9_pickmode.c
@@ -330,13 +273,16 @@

 vp9/encoder/vp9_quantize.h
 vp9/encoder/vp9_ratectrl.c
 vp9/encoder/vp9_ratectrl.h
+vp9/encoder/vp9_rd.c
+vp9/encoder/vp9_rd.h
 vp9/encoder/vp9_rdopt.c
 vp9/encoder/vp9_rdopt.h
 vp9/encoder/vp9_resize.c
 vp9/encoder/vp9_resize.h
-vp9/encoder/vp9_sad.c
 vp9/encoder/vp9_segmentation.c
 vp9/encoder/vp9_segmentation.h
+vp9/encoder/vp9_skin_detection.c
+vp9/encoder/vp9_skin_detection.h
 vp9/encoder/vp9_speed_features.c
 vp9/encoder/vp9_speed_features.h
 vp9/encoder/vp9_subexp.c
@@ -349,59 +295,22 @@

 vp9/encoder/vp9_tokenize.h
 vp9/encoder/vp9_treewriter.c
 vp9/encoder/vp9_treewriter.h
-vp9/encoder/vp9_variance.c
-vp9/encoder/vp9_variance.h
-vp9/encoder/vp9_write_bit_buffer.c
-vp9/encoder/vp9_write_bit_buffer.h
-vp9/encoder/vp9_writer.c
-vp9/encoder/vp9_writer.h
 vp9/vp9_common.mk
 vp9/vp9_cx_iface.c
-vp9/vp9cx.mk
 vp9/vp9_dx_iface.c
-vp9/vp9dx.mk
 vp9/vp9_iface_common.h
-vpx_config.c
+vp9/vp9cx.mk
+vp9/vp9dx.mk
 vpx/internal/vpx_codec_internal.h
 vpx/internal/vpx_psnr.h
-vpx_mem/include/vpx_mem_intrnl.h
-vpx_mem/vpx_mem.c
-vpx_mem/vpx_mem.h
-vpx_mem/vpx_mem.mk
-vpx_ports/arm_cpudetect.c
-vpx_ports/arm.h
-vpx_ports/asm_offsets.h
-vpx_ports/emmintrin_compat.h
-vpx_ports/mem.h
-vpx_ports/mem_ops_aligned.h
-vpx_ports/mem_ops.h
-vpx_ports/vpx_once.h
-vpx_ports/vpx_ports.mk
-vpx_ports/vpx_timer.h
-vpx_scale/arm/neon/vp8_vpxyv12_copyframe_func_neon.asm.s
-vpx_scale/arm/neon/vp8_vpxyv12_copysrcframe_func_neon.asm.s
-vpx_scale/arm/neon/vp8_vpxyv12_extendframeborders_neon.asm.s
-vpx_scale/arm/neon/yv12extend_arm.c
-vpx_scale/generic/gen_scalers.c
-vpx_scale/generic/vpx_scale.c
-vpx_scale/generic/yv12config.c
-vpx_scale/generic/yv12extend.c
-vpx_scale/vpx_scale_asm_offsets.c
-vpx_scale/vpx_scale.h
-vpx_scale/vpx_scale.mk
-vpx_scale/vpx_scale_rtcd.c
-vpx_scale/vpx_scale_rtcd.pl
-vpx_scale/yv12config.h
-vpx/src/svc_encodeframe.c
 vpx/src/vpx_codec.c
 vpx/src/vpx_decoder.c
 vpx/src/vpx_encoder.c
 vpx/src/vpx_image.c
 vpx/src/vpx_psnr.c
-vpx/svc_context.h
+vpx/vp8.h
 vpx/vp8cx.h
 vpx/vp8dx.h
-vpx/vp8.h
 vpx/vpx_codec.h
 vpx/vpx_codec.mk
 vpx/vpx_decoder.h
@@ -409,3 +318,98 @@

 vpx/vpx_frame_buffer.h
 vpx/vpx_image.h
 vpx/vpx_integer.h
+vpx_config.c
+vpx_dsp/arm/bilinear_filter_media.asm.s
+vpx_dsp/arm/fwd_txfm_neon.c
+vpx_dsp/arm/idct16x16_1_add_neon.asm.s
+vpx_dsp/arm/idct16x16_add_neon.asm.s
+vpx_dsp/arm/idct16x16_neon.c
+vpx_dsp/arm/idct32x32_1_add_neon.asm.s
+vpx_dsp/arm/idct32x32_add_neon.asm.s
+vpx_dsp/arm/idct4x4_1_add_neon.asm.s
+vpx_dsp/arm/idct4x4_add_neon.asm.s
+vpx_dsp/arm/idct8x8_1_add_neon.asm.s
+vpx_dsp/arm/idct8x8_add_neon.asm.s
+vpx_dsp/arm/intrapred_neon.c
+vpx_dsp/arm/intrapred_neon_asm.asm.s
+vpx_dsp/arm/loopfilter_16_neon.asm.s
+vpx_dsp/arm/loopfilter_4_neon.asm.s
+vpx_dsp/arm/loopfilter_8_neon.asm.s
+vpx_dsp/arm/loopfilter_mb_neon.asm.s
+vpx_dsp/arm/loopfilter_neon.c
+vpx_dsp/arm/sad4d_neon.c
+vpx_dsp/arm/sad_media.asm.s
+vpx_dsp/arm/sad_neon.c
+vpx_dsp/arm/save_reg_neon.asm.s
+vpx_dsp/arm/subpel_variance_media.c
+vpx_dsp/arm/subpel_variance_neon.c
+vpx_dsp/arm/subtract_neon.c
+vpx_dsp/arm/variance_halfpixvar16x16_h_media.asm.s
+vpx_dsp/arm/variance_halfpixvar16x16_hv_media.asm.s
+vpx_dsp/arm/variance_halfpixvar16x16_v_media.asm.s
+vpx_dsp/arm/variance_media.asm.s
+vpx_dsp/arm/variance_neon.c
+vpx_dsp/arm/vpx_convolve8_avg_neon_asm.asm.s
+vpx_dsp/arm/vpx_convolve8_neon_asm.asm.s
+vpx_dsp/arm/vpx_convolve_avg_neon_asm.asm.s
+vpx_dsp/arm/vpx_convolve_copy_neon_asm.asm.s
+vpx_dsp/arm/vpx_convolve_neon.c
+vpx_dsp/bitreader.c
+vpx_dsp/bitreader.h
+vpx_dsp/bitreader_buffer.c
+vpx_dsp/bitreader_buffer.h
+vpx_dsp/bitwriter.c
+vpx_dsp/bitwriter.h
+vpx_dsp/bitwriter_buffer.c
+vpx_dsp/bitwriter_buffer.h
+vpx_dsp/fwd_txfm.c
+vpx_dsp/fwd_txfm.h
+vpx_dsp/intrapred.c
+vpx_dsp/inv_txfm.c
+vpx_dsp/inv_txfm.h
+vpx_dsp/loopfilter.c
+vpx_dsp/prob.c
+vpx_dsp/prob.h
+vpx_dsp/quantize.c
+vpx_dsp/quantize.h
+vpx_dsp/sad.c
+vpx_dsp/subtract.c
+vpx_dsp/txfm_common.h
+vpx_dsp/variance.c
+vpx_dsp/variance.h
+vpx_dsp/vpx_convolve.c
+vpx_dsp/vpx_convolve.h
+vpx_dsp/vpx_dsp.mk
+vpx_dsp/vpx_dsp_common.h
+vpx_dsp/vpx_dsp_rtcd.c
+vpx_dsp/vpx_dsp_rtcd_defs.pl
+vpx_dsp/vpx_filter.h
+vpx_mem/include/vpx_mem_intrnl.h
+vpx_mem/vpx_mem.c
+vpx_mem/vpx_mem.h
+vpx_mem/vpx_mem.mk
+vpx_ports/arm.h
+vpx_ports/arm_cpudetect.c
+vpx_ports/bitops.h
+vpx_ports/emmintrin_compat.h
+vpx_ports/mem.h
+vpx_ports/mem_ops.h
+vpx_ports/mem_ops_aligned.h
+vpx_ports/msvc.h
+vpx_ports/system_state.h
+vpx_ports/vpx_once.h
+vpx_ports/vpx_ports.mk
+vpx_ports/vpx_timer.h
+vpx_scale/generic/gen_scalers.c
+vpx_scale/generic/vpx_scale.c
+vpx_scale/generic/yv12config.c
+vpx_scale/generic/yv12extend.c
+vpx_scale/vpx_scale.h
+vpx_scale/vpx_scale.mk
+vpx_scale/vpx_scale_rtcd.c
+vpx_scale/vpx_scale_rtcd.pl
+vpx_scale/yv12config.h
+vpx_util/endian_inl.h
+vpx_util/vpx_thread.c
+vpx_util/vpx_thread.h
+vpx_util/vpx_util.mk

```


### `armv7a-neon/vp8_rtcd.h`

```diff
@@ -7,10 +7,6 @@

 #define RTCD_EXTERN extern
 #endif
 
-#ifdef __cplusplus
-extern "C" {
-#endif
-
 /*
  * VP8
  */
@@ -26,6 +22,10 @@

 union int_mv;
 struct yv12_buffer_config;
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 void vp8_bilinear_predict16x16_c(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 void vp8_bilinear_predict16x16_armv6(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 void vp8_bilinear_predict16x16_neon(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
@@ -49,10 +49,12 @@

 #define vp8_block_error vp8_block_error_c
 
 void vp8_build_intra_predictors_mbuv_s_c(struct macroblockd *x, unsigned char * uabove_row, unsigned char * vabove_row,  unsigned char *uleft, unsigned char *vleft, int left_stride, unsigned char * upred_ptr, unsigned char * vpred_ptr, int pred_stride);
-#define vp8_build_intra_predictors_mbuv_s vp8_build_intra_predictors_mbuv_s_c
+void vp8_build_intra_predictors_mbuv_s_neon(struct macroblockd *x, unsigned char * uabove_row, unsigned char * vabove_row,  unsigned char *uleft, unsigned char *vleft, int left_stride, unsigned char * upred_ptr, unsigned char * vpred_ptr, int pred_stride);
+#define vp8_build_intra_predictors_mbuv_s vp8_build_intra_predictors_mbuv_s_neon
 
 void vp8_build_intra_predictors_mby_s_c(struct macroblockd *x, unsigned char * yabove_row, unsigned char * yleft, int left_stride, unsigned char * ypred_ptr, int y_stride);
-#define vp8_build_intra_predictors_mby_s vp8_build_intra_predictors_mby_s_c
+void vp8_build_intra_predictors_mby_s_neon(struct macroblockd *x, unsigned char * yabove_row, unsigned char * yleft, int left_stride, unsigned char * ypred_ptr, int y_stride);
+#define vp8_build_intra_predictors_mby_s vp8_build_intra_predictors_mby_s_neon
 
 void vp8_clear_system_state_c();
 #define vp8_clear_system_state vp8_clear_system_state_c
@@ -77,10 +79,14 @@

 void vp8_dc_only_idct_add_neon(short input, unsigned char *pred, int pred_stride, unsigned char *dst, int dst_stride);
 #define vp8_dc_only_idct_add vp8_dc_only_idct_add_neon
 
-int vp8_denoiser_filter_c(struct yv12_buffer_config* mc_running_avg, struct yv12_buffer_config* running_avg, struct macroblock* signal, unsigned int motion_magnitude2, int y_offset, int uv_offset);
-int vp8_denoiser_filter_neon(struct yv12_buffer_config* mc_running_avg, struct yv12_buffer_config* running_avg, struct macroblock* signal, unsigned int motion_magnitude2, int y_offset, int uv_offset);
+int vp8_denoiser_filter_c(unsigned char *mc_running_avg_y, int mc_avg_y_stride, unsigned char *running_avg_y, int avg_y_stride, unsigned char *sig, int sig_stride, unsigned int motion_magnitude, int increase_denoising);
+int vp8_denoiser_filter_neon(unsigned char *mc_running_avg_y, int mc_avg_y_stride, unsigned char *running_avg_y, int avg_y_stride, unsigned char *sig, int sig_stride, unsigned int motion_magnitude, int increase_denoising);
 #define vp8_denoiser_filter vp8_denoiser_filter_neon
 
+int vp8_denoiser_filter_uv_c(unsigned char *mc_running_avg, int mc_avg_stride, unsigned char *running_avg, int avg_stride, unsigned char *sig, int sig_stride, unsigned int motion_magnitude, int increase_denoising);
+int vp8_denoiser_filter_uv_neon(unsigned char *mc_running_avg, int mc_avg_stride, unsigned char *running_avg, int avg_stride, unsigned char *sig, int sig_stride, unsigned int motion_magnitude, int increase_denoising);
+#define vp8_denoiser_filter_uv vp8_denoiser_filter_uv_neon
+
 void vp8_dequant_idct_add_c(short *input, short *dq, unsigned char *output, int stride);
 void vp8_dequant_idct_add_v6(short *input, short *dq, unsigned char *output, int stride);
 void vp8_dequant_idct_add_neon(short *input, short *dq, unsigned char *output, int stride);
@@ -105,24 +111,12 @@

 #define vp8_diamond_search_sad vp8_diamond_search_sad_c
 
 void vp8_fast_quantize_b_c(struct block *, struct blockd *);
-void vp8_fast_quantize_b_armv6(struct block *, struct blockd *);
 void vp8_fast_quantize_b_neon(struct block *, struct blockd *);
 #define vp8_fast_quantize_b vp8_fast_quantize_b_neon
 
-void vp8_fast_quantize_b_pair_c(struct block *b1, struct block *b2, struct blockd *d1, struct blockd *d2);
-void vp8_fast_quantize_b_pair_neon(struct block *b1, struct block *b2, struct blockd *d1, struct blockd *d2);
-#define vp8_fast_quantize_b_pair vp8_fast_quantize_b_pair_neon
-
 int vp8_full_search_sad_c(struct macroblock *x, struct block *b, struct blockd *d, union int_mv *ref_mv, int sad_per_bit, int distance, struct variance_vtable *fn_ptr, int *mvcost[2], union int_mv *center_mv);
 #define vp8_full_search_sad vp8_full_search_sad_c
 
-unsigned int vp8_get4x4sse_cs_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride);
-unsigned int vp8_get4x4sse_cs_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride);
-#define vp8_get4x4sse_cs vp8_get4x4sse_cs_neon
-
-unsigned int vp8_get_mb_ss_c(const short *);
-#define vp8_get_mb_ss vp8_get_mb_ss_c
-
 void vp8_intra4x4_predict_c(unsigned char *Above, unsigned char *yleft, int left_stride, int b_mode, unsigned char *dst, int dst_stride, unsigned char top_left);
 void vp8_intra4x4_predict_armv6(unsigned char *Above, unsigned char *yleft, int left_stride, int b_mode, unsigned char *dst, int dst_stride, unsigned char top_left);
 #define vp8_intra4x4_predict vp8_intra4x4_predict_armv6
@@ -173,98 +167,12 @@

 int vp8_mbuverror_c(struct macroblock *mb);
 #define vp8_mbuverror vp8_mbuverror_c
 
-unsigned int vp8_mse16x16_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_mse16x16_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_mse16x16_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_mse16x16 vp8_mse16x16_neon
-
-void vp8_quantize_mb_c(struct macroblock *);
-void vp8_quantize_mb_neon(struct macroblock *);
-#define vp8_quantize_mb vp8_quantize_mb_neon
-
-void vp8_quantize_mbuv_c(struct macroblock *);
-void vp8_quantize_mbuv_neon(struct macroblock *);
-#define vp8_quantize_mbuv vp8_quantize_mbuv_neon
-
-void vp8_quantize_mby_c(struct macroblock *);
-void vp8_quantize_mby_neon(struct macroblock *);
-#define vp8_quantize_mby vp8_quantize_mby_neon
-
 int vp8_refining_search_sad_c(struct macroblock *x, struct block *b, struct blockd *d, union int_mv *ref_mv, int sad_per_bit, int distance, struct variance_vtable *fn_ptr, int *mvcost[2], union int_mv *center_mv);
 #define vp8_refining_search_sad vp8_refining_search_sad_c
 
 void vp8_regular_quantize_b_c(struct block *, struct blockd *);
 #define vp8_regular_quantize_b vp8_regular_quantize_b_c
 
-void vp8_regular_quantize_b_pair_c(struct block *b1, struct block *b2, struct blockd *d1, struct blockd *d2);
-#define vp8_regular_quantize_b_pair vp8_regular_quantize_b_pair_c
-
-unsigned int vp8_sad16x16_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad16x16_armv6(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad16x16_neon(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad16x16 vp8_sad16x16_neon
-
-void vp8_sad16x16x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x16x3 vp8_sad16x16x3_c
-
-void vp8_sad16x16x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x16x4d vp8_sad16x16x4d_c
-
-void vp8_sad16x16x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad16x16x8 vp8_sad16x16x8_c
-
-unsigned int vp8_sad16x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad16x8_neon(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad16x8 vp8_sad16x8_neon
-
-void vp8_sad16x8x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x8x3 vp8_sad16x8x3_c
-
-void vp8_sad16x8x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x8x4d vp8_sad16x8x4d_c
-
-void vp8_sad16x8x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad16x8x8 vp8_sad16x8x8_c
-
-unsigned int vp8_sad4x4_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad4x4_neon(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad4x4 vp8_sad4x4_neon
-
-void vp8_sad4x4x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad4x4x3 vp8_sad4x4x3_c
-
-void vp8_sad4x4x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad4x4x4d vp8_sad4x4x4d_c
-
-void vp8_sad4x4x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad4x4x8 vp8_sad4x4x8_c
-
-unsigned int vp8_sad8x16_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad8x16_neon(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad8x16 vp8_sad8x16_neon
-
-void vp8_sad8x16x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x16x3 vp8_sad8x16x3_c
-
-void vp8_sad8x16x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x16x4d vp8_sad8x16x4d_c
-
-void vp8_sad8x16x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad8x16x8 vp8_sad8x16x8_c
-
-unsigned int vp8_sad8x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad8x8_neon(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad8x8 vp8_sad8x8_neon
-
-void vp8_sad8x8x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x8x3 vp8_sad8x8x3_c
-
-void vp8_sad8x8x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x8x4d vp8_sad8x8x4d_c
-
-void vp8_sad8x8x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad8x8x8 vp8_sad8x8x8_c
-
 void vp8_short_fdct4x4_c(short *input, short *output, int pitch);
 void vp8_short_fdct4x4_armv6(short *input, short *output, int pitch);
 void vp8_short_fdct4x4_neon(short *input, short *output, int pitch);
@@ -300,8 +208,7 @@

 
 void vp8_sixtap_predict4x4_c(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 void vp8_sixtap_predict4x4_armv6(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
-void vp8_sixtap_predict4x4_neon(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
-#define vp8_sixtap_predict4x4 vp8_sixtap_predict4x4_neon
+#define vp8_sixtap_predict4x4 vp8_sixtap_predict4x4_armv6
 
 void vp8_sixtap_predict8x4_c(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 void vp8_sixtap_predict8x4_armv6(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
@@ -313,83 +220,6 @@

 void vp8_sixtap_predict8x8_neon(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 #define vp8_sixtap_predict8x8 vp8_sixtap_predict8x8_neon
 
-unsigned int vp8_sub_pixel_mse16x16_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_mse16x16 vp8_sub_pixel_mse16x16_c
-
-unsigned int vp8_sub_pixel_variance16x16_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-unsigned int vp8_sub_pixel_variance16x16_armv6(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-unsigned int vp8_sub_pixel_variance16x16_neon(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance16x16 vp8_sub_pixel_variance16x16_neon
-
-unsigned int vp8_sub_pixel_variance16x8_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance16x8 vp8_sub_pixel_variance16x8_c
-
-unsigned int vp8_sub_pixel_variance4x4_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance4x4 vp8_sub_pixel_variance4x4_c
-
-unsigned int vp8_sub_pixel_variance8x16_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance8x16 vp8_sub_pixel_variance8x16_c
-
-unsigned int vp8_sub_pixel_variance8x8_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-unsigned int vp8_sub_pixel_variance8x8_armv6(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-unsigned int vp8_sub_pixel_variance8x8_neon(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance8x8 vp8_sub_pixel_variance8x8_neon
-
-void vp8_subtract_b_c(struct block *be, struct blockd *bd, int pitch);
-void vp8_subtract_b_armv6(struct block *be, struct blockd *bd, int pitch);
-void vp8_subtract_b_neon(struct block *be, struct blockd *bd, int pitch);
-#define vp8_subtract_b vp8_subtract_b_neon
-
-void vp8_subtract_mbuv_c(short *diff, unsigned char *usrc, unsigned char *vsrc, int src_stride, unsigned char *upred, unsigned char *vpred, int pred_stride);
-void vp8_subtract_mbuv_armv6(short *diff, unsigned char *usrc, unsigned char *vsrc, int src_stride, unsigned char *upred, unsigned char *vpred, int pred_stride);
-void vp8_subtract_mbuv_neon(short *diff, unsigned char *usrc, unsigned char *vsrc, int src_stride, unsigned char *upred, unsigned char *vpred, int pred_stride);
-#define vp8_subtract_mbuv vp8_subtract_mbuv_neon
-
-void vp8_subtract_mby_c(short *diff, unsigned char *src, int src_stride, unsigned char *pred, int pred_stride);
-void vp8_subtract_mby_armv6(short *diff, unsigned char *src, int src_stride, unsigned char *pred, int pred_stride);
-void vp8_subtract_mby_neon(short *diff, unsigned char *src, int src_stride, unsigned char *pred, int pred_stride);
-#define vp8_subtract_mby vp8_subtract_mby_neon
-
-unsigned int vp8_variance16x16_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance16x16_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance16x16_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance16x16 vp8_variance16x16_neon
-
-unsigned int vp8_variance16x8_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance16x8_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance16x8 vp8_variance16x8_neon
-
-unsigned int vp8_variance4x4_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance4x4 vp8_variance4x4_c
-
-unsigned int vp8_variance8x16_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance8x16_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance8x16 vp8_variance8x16_neon
-
-unsigned int vp8_variance8x8_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance8x8_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance8x8_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance8x8 vp8_variance8x8_neon
-
-unsigned int vp8_variance_halfpixvar16x16_h_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_h_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_h_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance_halfpixvar16x16_h vp8_variance_halfpixvar16x16_h_neon
-
-unsigned int vp8_variance_halfpixvar16x16_hv_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_hv_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_hv_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance_halfpixvar16x16_hv vp8_variance_halfpixvar16x16_hv_neon
-
-unsigned int vp8_variance_halfpixvar16x16_v_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_v_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_v_neon(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance_halfpixvar16x16_v vp8_variance_halfpixvar16x16_v_neon
-
-void vp8_yv12_copy_partial_frame_c(struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
-void vp8_yv12_copy_partial_frame_neon(struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
-#define vp8_yv12_copy_partial_frame vp8_yv12_copy_partial_frame_neon
-
 void vp8_rtcd(void);
 
 #include "vpx_config.h"

```


### `armv7a-neon/vpx_config.c`

```diff
@@ -5,5 +5,6 @@

 /* tree. An additional intellectual property rights grant can be found */
 /* in the file PATENTS.  All contributing project authors may */
 /* be found in the AUTHORS file in the root of the source tree. */
-static const char* const cfg = "--target=armv7-android-gcc --disable-runtime-cpu-detect --sdk-path=/usr/local/google/home/hkuang/Downloads/android-ndk-r9d --disable-examples --disable-docs --enable-realtime-only";
+#include "vpx/vpx_codec.h"
+static const char* const cfg = "--target=armv7-android-gcc --disable-runtime-cpu-detect --sdk-path=/usr/local/google/home/vigneshv/Downloads/android-ndk-r10 --disable-examples --disable-docs --enable-realtime-only --disable-webm-io";
 const char *vpx_codec_build_config(void) {return cfg;}

```


### `armv7a-neon/vpx_config.h`

```diff
@@ -9,18 +9,19 @@

 #ifndef VPX_CONFIG_H
 #define VPX_CONFIG_H
 #define RESTRICT    
-#define INLINE      __inline__ __attribute__((always_inline))
+#define INLINE      inline
 #define ARCH_ARM 1
 #define ARCH_MIPS 0
 #define ARCH_X86 0
 #define ARCH_X86_64 0
-#define ARCH_PPC32 0
-#define ARCH_PPC64 0
-#define HAVE_EDSP 1
+#define HAVE_EDSP 0
 #define HAVE_MEDIA 1
 #define HAVE_NEON 1
+#define HAVE_NEON_ASM 1
 #define HAVE_MIPS32 0
 #define HAVE_DSPR2 0
+#define HAVE_MSA 0
+#define HAVE_MIPS64 0
 #define HAVE_MMX 0
 #define HAVE_SSE 0
 #define HAVE_SSE2 0
@@ -29,19 +30,18 @@

 #define HAVE_SSE4_1 0
 #define HAVE_AVX 0
 #define HAVE_AVX2 0
-#define HAVE_ALTIVEC 0
 #define HAVE_VPX_PORTS 1
 #define HAVE_STDINT_H 1
-#define HAVE_ALT_TREE_LAYOUT 0
 #define HAVE_PTHREAD_H 1
 #define HAVE_SYS_MMAN_H 1
 #define HAVE_UNISTD_H 1
+#define CONFIG_DEPENDENCY_TRACKING 1
 #define CONFIG_EXTERNAL_BUILD 0
-#define CONFIG_INSTALL_DOCS 0
+#define CONFIG_INSTALL_DOCS 1
 #define CONFIG_INSTALL_BINS 1
 #define CONFIG_INSTALL_LIBS 1
 #define CONFIG_INSTALL_SRCS 0
-#define CONFIG_USE_X86INC 1
+#define CONFIG_USE_X86INC 0
 #define CONFIG_DEBUG 0
 #define CONFIG_GPROF 0
 #define CONFIG_GCOV 0
@@ -52,10 +52,6 @@

 #define CONFIG_BIG_ENDIAN 0
 #define CONFIG_CODEC_SRCS 0
 #define CONFIG_DEBUG_LIBS 0
-#define CONFIG_FAST_UNALIGNED 1
-#define CONFIG_MEM_MANAGER 0
-#define CONFIG_MEM_TRACKER 0
-#define CONFIG_MEM_CHECKS 0
 #define CONFIG_DEQUANT_TOKENS 0
 #define CONFIG_DC_RECON 0
 #define CONFIG_RUNTIME_CPU_DETECT 0
@@ -67,8 +63,11 @@

 #define CONFIG_VP8_DECODER 1
 #define CONFIG_VP9_ENCODER 1
 #define CONFIG_VP9_DECODER 1
+#define CONFIG_VP10_ENCODER 0
+#define CONFIG_VP10_DECODER 0
 #define CONFIG_VP8 1
 #define CONFIG_VP9 1
+#define CONFIG_VP10 0
 #define CONFIG_ENCODERS 1
 #define CONFIG_DECODERS 1
 #define CONFIG_STATIC_MSVCRT 0
@@ -82,12 +81,18 @@

 #define CONFIG_POSTPROC_VISUALIZER 0
 #define CONFIG_OS_SUPPORT 1
 #define CONFIG_UNIT_TESTS 0
-#define CONFIG_WEBM_IO 1
+#define CONFIG_WEBM_IO 0
+#define CONFIG_LIBYUV 1
 #define CONFIG_DECODE_PERF_TESTS 0
+#define CONFIG_ENCODE_PERF_TESTS 0
 #define CONFIG_MULTI_RES_ENCODING 0
 #define CONFIG_TEMPORAL_DENOISING 1
+#define CONFIG_VP9_TEMPORAL_DENOISING 0
+#define CONFIG_COEFFICIENT_RANGE_CHECKING 0
+#define CONFIG_VP9_HIGHBITDEPTH 0
 #define CONFIG_EXPERIMENTAL 0
-#define CONFIG_DECRYPT 0
-#define CONFIG_MULTIPLE_ARF 0
-#define CONFIG_ALPHA 0
+#define CONFIG_SIZE_LIMIT 0
+#define CONFIG_SPATIAL_SVC 0
+#define CONFIG_FP_MB_STATS 0
+#define CONFIG_EMULATE_HARDWARE 0
 #endif /* VPX_CONFIG_H */

```


### `armv7a-neon/vpx_scale_rtcd.h`

```diff
@@ -7,12 +7,12 @@

 #define RTCD_EXTERN extern
 #endif
 
+struct yv12_buffer_config;
+
 #ifdef __cplusplus
 extern "C" {
 #endif
 
-struct yv12_buffer_config;
-
 void vp8_horizontal_line_2_1_scale_c(const unsigned char *source, unsigned int source_width, unsigned char *dest, unsigned int dest_width);
 #define vp8_horizontal_line_2_1_scale vp8_horizontal_line_2_1_scale_c
 
@@ -35,18 +35,16 @@

 #define vp8_vertical_band_5_4_scale vp8_vertical_band_5_4_scale_c
 
 void vp8_yv12_copy_frame_c(const struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
-void vp8_yv12_copy_frame_neon(const struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
-#define vp8_yv12_copy_frame vp8_yv12_copy_frame_neon
+#define vp8_yv12_copy_frame vp8_yv12_copy_frame_c
 
 void vp8_yv12_extend_frame_borders_c(struct yv12_buffer_config *ybf);
-void vp8_yv12_extend_frame_borders_neon(struct yv12_buffer_config *ybf);
-#define vp8_yv12_extend_frame_borders vp8_yv12_extend_frame_borders_neon
+#define vp8_yv12_extend_frame_borders vp8_yv12_extend_frame_borders_c
 
-void vp9_extend_frame_borders_c(struct yv12_buffer_config *ybf);
-#define vp9_extend_frame_borders vp9_extend_frame_borders_c
+void vpx_extend_frame_borders_c(struct yv12_buffer_config *ybf);
+#define vpx_extend_frame_borders vpx_extend_frame_borders_c
 
-void vp9_extend_frame_inner_borders_c(struct yv12_buffer_config *ybf);
-#define vp9_extend_frame_inner_borders vp9_extend_frame_inner_borders_c
+void vpx_extend_frame_inner_borders_c(struct yv12_buffer_config *ybf);
+#define vpx_extend_frame_inner_borders vpx_extend_frame_inner_borders_c
 
 void vpx_yv12_copy_y_c(const struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
 #define vpx_yv12_copy_y vpx_yv12_copy_y_c

```


### `armv7a-neon/vpx_version.h`

```diff
@@ -1,7 +1,7 @@

 #define VERSION_MAJOR  1
-#define VERSION_MINOR  3
+#define VERSION_MINOR  4
 #define VERSION_PATCH  0
-#define VERSION_EXTRA  "2239-g4fffefe"
+#define VERSION_EXTRA  ""
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.3.0-2239-g4fffefe"
-#define VERSION_STRING      " v1.3.0-2239-g4fffefe"
+#define VERSION_STRING_NOSP "v1.4.0"
+#define VERSION_STRING      " v1.4.0"

```


### `armv7a/libvpx_srcs.txt`

```diff
@@ -1,6 +1,6 @@

+CHANGELOG
 build/make/rtcd.pl
 build/make/version.sh
-CHANGELOG
 libs.mk
 vp8/common/alloccommon.c
 vp8/common/alloccommon.h
@@ -19,23 +19,16 @@

 vp8/common/arm/armv6/loopfilter_v6.asm.s
 vp8/common/arm/armv6/simpleloopfilter_v6.asm.s
 vp8/common/arm/armv6/sixtappredict8x4_v6.asm.s
-vp8/common/arm/armv6/vp8_sad16x16_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance16x16_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance8x8_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance_halfpixvar16x16_h_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance_halfpixvar16x16_hv_armv6.asm.s
-vp8/common/arm/armv6/vp8_variance_halfpixvar16x16_v_armv6.asm.s
 vp8/common/arm/bilinearfilter_arm.c
 vp8/common/arm/bilinearfilter_arm.h
 vp8/common/arm/dequantize_arm.c
 vp8/common/arm/filter_arm.c
 vp8/common/arm/loopfilter_arm.c
-vp8/common/arm/reconintra_arm.c
-vp8/common/arm/variance_arm.c
 vp8/common/blockd.c
 vp8/common/blockd.h
 vp8/common/coefupdateprobs.h
 vp8/common/common.h
+vp8/common/copy_c.c
 vp8/common/debugmodes.c
 vp8/common/default_coef_probs.h
 vp8/common/dequantize.c
@@ -56,28 +49,25 @@

 vp8/common/idct_blk.c
 vp8/common/idctllm.c
 vp8/common/invtrans.h
-vp8/common/loopfilter.c
-vp8/common/loopfilter_filters.c
 vp8/common/loopfilter.h
+vp8/common/loopfilter_filters.c
 vp8/common/mbpitch.c
 vp8/common/modecont.c
 vp8/common/modecont.h
 vp8/common/mv.h
+vp8/common/onyx.h
 vp8/common/onyxc_int.h
 vp8/common/onyxd.h
-vp8/common/onyx.h
 vp8/common/ppflags.h
-vp8/common/pragmas.h
 vp8/common/quant_common.c
 vp8/common/quant_common.h
 vp8/common/reconinter.c
 vp8/common/reconinter.h
+vp8/common/reconintra.c
 vp8/common/reconintra4x4.c
 vp8/common/reconintra4x4.h
-vp8/common/reconintra.c
 vp8/common/rtcd.c
 vp8/common/rtcd_defs.pl
-vp8/common/sad_c.c
 vp8/common/setupintrarecon.c
 vp8/common/setupintrarecon.h
 vp8/common/swapyv12buffer.c
@@ -86,9 +76,8 @@

 vp8/common/threading.h
 vp8/common/treecoder.c
 vp8/common/treecoder.h
-vp8/common/variance_c.c
-vp8/common/variance.h
 vp8/common/vp8_entropymodedata.h
+vp8/common/vp8_loopfilter.c
 vp8/decoder/dboolhuff.c
 vp8/decoder/dboolhuff.h
 vp8/decoder/decodeframe.c
@@ -101,21 +90,13 @@

 vp8/decoder/onyxd_int.h
 vp8/decoder/threading.c
 vp8/decoder/treereader.h
-vp8/encoder/arm/armv5te/boolhuff_armv5te.asm.s
-vp8/encoder/arm/armv5te/vp8_packtokens_armv5.asm.s
-vp8/encoder/arm/armv5te/vp8_packtokens_mbrow_armv5.asm.s
-vp8/encoder/arm/armv5te/vp8_packtokens_partitions_armv5.asm.s
-vp8/encoder/arm/armv6/vp8_fast_quantize_b_armv6.asm.s
-vp8/encoder/arm/armv6/vp8_mse16x16_armv6.asm.s
 vp8/encoder/arm/armv6/vp8_short_fdct4x4_armv6.asm.s
-vp8/encoder/arm/armv6/vp8_subtract_armv6.asm.s
 vp8/encoder/arm/armv6/walsh_v6.asm.s
-vp8/encoder/arm/boolhuff_arm.c
 vp8/encoder/arm/dct_arm.c
-vp8/encoder/arm/quantize_arm.c
 vp8/encoder/bitstream.c
 vp8/encoder/bitstream.h
 vp8/encoder/block.h
+vp8/encoder/boolhuff.c
 vp8/encoder/boolhuff.h
 vp8/encoder/dct.c
 vp8/encoder/dct_value_cost.h
@@ -144,7 +125,6 @@

 vp8/encoder/pickinter.c
 vp8/encoder/pickinter.h
 vp8/encoder/picklpf.c
-vp8/encoder/quantize.c
 vp8/encoder/quantize.h
 vp8/encoder/ratectrl.c
 vp8/encoder/ratectrl.h
@@ -156,22 +136,20 @@

 vp8/encoder/tokenize.h
 vp8/encoder/treewriter.c
 vp8/encoder/treewriter.h
-vp8/encoder/vp8_asm_enc_offsets.c
+vp8/encoder/vp8_quantize.c
 vp8/vp8_common.mk
-vp8/vp8cx_arm.mk
 vp8/vp8_cx_iface.c
-vp8/vp8cx.mk
 vp8/vp8_dx_iface.c
+vp8/vp8cx.mk
+vp8/vp8cx_arm.mk
 vp8/vp8dx.mk
 vp9/common/vp9_alloccommon.c
 vp9/common/vp9_alloccommon.h
 vp9/common/vp9_blockd.c
 vp9/common/vp9_blockd.h
+vp9/common/vp9_common.h
 vp9/common/vp9_common_data.c
 vp9/common/vp9_common_data.h
-vp9/common/vp9_common.h
-vp9/common/vp9_convolve.c
-vp9/common/vp9_convolve.h
 vp9/common/vp9_debugmodes.c
 vp9/common/vp9_entropy.c
 vp9/common/vp9_entropy.h
@@ -187,18 +165,14 @@

 vp9/common/vp9_idct.c
 vp9/common/vp9_idct.h
 vp9/common/vp9_loopfilter.c
-vp9/common/vp9_loopfilter_filters.c
 vp9/common/vp9_loopfilter.h
 vp9/common/vp9_mv.h
 vp9/common/vp9_mvref_common.c
 vp9/common/vp9_mvref_common.h
 vp9/common/vp9_onyxc_int.h
 vp9/common/vp9_ppflags.h
-vp9/common/vp9_pragmas.h
 vp9/common/vp9_pred_common.c
 vp9/common/vp9_pred_common.h
-vp9/common/vp9_prob.c
-vp9/common/vp9_prob.h
 vp9/common/vp9_quant_common.c
 vp9/common/vp9_quant_common.h
 vp9/common/vp9_reconinter.c
@@ -213,8 +187,9 @@

 vp9/common/vp9_scan.h
 vp9/common/vp9_seg_common.c
 vp9/common/vp9_seg_common.h
-vp9/common/vp9_systemdependent.h
 vp9/common/vp9_textblit.h
+vp9/common/vp9_thread_common.c
+vp9/common/vp9_thread_common.h
 vp9/common/vp9_tile_common.c
 vp9/common/vp9_tile_common.h
 vp9/decoder/vp9_decodeframe.c
@@ -229,21 +204,18 @@

 vp9/decoder/vp9_dsubexp.h
 vp9/decoder/vp9_dthread.c
 vp9/decoder/vp9_dthread.h
-vp9/decoder/vp9_read_bit_buffer.c
-vp9/decoder/vp9_read_bit_buffer.h
-vp9/decoder/vp9_reader.c
-vp9/decoder/vp9_reader.h
-vp9/decoder/vp9_thread.c
-vp9/decoder/vp9_thread.h
 vp9/encoder/vp9_aq_complexity.c
 vp9/encoder/vp9_aq_complexity.h
 vp9/encoder/vp9_aq_cyclicrefresh.c
 vp9/encoder/vp9_aq_cyclicrefresh.h
 vp9/encoder/vp9_aq_variance.c
 vp9/encoder/vp9_aq_variance.h
+vp9/encoder/vp9_avg.c
 vp9/encoder/vp9_bitstream.c
 vp9/encoder/vp9_bitstream.h
 vp9/encoder/vp9_block.h
+vp9/encoder/vp9_context_tree.c
+vp9/encoder/vp9_context_tree.h
 vp9/encoder/vp9_cost.c
 vp9/encoder/vp9_cost.h
 vp9/encoder/vp9_dct.c
@@ -253,6 +225,10 @@

 vp9/encoder/vp9_encodemb.h
 vp9/encoder/vp9_encodemv.c
 vp9/encoder/vp9_encodemv.h
+vp9/encoder/vp9_encoder.c
+vp9/encoder/vp9_encoder.h
+vp9/encoder/vp9_ethread.c
+vp9/encoder/vp9_ethread.h
 vp9/encoder/vp9_extend.c
 vp9/encoder/vp9_extend.h
 vp9/encoder/vp9_firstpass.c
@@ -263,8 +239,6 @@

 vp9/encoder/vp9_mbgraph.h
 vp9/encoder/vp9_mcomp.c
 vp9/encoder/vp9_mcomp.h
-vp9/encoder/vp9_onyx_if.c
-vp9/encoder/vp9_onyx_int.h
 vp9/encoder/vp9_picklpf.c
 vp9/encoder/vp9_picklpf.h
 vp9/encoder/vp9_pickmode.c
@@ -273,13 +247,16 @@

 vp9/encoder/vp9_quantize.h
 vp9/encoder/vp9_ratectrl.c
 vp9/encoder/vp9_ratectrl.h
+vp9/encoder/vp9_rd.c
+vp9/encoder/vp9_rd.h
 vp9/encoder/vp9_rdopt.c
 vp9/encoder/vp9_rdopt.h
 vp9/encoder/vp9_resize.c
 vp9/encoder/vp9_resize.h
-vp9/encoder/vp9_sad.c
 vp9/encoder/vp9_segmentation.c
 vp9/encoder/vp9_segmentation.h
+vp9/encoder/vp9_skin_detection.c
+vp9/encoder/vp9_skin_detection.h
 vp9/encoder/vp9_speed_features.c
 vp9/encoder/vp9_speed_features.h
 vp9/encoder/vp9_subexp.c
@@ -292,55 +269,22 @@

 vp9/encoder/vp9_tokenize.h
 vp9/encoder/vp9_treewriter.c
 vp9/encoder/vp9_treewriter.h
-vp9/encoder/vp9_variance.c
-vp9/encoder/vp9_variance.h
-vp9/encoder/vp9_write_bit_buffer.c
-vp9/encoder/vp9_write_bit_buffer.h
-vp9/encoder/vp9_writer.c
-vp9/encoder/vp9_writer.h
 vp9/vp9_common.mk
 vp9/vp9_cx_iface.c
-vp9/vp9cx.mk
 vp9/vp9_dx_iface.c
-vp9/vp9dx.mk
 vp9/vp9_iface_common.h
-vpx_config.c
+vp9/vp9cx.mk
+vp9/vp9dx.mk
 vpx/internal/vpx_codec_internal.h
 vpx/internal/vpx_psnr.h
-vpx_mem/include/vpx_mem_intrnl.h
-vpx_mem/vpx_mem.c
-vpx_mem/vpx_mem.h
-vpx_mem/vpx_mem.mk
-vpx_ports/arm_cpudetect.c
-vpx_ports/arm.h
-vpx_ports/asm_offsets.h
-vpx_ports/emmintrin_compat.h
-vpx_ports/mem.h
-vpx_ports/mem_ops_aligned.h
-vpx_ports/mem_ops.h
-vpx_ports/vpx_once.h
-vpx_ports/vpx_ports.mk
-vpx_ports/vpx_timer.h
-vpx_scale/generic/gen_scalers.c
-vpx_scale/generic/vpx_scale.c
-vpx_scale/generic/yv12config.c
-vpx_scale/generic/yv12extend.c
-vpx_scale/vpx_scale_asm_offsets.c
-vpx_scale/vpx_scale.h
-vpx_scale/vpx_scale.mk
-vpx_scale/vpx_scale_rtcd.c
-vpx_scale/vpx_scale_rtcd.pl
-vpx_scale/yv12config.h
-vpx/src/svc_encodeframe.c
 vpx/src/vpx_codec.c
 vpx/src/vpx_decoder.c
 vpx/src/vpx_encoder.c
 vpx/src/vpx_image.c
 vpx/src/vpx_psnr.c
-vpx/svc_context.h
+vpx/vp8.h
 vpx/vp8cx.h
 vpx/vp8dx.h
-vpx/vp8.h
 vpx/vpx_codec.h
 vpx/vpx_codec.mk
 vpx/vpx_decoder.h
@@ -348,3 +292,70 @@

 vpx/vpx_frame_buffer.h
 vpx/vpx_image.h
 vpx/vpx_integer.h
+vpx_config.c
+vpx_dsp/arm/bilinear_filter_media.asm.s
+vpx_dsp/arm/sad_media.asm.s
+vpx_dsp/arm/subpel_variance_media.c
+vpx_dsp/arm/variance_halfpixvar16x16_h_media.asm.s
+vpx_dsp/arm/variance_halfpixvar16x16_hv_media.asm.s
+vpx_dsp/arm/variance_halfpixvar16x16_v_media.asm.s
+vpx_dsp/arm/variance_media.asm.s
+vpx_dsp/bitreader.c
+vpx_dsp/bitreader.h
+vpx_dsp/bitreader_buffer.c
+vpx_dsp/bitreader_buffer.h
+vpx_dsp/bitwriter.c
+vpx_dsp/bitwriter.h
+vpx_dsp/bitwriter_buffer.c
+vpx_dsp/bitwriter_buffer.h
+vpx_dsp/fwd_txfm.c
+vpx_dsp/fwd_txfm.h
+vpx_dsp/intrapred.c
+vpx_dsp/inv_txfm.c
+vpx_dsp/inv_txfm.h
+vpx_dsp/loopfilter.c
+vpx_dsp/prob.c
+vpx_dsp/prob.h
+vpx_dsp/quantize.c
+vpx_dsp/quantize.h
+vpx_dsp/sad.c
+vpx_dsp/subtract.c
+vpx_dsp/txfm_common.h
+vpx_dsp/variance.c
+vpx_dsp/variance.h
+vpx_dsp/vpx_convolve.c
+vpx_dsp/vpx_convolve.h
+vpx_dsp/vpx_dsp.mk
+vpx_dsp/vpx_dsp_common.h
+vpx_dsp/vpx_dsp_rtcd.c
+vpx_dsp/vpx_dsp_rtcd_defs.pl
+vpx_dsp/vpx_filter.h
+vpx_mem/include/vpx_mem_intrnl.h
+vpx_mem/vpx_mem.c
+vpx_mem/vpx_mem.h
+vpx_mem/vpx_mem.mk
+vpx_ports/arm.h
+vpx_ports/arm_cpudetect.c
+vpx_ports/bitops.h
+vpx_ports/emmintrin_compat.h
+vpx_ports/mem.h
+vpx_ports/mem_ops.h
+vpx_ports/mem_ops_aligned.h
+vpx_ports/msvc.h
+vpx_ports/system_state.h
+vpx_ports/vpx_once.h
+vpx_ports/vpx_ports.mk
+vpx_ports/vpx_timer.h
+vpx_scale/generic/gen_scalers.c
+vpx_scale/generic/vpx_scale.c
+vpx_scale/generic/yv12config.c
+vpx_scale/generic/yv12extend.c
+vpx_scale/vpx_scale.h
+vpx_scale/vpx_scale.mk
+vpx_scale/vpx_scale_rtcd.c
+vpx_scale/vpx_scale_rtcd.pl
+vpx_scale/yv12config.h
+vpx_util/endian_inl.h
+vpx_util/vpx_thread.c
+vpx_util/vpx_thread.h
+vpx_util/vpx_util.mk

```


### `armv7a/vp8_rtcd.h`

```diff
@@ -7,10 +7,6 @@

 #define RTCD_EXTERN extern
 #endif
 
-#ifdef __cplusplus
-extern "C" {
-#endif
-
 /*
  * VP8
  */
@@ -26,6 +22,10 @@

 union int_mv;
 struct yv12_buffer_config;
 
+#ifdef __cplusplus
+extern "C" {
+#endif
+
 void vp8_bilinear_predict16x16_c(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 void vp8_bilinear_predict16x16_armv6(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 #define vp8_bilinear_predict16x16 vp8_bilinear_predict16x16_armv6
@@ -70,9 +70,12 @@

 void vp8_dc_only_idct_add_v6(short input, unsigned char *pred, int pred_stride, unsigned char *dst, int dst_stride);
 #define vp8_dc_only_idct_add vp8_dc_only_idct_add_v6
 
-int vp8_denoiser_filter_c(struct yv12_buffer_config* mc_running_avg, struct yv12_buffer_config* running_avg, struct macroblock* signal, unsigned int motion_magnitude2, int y_offset, int uv_offset);
+int vp8_denoiser_filter_c(unsigned char *mc_running_avg_y, int mc_avg_y_stride, unsigned char *running_avg_y, int avg_y_stride, unsigned char *sig, int sig_stride, unsigned int motion_magnitude, int increase_denoising);
 #define vp8_denoiser_filter vp8_denoiser_filter_c
 
+int vp8_denoiser_filter_uv_c(unsigned char *mc_running_avg, int mc_avg_stride, unsigned char *running_avg, int avg_stride, unsigned char *sig, int sig_stride, unsigned int motion_magnitude, int increase_denoising);
+#define vp8_denoiser_filter_uv vp8_denoiser_filter_uv_c
+
 void vp8_dequant_idct_add_c(short *input, short *dq, unsigned char *output, int stride);
 void vp8_dequant_idct_add_v6(short *input, short *dq, unsigned char *output, int stride);
 #define vp8_dequant_idct_add vp8_dequant_idct_add_v6
@@ -93,21 +96,11 @@

 #define vp8_diamond_search_sad vp8_diamond_search_sad_c
 
 void vp8_fast_quantize_b_c(struct block *, struct blockd *);
-void vp8_fast_quantize_b_armv6(struct block *, struct blockd *);
-#define vp8_fast_quantize_b vp8_fast_quantize_b_armv6
-
-void vp8_fast_quantize_b_pair_c(struct block *b1, struct block *b2, struct blockd *d1, struct blockd *d2);
-#define vp8_fast_quantize_b_pair vp8_fast_quantize_b_pair_c
+#define vp8_fast_quantize_b vp8_fast_quantize_b_c
 
 int vp8_full_search_sad_c(struct macroblock *x, struct block *b, struct blockd *d, union int_mv *ref_mv, int sad_per_bit, int distance, struct variance_vtable *fn_ptr, int *mvcost[2], union int_mv *center_mv);
 #define vp8_full_search_sad vp8_full_search_sad_c
 
-unsigned int vp8_get4x4sse_cs_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride);
-#define vp8_get4x4sse_cs vp8_get4x4sse_cs_c
-
-unsigned int vp8_get_mb_ss_c(const short *);
-#define vp8_get_mb_ss vp8_get_mb_ss_c
-
 void vp8_intra4x4_predict_c(unsigned char *Above, unsigned char *yleft, int left_stride, int b_mode, unsigned char *dst, int dst_stride, unsigned char top_left);
 void vp8_intra4x4_predict_armv6(unsigned char *Above, unsigned char *yleft, int left_stride, int b_mode, unsigned char *dst, int dst_stride, unsigned char top_left);
 #define vp8_intra4x4_predict vp8_intra4x4_predict_armv6
@@ -150,89 +143,12 @@

 int vp8_mbuverror_c(struct macroblock *mb);
 #define vp8_mbuverror vp8_mbuverror_c
 
-unsigned int vp8_mse16x16_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_mse16x16_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_mse16x16 vp8_mse16x16_armv6
-
-void vp8_quantize_mb_c(struct macroblock *);
-#define vp8_quantize_mb vp8_quantize_mb_c
-
-void vp8_quantize_mbuv_c(struct macroblock *);
-#define vp8_quantize_mbuv vp8_quantize_mbuv_c
-
-void vp8_quantize_mby_c(struct macroblock *);
-#define vp8_quantize_mby vp8_quantize_mby_c
-
 int vp8_refining_search_sad_c(struct macroblock *x, struct block *b, struct blockd *d, union int_mv *ref_mv, int sad_per_bit, int distance, struct variance_vtable *fn_ptr, int *mvcost[2], union int_mv *center_mv);
 #define vp8_refining_search_sad vp8_refining_search_sad_c
 
 void vp8_regular_quantize_b_c(struct block *, struct blockd *);
 #define vp8_regular_quantize_b vp8_regular_quantize_b_c
 
-void vp8_regular_quantize_b_pair_c(struct block *b1, struct block *b2, struct blockd *d1, struct blockd *d2);
-#define vp8_regular_quantize_b_pair vp8_regular_quantize_b_pair_c
-
-unsigned int vp8_sad16x16_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-unsigned int vp8_sad16x16_armv6(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad16x16 vp8_sad16x16_armv6
-
-void vp8_sad16x16x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x16x3 vp8_sad16x16x3_c
-
-void vp8_sad16x16x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x16x4d vp8_sad16x16x4d_c
-
-void vp8_sad16x16x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad16x16x8 vp8_sad16x16x8_c
-
-unsigned int vp8_sad16x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad16x8 vp8_sad16x8_c
-
-void vp8_sad16x8x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x8x3 vp8_sad16x8x3_c
-
-void vp8_sad16x8x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad16x8x4d vp8_sad16x8x4d_c
-
-void vp8_sad16x8x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad16x8x8 vp8_sad16x8x8_c
-
-unsigned int vp8_sad4x4_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad4x4 vp8_sad4x4_c
-
-void vp8_sad4x4x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad4x4x3 vp8_sad4x4x3_c
-
-void vp8_sad4x4x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad4x4x4d vp8_sad4x4x4d_c
-
-void vp8_sad4x4x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad4x4x8 vp8_sad4x4x8_c
-
-unsigned int vp8_sad8x16_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad8x16 vp8_sad8x16_c
-
-void vp8_sad8x16x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x16x3 vp8_sad8x16x3_c
-
-void vp8_sad8x16x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x16x4d vp8_sad8x16x4d_c
-
-void vp8_sad8x16x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad8x16x8 vp8_sad8x16x8_c
-
-unsigned int vp8_sad8x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int ref_stride, unsigned int max_sad);
-#define vp8_sad8x8 vp8_sad8x8_c
-
-void vp8_sad8x8x3_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x8x3 vp8_sad8x8x3_c
-
-void vp8_sad8x8x4d_c(const unsigned char *src_ptr, int src_stride, const unsigned char * const ref_ptr[], int  ref_stride, unsigned int *sad_array);
-#define vp8_sad8x8x4d vp8_sad8x8x4d_c
-
-void vp8_sad8x8x8_c(const unsigned char *src_ptr, int src_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned short *sad_array);
-#define vp8_sad8x8x8 vp8_sad8x8x8_c
-
 void vp8_short_fdct4x4_c(short *input, short *output, int pitch);
 void vp8_short_fdct4x4_armv6(short *input, short *output, int pitch);
 #define vp8_short_fdct4x4 vp8_short_fdct4x4_armv6
@@ -272,70 +188,6 @@

 void vp8_sixtap_predict8x8_armv6(unsigned char *src, int src_pitch, int xofst, int yofst, unsigned char *dst, int dst_pitch);
 #define vp8_sixtap_predict8x8 vp8_sixtap_predict8x8_armv6
 
-unsigned int vp8_sub_pixel_mse16x16_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_mse16x16 vp8_sub_pixel_mse16x16_c
-
-unsigned int vp8_sub_pixel_variance16x16_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-unsigned int vp8_sub_pixel_variance16x16_armv6(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance16x16 vp8_sub_pixel_variance16x16_armv6
-
-unsigned int vp8_sub_pixel_variance16x8_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance16x8 vp8_sub_pixel_variance16x8_c
-
-unsigned int vp8_sub_pixel_variance4x4_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance4x4 vp8_sub_pixel_variance4x4_c
-
-unsigned int vp8_sub_pixel_variance8x16_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance8x16 vp8_sub_pixel_variance8x16_c
-
-unsigned int vp8_sub_pixel_variance8x8_c(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-unsigned int vp8_sub_pixel_variance8x8_armv6(const unsigned char  *src_ptr, int  source_stride, int  xoffset, int  yoffset, const unsigned char *ref_ptr, int Refstride, unsigned int *sse);
-#define vp8_sub_pixel_variance8x8 vp8_sub_pixel_variance8x8_armv6
-
-void vp8_subtract_b_c(struct block *be, struct blockd *bd, int pitch);
-void vp8_subtract_b_armv6(struct block *be, struct blockd *bd, int pitch);
-#define vp8_subtract_b vp8_subtract_b_armv6
-
-void vp8_subtract_mbuv_c(short *diff, unsigned char *usrc, unsigned char *vsrc, int src_stride, unsigned char *upred, unsigned char *vpred, int pred_stride);
-void vp8_subtract_mbuv_armv6(short *diff, unsigned char *usrc, unsigned char *vsrc, int src_stride, unsigned char *upred, unsigned char *vpred, int pred_stride);
-#define vp8_subtract_mbuv vp8_subtract_mbuv_armv6
-
-void vp8_subtract_mby_c(short *diff, unsigned char *src, int src_stride, unsigned char *pred, int pred_stride);
-void vp8_subtract_mby_armv6(short *diff, unsigned char *src, int src_stride, unsigned char *pred, int pred_stride);
-#define vp8_subtract_mby vp8_subtract_mby_armv6
-
-unsigned int vp8_variance16x16_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance16x16_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance16x16 vp8_variance16x16_armv6
-
-unsigned int vp8_variance16x8_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance16x8 vp8_variance16x8_c
-
-unsigned int vp8_variance4x4_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance4x4 vp8_variance4x4_c
-
-unsigned int vp8_variance8x16_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance8x16 vp8_variance8x16_c
-
-unsigned int vp8_variance8x8_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance8x8_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance8x8 vp8_variance8x8_armv6
-
-unsigned int vp8_variance_halfpixvar16x16_h_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_h_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance_halfpixvar16x16_h vp8_variance_halfpixvar16x16_h_armv6
-
-unsigned int vp8_variance_halfpixvar16x16_hv_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_hv_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance_halfpixvar16x16_hv vp8_variance_halfpixvar16x16_hv_armv6
-
-unsigned int vp8_variance_halfpixvar16x16_v_c(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-unsigned int vp8_variance_halfpixvar16x16_v_armv6(const unsigned char *src_ptr, int source_stride, const unsigned char *ref_ptr, int  ref_stride, unsigned int *sse);
-#define vp8_variance_halfpixvar16x16_v vp8_variance_halfpixvar16x16_v_armv6
-
-void vp8_yv12_copy_partial_frame_c(struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
-#define vp8_yv12_copy_partial_frame vp8_yv12_copy_partial_frame_c
-
 void vp8_rtcd(void);
 
 #include "vpx_config.h"

```


### `armv7a/vpx_config.c`

```diff
@@ -5,5 +5,6 @@

 /* tree. An additional intellectual property rights grant can be found */
 /* in the file PATENTS.  All contributing project authors may */
 /* be found in the AUTHORS file in the root of the source tree. */
-static const char* const cfg = "--target=armv7-android-gcc --disable-runtime-cpu-detect --sdk-path=/usr/local/google/home/hkuang/Downloads/android-ndk-r9d --disable-neon --disable-examples --disable-docs --enable-realtime-only";
+#include "vpx/vpx_codec.h"
+static const char* const cfg = "--target=armv7-android-gcc --disable-runtime-cpu-detect --sdk-path=/usr/local/google/home/vigneshv/Downloads/android-ndk-r10 --disable-neon --disable-neon-asm --disable-examples --disable-docs --enable-realtime-only --disable-webm-io";
 const char *vpx_codec_build_config(void) {return cfg;}

```


### `armv7a/vpx_config.h`

```diff
@@ -9,18 +9,19 @@

 #ifndef VPX_CONFIG_H
 #define VPX_CONFIG_H
 #define RESTRICT    
-#define INLINE      __inline__ __attribute__((always_inline))
+#define INLINE      inline
 #define ARCH_ARM 1
 #define ARCH_MIPS 0
 #define ARCH_X86 0
 #define ARCH_X86_64 0
-#define ARCH_PPC32 0
-#define ARCH_PPC64 0
-#define HAVE_EDSP 1
+#define HAVE_EDSP 0
 #define HAVE_MEDIA 1
 #define HAVE_NEON 0
+#define HAVE_NEON_ASM 0
 #define HAVE_MIPS32 0
 #define HAVE_DSPR2 0
+#define HAVE_MSA 0
+#define HAVE_MIPS64 0
 #define HAVE_MMX 0
 #define HAVE_SSE 0
 #define HAVE_SSE2 0
@@ -29,19 +30,18 @@

 #define HAVE_SSE4_1 0
 #define HAVE_AVX 0
 #define HAVE_AVX2 0
-#define HAVE_ALTIVEC 0
 #define HAVE_VPX_PORTS 1
 #define HAVE_STDINT_H 1
-#define HAVE_ALT_TREE_LAYOUT 0
 #define HAVE_PTHREAD_H 1
 #define HAVE_SYS_MMAN_H 1
 #define HAVE_UNISTD_H 1
+#define CONFIG_DEPENDENCY_TRACKING 1
 #define CONFIG_EXTERNAL_BUILD 0
-#define CONFIG_INSTALL_DOCS 0
+#define CONFIG_INSTALL_DOCS 1
 #define CONFIG_INSTALL_BINS 1
 #define CONFIG_INSTALL_LIBS 1
 #define CONFIG_INSTALL_SRCS 0
-#define CONFIG_USE_X86INC 1
+#define CONFIG_USE_X86INC 0
 #define CONFIG_DEBUG 0
 #define CONFIG_GPROF 0
 #define CONFIG_GCOV 0
@@ -52,10 +52,6 @@

 #define CONFIG_BIG_ENDIAN 0
 #define CONFIG_CODEC_SRCS 0
 #define CONFIG_DEBUG_LIBS 0
-#define CONFIG_FAST_UNALIGNED 1
-#define CONFIG_MEM_MANAGER 0
-#define CONFIG_MEM_TRACKER 0
-#define CONFIG_MEM_CHECKS 0
 #define CONFIG_DEQUANT_TOKENS 0
 #define CONFIG_DC_RECON 0
 #define CONFIG_RUNTIME_CPU_DETECT 0
@@ -67,8 +63,11 @@

 #define CONFIG_VP8_DECODER 1
 #define CONFIG_VP9_ENCODER 1
 #define CONFIG_VP9_DECODER 1
+#define CONFIG_VP10_ENCODER 0
+#define CONFIG_VP10_DECODER 0
 #define CONFIG_VP8 1
 #define CONFIG_VP9 1
+#define CONFIG_VP10 0
 #define CONFIG_ENCODERS 1
 #define CONFIG_DECODERS 1
 #define CONFIG_STATIC_MSVCRT 0
@@ -82,12 +81,18 @@

 #define CONFIG_POSTPROC_VISUALIZER 0
 #define CONFIG_OS_SUPPORT 1
 #define CONFIG_UNIT_TESTS 0
-#define CONFIG_WEBM_IO 1
+#define CONFIG_WEBM_IO 0
+#define CONFIG_LIBYUV 1
 #define CONFIG_DECODE_PERF_TESTS 0
+#define CONFIG_ENCODE_PERF_TESTS 0
 #define CONFIG_MULTI_RES_ENCODING 0
 #define CONFIG_TEMPORAL_DENOISING 1
+#define CONFIG_VP9_TEMPORAL_DENOISING 0
+#define CONFIG_COEFFICIENT_RANGE_CHECKING 0
+#define CONFIG_VP9_HIGHBITDEPTH 0
 #define CONFIG_EXPERIMENTAL 0
-#define CONFIG_DECRYPT 0
-#define CONFIG_MULTIPLE_ARF 0
-#define CONFIG_ALPHA 0
+#define CONFIG_SIZE_LIMIT 0
+#define CONFIG_SPATIAL_SVC 0
+#define CONFIG_FP_MB_STATS 0
+#define CONFIG_EMULATE_HARDWARE 0
 #endif /* VPX_CONFIG_H */

```


### `armv7a/vpx_scale_rtcd.h`

```diff
@@ -7,12 +7,12 @@

 #define RTCD_EXTERN extern
 #endif
 
+struct yv12_buffer_config;
+
 #ifdef __cplusplus
 extern "C" {
 #endif
 
-struct yv12_buffer_config;
-
 void vp8_horizontal_line_2_1_scale_c(const unsigned char *source, unsigned int source_width, unsigned char *dest, unsigned int dest_width);
 #define vp8_horizontal_line_2_1_scale vp8_horizontal_line_2_1_scale_c
 
@@ -40,11 +40,11 @@

 void vp8_yv12_extend_frame_borders_c(struct yv12_buffer_config *ybf);
 #define vp8_yv12_extend_frame_borders vp8_yv12_extend_frame_borders_c
 
-void vp9_extend_frame_borders_c(struct yv12_buffer_config *ybf);
-#define vp9_extend_frame_borders vp9_extend_frame_borders_c
+void vpx_extend_frame_borders_c(struct yv12_buffer_config *ybf);
+#define vpx_extend_frame_borders vpx_extend_frame_borders_c
 
-void vp9_extend_frame_inner_borders_c(struct yv12_buffer_config *ybf);
-#define vp9_extend_frame_inner_borders vp9_extend_frame_inner_borders_c
+void vpx_extend_frame_inner_borders_c(struct yv12_buffer_config *ybf);
+#define vpx_extend_frame_inner_borders vpx_extend_frame_inner_borders_c
 
 void vpx_yv12_copy_y_c(const struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
 #define vpx_yv12_copy_y vpx_yv12_copy_y_c

```


### `armv7a/vpx_version.h`

```diff
@@ -1,7 +1,7 @@

 #define VERSION_MAJOR  1
-#define VERSION_MINOR  3
+#define VERSION_MINOR  4
 #define VERSION_PATCH  0
-#define VERSION_EXTRA  "2239-g4fffefe"
+#define VERSION_EXTRA  ""
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.3.0-2239-g4fffefe"
-#define VERSION_STRING      " v1.3.0-2239-g4fffefe"
+#define VERSION_STRING_NOSP "v1.4.0"
+#define VERSION_STRING      " v1.4.0"

```


### `generic/vpx_config.c`

```diff
@@ -5,5 +5,6 @@

 /* tree. An additional intellectual property rights grant can be found */
 /* in the file PATENTS.  All contributing project authors may */
 /* be found in the AUTHORS file in the root of the source tree. */
-static const char* const cfg = "--force-target=generic-gnu --disable-examples --disable-docs --enable-realtime-only";
+#include "vpx/vpx_codec.h"
+static const char* const cfg = "--force-target=generic-gnu --disable-examples --disable-docs --enable-realtime-only --disable-webm-io";
 const char *vpx_codec_build_config(void) {return cfg;}

```


### `generic/vpx_config.h`

```diff
@@ -9,18 +9,19 @@

 #ifndef VPX_CONFIG_H
 #define VPX_CONFIG_H
 #define RESTRICT    
-#define INLINE      __inline__ __attribute__((always_inline))
+#define INLINE      inline
 #define ARCH_ARM 0
 #define ARCH_MIPS 0
 #define ARCH_X86 0
 #define ARCH_X86_64 0
-#define ARCH_PPC32 0
-#define ARCH_PPC64 0
 #define HAVE_EDSP 0
 #define HAVE_MEDIA 0
 #define HAVE_NEON 0
+#define HAVE_NEON_ASM 0
 #define HAVE_MIPS32 0
 #define HAVE_DSPR2 0
+#define HAVE_MSA 0
+#define HAVE_MIPS64 0
 #define HAVE_MMX 0
 #define HAVE_SSE 0
 #define HAVE_SSE2 0
@@ -29,19 +30,18 @@

 #define HAVE_SSE4_1 0
 #define HAVE_AVX 0
 #define HAVE_AVX2 0
-#define HAVE_ALTIVEC 0
 #define HAVE_VPX_PORTS 1
 #define HAVE_STDINT_H 1
-#define HAVE_ALT_TREE_LAYOUT 0
 #define HAVE_PTHREAD_H 1
 #define HAVE_SYS_MMAN_H 1
 #define HAVE_UNISTD_H 1
+#define CONFIG_DEPENDENCY_TRACKING 1
 #define CONFIG_EXTERNAL_BUILD 0
-#define CONFIG_INSTALL_DOCS 0
+#define CONFIG_INSTALL_DOCS 1
 #define CONFIG_INSTALL_BINS 1
 #define CONFIG_INSTALL_LIBS 1
 #define CONFIG_INSTALL_SRCS 0
-#define CONFIG_USE_X86INC 1
+#define CONFIG_USE_X86INC 0
 #define CONFIG_DEBUG 0
 #define CONFIG_GPROF 0
 #define CONFIG_GCOV 0
@@ -52,10 +52,6 @@

 #define CONFIG_BIG_ENDIAN 0
 #define CONFIG_CODEC_SRCS 0
 #define CONFIG_DEBUG_LIBS 0
-#define CONFIG_FAST_UNALIGNED 1
-#define CONFIG_MEM_MANAGER 0
-#define CONFIG_MEM_TRACKER 0
-#define CONFIG_MEM_CHECKS 0
 #define CONFIG_DEQUANT_TOKENS 0
 #define CONFIG_DC_RECON 0
 #define CONFIG_RUNTIME_CPU_DETECT 0
@@ -67,8 +63,11 @@

 #define CONFIG_VP8_DECODER 1
 #define CONFIG_VP9_ENCODER 1
 #define CONFIG_VP9_DECODER 1
+#define CONFIG_VP10_ENCODER 0
+#define CONFIG_VP10_DECODER 0
 #define CONFIG_VP8 1
 #define CONFIG_VP9 1
+#define CONFIG_VP10 0
 #define CONFIG_ENCODERS 1
 #define CONFIG_DECODERS 1
 #define CONFIG_STATIC_MSVCRT 0
@@ -82,12 +81,18 @@

 #define CONFIG_POSTPROC_VISUALIZER 0
 #define CONFIG_OS_SUPPORT 1
 #define CONFIG_UNIT_TESTS 1
-#define CONFIG_WEBM_IO 1
+#define CONFIG_WEBM_IO 0
+#define CONFIG_LIBYUV 1
 #define CONFIG_DECODE_PERF_TESTS 0
+#define CONFIG_ENCODE_PERF_TESTS 0
 #define CONFIG_MULTI_RES_ENCODING 0
 #define CONFIG_TEMPORAL_DENOISING 1
+#define CONFIG_VP9_TEMPORAL_DENOISING 0
+#define CONFIG_COEFFICIENT_RANGE_CHECKING 0
+#define CONFIG_VP9_HIGHBITDEPTH 0
 #define CONFIG_EXPERIMENTAL 0
-#define CONFIG_DECRYPT 0
-#define CONFIG_MULTIPLE_ARF 0
-#define CONFIG_ALPHA 0
+#define CONFIG_SIZE_LIMIT 0
+#define CONFIG_SPATIAL_SVC 0
+#define CONFIG_FP_MB_STATS 0
+#define CONFIG_EMULATE_HARDWARE 0
 #endif /* VPX_CONFIG_H */

```


### `generic/vpx_scale_rtcd.h`

```diff
@@ -7,12 +7,12 @@

 #define RTCD_EXTERN extern
 #endif
 
+struct yv12_buffer_config;
+
 #ifdef __cplusplus
 extern "C" {
 #endif
 
-struct yv12_buffer_config;
-
 void vp8_horizontal_line_2_1_scale_c(const unsigned char *source, unsigned int source_width, unsigned char *dest, unsigned int dest_width);
 #define vp8_horizontal_line_2_1_scale vp8_horizontal_line_2_1_scale_c
 
@@ -40,11 +40,11 @@

 void vp8_yv12_extend_frame_borders_c(struct yv12_buffer_config *ybf);
 #define vp8_yv12_extend_frame_borders vp8_yv12_extend_frame_borders_c
 
-void vp9_extend_frame_borders_c(struct yv12_buffer_config *ybf);
-#define vp9_extend_frame_borders vp9_extend_frame_borders_c
+void vpx_extend_frame_borders_c(struct yv12_buffer_config *ybf);
+#define vpx_extend_frame_borders vpx_extend_frame_borders_c
 
-void vp9_extend_frame_inner_borders_c(struct yv12_buffer_config *ybf);
-#define vp9_extend_frame_inner_borders vp9_extend_frame_inner_borders_c
+void vpx_extend_frame_inner_borders_c(struct yv12_buffer_config *ybf);
+#define vpx_extend_frame_inner_borders vpx_extend_frame_inner_borders_c
 
 void vpx_yv12_copy_y_c(const struct yv12_buffer_config *src_ybc, struct yv12_buffer_config *dst_ybc);
 #define vpx_yv12_copy_y vpx_yv12_copy_y_c

```


### `generic/vpx_version.h`

```diff
@@ -1,7 +1,7 @@

 #define VERSION_MAJOR  1
-#define VERSION_MINOR  3
+#define VERSION_MINOR  4
 #define VERSION_PATCH  0
-#define VERSION_EXTRA  "2239-g4fffefe"
+#define VERSION_EXTRA  ""
 #define VERSION_PACKED ((VERSION_MAJOR<<16)|(VERSION_MINOR<<8)|(VERSION_PATCH))
-#define VERSION_STRING_NOSP "v1.3.0-2239-g4fffefe"
-#define VERSION_STRING      " v1.3.0-2239-g4fffefe"
+#define VERSION_STRING_NOSP "v1.4.0"
+#define VERSION_STRING      " v1.4.0"

```


### `libvpx/args.c`

```diff
@@ -14,9 +14,7 @@

 #include <limits.h>
 #include "args.h"
 
-#ifdef _MSC_VER
-#define snprintf _snprintf
-#endif
+#include "vpx_ports/msvc.h"
 
 #if defined(__GNUC__) && __GNUC__
 extern void die(const char *fmt, ...) __attribute__((noreturn));

```


_[790 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
