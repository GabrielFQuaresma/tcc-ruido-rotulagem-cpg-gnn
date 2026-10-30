# Pacote de anotacao — caso 21

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

# Evidencia do caso 21

## Identificacao

- projeto: Android
- CVE: CVE-2016-1621
- CWE atribuida pelo BigVul: CWE-119
- commit: `5a9753fca56f0eeb9f61e342b2fccffc364f9426`
- URL do commit: https://android.googlesource.com/platform/external/libvpx/+/5a9753fca56f0eeb9f61e342b2fccffc364f9426
- arquivo da funcao marcada: `libvpx/test/variance_test.cc`

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
@@ -1,18 +1,15 @@
    virtual void SetUp() {
-    const tuple<int, int, SubpelVarianceFunctionType>& params =
-        this->GetParam();
+    const tuple<int, int, MseFunctionType>& params = this->GetParam();
      log2width_  = get<0>(params);
      width_ = 1 << log2width_;
      log2height_ = get<1>(params);
      height_ = 1 << log2height_;
-    subpel_variance_ = get<2>(params);
+    mse_ = get<2>(params);
  
      rnd(ACMRandom::DeterministicSeed());
      block_size_ = width_ * height_;
      src_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
-    sec_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
-    ref_ = new uint8_t[block_size_ + width_ + height_ + 1];
+    ref_ = new uint8_t[block_size_];
      ASSERT_TRUE(src_ != NULL);
-    ASSERT_TRUE(sec_ != NULL);
      ASSERT_TRUE(ref_ != NULL);
    }
```

## Corpo completo da funcao antes da correcao

```c
   virtual void SetUp() {
    const tuple<int, int, SubpelVarianceFunctionType>& params =
        this->GetParam();
     log2width_  = get<0>(params);
     width_ = 1 << log2width_;
     log2height_ = get<1>(params);
     height_ = 1 << log2height_;
    subpel_variance_ = get<2>(params);
 
     rnd(ACMRandom::DeterministicSeed());
     block_size_ = width_ * height_;
     src_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
    sec_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
    ref_ = new uint8_t[block_size_ + width_ + height_ + 1];
     ASSERT_TRUE(src_ != NULL);
    ASSERT_TRUE(sec_ != NULL);
     ASSERT_TRUE(ref_ != NULL);
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
| `libvpx/test/cpu_speed_test.cc` |  |  |  |
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
| `libvpx/test/variance_test.cc` **(funcao marcada esta aqui)** |  |  |  |
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


### `libvpx/test/variance_test.cc`

```diff
@@ -7,111 +7,271 @@

  *  in the file PATENTS.  All contributing project authors may
  *  be found in the AUTHORS file in the root of the source tree.
  */
-#include <stdlib.h>
+
+#include <cstdlib>
 #include <new>
 
 #include "third_party/googletest/src/include/gtest/gtest.h"
 
+#include "./vpx_config.h"
+#include "./vpx_dsp_rtcd.h"
+#include "test/acm_random.h"
 #include "test/clear_system_state.h"
 #include "test/register_state_check.h"
-
+#include "vpx/vpx_codec.h"
 #include "vpx/vpx_integer.h"
-#include "./vpx_config.h"
 #include "vpx_mem/vpx_mem.h"
-#if CONFIG_VP8_ENCODER
-# include "./vp8_rtcd.h"
-# include "vp8/common/variance.h"
-#endif
-#if CONFIG_VP9_ENCODER
-# include "./vp9_rtcd.h"
-# include "vp9/encoder/vp9_variance.h"
-#endif
-#include "test/acm_random.h"
+#include "vpx_ports/mem.h"
 
 namespace {
 
+typedef unsigned int (*VarianceMxNFunc)(const uint8_t *a, int a_stride,
+                                        const uint8_t *b, int b_stride,
+                                        unsigned int *sse);
+typedef unsigned int (*SubpixVarMxNFunc)(const uint8_t *a, int a_stride,
+                                         int xoffset, int yoffset,
+                                         const uint8_t *b, int b_stride,
+                                         unsigned int *sse);
+typedef unsigned int (*SubpixAvgVarMxNFunc)(const uint8_t *a, int a_stride,
+                                            int xoffset, int yoffset,
+                                            const uint8_t *b, int b_stride,
+                                            uint32_t *sse,
+                                            const uint8_t *second_pred);
+typedef unsigned int (*Get4x4SseFunc)(const uint8_t *a, int a_stride,
+                                      const uint8_t *b, int b_stride);
+typedef unsigned int (*SumOfSquaresFunction)(const int16_t *src);
+
+
 using ::std::tr1::get;
 using ::std::tr1::make_tuple;
 using ::std::tr1::tuple;
 using libvpx_test::ACMRandom;
 
-static unsigned int variance_ref(const uint8_t *ref, const uint8_t *src,
-                                 int l2w, int l2h, unsigned int *sse_ptr) {
-  int se = 0;
-  unsigned int sse = 0;
-  const int w = 1 << l2w, h = 1 << l2h;
-  for (int y = 0; y < h; y++) {
-    for (int x = 0; x < w; x++) {
-      int diff = ref[w * y + x] - src[w * y + x];
-      se += diff;
-      sse += diff * diff;
-    }
+// Truncate high bit depth results by downshifting (with rounding) by:
+// 2 * (bit_depth - 8) for sse
+// (bit_depth - 8) for se
+static void RoundHighBitDepth(int bit_depth, int64_t *se, uint64_t *sse) {
+  switch (bit_depth) {
+    case VPX_BITS_12:
+      *sse = (*sse + 128) >> 8;
+      *se = (*se + 8) >> 4;
+      break;
+    case VPX_BITS_10:
+      *sse = (*sse + 8) >> 4;
+      *se = (*se + 2) >> 2;
+      break;
+    case VPX_BITS_8:
+    default:
+      break;
   }
-  *sse_ptr = sse;
-  return sse - (((int64_t) se * se) >> (l2w + l2h));
 }
 
-static unsigned int subpel_variance_ref(const uint8_t *ref, const uint8_t *src,
-                                        int l2w, int l2h, int xoff, int yoff,
-                                        unsigned int *sse_ptr) {
-  int se = 0;
-  unsigned int sse = 0;
-  const int w = 1 << l2w, h = 1 << l2h;
+static unsigned int mb_ss_ref(const int16_t *src) {
+  unsigned int res = 0;
+  for (int i = 0; i < 256; ++i) {
+    res += src[i] * src[i];
+  }
+  return res;
+}
+
+static uint32_t variance_ref(const uint8_t *src, const uint8_t *ref,
+                             int l2w, int l2h, int src_stride_coeff,
+                             int ref_stride_coeff, uint32_t *sse_ptr,
+                             bool use_high_bit_depth_,
+                             vpx_bit_depth_t bit_depth) {
+  int64_t se = 0;
+  uint64_t sse = 0;
+  const int w = 1 << l2w;
+  const int h = 1 << l2h;
   for (int y = 0; y < h; y++) {
     for (int x = 0; x < w; x++) {
-      // bilinear interpolation at a 16th pel step
-      const int a1 = ref[(w + 1) * (y + 0) + x + 0];
-      const int a2 = ref[(w + 1) * (y + 0) + x + 1];
-      const int b1 = ref[(w + 1) * (y + 1) + x + 0];
-      const int b2 = ref[(w + 1) * (y + 1) + x + 1];
-      const int a = a1 + (((a2 - a1) * xoff + 8) >> 4);
-      const int b = b1 + (((b2 - b1) * xoff + 8) >> 4);
-      const int r = a + (((b - a) * yoff + 8) >> 4);
-      int diff = r - src[w * y + x];
-      se += diff;
-      sse += diff * diff;
+      int diff;
+      if (!use_high_bit_depth_) {
+        diff = ref[w * y * ref_stride_coeff + x] -
+               src[w * y * src_stride_coeff + x];
+        se += diff;
+        sse += diff * diff;
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        diff = CONVERT_TO_SHORTPTR(ref)[w * y * ref_stride_coeff + x] -
+               CONVERT_TO_SHORTPTR(src)[w * y * src_stride_coeff + x];
+        se += diff;
+        sse += diff * diff;
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+      }
     }
   }
-  *sse_ptr = sse;
-  return sse - (((int64_t) se * se) >> (l2w + l2h));
+  RoundHighBitDepth(bit_depth, &se, &sse);
+  *sse_ptr = static_cast<uint32_t>(sse);
+  return static_cast<uint32_t>(sse -
+                               ((static_cast<int64_t>(se) * se) >>
+                                (l2w + l2h)));
+}
+
+/* The subpel reference functions differ from the codec version in one aspect:
+ * they calculate the bilinear factors directly instead of using a lookup table
+ * and therefore upshift xoff and yoff by 1. Only every other calculated value
+ * is used so the codec version shrinks the table to save space and maintain
+ * compatibility with vp8.
+ */
+static uint32_t subpel_variance_ref(const uint8_t *ref, const uint8_t *src,
+                                    int l2w, int l2h, int xoff, int yoff,
+                                    uint32_t *sse_ptr,
+                                    bool use_high_bit_depth_,
+                                    vpx_bit_depth_t bit_depth) {
+  int64_t se = 0;
+  uint64_t sse = 0;
+  const int w = 1 << l2w;
+  const int h = 1 << l2h;
+
+  xoff <<= 1;
+  yoff <<= 1;
+
+  for (int y = 0; y < h; y++) {
+    for (int x = 0; x < w; x++) {
+      // Bilinear interpolation at a 16th pel step.
+      if (!use_high_bit_depth_) {
+        const int a1 = ref[(w + 1) * (y + 0) + x + 0];
+        const int a2 = ref[(w + 1) * (y + 0) + x + 1];
+        const int b1 = ref[(w + 1) * (y + 1) + x + 0];
+        const int b2 = ref[(w + 1) * (y + 1) + x + 1];
+        const int a = a1 + (((a2 - a1) * xoff + 8) >> 4);
+        const int b = b1 + (((b2 - b1) * xoff + 8) >> 4);
+        const int r = a + (((b - a) * yoff + 8) >> 4);
+        const int diff = r - src[w * y + x];
+        se += diff;
+        sse += diff * diff;
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        uint16_t *ref16 = CONVERT_TO_SHORTPTR(ref);
+        uint16_t *src16 = CONVERT_TO_SHORTPTR(src);
+        const int a1 = ref16[(w + 1) * (y + 0) + x + 0];
+        const int a2 = ref16[(w + 1) * (y + 0) + x + 1];
+        const int b1 = ref16[(w + 1) * (y + 1) + x + 0];
+        const int b2 = ref16[(w + 1) * (y + 1) + x + 1];
+        const int a = a1 + (((a2 - a1) * xoff + 8) >> 4);
+        const int b = b1 + (((b2 - b1) * xoff + 8) >> 4);
+        const int r = a + (((b - a) * yoff + 8) >> 4);
+        const int diff = r - src16[w * y + x];
+        se += diff;
+        sse += diff * diff;
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+      }
+    }
+  }
+  RoundHighBitDepth(bit_depth, &se, &sse);
+  *sse_ptr = static_cast<uint32_t>(sse);
+  return static_cast<uint32_t>(sse -
+                               ((static_cast<int64_t>(se) * se) >>
+                                (l2w + l2h)));
+}
+
+class SumOfSquaresTest : public ::testing::TestWithParam<SumOfSquaresFunction> {
+ public:
+  SumOfSquaresTest() : func_(GetParam()) {}
+
+  virtual ~SumOfSquaresTest() {
+    libvpx_test::ClearSystemState();
+  }
+
+ protected:
+  void ConstTest();
+  void RefTest();
+
+  SumOfSquaresFunction func_;
+  ACMRandom rnd_;
+};
+
+void SumOfSquaresTest::ConstTest() {
+  int16_t mem[256];
+  unsigned int res;
+  for (int v = 0; v < 256; ++v) {
+    for (int i = 0; i < 256; ++i) {
+      mem[i] = v;
+    }
+    ASM_REGISTER_STATE_CHECK(res = func_(mem));
+    EXPECT_EQ(256u * (v * v), res);
+  }
+}
+
+void SumOfSquaresTest::RefTest() {
+  int16_t mem[256];
+  for (int i = 0; i < 100; ++i) {
+    for (int j = 0; j < 256; ++j) {
+      mem[j] = rnd_.Rand8() - rnd_.Rand8();
+    }
+
+    const unsigned int expected = mb_ss_ref(mem);
+    unsigned int res;
+    ASM_REGISTER_STATE_CHECK(res = func_(mem));
+    EXPECT_EQ(expected, res);
+  }
 }
 
 template<typename VarianceFunctionType>
 class VarianceTest
-    : public ::testing::TestWithParam<tuple<int, int, VarianceFunctionType> > {
+    : public ::testing::TestWithParam<tuple<int, int,
+                                            VarianceFunctionType, int> > {
  public:
   virtual void SetUp() {
-    const tuple<int, int, VarianceFunctionType>& params = this->GetParam();
+    const tuple<int, int, VarianceFunctionType, int>& params = this->GetParam();
     log2width_  = get<0>(params);
     width_ = 1 << log2width_;
     log2height_ = get<1>(params);
     height_ = 1 << log2height_;
     variance_ = get<2>(params);
+    if (get<3>(params)) {
+      bit_depth_ = static_cast<vpx_bit_depth_t>(get<3>(params));
+      use_high_bit_depth_ = true;
+    } else {
+      bit_depth_ = VPX_BITS_8;
+      use_high_bit_depth_ = false;
+    }
+    mask_ = (1 << bit_depth_) - 1;
 
-    rnd(ACMRandom::DeterministicSeed());
+    rnd_.Reset(ACMRandom::DeterministicSeed());
     block_size_ = width_ * height_;
-    src_ = new uint8_t[block_size_];
-    ref_ = new uint8_t[block_size_];
+    if (!use_high_bit_depth_) {
+      src_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_ * 2));
+      ref_ = new uint8_t[block_size_ * 2];
+#if CONFIG_VP9_HIGHBITDEPTH
+    } else {
+      src_ = CONVERT_TO_BYTEPTR(reinterpret_cast<uint16_t *>(
+          vpx_memalign(16, block_size_ * 2 * sizeof(uint16_t))));
+      ref_ = CONVERT_TO_BYTEPTR(new uint16_t[block_size_ * 2]);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+    }
     ASSERT_TRUE(src_ != NULL);
     ASSERT_TRUE(ref_ != NULL);
   }
 
   virtual void TearDown() {
-    delete[] src_;
-    delete[] ref_;
+    if (!use_high_bit_depth_) {
+      vpx_free(src_);
+      delete[] ref_;
+#if CONFIG_VP9_HIGHBITDEPTH
+    } else {
+      vpx_free(CONVERT_TO_SHORTPTR(src_));
+      delete[] CONVERT_TO_SHORTPTR(ref_);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+    }
     libvpx_test::ClearSystemState();
   }
 
  protected:
   void ZeroTest();
   void RefTest();
+  void RefStrideTest();
   void OneQuarterTest();
 
-  ACMRandom rnd;
-  uint8_t* src_;
-  uint8_t* ref_;
+  ACMRandom rnd_;
+  uint8_t *src_;
+  uint8_t *ref_;
   int width_, log2width_;
   int height_, log2height_;
+  vpx_bit_depth_t bit_depth_;
+  int mask_;
+  bool use_high_bit_depth_;
   int block_size_;
   VarianceFunctionType variance_;
 };
@@ -119,13 +279,28 @@

 template<typename VarianceFunctionType>
 void VarianceTest<VarianceFunctionType>::ZeroTest() {
   for (int i = 0; i <= 255; ++i) {
-    memset(src_, i, block_size_);
+    if (!use_high_bit_depth_) {
+      memset(src_, i, block_size_);
+#if CONFIG_VP9_HIGHBITDEPTH
+    } else {
+      vpx_memset16(CONVERT_TO_SHORTPTR(src_), i << (bit_depth_ - 8),
+                   block_size_);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+    }
     for (int j = 0; j <= 255; ++j) {
-      memset(ref_, j, block_size_);
+      if (!use_high_bit_depth_) {
+        memset(ref_, j, block_size_);
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        vpx_memset16(CONVERT_TO_SHORTPTR(ref_), j  << (bit_depth_ - 8),
+                     block_size_);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+      }
       unsigned int sse;
       unsigned int var;
-      REGISTER_STATE_CHECK(var = variance_(src_, width_, ref_, width_, &sse));
-      EXPECT_EQ(0u, var) << "src values: " << i << "ref values: " << j;
+      ASM_REGISTER_STATE_CHECK(
+          var = variance_(src_, width_, ref_, width_, &sse));
+      EXPECT_EQ(0u, var) << "src values: " << i << " ref values: " << j;
     }
   }
 }
@@ -134,14 +309,58 @@

 void VarianceTest<VarianceFunctionType>::RefTest() {
   for (int i = 0; i < 10; ++i) {
     for (int j = 0; j < block_size_; j++) {
-      src_[j] = rnd.Rand8();
-      ref_[j] = rnd.Rand8();
+    if (!use_high_bit_depth_) {
+      src_[j] = rnd_.Rand8();
+      ref_[j] = rnd_.Rand8();
+#if CONFIG_VP9_HIGHBITDEPTH
+    } else {
+      CONVERT_TO_SHORTPTR(src_)[j] = rnd_.Rand16() && mask_;
+      CONVERT_TO_SHORTPTR(ref_)[j] = rnd_.Rand16() && mask_;
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+    }
     }
     unsigned int sse1, sse2;
     unsigned int var1;
-    REGISTER_STATE_CHECK(var1 = variance_(src_, width_, ref_, width_, &sse1));
+    const int stride_coeff = 1;
+    ASM_REGISTER_STATE_CHECK(
+        var1 = variance_(src_, width_, ref_, width_, &sse1));
     const unsigned int var2 = variance_ref(src_, ref_, log2width_,
-                                           log2height_, &sse2);
+                                           log2height_, stride_coeff,
+                                           stride_coeff, &sse2,
+                                           use_high_bit_depth_, bit_depth_);
+    EXPECT_EQ(sse1, sse2);
+    EXPECT_EQ(var1, var2);
+  }
+}
+
+template<typename VarianceFunctionType>
+void VarianceTest<VarianceFunctionType>::RefStrideTest() {
+  for (int i = 0; i < 10; ++i) {
+    int ref_stride_coeff = i % 2;
+    int src_stride_coeff = (i >> 1) % 2;
+    for (int j = 0; j < block_size_; j++) {
+      int ref_ind = (j / width_) * ref_stride_coeff * width_ + j % width_;
+      int src_ind = (j / width_) * src_stride_coeff * width_ + j % width_;
+      if (!use_high_bit_depth_) {
+        src_[src_ind] = rnd_.Rand8();
+        ref_[ref_ind] = rnd_.Rand8();
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        CONVERT_TO_SHORTPTR(src_)[src_ind] = rnd_.Rand16() && mask_;
+        CONVERT_TO_SHORTPTR(ref_)[ref_ind] = rnd_.Rand16() && mask_;
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+      }
+    }
+    unsigned int sse1, sse2;
+    unsigned int var1;
+
+    ASM_REGISTER_STATE_CHECK(
+        var1 = variance_(src_, width_ * src_stride_coeff,
+                         ref_, width_ * ref_stride_coeff, &sse1));
+    const unsigned int var2 = variance_ref(src_, ref_, log2width_,
+                                           log2height_, src_stride_coeff,
+                                           ref_stride_coeff, &sse2,
+                                           use_high_bit_depth_, bit_depth_);
     EXPECT_EQ(sse1, sse2);
     EXPECT_EQ(var1, var2);
   }
@@ -149,561 +368,1673 @@

 
 template<typename VarianceFunctionType>
 void VarianceTest<VarianceFunctionType>::OneQuarterTest() {
-  memset(src_, 255, block_size_);
   const int half = block_size_ / 2;
-  memset(ref_, 255, half);
-  memset(ref_ + half, 0, half);
+  if (!use_high_bit_depth_) {
+    memset(src_, 255, block_size_);
+    memset(ref_, 255, half);
+    memset(ref_ + half, 0, half);
+#if CONFIG_VP9_HIGHBITDEPTH
+  } else {
+    vpx_memset16(CONVERT_TO_SHORTPTR(src_), 255 << (bit_depth_ - 8),
+                 block_size_);
+    vpx_memset16(CONVERT_TO_SHORTPTR(ref_), 255 << (bit_depth_ - 8), half);
+    vpx_memset16(CONVERT_TO_SHORTPTR(ref_) + half, 0, half);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+  }
   unsigned int sse;
   unsigned int var;
-  REGISTER_STATE_CHECK(var = variance_(src_, width_, ref_, width_, &sse));
+  ASM_REGISTER_STATE_CHECK(var = variance_(src_, width_, ref_, width_, &sse));
   const unsigned int expected = block_size_ * 255 * 255 / 4;
   EXPECT_EQ(expected, var);
 }
 
-#if CONFIG_VP9_ENCODER
-
-unsigned int subpel_avg_variance_ref(const uint8_t *ref,
-                                     const uint8_t *src,
-                                     const uint8_t *second_pred,
-                                     int l2w, int l2h,
-                                     int xoff, int yoff,
-                                     unsigned int *sse_ptr) {
-  int se = 0;
-  unsigned int sse = 0;
-  const int w = 1 << l2w, h = 1 << l2h;
-  for (int y = 0; y < h; y++) {
-    for (int x = 0; x < w; x++) {
-      // bilinear interpolation at a 16th pel step
-      const int a1 = ref[(w + 1) * (y + 0) + x + 0];
-      const int a2 = ref[(w + 1) * (y + 0) + x + 1];
-      const int b1 = ref[(w + 1) * (y + 1) + x + 0];
-      const int b2 = ref[(w + 1) * (y + 1) + x + 1];
-      const int a = a1 + (((a2 - a1) * xoff + 8) >> 4);
-      const int b = b1 + (((b2 - b1) * xoff + 8) >> 4);
-      const int r = a + (((b - a) * yoff + 8) >> 4);
-      int diff = ((r + second_pred[w * y + x] + 1) >> 1) - src[w * y + x];
-      se += diff;
-      sse += diff * diff;
-    }
-  }
-  *sse_ptr = sse;
-  return sse - (((int64_t) se * se) >> (l2w + l2h));
-}
-
-template<typename SubpelVarianceFunctionType>
-class SubpelVarianceTest
-    : public ::testing::TestWithParam<tuple<int, int,
-                                            SubpelVarianceFunctionType> > {
+template<typename MseFunctionType>
+class MseTest
+    : public ::testing::TestWithParam<tuple<int, int, MseFunctionType> > {
  public:
   virtual void SetUp() {
-    const tuple<int, int, SubpelVarianceFunctionType>& params =
-        this->GetParam();
+    const tuple<int, int, MseFunctionType>& params = this->GetParam();
     log2width_  = get<0>(params);
     width_ = 1 << log2width_;
     log2height_ = get<1>(params);
     height_ = 1 << log2height_;
-    subpel_variance_ = get<2>(params);
+    mse_ = get<2>(params);
 
     rnd(ACMRandom::DeterministicSeed());
     block_size_ = width_ * height_;
     src_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
-    sec_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
-    ref_ = new uint8_t[block_size_ + width_ + height_ + 1];
+    ref_ = new uint8_t[block_size_];
     ASSERT_TRUE(src_ != NULL);
-    ASSERT_TRUE(sec_ != NULL);
     ASSERT_TRUE(ref_ != NULL);
   }
 
   virtual void TearDown() {
     vpx_free(src_);
     delete[] ref_;
-    vpx_free(sec_);
+    libvpx_test::ClearSystemState();
+  }
+
+ protected:
+  void RefTest_mse();
+  void RefTest_sse();
+  void MaxTest_mse();
+  void MaxTest_sse();
+
+  ACMRandom rnd;
+  uint8_t* src_;
+  uint8_t* ref_;
+  int width_, log2width_;
+  int height_, log2height_;
+  int block_size_;
+  MseFunctionType mse_;
+};
+
+template<typename MseFunctionType>
+void MseTest<MseFunctionType>::RefTest_mse() {
+  for (int i = 0; i < 10; ++i) {
+    for (int j = 0; j < block_size_; j++) {
+      src_[j] = rnd.Rand8();
+      ref_[j] = rnd.Rand8();
+    }
+    unsigned int sse1, sse2;
+    const int stride_coeff = 1;
+    ASM_REGISTER_STATE_CHECK(mse_(src_, width_, ref_, width_, &sse1));
+    variance_ref(src_, ref_, log2width_, log2height_, stride_coeff,
+                 stride_coeff, &sse2, false, VPX_BITS_8);
+    EXPECT_EQ(sse1, sse2);
+  }
+}
+
+template<typename MseFunctionType>
+void MseTest<MseFunctionType>::RefTest_sse() {
+  for (int i = 0; i < 10; ++i) {
+    for (int j = 0; j < block_size_; j++) {
+      src_[j] = rnd.Rand8();
+      ref_[j] = rnd.Rand8();
+    }
+    unsigned int sse2;
+    unsigned int var1;
+    const int stride_coeff = 1;
+    ASM_REGISTER_STATE_CHECK(var1 = mse_(src_, width_, ref_, width_));
+    variance_ref(src_, ref_, log2width_, log2height_, stride_coeff,
+                 stride_coeff, &sse2, false, VPX_BITS_8);
+    EXPECT_EQ(var1, sse2);
+  }
+}
+
+template<typename MseFunctionType>
+void MseTest<MseFunctionType>::MaxTest_mse() {
+  memset(src_, 255, block_size_);
+  memset(ref_, 0, block_size_);
+  unsigned int sse;
+  ASM_REGISTER_STATE_CHECK(mse_(src_, width_, ref_, width_, &sse));
+  const unsigned int expected = block_size_ * 255 * 255;
+  EXPECT_EQ(expected, sse);
+}
+
+template<typename MseFunctionType>
+void MseTest<MseFunctionType>::MaxTest_sse() {
+  memset(src_, 255, block_size_);
+  memset(ref_, 0, block_size_);
+  unsigned int var;
+  ASM_REGISTER_STATE_CHECK(var = mse_(src_, width_, ref_, width_));
+  const unsigned int expected = block_size_ * 255 * 255;
+  EXPECT_EQ(expected, var);
+}
+
+static uint32_t subpel_avg_variance_ref(const uint8_t *ref,
+                                        const uint8_t *src,
+                                        const uint8_t *second_pred,
+                                        int l2w, int l2h,
+                                        int xoff, int yoff,
+                                        uint32_t *sse_ptr,
+                                        bool use_high_bit_depth,
+                                        vpx_bit_depth_t bit_depth) {
+  int64_t se = 0;
+  uint64_t sse = 0;
+  const int w = 1 << l2w;
+  const int h = 1 << l2h;
+
+  xoff <<= 1;
+  yoff <<= 1;
+
+  for (int y = 0; y < h; y++) {
+    for (int x = 0; x < w; x++) {
+      // bilinear interpolation at a 16th pel step
+      if (!use_high_bit_depth) {
+        const int a1 = ref[(w + 1) * (y + 0) + x + 0];
+        const int a2 = ref[(w + 1) * (y + 0) + x + 1];
+        const int b1 = ref[(w + 1) * (y + 1) + x + 0];
+        const int b2 = ref[(w + 1) * (y + 1) + x + 1];
+        const int a = a1 + (((a2 - a1) * xoff + 8) >> 4);
+        const int b = b1 + (((b2 - b1) * xoff + 8) >> 4);
+        const int r = a + (((b - a) * yoff + 8) >> 4);
+        const int diff = ((r + second_pred[w * y + x] + 1) >> 1) - src[w * y + x];
+        se += diff;
+        sse += diff * diff;
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        uint16_t *ref16 = CONVERT_TO_SHORTPTR(ref);
+        uint16_t *src16 = CONVERT_TO_SHORTPTR(src);
+        uint16_t *sec16   = CONVERT_TO_SHORTPTR(second_pred);
+        const int a1 = ref16[(w + 1) * (y + 0) + x + 0];
+        const int a2 = ref16[(w + 1) * (y + 0) + x + 1];
+        const int b1 = ref16[(w + 1) * (y + 1) + x + 0];
+        const int b2 = ref16[(w + 1) * (y + 1) + x + 1];
+        const int a = a1 + (((a2 - a1) * xoff + 8) >> 4);
+        const int b = b1 + (((b2 - b1) * xoff + 8) >> 4);
+        const int r = a + (((b - a) * yoff + 8) >> 4);
+        const int diff = ((r + sec16[w * y + x] + 1) >> 1) - src16[w * y + x];
+        se += diff;
+        sse += diff * diff;
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+      }
+    }
+  }
+  RoundHighBitDepth(bit_depth, &se, &sse);
+  *sse_ptr = static_cast<uint32_t>(sse);
+  return static_cast<uint32_t>(sse -
+                               ((static_cast<int64_t>(se) * se) >>
+                                (l2w + l2h)));
+}
+
+template<typename SubpelVarianceFunctionType>
+class SubpelVarianceTest
+    : public ::testing::TestWithParam<tuple<int, int,
+                                            SubpelVarianceFunctionType, int> > {
+ public:
+  virtual void SetUp() {
+    const tuple<int, int, SubpelVarianceFunctionType, int>& params =
+        this->GetParam();
+    log2width_  = get<0>(params);
+    width_ = 1 << log2width_;
+    log2height_ = get<1>(params);
+    height_ = 1 << log2height_;
+    subpel_variance_ = get<2>(params);
+    if (get<3>(params)) {
+      bit_depth_ = (vpx_bit_depth_t) get<3>(params);
+      use_high_bit_depth_ = true;
+    } else {
+      bit_depth_ = VPX_BITS_8;
+      use_high_bit_depth_ = false;
+    }
+    mask_ = (1 << bit_depth_)-1;
+
+    rnd_.Reset(ACMRandom::DeterministicSeed());
+    block_size_ = width_ * height_;
+    if (!use_high_bit_depth_) {
+      src_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
+      sec_ = reinterpret_cast<uint8_t *>(vpx_memalign(16, block_size_));
+      ref_ = new uint8_t[block_size_ + width_ + height_ + 1];
+#if CONFIG_VP9_HIGHBITDEPTH
+    } else {
+      src_ = CONVERT_TO_BYTEPTR(
+          reinterpret_cast<uint16_t *>(
+              vpx_memalign(16, block_size_*sizeof(uint16_t))));
+      sec_ = CONVERT_TO_BYTEPTR(
+          reinterpret_cast<uint16_t *>(
+              vpx_memalign(16, block_size_*sizeof(uint16_t))));
+      ref_ = CONVERT_TO_BYTEPTR(
+          new uint16_t[block_size_ + width_ + height_ + 1]);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+    }
+    ASSERT_TRUE(src_ != NULL);
+    ASSERT_TRUE(sec_ != NULL);
+    ASSERT_TRUE(ref_ != NULL);
+  }
+
+  virtual void TearDown() {
+    if (!use_high_bit_depth_) {
+      vpx_free(src_);
+      delete[] ref_;
+      vpx_free(sec_);
+#if CONFIG_VP9_HIGHBITDEPTH
+    } else {
+      vpx_free(CONVERT_TO_SHORTPTR(src_));
+      delete[] CONVERT_TO_SHORTPTR(ref_);
+      vpx_free(CONVERT_TO_SHORTPTR(sec_));
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+    }
     libvpx_test::ClearSystemState();
   }
 
  protected:
   void RefTest();
+  void ExtremeRefTest();
 
-  ACMRandom rnd;
+  ACMRandom rnd_;
   uint8_t *src_;
   uint8_t *ref_;
   uint8_t *sec_;
+  bool use_high_bit_depth_;
+  vpx_bit_depth_t bit_depth_;
   int width_, log2width_;
   int height_, log2height_;
-  int block_size_;
+  int block_size_,  mask_;
   SubpelVarianceFunctionType subpel_variance_;
 };
 
 template<typename SubpelVarianceFunctionType>
 void SubpelVarianceTest<SubpelVarianceFunctionType>::RefTest() {
-  for (int x = 0; x < 16; ++x) {
-    for (int y = 0; y < 16; ++y) {
-      for (int j = 0; j < block_size_; j++) {
-        src_[j] = rnd.Rand8();
-      }
-      for (int j = 0; j < block_size_ + width_ + height_ + 1; j++) {
-        ref_[j] = rnd.Rand8();
+  for (int x = 0; x < 8; ++x) {
+    for (int y = 0; y < 8; ++y) {
+      if (!use_high_bit_depth_) {
+        for (int j = 0; j < block_size_; j++) {
+          src_[j] = rnd_.Rand8();
+        }
+        for (int j = 0; j < block_size_ + width_ + height_ + 1; j++) {
+          ref_[j] = rnd_.Rand8();
+        }
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        for (int j = 0; j < block_size_; j++) {
+          CONVERT_TO_SHORTPTR(src_)[j] = rnd_.Rand16() & mask_;
+        }
+        for (int j = 0; j < block_size_ + width_ + height_ + 1; j++) {
+          CONVERT_TO_SHORTPTR(ref_)[j] = rnd_.Rand16() & mask_;
+        }
+#endif  // CONFIG_VP9_HIGHBITDEPTH
       }
       unsigned int sse1, sse2;
       unsigned int var1;
-      REGISTER_STATE_CHECK(var1 = subpel_variance_(ref_, width_ + 1, x, y,
-                                                   src_, width_, &sse1));
-      const unsigned int var2 = subpel_variance_ref(ref_, src_, log2width_,
-                                                    log2height_, x, y, &sse2);
+      ASM_REGISTER_STATE_CHECK(var1 = subpel_variance_(ref_, width_ + 1, x, y,
+                                                       src_, width_, &sse1));
+      const unsigned int var2 = subpel_variance_ref(ref_, src_,
+                                                    log2width_, log2height_,
+                                                    x, y, &sse2,
+                                                    use_high_bit_depth_,
+                                                    bit_depth_);
       EXPECT_EQ(sse1, sse2) << "at position " << x << ", " << y;
       EXPECT_EQ(var1, var2) << "at position " << x << ", " << y;
     }
   }
 }
 
+template<typename SubpelVarianceFunctionType>
+void SubpelVarianceTest<SubpelVarianceFunctionType>::ExtremeRefTest() {
+  // Compare against reference.
+  // Src: Set the first half of values to 0, the second half to the maximum.
+  // Ref: Set the first half of values to the maximum, the second half to 0.
+  for (int x = 0; x < 8; ++x) {
+    for (int y = 0; y < 8; ++y) {
+      const int half = block_size_ / 2;
+      if (!use_high_bit_depth_) {
+        memset(src_, 0, half);
+        memset(src_ + half, 255, half);
+        memset(ref_, 255, half);
+        memset(ref_ + half, 0, half + width_ + height_ + 1);
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        vpx_memset16(CONVERT_TO_SHORTPTR(src_), mask_, half);
+        vpx_memset16(CONVERT_TO_SHORTPTR(src_) + half, 0, half);
+        vpx_memset16(CONVERT_TO_SHORTPTR(ref_), 0, half);
+        vpx_memset16(CONVERT_TO_SHORTPTR(ref_) + half, mask_,
+                     half + width_ + height_ + 1);
+#endif  // CONFIG_VP9_HIGHBITDEPTH
+      }
+      unsigned int sse1, sse2;
+      unsigned int var1;
+      ASM_REGISTER_STATE_CHECK(
+          var1 = subpel_variance_(ref_, width_ + 1, x, y, src_, width_, &sse1));
+      const unsigned int var2 =
+          subpel_variance_ref(ref_, src_, log2width_, log2height_,
+                              x, y, &sse2, use_high_bit_depth_, bit_depth_);
+      EXPECT_EQ(sse1, sse2) << "for xoffset " << x << " and yoffset " << y;
+      EXPECT_EQ(var1, var2) << "for xoffset " << x << " and yoffset " << y;
+    }
+  }
+}
+
 template<>
-void SubpelVarianceTest<vp9_subp_avg_variance_fn_t>::RefTest() {
-  for (int x = 0; x < 16; ++x) {
-    for (int y = 0; y < 16; ++y) {
-      for (int j = 0; j < block_size_; j++) {
-        src_[j] = rnd.Rand8();
-        sec_[j] = rnd.Rand8();
-      }
-      for (int j = 0; j < block_size_ + width_ + height_ + 1; j++) {
-        ref_[j] = rnd.Rand8();
+void SubpelVarianceTest<SubpixAvgVarMxNFunc>::RefTest() {
+  for (int x = 0; x < 8; ++x) {
+    for (int y = 0; y < 8; ++y) {
+      if (!use_high_bit_depth_) {
+        for (int j = 0; j < block_size_; j++) {
+          src_[j] = rnd_.Rand8();
+          sec_[j] = rnd_.Rand8();
+        }
+        for (int j = 0; j < block_size_ + width_ + height_ + 1; j++) {
+          ref_[j] = rnd_.Rand8();
+        }
+#if CONFIG_VP9_HIGHBITDEPTH
+      } else {
+        for (int j = 0; j < block_size_; j++) {
+          CONVERT_TO_SHORTPTR(src_)[j] = rnd_.Rand16() & mask_;
+          CONVERT_TO_SHORTPTR(sec_)[j] = rnd_.Rand16() & mask_;
+        }
+        for (int j = 0; j < block_size_ + width_ + height_ + 1; j++) {
+          CONVERT_TO_SHORTPTR(ref_)[j] = rnd_.Rand16() & mask_;
+        }
+#endif  // CONFIG_VP9_HIGHBITDEPTH
       }
       unsigned int sse1, sse2;
       unsigned int var1;
-      REGISTER_STATE_CHECK(var1 = subpel_variance_(ref_, width_ + 1, x, y,
-                                                   src_, width_, &sse1, sec_));
+      ASM_REGISTER_STATE_CHECK(
+          var1 = subpel_variance_(ref_, width_ + 1, x, y,
+                                  src_, width_, &sse1, sec_));
       const unsigned int var2 = subpel_avg_variance_ref(ref_, src_, sec_,
                                                         log2width_, log2height_,
-                                                        x, y, &sse2);
+                                                        x, y, &sse2,
+                                                        use_high_bit_depth_,
+                                                        bit_depth_);
       EXPECT_EQ(sse1, sse2) << "at position " << x << ", " << y;
       EXPECT_EQ(var1, var2) << "at position " << x << ", " << y;
     }
   }
 }
 
-#endif  // CONFIG_VP9_ENCODER
+typedef MseTest<Get4x4SseFunc> VpxSseTest;
+typedef MseTest<VarianceMxNFunc> VpxMseTest;
+typedef VarianceTest<VarianceMxNFunc> VpxVarianceTest;
+typedef SubpelVarianceTest<SubpixVarMxNFunc> VpxSubpelVarianceTest;
+typedef SubpelVarianceTest<SubpixAvgVarMxNFunc> VpxSubpelAvgVarianceTest;
 
-// -----------------------------------------------------------------------------
-// VP8 test cases.
+TEST_P(VpxSseTest, Ref_sse) { RefTest_sse(); }
+TEST_P(VpxSseTest, Max_sse) { MaxTest_sse(); }
+TEST_P(VpxMseTest, Ref_mse) { RefTest_mse(); }
+TEST_P(VpxMseTest, Max_mse) { MaxTest_mse(); }
+TEST_P(VpxVarianceTest, Zero) { ZeroTest(); }
+TEST_P(VpxVarianceTest, Ref) { RefTest(); }
+TEST_P(VpxVarianceTest, RefStride) { RefStrideTest(); }
+TEST_P(VpxVarianceTest, OneQuarter) { OneQuarterTest(); }
+TEST_P(SumOfSquaresTest, Const) { ConstTest(); }
+TEST_P(SumOfSquaresTest, Ref) { RefTest(); }
+TEST_P(VpxSubpelVarianceTest, Ref) { RefTest(); }
+TEST_P(VpxSubpelVarianceTest, ExtremeRef) { ExtremeRefTest(); }
+TEST_P(VpxSubpelAvgVarianceTest, Ref) { RefTest(); }
 
-namespace vp8 {
+INSTANTIATE_TEST_CASE_P(C, SumOfSquaresTest,
+                        ::testing::Values(vpx_get_mb_ss_c));
 
-#if CONFIG_VP8_ENCODER
-typedef VarianceTest<vp8_variance_fn_t> VP8VarianceTest;
+const Get4x4SseFunc get4x4sse_cs_c = vpx_get4x4sse_cs_c;
+INSTANTIATE_TEST_CASE_P(C, VpxSseTest,
+                        ::testing::Values(make_tuple(2, 2, get4x4sse_cs_c)));
 
-TEST_P(VP8VarianceTest, Zero) { ZeroTest(); }
-TEST_P(VP8VarianceTest, Ref) { RefTest(); }
-TEST_P(VP8VarianceTest, OneQuarter) { OneQuarterTest(); }
+const VarianceMxNFunc mse16x16_c = vpx_mse16x16_c;
+const VarianceMxNFunc mse16x8_c = vpx_mse16x8_c;
+const VarianceMxNFunc mse8x16_c = vpx_mse8x16_c;
+const VarianceMxNFunc mse8x8_c = vpx_mse8x8_c;
+INSTANTIATE_TEST_CASE_P(C, VpxMseTest,
+                        ::testing::Values(make_tuple(4, 4, mse16x16_c),
+                                          make_tuple(4, 3, mse16x8_c),
+                                          make_tuple(3, 4, mse8x16_c),
+                                          make_tuple(3, 3, mse8x8_c)));
 
-const vp8_variance_fn_t variance4x4_c = vp8_variance4x4_c;
-const vp8_variance_fn_t variance8x8_c = vp8_variance8x8_c;
-const vp8_variance_fn_t variance8x16_c = vp8_variance8x16_c;
-const vp8_variance_fn_t variance16x8_c = vp8_variance16x8_c;
-const vp8_variance_fn_t variance16x16_c = vp8_variance16x16_c;
+const VarianceMxNFunc variance64x64_c = vpx_variance64x64_c;
+const VarianceMxNFunc variance64x32_c = vpx_variance64x32_c;
+const VarianceMxNFunc variance32x64_c = vpx_variance32x64_c;
+const VarianceMxNFunc variance32x32_c = vpx_variance32x32_c;
+const VarianceMxNFunc variance32x16_c = vpx_variance32x16_c;
+const VarianceMxNFunc variance16x32_c = vpx_variance16x32_c;
+const VarianceMxNFunc variance16x16_c = vpx_variance16x16_c;
+const VarianceMxNFunc variance16x8_c = vpx_variance16x8_c;
+const VarianceMxNFunc variance8x16_c = vpx_variance8x16_c;
+const VarianceMxNFunc variance8x8_c = vpx_variance8x8_c;
+const VarianceMxNFunc variance8x4_c = vpx_variance8x4_c;
+const VarianceMxNFunc variance4x8_c = vpx_variance4x8_c;
+const VarianceMxNFunc variance4x4_c = vpx_variance4x4_c;
 INSTANTIATE_TEST_CASE_P(
-    C, VP8VarianceTest,
-    ::testing::Values(make_tuple(2, 2, variance4x4_c),
-                      make_tuple(3, 3, variance8x8_c),
-                      make_tuple(3, 4, variance8x16_c),
-                      make_tuple(4, 3, variance16x8_c),
-                      make_tuple(4, 4, variance16x16_c)));
+    C, VpxVarianceTest,
+    ::testing::Values(make_tuple(6, 6, variance64x64_c, 0),
+                      make_tuple(6, 5, variance64x32_c, 0),
+                      make_tuple(5, 6, variance32x64_c, 0),
+                      make_tuple(5, 5, variance32x32_c, 0),
+                      make_tuple(5, 4, variance32x16_c, 0),
+                      make_tuple(4, 5, variance16x32_c, 0),
+                      make_tuple(4, 4, variance16x16_c, 0),
+                      make_tuple(4, 3, variance16x8_c, 0),
+                      make_tuple(3, 4, variance8x16_c, 0),
+                      make_tuple(3, 3, variance8x8_c, 0),
+                      make_tuple(3, 2, variance8x4_c, 0),
+                      make_tuple(2, 3, variance4x8_c, 0),
+                      make_tuple(2, 2, variance4x4_c, 0)));
 
-#if HAVE_NEON
-const vp8_variance_fn_t variance8x8_neon = vp8_variance8x8_neon;
-const vp8_variance_fn_t variance8x16_neon = vp8_variance8x16_neon;
-const vp8_variance_fn_t variance16x8_neon = vp8_variance16x8_neon;
-const vp8_variance_fn_t variance16x16_neon = vp8_variance16x16_neon;
+const SubpixVarMxNFunc subpel_var64x64_c = vpx_sub_pixel_variance64x64_c;
+const SubpixVarMxNFunc subpel_var64x32_c = vpx_sub_pixel_variance64x32_c;
+const SubpixVarMxNFunc subpel_var32x64_c = vpx_sub_pixel_variance32x64_c;
+const SubpixVarMxNFunc subpel_var32x32_c = vpx_sub_pixel_variance32x32_c;
+const SubpixVarMxNFunc subpel_var32x16_c = vpx_sub_pixel_variance32x16_c;
+const SubpixVarMxNFunc subpel_var16x32_c = vpx_sub_pixel_variance16x32_c;
+const SubpixVarMxNFunc subpel_var16x16_c = vpx_sub_pixel_variance16x16_c;
+const SubpixVarMxNFunc subpel_var16x8_c = vpx_sub_pixel_variance16x8_c;
+const SubpixVarMxNFunc subpel_var8x16_c = vpx_sub_pixel_variance8x16_c;
+const SubpixVarMxNFunc subpel_var8x8_c = vpx_sub_pixel_variance8x8_c;
+const SubpixVarMxNFunc subpel_var8x4_c = vpx_sub_pixel_variance8x4_c;
+const SubpixVarMxNFunc subpel_var4x8_c = vpx_sub_pixel_variance4x8_c;
+const SubpixVarMxNFunc subpel_var4x4_c = vpx_sub_pixel_variance4x4_c;
 INSTANTIATE_TEST_CASE_P(
-    NEON, VP8VarianceTest,
-    ::testing::Values(make_tuple(3, 3, variance8x8_neon),
-                      make_tuple(3, 4, variance8x16_neon),
-                      make_tuple(4, 3, variance16x8_neon),
-                      make_tuple(4, 4, variance16x16_neon)));
-#endif
+    C, VpxSubpelVarianceTest,
+    ::testing::Values(make_tuple(6, 6, subpel_var64x64_c, 0),
+                      make_tuple(6, 5, subpel_var64x32_c, 0),
+                      make_tuple(5, 6, subpel_var32x64_c, 0),
+                      make_tuple(5, 5, subpel_var32x32_c, 0),
+                      make_tuple(5, 4, subpel_var32x16_c, 0),
+                      make_tuple(4, 5, subpel_var16x32_c, 0),
+                      make_tuple(4, 4, subpel_var16x16_c, 0),
+                      make_tuple(4, 3, subpel_var16x8_c, 0),
+                      make_tuple(3, 4, subpel_var8x16_c, 0),
+                      make_tuple(3, 3, subpel_var8x8_c, 0),
+                      make_tuple(3, 2, subpel_var8x4_c, 0),
+                      make_tuple(2, 3, subpel_var4x8_c, 0),
+                      make_tuple(2, 2, subpel_var4x4_c, 0)));
+
+const SubpixAvgVarMxNFunc subpel_avg_var64x64_c =
+    vpx_sub_pixel_avg_variance64x64_c;
+const SubpixAvgVarMxNFunc subpel_avg_var64x32_c =
+    vpx_sub_pixel_avg_variance64x32_c;
+const SubpixAvgVarMxNFunc subpel_avg_var32x64_c =
+    vpx_sub_pixel_avg_variance32x64_c;
+const SubpixAvgVarMxNFunc subpel_avg_var32x32_c =
+    vpx_sub_pixel_avg_variance32x32_c;
+const SubpixAvgVarMxNFunc subpel_avg_var32x16_c =
+    vpx_sub_pixel_avg_variance32x16_c;
+const SubpixAvgVarMxNFunc subpel_avg_var16x32_c =
+    vpx_sub_pixel_avg_variance16x32_c;
+const SubpixAvgVarMxNFunc subpel_avg_var16x16_c =
+    vpx_sub_pixel_avg_variance16x16_c;
+const SubpixAvgVarMxNFunc subpel_avg_var16x8_c =
+    vpx_sub_pixel_avg_variance16x8_c;
+const SubpixAvgVarMxNFunc subpel_avg_var8x16_c =
+    vpx_sub_pixel_avg_variance8x16_c;
+const SubpixAvgVarMxNFunc subpel_avg_var8x8_c = vpx_sub_pixel_avg_variance8x8_c;
+const SubpixAvgVarMxNFunc subpel_avg_var8x4_c = vpx_sub_pixel_avg_variance8x4_c;
+const SubpixAvgVarMxNFunc subpel_avg_var4x8_c = vpx_sub_pixel_avg_variance4x8_c;
+const SubpixAvgVarMxNFunc subpel_avg_var4x4_c = vpx_sub_pixel_avg_variance4x4_c;
+INSTANTIATE_TEST_CASE_P(
+    C, VpxSubpelAvgVarianceTest,
+    ::testing::Values(make_tuple(6, 6, subpel_avg_var64x64_c, 0),
+                      make_tuple(6, 5, subpel_avg_var64x32_c, 0),
+                      make_tuple(5, 6, subpel_avg_var32x64_c, 0),
+                      make_tuple(5, 5, subpel_avg_var32x32_c, 0),
+                      make_tuple(5, 4, subpel_avg_var32x16_c, 0),
+                      make_tuple(4, 5, subpel_avg_var16x32_c, 0),
+                      make_tuple(4, 4, subpel_avg_var16x16_c, 0),
+                      make_tuple(4, 3, subpel_avg_var16x8_c, 0),
+                      make_tuple(3, 4, subpel_avg_var8x16_c, 0),
+                      make_tuple(3, 3, subpel_avg_var8x8_c, 0),
+                      make_tuple(3, 2, subpel_avg_var8x4_c, 0),
+                      make_tuple(2, 3, subpel_avg_var4x8_c, 0),
+                      make_tuple(2, 2, subpel_avg_var4x4_c, 0)));
+
+#if CONFIG_VP9_HIGHBITDEPTH
+typedef MseTest<VarianceMxNFunc> VpxHBDMseTest;
+typedef VarianceTest<VarianceMxNFunc> VpxHBDVarianceTest;
+typedef SubpelVarianceTest<SubpixVarMxNFunc> VpxHBDSubpelVarianceTest;
+typedef SubpelVarianceTest<SubpixAvgVarMxNFunc>
+    VpxHBDSubpelAvgVarianceTest;
+
+TEST_P(VpxHBDMseTest, Ref_mse) { RefTest_mse(); }
+TEST_P(VpxHBDMseTest, Max_mse) { MaxTest_mse(); }
+TEST_P(VpxHBDVarianceTest, Zero) { ZeroTest(); }
+TEST_P(VpxHBDVarianceTest, Ref) { RefTest(); }
+TEST_P(VpxHBDVarianceTest, RefStride) { RefStrideTest(); }
+TEST_P(VpxHBDVarianceTest, OneQuarter) { OneQuarterTest(); }
+TEST_P(VpxHBDSubpelVarianceTest, Ref) { RefTest(); }
+TEST_P(VpxHBDSubpelVarianceTest, ExtremeRef) { ExtremeRefTest(); }
+TEST_P(VpxHBDSubpelAvgVarianceTest, Ref) { RefTest(); }
+
+/* TODO(debargha): This test does not support the highbd version
+const VarianceMxNFunc highbd_12_mse16x16_c = vpx_highbd_12_mse16x16_c;
+const VarianceMxNFunc highbd_12_mse16x8_c = vpx_highbd_12_mse16x8_c;
+const VarianceMxNFunc highbd_12_mse8x16_c = vpx_highbd_12_mse8x16_c;
+const VarianceMxNFunc highbd_12_mse8x8_c = vpx_highbd_12_mse8x8_c;
+
+const VarianceMxNFunc highbd_10_mse16x16_c = vpx_highbd_10_mse16x16_c;
+const VarianceMxNFunc highbd_10_mse16x8_c = vpx_highbd_10_mse16x8_c;
+const VarianceMxNFunc highbd_10_mse8x16_c = vpx_highbd_10_mse8x16_c;
+const VarianceMxNFunc highbd_10_mse8x8_c = vpx_highbd_10_mse8x8_c;
+
+const VarianceMxNFunc highbd_8_mse16x16_c = vpx_highbd_8_mse16x16_c;
+const VarianceMxNFunc highbd_8_mse16x8_c = vpx_highbd_8_mse16x8_c;
+const VarianceMxNFunc highbd_8_mse8x16_c = vpx_highbd_8_mse8x16_c;
+const VarianceMxNFunc highbd_8_mse8x8_c = vpx_highbd_8_mse8x8_c;
+INSTANTIATE_TEST_CASE_P(
+    C, VpxHBDMseTest, ::testing::Values(make_tuple(4, 4, highbd_12_mse16x16_c),
+                                        make_tuple(4, 4, highbd_12_mse16x8_c),
+                                        make_tuple(4, 4, highbd_12_mse8x16_c),
+                                        make_tuple(4, 4, highbd_12_mse8x8_c),
+                                        make_tuple(4, 4, highbd_10_mse16x16_c),
+                                        make_tuple(4, 4, highbd_10_mse16x8_c),
+                                        make_tuple(4, 4, highbd_10_mse8x16_c),
+                                        make_tuple(4, 4, highbd_10_mse8x8_c),
+                                        make_tuple(4, 4, highbd_8_mse16x16_c),
+                                        make_tuple(4, 4, highbd_8_mse16x8_c),
+                                        make_tuple(4, 4, highbd_8_mse8x16_c),
+                                        make_tuple(4, 4, highbd_8_mse8x8_c)));
+*/
+
+const VarianceMxNFunc highbd_12_variance64x64_c = vpx_highbd_12_variance64x64_c;
+const VarianceMxNFunc highbd_12_variance64x32_c = vpx_highbd_12_variance64x32_c;
+const VarianceMxNFunc highbd_12_variance32x64_c = vpx_highbd_12_variance32x64_c;
+const VarianceMxNFunc highbd_12_variance32x32_c = vpx_highbd_12_variance32x32_c;
+const VarianceMxNFunc highbd_12_variance32x16_c = vpx_highbd_12_variance32x16_c;
+const VarianceMxNFunc highbd_12_variance16x32_c = vpx_highbd_12_variance16x32_c;
+const VarianceMxNFunc highbd_12_variance16x16_c = vpx_highbd_12_variance16x16_c;
+const VarianceMxNFunc highbd_12_variance16x8_c = vpx_highbd_12_variance16x8_c;
+const VarianceMxNFunc highbd_12_variance8x16_c = vpx_highbd_12_variance8x16_c;
+const VarianceMxNFunc highbd_12_variance8x8_c = vpx_highbd_12_variance8x8_c;
+const VarianceMxNFunc highbd_12_variance8x4_c = vpx_highbd_12_variance8x4_c;
+const VarianceMxNFunc highbd_12_variance4x8_c = vpx_highbd_12_variance4x8_c;
+const VarianceMxNFunc highbd_12_variance4x4_c = vpx_highbd_12_variance4x4_c;
+const VarianceMxNFunc highbd_10_variance64x64_c = vpx_highbd_10_variance64x64_c;
+const VarianceMxNFunc highbd_10_variance64x32_c = vpx_highbd_10_variance64x32_c;
+const VarianceMxNFunc highbd_10_variance32x64_c = vpx_highbd_10_variance32x64_c;
+const VarianceMxNFunc highbd_10_variance32x32_c = vpx_highbd_10_variance32x32_c;
+const VarianceMxNFunc highbd_10_variance32x16_c = vpx_highbd_10_variance32x16_c;
+const VarianceMxNFunc highbd_10_variance16x32_c = vpx_highbd_10_variance16x32_c;
+const VarianceMxNFunc highbd_10_variance16x16_c = vpx_highbd_10_variance16x16_c;
+const VarianceMxNFunc highbd_10_variance16x8_c = vpx_highbd_10_variance16x8_c;
+const VarianceMxNFunc highbd_10_variance8x16_c = vpx_highbd_10_variance8x16_c;
+const VarianceMxNFunc highbd_10_variance8x8_c = vpx_highbd_10_variance8x8_c;
+const VarianceMxNFunc highbd_10_variance8x4_c = vpx_highbd_10_variance8x4_c;
+const VarianceMxNFunc highbd_10_variance4x8_c = vpx_highbd_10_variance4x8_c;
+const VarianceMxNFunc highbd_10_variance4x4_c = vpx_highbd_10_variance4x4_c;
+const VarianceMxNFunc highbd_8_variance64x64_c = vpx_highbd_8_variance64x64_c;
+const VarianceMxNFunc highbd_8_variance64x32_c = vpx_highbd_8_variance64x32_c;
+const VarianceMxNFunc highbd_8_variance32x64_c = vpx_highbd_8_variance32x64_c;
+const VarianceMxNFunc highbd_8_variance32x32_c = vpx_highbd_8_variance32x32_c;
+const VarianceMxNFunc highbd_8_variance32x16_c = vpx_highbd_8_variance32x16_c;
+const VarianceMxNFunc highbd_8_variance16x32_c = vpx_highbd_8_variance16x32_c;
+const VarianceMxNFunc highbd_8_variance16x16_c = vpx_highbd_8_variance16x16_c;
+const VarianceMxNFunc highbd_8_variance16x8_c = vpx_highbd_8_variance16x8_c;
+const VarianceMxNFunc highbd_8_variance8x16_c = vpx_highbd_8_variance8x16_c;
+const VarianceMxNFunc highbd_8_variance8x8_c = vpx_highbd_8_variance8x8_c;
+const VarianceMxNFunc highbd_8_variance8x4_c = vpx_highbd_8_variance8x4_c;
+const VarianceMxNFunc highbd_8_variance4x8_c = vpx_highbd_8_variance4x8_c;
+const VarianceMxNFunc highbd_8_variance4x4_c = vpx_highbd_8_variance4x4_c;
+INSTANTIATE_TEST_CASE_P(
+    C, VpxHBDVarianceTest,
+    ::testing::Values(make_tuple(6, 6, highbd_12_variance64x64_c, 12),
+                      make_tuple(6, 5, highbd_12_variance64x32_c, 12),
+                      make_tuple(5, 6, highbd_12_variance32x64_c, 12),
+                      make_tuple(5, 5, highbd_12_variance32x32_c, 12),
+                      make_tuple(5, 4, highbd_12_variance32x16_c, 12),
+                      make_tuple(4, 5, highbd_12_variance16x32_c, 12),
+                      make_tuple(4, 4, highbd_12_variance16x16_c, 12),
+                      make_tuple(4, 3, highbd_12_variance16x8_c, 12),
+                      make_tuple(3, 4, highbd_12_variance8x16_c, 12),
+                      make_tuple(3, 3, highbd_12_variance8x8_c, 12),
+                      make_tuple(3, 2, highbd_12_variance8x4_c, 12),
+                      make_tuple(2, 3, highbd_12_variance4x8_c, 12),
+                      make_tuple(2, 2, highbd_12_variance4x4_c, 12),
+                      make_tuple(6, 6, highbd_10_variance64x64_c, 10),
+                      make_tuple(6, 5, highbd_10_variance64x32_c, 10),
+                      make_tuple(5, 6, highbd_10_variance32x64_c, 10),
+                      make_tuple(5, 5, highbd_10_variance32x32_c, 10),
+                      make_tuple(5, 4, highbd_10_variance32x16_c, 10),
+                      make_tuple(4, 5, highbd_10_variance16x32_c, 10),
+                      make_tuple(4, 4, highbd_10_variance16x16_c, 10),
+                      make_tuple(4, 3, highbd_10_variance16x8_c, 10),
+                      make_tuple(3, 4, highbd_10_variance8x16_c, 10),
+                      make_tuple(3, 3, highbd_10_variance8x8_c, 10),
+                      make_tuple(3, 2, highbd_10_variance8x4_c, 10),
+                      make_tuple(2, 3, highbd_10_variance4x8_c, 10),
+                      make_tuple(2, 2, highbd_10_variance4x4_c, 10),
+                      make_tuple(6, 6, highbd_8_variance64x64_c, 8),
+                      make_tuple(6, 5, highbd_8_variance64x32_c, 8),
+                      make_tuple(5, 6, highbd_8_variance32x64_c, 8),
+                      make_tuple(5, 5, highbd_8_variance32x32_c, 8),
+                      make_tuple(5, 4, highbd_8_variance32x16_c, 8),
+                      make_tuple(4, 5, highbd_8_variance16x32_c, 8),
+                      make_tuple(4, 4, highbd_8_variance16x16_c, 8),
+                      make_tuple(4, 3, highbd_8_variance16x8_c, 8),
+                      make_tuple(3, 4, highbd_8_variance8x16_c, 8),
+                      make_tuple(3, 3, highbd_8_variance8x8_c, 8),
+                      make_tuple(3, 2, highbd_8_variance8x4_c, 8),
+                      make_tuple(2, 3, highbd_8_variance4x8_c, 8),
+                      make_tuple(2, 2, highbd_8_variance4x4_c, 8)));
+
+const SubpixVarMxNFunc highbd_8_subpel_var64x64_c =
+    vpx_highbd_8_sub_pixel_variance64x64_c;
+const SubpixVarMxNFunc highbd_8_subpel_var64x32_c =
+    vpx_highbd_8_sub_pixel_variance64x32_c;
+const SubpixVarMxNFunc highbd_8_subpel_var32x64_c =
+    vpx_highbd_8_sub_pixel_variance32x64_c;
+const SubpixVarMxNFunc highbd_8_subpel_var32x32_c =
+    vpx_highbd_8_sub_pixel_variance32x32_c;
+const SubpixVarMxNFunc highbd_8_subpel_var32x16_c =
+    vpx_highbd_8_sub_pixel_variance32x16_c;
+const SubpixVarMxNFunc highbd_8_subpel_var16x32_c =
+    vpx_highbd_8_sub_pixel_variance16x32_c;
+const SubpixVarMxNFunc highbd_8_subpel_var16x16_c =
+    vpx_highbd_8_sub_pixel_variance16x16_c;
+const SubpixVarMxNFunc highbd_8_subpel_var16x8_c =
+    vpx_highbd_8_sub_pixel_variance16x8_c;
+const SubpixVarMxNFunc highbd_8_subpel_var8x16_c =
+    vpx_highbd_8_sub_pixel_variance8x16_c;
+const SubpixVarMxNFunc highbd_8_subpel_var8x8_c =
+    vpx_highbd_8_sub_pixel_variance8x8_c;
+const SubpixVarMxNFunc highbd_8_subpel_var8x4_c =
+    vpx_highbd_8_sub_pixel_variance8x4_c;
+const SubpixVarMxNFunc highbd_8_subpel_var4x8_c =
+    vpx_highbd_8_sub_pixel_variance4x8_c;
+const SubpixVarMxNFunc highbd_8_subpel_var4x4_c =
+    vpx_highbd_8_sub_pixel_variance4x4_c;
+const SubpixVarMxNFunc highbd_10_subpel_var64x64_c =
+    vpx_highbd_10_sub_pixel_variance64x64_c;
+const SubpixVarMxNFunc highbd_10_subpel_var64x32_c =
+    vpx_highbd_10_sub_pixel_variance64x32_c;
+const SubpixVarMxNFunc highbd_10_subpel_var32x64_c =
+    vpx_highbd_10_sub_pixel_variance32x64_c;
+const SubpixVarMxNFunc highbd_10_subpel_var32x32_c =
+    vpx_highbd_10_sub_pixel_variance32x32_c;
+const SubpixVarMxNFunc highbd_10_subpel_var32x16_c =
+    vpx_highbd_10_sub_pixel_variance32x16_c;
+const SubpixVarMxNFunc highbd_10_subpel_var16x32_c =
+    vpx_highbd_10_sub_pixel_variance16x32_c;
+const SubpixVarMxNFunc highbd_10_subpel_var16x16_c =
+    vpx_highbd_10_sub_pixel_variance16x16_c;
+const SubpixVarMxNFunc highbd_10_subpel_var16x8_c =
+    vpx_highbd_10_sub_pixel_variance16x8_c;
+const SubpixVarMxNFunc highbd_10_subpel_var8x16_c =
+    vpx_highbd_10_sub_pixel_variance8x16_c;
+const SubpixVarMxNFunc highbd_10_subpel_var8x8_c =
+    vpx_highbd_10_sub_pixel_variance8x8_c;
+const SubpixVarMxNFunc highbd_10_subpel_var8x4_c =
+    vpx_highbd_10_sub_pixel_variance8x4_c;
+const SubpixVarMxNFunc highbd_10_subpel_var4x8_c =
+    vpx_highbd_10_sub_pixel_variance4x8_c;
+const SubpixVarMxNFunc highbd_10_subpel_var4x4_c =
+    vpx_highbd_10_sub_pixel_variance4x4_c;
+const SubpixVarMxNFunc highbd_12_subpel_var64x64_c =
+    vpx_highbd_12_sub_pixel_variance64x64_c;
+const SubpixVarMxNFunc highbd_12_subpel_var64x32_c =
+    vpx_highbd_12_sub_pixel_variance64x32_c;
+const SubpixVarMxNFunc highbd_12_subpel_var32x64_c =
+    vpx_highbd_12_sub_pixel_variance32x64_c;
+const SubpixVarMxNFunc highbd_12_subpel_var32x32_c =
+    vpx_highbd_12_sub_pixel_variance32x32_c;
+const SubpixVarMxNFunc highbd_12_subpel_var32x16_c =
+    vpx_highbd_12_sub_pixel_variance32x16_c;
+const SubpixVarMxNFunc highbd_12_subpel_var16x32_c =
+    vpx_highbd_12_sub_pixel_variance16x32_c;
+const SubpixVarMxNFunc highbd_12_subpel_var16x16_c =
+    vpx_highbd_12_sub_pixel_variance16x16_c;
+const SubpixVarMxNFunc highbd_12_subpel_var16x8_c =
+    vpx_highbd_12_sub_pixel_variance16x8_c;
+const SubpixVarMxNFunc highbd_12_subpel_var8x16_c =
+    vpx_highbd_12_sub_pixel_variance8x16_c;
+const SubpixVarMxNFunc highbd_12_subpel_var8x8_c =
+    vpx_highbd_12_sub_pixel_variance8x8_c;
+const SubpixVarMxNFunc highbd_12_subpel_var8x4_c =
+    vpx_highbd_12_sub_pixel_variance8x4_c;
+const SubpixVarMxNFunc highbd_12_subpel_var4x8_c =
+    vpx_highbd_12_sub_pixel_variance4x8_c;
+const SubpixVarMxNFunc highbd_12_subpel_var4x4_c =
+    vpx_highbd_12_sub_pixel_variance4x4_c;
+INSTANTIATE_TEST_CASE_P(
+    C, VpxHBDSubpelVarianceTest,
+    ::testing::Values(make_tuple(6, 6, highbd_8_subpel_var64x64_c, 8),
+                      make_tuple(6, 5, highbd_8_subpel_var64x32_c, 8),
+                      make_tuple(5, 6, highbd_8_subpel_var32x64_c, 8),
+                      make_tuple(5, 5, highbd_8_subpel_var32x32_c, 8),
+                      make_tuple(5, 4, highbd_8_subpel_var32x16_c, 8),
+                      make_tuple(4, 5, highbd_8_subpel_var16x32_c, 8),
+                      make_tuple(4, 4, highbd_8_subpel_var16x16_c, 8),
+                      make_tuple(4, 3, highbd_8_subpel_var16x8_c, 8),
+                      make_tuple(3, 4, highbd_8_subpel_var8x16_c, 8),
+                      make_tuple(3, 3, highbd_8_subpel_var8x8_c, 8),
+                      make_tuple(3, 2, highbd_8_subpel_var8x4_c, 8),
+                      make_tuple(2, 3, highbd_8_subpel_var4x8_c, 8),
+                      make_tuple(2, 2, highbd_8_subpel_var4x4_c, 8),
+                      make_tuple(6, 6, highbd_10_subpel_var64x64_c, 10),
+                      make_tuple(6, 5, highbd_10_subpel_var64x32_c, 10),
+                      make_tuple(5, 6, highbd_10_subpel_var32x64_c, 10),
+                      make_tuple(5, 5, highbd_10_subpel_var32x32_c, 10),
+                      make_tuple(5, 4, highbd_10_subpel_var32x16_c, 10),
+                      make_tuple(4, 5, highbd_10_subpel_var16x32_c, 10),
+                      make_tuple(4, 4, highbd_10_subpel_var16x16_c, 10),
+                      make_tuple(4, 3, highbd_10_subpel_var16x8_c, 10),
+                      make_tuple(3, 4, highbd_10_subpel_var8x16_c, 10),
+                      make_tuple(3, 3, highbd_10_subpel_var8x8_c, 10),
+                      make_tuple(3, 2, highbd_10_subpel_var8x4_c, 10),
+                      make_tuple(2, 3, highbd_10_subpel_var4x8_c, 10),
+                      make_tuple(2, 2, highbd_10_subpel_var4x4_c, 10),
+                      make_tuple(6, 6, highbd_12_subpel_var64x64_c, 12),
+                      make_tuple(6, 5, highbd_12_subpel_var64x32_c, 12),
+                      make_tuple(5, 6, highbd_12_subpel_var32x64_c, 12),
+                      make_tuple(5, 5, highbd_12_subpel_var32x32_c, 12),
+                      make_tuple(5, 4, highbd_12_subpel_var32x16_c, 12),
+                      make_tuple(4, 5, highbd_12_subpel_var16x32_c, 12),
+                      make_tuple(4, 4, highbd_12_subpel_var16x16_c, 12),
+                      make_tuple(4, 3, highbd_12_subpel_var16x8_c, 12),
+                      make_tuple(3, 4, highbd_12_subpel_var8x16_c, 12),
+                      make_tuple(3, 3, highbd_12_subpel_var8x8_c, 12),
+                      make_tuple(3, 2, highbd_12_subpel_var8x4_c, 12),
+                      make_tuple(2, 3, highbd_12_subpel_var4x8_c, 12),
+                      make_tuple(2, 2, highbd_12_subpel_var4x4_c, 12)));
+
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var64x64_c =
+    vpx_highbd_8_sub_pixel_avg_variance64x64_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var64x32_c =
+    vpx_highbd_8_sub_pixel_avg_variance64x32_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var32x64_c =
+    vpx_highbd_8_sub_pixel_avg_variance32x64_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var32x32_c =
+    vpx_highbd_8_sub_pixel_avg_variance32x32_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var32x16_c =
+    vpx_highbd_8_sub_pixel_avg_variance32x16_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var16x32_c =
+    vpx_highbd_8_sub_pixel_avg_variance16x32_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var16x16_c =
+    vpx_highbd_8_sub_pixel_avg_variance16x16_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var16x8_c =
+    vpx_highbd_8_sub_pixel_avg_variance16x8_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var8x16_c =
+    vpx_highbd_8_sub_pixel_avg_variance8x16_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var8x8_c =
+    vpx_highbd_8_sub_pixel_avg_variance8x8_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var8x4_c =
+    vpx_highbd_8_sub_pixel_avg_variance8x4_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var4x8_c =
+    vpx_highbd_8_sub_pixel_avg_variance4x8_c;
+const SubpixAvgVarMxNFunc highbd_8_subpel_avg_var4x4_c =
+    vpx_highbd_8_sub_pixel_avg_variance4x4_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var64x64_c =
+    vpx_highbd_10_sub_pixel_avg_variance64x64_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var64x32_c =
+    vpx_highbd_10_sub_pixel_avg_variance64x32_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var32x64_c =
+    vpx_highbd_10_sub_pixel_avg_variance32x64_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var32x32_c =
+    vpx_highbd_10_sub_pixel_avg_variance32x32_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var32x16_c =
+    vpx_highbd_10_sub_pixel_avg_variance32x16_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var16x32_c =
+    vpx_highbd_10_sub_pixel_avg_variance16x32_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var16x16_c =
+    vpx_highbd_10_sub_pixel_avg_variance16x16_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var16x8_c =
+    vpx_highbd_10_sub_pixel_avg_variance16x8_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var8x16_c =
+    vpx_highbd_10_sub_pixel_avg_variance8x16_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var8x8_c =
+    vpx_highbd_10_sub_pixel_avg_variance8x8_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var8x4_c =
+    vpx_highbd_10_sub_pixel_avg_variance8x4_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var4x8_c =
+    vpx_highbd_10_sub_pixel_avg_variance4x8_c;
+const SubpixAvgVarMxNFunc highbd_10_subpel_avg_var4x4_c =
+    vpx_highbd_10_sub_pixel_avg_variance4x4_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var64x64_c =
+    vpx_highbd_12_sub_pixel_avg_variance64x64_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var64x32_c =
+    vpx_highbd_12_sub_pixel_avg_variance64x32_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var32x64_c =
+    vpx_highbd_12_sub_pixel_avg_variance32x64_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var32x32_c =
+    vpx_highbd_12_sub_pixel_avg_variance32x32_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var32x16_c =
+    vpx_highbd_12_sub_pixel_avg_variance32x16_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var16x32_c =
+    vpx_highbd_12_sub_pixel_avg_variance16x32_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var16x16_c =
+    vpx_highbd_12_sub_pixel_avg_variance16x16_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var16x8_c =
+    vpx_highbd_12_sub_pixel_avg_variance16x8_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var8x16_c =
+    vpx_highbd_12_sub_pixel_avg_variance8x16_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var8x8_c =
+    vpx_highbd_12_sub_pixel_avg_variance8x8_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var8x4_c =
+    vpx_highbd_12_sub_pixel_avg_variance8x4_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var4x8_c =
+    vpx_highbd_12_sub_pixel_avg_variance4x8_c;
+const SubpixAvgVarMxNFunc highbd_12_subpel_avg_var4x4_c =
+    vpx_highbd_12_sub_pixel_avg_variance4x4_c;
+INSTANTIATE_TEST_CASE_P(
+    C, VpxHBDSubpelAvgVarianceTest,
+    ::testing::Values(
+        make_tuple(6, 6, highbd_8_subpel_avg_var64x64_c, 8),
+        make_tuple(6, 5, highbd_8_subpel_avg_var64x32_c, 8),
+        make_tuple(5, 6, highbd_8_subpel_avg_var32x64_c, 8),
+        make_tuple(5, 5, highbd_8_subpel_avg_var32x32_c, 8),
+        make_tuple(5, 4, highbd_8_subpel_avg_var32x16_c, 8),
+        make_tuple(4, 5, highbd_8_subpel_avg_var16x32_c, 8),
+        make_tuple(4, 4, highbd_8_subpel_avg_var16x16_c, 8),
+        make_tuple(4, 3, highbd_8_subpel_avg_var16x8_c, 8),
+        make_tuple(3, 4, highbd_8_subpel_avg_var8x16_c, 8),
+        make_tuple(3, 3, highbd_8_subpel_avg_var8x8_c, 8),
+        make_tuple(3, 2, highbd_8_subpel_avg_var8x4_c, 8),
+        make_tuple(2, 3, highbd_8_subpel_avg_var4x8_c, 8),
+        make_tuple(2, 2, highbd_8_subpel_avg_var4x4_c, 8),
+        make_tuple(6, 6, highbd_10_subpel_avg_var64x64_c, 10),
+        make_tuple(6, 5, highbd_10_subpel_avg_var64x32_c, 10),
+        make_tuple(5, 6, highbd_10_subpel_avg_var32x64_c, 10),
+        make_tuple(5, 5, highbd_10_subpel_avg_var32x32_c, 10),
+        make_tuple(5, 4, highbd_10_subpel_avg_var32x16_c, 10),
+        make_tuple(4, 5, highbd_10_subpel_avg_var16x32_c, 10),
+        make_tuple(4, 4, highbd_10_subpel_avg_var16x16_c, 10),
+        make_tuple(4, 3, highbd_10_subpel_avg_var16x8_c, 10),
+        make_tuple(3, 4, highbd_10_subpel_avg_var8x16_c, 10),
+        make_tuple(3, 3, highbd_10_subpel_avg_var8x8_c, 10),
+        make_tuple(3, 2, highbd_10_subpel_avg_var8x4_c, 10),
+        make_tuple(2, 3, highbd_10_subpel_avg_var4x8_c, 10),
+        make_tuple(2, 2, highbd_10_subpel_avg_var4x4_c, 10),
+        make_tuple(6, 6, highbd_12_subpel_avg_var64x64_c, 12),
+        make_tuple(6, 5, highbd_12_subpel_avg_var64x32_c, 12),
+        make_tuple(5, 6, highbd_12_subpel_avg_var32x64_c, 12),
+        make_tuple(5, 5, highbd_12_subpel_avg_var32x32_c, 12),
+        make_tuple(5, 4, highbd_12_subpel_avg_var32x16_c, 12),
+        make_tuple(4, 5, highbd_12_subpel_avg_var16x32_c, 12),
+        make_tuple(4, 4, highbd_12_subpel_avg_var16x16_c, 12),
+        make_tuple(4, 3, highbd_12_subpel_avg_var16x8_c, 12),
+        make_tuple(3, 4, highbd_12_subpel_avg_var8x16_c, 12),
+        make_tuple(3, 3, highbd_12_subpel_avg_var8x8_c, 12),
+        make_tuple(3, 2, highbd_12_subpel_avg_var8x4_c, 12),
+        make_tuple(2, 3, highbd_12_subpel_avg_var4x8_c, 12),
+        make_tuple(2, 2, highbd_12_subpel_avg_var4x4_c, 12)));
+#endif  // CONFIG_VP9_HIGHBITDEPTH
 
 #if HAVE_MMX
-const vp8_variance_fn_t variance4x4_mmx = vp8_variance4x4_mmx;
-const vp8_variance_fn_t variance8x8_mmx = vp8_variance8x8_mmx;
-const vp8_variance_fn_t variance8x16_mmx = vp8_variance8x16_mmx;
-const vp8_variance_fn_t variance16x8_mmx = vp8_variance16x8_mmx;
-const vp8_variance_fn_t variance16x16_mmx = vp8_variance16x16_mmx;
+const VarianceMxNFunc mse16x16_mmx = vpx_mse16x16_mmx;
+INSTANTIATE_TEST_CASE_P(MMX, VpxMseTest,
+                        ::testing::Values(make_tuple(4, 4, mse16x16_mmx)));
+
+INSTANTIATE_TEST_CASE_P(MMX, SumOfSquaresTest,
+                        ::testing::Values(vpx_get_mb_ss_mmx));
+
+const VarianceMxNFunc variance16x16_mmx = vpx_variance16x16_mmx;
+const VarianceMxNFunc variance16x8_mmx = vpx_variance16x8_mmx;
+const VarianceMxNFunc variance8x16_mmx = vpx_variance8x16_mmx;
+const VarianceMxNFunc variance8x8_mmx = vpx_variance8x8_mmx;
+const VarianceMxNFunc variance4x4_mmx = vpx_variance4x4_mmx;
 INSTANTIATE_TEST_CASE_P(
-    MMX, VP8VarianceTest,
-    ::testing::Values(make_tuple(2, 2, variance4x4_mmx),
-                      make_tuple(3, 3, variance8x8_mmx),
-                      make_tuple(3, 4, variance8x16_mmx),
-                      make_tuple(4, 3, variance16x8_mmx),
-                      make_tuple(4, 4, variance16x16_mmx)));
-#endif
+    MMX, VpxVarianceTest,
+    ::testing::Values(make_tuple(4, 4, variance16x16_mmx, 0),
+                      make_tuple(4, 3, variance16x8_mmx, 0),
+                      make_tuple(3, 4, variance8x16_mmx, 0),
+                      make_tuple(3, 3, variance8x8_mmx, 0),
+                      make_tuple(2, 2, variance4x4_mmx, 0)));
+
+const SubpixVarMxNFunc subpel_var16x16_mmx = vpx_sub_pixel_variance16x16_mmx;
+const SubpixVarMxNFunc subpel_var16x8_mmx = vpx_sub_pixel_variance16x8_mmx;
+const SubpixVarMxNFunc subpel_var8x16_mmx = vpx_sub_pixel_variance8x16_mmx;
+const SubpixVarMxNFunc subpel_var8x8_mmx = vpx_sub_pixel_variance8x8_mmx;
+const SubpixVarMxNFunc subpel_var4x4_mmx = vpx_sub_pixel_variance4x4_mmx;
+INSTANTIATE_TEST_CASE_P(
+    MMX, VpxSubpelVarianceTest,
+    ::testing::Values(make_tuple(4, 4, subpel_var16x16_mmx, 0),
+                      make_tuple(4, 3, subpel_var16x8_mmx, 0),
+                      make_tuple(3, 4, subpel_var8x16_mmx, 0),
+                      make_tuple(3, 3, subpel_var8x8_mmx, 0),
+                      make_tuple(2, 2, subpel_var4x4_mmx, 0)));
+#endif  // HAVE_MMX
 
 #if HAVE_SSE2
-const vp8_variance_fn_t variance4x4_wmt = vp8_variance4x4_wmt;
-const vp8_variance_fn_t variance8x8_wmt = vp8_variance8x8_wmt;
-const vp8_variance_fn_t variance8x16_wmt = vp8_variance8x16_wmt;
-const vp8_variance_fn_t variance16x8_wmt = vp8_variance16x8_wmt;
-const vp8_variance_fn_t variance16x16_wmt = vp8_variance16x16_wmt;
+INSTANTIATE_TEST_CASE_P(SSE2, SumOfSquaresTest,
+                        ::testing::Values(vpx_get_mb_ss_sse2));
+
+const VarianceMxNFunc mse16x16_sse2 = vpx_mse16x16_sse2;
+const VarianceMxNFunc mse16x8_sse2 = vpx_mse16x8_sse2;
+const VarianceMxNFunc mse8x16_sse2 = vpx_mse8x16_sse2;
+const VarianceMxNFunc mse8x8_sse2 = vpx_mse8x8_sse2;
+INSTANTIATE_TEST_CASE_P(SSE2, VpxMseTest,
+                        ::testing::Values(make_tuple(4, 4, mse16x16_sse2),
+                                          make_tuple(4, 3, mse16x8_sse2),
+                                          make_tuple(3, 4, mse8x16_sse2),
+                                          make_tuple(3, 3, mse8x8_sse2)));
+
+const VarianceMxNFunc variance64x64_sse2 = vpx_variance64x64_sse2;
+const VarianceMxNFunc variance64x32_sse2 = vpx_variance64x32_sse2;
+const VarianceMxNFunc variance32x64_sse2 = vpx_variance32x64_sse2;
+const VarianceMxNFunc variance32x32_sse2 = vpx_variance32x32_sse2;
+const VarianceMxNFunc variance32x16_sse2 = vpx_variance32x16_sse2;
+const VarianceMxNFunc variance16x32_sse2 = vpx_variance16x32_sse2;
+const VarianceMxNFunc variance16x16_sse2 = vpx_variance16x16_sse2;
+const VarianceMxNFunc variance16x8_sse2 = vpx_variance16x8_sse2;
+const VarianceMxNFunc variance8x16_sse2 = vpx_variance8x16_sse2;
+const VarianceMxNFunc variance8x8_sse2 = vpx_variance8x8_sse2;
+const VarianceMxNFunc variance8x4_sse2 = vpx_variance8x4_sse2;
+const VarianceMxNFunc variance4x8_sse2 = vpx_variance4x8_sse2;
+const VarianceMxNFunc variance4x4_sse2 = vpx_variance4x4_sse2;
 INSTANTIATE_TEST_CASE_P(
-    SSE2, VP8VarianceTest,
-    ::testing::Values(make_tuple(2, 2, variance4x4_wmt),
-                      make_tuple(3, 3, variance8x8_wmt),
-                      make_tuple(3, 4, variance8x16_wmt),
-                      make_tuple(4, 3, variance16x8_wmt),
-                      make_tuple(4, 4, variance16x16_wmt)));
-#endif
-#endif  // CONFIG_VP8_ENCODER
+    SSE2, VpxVarianceTest,
+    ::testing::Values(make_tuple(6, 6, variance64x64_sse2, 0),
+                      make_tuple(6, 5, variance64x32_sse2, 0),
+                      make_tuple(5, 6, variance32x64_sse2, 0),
+                      make_tuple(5, 5, variance32x32_sse2, 0),
+                      make_tuple(5, 4, variance32x16_sse2, 0),
+                      make_tuple(4, 5, variance16x32_sse2, 0),
+                      make_tuple(4, 4, variance16x16_sse2, 0),
+                      make_tuple(4, 3, variance16x8_sse2, 0),
+                      make_tuple(3, 4, variance8x16_sse2, 0),
+                      make_tuple(3, 3, variance8x8_sse2, 0),
+                      make_tuple(3, 2, variance8x4_sse2, 0),
+                      make_tuple(2, 3, variance4x8_sse2, 0),
+                      make_tuple(2, 2, variance4x4_sse2, 0)));
 
-}  // namespace vp8
-
-// -----------------------------------------------------------------------------
-// VP9 test cases.
-
-namespace vp9 {
-
-#if CONFIG_VP9_ENCODER
-typedef VarianceTest<vp9_variance_fn_t> VP9VarianceTest;
-typedef SubpelVarianceTest<vp9_subpixvariance_fn_t> VP9SubpelVarianceTest;
-typedef SubpelVarianceTest<vp9_subp_avg_variance_fn_t> VP9SubpelAvgVarianceTest;
-
-TEST_P(VP9VarianceTest, Zero) { ZeroTest(); }
-TEST_P(VP9VarianceTest, Ref) { RefTest(); }
-TEST_P(VP9SubpelVarianceTest, Ref) { RefTest(); }
-TEST_P(VP9SubpelAvgVarianceTest, Ref) { RefTest(); }
-TEST_P(VP9VarianceTest, OneQuarter) { OneQuarterTest(); }
-
-const vp9_variance_fn_t variance4x4_c = vp9_variance4x4_c;
-const vp9_variance_fn_t variance4x8_c = vp9_variance4x8_c;
-const vp9_variance_fn_t variance8x4_c = vp9_variance8x4_c;
-const vp9_variance_fn_t variance8x8_c = vp9_variance8x8_c;
-const vp9_variance_fn_t variance8x16_c = vp9_variance8x16_c;
-const vp9_variance_fn_t variance16x8_c = vp9_variance16x8_c;
-const vp9_variance_fn_t variance16x16_c = vp9_variance16x16_c;
-const vp9_variance_fn_t variance16x32_c = vp9_variance16x32_c;
-const vp9_variance_fn_t variance32x16_c = vp9_variance32x16_c;
-const vp9_variance_fn_t variance32x32_c = vp9_variance32x32_c;
-const vp9_variance_fn_t variance32x64_c = vp9_variance32x64_c;
-const vp9_variance_fn_t variance64x32_c = vp9_variance64x32_c;
-const vp9_variance_fn_t variance64x64_c = vp9_variance64x64_c;
-INSTANTIATE_TEST_CASE_P(
-    C, VP9VarianceTest,
-    ::testing::Values(make_tuple(2, 2, variance4x4_c),
-                      make_tuple(2, 3, variance4x8_c),
-                      make_tuple(3, 2, variance8x4_c),
-                      make_tuple(3, 3, variance8x8_c),
-                      make_tuple(3, 4, variance8x16_c),
-                      make_tuple(4, 3, variance16x8_c),
-                      make_tuple(4, 4, variance16x16_c),
-                      make_tuple(4, 5, variance16x32_c),
-                      make_tuple(5, 4, variance32x16_c),
-                      make_tuple(5, 5, variance32x32_c),
-                      make_tuple(5, 6, variance32x64_c),
-                      make_tuple(6, 5, variance64x32_c),
-                      make_tuple(6, 6, variance64x64_c)));
-
-const vp9_subpixvariance_fn_t subpel_variance4x4_c =
-    vp9_sub_pixel_variance4x4_c;
-const vp9_subpixvariance_fn_t subpel_variance4x8_c =
-    vp9_sub_pixel_variance4x8_c;
-const vp9_subpixvariance_fn_t subpel_variance8x4_c =
-    vp9_sub_pixel_variance8x4_c;
-const vp9_subpixvariance_fn_t subpel_variance8x8_c =
-    vp9_sub_pixel_variance8x8_c;
-const vp9_subpixvariance_fn_t subpel_variance8x16_c =
-    vp9_sub_pixel_variance8x16_c;
-const vp9_subpixvariance_fn_t subpel_variance16x8_c =
-    vp9_sub_pixel_variance16x8_c;
-const vp9_subpixvariance_fn_t subpel_variance16x16_c =
-    vp9_sub_pixel_variance16x16_c;
-const vp9_subpixvariance_fn_t subpel_variance16x32_c =
-    vp9_sub_pixel_variance16x32_c;
-const vp9_subpixvariance_fn_t subpel_variance32x16_c =
-    vp9_sub_pixel_variance32x16_c;
-const vp9_subpixvariance_fn_t subpel_variance32x32_c =
-    vp9_sub_pixel_variance32x32_c;
-const vp9_subpixvariance_fn_t subpel_variance32x64_c =
-    vp9_sub_pixel_variance32x64_c;
-const vp9_subpixvariance_fn_t subpel_variance64x32_c =
-    vp9_sub_pixel_variance64x32_c;
-const vp9_subpixvariance_fn_t subpel_variance64x64_c =
-    vp9_sub_pixel_variance64x64_c;
-INSTANTIATE_TEST_CASE_P(
-    C, VP9SubpelVarianceTest,
-    ::testing::Values(make_tuple(2, 2, subpel_variance4x4_c),
-                      make_tuple(2, 3, subpel_variance4x8_c),
-                      make_tuple(3, 2, subpel_variance8x4_c),
-                      make_tuple(3, 3, subpel_variance8x8_c),
-                      make_tuple(3, 4, subpel_variance8x16_c),
-                      make_tuple(4, 3, subpel_variance16x8_c),
-                      make_tuple(4, 4, subpel_variance16x16_c),
-                      make_tuple(4, 5, subpel_variance16x32_c),
-                      make_tuple(5, 4, subpel_variance32x16_c),
-                      make_tuple(5, 5, subpel_variance32x32_c),
-                      make_tuple(5, 6, subpel_variance32x64_c),
-                      make_tuple(6, 5, subpel_variance64x32_c),
-                      make_tuple(6, 6, subpel_variance64x64_c)));
-
-const vp9_subp_avg_variance_fn_t subpel_avg_variance4x4_c =
-    vp9_sub_pixel_avg_variance4x4_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance4x8_c =
-    vp9_sub_pixel_avg_variance4x8_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance8x4_c =
-    vp9_sub_pixel_avg_variance8x4_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance8x8_c =
-    vp9_sub_pixel_avg_variance8x8_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance8x16_c =
-    vp9_sub_pixel_avg_variance8x16_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance16x8_c =
-    vp9_sub_pixel_avg_variance16x8_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance16x16_c =
-    vp9_sub_pixel_avg_variance16x16_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance16x32_c =
-    vp9_sub_pixel_avg_variance16x32_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance32x16_c =
-    vp9_sub_pixel_avg_variance32x16_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance32x32_c =
-    vp9_sub_pixel_avg_variance32x32_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance32x64_c =
-    vp9_sub_pixel_avg_variance32x64_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance64x32_c =
-    vp9_sub_pixel_avg_variance64x32_c;
-const vp9_subp_avg_variance_fn_t subpel_avg_variance64x64_c =
-    vp9_sub_pixel_avg_variance64x64_c;
-INSTANTIATE_TEST_CASE_P(
-    C, VP9SubpelAvgVarianceTest,
-    ::testing::Values(make_tuple(2, 2, subpel_avg_variance4x4_c),
-                      make_tuple(2, 3, subpel_avg_variance4x8_c),
-                      make_tuple(3, 2, subpel_avg_variance8x4_c),
-                      make_tuple(3, 3, subpel_avg_variance8x8_c),
-                      make_tuple(3, 4, subpel_avg_variance8x16_c),
-                      make_tuple(4, 3, subpel_avg_variance16x8_c),
-                      make_tuple(4, 4, subpel_avg_variance16x16_c),
-                      make_tuple(4, 5, subpel_avg_variance16x32_c),
-                      make_tuple(5, 4, subpel_avg_variance32x16_c),
-                      make_tuple(5, 5, subpel_avg_variance32x32_c),
-                      make_tuple(5, 6, subpel_avg_variance32x64_c),
-                      make_tuple(6, 5, subpel_avg_variance64x32_c),
-                      make_tuple(6, 6, subpel_avg_variance64x64_c)));
-
-#if HAVE_MMX
-const vp9_variance_fn_t variance4x4_mmx = vp9_variance4x4_mmx;
-const vp9_variance_fn_t variance8x8_mmx = vp9_variance8x8_mmx;
-const vp9_variance_fn_t variance8x16_mmx = vp9_variance8x16_mmx;
-const vp9_variance_fn_t variance16x8_mmx = vp9_variance16x8_mmx;
-const vp9_variance_fn_t variance16x16_mmx = vp9_variance16x16_mmx;
-INSTANTIATE_TEST_CASE_P(
-    MMX, VP9VarianceTest,
-    ::testing::Values(make_tuple(2, 2, variance4x4_mmx),
-                      make_tuple(3, 3, variance8x8_mmx),
-                      make_tuple(3, 4, variance8x16_mmx),
-                      make_tuple(4, 3, variance16x8_mmx),
-                      make_tuple(4, 4, variance16x16_mmx)));
-#endif
-
-#if HAVE_SSE2
 #if CONFIG_USE_X86INC
-const vp9_variance_fn_t variance4x4_sse2 = vp9_variance4x4_sse2;
-const vp9_variance_fn_t variance4x8_sse2 = vp9_variance4x8_sse2;
-const vp9_variance_fn_t variance8x4_sse2 = vp9_variance8x4_sse2;
-const vp9_variance_fn_t variance8x8_sse2 = vp9_variance8x8_sse2;
-const vp9_variance_fn_t variance8x16_sse2 = vp9_variance8x16_sse2;
-const vp9_variance_fn_t variance16x8_sse2 = vp9_variance16x8_sse2;
-const vp9_variance_fn_t variance16x16_sse2 = vp9_variance16x16_sse2;
-const vp9_variance_fn_t variance16x32_sse2 = vp9_variance16x32_sse2;
-const vp9_variance_fn_t variance32x16_sse2 = vp9_variance32x16_sse2;
-const vp9_variance_fn_t variance32x32_sse2 = vp9_variance32x32_sse2;
-const vp9_variance_fn_t variance32x64_sse2 = vp9_variance32x64_sse2;
-const vp9_variance_fn_t variance64x32_sse2 = vp9_variance64x32_sse2;
-const vp9_variance_fn_t variance64x64_sse2 = vp9_variance64x64_sse2;
+const SubpixVarMxNFunc subpel_variance64x64_sse2 =
+    vpx_sub_pixel_variance64x64_sse2;
+const SubpixVarMxNFunc subpel_variance64x32_sse2 =
+    vpx_sub_pixel_variance64x32_sse2;
+const SubpixVarMxNFunc subpel_variance32x64_sse2 =
+    vpx_sub_pixel_variance32x64_sse2;
+const SubpixVarMxNFunc subpel_variance32x32_sse2 =
+    vpx_sub_pixel_variance32x32_sse2;
+const SubpixVarMxNFunc subpel_variance32x16_sse2 =
+    vpx_sub_pixel_variance32x16_sse2;
+const SubpixVarMxNFunc subpel_variance16x32_sse2 =
+    vpx_sub_pixel_variance16x32_sse2;
+const SubpixVarMxNFunc subpel_variance16x16_sse2 =
+    vpx_sub_pixel_variance16x16_sse2;
+const SubpixVarMxNFunc subpel_variance16x8_sse2 =
+    vpx_sub_pixel_variance16x8_sse2;
+const SubpixVarMxNFunc subpel_variance8x16_sse2 =
+    vpx_sub_pixel_variance8x16_sse2;
+const SubpixVarMxNFunc subpel_variance8x8_sse2 = vpx_sub_pixel_variance8x8_sse2;
+const SubpixVarMxNFunc subpel_variance8x4_sse2 = vpx_sub_pixel_variance8x4_sse2;
+const SubpixVarMxNFunc subpel_variance4x8_sse = vpx_sub_pixel_variance4x8_sse;
+const SubpixVarMxNFunc subpel_variance4x4_sse = vpx_sub_pixel_variance4x4_sse;
 INSTANTIATE_TEST_CASE_P(
-    SSE2, VP9VarianceTest,
-    ::testing::Values(make_tuple(2, 2, variance4x4_sse2),
-                      make_tuple(2, 3, variance4x8_sse2),
-                      make_tuple(3, 2, variance8x4_sse2),
-                      make_tuple(3, 3, variance8x8_sse2),
-                      make_tuple(3, 4, variance8x16_sse2),
-                      make_tuple(4, 3, variance16x8_sse2),
-                      make_tuple(4, 4, variance16x16_sse2),
-                      make_tuple(4, 5, variance16x32_sse2),
-                      make_tuple(5, 4, variance32x16_sse2),
-                      make_tuple(5, 5, variance32x32_sse2),
-                      make_tuple(5, 6, variance32x64_sse2),
-                      make_tuple(6, 5, variance64x32_sse2),
-                      make_tuple(6, 6, variance64x64_sse2)));
+    SSE2, VpxSubpelVarianceTest,
+    ::testing::Values(make_tuple(6, 6, subpel_variance64x64_sse2, 0),
+                      make_tuple(6, 5, subpel_variance64x32_sse2, 0),
+                      make_tuple(5, 6, subpel_variance32x64_sse2, 0),
+                      make_tuple(5, 5, subpel_variance32x32_sse2, 0),
+                      make_tuple(5, 4, subpel_variance32x16_sse2, 0),
+                      make_tuple(4, 5, subpel_variance16x32_sse2, 0),
+                      make_tuple(4, 4, subpel_variance16x16_sse2, 0),
+                      make_tuple(4, 3, subpel_variance16x8_sse2, 0),
+                      make_tuple(3, 4, subpel_variance8x16_sse2, 0),
+                      make_tuple(3, 3, subpel_variance8x8_sse2, 0),
+                      make_tuple(3, 2, subpel_variance8x4_sse2, 0),
+                      make_tuple(2, 3, subpel_variance4x8_sse, 0),
+                      make_tuple(2, 2, subpel_variance4x4_sse, 0)));
 
-const vp9_subpixvariance_fn_t subpel_variance4x4_sse =
-    vp9_sub_pixel_variance4x4_sse;
-const vp9_subpixvariance_fn_t subpel_variance4x8_sse =
-    vp9_sub_pixel_variance4x8_sse;
-const vp9_subpixvariance_fn_t subpel_variance8x4_sse2 =
-    vp9_sub_pixel_variance8x4_sse2;
-const vp9_subpixvariance_fn_t subpel_variance8x8_sse2 =
-    vp9_sub_pixel_variance8x8_sse2;
-const vp9_subpixvariance_fn_t subpel_variance8x16_sse2 =
-    vp9_sub_pixel_variance8x16_sse2;
-const vp9_subpixvariance_fn_t subpel_variance16x8_sse2 =
-    vp9_sub_pixel_variance16x8_sse2;
-const vp9_subpixvariance_fn_t subpel_variance16x16_sse2 =
-    vp9_sub_pixel_variance16x16_sse2;
-const vp9_subpixvariance_fn_t subpel_variance16x32_sse2 =
-    vp9_sub_pixel_variance16x32_sse2;
-const vp9_subpixvariance_fn_t subpel_variance32x16_sse2 =
-    vp9_sub_pixel_variance32x16_sse2;
-const vp9_subpixvariance_fn_t subpel_variance32x32_sse2 =
-    vp9_sub_pixel_variance32x32_sse2;
-const vp9_subpixvariance_fn_t subpel_variance32x64_sse2 =
-    vp9_sub_pixel_variance32x64_sse2;
-const vp9_subpixvariance_fn_t subpel_variance64x32_sse2 =
-    vp9_sub_pixel_variance64x32_sse2;
-const vp9_subpixvariance_fn_t subpel_variance64x64_sse2 =
-    vp9_sub_pixel_variance64x64_sse2;
+const SubpixAvgVarMxNFunc subpel_avg_variance64x64_sse2 =
+    vpx_sub_pixel_avg_variance64x64_sse2;
+const SubpixAvgVarMxNFunc subpel_avg_variance64x32_sse2 =
+  
[... patch truncado ...]
```


_[807 arquivo(s) do commit omitido(s) do diff por limite de tamanho; todos aparecem na tabela acima.]_

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
