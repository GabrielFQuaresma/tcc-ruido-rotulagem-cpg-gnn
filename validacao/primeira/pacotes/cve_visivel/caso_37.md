# Pacote de anotacao — caso 37

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

# Evidencia do caso 37

## Identificacao

- projeto: Android
- CVE: CVE-2017-0587
- CWE atribuida pelo BigVul: CWE-119
- commit: `a86eb798d077b9b25c8f8c77e3c02c2f287c1ce7`
- URL do commit: https://android.googlesource.com/platform/external/libmpeg2/+/a86eb798d077b9b25c8f8c77e3c02c2f287c1ce7
- arquivo da funcao marcada: `decoder/impeg2d_dec_hdr.c`

## Mensagem do commit

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

## Resumo da CVE

> A remote code execution vulnerability in libmpeg2 in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2. Android ID: A-35219737.

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
IMPEG2D_ERROR_CODES_T impeg2d_dec_seq_hdr(dec_state_t *ps_dec)
{
 stream_t *ps_stream;
    ps_stream = &ps_dec->s_bit_stream;
    UWORD16 u2_height;
    UWORD16 u2_width;

 if (impeg2d_bit_stream_nxt(ps_stream,START_CODE_LEN) != SEQUENCE_HEADER_CODE)
 {
        impeg2d_bit_stream_flush(ps_stream,START_CODE_LEN);
 return IMPEG2D_FRM_HDR_START_CODE_NOT_FOUND;

 }
    impeg2d_bit_stream_flush(ps_stream,START_CODE_LEN);

    u2_width    = impeg2d_bit_stream_get(ps_stream,12);
    u2_height   = impeg2d_bit_stream_get(ps_stream,12);

 if ((u2_width != ps_dec->u2_horizontal_size)
 || (u2_height != ps_dec->u2_vertical_size))
 {
 if (0 == ps_dec->u2_header_done)
 {
 /* This is the first time we are reading the resolution */
            ps_dec->u2_horizontal_size = u2_width;
            ps_dec->u2_vertical_size = u2_height;
 if (0 == ps_dec->u4_frm_buf_stride)
 {
                ps_dec->u4_frm_buf_stride  = (UWORD32) (u2_width);
 }
 }
 else
 {
 if((u2_width > ps_dec->u2_create_max_width)
 || (u2_height > ps_dec->u2_create_max_height))
 {
                IMPEG2D_ERROR_CODES_T e_error = IMPEG2D_UNSUPPORTED_DIMENSIONS;

                ps_dec->u2_reinit_max_height   = u2_height;
                ps_dec->u2_reinit_max_width    = u2_width;

 return e_error;
 }
 else
 {
 /* The resolution has changed */
 return (IMPEG2D_ERROR_CODES_T)IVD_RES_CHANGED;
 }
 }
 }

 if((ps_dec->u2_horizontal_size > ps_dec->u2_create_max_width)

                     || (ps_dec->u2_vertical_size > ps_dec->u2_create_max_height))
     {
         IMPEG2D_ERROR_CODES_T e_error = IMPEG2D_UNSUPPORTED_DIMENSIONS;
        return SET_IVD_FATAL_ERROR(e_error);
     }
 
 
 /*------------------------------------------------------------------------*/
 /* Flush the following as they are not being used                         */
 /* aspect_ratio_info (4 bits)                                             */
 /*------------------------------------------------------------------------*/
    ps_dec->u2_aspect_ratio_info = impeg2d_bit_stream_get(ps_stream,4);

 /*------------------------------------------------------------------------*/
 /* Frame rate code(4 bits)                                                */
 /*------------------------------------------------------------------------*/
    ps_dec->u2_frame_rate_code = impeg2d_bit_stream_get(ps_stream,4);
 if (ps_dec->u2_frame_rate_code > MPEG2_MAX_FRAME_RATE_CODE)
 {
 return IMPEG2D_FRM_HDR_DECODE_ERR;
 }
 /*------------------------------------------------------------------------*/
 /* Flush the following as they are not being used                         */
 /* bit_rate_value (18 bits)                                               */
 /*------------------------------------------------------------------------*/
    impeg2d_bit_stream_flush(ps_stream,18);
    GET_MARKER_BIT(ps_dec,ps_stream);
 /*------------------------------------------------------------------------*/
 /* Flush the following as they are not being used                         */
 /* vbv_buffer_size_value(10 bits), constrained_parameter_flag (1 bit)     */
 /*------------------------------------------------------------------------*/
    impeg2d_bit_stream_flush(ps_stream,11);

 /*------------------------------------------------------------------------*/
 /* Quantization matrix for the intra blocks                               */
 /*------------------------------------------------------------------------*/
 if(impeg2d_bit_stream_get_bit(ps_stream) == 1)
 {
        UWORD16 i;
 for(i = 0; i < NUM_PELS_IN_BLOCK; i++)
 {
            ps_dec->au1_intra_quant_matrix[gau1_impeg2_inv_scan_zig_zag[i]] = (UWORD8)impeg2d_bit_stream_get(ps_stream,8);
 }

 }
 else
 {
        memcpy(ps_dec->au1_intra_quant_matrix,gau1_impeg2_intra_quant_matrix_default,
                NUM_PELS_IN_BLOCK);
 }

 /*------------------------------------------------------------------------*/
 /* Quantization matrix for the inter blocks                               */
 /*------------------------------------------------------------------------*/
 if(impeg2d_bit_stream_get_bit(ps_stream) == 1)
 {
        UWORD16 i;
 for(i = 0; i < NUM_PELS_IN_BLOCK; i++)
 {
            ps_dec->au1_inter_quant_matrix[gau1_impeg2_inv_scan_zig_zag[i]] = (UWORD8)impeg2d_bit_stream_get(ps_stream,8);
 }
 }
 else
 {
        memcpy(ps_dec->au1_inter_quant_matrix,gau1_impeg2_inter_quant_matrix_default,
            NUM_PELS_IN_BLOCK);
 }
    impeg2d_next_start_code(ps_dec);

 return (IMPEG2D_ERROR_CODES_T)IVD_ERROR_NONE;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **3**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `decoder/impeg2d_api_main.c` |  |  |  |
| `decoder/impeg2d_dec_hdr.c` **(funcao marcada esta aqui)** |  |  |  |
| `decoder/impeg2d_decoder.c` |  |  |  |


### `decoder/impeg2d_dec_hdr.c`

```diff
@@ -189,7 +189,9 @@

                     || (ps_dec->u2_vertical_size > ps_dec->u2_create_max_height))
     {
         IMPEG2D_ERROR_CODES_T e_error = IMPEG2D_UNSUPPORTED_DIMENSIONS;
-        return SET_IVD_FATAL_ERROR(e_error);
+        ps_dec->u2_reinit_max_height   = ps_dec->u2_vertical_size;
+        ps_dec->u2_reinit_max_width    = ps_dec->u2_horizontal_size;
+        return e_error;
     }
 
 

```


### `decoder/impeg2d_api_main.c`

```diff
@@ -3136,7 +3136,8 @@

         bytes_remaining -= ps_dec_op->s_ivd_video_decode_op_t.u4_num_bytes_consumed;
     }
 
-    if((1 != ps_dec_state->u2_decode_header) && ((bytes_remaining > 0) || ps_dec_state->u1_flushfrm))
+    if((1 != ps_dec_state->u2_decode_header) &&
+        (((bytes_remaining > 0) && (1 == ps_dec_state->u2_header_done)) || ps_dec_state->u1_flushfrm))
     {
         if(ps_dec_state->u1_flushfrm)
         {

```


### `decoder/impeg2d_decoder.c`

```diff
@@ -123,7 +123,14 @@

                 if(ps_op->s_ivd_video_decode_op_t.u4_error_code == 0)
                     ps_op->s_ivd_video_decode_op_t.u4_error_code = e_error;
 
+                if (IMPEG2D_UNSUPPORTED_DIMENSIONS == e_error)
+                {
+                    ps_op->s_ivd_video_decode_op_t.u4_num_bytes_consumed = 0;
+                    ps_dec->u2_header_done = 0;
 
+                    ps_op->s_ivd_video_decode_op_t.u4_pic_ht = ps_dec->u2_reinit_max_height;
+                    ps_op->s_ivd_video_decode_op_t.u4_pic_wd = ps_dec->u2_reinit_max_width;
+                }
                 impeg2d_next_code(ps_dec, SEQUENCE_HEADER_CODE);
                 return;
             }

```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
