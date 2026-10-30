# Pacote de anotacao — caso 08

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

# Evidencia do caso 08

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-119
- arquivo da funcao marcada: `decoder/impeg2d_dec_hdr.c`

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
WORD32 impeg2d_get_slice_pos(dec_state_multi_core_t *ps_dec_state_multi_core)
{
    WORD32 u4_bits;
    WORD32 i4_row;


 dec_state_t *ps_dec = ps_dec_state_multi_core->ps_dec_state[0];
    WORD32 i4_prev_row;
 stream_t s_bitstrm;
    WORD32 i4_start_row;
    WORD32 i4_slice_bistream_ofst;
    WORD32 i;
    s_bitstrm = ps_dec->s_bit_stream;
    i4_prev_row = -1;

    ps_dec_state_multi_core->ps_dec_state[0]->i4_start_mb_y = 0;
    ps_dec_state_multi_core->ps_dec_state[1]->i4_start_mb_y = -1;
    ps_dec_state_multi_core->ps_dec_state[2]->i4_start_mb_y = -1;
    ps_dec_state_multi_core->ps_dec_state[3]->i4_start_mb_y = -1;

    ps_dec_state_multi_core->ps_dec_state[0]->i4_end_mb_y = ps_dec->u2_num_vert_mb;
    ps_dec_state_multi_core->ps_dec_state[1]->i4_end_mb_y = -1;
    ps_dec_state_multi_core->ps_dec_state[2]->i4_end_mb_y = -1;
    ps_dec_state_multi_core->ps_dec_state[3]->i4_end_mb_y = -1;

 if(ps_dec->i4_num_cores == 1)
 return 0;
 /* Reset the jobq to start of the jobq buffer */
    impeg2_jobq_reset((jobq_t *)ps_dec->pv_jobq);

    i4_start_row = -1;
    i4_slice_bistream_ofst = 0;
 while(1)
 {
        WORD32 i4_is_slice;

 if(s_bitstrm.u4_offset + START_CODE_LEN >= s_bitstrm.u4_max_offset)
 {
 break;
 }
        u4_bits = impeg2d_bit_stream_nxt(&s_bitstrm,START_CODE_LEN);

        i4_row = u4_bits & 0xFF;

 /* Detect end of frame */
        i4_is_slice = (((u4_bits >> 8) == 0x01) && (i4_row) && (i4_row <= ps_dec->u2_num_vert_mb));
 if(!i4_is_slice)
 break;


         i4_row -= 1;
 
 
        if(i4_prev_row != i4_row)
         {
             /* Create a job for previous slice row */
             if(i4_start_row != -1)
 {
 job_t s_job;
                IV_API_CALL_STATUS_T ret;
                s_job.i2_start_mb_y = i4_start_row;
                s_job.i2_end_mb_y = i4_row;
                s_job.i4_cmd = CMD_PROCESS;
                s_job.i4_bistream_ofst = i4_slice_bistream_ofst;
                ret = impeg2_jobq_queue(ps_dec->pv_jobq, &s_job, sizeof(s_job), 1, 0);
 if(ret != IV_SUCCESS)
 return ret;

 }
 /* Store current slice's bitstream offset */
            i4_slice_bistream_ofst = s_bitstrm.u4_offset >> 3;
            i4_slice_bistream_ofst -= (size_t)s_bitstrm.pv_bs_buf & 3;
            i4_prev_row = i4_row;


             /* Store current slice's row position */
             i4_start_row = i4_row;
 
         }
 
 
        impeg2d_bit_stream_flush(&s_bitstrm, START_CODE_LEN);

 /* Flush the bytes till a  start code is encountered  */
 while(impeg2d_bit_stream_nxt(&s_bitstrm, 24) != START_CODE_PREFIX)
 {
            impeg2d_bit_stream_get(&s_bitstrm, 8);

 if(s_bitstrm.u4_offset >= s_bitstrm.u4_max_offset)
 {
 break;
 }
 }
 }

 /* Create job for the last slice row */
 {
 job_t s_job;
        IV_API_CALL_STATUS_T e_ret;
        s_job.i2_start_mb_y = i4_start_row;
        s_job.i2_end_mb_y = ps_dec->u2_num_vert_mb;
        s_job.i4_cmd = CMD_PROCESS;
        s_job.i4_bistream_ofst = i4_slice_bistream_ofst;
        e_ret = impeg2_jobq_queue(ps_dec->pv_jobq, &s_job, sizeof(s_job), 1, 0);
 if(e_ret != IV_SUCCESS)
 return e_ret;

 }
 if((NULL != ps_dec->ps_disp_pic) && ((0 == ps_dec->u4_share_disp_buf) || (IV_YUV_420P != ps_dec->i4_chromaFormat)))
 {
 for(i = 0; i < ps_dec->u2_vertical_size; i+=64)
 {
 job_t s_job;
            IV_API_CALL_STATUS_T ret;
            s_job.i2_start_mb_y = i;
            s_job.i2_start_mb_y >>= 4;
            s_job.i2_end_mb_y = (i + 64);
            s_job.i2_end_mb_y >>= 4;
            s_job.i4_cmd = CMD_FMTCONV;
            s_job.i4_bistream_ofst = 0;
            ret = impeg2_jobq_queue(ps_dec->pv_jobq, &s_job, sizeof(s_job), 1, 0);
 if(ret != IV_SUCCESS)
 return ret;

 }
 }

    impeg2_jobq_terminate(ps_dec->pv_jobq);
    ps_dec->i4_bytes_consumed = s_bitstrm.u4_offset >> 3;
    ps_dec->i4_bytes_consumed -= ((size_t)s_bitstrm.pv_bs_buf & 3);

 return 0;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `decoder/impeg2d_dec_hdr.c` **(funcao marcada esta aqui)** |  |  |  |


### `decoder/impeg2d_dec_hdr.c`

```diff
@@ -18,6 +18,7 @@

  * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
 #include <string.h>
+#include <cutils/log.h>
 
 #include "iv_datatypedef.h"
 #include "iv.h"
@@ -915,6 +916,12 @@

             temp = u4_bits_read & 0xFF;
             i4_continue_decode = (((u4_bits_read >> 8) == 0x01) && (temp) && (temp <= 0xAF));
 
+            if (1 == ps_dec->i4_num_cores && 0 == ps_dec->u2_num_mbs_left)
+            {
+                i4_continue_decode = 0;
+                android_errorWriteLog(0x534e4554, "26070014");
+            }
+
             if(i4_continue_decode)
             {
                 /* If the slice is from the same row, then continue decoding without dequeue */
@@ -1148,7 +1155,7 @@

         i4_row -= 1;
 
 
-        if(i4_prev_row != i4_row)
+        if(i4_prev_row < i4_row)
         {
             /* Create a job for previous slice row */
             if(i4_start_row != -1)
@@ -1172,6 +1179,8 @@

             /* Store current slice's row position */
             i4_start_row = i4_row;
 
+        } else if (i4_prev_row > i4_row) {
+            android_errorWriteLog(0x534e4554, "26070014");
         }
 
 

```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
