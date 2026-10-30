# Pacote de anotacao — caso 44

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

# Evidencia do caso 44

## Identificacao

- projeto: _[removido nesta condicao]_
- CVE: _[removida nesta condicao]_
- CWE atribuida pelo BigVul: CWE-125
- arquivo da funcao marcada: `src/f_hmp.c`

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
_WM_ParseNewHmp(uint8_t *hmp_data, uint32_t hmp_size) {
    uint8_t is_hmp2 = 0;
    uint32_t zero_cnt = 0;
    uint32_t i = 0;
    uint32_t hmp_file_length = 0;
    uint32_t hmp_chunks = 0;
    uint32_t hmp_divisions = 0;
    uint32_t hmp_unknown = 0;
    uint32_t hmp_bpm = 0;
    uint32_t hmp_song_time = 0;
    struct _mdi *hmp_mdi;
    uint8_t **hmp_chunk;
    uint32_t *chunk_length;
    uint32_t *chunk_ofs;
    uint32_t *chunk_delta;
    uint8_t *chunk_end;
    uint32_t chunk_num = 0;
    uint32_t hmp_track = 0;
    uint32_t smallest_delta = 0;
    uint32_t subtract_delta = 0;
    uint32_t end_of_chunks = 0;
    uint32_t var_len_shift = 0;

    float tempo_f = 500000.0;
    float samples_per_delta_f = 0.0;


    uint32_t sample_count = 0;
    float sample_count_f = 0;
    float sample_remainder = 0;

    if (memcmp(hmp_data, "HMIMIDIP", 8)) {
        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMP, NULL, 0);
        return NULL;
    }
    hmp_data += 8;
    hmp_size -= 8;

    if (!memcmp(hmp_data, "013195", 6)) {
        hmp_data += 6;
        hmp_size -= 6;
        is_hmp2 = 1;
    }

    if (is_hmp2) {
        zero_cnt = 18;
    } else {
        zero_cnt = 24;
    }
    for (i = 0; i < zero_cnt; i++) {
        if (hmp_data[i] != 0) {
            _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMP, NULL, 0);
            return NULL;
        }
    }
    hmp_data += zero_cnt;
    hmp_size -= zero_cnt;

    hmp_file_length = *hmp_data++;
    hmp_file_length += (*hmp_data++ << 8);
    hmp_file_length += (*hmp_data++ << 16);
    hmp_file_length += (*hmp_data++ << 24);
    hmp_size -= 4;

    UNUSED(hmp_file_length);

    hmp_data += 12;
    hmp_size -= 12;

    hmp_chunks = *hmp_data++;
    hmp_chunks += (*hmp_data++ << 8);
    hmp_chunks += (*hmp_data++ << 16);
    hmp_chunks += (*hmp_data++ << 24);
    hmp_size -= 4;

    hmp_unknown = *hmp_data++;
    hmp_unknown += (*hmp_data++ << 8);
    hmp_unknown += (*hmp_data++ << 16);
    hmp_unknown += (*hmp_data++ << 24);
    hmp_size -= 4;

    UNUSED(hmp_unknown);

    hmp_divisions = 60;

    hmp_bpm = *hmp_data++;
    hmp_bpm += (*hmp_data++ << 8);
    hmp_bpm += (*hmp_data++ << 16);
    hmp_bpm += (*hmp_data++ << 24);
    hmp_size -= 4;

    /* Slow but needed for accuracy */
    if ((_WM_MixerOptions & WM_MO_ROUNDTEMPO)) {
        tempo_f = (float) (60000000 / hmp_bpm) + 0.5f;
    } else {
        tempo_f = (float) (60000000 / hmp_bpm);
    }

    samples_per_delta_f = _WM_GetSamplesPerTick(hmp_divisions, tempo_f);


    hmp_song_time = *hmp_data++;
    hmp_song_time += (*hmp_data++ << 8);
    hmp_song_time += (*hmp_data++ << 16);
    hmp_song_time += (*hmp_data++ << 24);
    hmp_size -= 4;


    UNUSED(hmp_song_time);

    if (is_hmp2) {
        hmp_data += 840;
        hmp_size -= 840;
    } else {
        hmp_data += 712;
        hmp_size -= 712;
    }

    hmp_mdi = _WM_initMDI();

    _WM_midi_setup_divisions(hmp_mdi, hmp_divisions);
    _WM_midi_setup_tempo(hmp_mdi, (uint32_t)tempo_f);

    hmp_chunk = malloc(sizeof(uint8_t *) * hmp_chunks);
    chunk_length = malloc(sizeof(uint32_t) * hmp_chunks);
    chunk_delta = malloc(sizeof(uint32_t) * hmp_chunks);
    chunk_ofs = malloc(sizeof(uint32_t) * hmp_chunks);
    chunk_end = malloc(sizeof(uint8_t) * hmp_chunks);

    smallest_delta = 0xffffffff;
    for (i = 0; i < hmp_chunks; i++) {
        hmp_chunk[i] = hmp_data;
        chunk_ofs[i] = 0;

        chunk_num = *hmp_data++;
        chunk_num += (*hmp_data++ << 8);
        chunk_num += (*hmp_data++ << 16);
        chunk_num += (*hmp_data++ << 24);
        chunk_ofs[i] += 4;

        UNUSED(chunk_num);

        chunk_length[i] = *hmp_data++;
        chunk_length[i] += (*hmp_data++ << 8);
        chunk_length[i] += (*hmp_data++ << 16);
        chunk_length[i] += (*hmp_data++ << 24);
        chunk_ofs[i] += 4;

        if (chunk_length[i] > hmp_size) {
            _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMP, "file too short", 0);
            goto _hmp_end;
        }
        hmp_size -= chunk_length[i];

        hmp_track = *hmp_data++;
        hmp_track += (*hmp_data++ << 8);
        hmp_track += (*hmp_data++ << 16);
        hmp_track += (*hmp_data++ << 24);
        chunk_ofs[i] += 4;

        UNUSED(hmp_track);

        chunk_delta[i] = 0;
        var_len_shift = 0;
        if (*hmp_data < 0x80) {
            do {
                chunk_delta[i] = chunk_delta[i] | ((*hmp_data++ & 0x7F) << var_len_shift);
                var_len_shift += 7;
                chunk_ofs[i]++;
            } while (*hmp_data < 0x80);
        }
        chunk_delta[i] = chunk_delta[i] | ((*hmp_data++ & 0x7F) << var_len_shift);
        chunk_ofs[i]++;

        if (chunk_delta[i] < smallest_delta) {
            smallest_delta = chunk_delta[i];
        }
 
         hmp_data = hmp_chunk[i] + chunk_length[i];
         hmp_chunk[i] += chunk_ofs[i]++;
         chunk_end[i] = 0;
     }

    subtract_delta = smallest_delta;
    sample_count_f = (((float) smallest_delta * samples_per_delta_f) + sample_remainder);

    sample_count = (uint32_t) sample_count_f;
    sample_remainder = sample_count_f - (float) sample_count;

    hmp_mdi->events[hmp_mdi->event_count - 1].samples_to_next += sample_count;
    hmp_mdi->extra_info.approx_total_samples += sample_count;

    while (end_of_chunks < hmp_chunks) {
        smallest_delta = 0;


        for (i = 0; i < hmp_chunks; i++) {
            if (chunk_end[i])
                continue;

            if (chunk_delta[i]) {
                chunk_delta[i] -= subtract_delta;
                if (chunk_delta[i]) {
                    if ((!smallest_delta)
                        || (smallest_delta > chunk_delta[i])) {
                        smallest_delta = chunk_delta[i];
                    }
                    continue;
                }
            }
            do {
                if (((hmp_chunk[i][0] & 0xf0) == 0xb0 ) && ((hmp_chunk[i][1] == 110) || (hmp_chunk[i][1] == 111)) && (hmp_chunk[i][2] > 0x7f)) {
                     hmp_chunk[i] += 3;
                 } else {
                     uint32_t setup_ret = 0;
 
                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], 0)) == 0) {
                         goto _hmp_end;
                     }
 
                     if ((hmp_chunk[i][0] == 0xff) && (hmp_chunk[i][1] == 0x2f) && (hmp_chunk[i][2] == 0x00)) {
                         /* End of Chunk */
                         end_of_chunks++;
                         chunk_end[i] = 1;
                         hmp_chunk[i] += 3;
                         goto NEXT_CHUNK;
                     } else if ((hmp_chunk[i][0] == 0xff) && (hmp_chunk[i][1] == 0x51) && (hmp_chunk[i][2] == 0x03)) {
                        /* Tempo */
                        tempo_f = (float)((hmp_chunk[i][3] << 16) + (hmp_chunk[i][4] << 8)+ hmp_chunk[i][5]);
                        if (tempo_f == 0.0)
                            tempo_f = 500000.0;

                         fprintf(stderr,"DEBUG: Tempo change %f\r\n", tempo_f);
                     }
                     hmp_chunk[i] += setup_ret;
                 }
                 var_len_shift = 0;
                 chunk_delta[i] = 0;
                if (*hmp_chunk[i] < 0x80) {
                     do {
                         chunk_delta[i] = chunk_delta[i] + ((*hmp_chunk[i] & 0x7F) << var_len_shift);
                         var_len_shift += 7;
                         hmp_chunk[i]++;
                     } while (*hmp_chunk[i] < 0x80);
                 }
                 chunk_delta[i] = chunk_delta[i] + ((*hmp_chunk[i] & 0x7F) << var_len_shift);
                 hmp_chunk[i]++;
             } while (!chunk_delta[i]);
 
             if ((!smallest_delta) || (smallest_delta > chunk_delta[i])) {
                smallest_delta = chunk_delta[i];
            }
        NEXT_CHUNK: continue;
        }

        subtract_delta = smallest_delta;
        sample_count_f= (((float) smallest_delta * samples_per_delta_f) + sample_remainder);

        sample_count = (uint32_t) sample_count_f;
        sample_remainder = sample_count_f - (float) sample_count;

        hmp_mdi->events[hmp_mdi->event_count - 1].samples_to_next += sample_count;
        hmp_mdi->extra_info.approx_total_samples += sample_count;

    }

    if ((hmp_mdi->reverb = _WM_init_reverb(_WM_SampleRate, _WM_reverb_room_width, _WM_reverb_room_length, _WM_reverb_listen_posx, _WM_reverb_listen_posy)) == NULL) {
        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_MEM, "to init reverb", 0);
        goto _hmp_end;
    }

    hmp_mdi->extra_info.current_sample = 0;
    hmp_mdi->current_event = &hmp_mdi->events[0];
    hmp_mdi->samples_to_mix = 0;
    hmp_mdi->note = NULL;

    _WM_ResetToStart(hmp_mdi);

_hmp_end:
    free(hmp_chunk);
    free(chunk_length);
    free(chunk_delta);
    free(chunk_ofs);
    free(chunk_end);
    if (hmp_mdi->reverb) return (hmp_mdi);
    _WM_freeMDI(hmp_mdi);
    return NULL;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **7**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `include/internal_midi.h` | modified | 1 | 1 |
| `src/f_hmi.c` | modified | 34 | 6 |
| `src/f_hmp.c` **(funcao marcada esta aqui)** | modified | 13 | 2 |
| `src/f_midi.c` | modified | 37 | 18 |
| `src/f_mus.c` | modified | 3 | 2 |
| `src/f_xmidi.c` | modified | 1 | 1 |
| `src/internal_midi.c` | modified | 73 | 10 |


### `src/f_hmp.c`

```diff
@@ -235,6 +235,7 @@ _WM_ParseNewHmp(uint8_t *hmp_data, uint32_t hmp_size) {
 
         // goto start of next chunk
         hmp_data = hmp_chunk[i] + chunk_length[i];
+        chunk_length[i] -= chunk_ofs[i];
         hmp_chunk[i] += chunk_ofs[i]++;
         chunk_end[i] = 0;
     }
@@ -273,17 +274,19 @@ _WM_ParseNewHmp(uint8_t *hmp_data, uint32_t hmp_size) {
                     // Reserved for loop markers
                     // TODO: still deciding what to do about these
                     hmp_chunk[i] += 3;
+                    chunk_length[i] -= 3;
                 } else {
                     uint32_t setup_ret = 0;
 
-                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], 0)) == 0) {
+                    if ((setup_ret = _WM_SetupMidiEvent(hmp_mdi, hmp_chunk[i], chunk_length[i], 0)) == 0) {
                         goto _hmp_end;
                     }
 
                     if ((hmp_chunk[i][0] == 0xff) && (hmp_chunk[i][1] == 0x2f) && (hmp_chunk[i][2] == 0x00)) {
                         /* End of Chunk */
                         end_of_chunks++;
                         chunk_end[i] = 1;
+                        chunk_length[i] -= 3;
                         hmp_chunk[i] += 3;
                         goto NEXT_CHUNK;
                     } else if ((hmp_chunk[i][0] == 0xff) && (hmp_chunk[i][1] == 0x51) && (hmp_chunk[i][2] == 0x03)) {
@@ -296,18 +299,26 @@ _WM_ParseNewHmp(uint8_t *hmp_data, uint32_t hmp_size) {
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


### `include/internal_midi.h`

```diff
@@ -191,7 +191,7 @@ extern int _WM_midi_setup_divisions(struct _mdi *mdi, uint32_t divisions);
 
 extern struct _mdi * _WM_initMDI(void);
 extern void _WM_freeMDI(struct _mdi *mdi);
-extern uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t running_event);
+extern uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint32_t siz, uint8_t running_event);
 extern void _WM_ResetToStart(struct _mdi *mdi);
 extern void _WM_do_pan_adjust(struct _mdi *mdi, uint8_t ch);
 extern void _WM_do_note_off_extra(struct _note *nte);
```


### `src/f_hmi.c`

```diff
@@ -42,10 +42,10 @@ struct _mdi *
 _WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
     uint32_t hmi_tmp = 0;
     uint8_t *hmi_base = hmi_data;
+    uint32_t data_siz;
     uint16_t hmi_bpm = 0;
     uint16_t hmi_division = 0;
 
-//  uint32_t hmi_duration_secs = 0;
     uint32_t hmi_track_cnt = 0;
     uint32_t *hmi_track_offset = NULL;
     uint32_t i = 0;
@@ -74,8 +74,6 @@ _WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
         uint8_t channel;
     } *note;
 
-    //FIXME: This needs to be used for sanity check.
-    UNUSED(hmi_size);
 
     if (memcmp(hmi_data, "HMI-MIDISONG061595", 18)) {
         _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, NULL, 0);
@@ -216,21 +214,35 @@ _WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
             do {
                 hmi_data = hmi_base + hmi_track_offset[i];
                 hmi_delta[i] = 0;
+                if (hmi_track_offset[i] >= hmi_size) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                    goto _hmi_end;
+                }
+                data_siz = hmi_size - hmi_track_offset[i];
 
                 if (hmi_data[0] == 0xfe) {
                     // HMI only event of some sort.
                     if (hmi_data[1] == 0x10) {
                         hmi_tmp = (hmi_data[4] + 5);
                         hmi_data += hmi_tmp;
                         hmi_track_offset[i] += hmi_tmp;
+                        hmi_tmp += 4;
                     } else if (hmi_data[1] == 0x15) {
                         hmi_data += 4;
                         hmi_track_offset[i] += 4;
+                        hmi_tmp = 8;
+                    } else {
+                        hmi_tmp = 4;
                     }
                     hmi_data += 4;
                     hmi_track_offset[i] += 4;
+                    if (hmi_tmp > data_siz) {
+                        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                        goto _hmi_end;
+                    }
+                    data_siz -= hmi_tmp;
                 } else {
-                    if ((setup_ret = _WM_SetupMidiEvent(hmi_mdi,hmi_data,hmi_running_event[i])) == 0) {
+                    if ((setup_ret = _WM_SetupMidiEvent(hmi_mdi,hmi_data,data_siz,hmi_running_event[i])) == 0) {
                         goto _hmi_end;
                     }
                     if ((hmi_data[0] == 0xff) && (hmi_data[1] == 0x2f) && (hmi_data[2] == 0x00)) {
@@ -269,17 +281,25 @@ _WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
 
                         hmi_data += setup_ret;
                         hmi_track_offset[i] += setup_ret;
+                        data_siz -= setup_ret;
 
                         note[hmi_tmp].length = 0;
-                        if (*hmi_data > 0x7f) {
+                        if (data_siz && *hmi_data > 0x7f) {
                             do {
+                                if (!data_siz) break;
                                 note[hmi_tmp].length = (note[hmi_tmp].length << 7) | (*hmi_data & 0x7F);
                                 hmi_data++;
+                                data_siz--;
                                 hmi_track_offset[i]++;
                             } while (*hmi_data > 0x7F);
                         }
+                        if (!data_siz) {
+                            _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                            goto _hmi_end;
+                        }
                         note[hmi_tmp].length = (note[hmi_tmp].length << 7) | (*hmi_data & 0x7F);
                         hmi_data++;
+                        data_siz--;
                         hmi_track_offset[i]++;
 
                         if (note[hmi_tmp].length) {
@@ -293,20 +313,28 @@ _WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
                     } else {
                         hmi_data += setup_ret;
                         hmi_track_offset[i] += setup_ret;
+                        data_siz -= setup_ret;
                     }
                 }
 
                 // get track delta
                 // hmi_delta[i] = 0; // set at start of loop
-                if (*hmi_data > 0x7f) {
+                if (data_siz && *hmi_data > 0x7f) {
                     do {
+                        if (!data_siz) break;
                         hmi_delta[i] = (hmi_delta[i] << 7) | (*hmi_data & 0x7F);
                         hmi_data++;
+                        data_siz--;
                         hmi_track_offset[i]++;
                     } while (*hmi_data > 0x7F);
                 }
+                if (!data_siz) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                    goto _hmi_end;
+                }
                 hmi_delta[i] = (hmi_delta[i] << 7) | (*hmi_data & 0x7F);
                 hmi_data++;
+                data_siz--;
                 hmi_track_offset[i]++;
             } while (!hmi_delta[i]);
             if ((!smallest_delta) || (smallest_delta > hmi_delta[i])) {
```


### `src/f_midi.c`

```diff
@@ -43,8 +43,8 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
 
     uint32_t tmp_val;
     uint32_t midi_type;
-    uint32_t track_size;
     uint8_t **tracks;
+    uint32_t *track_size;
     uint32_t end_of_tracks = 0;
     uint32_t no_tracks;
     uint32_t i;
@@ -56,15 +56,11 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
     float sample_count_f = 0.0;
     float sample_remainder = 0.0;
     uint8_t *sysex_store = NULL;
-//  uint32_t sysex_store_len = 0;
 
     uint32_t *track_delta;
     uint8_t *track_end;
     uint32_t smallest_delta = 0;
     uint32_t subtract_delta = 0;
-//  uint32_t tmp_length = 0;
-//  uint8_t current_event = 0;
-//  uint8_t current_event_ch = 0;
     uint8_t *running_event;
     uint32_t setup_ret = 0;
 
@@ -151,6 +147,7 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
     _WM_midi_setup_divisions(mdi,divisions);
 
     tracks = malloc(sizeof(uint8_t *) * no_tracks);
+    track_size = malloc(sizeof(uint32_t) * no_tracks);
     track_delta = malloc(sizeof(uint32_t) * no_tracks);
     track_end = malloc(sizeof(uint8_t) * no_tracks);
     running_event = malloc(sizeof(uint8_t) * no_tracks);
@@ -168,38 +165,42 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
         midi_data += 4;
         midi_size -= 4;
 
-        track_size = *midi_data++ << 24;
-        track_size |= *midi_data++ << 16;
-        track_size |= *midi_data++ << 8;
-        track_size |= *midi_data++;
+        /* track size */
+        tmp_val = *midi_data++ << 24;
+        tmp_val |= *midi_data++ << 16;
+        tmp_val |= *midi_data++ << 8;
+        tmp_val |= *midi_data++;
         midi_size -= 4;
-        if (midi_size < track_size) {
+        if (midi_size < tmp_val) {
             _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
             goto _end;
         }
-        if (track_size < 3) {
+        if (tmp_val < 3) {
             _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(bad track size)", 0);
             goto _end;
         }
-        if ((midi_data[track_size - 3] != 0xFF)
-                || (midi_data[track_size - 2] != 0x2F)
-                || (midi_data[track_size - 1] != 0x00)) {
+        if ((midi_data[tmp_val - 3] != 0xFF)
+                || (midi_data[tmp_val - 2] != 0x2F)
+                || (midi_data[tmp_val - 1] != 0x00)) {
             _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(missing EOT)", 0);
             goto _end;
         }
         tracks[i] = midi_data;
-        midi_data += track_size;
-        midi_size -= track_size;
+        track_size[i] = tmp_val;
+        midi_data += tmp_val;
+        midi_size -= tmp_val;
         track_end[i] = 0;
         running_event[i] = 0;
         track_delta[i] = 0;
 
         while (*tracks[i] > 0x7F) {
             track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
             tracks[i]++;
+            track_size[i]--;
         }
         track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
         tracks[i]++;
+        track_size[i]--;
 
         if (midi_type == 1 ) {
             if (track_delta[i] < smallest_delta) {
@@ -243,7 +244,7 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
                     }
                 }
                 do {
-                    setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], running_event[i]);
+                    setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], track_size[i], running_event[i]);
                     if (setup_ret == 0) {
                         goto _end;
                     }
@@ -259,6 +260,7 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
                             end_of_tracks++;
                             track_end[i] = 1;
                             tracks[i] += 3;
+                            track_size[i] -= 3;
                             goto NEXT_TRACK;
                         } else if ((tracks[i][0] == 0xff) && (tracks[i][1] == 0x51) && (tracks[i][2] == 0x03)) {
                             /* Tempo */
@@ -270,15 +272,23 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
                         }
                     }
                     tracks[i] += setup_ret;
+                    track_size[i] -= setup_ret;
 
                     if (*tracks[i] > 0x7f) {
                         do {
+                            if (!track_size[i]) break;
                             track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                             tracks[i]++;
+                            track_size[i]--;
                         } while (*tracks[i] > 0x7f);
                     }
+                    if (!track_size[i]) {
+                        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
+                        goto _end;
+                    }
                     track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                     tracks[i]++;
+                    track_size[i]--;
                 } while (!track_delta[i]);
                 if ((!smallest_delta) || (smallest_delta > track_delta[i])) {
                     smallest_delta = track_delta[i];
@@ -304,7 +314,7 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
         for (i = 0; i < no_tracks; i++) {
             running_event[i] = 0;
             do {
-                setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], running_event[i]);
+                setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], track_size[i], running_event[i]);
                 if (setup_ret == 0) {
                     goto _end;
                 }
@@ -329,16 +339,24 @@ _WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
                     }
                 }
                 tracks[i] += setup_ret;
+                track_size[i] -= setup_ret;
 
                 track_delta[i] = 0;
                 if (*tracks[i] > 0x7f) {
                     do {
+                        if (!track_size[i]) break;
                         track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                         tracks[i]++;
+                        track_size[i]--;
                     } while (*tracks[i] > 0x7f);
                 }
+                if (!track_size[i]) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
+                    goto _end;
+                }
                 track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                 tracks[i]++;
+                track_size[i]--;
 
                 sample_count_f = (((float) track_delta[i] * samples_per_delta_f)
                                   + sample_remainder);
@@ -372,6 +390,7 @@ _end:   free(sysex_store);
     free(track_delta);
     free(running_event);
     free(tracks);
+    free(track_size);
     if (mdi->reverb) return (mdi);
     _WM_freeMDI(mdi);
     return (NULL);
```


### `src/f_mus.c`

```diff
@@ -61,7 +61,8 @@ _WM_ParseNewMus(uint8_t *mus_data, uint32_t mus_size) {
     float tempo_f = 0.0;
     uint16_t mus_freq = 0;
     float samples_per_tick_f = 0.0;
-    uint8_t mus_event[] = { 0, 0, 0, 0 };
+#define MUS_SZ 4
+    uint8_t mus_event[MUS_SZ] = { 0, 0, 0, 0 };
     uint8_t mus_event_size = 0;
     uint8_t mus_prev_vol[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
     uint32_t setup_ret = 0;
@@ -314,7 +315,7 @@ _WM_ParseNewMus(uint8_t *mus_data, uint32_t mus_size) {
                 break;
         }
 
-        setup_ret = _WM_SetupMidiEvent(mus_mdi, (uint8_t *)mus_event, 0);
+        setup_ret = _WM_SetupMidiEvent(mus_mdi, (uint8_t *)mus_event, MUS_SZ, 0);
         if (setup_ret == 0) {
             goto _mus_end;
         }
```


### `src/f_xmidi.c`

```diff
@@ -267,7 +267,7 @@ struct _mdi *_WM_ParseNewXmi(uint8_t *xmi_data, uint32_t xmi_size) {
                             setup_ret = 6;
                             goto _XMI_Next_Event;
                         }
-                        if ((setup_ret = _WM_SetupMidiEvent(xmi_mdi,xmi_data,0)) == 0) {
+                        if ((setup_ret = _WM_SetupMidiEvent(xmi_mdi,xmi_data, xmi_size, 0)) == 0) {
                             goto _xmi_end;
                         }
 
```


### `src/internal_midi.c`

```diff
@@ -1962,7 +1962,7 @@ void _WM_freeMDI(struct _mdi *mdi) {
     free(mdi);
 }
 
-uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t running_event) {
+uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint32_t siz, uint8_t running_event) {
     /*
      Only add standard MIDI and Sysex events in here.
      Non-standard events need to be handled by calling function
@@ -1978,10 +1978,13 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
     uint8_t data_2 = 0;
     char *text = NULL;
 
+    if (!siz) goto shortbuf;
+
     if (event_data[0] >= 0x80) {
         command = *event_data & 0xf0;
         channel = *event_data++ & 0x0f;
         ret_cnt++;
+        if (--siz == 0) goto shortbuf;
     } else {
         command = running_event & 0xf0;
         channel = running_event & 0x0f;
@@ -1990,25 +1993,29 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
     switch(command) {
         case 0x80:
         _SETUP_NOTEOFF:
+            if (siz < 2) goto shortbuf;
             data_1 = *event_data++;
             data_2 = *event_data++;
             _WM_midi_setup_noteoff(mdi, channel, data_1, data_2);
             ret_cnt += 2;
             break;
         case 0x90:
             if (event_data[1] == 0) goto _SETUP_NOTEOFF; /* A velocity of 0 in a note on is actually a note off */
+            if (siz < 2) goto shortbuf;
             data_1 = *event_data++;
             data_2 = *event_data++;
             midi_setup_noteon(mdi, channel, data_1, data_2);
             ret_cnt += 2;
             break;
         case 0xa0:
+            if (siz < 2) goto shortbuf;
             data_1 = *event_data++;
             data_2 = *event_data++;
             midi_setup_aftertouch(mdi, channel, data_1, data_2);
             ret_cnt += 2;
             break;
         case 0xb0:
+            if (siz < 2) goto shortbuf;
             data_1 = *event_data++;
             data_2 = *event_data++;
             midi_setup_control(mdi, channel, data_1, data_2);
@@ -2025,6 +2032,7 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
             ret_cnt++;
             break;
         case 0xe0:
+            if (siz < 2) goto shortbuf;
             data_1 = *event_data++;
             data_2 = *event_data++;
             midi_setup_pitch(mdi, channel, ((data_2 << 7) | (data_1 & 0x7f)));
@@ -2041,23 +2049,29 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                      Sequence Number
                      We only setting this up here for WM_Event2Midi function
                      */
+                    if (siz < 4) goto shortbuf;
                     midi_setup_sequenceno(mdi, ((event_data[2] << 8) + event_data[3]));
                     ret_cnt += 4;
                 } else if (event_data[0] == 0x01) {
                     /* Text Event */
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     text = malloc(tmp_length + 1);
                     memcpy(text, event_data, tmp_length);
@@ -2071,16 +2085,21 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     /* Copy copyright info in the getinfo struct */
                     if (mdi->extra_info.copyright) {
@@ -2107,16 +2126,21 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     text = malloc(tmp_length + 1);
                     memcpy(text, event_data, tmp_length);
@@ -2130,16 +2154,21 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     text = malloc(tmp_length + 1);
                     memcpy(text, event_data, tmp_length);
@@ -2153,16 +2182,21 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     text = malloc(tmp_length + 1);
                     memcpy(text, event_data, tmp_length);
@@ -2176,16 +2210,21 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     text = malloc(tmp_length + 1);
                     memcpy(text, event_data, tmp_length);
@@ -2199,16 +2238,21 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                     /* Get Length */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     event_data++;
                     ret_cnt++;
+                    if (--siz < tmp_length) goto shortbuf;
+                    if (!tmp_length) break; /* bad file? */
 
                     text = malloc(tmp_length + 1);
                     memcpy(text, event_data, tmp_length);
@@ -2222,13 +2266,15 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                      Channel Prefix
                      We only setting this up here for WM_Event2Midi function
                      */
+                    if (siz < 3) goto shortbuf;
                     midi_setup_channelprefix(mdi, event_data[2]);
                     ret_cnt += 3;
                 } else if ((event_data[0] == 0x21) && (event_data[1] == 0x01)) {
                     /*
                      Port Prefix
                      We only setting this up here for WM_Event2Midi function
                      */
+                    if (siz < 3) goto shortbuf;
                     midi_setup_portprefix(mdi, event_data[2]);
                     ret_cnt += 3;
                 } else if ((event_data[0] == 0x2F) && (event_data[1] == 0x00)) {
@@ -2237,6 +2283,7 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                      Deal with this inside calling function
                      We only setting this up here for _WM_Event2Midi function
                      */
+                    if (siz < 2) goto shortbuf;
                     _WM_midi_setup_endoftrack(mdi);
                     ret_cnt += 2;
                 } else if ((event_data[0] == 0x51) && (event_data[1] == 0x03)) {
@@ -2245,9 +2292,11 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                      Deal with this inside calling function.
                      We only setting this up here for _WM_Event2Midi function
                      */
+                    if (siz < 5) goto shortbuf;
                     _WM_midi_setup_tempo(mdi, ((event_data[2] << 16) + (event_data[3] << 8) + event_data[4]));
                     ret_cnt += 5;
                 } else if ((event_data[0] == 0x54) && (event_data[1] == 0x05)) {
+                    if (siz < 7) goto shortbuf;
                     /*
                      SMPTE Offset
                      We only setting this up here for WM_Event2Midi function
@@ -2265,13 +2314,15 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                      Time Signature
                      We only setting this up here for WM_Event2Midi function
                      */
+                    if (siz < 6) goto shortbuf;
                     midi_setup_timesignature(mdi, ((event_data[2] << 24) + (event_data[3] << 16) + (event_data[4] << 8) + event_data[5]));
                     ret_cnt += 6;
                 } else if ((event_data[0] == 0x59) && (event_data[1] == 0x02)) {
                     /*
                      Key Signature
                      We only setting this up here for WM_Event2Midi function
                      */
+                    if (siz < 4) goto shortbuf;
                     midi_setup_keysignature(mdi, ((event_data[2] << 8) + event_data[3]));
                     ret_cnt += 4;
                 } else {
@@ -2280,16 +2331,20 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
                      */
                     event_data++;
                     ret_cnt++;
-                    if (*event_data > 0x7f) {
+                    if (--siz && *event_data > 0x7f) {
                         do {
+                            if (!siz) break;
                             tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                             event_data++;
+                            siz--;
                             ret_cnt++;
                         } while (*event_data > 0x7f);
                     }
+                    if (!siz) goto shortbuf;
                     tmp_length = (tmp_length << 7) + (*event_data & 0x7f);
                     ret_cnt++;
                     ret_cnt += tmp_length;
+                    if (--siz < tmp_length) goto shortbuf;
                 }
 
             } else if ((channel == 0) || (channel == 7)) {
@@ -2301,15 +2356,19 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
 
                 if (*event_data > 0x7f) {
                     do {
+                        if (!siz) break;
                         sysex_len = (sysex_len << 7) + (*event_data & 0x7F);
                         event_data++;
+                        siz--;
                         ret_cnt++;
                     } while (*event_data > 0x7f);
                 }
+                if (!siz) goto shortbuf;
                 sysex_len = (sysex_len << 7) + (*event_data & 0x7F);
                 event_data++;
-                if (!sysex_len) break;
                 ret_cnt++;
+                if (--siz < sysex_len) goto shortbuf;
+                if (!sysex_len) break; /* bad file? */
 
                 sysex_store = malloc(sizeof(uint8_t) * sysex_len);
                 memcpy(sysex_store, event_data, sysex_len);
@@ -2381,5 +2440,9 @@ uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t runn
     if (ret_cnt == 0)
         _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(missing event)", 0);
     return ret_cnt;
+
+shortbuf:
+    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
+    return 0;
 }
 
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
