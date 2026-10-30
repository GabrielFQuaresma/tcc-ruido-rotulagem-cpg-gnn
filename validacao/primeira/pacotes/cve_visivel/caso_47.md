# Pacote de anotacao — caso 47

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

# Evidencia do caso 47

## Identificacao

- projeto: gstreamer
- CVE: CVE-2009-0397
- CWE atribuida pelo BigVul: CWE-119
- commit: `bdc20b9baf13564d9a061343416395f8f9a92b53`
- URL do commit: https://cgit.freedesktop.org/gstreamer/gst-plugins-good/commit/?id=bdc20b9baf13564d9a061343416395f8f9a92b53
- arquivo da funcao marcada: `_ausente_`

## Mensagem do commit

_Nao disponivel neste registro._

## Resumo da CVE

> Heap-based buffer overflow in the qtdemux_parse_samples function in gst/qtdemux/qtdemux.c in GStreamer Good Plug-ins (aka gst-plugins-good) 0.10.9 through 0.10.11, and GStreamer Plug-ins (aka gstreamer-plugins) 0.8.5, might allow remote attackers to execute arbitrary code via crafted Time-to-sample (aka stts) atom data in a malformed QuickTime media .mov file.

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
qtdemux_parse_samples (GstQTDemux * qtdemux, QtDemuxStream * stream,
    GNode * stbl)
{
  int offset;
  GNode *stsc;
  GNode *stsz;
  GNode *stco;
  GNode *co64;
  GNode *stts;
  GNode *stss;
  GNode *ctts;
  const guint8 *stsc_data, *stsz_data, *stco_data;
  int sample_size;
  int sample_index;
  int n_samples;
  int n_samples_per_chunk;
  int n_sample_times;
  QtDemuxSample *samples;
  gint i, j, k;
  int index;
  guint64 timestamp, time;

  /* sample to chunk */
  if (!(stsc = qtdemux_tree_get_child_by_type (stbl, FOURCC_stsc)))
    goto corrupt_file;
  stsc_data = (const guint8 *) stsc->data;
  /* sample size */
  if (!(stsz = qtdemux_tree_get_child_by_type (stbl, FOURCC_stsz)))
    goto corrupt_file;
  stsz_data = (const guint8 *) stsz->data;
  /* chunk offsets */
  stco = qtdemux_tree_get_child_by_type (stbl, FOURCC_stco);
  co64 = qtdemux_tree_get_child_by_type (stbl, FOURCC_co64);
  if (stco) {
    stco_data = (const guint8 *) stco->data;
  } else {
    stco_data = NULL;
    if (co64 == NULL)
      goto corrupt_file;
  }
  /* sample time */
  if (!(stts = qtdemux_tree_get_child_by_type (stbl, FOURCC_stts)))
    goto corrupt_file;

  /* sample sync, can be NULL */
  stss = qtdemux_tree_get_child_by_type (stbl, FOURCC_stss);

  sample_size = QT_UINT32 (stsz_data + 12);
  if (sample_size == 0 || stream->sampled) {
    n_samples = QT_UINT32 (stsz_data + 16);
    GST_DEBUG_OBJECT (qtdemux, "stsz sample_size 0, allocating n_samples %d",
        n_samples);
    stream->n_samples = n_samples;
    samples = g_new0 (QtDemuxSample, n_samples);
    stream->samples = samples;

    for (i = 0; i < n_samples; i++) {
      if (sample_size == 0)
        samples[i].size = QT_UINT32 (stsz_data + i * 4 + 20);
      else
        samples[i].size = sample_size;

      GST_LOG_OBJECT (qtdemux, "sample %d has size %d", i, samples[i].size);
      /* init other fields to defaults for this sample */
      samples[i].keyframe = FALSE;
    }
    n_samples_per_chunk = QT_UINT32 (stsc_data + 12);
    index = 0;
    for (i = 0; i < n_samples_per_chunk; i++) {
      guint32 first_chunk, last_chunk;
      guint32 samples_per_chunk;

      first_chunk = QT_UINT32 (stsc_data + 16 + i * 12 + 0) - 1;
      if (i == n_samples_per_chunk - 1) {
        last_chunk = G_MAXUINT32;
      } else {
        last_chunk = QT_UINT32 (stsc_data + 16 + i * 12 + 12) - 1;
      }
      samples_per_chunk = QT_UINT32 (stsc_data + 16 + i * 12 + 4);

      for (j = first_chunk; j < last_chunk; j++) {
        guint64 chunk_offset;

        if (stco) {
          chunk_offset = QT_UINT32 (stco_data + 16 + j * 4);
        } else {
          chunk_offset = QT_UINT64 ((guint8 *) co64->data + 16 + j * 8);
        }
        for (k = 0; k < samples_per_chunk; k++) {
          GST_LOG_OBJECT (qtdemux, "Creating entry %d with offset %lld",
              index, chunk_offset);
          samples[index].chunk = j;
          samples[index].offset = chunk_offset;
          chunk_offset += samples[index].size;
          index++;
          if (index >= n_samples)
            goto done2;
        }
      }
    }
  done2:

    n_sample_times = QT_UINT32 ((guint8 *) stts->data + 12);
    timestamp = 0;
     stream->min_duration = 0;
     time = 0;
     index = 0;
    for (i = 0; i < n_sample_times; i++) {
       guint32 n;
       guint32 duration;
 
       n = QT_UINT32 ((guint8 *) stts->data + 16 + 8 * i);
       duration = QT_UINT32 ((guint8 *) stts->data + 16 + 8 * i + 4);
      for (j = 0; j < n; j++) {
         GST_DEBUG_OBJECT (qtdemux, "sample %d: timestamp %" GST_TIME_FORMAT,
             index, GST_TIME_ARGS (timestamp));
 
        samples[index].timestamp = timestamp;
        /* take first duration for fps */
        if (stream->min_duration == 0)
          stream->min_duration = duration;
        /* add non-scaled values to avoid rounding errors */
        time += duration;
        timestamp = gst_util_uint64_scale (time, GST_SECOND, stream->timescale);
        samples[index].duration = timestamp - samples[index].timestamp;

        index++;
      }
    }
    if (stss) {
      /* mark keyframes */
      guint32 n_sample_syncs;

      n_sample_syncs = QT_UINT32 ((guint8 *) stss->data + 12);
      if (n_sample_syncs == 0) {
        stream->all_keyframe = TRUE;
      } else {
        offset = 16;
         for (i = 0; i < n_sample_syncs; i++) {
           /* note that the first sample is index 1, not 0 */
           index = QT_UINT32 ((guint8 *) stss->data + offset);
          if (index > 0) {
             samples[index - 1].keyframe = TRUE;
             offset += 4;
           }
        }
      }
    } else {
      /* no stss, all samples are keyframes */
      stream->all_keyframe = TRUE;
    }
  } else {
    GST_DEBUG_OBJECT (qtdemux,
        "stsz sample_size %d != 0, treating chunks as samples", sample_size);

    /* treat chunks as samples */
    if (stco) {
      n_samples = QT_UINT32 (stco_data + 12);
    } else {
      n_samples = QT_UINT32 ((guint8 *) co64->data + 12);
    }
    stream->n_samples = n_samples;
    GST_DEBUG_OBJECT (qtdemux, "allocating n_samples %d", n_samples);
    samples = g_new0 (QtDemuxSample, n_samples);
    stream->samples = samples;

    n_samples_per_chunk = QT_UINT32 (stsc_data + 12);
    GST_DEBUG_OBJECT (qtdemux, "n_samples_per_chunk %d", n_samples_per_chunk);
    sample_index = 0;
    timestamp = 0;
    for (i = 0; i < n_samples_per_chunk; i++) {
      guint32 first_chunk, last_chunk;
      guint32 samples_per_chunk;

      first_chunk = QT_UINT32 (stsc_data + 16 + i * 12 + 0) - 1;
      /* the last chunk of each entry is calculated by taking the first chunk
       * of the next entry; except if there is no next, where we fake it with
       * INT_MAX */
      if (i == n_samples_per_chunk - 1) {
        last_chunk = G_MAXUINT32;
      } else {
        last_chunk = QT_UINT32 (stsc_data + 16 + i * 12 + 12) - 1;
      }
      samples_per_chunk = QT_UINT32 (stsc_data + 16 + i * 12 + 4);

      GST_LOG_OBJECT (qtdemux,
          "entry %d has first_chunk %d, last_chunk %d, samples_per_chunk %d", i,
          first_chunk, last_chunk, samples_per_chunk);

      for (j = first_chunk; j < last_chunk; j++) {
        guint64 chunk_offset;

        if (j >= n_samples)
          goto done;

        if (stco) {
          chunk_offset = QT_UINT32 (stco_data + 16 + j * 4);
        } else {
          chunk_offset = QT_UINT64 ((guint8 *) co64->data + 16 + j * 8);
        }
        GST_LOG_OBJECT (qtdemux,
            "Creating entry %d with offset %" G_GUINT64_FORMAT, j,
            chunk_offset);

        samples[j].chunk = j;
        samples[j].offset = chunk_offset;

        if (stream->samples_per_frame * stream->bytes_per_frame) {
          samples[j].size = (samples_per_chunk * stream->n_channels) /
              stream->samples_per_frame * stream->bytes_per_frame;
        } else {
          samples[j].size = samples_per_chunk;
        }

        GST_DEBUG_OBJECT (qtdemux, "sample %d: timestamp %" GST_TIME_FORMAT
            ", size %u", j, GST_TIME_ARGS (timestamp), samples[j].size);

        samples[j].timestamp = timestamp;
        sample_index += samples_per_chunk;

        timestamp = gst_util_uint64_scale (sample_index,
            GST_SECOND, stream->timescale);
        samples[j].duration = timestamp - samples[j].timestamp;

        samples[j].keyframe = TRUE;
      }
    }
  }

  /* composition time to sample */
  if ((ctts = qtdemux_tree_get_child_by_type (stbl, FOURCC_ctts))) {
    const guint8 *ctts_data = (const guint8 *) ctts->data;
    guint32 n_entries = QT_UINT32 (ctts_data + 12);
    guint32 count;
    gint32 soffset;

    /* Fill in the pts_offsets */
     for (i = 0, j = 0; (j < stream->n_samples) && (i < n_entries); i++) {
       count = QT_UINT32 (ctts_data + 16 + i * 8);
       soffset = QT_UINT32 (ctts_data + 20 + i * 8);
      for (k = 0; k < count; k++, j++) {
         /* we operate with very small soffset values here, it shouldn't overflow */
         samples[j].pts_offset = soffset * GST_SECOND / stream->timescale;
       }
    }
  }
done:
  return TRUE;

/* ERRORS */
corrupt_file:
  {
    GST_ELEMENT_ERROR (qtdemux, STREAM, DECODE,
        (_("This file is corrupt and cannot be played.")), (NULL));
    return FALSE;
  }
}

```

## Contexto: o commit inteiro

_O BigVul nao traz o diff do commit completo para este caso._

---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
