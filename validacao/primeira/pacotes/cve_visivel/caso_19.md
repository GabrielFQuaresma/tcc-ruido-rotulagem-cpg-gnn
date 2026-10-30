# Pacote de anotacao — caso 19

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

# Evidencia do caso 19

## Identificacao

- projeto: gst-plugins-ugly
- CVE: CVE-2017-5847
- CWE atribuida pelo BigVul: CWE-125
- commit: `d21017b52a585f145e8d62781bcc1c5fefc7ee37`
- URL do commit: https://github.com/GStreamer/gst-plugins-ugly/commit/d21017b52a585f145e8d62781bcc1c5fefc7ee37
- arquivo da funcao marcada: `gst/asfdemux/gstasfdemux.c`

## Mensagem do commit

> asfdemux: Check that we have enough data available before parsing bool/uint extended content descriptors
> 
> https://bugzilla.gnome.org/show_bug.cgi?id=777955

## Resumo da CVE

> The gst_asf_demux_process_ext_content_desc function in gst/asfdemux/gstasfdemux.c in gst-plugins-ugly in GStreamer allows remote attackers to cause a denial of service (out-of-bounds heap read) via vectors involving extended content descriptors.

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
gst_asf_demux_process_ext_content_desc (GstASFDemux * demux, guint8 * data,
    guint64 size)
{
  /* Other known (and unused) 'text/unicode' metadata available :
   *
   *   WM/Lyrics =
   *   WM/MediaPrimaryClassID = {D1607DBC-E323-4BE2-86A1-48A42A28441E}
   *   WMFSDKVersion = 9.00.00.2980
   *   WMFSDKNeeded = 0.0.0.0000
   *   WM/UniqueFileIdentifier = AMGa_id=R    15334;AMGp_id=P     5149;AMGt_id=T  2324984
   *   WM/Publisher = 4AD
   *   WM/Provider = AMG
   *   WM/ProviderRating = 8
   *   WM/ProviderStyle = Rock (similar to WM/Genre)
   *   WM/GenreID (similar to WM/Genre)
   *   WM/TrackNumber (same as WM/Track but as a string)
   *
   * Other known (and unused) 'non-text' metadata available :
   *
   *   WM/EncodingTime
   *   WM/MCDI
   *   IsVBR
   *
   * We might want to read WM/TrackNumber and use atoi() if we don't have
   * WM/Track
   */

  GstTagList *taglist;
  guint16 blockcount, i;
  gboolean content3D = FALSE;

  struct
  {
    const gchar *interleave_name;
    GstASF3DMode interleaving_type;
  } stereoscopic_layout_map[] = {
    {
    "SideBySideRF", GST_ASF_3D_SIDE_BY_SIDE_HALF_RL}, {
    "SideBySideLF", GST_ASF_3D_SIDE_BY_SIDE_HALF_LR}, {
    "OverUnderRT", GST_ASF_3D_TOP_AND_BOTTOM_HALF_RL}, {
    "OverUnderLT", GST_ASF_3D_TOP_AND_BOTTOM_HALF_LR}, {
    "DualStream", GST_ASF_3D_DUAL_STREAM}
  };
  GST_INFO_OBJECT (demux, "object is an extended content description");

  taglist = gst_tag_list_new_empty ();

  /* Content Descriptor Count */
  if (size < 2)
    goto not_enough_data;

  blockcount = gst_asf_demux_get_uint16 (&data, &size);

  for (i = 1; i <= blockcount; ++i) {
    const gchar *gst_tag_name;
    guint16 datatype;
    guint16 value_len;
    guint16 name_len;
    GValue tag_value = { 0, };
    gsize in, out;
    gchar *name;
    gchar *name_utf8 = NULL;
    gchar *value;

    /* Descriptor */
    if (!gst_asf_demux_get_string (&name, &name_len, &data, &size))
      goto not_enough_data;

    if (size < 2) {
      g_free (name);
      goto not_enough_data;
    }
    /* Descriptor Value Data Type */
    datatype = gst_asf_demux_get_uint16 (&data, &size);

    /* Descriptor Value (not really a string, but same thing reading-wise) */
    if (!gst_asf_demux_get_string (&value, &value_len, &data, &size)) {
      g_free (name);
      goto not_enough_data;
    }

    name_utf8 =
        g_convert (name, name_len, "UTF-8", "UTF-16LE", &in, &out, NULL);

    if (name_utf8 != NULL) {
      GST_DEBUG ("Found tag/metadata %s", name_utf8);

      gst_tag_name = gst_asf_demux_get_gst_tag_from_tag_name (name_utf8);
      GST_DEBUG ("gst_tag_name %s", GST_STR_NULL (gst_tag_name));

      switch (datatype) {
        case ASF_DEMUX_DATA_TYPE_UTF16LE_STRING:{
          gchar *value_utf8;

          value_utf8 = g_convert (value, value_len, "UTF-8", "UTF-16LE",
              &in, &out, NULL);

          /* get rid of tags with empty value */
          if (value_utf8 != NULL && *value_utf8 != '\0') {
            GST_DEBUG ("string value %s", value_utf8);

            value_utf8[out] = '\0';

            if (gst_tag_name != NULL) {
              if (strcmp (gst_tag_name, GST_TAG_DATE_TIME) == 0) {
                guint year = atoi (value_utf8);

                if (year > 0) {
                  g_value_init (&tag_value, GST_TYPE_DATE_TIME);
                  g_value_take_boxed (&tag_value, gst_date_time_new_y (year));
                }
              } else if (strcmp (gst_tag_name, GST_TAG_GENRE) == 0) {
                guint id3v1_genre_id;
                const gchar *genre_str;

                if (sscanf (value_utf8, "(%u)", &id3v1_genre_id) == 1 &&
                    ((genre_str = gst_tag_id3_genre_get (id3v1_genre_id)))) {
                  GST_DEBUG ("Genre: %s -> %s", value_utf8, genre_str);
                  g_free (value_utf8);
                  value_utf8 = g_strdup (genre_str);
                }
              } else {
                GType tag_type;

                /* convert tag from string to other type if required */
                tag_type = gst_tag_get_type (gst_tag_name);
                g_value_init (&tag_value, tag_type);
                if (!gst_value_deserialize (&tag_value, value_utf8)) {
                  GValue from_val = { 0, };

                  g_value_init (&from_val, G_TYPE_STRING);
                  g_value_set_string (&from_val, value_utf8);
                  if (!g_value_transform (&from_val, &tag_value)) {
                    GST_WARNING_OBJECT (demux,
                        "Could not transform string tag to " "%s tag type %s",
                        gst_tag_name, g_type_name (tag_type));
                    g_value_unset (&tag_value);
                  }
                  g_value_unset (&from_val);
                }
              }
            } else {
              /* metadata ! */
              GST_DEBUG ("Setting metadata");
              g_value_init (&tag_value, G_TYPE_STRING);
              g_value_set_string (&tag_value, value_utf8);
              /* If we found a stereoscopic marker, look for StereoscopicLayout
               * metadata */
              if (content3D) {
                guint i;
                if (strncmp ("StereoscopicLayout", name_utf8,
                        strlen (name_utf8)) == 0) {
                  for (i = 0; i < G_N_ELEMENTS (stereoscopic_layout_map); i++) {
                    if (g_str_equal (stereoscopic_layout_map[i].interleave_name,
                            value_utf8)) {
                      demux->asf_3D_mode =
                          stereoscopic_layout_map[i].interleaving_type;
                      GST_INFO ("find interleave type %u", demux->asf_3D_mode);
                    }
                  }
                }
                GST_INFO_OBJECT (demux, "3d type is %u", demux->asf_3D_mode);
              } else {
                demux->asf_3D_mode = GST_ASF_3D_NONE;
                GST_INFO_OBJECT (demux, "None 3d type");
              }
            }
          } else if (value_utf8 == NULL) {
            GST_WARNING ("Failed to convert string value to UTF8, skipping");
          } else {
            GST_DEBUG ("Skipping empty string value for %s",
                GST_STR_NULL (gst_tag_name));
          }
          g_free (value_utf8);
          break;
        }
        case ASF_DEMUX_DATA_TYPE_BYTE_ARRAY:{
          if (gst_tag_name) {
            if (!g_str_equal (gst_tag_name, GST_TAG_IMAGE)) {
              GST_FIXME ("Unhandled byte array tag %s",
                  GST_STR_NULL (gst_tag_name));
              break;
            } else {
              asf_demux_parse_picture_tag (taglist, (guint8 *) value,
                  value_len);
            }
          }
           break;
         }
         case ASF_DEMUX_DATA_TYPE_DWORD:{
          guint uint_val = GST_READ_UINT32_LE (value);
 
           /* this is the track number */
           g_value_init (&tag_value, G_TYPE_UINT);

          /* WM/Track counts from 0 */
          if (!strcmp (name_utf8, "WM/Track"))
            ++uint_val;

          g_value_set_uint (&tag_value, uint_val);
          break;
         }
           /* Detect 3D */
         case ASF_DEMUX_DATA_TYPE_BOOL:{
          gboolean bool_val = GST_READ_UINT32_LE (value);
 
           if (strncmp ("Stereoscopic", name_utf8, strlen (name_utf8)) == 0) {
             if (bool_val) {
              GST_INFO_OBJECT (demux, "This is 3D contents");
              content3D = TRUE;
            } else {
              GST_INFO_OBJECT (demux, "This is not 3D contenst");
              content3D = FALSE;
            }
          }

          break;
        }
        default:{
          GST_DEBUG ("Skipping tag %s of type %d", gst_tag_name, datatype);
          break;
        }
      }

      if (G_IS_VALUE (&tag_value)) {
        if (gst_tag_name) {
          GstTagMergeMode merge_mode = GST_TAG_MERGE_APPEND;

          /* WM/TrackNumber is more reliable than WM/Track, since the latter
           * is supposed to have a 0 base but is often wrongly written to start
           * from 1 as well, so prefer WM/TrackNumber when we have it: either
           * replace the value added earlier from WM/Track or put it first in
           * the list, so that it will get picked up by _get_uint() */
          if (strcmp (name_utf8, "WM/TrackNumber") == 0)
            merge_mode = GST_TAG_MERGE_REPLACE;

          gst_tag_list_add_values (taglist, merge_mode, gst_tag_name,
              &tag_value, NULL);
        } else {
          GST_DEBUG ("Setting global metadata %s", name_utf8);
          gst_structure_set_value (demux->global_metadata, name_utf8,
              &tag_value);
        }

        g_value_unset (&tag_value);
      }
    }

    g_free (name);
    g_free (value);
    g_free (name_utf8);
  }

  gst_asf_demux_add_global_tags (demux, taglist);

  return GST_FLOW_OK;

  /* Errors */
not_enough_data:
  {
    GST_WARNING ("Unexpected end of data parsing ext content desc object");
    gst_tag_list_unref (taglist);
    return GST_FLOW_OK;         /* not really fatal */
  }
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `gst/asfdemux/gstasfdemux.c` **(funcao marcada esta aqui)** | modified | 12 | 2 |


### `gst/asfdemux/gstasfdemux.c`

```diff
@@ -3439,7 +3439,12 @@ gst_asf_demux_process_ext_content_desc (GstASFDemux * demux, guint8 * data,
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
@@ -3453,7 +3458,12 @@ gst_asf_demux_process_ext_content_desc (GstASFDemux * demux, guint8 * data,
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

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
