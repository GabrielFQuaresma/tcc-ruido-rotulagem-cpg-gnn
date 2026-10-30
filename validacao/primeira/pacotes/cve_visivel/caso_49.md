# Pacote de anotacao — caso 49

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

# Evidencia do caso 49

## Identificacao

- projeto: FFmpeg
- CVE: CVE-2013-4263
- CWE atribuida pelo BigVul: CWE-119
- commit: `e43a0a232dbf6d3c161823c2e07c52e76227a1bc`
- URL do commit: https://github.com/FFmpeg/FFmpeg/commit/e43a0a232dbf6d3c161823c2e07c52e76227a1bc
- arquivo da funcao marcada: `libavfilter/vf_delogo.c`

## Mensagem do commit

> avfilter: fix plane validity checks
> 
> Fixes out of array accesses
> 
> Signed-off-by: Michael Niedermayer <michaelni@gmx.at>

## Resumo da CVE

> libavfilter in FFmpeg before 2.0.1 has unspecified impact and remote vectors related to a crafted *plane,* which triggers an out-of-bounds heap write.

## Diff da funcao marcada (func_before vs func_after)

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

## Corpo completo da funcao antes da correcao

```c
static int filter_frame(AVFilterLink *inlink, AVFrame *in)
{
    DelogoContext *s = inlink->dst->priv;
    AVFilterLink *outlink = inlink->dst->outputs[0];
    const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(inlink->format);
    AVFrame *out;
    int hsub0 = desc->log2_chroma_w;
    int vsub0 = desc->log2_chroma_h;
    int direct = 0;
    int plane;
    AVRational sar;

    if (av_frame_is_writable(in)) {
        direct = 1;
        out = in;
    } else {
        out = ff_get_video_buffer(outlink, outlink->w, outlink->h);
        if (!out) {
            av_frame_free(&in);
            return AVERROR(ENOMEM);
        }

        av_frame_copy_props(out, in);
    }

    sar = in->sample_aspect_ratio;
    /* Assume square pixels if SAR is unknown */
     if (!sar.num)
         sar.num = sar.den = 1;
 
    for (plane = 0; plane < 4 && in->data[plane]; plane++) {
         int hsub = plane == 1 || plane == 2 ? hsub0 : 0;
         int vsub = plane == 1 || plane == 2 ? vsub0 : 0;
 
        apply_delogo(out->data[plane], out->linesize[plane],
                     in ->data[plane], in ->linesize[plane],
                     FF_CEIL_RSHIFT(inlink->w, hsub),
                     FF_CEIL_RSHIFT(inlink->h, vsub),
                     sar, s->x>>hsub, s->y>>vsub,
                     /* Up and left borders were rounded down, inject lost bits
                      * into width and height to avoid error accumulation */
                     FF_CEIL_RSHIFT(s->w + (s->x & ((1<<hsub)-1)), hsub),
                     FF_CEIL_RSHIFT(s->h + (s->y & ((1<<vsub)-1)), vsub),
                     s->band>>FFMIN(hsub, vsub),
                     s->show, direct);
    }

    if (!direct)
        av_frame_free(&in);

    return ff_filter_frame(outlink, out);
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **11**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `libavfilter/vf_boxblur.c` | modified | 2 | 2 |
| `libavfilter/vf_delogo.c` **(funcao marcada esta aqui)** | modified | 1 | 1 |
| `libavfilter/vf_fieldmatch.c` | modified | 1 | 1 |
| `libavfilter/vf_fieldorder.c` | modified | 1 | 1 |
| `libavfilter/vf_gradfun.c` | modified | 1 | 1 |
| `libavfilter/vf_hflip.c` | modified | 1 | 1 |
| `libavfilter/vf_kerndeint.c` | modified | 1 | 1 |
| `libavfilter/vf_lut.c` | modified | 1 | 1 |
| `libavfilter/vf_pad.c` | modified | 2 | 2 |
| `libavfilter/vf_showinfo.c` | modified | 2 | 2 |
| `libavfilter/vf_vignette.c` | modified | 1 | 1 |


### `libavfilter/vf_delogo.c`

```diff
@@ -237,7 +237,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
     if (!sar.num)
         sar.num = sar.den = 1;
 
-    for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
         int hsub = plane == 1 || plane == 2 ? hsub0 : 0;
         int vsub = plane == 1 || plane == 2 ? vsub0 : 0;
 
```


### `libavfilter/vf_boxblur.c`

```diff
@@ -313,13 +313,13 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
     }
     av_frame_copy_props(out, in);
 
-    for (plane = 0; in->data[plane] && plane < 4; plane++)
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++)
         hblur(out->data[plane], out->linesize[plane],
               in ->data[plane], in ->linesize[plane],
               w[plane], h[plane], s->radius[plane], s->power[plane],
               s->temp);
 
-    for (plane = 0; in->data[plane] && plane < 4; plane++)
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++)
         vblur(out->data[plane], out->linesize[plane],
               out->data[plane], out->linesize[plane],
               w[plane], h[plane], s->radius[plane], s->power[plane],
```


### `libavfilter/vf_fieldmatch.c`

```diff
@@ -608,7 +608,7 @@ static void copy_fields(const FieldMatchContext *fm, AVFrame *dst,
                         const AVFrame *src, int field)
 {
     int plane;
-    for (plane = 0; plane < 4 && src->data[plane]; plane++)
+    for (plane = 0; plane < 4 && src->data[plane] && src->linesize[plane]; plane++)
         av_image_copy_plane(dst->data[plane] + field*dst->linesize[plane], dst->linesize[plane] << 1,
                             src->data[plane] + field*src->linesize[plane], src->linesize[plane] << 1,
                             get_width(fm, src, plane), get_height(fm, src, plane) / 2);
```


### `libavfilter/vf_fieldorder.c`

```diff
@@ -106,7 +106,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
             "picture will move %s one line\n",
             s->dst_tff ? "up" : "down");
     h = frame->height;
-    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
         line_step = frame->linesize[plane];
         line_size = s->line_size[plane];
         data = frame->data[plane];
```


### `libavfilter/vf_gradfun.c`

```diff
@@ -199,7 +199,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
         av_frame_copy_props(out, in);
     }
 
-    for (p = 0; p < 4 && in->data[p]; p++) {
+    for (p = 0; p < 4 && in->data[p] && in->linesize[p]; p++) {
         int w = inlink->w;
         int h = inlink->h;
         int r = s->radius;
```


### `libavfilter/vf_hflip.c`

```diff
@@ -90,7 +90,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
     if (av_pix_fmt_desc_get(inlink->format)->flags & AV_PIX_FMT_FLAG_PAL)
         memcpy(out->data[1], in->data[1], AVPALETTE_SIZE);
 
-    for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
         const int width  = (plane == 1 || plane == 2) ? FF_CEIL_RSHIFT(inlink->w, s->hsub) : inlink->w;
         const int height = (plane == 1 || plane == 2) ? FF_CEIL_RSHIFT(inlink->h, s->vsub) : inlink->h;
         step = s->max_step[plane];
```


### `libavfilter/vf_kerndeint.c`

```diff
@@ -150,7 +150,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *inpic)
     av_frame_copy_props(outpic, inpic);
     outpic->interlaced_frame = 0;
 
-    for (plane = 0; inpic->data[plane] && plane < 4; plane++) {
+    for (plane = 0; plane < 4 && inpic->data[plane] && inpic->linesize[plane]; plane++) {
         h = plane == 0 ? inlink->h : FF_CEIL_RSHIFT(inlink->h, kerndeint->vsub);
         bwidth = kerndeint->tmp_bwidth[plane];
 
```


### `libavfilter/vf_lut.c`

```diff
@@ -304,7 +304,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
         }
     } else {
         /* planar */
-        for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+        for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
             int vsub = plane == 1 || plane == 2 ? s->vsub : 0;
             int hsub = plane == 1 || plane == 2 ? s->hsub : 0;
             int h = FF_CEIL_RSHIFT(inlink->h, vsub);
```


### `libavfilter/vf_pad.c`

```diff
@@ -214,7 +214,7 @@ static AVFrame *get_video_buffer(AVFilterLink *inlink, int w, int h)
     frame->width  = w;
     frame->height = h;
 
-    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
         int hsub = s->draw.hsub[plane];
         int vsub = s->draw.vsub[plane];
         frame->data[plane] += (s->x >> hsub) * s->draw.pixelstep[plane] +
@@ -311,7 +311,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
         int i;
 
         out = in;
-        for (i = 0; i < 4 && out->data[i]; i++) {
+        for (i = 0; i < 4 && out->data[i] && out->linesize[i]; i++) {
             int hsub = s->draw.hsub[i];
             int vsub = s->draw.vsub[i];
             out->data[i] -= (s->x >> hsub) * s->draw.pixelstep[i] +
```


### `libavfilter/vf_showinfo.c`

```diff
@@ -38,7 +38,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
     uint32_t plane_checksum[4] = {0}, checksum = 0;
     int i, plane, vsub = desc->log2_chroma_h;
 
-    for (plane = 0; plane < 4 && frame->data[plane]; plane++) {
+    for (plane = 0; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++) {
         int64_t linesize = av_image_get_linesize(frame->format, frame->width, plane);
         uint8_t *data = frame->data[plane];
         int h = plane == 1 || plane == 2 ? FF_CEIL_RSHIFT(inlink->h, vsub) : inlink->h;
@@ -68,7 +68,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
            av_get_picture_type_char(frame->pict_type),
            checksum, plane_checksum[0]);
 
-    for (plane = 1; plane < 4 && frame->data[plane]; plane++)
+    for (plane = 1; plane < 4 && frame->data[plane] && frame->linesize[plane]; plane++)
         av_log(ctx, AV_LOG_INFO, " %08X", plane_checksum[plane]);
     av_log(ctx, AV_LOG_INFO, "]\n");
 
```


### `libavfilter/vf_vignette.c`

```diff
@@ -239,7 +239,7 @@ static int filter_frame(AVFilterLink *inlink, AVFrame *in)
     } else {
         int plane;
 
-        for (plane = 0; plane < 4 && in->data[plane]; plane++) {
+        for (plane = 0; plane < 4 && in->data[plane] && in->linesize[plane]; plane++) {
             uint8_t       *dst = out->data[plane];
             const uint8_t *src = in ->data[plane];
             const float *fmap = s->fmap;
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
