# Pacote de anotacao — caso 25

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

# Evidencia do caso 25

## Identificacao

- projeto: FFmpeg
- CVE: CVE-2013-7012
- CWE atribuida pelo BigVul: CWE-119
- commit: `780669ef7c23c00836a24921fcc6b03be2b8ca4a`
- URL do commit: https://github.com/FFmpeg/FFmpeg/commit/780669ef7c23c00836a24921fcc6b03be2b8ca4a
- arquivo da funcao marcada: `libavcodec/jpeg2000dec.c`

## Mensagem do commit

> avcodec/jpeg2000dec: non zero image offsets are not supported
> 
> Fixes out of array accesses
> Fixes Ticket3080
> Found-by: ami_stuff
> Signed-off-by: Michael Niedermayer <michaelni@gmx.at>

## Resumo da CVE

> The get_siz function in libavcodec/jpeg2000dec.c in FFmpeg before 2.1 does not prevent attempts to use non-zero image offsets, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted JPEG2000 data.

## Diff da funcao marcada (func_before vs func_after)

```diff
--- func_before
+++ func_after
@@ -20,6 +20,11 @@
      s->tile_offset_y  = bytestream2_get_be32u(&s->g); // YT0Siz
      ncomponents       = bytestream2_get_be16u(&s->g); // CSiz
  
+    if (s->image_offset_x || s->image_offset_y) {
+        avpriv_request_sample(s->avctx, "Support for image offsets");
+        return AVERROR_PATCHWELCOME;
+    }
+
      if (ncomponents <= 0) {
          av_log(s->avctx, AV_LOG_ERROR, "Invalid number of components: %d\n",
                 s->ncomponents);
```

## Corpo completo da funcao antes da correcao

```c
static int get_siz(Jpeg2000DecoderContext *s)
{
    int i;
    int ncomponents;
    uint32_t log2_chroma_wh = 0;
    const enum AVPixelFormat *possible_fmts = NULL;
    int possible_fmts_nb = 0;

    if (bytestream2_get_bytes_left(&s->g) < 36)
        return AVERROR_INVALIDDATA;

    s->avctx->profile = bytestream2_get_be16u(&s->g); // Rsiz
    s->width          = bytestream2_get_be32u(&s->g); // Width
    s->height         = bytestream2_get_be32u(&s->g); // Height
    s->image_offset_x = bytestream2_get_be32u(&s->g); // X0Siz
    s->image_offset_y = bytestream2_get_be32u(&s->g); // Y0Siz
    s->tile_width     = bytestream2_get_be32u(&s->g); // XTSiz
    s->tile_height    = bytestream2_get_be32u(&s->g); // YTSiz
    s->tile_offset_x  = bytestream2_get_be32u(&s->g); // XT0Siz
     s->tile_offset_y  = bytestream2_get_be32u(&s->g); // YT0Siz
     ncomponents       = bytestream2_get_be16u(&s->g); // CSiz
 
     if (ncomponents <= 0) {
         av_log(s->avctx, AV_LOG_ERROR, "Invalid number of components: %d\n",
                s->ncomponents);
        return AVERROR_INVALIDDATA;
    }

    if (ncomponents > 4) {
        avpriv_request_sample(s->avctx, "Support for %d components",
                              s->ncomponents);
        return AVERROR_PATCHWELCOME;
    }

    s->ncomponents = ncomponents;

    if (s->tile_width <= 0 || s->tile_height <= 0) {
        av_log(s->avctx, AV_LOG_ERROR, "Invalid tile dimension %dx%d.\n",
               s->tile_width, s->tile_height);
        return AVERROR_INVALIDDATA;
    }

    if (bytestream2_get_bytes_left(&s->g) < 3 * s->ncomponents)
        return AVERROR_INVALIDDATA;

    for (i = 0; i < s->ncomponents; i++) { // Ssiz_i XRsiz_i, YRsiz_i
        uint8_t x    = bytestream2_get_byteu(&s->g);
        s->cbps[i]   = (x & 0x7f) + 1;
        s->precision = FFMAX(s->cbps[i], s->precision);
        s->sgnd[i]   = !!(x & 0x80);
        s->cdx[i]    = bytestream2_get_byteu(&s->g);
        s->cdy[i]    = bytestream2_get_byteu(&s->g);
        if (   !s->cdx[i] || s->cdx[i] == 3 || s->cdx[i] > 4
            || !s->cdy[i] || s->cdy[i] == 3 || s->cdy[i] > 4) {
            av_log(s->avctx, AV_LOG_ERROR, "Invalid sample separation %d/%d\n", s->cdx[i], s->cdy[i]);
            return AVERROR_INVALIDDATA;
        }
        log2_chroma_wh |= s->cdy[i] >> 1 << i * 4 | s->cdx[i] >> 1 << i * 4 + 2;
    }

    s->numXtiles = ff_jpeg2000_ceildiv(s->width  - s->tile_offset_x, s->tile_width);
    s->numYtiles = ff_jpeg2000_ceildiv(s->height - s->tile_offset_y, s->tile_height);

    if (s->numXtiles * (uint64_t)s->numYtiles > INT_MAX/sizeof(*s->tile)) {
        s->numXtiles = s->numYtiles = 0;
        return AVERROR(EINVAL);
    }

    s->tile = av_mallocz_array(s->numXtiles * s->numYtiles, sizeof(*s->tile));
    if (!s->tile) {
        s->numXtiles = s->numYtiles = 0;
        return AVERROR(ENOMEM);
    }

    for (i = 0; i < s->numXtiles * s->numYtiles; i++) {
        Jpeg2000Tile *tile = s->tile + i;

        tile->comp = av_mallocz(s->ncomponents * sizeof(*tile->comp));
        if (!tile->comp)
            return AVERROR(ENOMEM);
    }

    /* compute image size with reduction factor */
    s->avctx->width  = ff_jpeg2000_ceildivpow2(s->width  - s->image_offset_x,
                                               s->reduction_factor);
    s->avctx->height = ff_jpeg2000_ceildivpow2(s->height - s->image_offset_y,
                                               s->reduction_factor);

    if (s->avctx->profile == FF_PROFILE_JPEG2000_DCINEMA_2K ||
        s->avctx->profile == FF_PROFILE_JPEG2000_DCINEMA_4K) {
        possible_fmts = xyz_pix_fmts;
        possible_fmts_nb = FF_ARRAY_ELEMS(xyz_pix_fmts);
    } else {
        switch (s->colour_space) {
        case 16:
            possible_fmts = rgb_pix_fmts;
            possible_fmts_nb = FF_ARRAY_ELEMS(rgb_pix_fmts);
            break;
        case 17:
            possible_fmts = gray_pix_fmts;
            possible_fmts_nb = FF_ARRAY_ELEMS(gray_pix_fmts);
            break;
        case 18:
            possible_fmts = yuv_pix_fmts;
            possible_fmts_nb = FF_ARRAY_ELEMS(yuv_pix_fmts);
            break;
        default:
            possible_fmts = all_pix_fmts;
            possible_fmts_nb = FF_ARRAY_ELEMS(all_pix_fmts);
            break;
        }
    }
    for (i = 0; i < possible_fmts_nb; ++i) {
        if (pix_fmt_match(possible_fmts[i], ncomponents, s->precision, log2_chroma_wh, s->pal8)) {
            s->avctx->pix_fmt = possible_fmts[i];
            break;
        }
    }
    if (s->avctx->pix_fmt == AV_PIX_FMT_NONE) {
        av_log(s->avctx, AV_LOG_ERROR,
               "Unknown pix_fmt, profile: %d, colour_space: %d, "
               "components: %d, precision: %d, "
               "cdx[1]: %d, cdy[1]: %d, cdx[2]: %d, cdy[2]: %d\n",
               s->avctx->profile, s->colour_space, ncomponents, s->precision,
               ncomponents > 2 ? s->cdx[1] : 0,
               ncomponents > 2 ? s->cdy[1] : 0,
               ncomponents > 2 ? s->cdx[2] : 0,
               ncomponents > 2 ? s->cdy[2] : 0);
    }
    s->avctx->bits_per_raw_sample = s->precision;
    return 0;
}

```

## Contexto: o commit inteiro

Arquivos tocados pelo commit: **1**

| arquivo | status | + | - |
| --- | --- | --- | --- |
| `libavcodec/jpeg2000dec.c` **(funcao marcada esta aqui)** | modified | 5 | 0 |


### `libavcodec/jpeg2000dec.c`

```diff
@@ -243,6 +243,11 @@ static int get_siz(Jpeg2000DecoderContext *s)
     s->tile_offset_y  = bytestream2_get_be32u(&s->g); // YT0Siz
     ncomponents       = bytestream2_get_be16u(&s->g); // CSiz
 
+    if (s->image_offset_x || s->image_offset_y) {
+        avpriv_request_sample(s->avctx, "Support for image offsets");
+        return AVERROR_PATCHWELCOME;
+    }
+
     if (ncomponents <= 0) {
         av_log(s->avctx, AV_LOG_ERROR, "Invalid number of components: %d\n",
                s->ncomponents);
```


---

Responda **apenas** com o objeto JSON descrito no contrato de saida.
Nada antes, nada depois, sem cercas de codigo.
